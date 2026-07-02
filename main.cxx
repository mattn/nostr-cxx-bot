#include <cpprest/base_uri.h>
#include <cpprest/ws_client.h>
#include <cpprest/ws_msg.h>

#include <cstdlib>
#include <ctime>
#include <exception>
#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>
#include <cassert>

#include <openssl/evp.h>

#include <libbech32/bech32.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include <spdlog/cfg/env.h>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <argparse/argparse.hpp>

#include "version.h"

static inline std::string digest2hex(const uint8_t *data, size_t len) {
  std::stringstream ss;
  ss << std::hex;
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2) << std::setfill('0') << (int)data[i];
  }
  return ss.str();
}

static inline std::vector<uint8_t> hex2bytes(const std::string &hex) {
  std::vector<uint8_t> bytes;
  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string s = hex.substr(i, 2);
    auto byte = (uint8_t)strtol(s.c_str(), nullptr, 16);
    bytes.push_back(byte);
  }
  return bytes;
}

static bool sign_event(const uint8_t *sk, nlohmann::json &ev) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);

  if (!secp256k1_ec_seckey_verify(ctx, sk)) {
    secp256k1_context_destroy(ctx);
    return false;
  }

  secp256k1_keypair keypair;
  if (!secp256k1_keypair_create(ctx, &keypair, sk)) {
    secp256k1_context_destroy(ctx);
    return false;
  }

  secp256k1_xonly_pubkey spubkey;
  if (!secp256k1_keypair_xonly_pub(ctx, &spubkey, nullptr, &keypair)) {
    secp256k1_context_destroy(ctx);
    return false;
  }
  uint8_t pubkey[32];
  if (!secp256k1_xonly_pubkey_serialize(ctx, pubkey, &spubkey)) {
    secp256k1_context_destroy(ctx);
    return false;
  }

  ev["pubkey"] = digest2hex(pubkey, sizeof(pubkey));

  nlohmann::json check = {0,          ev["pubkey"], ev["created_at"],
                          ev["kind"], ev["tags"],   ev["content"]};
  auto dump = check.dump();
  std::cout << dump << std::endl;

  uint8_t digest[32] = {0};
  EVP_Digest(dump.data(), dump.size(), digest, nullptr, EVP_sha256(), nullptr);

  auto id = digest2hex(digest, sizeof(digest));
  ev["id"] = id;

  uint8_t sig[64] = {0};
  if (!secp256k1_schnorrsig_sign32(ctx, sig, digest, &keypair, nullptr)) {
    secp256k1_context_destroy(ctx);
    return false;
  }
  secp256k1_context_destroy(ctx);

  ev["sig"] = digest2hex(sig, sizeof(sig));
  return true;
}

template <int from, int to, typename Iterator, typename Fn>
static void convert_bits(Iterator at, Iterator end, Fn fn) {
  constexpr unsigned int input_mask = ~((~0U) << from);
  constexpr unsigned int output_mask = ~((~0U) << to);
  unsigned int accum = 0;
  int sz = 0;
  while (at != end) {
    unsigned int val = (*at) & input_mask;
    sz += from;
    accum = (accum << from) | val;
    while (sz >= to) {
      unsigned int b = (accum >> (sz - to)) & output_mask;
      fn(b);
      sz -= to;
    }
    ++at;
  }
  if constexpr (to < from) {
    if (sz) {
      accum <<= (to - sz);
      unsigned int b = accum & output_mask;
      fn(b);
    }
  }
}

static inline time_t now() {
  time_t n;
  std::time(&n);
  return n;
}

static constexpr auto RELAY_URL = "wss://yabu.me";
static constexpr int HISTORY_LIMIT = 500;

// Decode a bech32 "nsec" string into a 32-byte secret key.
static bool load_secret_key(const std::string &prog, const char *nsec,
                            uint8_t sk[32]) {
  bech32::DecodedResult decoded;
  try {
    decoded = bech32::decode(nsec);
  } catch (const std::exception &e) {
    std::cerr << prog << ": failed to decode BOT_NSEC: " << e.what()
              << std::endl;
    return false;
  }
  if (decoded.hrp != "nsec") {
    std::cerr << prog << ": BOT_NSEC must be a valid nsec key" << std::endl;
    return false;
  }
  unsigned int written = 0;
  convert_bits<5, 8>(decoded.dp.begin(), decoded.dp.end(),
                     [&](unsigned char c) {
                       if (written < 32)
                         sk[written++] = c;
                     });
  if (written != 32) {
    std::cerr << prog << ": BOT_NSEC is not a valid 32-byte key" << std::endl;
    return false;
  }
  return true;
}

// Connect to the relay and send the subscription request.
static bool connect_and_subscribe(
    web::websockets::client::websocket_client &client) {
  try {
    client.connect(web::uri(RELAY_URL)).wait();
    nlohmann::json req = {"REQ", "sub",
                          {{"kinds", {1}}, {"limit", HISTORY_LIMIT}}};
    std::cout << req.dump() << std::endl;
    web::websockets::client::websocket_outgoing_message msg;
    msg.set_utf8_message(req.dump());
    client.send(msg);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
  return true;
}

// Build a signed kind-1 reply carrying the count and referencing reply_to.
static bool build_reply(const uint8_t *sk, int count,
                        const std::string &reply_to, nlohmann::json &ev) {
  ev["kind"] = 1;
  ev["content"] = std::to_string(count);
  ev["created_at"] = now();
  ev["tags"] = std::vector<std::vector<std::string>>{{"e", reply_to}};
  return sign_event(sk, ev);
}

// Handle a single incoming websocket line; reply when content equals "C++".
static void handle_message(web::websockets::client::websocket_client &client,
                           const uint8_t *sk, const std::string &line,
                           int &cpp) {
  if (line.empty())
    return;
  std::cout << line << std::endl;
  auto payload = nlohmann::json::parse(line);
  if (!payload.is_array() || payload.size() < 3 || payload[0] != "EVENT")
    return;
  auto event = payload[2];
  if (!event.contains("content") || !event["content"].is_string())
    return;
  auto content = event["content"].get<std::string>();
  std::cout << content << std::endl;
  if (content != "C++")
    return;

  nlohmann::json ev;
  if (!build_reply(sk, ++cpp, event["id"].get<std::string>(), ev)) {
    std::cerr << "failed to sign event" << std::endl;
    return;
  }

  nlohmann::json reply = {"EVENT", ev};
  std::cout << reply.dump() << std::endl;
  web::websockets::client::websocket_outgoing_message msg;
  msg.set_utf8_message(reply.dump());
  client.send(msg);
}

int main(int argc, char* argv[]) {
  argparse::ArgumentParser program("nostr-cxx-bot", VERSION);
  try {
    program.parse_args(argc, argv);
  } catch (const std::exception &err) {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    return 1;
  }

  spdlog::cfg::load_env_levels();

  auto nsec = getenv("BOT_NSEC");
  if (nsec == nullptr) {
    std::cerr << argv[0] << ": BOT_NSEC must be set" << std::endl;
    return 1;
  }
  uint8_t sk[32];
  if (!load_secret_key(argv[0], nsec, sk))
    return 1;

  web::websockets::client::websocket_client client;
  if (!connect_and_subscribe(client))
    return 1;

  int cpp = 0;
  while (true) {
    std::string line;
    try {
      line = client.receive().get().extract_string().get();
    } catch (std::exception &e) {
      // A failed receive means the connection is gone; stop the bot.
      std::cerr << e.what() << std::endl;
      return 1;
    }

    try {
      handle_message(client, sk, line, cpp);
    } catch (std::exception &e) {
      // A malformed or unexpected message must not kill the bot.
      std::cerr << e.what() << std::endl;
    }
  }
}
