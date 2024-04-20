#include <cpprest/base_uri.h>
#include <cpprest/ws_client.h>
#include <cpprest/ws_msg.h>

#include <ctime>
#include <exception>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

#include <libbech32/bech32.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#define SPDLOG_FMT_EXTERNAL
#include <spdlog/cfg/env.h>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <argparse/argparse.hpp>

static inline std::string digest2hex(const uint8_t *data, size_t len) {
  std::stringstream ss;
  ss << std::hex;
  for (int i = 0; i < len; ++i) {
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

static bool sign_event(const std::basic_string<uint8_t> sk,
                       nlohmann::json &ev) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);

  if (!secp256k1_ec_seckey_verify(ctx, sk.data())) {
    secp256k1_context_destroy(ctx);
    return false;
  }

  secp256k1_keypair keypair;
  if (!secp256k1_keypair_create(ctx, &keypair, sk.data())) {
    secp256k1_context_destroy(ctx);
    return false;
  }

  secp256k1_xonly_pubkey spubkey;
  if (!secp256k1_keypair_xonly_pub(ctx, &spubkey, NULL, &keypair)) {
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

int main() {
  spdlog::cfg::load_env_levels();

  uint8_t sk[32];
  bech32::DecodedResult decoded = bech32::decode(getenv("BOT_NSEC"));
  std::cout << decoded.hrp << std::endl;
  convert_bits<5, 8>(decoded.dp.begin(), decoded.dp.end(),
                     [&, pos = 0U](unsigned char c) mutable {
                       if (pos < 32)
                         sk[pos++] = c;
                     });

  web::websockets::client::websocket_client client;
  try {
    client.connect(web::uri("wss://yabu.me")).wait();
    web::websockets::client::websocket_outgoing_message msg;
    nlohmann::json req = {"REQ", "sub", {{"kinds", {1}}, {"limit", 500}}};
    std::cout << req.dump() << std::endl;
    msg.set_utf8_message(req.dump());
    client.send(msg);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }

  int cpp = 0;
  while (true) {
    try {
      auto line = client.receive().get().extract_string().get();
      if (line.empty())
        continue;
      std::cout << line << std::endl;
      auto payload = nlohmann::json::parse(line);
      if (payload[0] != "EVENT")
        continue;
      auto content = (std::string)payload[2]["content"];
      std::cout << content << std::endl;

      if (content == "C++") {
        cpp++;
        std::stringstream ss;
        ss << cpp;

        nlohmann::json ev;
        ev["kind"] = 1;
        ev["content"] = ss.str();
        ev["created_at"] = now();
        std::vector<std::vector<std::string>> tags = {{"e", payload[2]["id"]}};
        ev["tags"] = tags;
        sign_event(sk, ev);

        web::websockets::client::websocket_outgoing_message msg;
        nlohmann::json event = {"EVENT", ev};
        std::cout << event.dump() << std::endl;
        msg.set_utf8_message(event.dump());
        client.send(msg);
      }
    } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
      return 1;
    }
  }
}
