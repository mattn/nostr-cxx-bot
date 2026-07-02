# syntax=docker/dockerfile:1

# ---------- build stage ----------
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ make cmake git ca-certificates \
        libssl-dev zlib1g-dev libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Submodules under deps/ must be checked out on the host first:
#   git submodule update --init --recursive
COPY . .

# Dynamic build (default). libstdc++/libgcc are linked statically so the
# runtime image only needs glibc + openssl + zlib. strip to shrink.
# The deps must be built before the executable: linking by archive path
# only finds them once the archive files exist.
RUN cmake -B build -D CMAKE_BUILD_TYPE=Release \
        -D CMAKE_EXE_LINKER_FLAGS="-static-libgcc -static-libstdc++" \
    && cmake --build build --parallel "$(nproc)" \
        --target libsecp256k1 libbech32 libspdlog libcpprest \
    && cmake --build build --target nostr-cxx-bot \
    && strip build/nostr-cxx-bot

# Collect exactly the shared libs the binary needs (glibc/ca-certs come from
# the runtime base). cp -L materialises the versioned files behind the
# libz.so.1 symlink so the runtime image needs nothing else.
RUN mkdir -p /rootfs/usr/lib/x86_64-linux-gnu \
    && cp -L /usr/lib/x86_64-linux-gnu/libssl.so.3 \
             /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
             /usr/lib/x86_64-linux-gnu/libz.so.1 \
             /rootfs/usr/lib/x86_64-linux-gnu/

# ---------- runtime stage ----------
# distroless/base has glibc (needed for the binary's DNS/getaddrinfo) and
# ca-certificates (needed for TLS to wss:// relays), and nothing else.
# Built from the same Debian 12 (glibc 2.36) as the builder, so the copied
# libs match.
FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=builder /rootfs/ /
COPY --from=builder /src/build/nostr-cxx-bot /usr/local/bin/nostr-cxx-bot

# BOT_NSEC must be provided at runtime, e.g.:
#   docker run --rm -e BOT_NSEC=nsec1... <image>
ENTRYPOINT ["/usr/local/bin/nostr-cxx-bot"]
