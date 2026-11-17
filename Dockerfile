ARG TARGETARCH
# If TARGETARCH is amd64, result is x86_64. If arm64, result is aarch64.
ARG RUST_ARCH=${TARGETARCH/amd64/x86_64}
ARG RUST_ARCH=${RUST_ARCH/arm64/aarch64}
ARG TARGET=${RUST_ARCH}-unknown-linux-gnu
ARG RUSTFLAGS="-C target-feature=+crt-static"
ARG BIN=draytek-vpn-cli

FROM ghcr.io/profiidev/images/rust-gnu-builder:main@sha256:58cb837025f0f8eb4b256b8a2ef0ef93958961ba6835123578d8b0c338a974a8 AS planner

ARG BIN

COPY ./Cargo.toml ./Cargo.lock ./

RUN cargo chef prepare --recipe-path recipe.json --bin $BIN

FROM ghcr.io/profiidev/images/rust-gnu-builder:main@sha256:58cb837025f0f8eb4b256b8a2ef0ef93958961ba6835123578d8b0c338a974a8 AS builder

ARG BIN
ARG TARGET
ARG RUSTFLAGS

# vendored OpenSSL is built from source
RUN apt-get update && apt-get install -y perl make && rm -rf /var/lib/apt/lists/*

COPY --from=planner /app/recipe.json .

RUN \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/app/target \
  cargo chef cook --release --target $TARGET

COPY ./src ./src
COPY ./Cargo.toml ./Cargo.lock ./

RUN \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/app/target \
  cargo build --release --target $TARGET --bin $BIN \
  && mv ./target/$TARGET/release/$BIN ./app

FROM scratch

COPY --from=builder /app/app /draytek-vpn-cli

ENTRYPOINT ["/draytek-vpn-cli"]
