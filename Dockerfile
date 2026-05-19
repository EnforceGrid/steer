# ── Stage 1: dependency cache (cargo-chef) ───────────────────────────────────
# Build stages run on the host platform (native, no QEMU) and cross-compile
# to the target arch. This cuts arm64 CI time from ~1h to ~5 min.
FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm AS chef
ARG TARGETARCH
RUN cargo install cargo-chef --locked
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
      $([ "$TARGETARCH" = "arm64" ] && echo "gcc-aarch64-linux-gnu libc6-dev-arm64-cross") \
 && rm -rf /var/lib/apt/lists/* \
 && if [ "$TARGETARCH" = "arm64" ]; then rustup target add aarch64-unknown-linux-gnu; fi
WORKDIR /build

FROM --platform=$BUILDPLATFORM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 2: compile ──────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM chef AS builder
ARG TARGETARCH
COPY --from=planner /build/recipe.json recipe.json
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
      cargo chef cook --release --target aarch64-unknown-linux-gnu --recipe-path recipe.json; \
    else \
      cargo chef cook --release --recipe-path recipe.json; \
    fi
COPY . .
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
      cargo build --release --bin steer --target aarch64-unknown-linux-gnu \
      && cp target/aarch64-unknown-linux-gnu/release/steer target/release/steer; \
    else \
      cargo build --release --bin steer; \
    fi

# ── Stage 3: minimal runtime ──────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12

WORKDIR /app
COPY --from=builder /build/target/release/steer /app/steer
COPY dsl/   /app/dsl/
COPY steer.example.yaml /app/steer.yaml

EXPOSE 8080
ENTRYPOINT ["/app/steer"]
