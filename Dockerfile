# ── Stage 1: dependency cache (cargo-chef) ───────────────────────────────────
FROM rust:1-slim-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 2: compile ──────────────────────────────────────────────────────────
FROM chef AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin steer

# ── Stage 3: minimal runtime ──────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12

WORKDIR /app
COPY --from=builder /build/target/release/steer /app/steer
COPY dsl/   /app/dsl/
COPY steer.example.yaml /app/steer.yaml

EXPOSE 8080
ENTRYPOINT ["/app/steer"]
