# syntax=docker/dockerfile:1.5

# build stage
FROM docker.io/library/rust:1.91-bullseye AS builder
WORKDIR /app

# cache deps
RUN apt install libsqlite3-dev -y
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "// dummy file for cargo fetch" > src/main.rs
RUN cargo fetch

COPY src ./src
COPY static ./static
RUN cargo build --release

# run app
FROM docker.io/debian:bookworm-slim AS runtime
RUN apt update && apt install libsqlite3-dev -y
WORKDIR /app

COPY --from=builder /app/target/release/partyless /usr/local/bin/partyless
COPY static ./static
COPY templates/ ./templates

ENV RUST_LOG=info
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/partyless", "--db-file=./data/partyless.db", "--metrics-db-file=./data/partyless_metrics.db"]
