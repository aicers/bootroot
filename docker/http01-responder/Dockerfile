# Build Stage
# Pinned to an explicit patch release so the shipped binary is reproducible and
# Dependabot can propose toolchain bumps.
FROM rust:1.97.1-slim-bookworm AS builder

WORKDIR /usr/src/bootroot

# Copy source code (context is project root)
COPY . .

# Build the release binary
RUN cargo build --release --bin bootroot-http01-responder

# Runtime Stage
FROM debian:bookworm-slim

WORKDIR /app

# Install necessary runtime dependencies (SSL/TLS credentials)
RUN apt-get update && apt-get install -y ca-certificates openssl && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /usr/src/bootroot/target/release/bootroot-http01-responder .

# Expose HTTP-01 challenge and admin ports
EXPOSE 80 8080

ENTRYPOINT ["./bootroot-http01-responder"]
