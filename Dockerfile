# Build Stage
FROM rust:slim-bookworm AS builder

# Install nightly
RUN rustup toolchain install nightly && rustup default nightly

WORKDIR /usr/src/bootroot

# Copy source code (context is project root)
COPY . .

# Build the release binary
RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim

WORKDIR /app

# Install necessary runtime dependencies (SSL/TLS credentials)
RUN apt-get update && apt-get install -y ca-certificates openssl && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /usr/src/bootroot/target/release/bootroot-agent .

# Expose HTTP-01 challenge port
EXPOSE 80

ENTRYPOINT ["./bootroot-agent"]
