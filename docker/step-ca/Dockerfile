FROM golang:1.24-bookworm AS builder
ARG STEP_CA_VERSION=v0.29.0
ENV GOBIN=/usr/local/bin
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpcsclite-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN go install -tags postgres github.com/smallstep/certificates/cmd/step-ca@${STEP_CA_VERSION}

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpcsclite1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/step-ca /usr/local/bin/step-ca
