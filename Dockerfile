# Builder stage
FROM rust:1.98.0-alpine3.24 AS builder
WORKDIR /usr/src/treetop-rest

# Accept build args for git info
ARG GIT_BRANCH=main
ARG GIT_SHA=unknown
ARG GIT_DESCRIBE=unknown

# Set environment variables for vergen
ENV VERGEN_GIT_BRANCH=$GIT_BRANCH
ENV VERGEN_GIT_SHA=$GIT_SHA
ENV VERGEN_GIT_DESCRIBE=$GIT_DESCRIBE

RUN apk add --no-cache \
    openssl-dev \
    openssl-libs-static \
    musl-dev \
    curl \
    git

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY build.rs ./
COPY benches ./benches
COPY testdata ./testdata

RUN cargo build --locked --release --bin treetop-server

# Runtime stage
FROM alpine:3.24

LABEL org.opencontainers.image.source="https://github.com/treetop-policy-engine/treetop-rest"

RUN apk add --no-cache \
    ca-certificates \
    curl

WORKDIR /app

# Copy the compiled binary from builder
COPY --from=builder /usr/src/treetop-rest/target/release/treetop-server /app/treetop-server

# Create app user for security
RUN addgroup -g 1000 appgroup && \
    adduser -u 1000 -G appgroup -h /app -s /sbin/nologin -D appuser

# Adjust permissions
RUN chown -R appuser:appgroup /app

USER appuser

# Expose the default API port (config default is 9999; override with TREETOP_PORT)
EXPOSE 9999

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9999/readyz || exit 1

ENTRYPOINT ["/app/treetop-server"]
