# Multi-stage minimal build for Aegis zero-trust agentic gateway
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build tools
RUN apk add --no-cache git ca-certificates

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/bin/aegis ./cmd/aegis

# Production image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata sqlite

WORKDIR /etc/aegis

# Copy compiled binary and presets
COPY --from=builder /app/bin/aegis /usr/local/bin/aegis
COPY policies /etc/aegis/policies

ENV AEGIS_PORT=8080
ENV AEGIS_DB_PATH=/etc/aegis/data/aegis.db
ENV AEGIS_POLICIES_DIR=/etc/aegis/policies

VOLUME ["/etc/aegis/data"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/aegis"]
CMD ["serve"]
