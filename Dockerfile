# Multi-stage minimal build for Aegis zero-trust agentic gateway
FROM golang:alpine AS builder

WORKDIR /app

# Enable automatic toolchain resolution & install build tools
ENV GOTOOLCHAIN=auto
RUN apk add --no-cache git ca-certificates

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binaries
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/bin/aegis ./cmd/aegis
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/bin/aegis-cloud ./cmd/aegis-cloud

# Production image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata sqlite

WORKDIR /etc/aegis

# Copy compiled binaries and presets
COPY --from=builder /app/bin/aegis /usr/local/bin/aegis
COPY --from=builder /app/bin/aegis-cloud /usr/local/bin/aegis-cloud
COPY policies /etc/aegis/policies

ENV AEGIS_PORT=8080
ENV AEGIS_DB_PATH=/etc/aegis/data/aegis.db
ENV AEGIS_POLICIES_DIR=/etc/aegis/policies

VOLUME ["/etc/aegis/data"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/aegis"]
CMD ["serve"]
