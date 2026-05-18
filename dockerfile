# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Cache dependencies first
COPY go.mod go.sum* ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o dns-proxy .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

# ca-certificates needed for upstream TLS (forwarding to google etc.)
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S proxy && adduser -S proxy -G proxy

WORKDIR /app

COPY --from=builder /build/dns-proxy .
COPY blocklist.txt .

# Create directory for generated CA certs, owned by proxy user
RUN mkdir -p /app/certs && chown proxy:proxy /app/certs

USER proxy

# DNS: UDP+TCP 53  |  MITM proxy: 8080
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080/tcp

ENTRYPOINT ["/app/dns-proxy"]
CMD [
"-blocklist", "/app/blocklist.txt",
"-ca-cert",   "/app/certs/ca.crt",
"-ca-key",    "/app/certs/ca.key",
"-dns-addr",  ":53",
"-proxy-addr",":8080"
]