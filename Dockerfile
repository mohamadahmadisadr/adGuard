# ── Build stage ─────────────────────────────────────────────
FROM golang:latest AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o dnsproxy .

# ── Runtime stage ───────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S proxy && adduser -S proxy -G proxy

WORKDIR /app

# copy binary + blocklist
COPY --from=builder /build/dnsproxy .
COPY blocklist.txt .

# create cert directory BEFORE switching user
RUN mkdir -p /app/certs && \
    chown -R proxy:proxy /app && \
    chmod -R 755 /app

# IMPORTANT: switch user AFTER permissions are fixed
USER proxy

EXPOSE 53:53/udp
EXPOSE 53:53/tcp
EXPOSE 8080:8080/tcp

ENTRYPOINT ["/app/dnsproxy"]

CMD ["/app/dnsproxy", "-blocklist", "/app/blocklist.txt", "-ca-cert", "/app/certs/ca.crt", "-ca-key", "/app/certs/ca.key", "-dns-addr", ":53", "-proxy-addr", ":8080"]