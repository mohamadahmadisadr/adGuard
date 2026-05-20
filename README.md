# DNS Proxy

A Docker-ready DNS blocker and HTTP/HTTPS MITM proxy for filtering ad and tracking traffic. It listens for DNS on port `53` and proxy traffic on port `8080`, loads domains from `blocklist.txt`, and creates a local root CA certificate (`ca.crt`) for HTTPS inspection.

> Important: this project performs HTTPS interception for devices that trust its CA certificate. Only install the certificate on devices you own or administer, and keep `ca.key` private.

## What It Does

- Runs a DNS server on UDP/TCP port `53`.
- Blocks domains from `blocklist.txt` and built-in ad domains.
- Redirects selected ad-related domains to the local proxy.
- Runs an HTTP/HTTPS MITM proxy on port `8080`.
- Creates `/app/certs/ca.crt` and `/app/certs/ca.key` automatically on first start.
- Uses Google DNS (`8.8.8.8:53`) as the upstream resolver.

## Requirements

- Docker and Docker Compose
- A machine/server that can accept traffic on:
  - `53/udp`
  - `53/tcp`
  - `8080/tcp`
- Your server's LAN or public IP address
- Admin access on client devices to install a trusted certificate

## Install With Docker Compose

This is the recommended installation method. It uses the published Docker image:

```text
ahmadisadr/dns-proxy:latest
```

1. Create a folder for the service:

```bash
mkdir dns-proxy
cd dns-proxy
```

2. Create a `.env` file with the IP address clients will use to reach this server:

```bash
LOCAL_IP=192.168.1.50
TZ=America/Toronto
```

Replace `192.168.1.50` with your server's actual IP address.

3. Create a `blocklist.txt` file:

```bash
touch blocklist.txt
```

You can add domains later, one per line:

```text
ads.example.com
tracker.example.com
0.0.0.0 bad-domain.example
```

4. Create `docker-compose.yml`:

```yaml
services:
  dns-proxy:
    image: ahmadisadr/dns-proxy:latest
    container_name: dns-proxy
    restart: unless-stopped
    user: root
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "8080:8080/tcp"
    environment:
      - LOCAL_IP=${LOCAL_IP}
      - TZ=${TZ:-America/Toronto}
    volumes:
      - ./blocklist.txt:/app/blocklist.txt:ro
      - certs:/app/certs
    healthcheck:
      test: ["CMD-SHELL", "nc -zuw1 127.0.0.1 53 && nc -zw1 127.0.0.1 8080"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 5s

volumes:
  certs:
    driver: local
```

5. Pull and start the service:

```bash
docker compose up -d
```

6. Check that it is running:

```bash
docker compose ps
docker logs -f dns-proxy
```

You should see log lines showing that the DNS server is running and the MITM proxy is listening on `:8080`.

## Install With Docker Run

If you prefer not to use Docker Compose, run the container directly.

1. Create a folder and blocklist file:

```bash
mkdir dns-proxy
cd dns-proxy
touch blocklist.txt
```

2. Create a Docker volume for the generated certificate files:

```bash
docker volume create dns-proxy-certs
```

3. Start the container:

```bash
docker run -d \
  --name dns-proxy \
  --restart unless-stopped \
  -e LOCAL_IP=192.168.1.50 \
  -e TZ=America/Toronto \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 8080:8080/tcp \
  -v "$(pwd)/blocklist.txt:/app/blocklist.txt:ro" \
  -v dns-proxy-certs:/app/certs \
  ahmadisadr/dns-proxy:latest
```

Replace `192.168.1.50` with the server IP that client devices can reach.

4. Check the logs:

```bash
docker logs -f dns-proxy
```

## Docker Hub Image

The published image is available here:

[https://hub.docker.com/r/ahmadisadr/dns-proxy](https://hub.docker.com/r/ahmadisadr/dns-proxy)

## Get The CA Certificate

The CA certificate is generated the first time the container starts. Copy it from the running container:

```bash
docker cp dns-proxy:/app/certs/ca.crt ./ca.crt
```

Confirm the file exists:

```bash
ls -l ca.crt
```

Keep the private key secure. Do not share this file:

```text
/app/certs/ca.key
```

## Install `ca.crt` On Client Devices

Install `ca.crt` as a trusted root certificate on every device or browser that will use the HTTPS proxy.

### macOS

1. Open **Keychain Access**.
2. Select **System** keychain.
3. Drag `ca.crt` into the certificate list.
4. Double-click the imported `dns-proxy CA` certificate.
5. Expand **Trust**.
6. Set **When using this certificate** to **Always Trust**.
7. Close the window and enter your password.

Command-line alternative:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt
```

### Windows

1. Double-click `ca.crt`.
2. Click **Install Certificate**.
3. Choose **Local Machine**.
4. Select **Place all certificates in the following store**.
5. Choose **Trusted Root Certification Authorities**.
6. Finish the wizard and confirm the security warning.

### Linux

Debian/Ubuntu:

```bash
sudo cp ca.crt /usr/local/share/ca-certificates/dns-proxy.crt
sudo update-ca-certificates
```

Fedora/RHEL:

```bash
sudo cp ca.crt /etc/pki/ca-trust/source/anchors/dns-proxy.crt
sudo update-ca-trust
```

### iPhone / iPad

1. Send `ca.crt` to the device using AirDrop, email, or a local file share.
2. Open the certificate and install the profile.
3. Go to **Settings > General > VPN & Device Management** and install the profile if prompted.
4. Go to **Settings > General > About > Certificate Trust Settings**.
5. Enable full trust for `dns-proxy CA`.

### Android

1. Copy `ca.crt` to the device.
2. Go to **Settings > Security > Encryption & credentials**.
3. Choose **Install a certificate** or **Install from storage**.
4. Select **CA certificate**.
5. Pick `ca.crt` and install it.

Some Android apps ignore user-installed CA certificates. Browser traffic usually works, but individual apps may require extra configuration or may not allow HTTPS inspection.

### Firefox

Firefox may use its own certificate store.

1. Open **Settings**.
2. Search for **Certificates**.
3. Click **View Certificates**.
4. Open the **Authorities** tab.
5. Click **Import**.
6. Select `ca.crt`.
7. Enable trust for identifying websites.

## Configure Client DNS And Proxy

Each client device must use this server for both DNS and proxy traffic.

Use your server IP from `.env`:

```text
DNS server: 192.168.1.50
HTTP proxy: 192.168.1.50
Proxy port: 8080
HTTPS proxy: 192.168.1.50
Proxy port: 8080
```

Replace `192.168.1.50` with your own `LOCAL_IP`.

### Router Setup

If your router supports custom DNS, set the router's DHCP DNS server to the DNS proxy server IP. This makes devices on the network automatically use the proxy server for DNS.

You still need to configure the HTTP/HTTPS proxy on each device or browser if you want HTTPS MITM filtering.

### Manual Device Setup

If you do not configure your router:

1. Open the Wi-Fi or network settings on the client device.
2. Set DNS manually to the server IP.
3. Set HTTP and HTTPS proxy manually to the server IP and port `8080`.
4. Install and trust `ca.crt`.

## Test The Installation

Check DNS from a client machine:

```bash
nslookup example.com 192.168.1.50
```

Check a blocked domain:

```bash
nslookup doubleclick.net 192.168.1.50
```

Check the proxy:

```bash
curl -x http://192.168.1.50:8080 https://example.com
```

If the CA is trusted correctly, HTTPS pages should load through the proxy without certificate warnings.

## Update The Blocklist

Edit `blocklist.txt`, then restart the container:

```bash
docker compose restart dns-proxy
```

Supported blocklist formats include plain domains and common hosts-file style entries:

```text
ads.example.com
0.0.0.0 tracker.example.com
||ads.example.net^
```

## Stop Or Remove

Stop the service:

```bash
docker compose down
```

Stop the service and remove the generated certificate volume:

```bash
docker compose down -v
```

Removing the volume deletes the generated `ca.crt` and `ca.key`. If you start again after deleting the volume, a new CA will be generated and you must reinstall the new `ca.crt` on clients.

## Troubleshooting

### Port 53 Is Already In Use

Another DNS service may already be using port `53`.

Check what is using the port:

```bash
sudo lsof -i :53
```

Stop the conflicting service or change the host port mapping in `docker-compose.yaml`.

### Certificate Warnings In The Browser

Make sure:

- `ca.crt` was copied after the container started.
- The certificate is installed as a trusted root CA.
- The browser is using the system trust store, or `ca.crt` was imported into the browser's own certificate store.
- The client is configured to use the proxy on port `8080`.

### DNS Works But HTTPS Filtering Does Not

DNS blocking and HTTPS filtering are separate.

Make sure:

- Client DNS points to the server IP.
- Client HTTP and HTTPS proxy settings point to the server IP and port `8080`.
- `ca.crt` is trusted on the client.
- `LOCAL_IP` is set to the IP address clients can actually reach.

### Container Cannot Start

View logs:

```bash
docker logs dns-proxy
```

Rebuild the image:

```bash
docker compose build --no-cache
docker compose up -d
```

## Run Without Docker

You can also run the proxy directly with Go:

```bash
go run . \
  -blocklist ./blocklist.txt \
  -ca-cert ./ca.crt \
  -ca-key ./ca.key \
  -dns-addr :53535 \
  -proxy-addr :8080 \
  -local-ip 192.168.1.50
```

Listening on port `53` usually requires root/admin privileges. For local testing, use `:53535`.

## Security Notes

- Anyone with `ca.key` can create certificates trusted by your devices.
- Do not commit `ca.key` to GitHub.
- Use this only on networks and devices you control.
- Remove the trusted CA from devices when you stop using this proxy.
