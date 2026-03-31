# ssl-manager

Reusable Docker base image for in-container SSL certificate management with automatic HAProxy integration.

Any Docker service can inherit from this image to get:
- **Automatic SSL certificates** via Let's Encrypt (certbot, HTTP-01 challenge)
- **Automatic HAProxy registration** for domain-based routing (HTTP, HTTPS, WebSocket, custom ports)
- **Certificate auto-renewal** with background loop (~12h interval)
- **HTTP reverse proxy** on port 80 (serves ACME challenges, health endpoint, and proxies app traffic)

## Quick Start

### 1. Build the base image

```bash
docker build -t ssl-manager:latest .
```

### 2. Use it in your service's Dockerfile

```dockerfile
# Stage 1: Build your app (example)
FROM node:20-alpine AS builder
WORKDIR /app
COPY . .
RUN npm ci && npm run build

# Stage 2: Runtime — inherit from ssl-manager
FROM ssl-manager:latest

# Install your app's runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Copy your built app
COPY --from=builder /app/dist /app

# Your app's ports
EXPOSE 3000 443

# Your entrypoint calls ssl-setup first, then starts your app
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

### 3. Write your entrypoint

```bash
#!/bin/bash
set -euo pipefail

# Step 1: Run SSL setup (handles certs, HAProxy registration, proxy start)
/usr/local/bin/ssl-setup
ssl_exit=$?

# Source cert paths (written by ssl-setup)
if [ -f /tmp/.ssl-env ]; then
    source /tmp/.ssl-env
fi

# Step 2: Handle SSL_REQUIRED
if [ $ssl_exit -ne 0 ] && [ "${SSL_REQUIRED:-true}" = "true" ]; then
    echo "SSL setup failed (exit $ssl_exit) and SSL_REQUIRED=true"
    exit $ssl_exit
fi

# Step 3: Start your app
# SSL_CERT_FILE and SSL_KEY_FILE are set if SSL succeeded
if [ -n "${SSL_CERT_FILE:-}" ]; then
    echo "Starting with SSL: cert=$SSL_CERT_FILE"
    exec node /app/server.js --cert "$SSL_CERT_FILE" --key "$SSL_KEY_FILE"
else
    echo "Starting without SSL"
    exec node /app/server.js
fi
```

### 4. Run your container

```bash
# Without SSL (plain HTTP):
docker run -d --name my-service my-service:latest

# With SSL (automatic cert):
docker run -d --name my-service \
    --network haproxy-net \
    -v letsencrypt-data:/etc/letsencrypt \
    -e SSL_DOMAIN=myservice.example.com \
    -e SSL_ADMIN_EMAIL=admin@example.com \
    -e HAPROXY_HOST=haproxy \
    my-service:latest

# With SSL (direct, no HAProxy):
docker run -d --name my-service \
    -p 80:80 -p 443:443 \
    -v letsencrypt-data:/etc/letsencrypt \
    -e SSL_DOMAIN=myservice.example.com \
    -e SSL_ADMIN_EMAIL=admin@example.com \
    my-service:latest
```

## How It Works

### SSL Setup Flow

When your container starts with `SSL_DOMAIN` set:

```
Container starts
    │
    ├─ ssl-setup starts HTTP reverse proxy on port 80
    │   ├─ /.well-known/acme-challenge/* → certbot webroot
    │   ├─ /_ssl/health → cert status JSON
    │   └─ /* → your app on APP_HTTP_PORT (if set)
    │
    ├─ If HAPROXY_HOST set:
    │   ├─ Registers domain with HAProxy Registration API
    │   ├─ Waits for HAProxy to route traffic to this container
    │   └─ Verifies domain reachability via nonce endpoint
    │
    ├─ Certificate acquisition:
    │   ├─ Checks /etc/letsencrypt/live/$SSL_DOMAIN/
    │   ├─ If valid cert exists (>30 days remaining): reuse
    │   ├─ If SSL_TEST_MODE=true: generate self-signed cert
    │   └─ Otherwise: run certbot (webroot mode on port 80)
    │
    ├─ If HAPROXY_HOST set:
    │   └─ Re-registers with HTTPS port for TLS passthrough
    │
    ├─ Starts certificate renewal background loop
    │
    └─ Exports SSL_CERT_FILE and SSL_KEY_FILE
        → Your app reads these and starts with TLS
```

### HAProxy Integration

When `HAPROXY_HOST` is set, ssl-manager automatically registers your service with the [HAProxy Registration API](https://github.com/vrogojin/haproxy). This enables:

- **Domain-based HTTP routing** (Host header) on port 80
- **TLS passthrough** (SNI) on port 443
- **Extra ports** for non-standard protocols (WebSocket, TCP, etc.)

Registration payload:
```json
{
    "domain": "myservice.example.com",
    "container": "<container-hostname>",
    "http_port": 80,
    "https_port": 443,
    "extra_ports": [
        {"listen": 8080, "target": 8080, "mode": "http"},
        {"listen": 9443, "target": 9443, "mode": "tcp"}
    ]
}
```

### Certificate Renewal

A background loop runs every ~12 hours and calls `certbot renew`. When a certificate is renewed:
1. The deploy hook touches `/tmp/.ssl-renewal-restart`
2. Your entrypoint's supervisor loop detects this and restarts the app process
3. The app picks up the new certificate files

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SSL_DOMAIN` | No | (empty) | Domain for SSL. If unset, SSL is skipped entirely |
| `SSL_ADMIN_EMAIL` | No | (empty) | Email for Let's Encrypt. If unset, uses `--register-unsafely-without-email` |
| `SSL_REQUIRED` | No | `true` | If `true`, ssl-setup failure is fatal. If `false`, falls back to no-SSL |
| `SSL_HTTPS_PORT` | No | `443` | Backend port for HTTPS/TLS traffic via HAProxy |
| `SSL_CERT_RENEW_DAYS` | No | `30` | Renew cert if expiring within N days |
| `SSL_STAGING` | No | (empty) | Set to `true` for Let's Encrypt staging (test certs) |
| `SSL_TEST_MODE` | No | (empty) | Set to `true` to use self-signed cert (dev/CI only) |
| `HAPROXY_HOST` | No | (empty) | HAProxy container hostname. If unset, no HAProxy integration |
| `HAPROXY_API_PORT` | No | `8404` | HAProxy Registration API port |
| `HAPROXY_API_KEY` | No | (empty) | Bearer token for HAProxy API authentication |
| `APP_HTTP_PORT` | No | `0` | Your app's HTTP port behind the proxy. `0` = disabled |
| `EXTRA_PORTS` | No | (empty) | JSON array of extra port mappings for HAProxy |

## Provided Scripts

| Script | Purpose |
|--------|---------|
| `/usr/local/bin/ssl-setup` | Main orchestration (called once at startup) |
| `/usr/local/bin/ssl-renew` | Certificate renewal background loop |
| `/usr/local/bin/ssl-http-proxy` | HTTP reverse proxy on port 80 |
| `/usr/local/bin/haproxy-register` | HAProxy registration client (`register`/`unregister`) |
| `/usr/local/bin/ssl-verify` | Domain reachability verification (`http`/`https`) |

## Provided Endpoints (port 80)

| Path | Method | Description |
|------|--------|-------------|
| `/.well-known/acme-challenge/*` | GET | Certbot HTTP-01 challenge files |
| `/_ssl/health` | GET | Certificate status JSON (domain, expiry, days remaining) |
| `/_ssl/nonce/{nonce}` | GET/POST/DELETE | Nonce management for domain verification |
| `/*` | * | Reverse proxy to `APP_HTTP_PORT` (if configured) |

## Exit Codes (ssl-setup)

| Code | Meaning |
|------|---------|
| 0 | Success (or SSL_DOMAIN not set) |
| 10 | Domain not reachable at port 80 |
| 11 | Certbot failed |
| 12 | TLS verification failed |
| 13 | HAProxy registration failed |
| 14 | HAProxy reload failed |

## Integration Examples

### Example: Node.js Web App

```dockerfile
FROM ssl-manager:latest
RUN apt-get update && apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*
COPY app/ /app/
EXPOSE 3000 443
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

```bash
docker run -d --name webapp --network haproxy-net \
    -v letsencrypt-data:/etc/letsencrypt \
    -e SSL_DOMAIN=webapp.example.com \
    -e SSL_ADMIN_EMAIL=admin@example.com \
    -e SSL_HTTPS_PORT=3000 \
    -e HAPROXY_HOST=haproxy \
    webapp:latest
```

### Example: Python Flask API

```dockerfile
FROM ssl-manager:latest
RUN apt-get update && apt-get install -y python3-pip && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY app/ /app/
EXPOSE 5000
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

### Example: Go Binary with Custom TCP Port

```dockerfile
FROM golang:1.22 AS builder
COPY . .
RUN go build -o /server ./cmd/server

FROM ssl-manager:latest
COPY --from=builder /server /usr/local/bin/server
EXPOSE 9090 443
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

With extra ports for a custom TCP protocol:
```bash
docker run -d --name myserver --network haproxy-net \
    -v letsencrypt-data:/etc/letsencrypt \
    -e SSL_DOMAIN=myserver.example.com \
    -e SSL_HTTPS_PORT=9090 \
    -e HAPROXY_HOST=haproxy \
    -e 'EXTRA_PORTS=[{"listen":9090,"target":9090,"mode":"tcp"}]' \
    myserver:latest
```

### Example: Sharing Port 80 with Your App

If your app serves HTTP on port 80, ssl-manager's proxy forwards non-SSL traffic to it:

```bash
-e APP_HTTP_PORT=8080  # Your app listens on 8080 internally
```

The proxy on port 80 handles:
- `/.well-known/acme-challenge/*` → certbot
- `/_ssl/*` → ssl-manager
- Everything else → your app on port 8080

## Requirements

- Docker 20.10+ (for `--add-host host-gateway`)
- For HAProxy integration: [HAProxy with Registration API](https://github.com/vrogojin/haproxy) on `haproxy-net`
- For real SSL: a publicly reachable domain pointing to your server
- For testing: use `SSL_TEST_MODE=true` for self-signed certs

## Multi-Network Setup

When using HAProxy, your container needs to be on the HAProxy network. Use `docker create` + `docker network connect` + `docker start` to avoid routing race conditions:

```bash
docker create --name my-service --network haproxy-net \
    -e SSL_DOMAIN=... -e HAPROXY_HOST=haproxy \
    my-service:latest

# Connect additional networks BEFORE starting
docker network connect my-app-net my-service

# Now start — all networks are ready when the entrypoint runs
docker start my-service
```

## License

MIT
