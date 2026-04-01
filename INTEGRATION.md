# ssl-manager Integration Guide

A step-by-step guide for adding automatic SSL certificate management and HAProxy auto-registration to any Docker-based service.

**Audience:** Engineers with an existing Docker-based service who want to add production TLS with minimal effort.

**What you get:** Your container obtains its own Let's Encrypt certificate, registers itself with an HAProxy reverse proxy for domain-based routing, and renews certificates automatically in the background -- all without changes to your application code.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Step 1: Update Your Dockerfile](#step-1-update-your-dockerfile)
3. [Step 2: Write Your Entrypoint](#step-2-write-your-entrypoint)
4. [Step 3: Create Your Run Script](#step-3-create-your-run-script)
5. [Step 4: Configure HAProxy](#step-4-configure-haproxy)
6. [Step 5: Deploy](#step-5-deploy)
7. [Step 6: Verify](#step-6-verify)
8. [Complete Examples](#complete-examples)
9. [Environment Variable Reference](#environment-variable-reference)
10. [run-lib.sh Hook Reference](#run-libsh-hook-reference)
11. [Certificate Renewal](#certificate-renewal)
12. [Multi-Network Docker Routing](#multi-network-docker-routing)
13. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, you need:

1. **Docker 20.10+** installed and running.
2. **A domain name** pointing to your server's public IP (for real certificates). For development, you can use `SSL_TEST_MODE=true` to generate self-signed certificates without a domain.
3. **HAProxy with the Registration API** (optional but recommended). This is the [unicitynetwork/haproxy](https://github.com/unicitynetwork/haproxy) image that provides a REST API for dynamic backend registration. Without it, your container must bind ports 80 and 443 directly.
4. **The ssl-manager base image**, either:
   - Pull from registry: `docker pull ghcr.io/unicitynetwork/ssl-manager:latest`
   - Build locally: `cd ssl-manager && docker build -t ssl-manager:latest .`

---

## Step 1: Update Your Dockerfile

Change your runtime stage to inherit from the ssl-manager base image instead of a bare OS image. The ssl-manager image is based on `debian:trixie-slim` and includes certbot, openssl, curl, jq, netcat, python3, and procps.

### Before

```dockerfile
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y your-deps
COPY myapp /usr/local/bin/myapp
ENTRYPOINT ["/entrypoint.sh"]
```

### After

```dockerfile
FROM ghcr.io/unicitynetwork/ssl-manager:latest

# Install ONLY your app's runtime dependencies.
# ssl-manager already provides: certbot, openssl, curl, jq, netcat, python3, procps, ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
        your-runtime-deps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY myapp /usr/local/bin/myapp

# Expose your app's ports. Port 80 is already EXPOSE'd by ssl-manager.
EXPOSE 3000 443

# Volumes: /etc/letsencrypt is already declared by ssl-manager.
# Add your own data volume if needed.
VOLUME ["/data"]

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

### Multi-Stage Build Pattern

If your app has a build step, use a multi-stage build. The first stage compiles your app; the second stage inherits from ssl-manager and copies in the compiled binary.

```dockerfile
# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Runtime
FROM ghcr.io/unicitynetwork/ssl-manager:latest
RUN apt-get update && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/dist /app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 3000 443
ENTRYPOINT ["/entrypoint.sh"]
```

### What the Base Image Provides

The ssl-manager base image installs the following scripts into `/usr/local/bin/`:

| Script | Purpose |
|--------|---------|
| `ssl-setup` | Main orchestration -- called once at container startup |
| `ssl-renew` | Background renewal loop (started by ssl-setup) |
| `ssl-http-proxy` | Python HTTP reverse proxy on port 80 |
| `haproxy-register` | HAProxy Registration API client |
| `ssl-verify` | Domain reachability and TLS verification |

It also creates the ACME webroot directory at `/var/www/acme-challenge/` and declares a volume at `/etc/letsencrypt`.

---

## Step 2: Write Your Entrypoint

Your entrypoint script is the bridge between ssl-manager and your application. It follows a three-step pattern:

1. Call `ssl-setup` to obtain certificates and register with HAProxy.
2. Source `/tmp/.ssl-env` to get the certificate file paths.
3. Start your application, passing cert paths if SSL succeeded.

### Minimal Entrypoint

```bash
#!/bin/bash
set -e

# ── Step 1: SSL setup ────────────────────────────────────────────────────────
ssl_setup_exit=0
/usr/local/bin/ssl-setup || ssl_setup_exit=$?

# ── Step 2: Source certificate paths ─────────────────────────────────────────
if [ -f /tmp/.ssl-env ]; then
    . /tmp/.ssl-env
    echo "SSL configured: cert=${SSL_CERT_FILE}"
fi

# ── Step 3: Handle failure ───────────────────────────────────────────────────
if [ $ssl_setup_exit -ne 0 ] && [ "${SSL_REQUIRED:-true}" = "true" ]; then
    echo "ERROR: SSL setup failed (exit $ssl_setup_exit) and SSL_REQUIRED=true"
    exit $ssl_setup_exit
fi

# ── Step 4: Start your app ──────────────────────────────────────────────────
if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "${SSL_CERT_FILE}" ]; then
    exec myapp --cert "$SSL_CERT_FILE" --key "$SSL_KEY_FILE"
else
    exec myapp --no-tls
fi
```

### What ssl-setup Does

When your entrypoint calls `/usr/local/bin/ssl-setup`, the following happens in order:

1. If `SSL_DOMAIN` is not set, ssl-setup exits 0 immediately (TCP-only mode).
2. Starts the HTTP reverse proxy on port 80 (serves ACME challenges, health endpoint, and optional app proxying).
3. If `HAPROXY_HOST` is set (or auto-detected via DNS), registers the container with HAProxy for HTTP routing on this domain. Uses exponential backoff with retries.
4. Verifies domain reachability by posting a random nonce to the local proxy, then fetching it through the public domain name. This proves that traffic for `SSL_DOMAIN` reaches this container.
5. Checks for an existing valid certificate in `/etc/letsencrypt/live/$SSL_DOMAIN/`. If valid and not expiring within `SSL_CERT_RENEW_DAYS` (default 30), reuses it. Otherwise, runs certbot (or generates a self-signed cert if `SSL_TEST_MODE=true`).
6. Verifies the TLS certificate by starting a temporary openssl s_server and connecting to it.
7. Re-registers with HAProxy, this time including the HTTPS port for TLS passthrough (SNI-based routing).
8. Starts the background certificate renewal loop.
9. Writes `SSL_CERT_FILE` and `SSL_KEY_FILE` to `/tmp/.ssl-env`.

### Exit Codes

| Code | Meaning | Recommended Action |
|------|---------|--------------------|
| 0 | Success (or `SSL_DOMAIN` not set) | Proceed normally |
| 10 | Domain not reachable (nonce verification failed) | Check DNS, HAProxy routing, firewall |
| 11 | Certbot failed | Check rate limits, domain validation, certbot log at `/tmp/certbot.log` |
| 12 | TLS verification failed | Certificate may be corrupt |
| 13 | HAProxy registration failed | Check HAProxy is running, API key is correct, network connectivity |
| 14 | HAProxy reload failed | HAProxy configuration error |

### The SSL_REQUIRED Flag

The `SSL_REQUIRED` environment variable (default: `true`) controls whether SSL failure is fatal:

- `SSL_REQUIRED=true` (default): If ssl-setup fails, your entrypoint should exit with the error code. The container will not start.
- `SSL_REQUIRED=false`: If ssl-setup fails, your entrypoint should log a warning and start the app without TLS. This is useful for services that can operate in TCP-only mode.

### Handling Graceful Shutdown

If your app needs to deregister from HAProxy on shutdown, add signal handling:

```bash
handle_shutdown() {
    echo "Shutting down..."
    if [ -n "${SSL_DOMAIN:-}" ] && [ -n "${HAPROXY_HOST:-}" ]; then
        haproxy-register unregister 2>/dev/null || true
    fi
    # Stop SSL background processes
    [ -f /tmp/.ssl-http-proxy.pid ] && kill "$(cat /tmp/.ssl-http-proxy.pid)" 2>/dev/null || true
    [ -f /tmp/.ssl-renew.pid ] && kill "$(cat /tmp/.ssl-renew.pid)" 2>/dev/null || true
    # Forward signal to app
    kill -TERM "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null
    exit 0
}

trap 'handle_shutdown' SIGTERM SIGINT
```

---

## Step 3: Create Your Run Script

The run script lives on the **host** machine (not inside the container). It handles `docker create`, network setup, container startup, and health checks. The `run-lib.sh` library provides all of this in a reusable pattern -- you just implement hooks.

### Obtaining run-lib.sh

Copy `run-lib.sh` from the ssl-manager repository into your project's docker directory:

```bash
curl -o docker/run-lib.sh \
  https://raw.githubusercontent.com/unicitynetwork/ssl-manager/master/run-lib.sh
```

### Run Script Structure

```bash
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── App identity (set BEFORE sourcing) ───────────────────────────────────────
CONTAINER_NAME="${CONTAINER_NAME:-my-service}"
IMAGE_NAME="${MY_IMAGE:-my-service:latest}"
APP_TITLE="My Service"

# ── App networking ───────────────────────────────────────────────────────────
APP_NET="${APP_NET:-my-app-net}"          # Your app's Docker network
DATA_VOLUME="${DATA_VOLUME:-my-data}"     # Persistent data volume
HEALTH_PORT=3000                          # Primary port to poll for readiness
SSL_CHECK_PORT=3443                       # SSL port to verify (optional)
SSL_HTTPS_PORT="${SSL_HTTPS_PORT:-3443}"  # Backend HTTPS port for HAProxy
APP_HTTP_PORT="${APP_HTTP_PORT:-8080}"    # App HTTP port behind ssl-manager proxy

# ── Source the library ───────────────────────────────────────────────────────
source "${SCRIPT_DIR}/run-lib.sh"

# ── App-specific hooks (all optional) ────────────────────────────────────────

app_parse_args() {
    case "$1" in
        --db-host) require_arg "$1" "${2:-}"; DB_HOST="$2"; return 2 ;;
        *) return 0 ;;
    esac
}

app_env_args() {
    echo "-e DB_HOST=${DB_HOST:-localhost}"
    echo "-e DB_PORT=${DB_PORT:-5432}"
}

app_port_args() {
    echo "-p 3000:3000"
    echo "-p 3443:3443"
}

app_health_check() {
    local container="$1"
    local resp
    resp=$(docker exec "$container" curl -sf localhost:3000/health 2>/dev/null)
    if [ -n "$resp" ]; then
        echo "pass:Health endpoint OK"
    else
        echo "fail:Health endpoint not responding"
    fi
}

app_summary() {
    echo ""
    echo "Endpoints:"
    if [ "$USE_HAPROXY" = true ] && [ -n "$HAPROXY_HOST" ] && [ -n "$SSL_DOMAIN" ]; then
        echo "  HTTPS: https://$SSL_DOMAIN"
    else
        echo "  HTTP:  http://localhost:3000"
    fi
}

# ── Run ──────────────────────────────────────────────────────────────────────
ssl_manager_run "$@"
```

### Variables to Set Before Sourcing

These variables must be set **before** `source run-lib.sh`:

| Variable | Required | Description |
|----------|----------|-------------|
| `CONTAINER_NAME` | Yes | Docker container name |
| `IMAGE_NAME` | Yes | Docker image name:tag |
| `APP_TITLE` | No | Display title for the startup banner |
| `APP_NET` | No | App-specific Docker network name |
| `DATA_VOLUME` | No | Data volume name (mounted at `/data`) |
| `HEALTH_PORT` | No | Port to poll for readiness (default: 80) |
| `SSL_CHECK_PORT` | No | SSL port to check after startup |
| `SSL_HTTPS_PORT` | No | Backend HTTPS port for HAProxy (default: 443) |
| `APP_HTTP_PORT` | No | App HTTP port behind proxy (default: 0 = disabled) |

### What ssl_manager_run Does

When you call `ssl_manager_run "$@"` at the end of your script, the library:

1. **Parses CLI arguments** -- both ssl-manager's built-in flags and your `app_parse_args` hook.
2. **Validates** ports and domain format, then calls your `app_validate` hook.
3. **Prints configuration** banner with container name, image, SSL domain, HAProxy status, and your `app_print_config` output.
4. **Sets up Docker networks** (`APP_NET` and `HAPROXY_NET` if using HAProxy).
5. **Stops any existing container** with the same name.
6. **Creates and starts the container** using the `docker create` + `docker network connect` + `docker start` pattern (see [Multi-Network Docker Routing](#multi-network-docker-routing)).
7. **Waits for readiness** by polling `HEALTH_PORT` with TCP connect, up to `HEALTH_TIMEOUT` seconds.
8. **Runs health checks** -- built-in SSL checks plus your `app_health_check` hook.
9. **Prints summary** with pass/warn/fail counts and your `app_summary` output.

---

## Step 4: Configure HAProxy

If you want domain-based routing (multiple services sharing ports 80/443), you need HAProxy with the Registration API.

### Start HAProxy

```bash
docker network create haproxy-net

docker run -d \
    --name haproxy \
    --network haproxy-net \
    -p 80:80 -p 443:443 \
    -v haproxy-data:/etc/haproxy \
    ghcr.io/unicitynetwork/haproxy:latest
```

### How Registration Works

When your container starts with `HAPROXY_HOST=haproxy`:

1. **HTTP registration** -- ssl-setup sends a POST to `http://haproxy:8404/v1/backends` with `https_port: null`. HAProxy begins routing `Host: yourdomain.com` traffic on port 80 to your container's port 80.
2. **Nonce verification** -- ssl-setup generates a random nonce, stores it in the local HTTP proxy, and fetches it through the public domain. This proves HAProxy is routing correctly.
3. **Certificate acquisition** -- certbot requests a certificate. Let's Encrypt sends the HTTP-01 challenge to your domain, which HAProxy routes to your container, which the HTTP proxy serves from the webroot.
4. **HTTPS re-registration** -- After the certificate is obtained, ssl-setup re-registers with `https_port: 50002` (or whatever `SSL_HTTPS_PORT` is). HAProxy begins SNI-based TLS passthrough on port 443.

### Registration Payload

```json
{
    "domain": "myservice.example.com",
    "container": "abc123def456",
    "http_port": 80,
    "https_port": 443,
    "extra_ports": [
        {"listen": 8080, "target": 8080, "mode": "http"},
        {"listen": 9443, "target": 9443, "mode": "tcp"}
    ]
}
```

### Extra Ports

If your service uses non-standard ports (WebSocket, TCP protocols, etc.), pass them via `EXTRA_PORTS`:

```bash
-e 'EXTRA_PORTS=[{"listen":50001,"target":50001,"mode":"tcp"},{"listen":50003,"target":50003,"mode":"http"}]'
```

HAProxy will create listeners on these ports and route traffic to your container.

### API Authentication

If your HAProxy requires authentication:

```bash
-e HAPROXY_API_KEY=your-secret-token
```

This sends `Authorization: Bearer your-secret-token` with all API requests.

### Without HAProxy (Direct Mode)

If you do not use HAProxy, set `--no-haproxy` and bind ports directly:

```bash
./run-myservice.sh --domain myservice.example.com --no-haproxy
```

In this mode, run-lib.sh publishes your app's ports via `app_port_args()` and binds port 80 for the ACME proxy. Your server must be directly reachable on port 80 for certificate validation.

---

## Step 5: Deploy

### Build Your Image

```bash
docker build -t my-service:latest .
```

### Run with SSL and HAProxy

```bash
./run-myservice.sh \
    --domain myservice.example.com \
    --ssl-email admin@example.com
```

### Run without SSL (TCP only)

```bash
./run-myservice.sh --no-ssl
```

### Run with SSL, No HAProxy (Direct Ports)

```bash
./run-myservice.sh \
    --domain myservice.example.com \
    --ssl-email admin@example.com \
    --no-haproxy
```

### Run with Self-Signed Certificate (Development/CI)

```bash
./run-myservice.sh \
    --domain myservice.local \
    --ssl-test-mode \
    --no-haproxy
```

### Run with Let's Encrypt Staging (Rate Limit Testing)

```bash
./run-myservice.sh \
    --domain myservice.example.com \
    --ssl-staging
```

---

## Step 6: Verify

### Check Container Logs

```bash
docker logs -f my-service
```

Look for these key log lines:

```
[ssl-setup] Starting SSL setup for domain: myservice.example.com
[ssl-setup] HTTP reverse proxy ready (PID 42)
[ssl-setup] Registered with HAProxy (HTTP-only, status=201)
[ssl-setup] Domain reachability confirmed
[ssl-setup] Certificate acquired from Let's Encrypt
[ssl-setup] TLS verification passed: subject=CN = myservice.example.com
[ssl-setup] Re-registered with HAProxy (HTTPS port=443, status=200)
[ssl-setup] SSL setup complete for myservice.example.com
```

### Check Certificate Status

```bash
# Via health endpoint (from inside the container)
docker exec my-service curl -s localhost:80/_ssl/health | jq .

# Via certbot
docker exec my-service certbot certificates

# Via openssl
docker exec my-service openssl x509 -enddate -noout \
    -in /etc/letsencrypt/live/myservice.example.com/fullchain.pem
```

### Verify SSL Externally

```bash
# Check TLS handshake
openssl s_client -connect myservice.example.com:443 -servername myservice.example.com </dev/null 2>/dev/null | \
    openssl x509 -noout -subject -enddate

# From inside the container
docker exec my-service ssl-verify https
```

### Check HAProxy Registration

```bash
curl -s http://haproxy:8404/v1/backends | jq .
```

---

## Complete Examples

### Example 1: Node.js Express App

**Dockerfile:**

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .

FROM ghcr.io/unicitynetwork/ssl-manager:latest
RUN apt-get update && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app /app
WORKDIR /app

EXPOSE 3000 3443
VOLUME ["/data"]

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "server.js"]
```

**docker/entrypoint.sh:**

```bash
#!/bin/bash
set -e

# SSL setup
ssl_exit=0
/usr/local/bin/ssl-setup || ssl_exit=$?

if [ -f /tmp/.ssl-env ]; then
    . /tmp/.ssl-env
fi

if [ $ssl_exit -ne 0 ] && [ "${SSL_REQUIRED:-true}" = "true" ]; then
    echo "SSL setup failed (exit $ssl_exit)"
    exit $ssl_exit
fi

# Export cert paths as env vars for the Node.js app
export SSL_CERT="${SSL_CERT_FILE:-}"
export SSL_KEY="${SSL_KEY_FILE:-}"

exec "$@"
```

**server.js (relevant excerpt):**

```javascript
const https = require('https');
const http = require('http');
const fs = require('fs');
const app = require('./app');

// Always start HTTP
http.createServer(app).listen(3000, () => {
    console.log('HTTP listening on :3000');
});

// Start HTTPS if certs are available
if (process.env.SSL_CERT && fs.existsSync(process.env.SSL_CERT)) {
    const options = {
        cert: fs.readFileSync(process.env.SSL_CERT),
        key: fs.readFileSync(process.env.SSL_KEY),
    };
    https.createServer(options, app).listen(3443, () => {
        console.log('HTTPS listening on :3443');
    });
}
```

**docker/run-myapp.sh:**

```bash
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONTAINER_NAME="${CONTAINER_NAME:-my-express-app}"
IMAGE_NAME="${IMAGE_NAME:-my-express-app:latest}"
APP_TITLE="Express App"

APP_NET="${APP_NET:-app-net}"
DATA_VOLUME="${DATA_VOLUME:-express-data}"
HEALTH_PORT=3000
SSL_CHECK_PORT=3443
SSL_HTTPS_PORT="${SSL_HTTPS_PORT:-3443}"

source "${SCRIPT_DIR}/run-lib.sh"

app_port_args() {
    echo "-p 3000:3000"
    echo "-p 3443:3443"
}

app_health_check() {
    local container="$1"
    local resp
    resp=$(docker exec "$container" curl -sf http://localhost:3000/health 2>/dev/null)
    [ -n "$resp" ] && echo "pass:HTTP health OK" || echo "fail:HTTP health not responding"
}

ssl_manager_run "$@"
```

### Example 2: Python Flask API

**Dockerfile:**

```dockerfile
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

FROM ghcr.io/unicitynetwork/ssl-manager:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /app /app

EXPOSE 5000 5443
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

**docker/entrypoint.sh:**

```bash
#!/bin/bash
set -e

ssl_exit=0
/usr/local/bin/ssl-setup || ssl_exit=$?

if [ -f /tmp/.ssl-env ]; then
    . /tmp/.ssl-env
fi

if [ $ssl_exit -ne 0 ] && [ "${SSL_REQUIRED:-true}" = "true" ]; then
    exit $ssl_exit
fi

if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "${SSL_CERT_FILE}" ]; then
    exec gunicorn app:app \
        --bind 0.0.0.0:5000 \
        --bind 0.0.0.0:5443 \
        --certfile "$SSL_CERT_FILE" \
        --keyfile "$SSL_KEY_FILE"
else
    exec gunicorn app:app --bind 0.0.0.0:5000
fi
```

### Example 3: Fulcrum-Alpha (Real-World Implementation)

The Fulcrum-Alpha SPV server is a production example of ssl-manager integration. Key files:

- **Dockerfile:** `/home/vrogojin/Fulcrum-Alpha/docker/Dockerfile` -- Multi-stage build with C++ compilation in stage 1, `FROM ghcr.io/unicitynetwork/ssl-manager:latest` in stage 2.
- **Entrypoint:** `/home/vrogojin/Fulcrum-Alpha/docker/docker-entrypoint.sh` -- Full supervisor loop with crash recovery, database corruption detection, and SSL certificate renewal restart handling.
- **Run script:** `/home/vrogojin/Fulcrum-Alpha/docker/run-fulcrum.sh` -- Sources `run-lib.sh`, implements all hooks including `app_health_check` that tests the Electrum protocol.

Key patterns from the Fulcrum integration:

1. **Non-standard HTTPS port:** Fulcrum listens for Electrum SSL on port 50002, not 443. Set via `SSL_HTTPS_PORT=50002`.
2. **No HTTP app traffic:** Fulcrum does not serve HTTP, so `APP_HTTP_PORT=0` (the proxy only handles ACME challenges and health).
3. **Extra ports for HAProxy:** Four Electrum protocol ports (TCP, SSL, WS, WSS) are registered via `EXTRA_PORTS`.
4. **Supervisor loop:** The entrypoint monitors Fulcrum, restarts it on crash with exponential backoff, and detects database corruption patterns in log output.
5. **SSL renewal restart:** The supervisor loop checks for `/tmp/.ssl-renewal-restart` and regenerates the config file with new cert paths before restarting Fulcrum.

---

## Environment Variable Reference

### SSL Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SSL_DOMAIN` | _(empty)_ | Domain name for the SSL certificate. If unset, SSL is skipped entirely and ssl-setup exits 0. |
| `SSL_ADMIN_EMAIL` | _(empty)_ | Email address for Let's Encrypt registration. If unset, certbot registers without email (`--register-unsafely-without-email`). |
| `SSL_REQUIRED` | `true` | When `true`, ssl-setup failure is fatal (your entrypoint should exit). When `false`, the app can fall back to no-SSL mode. |
| `SSL_HTTPS_PORT` | `443` | The port your application listens on for TLS traffic. HAProxy performs SNI-based TLS passthrough to this port. |
| `SSL_CERT_RENEW_DAYS` | `30` | Renew the certificate if it expires within this many days. |
| `SSL_STAGING` | _(empty)_ | Set to `true` to use Let's Encrypt staging environment (test certificates that browsers reject, but no rate limits). |
| `SSL_TEST_MODE` | _(empty)_ | Set to `true` to generate a self-signed certificate instead of using certbot. For development and CI only. |
| `SSL_SKIP_VERIFY` | `false` | Set to `true` to skip the TLS verification step after certificate acquisition. |

### HAProxy Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `HAPROXY_HOST` | _(empty)_ | Hostname of the HAProxy container. If set, ssl-manager registers the service with HAProxy. If unset and a container named `haproxy` is resolvable via DNS, it is auto-detected. |
| `HAPROXY_API_PORT` | `8404` | Port for the HAProxy Registration API. |
| `HAPROXY_API_KEY` | _(empty)_ | Bearer token for API authentication. Sent as `Authorization: Bearer <key>`. |
| `EXTRA_PORTS` | _(empty)_ | JSON array of extra port mappings for HAProxy. Each entry: `{"listen": <int>, "target": <int>, "mode": "tcp"|"http"}`. |

### Application Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_HTTP_PORT` | `0` | Your app's HTTP port. The ssl-manager HTTP proxy on port 80 forwards non-ACME, non-ssl-manager requests to this port. Set to `0` to disable app proxying. Must not be `80` or `8404`. |

### run-lib.sh Configuration (Host-Side)

| Variable | Default | Description |
|----------|---------|-------------|
| `HAPROXY_NET` | `haproxy-net` | Docker network name for HAProxy communication. |
| `LETSENCRYPT_VOLUME` | `letsencrypt-data` | Docker volume name for Let's Encrypt certificate storage. |
| `HEALTH_TIMEOUT` | `120` | Seconds to wait for `HEALTH_PORT` to become available. |

---

## run-lib.sh Hook Reference

All hooks are optional. Implement them in your run script between `source run-lib.sh` and `ssl_manager_run "$@"`.

### app_parse_args

```bash
app_parse_args() {
    # Called for each CLI argument not recognized by run-lib.sh.
    # Return N (via exit code) to indicate N arguments consumed.
    # Return 0 if the argument is not recognized.
    case "$1" in
        --my-flag)    require_arg "$1" "${2:-}"; MY_VAR="$2"; return 2 ;;
        --my-switch)  MY_BOOL=true; return 1 ;;
        *)            return 0 ;;
    esac
}
```

**Return convention:** Return 0 means "not my argument, try the next parser." Return N > 0 means "I consumed N arguments." The `require_arg` helper validates that the next argument exists and is not another flag.

### app_env_args

```bash
app_env_args() {
    # Print one `-e KEY=VALUE` per line. These are passed to docker create.
    echo "-e MY_VAR=${MY_VAR:-default}"
    echo "-e MY_SECRET=${MY_SECRET}"
}
```

### app_port_args

```bash
app_port_args() {
    # Print one `-p host:container` per line.
    # Only used in direct mode (--no-haproxy). When HAProxy is active,
    # these are silently ignored because HAProxy owns all port bindings.
    echo "-p 3000:3000"
    echo "-p 3443:3443"
}
```

### app_docker_args

```bash
app_docker_args() {
    # Print additional docker create flags, one per line.
    echo "--dns 8.8.8.8"
    echo "--memory 2g"
    echo "--cpus 2"
}
```

### app_validate

```bash
app_validate() {
    # Called after all arguments are parsed. Validate custom args here.
    # Exit with error if validation fails.
    validate_port "MY_PORT" "$MY_PORT"
    if [ -z "$MY_REQUIRED_VAR" ]; then
        echo "ERROR: --my-required is required" >&2
        exit 1
    fi
}
```

### app_print_config

```bash
app_print_config() {
    # Print additional config lines in the startup banner.
    echo "  Database:   $DB_HOST:$DB_PORT"
    echo "  Workers:    $NUM_WORKERS"
}
```

### app_help

```bash
app_help() {
    # Print app-specific help section (shown after run-lib.sh's built-in help).
    cat <<'HELP'
Application Options:
  --db-host <host>    Database hostname (default: localhost)
  --workers <n>       Number of worker processes (default: 4)
HELP
}
```

### app_health_check

```bash
app_health_check() {
    local container="$1"
    # Print one result per line in the format "level:message"
    # Levels: pass, warn, fail
    #
    # Example: check a health endpoint
    local resp
    resp=$(docker exec "$container" curl -sf localhost:3000/health 2>/dev/null)
    if [ -n "$resp" ]; then
        echo "pass:Health endpoint OK"
    else
        echo "fail:Health endpoint not responding"
    fi

    # Example: check database connectivity
    if docker exec "$container" pg_isready -h localhost 2>/dev/null; then
        echo "pass:Database connected"
    else
        echo "warn:Database not reachable"
    fi
}
```

### app_needs_host_gateway

```bash
app_needs_host_gateway() {
    # Return 0 (success) if the container needs --add-host=host.docker.internal:host-gateway
    # This is needed when the app connects to services on the Docker host.
    [ "$DB_HOST" = "host.docker.internal" ]
}
```

### app_summary

```bash
app_summary() {
    # Print app-specific information after all health checks complete.
    echo ""
    echo "Endpoints:"
    echo "  API:   https://$SSL_DOMAIN/api"
    echo "  Admin: docker exec $CONTAINER_NAME my-admin-tool status"
}
```

---

## Certificate Renewal

### How It Works

After ssl-setup completes, it starts `/usr/local/bin/ssl-renew` as a background process. This process:

1. Waits 1 hour after container startup (to avoid renewal checks during initial configuration).
2. Runs `certbot renew` every ~12 hours (with random jitter of 0--30 minutes to avoid thundering herd).
3. Uses certbot's `--deploy-hook` to touch `/tmp/.ssl-renewal-restart` when a certificate is actually renewed.

### What Your App Needs to Do

When a certificate is renewed, the cert files on disk are updated, but your application is still using the old certificate in memory. You need to reload the certificate. There are two approaches:

**Approach 1: Watch the restart marker (recommended for long-running processes)**

Your supervisor loop checks for `/tmp/.ssl-renewal-restart` and restarts the app:

```bash
while true; do
    if [ -f /tmp/.ssl-renewal-restart ]; then
        echo "Certificate renewed, restarting app..."
        rm -f /tmp/.ssl-renewal-restart
        # Re-source cert paths
        [ -f /tmp/.ssl-env ] && . /tmp/.ssl-env
        # Kill and restart the app
        kill "$APP_PID" 2>/dev/null
    fi

    if ! kill -0 "$APP_PID" 2>/dev/null; then
        myapp --cert "$SSL_CERT_FILE" --key "$SSL_KEY_FILE" &
        APP_PID=$!
    fi

    sleep 30
done
```

**Approach 2: Application-level reload (if your app supports it)**

Some applications (e.g., nginx, HAProxy) can reload certificates without restart. In this case, you can add a certbot deploy hook that triggers the reload:

```bash
certbot renew --deploy-hook "kill -HUP $(cat /var/run/myapp.pid)"
```

### Self-Signed Mode

When `SSL_TEST_MODE=true`, the renewal loop sleeps indefinitely. Self-signed certificates are generated with a 365-day validity and do not need renewal.

---

## Multi-Network Docker Routing

### The Problem

When a container needs to be on multiple Docker networks (e.g., `haproxy-net` for SSL and `alpha-net` for backend communication), using `docker run --network haproxy-net` and then `docker network connect alpha-net` creates a race condition: the container's entrypoint starts executing before the second network is ready.

### The Solution

run-lib.sh uses the `docker create` + `docker network connect` + `docker start` pattern:

```bash
# 1. Create container on primary network (not started yet)
docker create --name my-service --network haproxy-net ...

# 2. Connect additional networks while container is stopped
docker network connect alpha-net my-service

# 3. Start -- all networks are ready when the entrypoint runs
docker start my-service
```

This is handled automatically by run-lib.sh. The primary network is `HAPROXY_NET` (when HAProxy is enabled) or `APP_NET`. The secondary network is `APP_NET` (when HAProxy is the primary).

### When to Use Multiple Networks

- **HAProxy + backend database:** Container needs `haproxy-net` for SSL and `db-net` for database access.
- **HAProxy + blockchain node:** Container needs `haproxy-net` for SSL and `alpha-net` for RPC communication with the node.

### Manual Multi-Network Setup (Without run-lib.sh)

If you are not using run-lib.sh:

```bash
docker create --name my-service \
    --network haproxy-net \
    -e SSL_DOMAIN=myservice.example.com \
    -e HAPROXY_HOST=haproxy \
    -v letsencrypt-data:/etc/letsencrypt \
    my-service:latest

docker network connect my-app-net my-service
docker start my-service
```

---

## Troubleshooting

### SSL setup fails with exit code 10 (domain unreachable)

**Symptom:** `[ssl-setup] ERROR: Domain myservice.example.com is not routable to this container`

**Causes and fixes:**
- DNS not configured: Ensure your domain's A record points to the server's public IP. Use `dig myservice.example.com` to verify.
- HAProxy not routing: Check that HAProxy is running and the container is on `haproxy-net`. Run `docker network inspect haproxy-net` to verify.
- Firewall blocking port 80: Ensure inbound port 80 is open. Let's Encrypt HTTP-01 validation requires port 80.
- Container not on the right network: If using multi-network setup, ensure `docker create` + `docker network connect` + `docker start` pattern is used.

### SSL setup fails with exit code 11 (certbot failed)

**Symptom:** `[ssl-setup] ERROR: Certificate acquisition failed`

**Causes and fixes:**
- Rate limited: Let's Encrypt has rate limits (50 certificates per domain per week). Use `--ssl-staging` for testing.
- Domain validation failed: Certbot could not reach `/.well-known/acme-challenge/` on your domain. Check that port 80 is routed correctly.
- Check certbot log: `docker exec my-service cat /tmp/certbot.log`

### SSL setup fails with exit code 13 (HAProxy registration failed)

**Symptom:** `[ssl-setup] ERROR: HAProxy registration failed after 300s of retries`

**Causes and fixes:**
- HAProxy not running: `docker ps | grep haproxy`
- Wrong network: Container must be on `haproxy-net` (or whatever `HAPROXY_NET` is set to).
- DNS resolution: ssl-setup waits up to 30 seconds for DNS. Check `docker exec my-service getent hosts haproxy`.
- TCP connectivity: ssl-setup waits up to 60 seconds for TCP. Check `docker exec my-service nc -z haproxy 8404`.
- API key mismatch: If HAProxy requires authentication, ensure `HAPROXY_API_KEY` is correct.

### Exit code 409 on HAProxy registration

**Symptom:** `[ssl-setup] Domain conflict (409) -- deleting stale registration`

**Cause:** The domain is registered to a different (probably dead) container. ssl-setup automatically deletes the stale registration and retries (up to 3 times). If the conflict persists, manually delete it:

```bash
curl -X DELETE http://haproxy:8404/v1/backends/myservice.example.com
```

### Container starts but SSL ports are not listening

**Causes and fixes:**
- ssl-setup succeeded but your app did not read the cert paths. Check that your entrypoint sources `/tmp/.ssl-env` and passes `SSL_CERT_FILE`/`SSL_KEY_FILE` to your app.
- App crashed after ssl-setup. Check `docker logs my-service` for app-specific errors.
- Wrong SSL_HTTPS_PORT: Ensure `SSL_HTTPS_PORT` matches the port your app actually listens on for TLS.

### APP_HTTP_PORT conflict

`APP_HTTP_PORT` cannot be `80` (that is the ssl-manager proxy) or `8404` (reserved for HAProxy API). If you set it to one of these values, `ssl-http-proxy` will refuse to start.

### Certificate renewal not working

- Check renewal loop is running: `docker exec my-service ps aux | grep ssl-renew`
- Force a renewal check: `docker exec my-service certbot renew --dry-run`
- Check renewal log: `docker exec my-service cat /var/log/certbot-renew.log`

### Self-signed certificate in production

If you see `[ssl-setup] WARNING: SSL_TEST_MODE is active`, you are using a self-signed certificate. Remove `SSL_TEST_MODE=true` from your environment variables.
