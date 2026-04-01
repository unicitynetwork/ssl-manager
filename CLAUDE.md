# ssl-manager -- In-Container SSL Management

## Project Overview

ssl-manager is a reusable Docker base image that provides automatic SSL certificate management and HAProxy auto-registration for any containerized service. It is part of the Unicity Network infrastructure stack and is published at `ghcr.io/unicitynetwork/ssl-manager:latest`.

Any Docker service can inherit from this image (`FROM ghcr.io/unicitynetwork/ssl-manager:latest`) to get:

- Automatic Let's Encrypt certificates via certbot (HTTP-01 challenge)
- Automatic HAProxy registration for domain-based routing (HTTP host header, TLS SNI passthrough, extra TCP/HTTP ports)
- Certificate auto-renewal with a background loop (~12 hour interval)
- HTTP reverse proxy on port 80 (serves ACME challenges, health endpoint, nonce verification, and optionally proxies app traffic)

The project has two components:

1. **The base Docker image** -- scripts installed inside `/usr/local/bin/` that run inside derived containers.
2. **run-lib.sh** -- a host-side bash library that provides a standardized `docker create` + `network connect` + `start` pattern with CLI argument parsing, health checks, and app hooks.

## Repository Structure

```
ssl-manager/
  Dockerfile                  # Base image: debian:trixie-slim + certbot + scripts
  publish.sh                  # Build and push to ghcr.io/unicitynetwork/ssl-manager
  run-lib.sh                  # Host-side startup library (sourced by app run scripts)
  README.md                   # User-facing README
  INTEGRATION.md              # Step-by-step integration guide for engineers
  CLAUDE.md                   # This file
  scripts/
    ssl-setup.sh              # Main orchestration (in-container, called once at startup)
    ssl-renew.sh              # Background certificate renewal loop
    ssl-http-proxy.py         # Python HTTP reverse proxy on port 80
    haproxy-register.sh       # HAProxy Registration API client (register/unregister)
    ssl-verify.sh             # Domain reachability and TLS verification utility
  examples/
    run-fulcrum.sh            # Example run script for Fulcrum-Alpha
```

## Key Concepts

### ssl-manager Base Image

The Dockerfile builds on `debian:trixie-slim` and installs: certbot, curl, jq, openssl, netcat-openbsd, python3, ca-certificates, procps. It copies the five scripts from `scripts/` into `/usr/local/bin/` (without `.sh` extensions), creates the ACME webroot at `/var/www/acme-challenge/`, exposes port 80, and declares a volume at `/etc/letsencrypt`.

Derived images use `FROM ghcr.io/unicitynetwork/ssl-manager:latest` as their runtime stage.

### ssl-setup.sh (In-Container Orchestration)

The main script, called once by the container's entrypoint. Located at `/usr/local/bin/ssl-setup` inside the container. Flow:

1. If `SSL_DOMAIN` is not set, exits 0 immediately (TCP-only mode).
2. Starts `ssl-http-proxy` on port 80 in the background. Waits up to 5 seconds for it to bind.
3. If `HAPROXY_HOST` is set (or auto-detected via DNS for hostname `haproxy`):
   - Waits for DNS resolution (up to 30s) and TCP connectivity (up to 60s) to `HAPROXY_HOST:HAPROXY_API_PORT`.
   - Registers with HAProxy via POST to `/v1/backends` with `https_port: null` (HTTP-only phase). Uses exponential backoff (2s, 4s, 8s... capped at 60s, max 5 minutes total).
   - Handles 409 (domain conflict) by deleting the stale registration and retrying (up to 3 times).
4. Verifies domain reachability: generates a random nonce, POSTs it to local proxy `/_ssl/nonce/{nonce}`, then GETs it through the public domain. Retries 3 times with 5-second intervals.
5. Checks for existing valid certificate in `/etc/letsencrypt/live/$SSL_DOMAIN/`. If valid and not expiring within `SSL_CERT_RENEW_DAYS` days, reuses it. Otherwise runs certbot (or generates self-signed cert if `SSL_TEST_MODE=true`).
6. Verifies TLS by starting a temporary `openssl s_server` on port 8443 and connecting to it via `openssl s_client`.
7. Re-registers with HAProxy including `https_port` for TLS passthrough.
8. Starts `ssl-renew` in the background.
9. Writes `SSL_CERT_FILE` and `SSL_KEY_FILE` to `/tmp/.ssl-env`.

Exit codes: 0 = success, 10 = domain unreachable, 11 = certbot failed, 12 = TLS verification failed, 13 = HAProxy registration failed, 14 = HAProxy reload failed.

### ssl-http-proxy.py (Port 80 Reverse Proxy)

A Python `http.server.ThreadingHTTPServer` that listens on port 80. Routes:

- `/.well-known/acme-challenge/*` -- serves files from webroot (for certbot HTTP-01 validation)
- `/_ssl/health` -- returns JSON with cert expiry, domain, upstream status
- `/_ssl/nonce/{nonce}` -- thread-safe in-memory nonce store (GET/POST/DELETE) used for domain verification
- `/*` -- reverse proxy to `APP_HTTP_PORT` on localhost (if configured and not 0)

Has safety checks: rejects `APP_HTTP_PORT=80` (circular proxy) and `APP_HTTP_PORT=8404` (reserved). Max proxy body size is 10MB.

### ssl-renew.sh (Background Renewal)

Started by ssl-setup after initial certificate acquisition. Runs as a background process for the container's lifetime.

- Waits 1 hour before first check.
- Runs `certbot renew` every ~12 hours with random jitter (0-30 minutes).
- Uses `--deploy-hook "touch /tmp/.ssl-renewal-restart"` so the app's supervisor loop can detect renewal and restart.
- In `SSL_TEST_MODE`, sleeps indefinitely (self-signed certs do not need renewal).

### haproxy-register.sh (API Client)

Standalone HAProxy Registration API client. Two modes:

- `haproxy-register register` -- POST to `/v1/backends` with domain, container hostname, ports.
- `haproxy-register unregister` -- DELETE `/v1/backends/$SSL_DOMAIN`. Returns success on 204 or 404.

Used by ssl-setup during startup and by entrypoints during graceful shutdown.

### ssl-verify.sh (Verification Utility)

Two verification modes:

- `ssl-verify http` -- nonce-based HTTP reachability test (same logic as ssl-setup step 4).
- `ssl-verify https` -- connects via `openssl s_client` and verifies TLS handshake.

### run-lib.sh (Host-Side Startup Library)

Sourced by app-specific run scripts on the Docker host. Provides:

- CLI argument parsing for SSL and HAProxy flags (--domain, --ssl-email, --no-ssl, --haproxy-host, etc.)
- Docker network creation (`APP_NET`, `HAPROXY_NET`)
- Container lifecycle: stop existing, `docker create` + `docker network connect` + `docker start` (avoids multi-network routing race)
- Port readiness polling with timeout
- Health checks with color-coded output (green pass, yellow warn, red fail)
- App hook system (see below)

Entry point: `ssl_manager_run "$@"` -- called at the end of the app's run script.

### HAProxy Registration API

ssl-manager integrates with a HAProxy instance that exposes a REST API at `HAPROXY_HOST:HAPROXY_API_PORT` (default port 8404). The API accepts:

- `POST /v1/backends` -- register a backend with domain, container, http_port, https_port, extra_ports.
- `DELETE /v1/backends/{domain}` -- unregister a domain.

Registration happens in two phases: first HTTP-only (for certbot validation), then with HTTPS port (for TLS passthrough after certificate acquisition).

### Certificate Lifecycle

1. **Acquisition:** ssl-setup obtains the initial certificate (certbot or self-signed).
2. **Renewal:** ssl-renew checks every ~12 hours and runs `certbot renew`. On success, touches `/tmp/.ssl-renewal-restart`.
3. **Rotation:** The app's supervisor loop detects the restart marker, re-sources `/tmp/.ssl-env`, and restarts the app process to load the new certificate.

## Integration Pattern

### 1. Dockerfile

```dockerfile
FROM ghcr.io/unicitynetwork/ssl-manager:latest
# Install your runtime deps (ssl-manager already has certbot, openssl, curl, jq, nc, python3, procps)
RUN apt-get update && apt-get install -y --no-install-recommends your-deps && ...
COPY your-app /usr/local/bin/your-app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE <your-ports>
ENTRYPOINT ["/entrypoint.sh"]
```

### 2. Entrypoint

```bash
#!/bin/bash
set -e
ssl_exit=0
/usr/local/bin/ssl-setup || ssl_exit=$?
[ -f /tmp/.ssl-env ] && . /tmp/.ssl-env
if [ $ssl_exit -ne 0 ] && [ "${SSL_REQUIRED:-true}" = "true" ]; then
    exit $ssl_exit
fi
if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "${SSL_CERT_FILE}" ]; then
    exec your-app --cert "$SSL_CERT_FILE" --key "$SSL_KEY_FILE"
else
    exec your-app --no-tls
fi
```

### 3. Run Script

```bash
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER_NAME="my-service"
IMAGE_NAME="my-service:latest"
APP_TITLE="My Service"
APP_NET="my-net"
DATA_VOLUME="my-data"
HEALTH_PORT=3000
SSL_HTTPS_PORT=3443
source "${SCRIPT_DIR}/run-lib.sh"
# implement app hooks...
ssl_manager_run "$@"
```

## Environment Variables (Complete Reference)

### In-Container (Used by ssl-setup and ssl-renew)

| Variable | Default | Description |
|----------|---------|-------------|
| `SSL_DOMAIN` | _(empty)_ | Domain for SSL. If unset, SSL is skipped. |
| `SSL_ADMIN_EMAIL` | _(empty)_ | Let's Encrypt registration email. |
| `SSL_REQUIRED` | `true` | If true, ssl-setup failure is fatal. |
| `SSL_HTTPS_PORT` | `443` | Backend TLS port for HAProxy passthrough. |
| `SSL_CERT_RENEW_DAYS` | `30` | Renew if cert expires within N days. |
| `SSL_STAGING` | _(empty)_ | `true` = use LE staging environment. |
| `SSL_TEST_MODE` | _(empty)_ | `true` = self-signed cert (dev/CI). |
| `SSL_SKIP_VERIFY` | `false` | `true` = skip TLS verification step. |
| `HAPROXY_HOST` | _(empty)_ | HAProxy hostname. Auto-detected via DNS if unset. |
| `HAPROXY_API_PORT` | `8404` | HAProxy Registration API port. |
| `HAPROXY_API_KEY` | _(empty)_ | Bearer token for API auth. |
| `APP_HTTP_PORT` | `0` | App HTTP port behind proxy (0 = disabled). Cannot be 80 or 8404. |
| `EXTRA_PORTS` | _(empty)_ | JSON array of extra HAProxy port mappings. |

### Host-Side (Used by run-lib.sh)

| Variable | Default | Description |
|----------|---------|-------------|
| `HAPROXY_NET` | `haproxy-net` | Docker network for HAProxy. |
| `LETSENCRYPT_VOLUME` | `letsencrypt-data` | Docker volume for cert storage. |
| `HEALTH_TIMEOUT` | `120` | Seconds to wait for health port. |

## run-lib.sh Hook Reference

All hooks are optional functions defined in the app's run script after `source run-lib.sh` and before `ssl_manager_run "$@"`.

| Hook | Signature | Purpose |
|------|-----------|---------|
| `app_parse_args` | `app_parse_args "$@"` | Custom CLI arg parsing. Return N for N args consumed, 0 for unrecognized. |
| `app_env_args` | `app_env_args` | Print `-e KEY=VALUE` lines for docker create. |
| `app_port_args` | `app_port_args` | Print `-p host:container` lines (direct mode only, ignored behind HAProxy). |
| `app_docker_args` | `app_docker_args` | Print extra docker create flags. |
| `app_validate` | `app_validate` | Validate custom args after parsing. Exit on error. |
| `app_print_config` | `app_print_config` | Print extra lines in startup banner. |
| `app_help` | `app_help` | Print app-specific help section. |
| `app_health_check` | `app_health_check "$container"` | Print `pass:msg`, `warn:msg`, or `fail:msg` lines. |
| `app_needs_host_gateway` | `app_needs_host_gateway` | Return 0 if `--add-host=host.docker.internal:host-gateway` needed. |
| `app_summary` | `app_summary` | Print app endpoints after startup. |

Helper functions available after sourcing run-lib.sh:
- `require_arg "$flag" "${2:-}"` -- validates that a flag has a value argument
- `validate_port "$name" "$value"` -- validates port is 1-65535 or 0
- `check_pass "$msg"` / `check_warn "$msg"` / `check_fail "$msg"` -- colored output helpers

## Common Tasks

### Add SSL to a New Service

1. Change your Dockerfile's runtime stage to `FROM ghcr.io/unicitynetwork/ssl-manager:latest`.
2. Add ssl-setup call to your entrypoint (see Integration Pattern above).
3. Copy `run-lib.sh` to your project and create a run script.
4. Run with `--domain your.domain.com`.

### Debug SSL Setup Failures

```bash
# Check logs for [ssl-setup] messages
docker logs my-service 2>&1 | grep '\[ssl-setup\]'

# Check certbot log
docker exec my-service cat /tmp/certbot.log

# Check HTTP proxy is running
docker exec my-service ps aux | grep ssl-http-proxy

# Test nonce endpoint manually
docker exec my-service curl -sf http://localhost:80/_ssl/health

# Test domain reachability
docker exec my-service ssl-verify http

# Test TLS
docker exec my-service ssl-verify https
```

Exit code meanings: 10 = domain unreachable (check DNS, HAProxy, firewall), 11 = certbot failed (check rate limits, `/tmp/certbot.log`), 12 = TLS verification failed (cert may be corrupt), 13 = HAProxy registration failed (check network, API key), 14 = HAProxy reload failed.

### Force Certificate Renewal

```bash
docker exec my-service certbot renew --force-renewal \
    --cert-name your.domain.com \
    --webroot --webroot-path /var/www/acme-challenge
```

Then restart the app to load the new cert, or touch the restart marker:

```bash
docker exec my-service touch /tmp/.ssl-renewal-restart
```

### Switch Domains

Stop the container, change `SSL_DOMAIN`, and restart. The old certificate remains in the letsencrypt volume but a new one will be obtained for the new domain.

### Disable SSL

Run with `--no-ssl` or omit `SSL_DOMAIN`. ssl-setup exits 0 immediately and no proxy or renewal loop is started.

### Test with Self-Signed Certificates

```bash
./run-myapp.sh --domain test.local --ssl-test-mode --no-haproxy
```

This generates a self-signed cert without contacting Let's Encrypt. The renewal loop sleeps indefinitely.

### Use Let's Encrypt Staging

```bash
./run-myapp.sh --domain your.domain.com --ssl-staging
```

Staging certificates are not trusted by browsers but have much higher rate limits. Good for testing the full flow.

## Build and Publish

```bash
# Build locally (tags as ssl-manager:latest)
docker build -t ssl-manager:latest .

# Build and push to GHCR
./publish.sh              # pushes :latest
./publish.sh v1.2.3       # pushes :v1.2.3 and :latest

# Custom registry
SSL_MANAGER_REGISTRY=my-registry.com/org ./publish.sh
```

The `publish.sh` script builds, tags (both the specified tag and `latest`), and optionally pushes to the registry. It also creates a local `ssl-manager:latest` tag for downstream builds.

## Dependencies

The base image installs these packages (all from Debian trixie repos):

- **certbot** -- Let's Encrypt ACME client
- **python3** -- required by certbot and ssl-http-proxy
- **curl** -- HTTP client for HAProxy API and nonce verification
- **jq** -- JSON processing for API payloads
- **openssl** -- certificate inspection, TLS verification, nonce generation, self-signed cert creation
- **netcat-openbsd** -- TCP port checking (`nc -z`)
- **ca-certificates** -- root CA bundle for TLS verification
- **procps** -- process utilities (`ps`)

## Architecture

### Orchestration Flow

```
Container Start
    |
    v
Entrypoint calls /usr/local/bin/ssl-setup
    |
    v
ssl-setup: SSL_DOMAIN set?
    |-- No --> exit 0 (TCP-only mode)
    |-- Yes
    v
Start ssl-http-proxy on port 80 (background)
    |   Routes: ACME challenges, health, nonces, app proxy
    v
HAPROXY_HOST set or auto-detected?
    |-- No --> skip HAProxy registration
    |-- Yes
    v
Wait for DNS + TCP connectivity (30s + 60s)
    |
    v
POST /v1/backends (http_port=80, https_port=null)
    |   Exponential backoff: 2s, 4s, 8s... up to 5 min total
    |   Handles 409 conflict by deleting stale registration
    v
Generate nonce, POST to local /_ssl/nonce/{nonce}
    |
    v
GET http://{SSL_DOMAIN}/_ssl/nonce/{nonce}
    |   3 attempts, 5s apart
    |-- Mismatch --> exit 10 (domain unreachable)
    v
Existing valid cert in /etc/letsencrypt/live/{domain}/?
    |-- Yes (>30 days left) --> reuse
    |-- No, SSL_TEST_MODE=true --> generate self-signed
    |-- No --> certbot certonly --webroot
    |          |-- Failure --> exit 11
    v
Start temporary openssl s_server on 8443
    |
    v
Connect via openssl s_client, verify subject
    |-- Failure --> exit 12
    v
POST /v1/backends (http_port=80, https_port={SSL_HTTPS_PORT})
    |-- Failure --> exit 13
    v
Start ssl-renew (background)
    |   Waits 1h, then checks every ~12h
    |   On renewal: touches /tmp/.ssl-renewal-restart
    v
Write /tmp/.ssl-env (SSL_CERT_FILE, SSL_KEY_FILE)
    |
    v
exit 0
    |
    v
Entrypoint sources /tmp/.ssl-env
    |
    v
Entrypoint starts app with cert paths
```

### Network Architecture (with HAProxy)

```
Internet
    |
    v
HAProxy (haproxy-net)
    |-- Port 80:  Host header routing --> container:80 (ssl-http-proxy)
    |-- Port 443: SNI TLS passthrough --> container:{SSL_HTTPS_PORT}
    |-- Extra ports: TCP/HTTP routing --> container:{target}
    |
    v
Container (haproxy-net + app-net)
    |-- Port 80:              ssl-http-proxy (ACME, health, nonce, app proxy)
    |-- Port {SSL_HTTPS_PORT}: Your app (TLS)
    |-- Port {APP_HTTP_PORT}:  Your app (HTTP, optional, proxied from port 80)
    |-- Port {extra targets}:  Your app (custom protocols)
    |
    v (via app-net)
Backend services (database, blockchain node, etc.)
```

### File Locations Inside Container

| Path | Purpose |
|------|---------|
| `/usr/local/bin/ssl-setup` | Main orchestration script |
| `/usr/local/bin/ssl-renew` | Renewal background loop |
| `/usr/local/bin/ssl-http-proxy` | HTTP reverse proxy (Python) |
| `/usr/local/bin/haproxy-register` | HAProxy API client |
| `/usr/local/bin/ssl-verify` | Verification utility |
| `/var/www/acme-challenge/` | ACME webroot directory |
| `/etc/letsencrypt/` | Certbot certificate storage (volume) |
| `/etc/letsencrypt/live/{domain}/fullchain.pem` | Certificate chain |
| `/etc/letsencrypt/live/{domain}/privkey.pem` | Private key |
| `/tmp/.ssl-env` | Sourceable file with SSL_CERT_FILE and SSL_KEY_FILE |
| `/tmp/.ssl-http-proxy.pid` | PID of the HTTP proxy process |
| `/tmp/.ssl-renew.pid` | PID of the renewal loop process |
| `/tmp/.ssl-renewal-restart` | Marker file created when cert is renewed |
| `/tmp/certbot.log` | Certbot output from initial acquisition |
| `/var/log/certbot-renew.log` | Certbot output from renewal checks |

## Real-World Integration: Fulcrum-Alpha

The Fulcrum-Alpha SPV server at `/home/vrogojin/Fulcrum-Alpha/docker/` is the reference integration:

- **Dockerfile** (`docker/Dockerfile`): Multi-stage build. Stage 1 compiles C++ with Qt. Stage 2 uses `FROM ghcr.io/unicitynetwork/ssl-manager:latest`, installs Qt runtime libs, copies binaries.
- **Entrypoint** (`docker/docker-entrypoint.sh`): Calls ssl-setup, sources .ssl-env, generates fulcrum.conf with cert paths, runs Fulcrum in a supervisor loop with crash recovery and database corruption detection. Handles graceful shutdown with HAProxy deregistration.
- **Run script** (`docker/run-fulcrum.sh`): Sources run-lib.sh, implements all hooks. Sets `SSL_HTTPS_PORT=50002` (non-standard), `APP_HTTP_PORT=0` (no HTTP). Auto-populates `EXTRA_PORTS` for four Electrum protocol ports when HAProxy is active.
