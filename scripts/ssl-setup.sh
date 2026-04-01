#!/bin/bash
# ssl-setup.sh — Main SSL orchestration script
#
# Obtains and configures TLS certificates for the container. When SSL_DOMAIN
# is not set, exits 0 immediately (TCP-only mode). Otherwise:
#   1. Starts the ssl-http-proxy on port 80
#   2. Optionally registers with HAProxy (exponential backoff)
#   3. Verifies domain reachability via nonce
#   4. Obtains or reuses a certificate (certbot or self-signed)
#   5. Verifies TLS handshake
#   6. Starts the background renewal loop
#   7. Exports SSL_CERT_FILE and SSL_KEY_FILE
#
# Exit codes:
#   0  — success (or SSL_DOMAIN not set)
#  10  — domain unreachable (nonce verification failed)
#  11  — certbot failed
#  12  — TLS verification failed
#  13  — HAProxy registration failed
#  14  — HAProxy reload failed
#
# Required tools: curl, jq, openssl, nc, python3
#
# Environment variables — see Section 6 of SSL_MANAGEMENT_ARCHITECTURE.md

set -euo pipefail

readonly SCRIPT_NAME="ssl-setup"
readonly WEBROOT="/var/www/acme-challenge"
readonly LOG_PREFIX="[${SCRIPT_NAME}]"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
: "${SSL_REQUIRED:=true}"
: "${SSL_STAGING:=false}"
: "${SSL_TEST_MODE:=false}"
: "${SSL_CERT_RENEW_DAYS:=30}"
: "${SSL_HTTPS_PORT:=443}"
: "${APP_HTTP_PORT:=0}"
: "${HAPROXY_API_PORT:=8404}"
: "${SSL_SKIP_VERIFY:=false}"
: "${SSL_ALIAS_PROXY_PORT:=8444}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '%s %s\n' "$LOG_PREFIX" "$*"; }
warn() { printf '%s WARNING: %s\n' "$LOG_PREFIX" "$*" >&2; }
err()  { printf '%s ERROR: %s\n' "$LOG_PREFIX" "$*" >&2; }

die() {
    local code="$1"; shift
    err "$@"
    exit "$code"
}

# PIDs of background processes we may need to clean up on error
HTTP_PROXY_PID=""
TLS_TEST_PID=""

cleanup_on_error() {
    if [[ -n "$HTTP_PROXY_PID" ]]; then
        kill "$HTTP_PROXY_PID" 2>/dev/null || true
    fi
    if [[ -n "$TLS_TEST_PID" ]]; then
        kill "$TLS_TEST_PID" 2>/dev/null || true
    fi
}
trap cleanup_on_error ERR

# Build curl auth header arguments as an array (safe for word splitting).
# Populates the global AUTH_HEADER_ARGS array.
build_auth_header() {
    AUTH_HEADER_ARGS=()
    if [[ -n "${HAPROXY_API_KEY:-}" ]]; then
        AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${HAPROXY_API_KEY}")
    fi
}

# ---------------------------------------------------------------------------
# Step 0: Early exit if SSL not requested
# ---------------------------------------------------------------------------
if [[ -z "${SSL_DOMAIN:-}" ]]; then
    log "SSL_DOMAIN not set — skipping SSL setup (TCP-only mode)"
    exit 0
fi

log "Starting SSL setup for domain: ${SSL_DOMAIN}"

# Parse domain aliases into an array
ALL_SSL_DOMAINS=("$SSL_DOMAIN")
if [[ -n "${SSL_DOMAIN_ALIASES:-}" ]]; then
    IFS=',' read -ra _aliases <<< "$SSL_DOMAIN_ALIASES"
    for _alias in "${_aliases[@]}"; do
        _alias=$(echo "$_alias" | xargs)  # trim whitespace
        # Skip empty, duplicates, and alias=primary
        if [[ -n "$_alias" && "$_alias" != "$SSL_DOMAIN" ]]; then
            local_dup=false
            for _existing in "${ALL_SSL_DOMAINS[@]}"; do
                if [[ "$_existing" == "$_alias" ]]; then local_dup=true; break; fi
            done
            if [[ "$local_dup" == "false" ]]; then
                ALL_SSL_DOMAINS+=("$_alias")
            fi
        fi
    done
    log "Domain aliases: ${ALL_SSL_DOMAINS[*]:1}"
fi

if [[ "${SSL_TEST_MODE}" == "true" ]]; then
    warn "SSL_TEST_MODE is active — using self-signed certificate"
    warn "This is NOT suitable for production. Clients will reject this certificate."
fi

# Validate required external commands
for cmd in curl jq openssl nc python3; do
    command -v "$cmd" &>/dev/null || die 1 "Required command not found: ${cmd}"
done

# ---------------------------------------------------------------------------
# Step 1: Start the HTTP reverse proxy on port 80
# ---------------------------------------------------------------------------
mkdir -p "${WEBROOT}/.well-known/acme-challenge"

log "Starting HTTP reverse proxy on port 80"
python3 /usr/local/bin/ssl-http-proxy \
    --port 80 \
    --webroot "$WEBROOT" \
    --upstream "127.0.0.1:${APP_HTTP_PORT}" \
    --cert-dir "/etc/letsencrypt/live/${SSL_DOMAIN}" &
HTTP_PROXY_PID=$!
echo "$HTTP_PROXY_PID" > /tmp/.ssl-http-proxy.pid

# Wait for the proxy to become ready (up to 5 seconds)
proxy_ready=false
for _ in $(seq 1 10); do
    if nc -z localhost 80 2>/dev/null; then
        proxy_ready=true
        break
    fi
    sleep 0.5
done

if [[ "$proxy_ready" != "true" ]]; then
    die 1 "HTTP reverse proxy failed to start on port 80"
fi
log "HTTP reverse proxy ready (PID ${HTTP_PROXY_PID})"

# ---------------------------------------------------------------------------
# Step 2: HAProxy detection and registration (HTTP-only, https_port=null)
# ---------------------------------------------------------------------------
HAPROXY_DETECTED=""

if [[ -n "${HAPROXY_HOST:-}" ]]; then
    HAPROXY_DETECTED="$HAPROXY_HOST"
    log "HAProxy mode: host=${HAPROXY_DETECTED}, api_port=${HAPROXY_API_PORT}"
elif getent hosts haproxy &>/dev/null; then
    HAPROXY_DETECTED="haproxy"
    log "HAProxy detected via DNS resolution: ${HAPROXY_DETECTED}"
fi

if [[ -n "$HAPROXY_DETECTED" ]]; then
    # Wait for Docker DNS to fully initialize (network interfaces may not be
    # ready immediately after container start, especially with multi-network)
    log "Waiting for DNS resolution of ${HAPROXY_DETECTED}..."
    for _dns_wait in $(seq 1 30); do
        if getent hosts "$HAPROXY_DETECTED" &>/dev/null; then
            log "DNS ready: $(getent hosts "$HAPROXY_DETECTED" | head -1)"
            break
        fi
        sleep 1
    done
    build_auth_header

    # Validate EXTRA_PORTS JSON before using with jq
    if [[ -n "${EXTRA_PORTS:-}" ]] && [[ "${EXTRA_PORTS}" != "null" ]]; then
        if ! echo "$EXTRA_PORTS" | jq empty 2>/dev/null; then
            die 13 "EXTRA_PORTS is not valid JSON: $EXTRA_PORTS"
        fi
    fi

    # Resolve hostname to IP for reliable curl
    HAPROXY_IP=$(getent hosts "$HAPROXY_DETECTED" 2>/dev/null | awk '{print $1}' | head -1)
    if [[ -z "$HAPROXY_IP" ]]; then
        HAPROXY_IP="$HAPROXY_DETECTED"
    fi
    log "Resolved ${HAPROXY_DETECTED} → ${HAPROXY_IP}"

    # Wait for actual TCP connectivity (not just DNS). Docker bridge networks
    # may not have their routing table entries ready when the entrypoint starts,
    # especially in multi-network setups. DNS works immediately (Docker's
    # embedded DNS is network-independent) but L3 routing requires the veth
    # pair and subnet route to be configured, which happens asynchronously.
    log "Waiting for TCP connectivity to ${HAPROXY_IP}:${HAPROXY_API_PORT}..."
    for _tcp_wait in $(seq 1 60); do
        if nc -z -w1 "$HAPROXY_IP" "$HAPROXY_API_PORT" 2>/dev/null; then
            log "TCP connectivity confirmed"
            break
        fi
        if [[ "$_tcp_wait" -eq 60 ]]; then
            log "WARNING: TCP connectivity not established after 60s"
        fi
        sleep 1
    done

    # Retry with exponential backoff: 2s, 4s, 8s, 16s, 32s, 60s (capped)
    # Maximum total wait: 5 minutes (300 seconds)
    haproxy_url="http://${HAPROXY_IP}:${HAPROXY_API_PORT}/v1/backends"
    backoff=2
    total_waited=0
    max_wait=300
    registered=false

    PAYLOAD=$(jq -n \
        --arg domain "$SSL_DOMAIN" \
        --arg container "$(hostname)" \
        --argjson http_port 80 \
        --argjson extra_ports "${EXTRA_PORTS:-null}" \
        '{domain: $domain, container: $container, http_port: $http_port, https_port: null, extra_ports: $extra_ports}')

    while [[ "$total_waited" -lt "$max_wait" ]]; do
        http_code=$(curl -s -o /dev/null -w '%{http_code}' \
            -X POST "${haproxy_url}" \
            -H "Content-Type: application/json" \
            "${AUTH_HEADER_ARGS[@]}" \
            -d "$PAYLOAD" 2>/dev/null) || http_code="000"

        if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
            registered=true
            log "Registered with HAProxy (HTTP-only, status=${http_code})"
            break
        fi

        if [[ "$http_code" == "409" ]]; then
            # Domain registered to a different (likely dead) container.
            # Delete the stale registration and retry (max 3 attempts).
            conflict_retries=$((${conflict_retries:-0} + 1))
            if [[ "$conflict_retries" -gt 3 ]]; then
                die 13 "Domain conflict persists after ${conflict_retries} delete attempts for ${SSL_DOMAIN}"
            fi
            log "Domain conflict (409) — deleting stale registration (attempt ${conflict_retries}/3)..."
            curl -s -o /dev/null -X DELETE \
                "${haproxy_url}/${SSL_DOMAIN}" \
                "${AUTH_HEADER_ARGS[@]}" \
                --max-time 5 2>/dev/null || true
            sleep 2
            continue  # Retry registration immediately
        fi

        log "HAProxy API not ready (status=${http_code}), retrying in ${backoff}s..."
        sleep "$backoff"
        total_waited=$((total_waited + backoff))
        if [[ "$backoff" -lt 60 ]]; then
            backoff=$((backoff * 2))
            if [[ "$backoff" -gt 60 ]]; then
                backoff=60
            fi
        fi
    done

    if [[ "$registered" != "true" ]]; then
        die 13 "HAProxy registration failed after ${total_waited}s of retries"
    fi

    # Register alias domains with HAProxy (HTTP-only)
    for _alias_domain in "${ALL_SSL_DOMAINS[@]:1}"; do
        ALIAS_PAYLOAD=$(jq -n \
            --arg domain "$_alias_domain" \
            --arg container "$(hostname)" \
            --argjson http_port 80 \
            --argjson extra_ports "${EXTRA_PORTS:-null}" \
            '{domain: $domain, container: $container, http_port: $http_port, https_port: null, extra_ports: $extra_ports}')

        _alias_registered=false
        for _attempt in 1 2 3; do
            _code=$(curl -s -o /dev/null -w '%{http_code}' \
                -X POST "${haproxy_url}" \
                -H "Content-Type: application/json" \
                "${AUTH_HEADER_ARGS[@]}" \
                -d "$ALIAS_PAYLOAD" 2>/dev/null) || _code="000"

            if [[ "$_code" == "200" || "$_code" == "201" ]]; then
                log "Registered alias ${_alias_domain} with HAProxy (HTTP-only)"
                _alias_registered=true
                break
            elif [[ "$_code" == "409" ]]; then
                curl -s -o /dev/null -X DELETE "${haproxy_url}/${_alias_domain}" \
                    "${AUTH_HEADER_ARGS[@]}" --max-time 5 2>/dev/null || true
                sleep 2
            else
                sleep 2
            fi
        done
        if [[ "$_alias_registered" != "true" ]]; then
            die 13 "HAProxy registration failed for alias ${_alias_domain} (status=${_code})"
        fi
    done
fi

# ---------------------------------------------------------------------------
# Step 3: Verify domain reachability via nonce
# ---------------------------------------------------------------------------
NONCE=$(openssl rand -hex 16)
log "Verifying domain reachability (nonce=${NONCE:0:8}...)"

# Register the nonce with the local proxy
curl -sf -X POST "http://localhost:80/_ssl/nonce/${NONCE}" >/dev/null

NONCE_MATCHED=false
RESPONSE=""
for attempt in 1 2 3; do
    RESPONSE=$(curl -sf --max-time 10 "http://${SSL_DOMAIN}/_ssl/nonce/${NONCE}" 2>/dev/null) || RESPONSE=""
    if [[ "$RESPONSE" == "$NONCE" ]]; then
        NONCE_MATCHED=true
        break
    fi
    log "Nonce attempt ${attempt}/3 failed, retrying in 5s..."
    sleep 5
done

# Clean up the nonce from proxy memory
curl -sf -X DELETE "http://localhost:80/_ssl/nonce/${NONCE}" >/dev/null 2>&1 || true

if [[ "$NONCE_MATCHED" != "true" ]]; then
    die 10 "Domain ${SSL_DOMAIN} is not routable to this container. Expected nonce: ${NONCE}, got: ${RESPONSE:-<no response>}"
fi
log "Domain reachability confirmed"

# Allow HAProxy time to reload after alias registrations
if [[ ${#ALL_SSL_DOMAINS[@]} -gt 1 ]]; then
    log "Waiting 5s for HAProxy to reload with alias routes..."
    sleep 5
fi

# Verify alias domains
for _alias_domain in "${ALL_SSL_DOMAINS[@]:1}"; do
    _ALIAS_NONCE=$(openssl rand -hex 16)
    log "Verifying alias reachability: ${_alias_domain}"
    curl -sf -X POST "http://localhost:80/_ssl/nonce/${_ALIAS_NONCE}" >/dev/null

    _ALIAS_MATCHED=false
    for _attempt in 1 2 3; do
        _RESP=$(curl -sf --max-time 10 "http://${_alias_domain}/_ssl/nonce/${_ALIAS_NONCE}" 2>/dev/null) || _RESP=""
        if [[ "$_RESP" == "$_ALIAS_NONCE" ]]; then
            _ALIAS_MATCHED=true
            break
        fi
        sleep 5
    done
    curl -sf -X DELETE "http://localhost:80/_ssl/nonce/${_ALIAS_NONCE}" >/dev/null 2>&1 || true

    if [[ "$_ALIAS_MATCHED" != "true" ]]; then
        die 10 "Alias domain ${_alias_domain} is not routable to this container"
    fi
    log "Alias reachability confirmed: ${_alias_domain}"
done

# ---------------------------------------------------------------------------
# Step 4: Certificate check and acquisition
# ---------------------------------------------------------------------------
CERT_DIR="/etc/letsencrypt/live/${SSL_DOMAIN}"
CERT_FILE="${CERT_DIR}/fullchain.pem"
KEY_FILE="${CERT_DIR}/privkey.pem"

need_cert=true

if [[ -f "$CERT_FILE" ]] && [[ -f "$KEY_FILE" ]]; then
    EXPIRY_RAW=$(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "$EXPIRY_RAW" +%s)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

    if [[ "$DAYS_LEFT" -gt "$SSL_CERT_RENEW_DAYS" ]]; then
        log "Existing certificate valid for ${DAYS_LEFT} days (threshold: ${SSL_CERT_RENEW_DAYS}), reusing"
        need_cert=false
    else
        log "Certificate expires in ${DAYS_LEFT} days (threshold: ${SSL_CERT_RENEW_DAYS}), renewing"
    fi
fi

if [[ "$need_cert" == "true" ]]; then
    if [[ "${SSL_TEST_MODE}" == "true" ]]; then
        # Generate a self-signed certificate for development/CI
        log "Generating self-signed certificate (SSL_TEST_MODE=true)"
        mkdir -p "$CERT_DIR"
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$KEY_FILE" \
            -out "$CERT_FILE" \
            -days 365 \
            -subj "/CN=${SSL_DOMAIN}" \
            2>/dev/null
        chmod 600 "$KEY_FILE"
        log "Self-signed certificate generated"
    else
        # Obtain certificate from Let's Encrypt via certbot webroot mode
        log "Requesting certificate from Let's Encrypt"

        certbot_args=(
            certonly
            --non-interactive
            --agree-tos
            --webroot
            --webroot-path "$WEBROOT"
            -d "${SSL_DOMAIN}"
        )

        if [[ -n "${SSL_ADMIN_EMAIL:-}" ]]; then
            certbot_args+=(--email "$SSL_ADMIN_EMAIL")
        else
            certbot_args+=(--register-unsafely-without-email)
        fi

        if [[ "${SSL_STAGING}" == "true" ]]; then
            certbot_args+=(--staging)
            log "Using Let's Encrypt staging environment"
        fi

        if ! certbot "${certbot_args[@]}" 2>&1 | tee /tmp/certbot.log; then
            err "certbot failed. Log output:"
            cat /tmp/certbot.log >&2
            die 11 "Certificate acquisition failed"
        fi
        log "Certificate acquired from Let's Encrypt"
    fi
fi

# Verify cert files exist after acquisition
if [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]]; then
    die 11 "Certificate files not found after acquisition: cert=${CERT_FILE}, key=${KEY_FILE}"
fi

# ---------------------------------------------------------------------------
# Step 4b: Acquire certificates for alias domains
# ---------------------------------------------------------------------------
for _alias_domain in "${ALL_SSL_DOMAINS[@]:1}"; do
    _ALIAS_CERT_DIR="/etc/letsencrypt/live/${_alias_domain}"
    _ALIAS_CERT="${_ALIAS_CERT_DIR}/fullchain.pem"
    _ALIAS_KEY="${_ALIAS_CERT_DIR}/privkey.pem"
    _alias_need_cert=true

    if [[ -f "$_ALIAS_CERT" ]] && [[ -f "$_ALIAS_KEY" ]]; then
        _EXPIRY_RAW=$(openssl x509 -enddate -noout -in "$_ALIAS_CERT" | cut -d= -f2)
        _EXPIRY_EPOCH=$(date -d "$_EXPIRY_RAW" +%s)
        _NOW_EPOCH=$(date +%s)
        _DAYS_LEFT=$(( (_EXPIRY_EPOCH - _NOW_EPOCH) / 86400 ))
        if [[ "$_DAYS_LEFT" -gt "$SSL_CERT_RENEW_DAYS" ]]; then
            log "Alias ${_alias_domain}: cert valid for ${_DAYS_LEFT} days, reusing"
            _alias_need_cert=false
        fi
    fi

    if [[ "$_alias_need_cert" == "true" ]]; then
        if [[ "${SSL_TEST_MODE}" == "true" ]]; then
            log "Generating self-signed certificate for alias: ${_alias_domain}"
            mkdir -p "$_ALIAS_CERT_DIR"
            openssl req -x509 -newkey rsa:2048 -nodes \
                -keyout "$_ALIAS_KEY" -out "$_ALIAS_CERT" \
                -days 365 -subj "/CN=${_alias_domain}" 2>/dev/null
            chmod 600 "$_ALIAS_KEY"
        else
            log "Requesting certificate for alias: ${_alias_domain}"
            _certbot_alias_args=(
                certonly --non-interactive --agree-tos
                --webroot --webroot-path "$WEBROOT"
                -d "${_alias_domain}"
            )
            if [[ -n "${SSL_ADMIN_EMAIL:-}" ]]; then
                _certbot_alias_args+=(--email "$SSL_ADMIN_EMAIL")
            else
                _certbot_alias_args+=(--register-unsafely-without-email)
            fi
            if [[ "${SSL_STAGING}" == "true" ]]; then
                _certbot_alias_args+=(--staging)
            fi

            if ! certbot "${_certbot_alias_args[@]}" 2>&1 | tee /tmp/certbot-alias.log; then
                err "certbot failed for alias ${_alias_domain}"
                cat /tmp/certbot-alias.log >&2
                die 11 "Certificate acquisition failed for alias ${_alias_domain}"
            fi
            log "Certificate acquired for alias: ${_alias_domain}"
        fi
    fi

    if [[ ! -f "$_ALIAS_CERT" ]] || [[ ! -f "$_ALIAS_KEY" ]]; then
        die 11 "Certificate files not found for alias ${_alias_domain}"
    fi
done

# ---------------------------------------------------------------------------
# Step 5: TLS verification
# ---------------------------------------------------------------------------
if [[ "${SSL_SKIP_VERIFY}" != "true" ]]; then
    log "Verifying TLS certificate"

    # Start a temporary TLS test server
    openssl s_server -cert "$CERT_FILE" -key "$KEY_FILE" \
        -accept 8443 -www -quiet &
    TLS_TEST_PID=$!
    sleep 1

    VERIFY_RESULT=$(printf '' | openssl s_client -connect localhost:8443 \
        -servername "${SSL_DOMAIN}" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null) || VERIFY_RESULT=""

    kill "$TLS_TEST_PID" 2>/dev/null || true
    wait "$TLS_TEST_PID" 2>/dev/null || true
    TLS_TEST_PID=""

    if [[ -z "$VERIFY_RESULT" ]]; then
        die 12 "TLS verification failed — certificate may be invalid"
    fi
    log "TLS verification passed: ${VERIFY_RESULT}"

    # Verify alias certificates
    for _alias_domain in "${ALL_SSL_DOMAINS[@]:1}"; do
        _ALIAS_CERT="/etc/letsencrypt/live/${_alias_domain}/fullchain.pem"
        _ALIAS_KEY="/etc/letsencrypt/live/${_alias_domain}/privkey.pem"

        log "Verifying TLS certificate for alias: ${_alias_domain}"
        kill "$TLS_TEST_PID" 2>/dev/null || true
        wait "$TLS_TEST_PID" 2>/dev/null || true

        openssl s_server -cert "$_ALIAS_CERT" -key "$_ALIAS_KEY" \
            -accept 8443 -www -quiet &
        TLS_TEST_PID=$!
        sleep 1

        _ALIAS_VERIFY=$(printf '' | openssl s_client -connect localhost:8443 \
            -servername "${_alias_domain}" 2>/dev/null \
            | openssl x509 -noout -subject 2>/dev/null) || _ALIAS_VERIFY=""

        kill "$TLS_TEST_PID" 2>/dev/null || true
        wait "$TLS_TEST_PID" 2>/dev/null || true
        TLS_TEST_PID=""

        if [[ -z "$_ALIAS_VERIFY" ]]; then
            die 12 "TLS verification failed for alias ${_alias_domain}"
        fi
        log "TLS verification passed for alias ${_alias_domain}: ${_ALIAS_VERIFY}"
    done
else
    log "Skipping TLS verification (SSL_SKIP_VERIFY=true)"
fi

# ---------------------------------------------------------------------------
# Step 6: Re-register ALL domains with HAProxy including HTTPS port
# ---------------------------------------------------------------------------
if [[ -n "$HAPROXY_DETECTED" ]]; then
    build_auth_header
    _haproxy_reregister_url="http://${HAPROXY_IP:-${HAPROXY_DETECTED}}:${HAPROXY_API_PORT}/v1/backends"

    # Primary domain → app's HTTPS port
    PAYLOAD=$(jq -n \
        --arg domain "$SSL_DOMAIN" \
        --arg container "$(hostname)" \
        --argjson http_port 80 \
        --argjson https_port "${SSL_HTTPS_PORT}" \
        --argjson extra_ports "${EXTRA_PORTS:-null}" \
        '{domain: $domain, container: $container, http_port: $http_port, https_port: $https_port, extra_ports: $extra_ports}')

    http_code=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST "$_haproxy_reregister_url" \
        -H "Content-Type: application/json" \
        "${AUTH_HEADER_ARGS[@]}" \
        -d "$PAYLOAD" --max-time 10 2>/dev/null) || http_code="000"

    if [[ "$http_code" != "200" && "$http_code" != "201" ]]; then
        die 13 "HAProxy HTTPS registration failed for ${SSL_DOMAIN} (status=${http_code})"
    fi
    log "Registered ${SSL_DOMAIN} with HAProxy (HTTPS port=${SSL_HTTPS_PORT})"

    # Alias domains → ssl-alias-proxy port (TLS terminated by ssl-manager)
    for _reg_domain in "${ALL_SSL_DOMAINS[@]:1}"; do
        PAYLOAD=$(jq -n \
            --arg domain "$_reg_domain" \
            --arg container "$(hostname)" \
            --argjson http_port 80 \
            --argjson https_port "${SSL_ALIAS_PROXY_PORT}" \
            --argjson extra_ports "${EXTRA_PORTS:-null}" \
            '{domain: $domain, container: $container, http_port: $http_port, https_port: $https_port, extra_ports: $extra_ports}')

        http_code=$(curl -s -o /dev/null -w '%{http_code}' \
            -X POST "$_haproxy_reregister_url" \
            -H "Content-Type: application/json" \
            "${AUTH_HEADER_ARGS[@]}" \
            -d "$PAYLOAD" --max-time 10 2>/dev/null) || http_code="000"

        if [[ "$http_code" != "200" && "$http_code" != "201" ]]; then
            die 13 "HAProxy HTTPS registration failed for alias ${_reg_domain} (status=${http_code})"
        fi
        log "Registered alias ${_reg_domain} with HAProxy (HTTPS→alias proxy port=${SSL_ALIAS_PROXY_PORT})"
    done
fi

# ---------------------------------------------------------------------------
# Step 6b: Start TLS alias proxy (if aliases configured)
# ---------------------------------------------------------------------------
if [[ ${#ALL_SSL_DOMAINS[@]} -gt 1 ]]; then
    log "Starting TLS alias proxy on port ${SSL_ALIAS_PROXY_PORT}"
    python3 /usr/local/bin/ssl-alias-proxy &
    ALIAS_PROXY_PID=$!
    echo "$ALIAS_PROXY_PID" > /tmp/.ssl-alias-proxy.pid

    # Wait for alias proxy to bind
    for _ in $(seq 1 10); do
        if nc -z localhost "$SSL_ALIAS_PROXY_PORT" 2>/dev/null; then
            log "TLS alias proxy ready (PID ${ALIAS_PROXY_PID})"
            break
        fi
        sleep 0.5
    done
fi

# ---------------------------------------------------------------------------
# Step 7: Start background renewal loop
# ---------------------------------------------------------------------------
log "Starting certificate renewal background loop"
/usr/local/bin/ssl-renew &
RENEWAL_PID=$!
echo "$RENEWAL_PID" > /tmp/.ssl-renew.pid
log "Renewal loop started (PID ${RENEWAL_PID})"

# ---------------------------------------------------------------------------
# Step 8: Export SSL cert paths
# ---------------------------------------------------------------------------
export SSL_CERT_FILE="$CERT_FILE"
export SSL_KEY_FILE="$KEY_FILE"

# Write paths to a sourceable file so the entrypoint can pick them up
# Primary cert paths (backwards compatible)
cat > /tmp/.ssl-env <<EOF
SSL_CERT_FILE=${CERT_FILE}
SSL_KEY_FILE=${KEY_FILE}
EOF

# Append alias cert paths for multi-domain consumers
if [[ ${#ALL_SSL_DOMAINS[@]} -gt 1 ]]; then
    {
        echo "SSL_ALL_DOMAINS=\"${ALL_SSL_DOMAINS[*]}\""
        for _d in "${ALL_SSL_DOMAINS[@]:1}"; do
            _var_safe=${_d//[.-]/_}
            echo "SSL_CERT_${_var_safe}=/etc/letsencrypt/live/${_d}/fullchain.pem"
            echo "SSL_KEY_${_var_safe}=/etc/letsencrypt/live/${_d}/privkey.pem"
        done
    } >> /tmp/.ssl-env
fi

EXPIRY_INFO=$(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)
log "SSL setup complete for ${SSL_DOMAIN}"
log "  Certificate: ${CERT_FILE}"
log "  Private key: ${KEY_FILE}"
log "  Expires:     ${EXPIRY_INFO}"
for _d in "${ALL_SSL_DOMAINS[@]:1}"; do
    _ALIAS_EXPIRY=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/${_d}/fullchain.pem" | cut -d= -f2)
    log "  Alias ${_d}: ${_ALIAS_EXPIRY}"
done

exit 0
