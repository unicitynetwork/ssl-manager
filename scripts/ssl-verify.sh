#!/bin/bash
# ssl-verify.sh — Domain reachability and TLS verification
#
# Usage:
#   ssl-verify.sh http     Verify HTTP reachability via nonce
#   ssl-verify.sh https    Verify TLS connection via openssl s_client
#
# HTTP verification:
#   1. Generates a random nonce
#   2. POSTs it to the local HTTP proxy at /_ssl/nonce/
#   3. GETs it through the public domain
#   4. Confirms the nonce matches (proves end-to-end reachability)
#   Retries 3 times with 5-second intervals.
#
# HTTPS verification:
#   Connects via openssl s_client to SSL_DOMAIN:SSL_HTTPS_PORT and verifies
#   a valid TLS handshake occurs.
#
# Environment variables:
#   SSL_DOMAIN      — domain to verify (required)
#   SSL_HTTPS_PORT  — TLS port for HTTPS verification (default: 443)
#
# Exit codes:
#   0  — verification passed
#   1  — verification failed
#   2  — usage error

set -euo pipefail

readonly SCRIPT_NAME="ssl-verify"
readonly LOG_PREFIX="[${SCRIPT_NAME}]"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
: "${SSL_HTTPS_PORT:=443}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '%s %s\n' "$LOG_PREFIX" "$*"; }
err()  { printf '%s ERROR: %s\n' "$LOG_PREFIX" "$*" >&2; }

usage() {
    printf 'Usage: %s http|https\n' "$SCRIPT_NAME" >&2
    exit 2
}

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    usage
fi

MODE="$1"

if [[ -z "${SSL_DOMAIN:-}" ]]; then
    err "SSL_DOMAIN is not set"
    exit 1
fi

# ---------------------------------------------------------------------------
# Verification modes
# ---------------------------------------------------------------------------
case "$MODE" in
    http)
        command -v curl &>/dev/null || { err "Required command not found: curl"; exit 1; }
        command -v openssl &>/dev/null || { err "Required command not found: openssl"; exit 1; }

        NONCE=$(openssl rand -hex 16)
        log "HTTP nonce verification for ${SSL_DOMAIN} (nonce=${NONCE:0:8}...)"

        # Register the nonce with the local proxy
        if ! curl -sf -X POST "http://localhost:80/_ssl/nonce/${NONCE}" >/dev/null 2>&1; then
            err "Failed to register nonce with local HTTP proxy (is ssl-http-proxy running on port 80?)"
            exit 1
        fi

        NONCE_MATCHED=false
        RESPONSE=""
        for attempt in 1 2 3; do
            RESPONSE=$(curl -sf --max-time 10 "http://${SSL_DOMAIN}/_ssl/nonce/${NONCE}" 2>/dev/null) || RESPONSE=""
            if [[ "$RESPONSE" == "$NONCE" ]]; then
                NONCE_MATCHED=true
                break
            fi
            if [[ "$attempt" -lt 3 ]]; then
                log "Nonce attempt ${attempt}/3 failed, retrying in 5s..."
                sleep 5
            fi
        done

        # Clean up the nonce
        curl -sf -X DELETE "http://localhost:80/_ssl/nonce/${NONCE}" >/dev/null 2>&1 || true

        if [[ "$NONCE_MATCHED" == "true" ]]; then
            log "HTTP verification passed — domain ${SSL_DOMAIN} is reachable"
            exit 0
        else
            err "HTTP verification failed — domain ${SSL_DOMAIN} is not routable to this container"
            err "  Expected nonce: ${NONCE}"
            err "  Got: ${RESPONSE:-<no response>}"
            exit 1
        fi
        ;;

    https)
        command -v openssl &>/dev/null || { err "Required command not found: openssl"; exit 1; }

        log "TLS verification for ${SSL_DOMAIN}:${SSL_HTTPS_PORT}"

        # Connect via openssl s_client and extract the certificate subject
        TLS_OUTPUT=$(printf '' | openssl s_client \
            -connect "${SSL_DOMAIN}:${SSL_HTTPS_PORT}" \
            -servername "${SSL_DOMAIN}" \
            2>/dev/null) || TLS_OUTPUT=""

        SUBJECT=$(printf '%s' "$TLS_OUTPUT" \
            | openssl x509 -noout -subject 2>/dev/null) || SUBJECT=""

        if [[ -n "$SUBJECT" ]]; then
            log "TLS verification passed: ${SUBJECT}"

            # Also extract and log expiry
            EXPIRY=$(printf '%s' "$TLS_OUTPUT" \
                | openssl x509 -noout -enddate 2>/dev/null) || EXPIRY=""
            if [[ -n "$EXPIRY" ]]; then
                log "Certificate expiry: ${EXPIRY}"
            fi

            exit 0
        else
            err "TLS verification failed — could not complete handshake to ${SSL_DOMAIN}:${SSL_HTTPS_PORT}"
            exit 1
        fi
        ;;

    *)
        err "Unknown mode: ${MODE}"
        usage
        ;;
esac
