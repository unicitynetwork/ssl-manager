#!/bin/bash
# haproxy-register.sh — HAProxy Registration API client
#
# Usage:
#   haproxy-register.sh register     Register this container with HAProxy
#   haproxy-register.sh unregister   Remove this container from HAProxy
#
# Registration POSTs to /v1/backends with domain, container hostname, ports,
# and optional extra_ports. Returns 0 on 200/201, 1 on failure.
#
# Unregistration sends DELETE to /v1/backends/$SSL_DOMAIN. Returns 0 on
# 204 or 404 (already gone), warns on other status codes.
#
# Environment variables:
#   SSL_DOMAIN        — domain to register (required)
#   SSL_HTTPS_PORT    — backend HTTPS port (default: 443)
#   APP_HTTP_PORT     — application HTTP port (default: 0)
#   HAPROXY_HOST      — HAProxy hostname (required)
#   HAPROXY_API_PORT  — HAProxy API port (default: 8404)
#   HAPROXY_API_KEY   — bearer token for API auth (optional)
#   EXTRA_PORTS       — JSON array of extra port mappings (optional)

set -euo pipefail

readonly SCRIPT_NAME="haproxy-register"
readonly LOG_PREFIX="[${SCRIPT_NAME}]"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
: "${SSL_HTTPS_PORT:=443}"
: "${HAPROXY_API_PORT:=8404}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '%s %s\n' "$LOG_PREFIX" "$*"; }
warn() { printf '%s WARNING: %s\n' "$LOG_PREFIX" "$*" >&2; }
err()  { printf '%s ERROR: %s\n' "$LOG_PREFIX" "$*" >&2; }

usage() {
    printf 'Usage: %s register|unregister\n' "$SCRIPT_NAME" >&2
    exit 1
}

# Build curl auth header arguments as an array
build_auth_header() {
    AUTH_HEADER_ARGS=()
    if [[ -n "${HAPROXY_API_KEY:-}" ]]; then
        AUTH_HEADER_ARGS=(-H "Authorization: Bearer ${HAPROXY_API_KEY}")
    fi
}

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    usage
fi

ACTION="$1"

if [[ -z "${SSL_DOMAIN:-}" ]]; then
    err "SSL_DOMAIN is not set"
    exit 1
fi

if [[ -z "${HAPROXY_HOST:-}" ]]; then
    err "HAPROXY_HOST is not set"
    exit 1
fi

for cmd in curl jq; do
    command -v "$cmd" &>/dev/null || { err "Required command not found: ${cmd}"; exit 1; }
done

BASE_URL="http://${HAPROXY_HOST}:${HAPROXY_API_PORT}/v1/backends"
build_auth_header

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
case "$ACTION" in
    register)
        PAYLOAD=$(jq -n \
            --arg domain "$SSL_DOMAIN" \
            --arg container "$(hostname)" \
            --argjson http_port 80 \
            --argjson https_port "${SSL_HTTPS_PORT}" \
            --argjson extra_ports "${EXTRA_PORTS:-null}" \
            '{domain: $domain, container: $container, http_port: $http_port, https_port: $https_port, extra_ports: $extra_ports}')

        http_code=$(curl -sf -o /tmp/.haproxy-register-response -w '%{http_code}' \
            -X POST "${BASE_URL}" \
            -H "Content-Type: application/json" \
            "${AUTH_HEADER_ARGS[@]}" \
            -d "$PAYLOAD" 2>/dev/null) || http_code="000"

        if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
            log "Registered with HAProxy: domain=${SSL_DOMAIN}, https_port=${SSL_HTTPS_PORT} (status=${http_code})"
        else
            err "Registration failed (status=${http_code})"
            if [[ -f /tmp/.haproxy-register-response ]]; then
                err "Response: $(cat /tmp/.haproxy-register-response)"
            fi
            exit 1
        fi

        # Register alias domains
        if [[ -n "${SSL_DOMAIN_ALIASES:-}" ]]; then
            IFS=',' read -ra _aliases <<< "$SSL_DOMAIN_ALIASES"
            for _alias in "${_aliases[@]}"; do
                _alias=$(echo "$_alias" | xargs)
                [[ -z "$_alias" ]] && continue
                # Aliases use the alias proxy port (TLS terminated by ssl-manager)
                ALIAS_PAYLOAD=$(jq -n \
                    --arg domain "$_alias" \
                    --arg container "$(hostname)" \
                    --argjson http_port 80 \
                    --argjson https_port "${SSL_HTTPS_PORT}" \
                    --argjson extra_ports "${EXTRA_PORTS:-null}" \
                    '{domain: $domain, container: $container, http_port: $http_port, https_port: $https_port, extra_ports: $extra_ports}')

                _code=$(curl -sf -o /dev/null -w '%{http_code}' \
                    -X POST "${BASE_URL}" -H "Content-Type: application/json" \
                    "${AUTH_HEADER_ARGS[@]}" -d "$ALIAS_PAYLOAD" 2>/dev/null) || _code="000"

                if [[ "$_code" == "200" || "$_code" == "201" ]]; then
                    log "Registered alias: ${_alias} (https_port=${SSL_HTTPS_PORT}, status=${_code})"
                else
                    warn "Failed to register alias: ${_alias} (status=${_code})"
                fi
            done
        fi
        exit 0
        ;;

    unregister)
        # Unregister primary domain
        http_code=$(curl -sf -o /tmp/.haproxy-register-response -w '%{http_code}' \
            -X DELETE "${BASE_URL}/${SSL_DOMAIN}" \
            "${AUTH_HEADER_ARGS[@]}" 2>/dev/null) || http_code="000"

        if [[ "$http_code" == "204" || "$http_code" == "200" ]]; then
            log "Unregistered from HAProxy: domain=${SSL_DOMAIN} (status=${http_code})"
        elif [[ "$http_code" == "404" ]]; then
            warn "Domain ${SSL_DOMAIN} was not registered with HAProxy (404 — already gone)"
        else
            warn "Unexpected response during unregistration (status=${http_code})"
            if [[ -f /tmp/.haproxy-register-response ]]; then
                warn "Response: $(cat /tmp/.haproxy-register-response)"
            fi
        fi

        # Unregister alias domains
        if [[ -n "${SSL_DOMAIN_ALIASES:-}" ]]; then
            IFS=',' read -ra _aliases <<< "$SSL_DOMAIN_ALIASES"
            for _alias in "${_aliases[@]}"; do
                _alias=$(echo "$_alias" | xargs)
                [[ -z "$_alias" ]] && continue
                curl -sf -o /dev/null -X DELETE "${BASE_URL}/${_alias}" \
                    "${AUTH_HEADER_ARGS[@]}" 2>/dev/null || true
                log "Unregistered alias: ${_alias}"
            done
        fi
        exit 0
        ;;

    *)
        err "Unknown action: ${ACTION}"
        usage
        ;;
esac
