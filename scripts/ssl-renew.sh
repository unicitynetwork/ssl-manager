#!/bin/bash
# ssl-renew.sh — Certificate renewal background loop
#
# Runs as a background process for the lifetime of the container. Checks
# certificate renewal every ~12 hours with random jitter. Uses certbot
# webroot mode against the always-running HTTP reverse proxy on port 80.
#
# When SSL_TEST_MODE=true, self-signed certs do not expire meaningfully,
# so this script sleeps indefinitely.
#
# Started by ssl-setup after initial certificate acquisition.

set -euo pipefail

readonly SCRIPT_NAME="ssl-renew"
readonly LOG_PREFIX="[${SCRIPT_NAME}]"
readonly WEBROOT="/var/www/acme-challenge"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
: "${SSL_TEST_MODE:=false}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '%s %s\n' "$LOG_PREFIX" "$*"; }
warn() { printf '%s WARNING: %s\n' "$LOG_PREFIX" "$*" >&2; }

# ---------------------------------------------------------------------------
# Early exit: no domain configured
# ---------------------------------------------------------------------------
if [[ -z "${SSL_DOMAIN:-}" ]]; then
    log "SSL_DOMAIN not set — renewal loop not needed"
    exit 0
fi

# ---------------------------------------------------------------------------
# Self-signed mode: sleep forever (no real expiry to worry about)
# ---------------------------------------------------------------------------
if [[ "${SSL_TEST_MODE}" == "true" ]]; then
    log "SSL_TEST_MODE=true — self-signed cert does not need renewal"
    log "Sleeping indefinitely (renewal loop inactive)"
    # Sleep in a loop to handle spurious wakeups and remain interruptible
    while true; do
        sleep 86400
    done
fi

# ---------------------------------------------------------------------------
# Log certificate expiry for all domains
# ---------------------------------------------------------------------------
log_cert_expiry() {
    local _domains="${SSL_DOMAIN}"
    if [[ -n "${SSL_DOMAIN_ALIASES:-}" ]]; then
        _domains="${SSL_DOMAIN} ${SSL_DOMAIN_ALIASES//,/ }"
    fi
    for _domain in $_domains; do
        local _cert="/etc/letsencrypt/live/${_domain}/fullchain.pem"
        if [[ -f "$_cert" ]]; then
            local expiry_raw expiry_epoch now_epoch days_left
            expiry_raw=$(openssl x509 -enddate -noout -in "$_cert" | cut -d= -f2)
            expiry_epoch=$(date -d "$expiry_raw" +%s)
            now_epoch=$(date +%s)
            days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
            log "Certificate for ${_domain} expires: ${expiry_raw} (${days_left} days remaining)"
        else
            warn "Certificate file not found for ${_domain}: ${_cert}"
        fi
    done
}

log "Renewal loop started for ${SSL_DOMAIN}${SSL_DOMAIN_ALIASES:+ (aliases: ${SSL_DOMAIN_ALIASES})}"
log_cert_expiry

# ---------------------------------------------------------------------------
# Initial delay: 1 hour after container startup
# ---------------------------------------------------------------------------
log "Waiting 1 hour before first renewal check"
sleep 3600

# ---------------------------------------------------------------------------
# Main renewal loop: every ~12 hours with random jitter (0-1800s)
# ---------------------------------------------------------------------------
while true; do
    log "Checking certificate renewal..."

    # Check tunnel health before renewal (if tunnel mode is active)
    if [[ -f /tmp/.ssl-tunnel-env ]]; then
        # shellcheck disable=SC1091
        . /tmp/.ssl-tunnel-env
        if [[ "${TUNNEL_ACTIVE:-}" == "true" ]] && [[ "${TUNNEL_TYPE:-}" == "wireguard" ]]; then
            _wg_handshake=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
            _now=$(date +%s)
            if [[ -n "$_wg_handshake" ]] && [[ "$_wg_handshake" -gt 0 ]]; then
                _handshake_age=$(( _now - _wg_handshake ))
                if [[ "$_handshake_age" -gt 180 ]]; then
                    warn "Tunnel handshake stale (${_handshake_age}s ago) — skipping renewal attempt"
                    log "Next renewal check in ~12 hours"
                    JITTER=$((RANDOM % 1800))
                    sleep $((43200 + JITTER))
                    continue
                fi
            fi
        fi
    fi

    # Track consecutive certbot failures to avoid rate limit exhaustion
    : "${_certbot_failures:=0}"
    : "${_certbot_failure_day:=$(date +%j)}"
    _today=$(date +%j)
    if [[ "$_today" != "$_certbot_failure_day" ]]; then
        _certbot_failures=0
        _certbot_failure_day="$_today"
    fi

    if [[ "$_certbot_failures" -ge 2 ]]; then
        warn "Skipping renewal: ${_certbot_failures} failures today (max 2 per 24h per domain)"
        JITTER=$((RANDOM % 1800))
        sleep $((43200 + JITTER))
        continue
    fi

    # Renew all managed certs (primary + aliases) without --cert-name
    if certbot renew \
        --webroot \
        --webroot-path "$WEBROOT" \
        --deploy-hook "touch /tmp/.ssl-renewal-restart" \
        2>&1 | tee -a /var/log/certbot-renew.log; then
        log "Renewal check complete"
        _certbot_failures=0
    else
        warn "Renewal check failed (certbot exited non-zero)"
        _certbot_failures=$((_certbot_failures + 1))
        warn "Consecutive failures today: ${_certbot_failures}/2"
    fi

    # Log current certificate expiry after each check
    log_cert_expiry

    # Check if the deploy hook fired (cert was actually renewed)
    if [[ -f /tmp/.ssl-renewal-restart ]]; then
        log "Certificate was renewed — service should be restarted to load new cert"
    fi

    # Sleep ~12 hours with random jitter (0-1800 seconds / 0-30 minutes)
    JITTER=$((RANDOM % 1800))
    SLEEP_SECONDS=$((43200 + JITTER))
    log "Next renewal check in $((SLEEP_SECONDS / 3600))h $(( (SLEEP_SECONDS % 3600) / 60 ))m"
    sleep "$SLEEP_SECONDS"
done
