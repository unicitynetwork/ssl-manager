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
# Log initial certificate expiry
# ---------------------------------------------------------------------------
CERT_FILE="/etc/letsencrypt/live/${SSL_DOMAIN}/fullchain.pem"

log_cert_expiry() {
    if [[ -f "$CERT_FILE" ]]; then
        local expiry_raw
        expiry_raw=$(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)
        local expiry_epoch now_epoch days_left
        expiry_epoch=$(date -d "$expiry_raw" +%s)
        now_epoch=$(date +%s)
        days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
        log "Certificate for ${SSL_DOMAIN} expires: ${expiry_raw} (${days_left} days remaining)"
    else
        warn "Certificate file not found: ${CERT_FILE}"
    fi
}

log "Renewal loop started for ${SSL_DOMAIN}"
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

    if certbot renew \
        --cert-name "${SSL_DOMAIN}" \
        --webroot \
        --webroot-path "$WEBROOT" \
        --deploy-hook "touch /tmp/.ssl-renewal-restart" \
        2>&1 | tee -a /var/log/certbot-renew.log; then
        log "Renewal check complete"
    else
        warn "Renewal check failed (certbot exited non-zero)"
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
