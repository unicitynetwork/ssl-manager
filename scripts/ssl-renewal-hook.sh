#!/bin/bash
# ssl-renewal-hook.sh — certbot --deploy-hook target, run once per *actual* renewal.
#
# Two responsibilities:
#   1. Touch the renewal marker (/tmp/.ssl-renewal-restart) so marker-watching
#      consumers reload the new cert — the app's supervisor loop (see
#      INTEGRATION.md "Certificate renewal") and the bundled ssl-alias-proxy.
#   2. If SSL_RELOAD_CMD is set, run it. This lets a long-running app that does
#      NOT actively watch the marker reload its cert with a one-line env var,
#      instead of every image re-implementing a watcher. Without this, a stable
#      app that loaded its cert into memory at startup keeps serving the old
#      (eventually EXPIRED) cert until it happens to restart — a footgun that
#      has caused production outages.
#
# certbot exports RENEWED_DOMAINS and RENEWED_LINEAGE to this hook; SSL_RELOAD_CMD
# may reference them. This hook never fails the renewal: a reload-command error is
# logged, not fatal.

set -uo pipefail

readonly MARKER="/tmp/.ssl-renewal-restart"
log()  { printf '[ssl-renewal-hook] %s\n' "$*"; }
warn() { printf '[ssl-renewal-hook] WARNING: %s\n' "$*" >&2; }

# 1. Marker — preserves the existing contract for marker-watching consumers.
if touch "$MARKER" 2>/dev/null; then
    log "renewal marker touched: ${MARKER} (renewed: ${RENEWED_DOMAINS:-unknown})"
else
    warn "could not touch marker ${MARKER}"
fi

# 2. Optional explicit reload command — closes the "stale cert in memory" footgun
#    for apps that do not watch the marker. Keep SSL_RELOAD_CMD self-resolving
#    (e.g. 'pkill -HUP -x myapp' or 'kill -HUP "$(cat /run/myapp.pid)"'): it runs
#    in the renewal process tree, not the app's, so it cannot see a PID the app
#    exported after startup.
if [[ -n "${SSL_RELOAD_CMD:-}" ]]; then
    log "running SSL_RELOAD_CMD: ${SSL_RELOAD_CMD}"
    if bash -c "${SSL_RELOAD_CMD}"; then
        log "SSL_RELOAD_CMD completed successfully"
    else
        warn "SSL_RELOAD_CMD exited non-zero (${?})"
    fi
fi

exit 0
