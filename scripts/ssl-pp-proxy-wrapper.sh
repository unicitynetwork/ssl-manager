#!/bin/bash
# ssl-pp-proxy-wrapper -- keeps the PROXY-aware TLS shim (ssl-pp-proxy) running.
#
# haproxy keeps routing :443 to the shim port for as long as the registration
# says so; a dead shim would therefore black-hole HTTPS. Restart on any non-zero
# exit with exponential backoff (reset after 5 min of stable running). A clean
# exit (0, from SIGTERM/SIGINT) stops the loop.

set -u

BACKOFF=1
MAX_BACKOFF=30
STABLE_THRESHOLD=300
COUNT=0
CHILD=""

trap '[ -n "$CHILD" ] && kill "$CHILD" 2>/dev/null; exit 0' TERM INT

while true; do
    COUNT=$((COUNT + 1))
    if [ "$COUNT" -gt 1 ]; then
        echo "[ssl-pp-proxy-wrapper] Restarting shim (attempt $COUNT, backoff ${BACKOFF}s)" >&2
        sleep "$BACKOFF"
        BACKOFF=$((BACKOFF * 2))
        [ "$BACKOFF" -gt "$MAX_BACKOFF" ] && BACKOFF=$MAX_BACKOFF
    fi
    START_TIME=$(date +%s)
    python3 /usr/local/bin/ssl-pp-proxy "$@" &
    CHILD=$!
    wait "$CHILD"
    EXIT_CODE=$?
    CHILD=""
    RUN_DURATION=$(( $(date +%s) - START_TIME ))
    if [ "$EXIT_CODE" -eq 0 ]; then
        echo "[ssl-pp-proxy-wrapper] Clean exit"
        break
    fi
    if [ "$EXIT_CODE" -eq 2 ]; then
        echo "[ssl-pp-proxy-wrapper] Configuration error (exit 2) -- not restarting" >&2
        exit 2
    fi
    if [ "$RUN_DURATION" -gt "$STABLE_THRESHOLD" ]; then
        BACKOFF=1
        COUNT=1
    fi
    echo "[ssl-pp-proxy-wrapper] Shim exited with code $EXIT_CODE after ${RUN_DURATION}s" >&2
done
