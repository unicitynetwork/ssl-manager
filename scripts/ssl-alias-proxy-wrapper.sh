#!/bin/bash
# ssl-alias-proxy-wrapper — Restarts the TLS alias proxy on crash.
#
# Python can't catch SIGSEGV (segfault in OpenSSL C code), so the
# internal Python supervisor loop doesn't help. This bash wrapper
# detects any non-zero exit (including signal-killed) and restarts
# with exponential backoff.
#
# Clean shutdown (exit 0 from SIGTERM/SIGINT) stops the loop.

set -u

BACKOFF=1
MAX_BACKOFF=60
STABLE_THRESHOLD=300  # reset backoff after 5 min of stable running
COUNT=0

while true; do
    COUNT=$((COUNT + 1))
    if [ $COUNT -gt 1 ]; then
        echo "[ssl-alias-wrapper] Restarting alias proxy (attempt $COUNT, backoff ${BACKOFF}s)"
        sleep $BACKOFF
        BACKOFF=$((BACKOFF * 2))
        if [ $BACKOFF -gt $MAX_BACKOFF ]; then BACKOFF=$MAX_BACKOFF; fi
    fi

    START_TIME=$(date +%s)
    python3 /usr/local/bin/ssl-alias-proxy "$@"
    EXIT_CODE=$?
    RUN_DURATION=$(( $(date +%s) - START_TIME ))

    if [ $EXIT_CODE -eq 0 ]; then
        echo "[ssl-alias-wrapper] Clean exit"
        break
    fi

    # Reset backoff if it ran stably for a while
    if [ $RUN_DURATION -gt $STABLE_THRESHOLD ]; then
        BACKOFF=1
        COUNT=1
    fi

    if [ $EXIT_CODE -gt 128 ]; then
        SIG=$((EXIT_CODE - 128))
        echo "[ssl-alias-wrapper] Proxy killed by signal $SIG (exit $EXIT_CODE) after ${RUN_DURATION}s"
    else
        echo "[ssl-alias-wrapper] Proxy exited with code $EXIT_CODE after ${RUN_DURATION}s"
    fi
done
