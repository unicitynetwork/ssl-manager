#!/bin/bash
# Same shape as a real ssl-manager consumer: ssl-setup, then exec the app.
set -e
ssl_exit=0
/usr/local/bin/ssl-setup || ssl_exit=$?
[ -f /tmp/.ssl-env ] && . /tmp/.ssl-env
export SSL_CERT_FILE SSL_KEY_FILE
if [ "$ssl_exit" -ne 0 ]; then
    echo "ssl-setup failed ($ssl_exit)" >&2
    exit "$ssl_exit"
fi
echo "app starting"
exec python3 /app.py
