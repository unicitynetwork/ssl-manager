FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        certbot \
        curl \
        jq \
        openssl \
        netcat-openbsd \
        python3 \
        ca-certificates \
        procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# SSL management scripts
COPY scripts/ssl-setup.sh       /usr/local/bin/ssl-setup
COPY scripts/ssl-renew.sh       /usr/local/bin/ssl-renew
COPY scripts/ssl-renewal-hook.sh /usr/local/bin/ssl-renewal-hook
COPY scripts/haproxy-register.sh /usr/local/bin/haproxy-register
COPY scripts/ssl-verify.sh      /usr/local/bin/ssl-verify
COPY scripts/ssl-http-proxy.py  /usr/local/bin/ssl-http-proxy
COPY scripts/ssl-alias-proxy.py /usr/local/bin/ssl-alias-proxy
COPY scripts/ssl-alias-proxy-wrapper.sh /usr/local/bin/ssl-alias-proxy-wrapper
# PROXY protocol v2 (default on; SSL_PROXY_PROTOCOL=off opts out)
COPY scripts/proxyproto.py      /usr/local/lib/ssl-manager/proxyproto.py
COPY scripts/ssl-pp-proxy.py    /usr/local/bin/ssl-pp-proxy
COPY scripts/ssl-pp-proxy-wrapper.sh /usr/local/bin/ssl-pp-proxy-wrapper

RUN chmod +x /usr/local/bin/ssl-setup \
             /usr/local/bin/ssl-renew \
             /usr/local/bin/ssl-renewal-hook \
             /usr/local/bin/haproxy-register \
             /usr/local/bin/ssl-verify \
             /usr/local/bin/ssl-http-proxy \
             /usr/local/bin/ssl-alias-proxy \
             /usr/local/bin/ssl-alias-proxy-wrapper \
             /usr/local/bin/ssl-pp-proxy \
             /usr/local/bin/ssl-pp-proxy-wrapper

# ACME challenge webroot directory
RUN mkdir -p /var/www/acme-challenge/.well-known/acme-challenge

# HTTP reverse proxy port (ACME challenges + app forwarding)
EXPOSE 80
# TLS alias proxy port (alias domain termination + forwarding to app)
EXPOSE 8444
# PROXY-v2-aware TLS shim (haproxy :443 SNI passthrough lands here; SSL_PROXY_HTTPS_PORT)
EXPOSE 8445

# Let's Encrypt certificate storage -- mount a volume here
VOLUME ["/etc/letsencrypt"]
