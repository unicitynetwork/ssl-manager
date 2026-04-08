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
COPY scripts/haproxy-register.sh /usr/local/bin/haproxy-register
COPY scripts/ssl-verify.sh      /usr/local/bin/ssl-verify
COPY scripts/ssl-http-proxy.py  /usr/local/bin/ssl-http-proxy
COPY scripts/ssl-alias-proxy.py /usr/local/bin/ssl-alias-proxy
COPY scripts/ssl-alias-proxy-wrapper.sh /usr/local/bin/ssl-alias-proxy-wrapper

RUN chmod +x /usr/local/bin/ssl-setup \
             /usr/local/bin/ssl-renew \
             /usr/local/bin/haproxy-register \
             /usr/local/bin/ssl-verify \
             /usr/local/bin/ssl-http-proxy \
             /usr/local/bin/ssl-alias-proxy \
             /usr/local/bin/ssl-alias-proxy-wrapper

# ACME challenge webroot directory
RUN mkdir -p /var/www/acme-challenge/.well-known/acme-challenge

# HTTP reverse proxy port (ACME challenges + app forwarding)
EXPOSE 80
# TLS alias proxy port (alias domain termination + forwarding to app)
EXPOSE 8444

# Let's Encrypt certificate storage -- mount a volume here
VOLUME ["/etc/letsencrypt"]
