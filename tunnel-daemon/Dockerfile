# haproxy-tunnel-daemon — Server-side tunnel management sidecar
#
# Runs as a sidecar sharing HAProxy's network namespace.
# Manages WireGuard peers, DTNP negotiation, and HAProxy backends.
#
# Usage:
#   docker run --network container:haproxy \
#     --cap-add NET_ADMIN \
#     --device /dev/net/tun:/dev/net/tun \
#     -v haproxy-socket:/var/run/haproxy \
#     -v tunnel-acl:/etc/haproxy-tunnel \
#     haproxy-tunnel-daemon

FROM debian:trixie-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        wireguard-tools \
        iproute2 \
        iptables \
        curl \
        jq \
        openssl \
        ca-certificates \
        iputils-ping \
        procps \
        nodejs \
        npm \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy daemon source
COPY src/ /opt/tunnel-daemon/src/
COPY package.json /opt/tunnel-daemon/

# Install Node.js dependencies
WORKDIR /opt/tunnel-daemon
RUN npm install --production 2>/dev/null || true

# Create required directories
RUN mkdir -p /var/lib/haproxy-tunnel/peers \
    && mkdir -p /etc/haproxy-tunnel \
    && mkdir -p /etc/wireguard

# Default ACL file (empty, must be configured)
RUN echo '{"acl":[]}' > /etc/haproxy-tunnel/acl.json

EXPOSE 9100

ENTRYPOINT ["node", "/opt/tunnel-daemon/src/index.mjs"]
