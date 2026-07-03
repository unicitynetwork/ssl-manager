# tunnel-client — standalone image to tunnel any http/https service on a firewalled host
# through the shared haproxy (pairs with the staging-tunnel sshd endpoint). No dependency
# on the service being tunneled: just Docker + credentials on the remote host.
FROM alpine:3.20

RUN apk add --no-cache openssh-client curl coreutils

COPY tunnel.sh /usr/local/bin/tunnel.sh
RUN chmod +x /usr/local/bin/tunnel.sh

ENTRYPOINT ["/usr/local/bin/tunnel.sh"]
