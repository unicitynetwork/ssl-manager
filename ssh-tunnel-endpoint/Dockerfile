# staging-tunnel — restricted sshd endpoint for remote (firewalled) staging backends.
#
# A tunnel-only OpenSSH server joined to `haproxy-net`. Firewalled hosts (dev laptops)
# open an SSH reverse tunnel here (`ssh -R 0.0.0.0:<rport>:backend:443`) and register
# their domain with the shared haproxy over an SSH `-L` forward to the Registration API
# (`haproxy:8404`). haproxy then SNI-routes `<feature>.staging.<base>` :443 to
# `staging-tunnel:<rport>`, through the tunnel, to the remote backend.
#
# No shell, no PTY, forwarding locked down per-key (see authorized_keys) — see README.md.
FROM alpine:3.20

RUN apk add --no-cache openssh-server && \
    adduser -D -s /bin/sh tunnel && \
    passwd -u tunnel 2>/dev/null || true

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && \
    mkdir -p /home/tunnel/.ssh /etc/ssh/keys && \
    chown -R tunnel:tunnel /home/tunnel/.ssh && chmod 700 /home/tunnel/.ssh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
