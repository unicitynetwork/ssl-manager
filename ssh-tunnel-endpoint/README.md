# ssh-tunnel-endpoint — SSH tunnel endpoint for remote services

A restricted, tunnel-only OpenSSH server on `haproxy-net` that lets **firewalled hosts**
(no public IP) serve an http/https service through the shared public haproxy. This is the
**server** side of the lightweight, negotiation-free **ssh-lite** tunnel mode; the
**client** is [`../ssh-tunnel-client`](../ssh-tunnel-client). (The heavier, Nostr-negotiated
WireGuard "full mode" is [`../tunnel-daemon`](../tunnel-daemon) + [`../tunnel-manager`](../tunnel-manager).)

A remote host opens an **SSH reverse tunnel** here and registers its domain with the shared
haproxy over an SSH `-L` forward to the Registration API:

```
remote:  ssh -R 0.0.0.0:<rport>:<service>:<port> -L 127.0.0.1:8404:haproxy:8404 tunnel@<host>:2022
         curl -XPOST http://127.0.0.1:8404/v1/backends \
              -d '{"domain":"<name>.<base>","container":"staging-tunnel","https_port":<rport>}'

result:  user ──HTTPS──► haproxy :443 (SNI) ──► staging-tunnel:<rport> ──ssh -R──► remote service:<port>
```

TLS terminates on the remote service (haproxy does SNI/TCP passthrough), so the tunnel
carries encrypted traffic only. The client automates all of this — see its README.

## Prerequisite (haproxy config, one-time)

The reverse-tunnel bind ports (default `21000-21099`) must be in haproxy's `ALLOWED_PORTS`
allowlist. That lives in the **haproxy** repo (`internal-ports.conf` — allowed for
registration but not host-published; applied by `./run-haproxy.sh`). It is haproxy config,
not part of this component.

## Deploy (on the haproxy host)

1. **Add developer keys.** Copy the example and add each host's public key, locked to
   tunnel-only + the Registration API:

   ```bash
   cp authorized_keys.example authorized_keys
   # append lines like:
   # restrict,port-forwarding,permitopen="haproxy:8404" ssh-ed25519 AAAA... alice@host
   ```

   `authorized_keys` is gitignored — never commit it.

2. **Provide a stable host key** (recommended). Generate once into the gitignored
   `hostkeys/` dir; the entrypoint installs it authoritatively on every start, so the
   fingerprint clients pin survives `docker compose down -v`, volume loss, and redeploys on
   another host. Skip this and the container auto-generates a key into its volume instead —
   stable across restarts, but a **new fingerprint** if the volume is ever recreated (which
   re-pins every client).

   ```bash
   mkdir -p hostkeys
   ssh-keygen -t ed25519 -N '' -f hostkeys/ssh_host_ed25519_key
   ssh-keygen -t rsa   -b 3072 -N '' -f hostkeys/ssh_host_rsa_key
   ```

   `hostkeys/` is gitignored — **back it up**, never commit it. (To keep an already-deployed
   fingerprint, copy the running key out first: `docker cp <name>:/etc/ssh/keys/. hostkeys/`.)

3. **Start the endpoint** (host port `2022` is often taken — override with `TUNNEL_SSH_PORT`):

   ```bash
   TUNNEL_SSH_PORT=2222 docker compose up -d --build
   ```

   Then read the **host-key** fingerprint to distribute as the pin. Do NOT `tail` the logs
   for `SHA256:` — sshd runs verbose and also logs *client* key fingerprints on connect. Use:

   ```bash
   docker logs staging-tunnel | grep -A1 'endpoint host key fingerprint'   # the startup line
   # or authoritatively, exactly what a client pins:
   ssh-keyscan -p 2222 <public-host> | ssh-keygen -lf -
   ```

   Give each remote host: the public host + ssh port, the `SHA256:…` fingerprint, and its key.
   The `container_name` (haproxy-net alias haproxy routes to) defaults to `staging-tunnel`;
   override with `TUNNEL_ENDPOINT_NAME` and have clients set `TUNNEL_ENDPOINT_ALIAS` to match.

## Security model

- **Key-only, no shell, no PTY.** `restrict,port-forwarding` disables everything except the
  forwards we need; `permitopen="haproxy:8404"` limits `-L` to the Registration API only.
- **Fail-closed by default.** Even a key added *without* those per-key options can't get a
  shell or reach other services: `sshd_config` sets `ForceCommand /bin/false` (any exec/shell
  request dies; `-N` tunnels are unaffected) and a global `PermitOpen haproxy:8404` (bounds `-L`
  for all keys). Per-key options remain the belt to this braces.
- **Reverse-tunnel bind ports** are bounded by the haproxy `ALLOWED_PORTS` allowlist
  (`21000-21099`) — a port a client binds that no domain is registered to is inert. The
  Registration API also rejects the internal ports (`8000`/`8404`) as a backend target.
- **Trust boundary.** A key-holder gains `haproxy-net` reach to `:8404` and can register
  domains — the same trust the shared haproxy already grants any on-net container. Issue
  per-host keys and revoke by removing the line. **Deregistration is ownership-scoped** (only
  a request sourced through the tunnel can delete that endpoint's registrations). Future
  hardening: `HAPROXY_API_KEY` + domain-scoped ACLs (the DTNP design has these).
- **Host keys** persist in the `ssh-tunnel-hostkeys` volume so the pinned fingerprint is
  stable across restarts.

## Rotate / revoke

- Revoke a host: delete its line from `authorized_keys`, `docker compose restart`.
- Rotate host key: `docker volume rm ssh-tunnel-endpoint_ssh-tunnel-hostkeys` then restart
  (re-distribute the new pin).
