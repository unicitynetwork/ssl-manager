# tunnel-client — expose a firewalled service through the shared haproxy

A standalone image that tunnels **any http/https service** running on a host with **no
public IP** to the shared haproxy, which then fronts it at `https://<domain>` (or
`http://<domain>`) exactly like any other backend. Pairs with the
[`staging-tunnel`](../ssh-tunnel-endpoint) sshd endpoint. The remote host needs only **Docker +
credentials** — nothing else.

```
user ──HTTPS──► haproxy :443 (SNI) ──► staging-tunnel:<rport> ──ssh -R──► your service:<port>
                (public host)                                            (firewalled host, TLS here)
```

## How it differs from a normal reverse proxy

- **TLS terminates at YOUR service** (haproxy does SNI / TCP passthrough on `:443`, `mode
  tcp`). In `MODE=https` your service must serve a valid cert for `<domain>`. This is the
  same model as every other haproxy-net backend.
- `MODE=http` registers on the `:80` `mode http` frontend instead — haproxy proxies plain
  HTTP to your service (no cert needed), but only `:80` is served (haproxy terminates no TLS).
- Registration points at the **endpoint** (`container: staging-tunnel` + the tunnel port),
  not your container — your container can't self-register (it isn't on haproxy-net). This
  client does the registration for it over the tunnel.

## Prerequisites (one-time, arranged by the haproxy host admin)

1. The `staging-tunnel` endpoint is running (see [../ssh-tunnel-endpoint](../ssh-tunnel-endpoint)).
2. Your public key is in the endpoint's `authorized_keys` (tunnel-only).
3. A DNS record for `<domain>` → the haproxy host's public IP.
4. The tunnel port range (`21000-21099`) is in haproxy's `ALLOWED_PORTS` (default).

You'll be given: the host + ssh port, the host-key `SHA256:…` fingerprint, and your key.

## Usage

### Convenience runner

```bash
./run-tunnel.sh \
  --domain   myservice.example.com \
  --target   localhost:8443 \
  --host     213.199.61.236 \
  --ssh-port 2222 \
  --key      ~/.ssh/tunnel_ed25519 \
  --fingerprint SHA256:f+l7Rb8TmYCkHdlovb7CZPxhLiSdKy0OdzXkO1MeQ5Q \
  --mode https \
  --net my-app-network      # so the container can reach the service by name; or --net host
```

`--target HOST:PORT` must be reachable **from the tunnel container** — share the service's
docker network with `--net`, or use `--net host` and `localhost:<port>`. `--dry-run` prints
the `docker run` without executing.

### Plain docker run

```bash
docker run -d --name tunnel-myservice --restart unless-stopped \
  --network my-app-network \
  -v ~/.ssh/tunnel_ed25519:/tunnel/id:ro \
  -e PUBLIC_HOST=213.199.61.236 -e TUNNEL_SSH_PORT=2222 \
  -e TUNNEL_HOST_KEY_FINGERPRINT=SHA256:… \
  -e DOMAIN=myservice.example.com \
  -e TARGET_HOST=myservice -e TARGET_PORT=8443 \
  -e MODE=https \
  tunnel-client:latest
```

### As a compose sidecar

```yaml
services:
  tunnel:
    image: tunnel-client:latest
    restart: unless-stopped
    depends_on: [myservice]
    environment:
      PUBLIC_HOST: 213.199.61.236
      TUNNEL_SSH_PORT: "2222"
      TUNNEL_HOST_KEY_FINGERPRINT: SHA256:…
      DOMAIN: myservice.example.com
      TARGET_HOST: myservice
      TARGET_PORT: "8443"
      MODE: https
    volumes:
      - ./tunnel_ed25519:/tunnel/id:ro
```

## Environment

| Var | Default | Meaning |
|---|---|---|
| `PUBLIC_HOST` | — | Public haproxy host. **Required.** |
| `DOMAIN` | — | Public hostname to expose. **Required.** |
| `TARGET_HOST` / `TARGET_PORT` | — | The local service (reachable from this container). **Required.** |
| `MODE` | `https` | `https` = SNI passthrough on :443 (service serves TLS); `http` = mode-http on :80. |
| `TUNNEL_SSH_PORT` / `TUNNEL_SSH_USER` | `2022` / `tunnel` | Endpoint sshd port / user. |
| `TUNNEL_SSH_KEY` | `/tunnel/id` | Path to the mounted private key. |
| `TUNNEL_HOST_KEY_FINGERPRINT` | — | `SHA256:…` pin (recommended; else trust-on-first-use). |
| `TUNNEL_ENDPOINT_ALIAS` | `staging-tunnel` | haproxy-net name of the endpoint (the backend target). |
| `TUNNEL_PORT_BASE` / `TUNNEL_PORT_SPAN` | `21000` / `100` | Remote tunnel port range (must be in haproxy `ALLOWED_PORTS`). |
| `TUNNEL_API_KEY` | — | Bearer token, only if the endpoint API requires `HAPROXY_API_KEY`. |
| `HEALTHCHECK` / `HEALTHCHECK_PATH` | `true` / `/` | Gate "tunnel LIVE" on the service answering; set `false` for non-HTTP TCP. |

## Behavior / guarantees

- Verifies the endpoint host-key fingerprint before connecting.
- Picks a deterministic remote port from the domain (idempotent), retries across the range
  on a bind clash, and distinguishes ssh auth/connect failures from port clashes.
- Won't declare "tunnel LIVE" until the service actually answers (avoids advertising a 502).
- Auto-reconnects and re-registers; deregisters on `SIGTERM` (even via a one-shot tunnel if
  the reverse tunnel already dropped). **Tear down with `docker stop` (SIGTERM), not a hard
  kill** — deregistration is ownership-scoped, so a SIGKILL leaves a stale entry that only
  an endpoint-sourced delete can remove.

## Build / publish

```bash
docker build -t tunnel-client:latest .
# publish (optional): docker tag + docker push to your registry
```
