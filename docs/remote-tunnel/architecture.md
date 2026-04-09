# Remote HAProxy Tunneling — Architecture Design

## 1. High-Level Architecture

```
FIREWALL-CONSTRAINED CLIENT HOST                 PUBLIC REMOTE HOST
┌──────────────────────────────────────────┐     ┌──────────────────────────────────────────────┐
│  Docker Container (ssl-manager derived)  │     │  Remote HAProxy Host                         │
│                                          │     │                                              │
│  ┌──────────────────────────────────┐   │     │  ┌──────────────────────────────────────┐   │
│  │  ssl-setup (orchestration)       │   │     │  │  haproxy-tunnel-daemon               │   │
│  │  - Detects REMOTE_HAPROXY_ID     │   │     │  │  - Listens on Nostr relays           │   │
│  │  - Delegates to tunnel-manager   │   │     │  │  - Handles DM negotiation            │   │
│  └──────────┬───────────────────────┘   │     │  │  - Manages tunnel port pool          │   │
│             │                           │     │  │  - Updates HAProxy config (runtime)  │   │
│  ┌──────────▼───────────────────────┐   │     │  │  - Calls DynDNS API                  │   │
│  │  tunnel-manager (new component)  │   │     │  └──────────────┬───────────────────────┘   │
│  │  - DM negotiation via Sphere SDK │◄──┼─────┼─────────────────┘  (Nostr/NIP-17)          │
│  │  - Establishes outbound tunnel   │   │     │                                              │
│  │  - Monitors + reconnects         │   │     │  ┌──────────────────────────────────────┐   │
│  │  - Signals ssl-setup on ready    │   │     │  │  HAProxy (runtime config)            │   │
│  └──────────┬───────────────────────┘   │     │  │  - Frontend port 80 / 443            │   │
│             │                           │     │  │  - Per-domain backend → tunnel port  │   │
│  ┌──────────▼───────────────────────┐   │     │  └──────────────────────────────────────┘   │
│  │  SSH / WireGuard tunnel          ├───┼────►│  tunnel-port-N (e.g., 127.0.0.1:21080)      │
│  │  (outbound, client-initiated)    │   │     │  tunnel-port-M (e.g., 127.0.0.1:21443)      │
│  └──────────┬───────────────────────┘   │     │                                              │
│             │ loopback                  │     │  ┌──────────────────────────────────────┐   │
│  ┌──────────▼───────────────────────┐   │     │  │  DynDNS integration                  │   │
│  │  ssl-http-proxy (port 80)        │   │     │  │  (Cloudflare, Route53, RFC 2136)     │   │
│  │  ssl-alias-proxy (port 8444)     │   │     │  └──────────────────────────────────────┘   │
│  │  App (port SSL_HTTPS_PORT)       │   │     │                                              │
│  └──────────────────────────────────┘   │     └──────────────────────────────────────────────┘
│                                          │
│  Nostr identity: client.npub             │                Internet
│  /tmp/.ssl-tunnel-env                    │                    │
└──────────────────────────────────────────┘      ┌─────────────────────┐
                                                   │  DNS: mydomain.com  │
                                                   │  → remote-haproxy-  │
                                                   │    public-ip        │
                                                   └─────────────────────┘
```

### Traffic Flow After Tunnel Establishment

```
Internet user
    │ HTTPS mydomain.com
    ▼
Remote HAProxy (public IP, port 443)
    │ SNI match → backend tunnel-port-M (127.0.0.1:21443)
    ▼
SSH/WireGuard tunnel endpoint on remote host
    │ forwarded through outbound tunnel
    ▼
Container port SSL_HTTPS_PORT (app TLS, unchanged)

Internet user
    │ HTTP mydomain.com (ACME challenge, nonce)
    ▼
Remote HAProxy (public IP, port 80)
    │ Host match → backend tunnel-port-N (127.0.0.1:21080)
    ▼
SSH/WireGuard tunnel endpoint on remote host
    │ forwarded through outbound tunnel
    ▼
Container port 80 (ssl-http-proxy, unchanged)
```

---

## 2. Component Inventory

### New Components

#### `tunnel-manager` (in-container, `/usr/local/bin/tunnel-manager`)

The core new component. A bash + Python hybrid script that orchestrates the entire remote tunneling lifecycle: Nostr identity bootstrap, DM-based negotiation with the remote HAProxy, tunnel process management, heartbeat, and reconnection. Communicates with ssl-setup via two Unix signals and a shared state file at `/tmp/.ssl-tunnel-env`. Stateless between restarts — all persistent state lives in the letsencrypt volume.

#### `haproxy-tunnel-daemon` (remote host side, outside this image)

A long-running process on the remote HAProxy host. Listens on Nostr relays for tunnel request DMs addressed to its npub. Manages a pool of available local ports, enforces ACLs, responds with tunnel credentials, applies HAProxy runtime API changes, triggers DynDNS updates, and sends heartbeat acknowledgements. This component is a peer system — ssl-manager defines the protocol it must implement, but the daemon itself runs outside the Docker image.

#### `nostr-dm-client` (in-container, `/usr/local/bin/nostr-dm-client`)

A thin Python script wrapping the NIP-17 gift-wrap DM protocol over raw WebSocket connections to Nostr relays. Exposes a simple CLI: `nostr-dm-client send <npub> <json-payload>` and `nostr-dm-client recv <timeout-secs>`. Used exclusively by `tunnel-manager`. Does not depend on the Sphere SDK daemon — it is a self-contained implementation using only Python's standard library plus the secp256k1 primitives already available via the `cryptography` package installed with certbot.

#### `/tmp/.ssl-tunnel-env`

Sourceable file written by `tunnel-manager` when a tunnel is established. Contains `TUNNEL_HTTP_PORT`, `TUNNEL_HTTPS_PORT` (the remote ports on the HAProxy host forwarded into the container), and `TUNNEL_TYPE`. Read by ssl-setup to know the tunnel is live before proceeding.

#### `/tmp/.ssl-tunnel.pid`

PID file for the active tunnel process (autossh or wg-quick wrapper). Used by tunnel-manager for monitoring and graceful teardown.

### Modified Components

#### `ssl-setup.sh`

Gains a new early branch: if `REMOTE_HAPROXY_ID` is set, delegate to `tunnel-manager --wait-ready` before proceeding with HAProxy registration. After `tunnel-manager` signals readiness, ssl-setup reads `/tmp/.ssl-tunnel-env` to discover the remote tunnel ports and constructs its HAProxy registration payload using the remote-side REST API URL (communicated by the daemon in the DM response). The nonce verification step works unchanged — traffic arrives through the tunnel transparently.

#### `haproxy-register.sh`

Gains a `--remote` flag. When tunneling, the HAProxy REST API endpoint is on the remote host, not a Docker-networked peer. The URL comes from `HAPROXY_REMOTE_API_URL` (written to `/tmp/.ssl-tunnel-env` by tunnel-manager). The payload gains two new optional fields: `tunnel_http_port` and `tunnel_https_port`, which the remote daemon uses to configure HAProxy backends pointing at the tunnel endpoints rather than container hostnames.

#### `ssl-renew.sh`

Gains awareness of `REMOTE_HAPROXY_ID`. On renewal, after certbot succeeds, it sends a DM to the remote daemon via `nostr-dm-client` with message type `CERT_RENEWED`, so the daemon can reload HAProxy if it performs TLS termination (relevant only if a future mode adds remote TLS termination; in the current passthrough design, this is informational only). The restart marker `/tmp/.ssl-renewal-restart` continues to work as-is.

#### `run-lib.sh`

Gains `--remote-haproxy-id`, `--tunnel-type`, `--tunnel-relay`, `--remote-haproxy-api-url` argument parsing, corresponding `_ssl_env_args` output, and removes the HAProxy network connect step when `REMOTE_HAPROXY_ID` is set (no shared Docker network needed).

---

## 3. Tunnel Lifecycle

### Establishment

The preferred tunnel protocol is **SSH remote port forwarding** using `autossh` for process supervision. The client generates a 4096-bit RSA keypair on first run, persisting it at `/etc/letsencrypt/tunnel-identity/id_rsa{,.pub}` so it survives container restarts. The remote daemon installs the public key in its `~/.ssh/authorized_keys` with a `command=""` restriction that permits only specific remote forwards to the allocated loopback ports.

The SSH command issued by tunnel-manager:
```
autossh -M 0 \
  -N \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes \
  -i /etc/letsencrypt/tunnel-identity/id_rsa \
  -R 127.0.0.1:${TUNNEL_HTTP_PORT}:localhost:80 \
  -R 127.0.0.1:${TUNNEL_HTTPS_PORT}:localhost:${SSL_HTTPS_PORT} \
  -p ${SSH_PORT} \
  ${TUNNEL_USER}@${TUNNEL_HOST}
```

Extra TCP ports from `EXTRA_PORTS` are mapped with additional `-R` flags, with ports allocated by the daemon and communicated in the `TUNNEL_ACCEPTED` message.

**WireGuard** is the alternative protocol for environments where SSH is filtered. The daemon generates a WireGuard server peer config and returns the client's `[Interface]` and `[Peer]` blocks in the `TUNNEL_ACCEPTED` message. tunnel-manager writes a `wg0.conf` and calls `wg-quick up`. WireGuard requires the container to run with `NET_ADMIN` capability (`--privileged` is not required if the capability is explicitly granted).

### Monitoring

tunnel-manager runs a background loop that probes the tunnel every 30 seconds by attempting a TCP connection to the remote daemon's management socket (a separate internal port returned in `TUNNEL_ACCEPTED` as `health_check_port`). If three consecutive probes fail, the tunnel is considered broken and RECONNECTING is entered. The tunnel process's PID is also watched; if autossh exits, the transition is immediate.

### Reconnection

On reconnection, tunnel-manager first attempts to re-establish an SSH session to the same endpoint (the daemon keeps the port allocation alive for 15 minutes after the last heartbeat, to accommodate brief network interruptions). If the same endpoint is reachable within 90 seconds, no re-negotiation DM is sent. If not, a new `TUNNEL_REQUEST` is sent with the original `request_id` included in a `reconnect_for` field, allowing the daemon to prioritize and potentially reuse the same port allocation.

### Teardown

When the container receives SIGTERM, the entrypoint's trap triggers `haproxy-register unregister` (existing behavior). For the tunnel mode, this also invokes `tunnel-manager teardown`, which sends `TUNNEL_TEARDOWN` and waits up to 10 seconds for a `TUNNEL_TEARDOWN_ACK` before proceeding to kill the autossh process. The 10-second wait is bounded to not delay graceful shutdown beyond Docker's stop timeout.

### State Machine

```
tunnel-manager states:

IDLE
  │ REMOTE_HAPROXY_ID set at startup
  ▼
BOOTSTRAPPING
  │ Load or generate secp256k1 identity + SSH keypair
  │ Connect to Nostr relays
  ▼
NEGOTIATING
  │ Send TUNNEL_REQUEST
  │ Wait up to 60s for TUNNEL_ACCEPTED or TUNNEL_REJECTED
  │ On REJECTED with retry_after: sleep, retry (max 3 attempts)
  │ On timeout: retry with backoff (30s, 60s, 120s)
  ▼
ESTABLISHING
  │ Launch autossh (SSH) or wg-quick (WireGuard)
  │ Verify tunnel ports are reachable locally
  │ Write /tmp/.ssl-tunnel-env
  │ Signal ssl-setup (SIGUSR1 = ready)
  ▼
ACTIVE
  │ Send HEARTBEAT every 5 minutes
  │ Monitor tunnel process (SIGCHLD, port probing)
  ▼
RECONNECTING (on tunnel process death or port probe failure)
  │ Kill old tunnel process
  │ Attempt to re-establish tunnel to same endpoint
  │ If endpoint unreachable after 3 attempts: re-negotiate via DM
  │ If re-negotiation fails: signal ssl-setup (SIGUSR2 = fatal)
  ▼
TEARING_DOWN (on SIGTERM from container shutdown)
  │ Send TUNNEL_TEARDOWN DM
  │ Kill tunnel process
  │ Remove /tmp/.ssl-tunnel-env
  └► IDLE
```

---

## 4. Dynamic DNS Integration

The DNS record problem is the critical path item: the container's domain must point to the remote HAProxy's public IP before certbot can perform HTTP-01 challenge validation.

### Ownership Model

The remote HAProxy daemon owns and manages the DNS record for the client's domain. This is an intentional centralization: the daemon knows its own public IP definitively, can update DNS before responding to `TUNNEL_REQUEST`, and the client does not need DNS provider credentials.

The daemon communicates its DNS action in `TUNNEL_ACCEPTED.dns_action`:

- **`managed`** — the daemon has updated (or will update within 30 seconds) the DNS A record for the domain to point to its own public IP. The client should wait for DNS propagation before proceeding. tunnel-manager polls `dig +short ${SSL_DOMAIN}` until it matches `dns_target`.
- **`pre-configured`** — the domain already points to the remote HAProxy (manually configured by the operator). No DNS action needed.
- **`client-managed`** — the daemon cannot manage DNS; the client must update DNS externally. In this case, `TUNNEL_ACCEPTED` still includes `dns_target` so the operator knows what IP to use. ssl-setup will proceed but may fail at nonce verification if DNS is not yet updated.

### DNS Provider Integration (daemon side)

The daemon supports a pluggable DNS backend:

- **Cloudflare API** — via `CF_API_TOKEN` and `CF_ZONE_ID` on the daemon host
- **Route53** — via IAM role or explicit credentials
- **RFC 2136 Dynamic DNS** — nsupdate with TSIG key, for self-hosted authoritative DNS
- **Webhook** — arbitrary HTTP POST to a URL configured on the daemon, for custom DNS providers

DNS TTL is set to 60 seconds on records managed by the daemon. On teardown, the daemon removes the A record or restores a configurable default (e.g., a maintenance page IP).

### Alternative: Client-Provided DNS Credentials

For cases where the daemon operator does not want to manage DNS for client domains, the DTNP protocol (see `protocol-spec.md`) supports passing encrypted DNS credentials from the client to the server in the `TUNNEL_REQUEST.dns_request.credentials_enc` field. The credentials are NIP-04 encrypted to the server's npub, giving the server temporary access to update DNS on the client's behalf. This approach is more complex but supports arbitrary DNS providers without requiring the daemon operator to configure zone access.

### Propagation Wait

tunnel-manager polls DNS resolution up to 120 seconds after receiving `TUNNEL_ACCEPTED` with `dns_action: managed`. It uses `dig @8.8.8.8 +short ${SSL_DOMAIN}` to bypass local resolver cache. Once the IP matches `dns_target`, it signals ssl-setup to proceed. If DNS has not propagated within 120 seconds, tunnel-manager logs a warning and proceeds anyway — ssl-setup will fail at nonce verification (exit code 10) if the record is wrong, and the existing retry logic provides a recovery window.

---

## 5. SSL Certificate Flow Through Tunnel

The certificate acquisition flow is structurally identical to the local mode because the tunnel makes the container's port 80 accessible on the public internet via the remote HAProxy. From certbot's perspective, nothing has changed.

**Detailed sequence:**

1. tunnel-manager establishes SSH tunnel: remote `127.0.0.1:21080` → container `localhost:80`.
2. Remote daemon configures HAProxy: `frontend http-in` routes `Host: mydomain.com` → `backend tunnel-mydomain-http` → `server s1 127.0.0.1:21080`.
3. dns_action completes: `mydomain.com` A record → remote HAProxy public IP.
4. ssl-setup proceeds normally: starts ssl-http-proxy on port 80, runs nonce verification (HTTP GET through HAProxy → tunnel → ssl-http-proxy).
5. certbot runs webroot mode: places challenge file in `/var/www/acme-challenge/`. Let's Encrypt validates via `http://mydomain.com/.well-known/acme-challenge/...` → remote HAProxy → tunnel → container ssl-http-proxy → webroot file. No changes to certbot invocation.
6. Certificate obtained. ssl-setup re-registers with HAProxy REST API (now at remote URL) with `https_port` set.
7. Remote daemon updates HAProxy: `frontend https-in` routes SNI `mydomain.com` → `backend tunnel-mydomain-https` → `server s1 127.0.0.1:21443`.
8. App TLS traffic flows: client → HAProxy port 443 → tunnel → container `SSL_HTTPS_PORT`. TLS is terminated by the app, not HAProxy (passthrough mode unchanged).

**Renewal** works identically. ssl-renew calls `certbot renew --webroot` every ~12 hours. The tunnel is long-lived and remains established for the container's lifetime. No special renewal path exists for remote mode — the tunnel simply keeps port 80 connected.

---

## 6. Security Model

### Identity and Authentication

Each party — client container and remote daemon — has a secp256k1 keypair (Nostr identity). DMs are NIP-17 gift-wrapped: encrypted to the recipient's pubkey, padded, and wrapped in an ephemeral event. An attacker who intercepts relay traffic cannot read message content.

The client authenticates to the daemon by signing the `TUNNEL_REQUEST` event with its private key. The daemon evaluates the client's npub against an ACL configured on the daemon host. The ACL can be an allowlist of npubs, or a delegated trust model where any client presenting a valid NIP-26 delegation from a trusted root key is accepted.

### Tunnel Security

SSH tunnels use public-key authentication only. The generated client SSH key is restricted on the server side via `authorized_keys` `command=""` and `permitopen` directives, limiting the key to forwarding only the specific ports allocated for that session. The daemon's `sshd` configuration must set `AllowTcpForwarding remote` and disable everything else for tunnel users.

Per-session HAProxy API keys are 32-byte random hex tokens, generated by the daemon and valid only for the lifetime of the session. They are transmitted only in the encrypted DM channel, never in plaintext.

### Threat Model Considerations

**Relay compromise:** If a Nostr relay is compromised, an attacker can observe encrypted event metadata (sender npub, recipient npub, timestamp) but cannot read message content (NIP-17 encryption). An attacker cannot forge messages because they do not have the client's or daemon's private key.

**Port squatting on remote host:** The daemon must validate that tunnel remote-forward requests target only the pre-allocated loopback ports. The `authorized_keys` `permitopen` restriction enforces this at the SSH protocol level.

**Domain hijacking:** A malicious client could request a tunnel for a domain it does not own, causing the daemon to update DNS. The daemon mitigates this by requiring domain-control verification: generating a challenge value that the client must serve at a known path, or using a TXT record challenge.

**DM replay:** Each `TUNNEL_REQUEST` includes a `timestamp` and `request_id`. The daemon rejects requests with timestamps older than 5 minutes or previously-seen `request_id` values (maintained in a small in-memory ring buffer).

---

## 7. Configuration

### New Environment Variables (in-container)

| Variable | Default | Description |
|----------|---------|-------------|
| `REMOTE_HAPROXY_ID` | _(empty)_ | Remote daemon's Nostr npub. Enables remote tunnel mode when set. |
| `TUNNEL_TYPE` | `ssh-remote-forward` | Preferred tunnel protocol. `ssh-remote-forward` or `wireguard`. |
| `TUNNEL_RELAY_URLS` | `wss://relay.primal.net,wss://relay.damus.io` | Comma-separated Nostr relay WebSocket URLs. |
| `TUNNEL_IDENTITY_DIR` | `/etc/letsencrypt/tunnel-identity` | Directory for persisted Nostr and SSH keypairs. Stored in letsencrypt volume. |
| `TUNNEL_NEGOTIATE_TIMEOUT` | `60` | Seconds to wait for `TUNNEL_ACCEPTED` before timeout and retry. |
| `TUNNEL_HEARTBEAT_INTERVAL` | `300` | Seconds between `TUNNEL_HEARTBEAT` messages. |
| `TUNNEL_RECONNECT_MAX` | `10` | Maximum reconnection attempts before fatal exit. |
| `DNS_PROPAGATION_TIMEOUT` | `120` | Seconds to wait for DNS to propagate after `dns_action: managed`. |
| `TUNNEL_SSH_PORT` | `22` | SSH port on remote tunnel endpoint (may differ from standard). |
| `REMOTE_HAPROXY_API_URL` | _(from DM)_ | Overrides the HAProxy API URL received in `TUNNEL_ACCEPTED`. Useful for testing. |

### New CLI Flags (`run-lib.sh`)

| Flag | Env Var Set | Description |
|------|-------------|-------------|
| `--remote-haproxy-id <npub>` | `REMOTE_HAPROXY_ID` | Enable remote tunnel mode targeting this daemon. |
| `--tunnel-type <type>` | `TUNNEL_TYPE` | Tunnel protocol preference. |
| `--tunnel-relay <url>` | `TUNNEL_RELAY_URLS` | Override Nostr relay URLs (comma-separated). |
| `--tunnel-ssh-port <port>` | `TUNNEL_SSH_PORT` | SSH port for tunnel endpoint. |
| `--dns-propagation-timeout <secs>` | `DNS_PROPAGATION_TIMEOUT` | DNS wait timeout override. |

When `--remote-haproxy-id` is set, `run-lib.sh` automatically suppresses `--haproxy-host` Docker network wiring (no haproxy-net connect) and removes `-p 80:80` port publishing (not needed; traffic arrives through the tunnel).

### New Dockerfile Dependencies

`autossh` is added to the base image's `apt-get install` list. WireGuard (`wireguard-tools`) is available as an optional install, documented as requiring the host kernel's WireGuard module and `NET_ADMIN` capability. The `cryptography` Python package (already a certbot dependency) provides secp256k1 primitives for nostr-dm-client.

---

## 8. Error Handling and Failure Modes

### New Exit Codes for ssl-setup

| Code | Meaning |
|------|---------|
| `15` | Tunnel negotiation failed (daemon rejected or timeout after all retries) |
| `16` | Tunnel establishment failed (SSH/WireGuard process failed to start) |
| `17` | DNS propagation timeout (tunnel live but domain not resolving to remote HAProxy) |

### Failure Scenarios

**Nostr relay unavailable at startup:** tunnel-manager retries connecting to relays with exponential backoff (2s, 4s, 8s, cap 60s). It tries all configured relays in round-robin. After 5 minutes total, exits with code 15.

**Daemon offline or not responding:** `TUNNEL_REQUEST` times out after `TUNNEL_NEGOTIATE_TIMEOUT`. Retried up to 3 times with 30-second gaps. If all fail, ssl-setup exits 15. The operator should verify the daemon is running and the npub is correct.

**SSH key rejected by daemon:** The daemon sends `TUNNEL_REJECTED` with `reason: acl_denied`. tunnel-manager logs the rejection, does not retry (retrying would not help), and exits 15. The operator must add the client's npub to the daemon's ACL.

**Tunnel process crashes during operation:** tunnel-manager enters RECONNECTING. It attempts re-establishment up to `TUNNEL_RECONNECT_MAX` times, with 10-second gaps. On exhaustion, it sends a `TUNNEL_TEARDOWN` DM and signals ssl-setup via SIGUSR2. The container restarts (Docker `--restart on-failure:5`), and the full negotiation sequence begins again from IDLE.

**HAProxy REST API unreachable (remote):** Identical to local mode: exponential backoff up to 5 minutes, exit 13. The remote API URL is provided by the daemon in `TUNNEL_ACCEPTED`, so an unreachable API indicates the daemon gave an incorrect URL or the HAProxy process is down on the remote host.

**DNS propagation timeout:** ssl-setup proceeds after logging a warning. If nonce verification then fails (exit 10), the operator must investigate DNS. The tunnel remains established; manual DNS correction will unblock the nonce verification on the next container restart.

**Graceful shutdown race:** If SIGTERM arrives during tunnel negotiation (before ACTIVE state), tunnel-manager abandons the DM exchange and exits immediately. Since no `TUNNEL_ACCEPTED` was received, no ports were allocated on the remote side and no teardown DM is needed.

---

## 9. Integration with Existing ssl-setup.sh Flow

The integration follows an **adapter pattern** at a single branch point in ssl-setup.sh, preserving all existing behavior when `REMOTE_HAPROXY_ID` is unset.

### Modified ssl-setup.sh Flow

```
Step 0: SSL_DOMAIN check (unchanged)
    │
    ▼
Step 0b: NEW — Remote tunnel mode detection
    if [ -n "${REMOTE_HAPROXY_ID:-}" ]; then
        tunnel-manager --start --wait-ready --timeout 300
        # Blocks until ACTIVE state or exit code 15/16
        . /tmp/.ssl-tunnel-env
        # HAPROXY_HOST, HAPROXY_API_PORT, HAPROXY_API_KEY overridden
        # from values in .ssl-tunnel-env
        HAPROXY_DETECTED="${HAPROXY_REMOTE_HOST}"
        HAPROXY_IP="${HAPROXY_REMOTE_IP}"
        # DNS propagation already handled by tunnel-manager
    fi
    │
    ▼
Step 1: Start ssl-http-proxy on port 80 (unchanged)
    │
    ▼
Step 2: HAProxy registration (unchanged logic, remote URL used transparently)
    │   In remote mode: payload gains tunnel_http_port + tunnel_https_port fields
    │   These are ignored by local HAProxy API; remote daemon expects them
    ▼
Step 3: Nonce verification (unchanged — traffic flows through tunnel)
    │
    ▼
Step 4: Certificate acquisition (unchanged — certbot uses webroot on port 80)
    │
    ▼
Step 5: TLS verification (unchanged)
    │
    ▼
Step 6: Re-register with HTTPS port (unchanged)
    │
    ▼
Step 7: Start ssl-renew (unchanged)
    │
    ▼
Step 8: Export /tmp/.ssl-env (unchanged)
```

The key design principle is **zero modification to the core ssl-setup phases**. The tunnel makes the container's ports publicly reachable before ssl-setup begins its HAProxy and certbot work. From ssl-setup's perspective, the only difference is where the HAProxy API lives (remote URL vs. Docker network neighbor) and that those coordinates come from `/tmp/.ssl-tunnel-env` rather than `HAPROXY_HOST`.

### Backwards Compatibility

If `REMOTE_HAPROXY_ID` is not set, the new code path is not executed. All existing environment variables, exit codes, log messages, file paths, and behavioral contracts remain identical. The only new dependency in the base image is `autossh`, which adds roughly 60KB and has no runtime overhead when unused.

### Entrypoint Pattern (unchanged)

The entrypoint script in derived images requires no modification. The `ssl-setup` exit code contract is preserved. The `/tmp/.ssl-env` file is written at the same point in the sequence. Apps that call `haproxy-register unregister` on shutdown also require no changes — the script will use the remote API URL sourced from the environment, which is populated from `/tmp/.ssl-tunnel-env` before the entrypoint calls ssl-setup.

---

## 10. Key Architectural Decisions

**Why SSH remote forwarding over a VPN mesh (Tailscale, Nebula)?** SSH is universally available in Debian base images with zero additional kernel requirements. VPN solutions require either a userspace implementation (performance cost) or kernel modules (privilege escalation, host dependency). SSH remote forwarding is a well-understood, minimal-privilege mechanism with decades of operational track record. autossh provides robust process management with zero configuration complexity.

**Why Nostr/NIP-17 for the control channel rather than a direct REST API?** The client is behind a firewall with no inbound access. The daemon cannot reach the client to initiate a tunnel. Nostr provides a decentralized, encrypted, store-and-forward messaging substrate that both parties can connect to outbound. The alternative — a centralized MQTT broker or long-poll HTTP endpoint — would require the daemon operator to run additional infrastructure and would be a single point of failure. Nostr relay redundancy (multiple relay URLs) provides resilience without additional daemon-side infrastructure.

**Why is the DNS record owned by the daemon?** The client does not know the remote HAProxy's public IP until after negotiation. Giving the client DNS credentials would require transmitting sensitive API keys in the DM channel, expanding the trust surface. The daemon, which controls the network egress IP, is the natural owner of the DNS record pointing to that IP.

**Why persist the SSH keypair in the letsencrypt volume?** The letsencrypt volume is already the persistent store for certificate material. Co-locating tunnel identity material avoids introducing a new volume mount. The alternative — regenerating the SSH key on every container restart — would require the daemon to update its `authorized_keys` on every restart, adding a round-trip DM exchange before every tunnel establishment.

---

## Appendix: File Locations (New)

| Path | Purpose |
|------|---------|
| `/usr/local/bin/tunnel-manager` | Tunnel lifecycle orchestrator |
| `/usr/local/bin/nostr-dm-client` | NIP-17 DM send/receive CLI |
| `/etc/letsencrypt/tunnel-identity/` | Persistent SSH and Nostr keypairs |
| `/etc/letsencrypt/tunnel-identity/id_rsa` | SSH private key for tunnel auth |
| `/etc/letsencrypt/tunnel-identity/id_rsa.pub` | SSH public key (sent to daemon) |
| `/etc/letsencrypt/tunnel-identity/nostr.json` | Nostr keypair (nsec, npub) |
| `/tmp/.ssl-tunnel-env` | Sourceable tunnel connection params |
| `/tmp/.ssl-tunnel.pid` | PID of active tunnel process |
| `/tmp/.ssl-tunnel-state` | Current tunnel-manager state (for debugging) |
