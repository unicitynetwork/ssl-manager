# Remote HAProxy Tunneling — Architecture Design

## 1. High-Level Architecture

The remote client container establishes a **full bidirectional VPN tunnel** (WireGuard) to the HAProxy host. The container operates as if it were on the HAProxy host's network — all outbound traffic (DynDNS API calls, certbot ACME validation, etc.) routes through the tunnel, and all inbound traffic (user requests, ACME challenges) arrives through it. The container sees the HAProxy host's public IP as its own egress.

```
FIREWALL-CONSTRAINED CLIENT HOST                    PUBLIC REMOTE HOST (HAProxy Container)
┌────────────────────────────────────────────┐     ┌──────────────────────────────────────────────────┐
│  Docker Container (ssl-manager derived)    │     │  HAProxy Docker Container                        │
│                                            │     │                                                  │
│  ┌────────────────────────────────────┐   │     │  ┌──────────────────────────────────────────┐   │
│  │  ssl-setup (orchestration)         │   │     │  │  haproxy-tunnel-daemon (inside container) │   │
│  │  - Detects REMOTE_HAPROXY_ID       │   │     │  │  - Node.js / Sphere SDK                  │   │
│  │  - Delegates to tunnel-manager     │   │     │  │  - Listens for DMs via Sphere SDK         │   │
│  └──────────┬─────────────────────────┘   │     │  │  - Handles DTNP negotiation               │   │
│             │                             │     │  │  - Manages WireGuard peer configs          │   │
│  ┌──────────▼─────────────────────────┐   │     │  │  - Updates HAProxy config (runtime API)   │   │
│  │  tunnel-manager (new component)    │   │     │  │  - Proxies DynDNS traffic (transparent)   │   │
│  │  - DM negotiation via Sphere SDK   │   │     │  └──────────────────┬───────────────────────┘   │
│  │  - Establishes WireGuard tunnel    │◄──┼─────┼───────────────────┘  (Nostr/NIP-17 via         │
│  │  - Monitors + reconnects           │   │     │                       Sphere SDK)               │
│  │  - Signals ssl-setup on ready      │   │     │                                                  │
│  └──────────┬─────────────────────────┘   │     │  ┌──────────────────────────────────────────┐   │
│             │                             │     │  │  WireGuard (wg0 interface)                │   │
│  ┌──────────▼─────────────────────────┐   │     │  │  - Server: 10.200.0.1/24                 │   │
│  │  WireGuard VPN (wg0 interface)     │   │     │  │  - Peers: 10.200.0.2, .3, .4, ...        │   │
│  │  - Client: 10.200.0.N/32           ├───┼────►│  │  - NAT masquerade for client egress       │   │
│  │  - Default route via tunnel        │   │     │  │  - Port forwarding for inbound traffic    │   │
│  │  - ALL traffic routed through wg0  │   │     │  └──────────────────────────────────────────┘   │
│  └──────────┬─────────────────────────┘   │     │                                                  │
│             │ (tunnel = full network)     │     │  ┌──────────────────────────────────────────┐   │
│  ┌──────────▼─────────────────────────┐   │     │  │  HAProxy                                  │   │
│  │  ssl-http-proxy (port 80)          │   │     │  │  - Frontend port 80 / 443                  │   │
│  │  ssl-alias-proxy (port 8444)       │   │     │  │  - Per-domain backend → WG peer IP:port   │   │
│  │  App (port SSL_HTTPS_PORT)         │   │     │  │  - Aliases: each gets own backend entry    │   │
│  │                                    │   │     │  └──────────────────────────────────────────┘   │
│  │  DynDNS client (direct outbound)   │   │     │                                                  │
│  │  → routes via wg0 → HAProxy host   │   │     │  Public IP: 198.51.100.42                       │
│  │  → HAProxy host NATs to internet   │   │     │  WireGuard listen: UDP 51820                     │
│  │                                    │   │     │                                                  │
│  │  certbot (direct outbound)         │   │     └──────────────────────────────────────────────────┘
│  │  → routes via wg0 → HAProxy host   │   │
│  │  → appears to originate from       │   │               Internet
│  │    HAProxy's public IP             │   │                  │
│  └────────────────────────────────────┘   │    ┌──────────────────────────┐
│                                            │    │  DNS: mydomain.com       │
│  Sphere SDK identity: client.npub          │    │  DNS: alias1.mydomain.com│
│  /tmp/.ssl-tunnel-env                      │    │  DNS: alias2.mydomain.com│
└────────────────────────────────────────────┘    │  → 198.51.100.42         │
                                                   └──────────────────────────┘
```

### Traffic Flows

**Inbound (internet → container):**
```
Internet user
    │ HTTPS mydomain.com (or any alias)
    ▼
HAProxy (public IP, port 443)
    │ SNI match → backend 10.200.0.N:${SSL_HTTPS_PORT}
    ▼
WireGuard tunnel (wg0)
    │ routed to client peer 10.200.0.N
    ▼
Container port SSL_HTTPS_PORT (app TLS, unchanged)
```

**Outbound (container → internet, e.g., DynDNS API call):**
```
Container process (certbot, curl to DynDNS, etc.)
    │ connects to external IP (e.g., api.cloudflare.com)
    ▼
wg0 interface (default route)
    │ all traffic exits via WireGuard tunnel
    ▼
HAProxy host WireGuard server (10.200.0.1)
    │ NAT masquerade (iptables MASQUERADE)
    ▼
Internet (appears to originate from HAProxy's public IP)
```

**Key insight:** Because all container traffic routes through the tunnel, the container behaves as if it is on the HAProxy host's network. DynDNS updates, certbot ACME challenges, health checks — everything works identically to the local HAProxy case. The container manages its own DNS credentials and calls its DynDNS provider directly; HAProxy merely provides transparent network connectivity.

### Multiple Domain Aliases

Each client can register a primary domain plus multiple aliases (`SSL_DOMAIN_ALIASES`). Because the tunnel is a full VPN (not per-port), all ports for all domains are accessible through a single WireGuard peer connection:

```
HAProxy backends for client 10.200.0.2:
  ├─ mydomain.com          → 10.200.0.2:80  (HTTP)  / 10.200.0.2:443 (HTTPS SNI)
  ├─ alias1.mydomain.com   → 10.200.0.2:8444 (alias proxy)
  ├─ alias2.mydomain.com   → 10.200.0.2:8444 (alias proxy)
  └─ extra TCP ports        → 10.200.0.2:50002, etc.
```

No per-alias port allocation needed on the HAProxy side — the WireGuard peer IP directly addresses the container, and HAProxy routes by domain to the appropriate container port.

---

## 2. Component Inventory

### New Components

#### `tunnel-manager` (in-container, `/usr/local/bin/tunnel-manager`)

Orchestrates the remote tunneling lifecycle. Uses **Sphere SDK** for DM-based negotiation with the remote HAProxy daemon — sends DTNP messages, receives responses, manages the conversation state machine. Establishes and monitors the WireGuard tunnel, handles reconnection, and signals ssl-setup on readiness via `/tmp/.ssl-tunnel-env`.

**Runtime:** Node.js (Sphere SDK requires it). Sphere SDK is added to the base image when `REMOTE_HAPROXY_ID` is configured, or pre-installed in the base image as an optional dependency.

**Why Sphere SDK, not a custom Nostr client:** Sphere SDK already implements NIP-17 gift-wrapped DMs, key management, relay connection pooling, and message delivery — all battle-tested. Reimplementing this in Python would duplicate effort, introduce bugs, and diverge from the Unicity ecosystem's standard communication layer.

#### `haproxy-tunnel-daemon` (inside HAProxy container)

Runs **inside the HAProxy Docker container** as a background process alongside HAProxy itself. Written in Node.js using Sphere SDK for DM communication. Responsibilities:

- Listens for DTNP `TUNNEL_REQUEST` DMs addressed to its npub
- Validates client npub against ACL
- Allocates WireGuard peer IP from its subnet pool (10.200.0.0/24)
- Generates WireGuard peer config and sends `TUNNEL_OFFER` via DM
- Adds WireGuard peer to the server's `wg0` interface
- Configures HAProxy backends via runtime API (pointing to client's WireGuard IP)
- Configures iptables NAT/masquerade for client egress traffic
- Handles heartbeat, reconnection, and teardown
- On teardown: removes WireGuard peer, HAProxy backends, iptables rules

**Why inside the HAProxy container:** The daemon needs direct access to HAProxy's runtime API (Unix socket), the WireGuard interface (`wg` CLI), and iptables. Running it alongside HAProxy avoids cross-container coordination, shared volume mounts, and network namespace complexity.

#### `/tmp/.ssl-tunnel-env`

Sourceable file written by `tunnel-manager` when the tunnel is established:
```bash
TUNNEL_ACTIVE=true
TUNNEL_TYPE=wireguard
TUNNEL_CLIENT_IP=10.200.0.2
TUNNEL_SERVER_IP=10.200.0.1
HAPROXY_HOST=10.200.0.1
HAPROXY_API_PORT=8404
HAPROXY_API_KEY=<per-session-token>
HAPROXY_REMOTE_PUBLIC_IP=198.51.100.42
```

After sourcing this file, ssl-setup's HAProxy registration calls target `10.200.0.1:8404` (the HAProxy's WireGuard IP), which is reachable through the tunnel.

### Modified Components

#### `ssl-setup.sh`

Gains a new early branch: if `REMOTE_HAPROXY_ID` is set, delegate to `tunnel-manager --start --wait-ready` before proceeding. After tunnel-manager signals readiness, ssl-setup sources `/tmp/.ssl-tunnel-env` which overrides `HAPROXY_HOST` to point at the WireGuard server IP. All subsequent steps (HAProxy registration, nonce verification, certbot, TLS verification) work unchanged — the tunnel provides transparent bidirectional connectivity.

#### `haproxy-register.sh`

Gains awareness of alias domains in the tunnel context. When registering via the tunnel, it includes all `SSL_DOMAIN_ALIASES` in the registration payload so HAProxy creates backends for each alias pointing to the client's WireGuard IP. The registration payload includes `tunnel_peer_ip` so HAProxy knows to route to the WireGuard address rather than a Docker network hostname.

#### `ssl-renew.sh`

No changes needed. certbot renewal works transparently through the tunnel — outbound ACME requests route via WireGuard, inbound challenge validation arrives through the tunnel. The restart marker `/tmp/.ssl-renewal-restart` continues to work as-is.

#### `run-lib.sh`

Gains `--remote-haproxy-id <npub>` and `--tunnel-relay <url>` argument parsing. When `REMOTE_HAPROXY_ID` is set:
- Suppresses `--haproxy-host` Docker network wiring (no haproxy-net)
- Removes `-p 80:80` port publishing (traffic arrives through tunnel)
- Adds `--cap-add=NET_ADMIN` to Docker create (required for WireGuard)
- Adds `--sysctl net.ipv4.conf.all.src_valid_mark=1` for WireGuard routing

---

## 3. Why WireGuard as Primary (Not SSH)

The critical requirement is **bidirectional full-network transparency**: the container must behave as if it's on the HAProxy host's network. This rules out SSH reverse port forwarding, which only forwards specific ports:

| Requirement | SSH -R (port forward) | WireGuard (VPN) |
|------------|----------------------|-----------------|
| Inbound traffic to container ports | Yes (explicit -R per port) | Yes (all ports, automatic) |
| Outbound from container to internet | No (separate SOCKS proxy needed) | Yes (default route via wg0) |
| Container sees HAProxy's public IP | No | Yes (NAT masquerade) |
| DynDNS API calls from container | Requires separate proxy | Works transparently |
| certbot outbound to ACME servers | Works (direct internet) | Works (via tunnel) |
| Adding new ports at runtime | Requires tunnel restart | Automatic (VPN covers all) |
| Multiple aliases (no per-alias ports) | Needs port per alias | Single peer IP, HAProxy routes by domain |
| Docker image size | ~60KB (autossh) | ~5MB (wireguard-tools) |
| Kernel requirement | None | Linux 5.6+ (or userspace) |
| Container capability | None | `NET_ADMIN` |

**WireGuard is the clear choice** because the bidirectional requirement makes SSH port forwarding inadequate without bolting on additional proxying infrastructure (SOCKS, DNS forwarding, etc.), which would be more complex than WireGuard.

**Fallback: SSH with tun device** — If WireGuard is unavailable (older kernels), SSH can create a full network tunnel via `-w` (tun device forwarding), though this is less performant and more complex to configure.

---

## 4. Transport Layer: Handling Restrictive Networks

### The Problem

WireGuard uses **UDP** (default port 51820). Many restrictive network environments block non-standard UDP:
- Corporate firewalls often allow only TCP 80/443 (HTTP/HTTPS)
- Hotel/airport WiFi frequently blocks all non-HTTP traffic
- Some ISPs throttle or block unrecognized UDP protocols
- HTTP proxies (common in enterprises) only support TCP CONNECT

### Solution: Layered Transport with wstunnel

We use a **layered architecture** — WireGuard remains the VPN layer, but its UDP traffic is optionally wrapped in a WebSocket (WSS) transport using **wstunnel** when direct UDP is blocked:

```
OPEN NETWORK (direct UDP):
  Container wg0 ──UDP──► Server:51820 (WireGuard)

RESTRICTIVE NETWORK (WebSocket wrapper):
  Container wg0 ──UDP──► localhost:51820 (wstunnel client)
                              │
                         WSS over TCP 443
                         (looks like HTTPS)
                              │
                              ▼
                         Server wstunnel ──UDP──► localhost:51820 (WireGuard)
```

**Why layered beats a standalone WebSocket VPN:**
- WireGuard config, key management, and operations are identical regardless of transport
- No code changes to tunnel-manager — only the WireGuard endpoint changes (direct vs. localhost)
- wstunnel adds only ~2-3% overhead and ~15-20ms latency
- Traffic looks like normal HTTPS to firewalls and DPI
- Works through HTTP CONNECT proxies
- Can be enabled/disabled without touching the VPN layer

### Transport Negotiation

The `TUNNEL_OFFER` message includes available transports:

```json
{
  "transports": [
    { "type": "udp",       "endpoint": "198.51.100.42:51820" },
    { "type": "wss",       "endpoint": "wss://198.51.100.42:443/tunnel" },
    { "type": "wss-proxy", "endpoint": "wss://198.51.100.42:443/tunnel",
                           "proxy_compatible": true }
  ]
}
```

tunnel-manager tries transports in order:
1. **Direct UDP** — fastest, try first (5-second handshake timeout)
2. **WSS** — if UDP fails, start wstunnel client, connect via WebSocket on port 443
3. **WSS via HTTP proxy** — if WSS direct fails, try through `HTTP_PROXY`/`HTTPS_PROXY` environment variables

The client can force a specific transport via `TUNNEL_TRANSPORT=wss` environment variable (useful when the client knows its network blocks UDP).

### wstunnel Integration

**Client side** (inside ssl-manager container):
```bash
# wstunnel wraps WireGuard UDP in WebSocket
wstunnel client \
  --udp-to-wss "127.0.0.1:51820:127.0.0.1:51820" \
  wss://198.51.100.42:443/tunnel
```

WireGuard config changes only the endpoint:
```ini
[Peer]
# Direct UDP:   Endpoint = 198.51.100.42:51820
# Via wstunnel: Endpoint = 127.0.0.1:51820   ← local wstunnel client
```

**Server side** (inside HAProxy container):
```bash
# wstunnel unwraps WebSocket back to UDP for WireGuard
wstunnel server \
  --restrict-to "127.0.0.1:51820" \
  wss://0.0.0.0:443/tunnel
```

The `--restrict-to` flag ensures the WebSocket tunnel can only forward to the WireGuard port — no arbitrary port access.

### DPI Evasion Properties

| Property | Direct UDP | WSS via wstunnel |
|----------|-----------|------------------|
| Protocol visible to firewall | WireGuard/UDP | HTTPS/WebSocket |
| Port | 51820 (non-standard) | 443 (standard HTTPS) |
| TLS encryption | WireGuard only | TLS 1.3 outer + WireGuard inner |
| Survives DPI | No (WireGuard fingerprinted) | Yes (looks like HTTPS) |
| Works through HTTP proxy | No | Yes (CONNECT tunnel) |
| Latency overhead | 0 | +15-20ms |
| Throughput | Native | ~97% of native |

### For Extreme DPI Environments

If even WebSocket traffic is fingerprinted (rare, but possible in state-level censorship), **sing-box** can be used as an alternative transport with VLESS/Trojan protocols that are designed to be indistinguishable from normal HTTPS browsing traffic. This is a future extension — wstunnel covers 99% of restrictive networks.

### New Dependencies

- `wstunnel` — Rust binary, ~5-8MB, statically compiled. Installed in base image alongside wireguard-tools.
- Total additional image size for tunnel support: ~10-13MB (wireguard-tools + wstunnel).

---

## 5. Tunnel Lifecycle

### Establishment

1. tunnel-manager loads or generates a Sphere SDK identity (secp256k1 keypair) and a WireGuard keypair. Both are persisted at `/etc/letsencrypt/tunnel-identity/` so they survive container restarts.
2. tunnel-manager sends `TUNNEL_REQUEST` DM via Sphere SDK to `REMOTE_HAPROXY_ID`, including:
   - Primary domain + all aliases
   - Required ports (HTTP 80, HTTPS `SSL_HTTPS_PORT`, alias proxy 8444, extra ports)
   - Client WireGuard public key
   - Client capabilities
3. haproxy-tunnel-daemon receives the request, validates ACL, allocates a WireGuard peer IP (e.g., 10.200.0.2/32), and responds with `TUNNEL_OFFER`:
   - WireGuard endpoint (public IP:51820)
   - Server WireGuard public key
   - Allocated client IP
   - Preshared key (encrypted to client's npub)
   - HAProxy API URL (via WireGuard IP)
4. tunnel-manager writes WireGuard config and brings up `wg0`:
   ```ini
   [Interface]
   PrivateKey = <client-private-key>
   Address = 10.200.0.2/32

   [Peer]
   PublicKey = <server-public-key>
   PresharedKey = <preshared-key>
   Endpoint = 198.51.100.42:51820
   AllowedIPs = 0.0.0.0/0    # route ALL traffic through tunnel
   PersistentKeepalive = 25
   ```
5. tunnel-manager verifies connectivity: pings `10.200.0.1`, then `curl http://10.200.0.1:8404/v1/health`.
6. tunnel-manager sends `TUNNEL_ESTABLISHED` DM.
7. tunnel-manager writes `/tmp/.ssl-tunnel-env` and signals ssl-setup to proceed.

### Monitoring

tunnel-manager runs a background loop:
- Every 30 seconds: ping `10.200.0.1` via `wg0`
- Every 5 minutes: send `TUNNEL_HEARTBEAT` DM via Sphere SDK
- Monitor `wg show wg0 latest-handshake` — if stale (>3 minutes), consider tunnel degraded
- If 3 consecutive ping failures: enter RECONNECTING

### Reconnection

1. Bring down `wg0`, bring it back up (WireGuard handles roaming automatically if the endpoint hasn't changed)
2. If endpoint is reachable within 90 seconds, no re-negotiation needed — WireGuard reconnects
3. If still unreachable after 90 seconds: send new `TUNNEL_REQUEST` DM with same idempotency key
4. After `TUNNEL_RECONNECT_MAX` total failures: signal fatal error to ssl-setup

### Teardown

On container SIGTERM:
1. Send `TUNNEL_TEARDOWN` DM via Sphere SDK (cleanup_dns: false — client manages its own DNS)
2. `wg-quick down wg0`
3. Remove `/tmp/.ssl-tunnel-env`
4. HAProxy daemon receives teardown → removes WireGuard peer, removes HAProxy backends

### State Machine

```
tunnel-manager states:

IDLE
  │ REMOTE_HAPROXY_ID set at startup
  ▼
BOOTSTRAPPING
  │ Load/generate Sphere SDK identity + WireGuard keypair
  │ Connect to Nostr relays via Sphere SDK
  ▼
NEGOTIATING
  │ Send TUNNEL_REQUEST via Sphere SDK DM
  │ Wait up to 60s for TUNNEL_OFFER or TUNNEL_REJECTED
  │ On REJECTED with retry_after: sleep, retry (max 3 attempts)
  │ On timeout: retry with backoff (30s, 60s, 120s)
  ▼
ESTABLISHING
  │ Write wg0.conf from TUNNEL_OFFER
  │ wg-quick up wg0
  │ Verify connectivity (ping + HAProxy API health)
  │ Send TUNNEL_ESTABLISHED DM
  │ Write /tmp/.ssl-tunnel-env
  ▼
ACTIVE
  │ Send HEARTBEAT every 5 minutes via Sphere SDK DM
  │ Monitor WireGuard handshake + ping
  ▼
RECONNECTING (on ping failure or stale handshake)
  │ wg-quick down/up wg0
  │ If endpoint unreachable after 90s: re-negotiate via DM
  │ If re-negotiation fails: signal ssl-setup (exit 16)
  ▼
TEARING_DOWN (on SIGTERM from container shutdown)
  │ Send TUNNEL_TEARDOWN DM via Sphere SDK
  │ wg-quick down wg0
  │ Remove /tmp/.ssl-tunnel-env
  └► IDLE
```

---

## 6. Dynamic DNS Integration

### Principle: Client Owns Its DNS

**HAProxy MUST NOT manage client DNS credentials.** The client is responsible for its own DynDNS updates. The tunnel provides transparent network connectivity so the client can reach its DNS provider directly.

### How It Works

1. The client container has its DynDNS credentials (env vars, config files — same as without tunneling).
2. The WireGuard tunnel routes all outbound traffic through the HAProxy host with NAT masquerade.
3. When the client calls its DynDNS provider API (e.g., `curl https://api.cloudflare.com/...`), the request exits through the HAProxy host's public IP — transparently.
4. The client updates its DNS A record to point to the HAProxy host's public IP (provided in `TUNNEL_OFFER.haproxy_public_ip`).
5. DNS propagation happens normally.

### What HAProxy Provides

The `TUNNEL_OFFER` message includes `haproxy_public_ip` — the IP address the client should use as the DNS A record value. The client uses this value when calling its DynDNS provider. HAProxy does not proxy, intercept, or see the DNS API credentials — it just provides NAT connectivity.

### DNS Flow Sequence

```
1. Client receives TUNNEL_OFFER with haproxy_public_ip=198.51.100.42
2. Client calls DynDNS API (via WireGuard → NAT → internet):
     curl -H "Authorization: Bearer ${CF_TOKEN}" \
       https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records \
       -d '{"type":"A","name":"mydomain.com","content":"198.51.100.42"}'
3. DNS propagates: mydomain.com → 198.51.100.42
4. ssl-setup proceeds with nonce verification (unchanged)
5. certbot obtains certificate (unchanged — HTTP-01 via tunnel)
```

For multiple aliases, the client repeats the DNS update for each alias domain — all pointing to the same HAProxy public IP.

### Pre-Configured DNS

If the client's domain already points to the HAProxy's public IP (manually configured, or via a previous tunnel session), no DNS update is needed. The client can skip the DynDNS step entirely.

---

## 7. SSL Certificate Flow Through Tunnel

The certificate flow is **identical to local mode** because the WireGuard tunnel provides full bidirectional connectivity. From certbot's and ssl-setup's perspective, nothing has changed:

1. WireGuard tunnel established: container has IP 10.200.0.2, default route via wg0.
2. HAProxy configured: `mydomain.com` HTTP → 10.200.0.2:80, HTTPS SNI → 10.200.0.2:${SSL_HTTPS_PORT}.
3. For each alias: HAProxy routes alias HTTP → 10.200.0.2:80, alias HTTPS → 10.200.0.2:8444.
4. DNS points all domains to HAProxy public IP.
5. ssl-setup starts ssl-http-proxy on port 80 (unchanged).
6. Nonce verification: ssl-setup POSTs nonce to localhost:80, GETs via public domain. The GET arrives through: internet → HAProxy → WireGuard → container:80. Works transparently.
7. certbot runs webroot on port 80: Let's Encrypt validates `http://mydomain.com/.well-known/acme-challenge/...` → HAProxy → WireGuard → container ssl-http-proxy → webroot. **certbot's outbound HTTPS to ACME servers also routes via WireGuard → NAT → internet.** No special configuration needed.
8. Certificate obtained. Re-register with HAProxy including HTTPS port.
9. For aliases: certbot obtains each alias cert, ssl-alias-proxy handles TLS termination.
10. ssl-renew runs normally — renewal traffic routes through tunnel transparently.

---

## 8. Security Model

### Identity and Authentication

Both sides use **Sphere SDK identities** (secp256k1 keypairs). All DM communication is NIP-17 gift-wrapped: encrypted to the recipient's pubkey, signed by the sender's key. The haproxy-tunnel-daemon maintains an ACL of authorized client npubs.

### Tunnel Security

WireGuard provides:
- **Mutual authentication** via public key exchange (negotiated through encrypted DMs)
- **Perfect forward secrecy** via Noise protocol handshake
- **Minimal attack surface** (~4,000 lines of kernel code, formally verified)
- **Preshared key** (optional, generated per-session) for post-quantum resistance
- **No listening port on client** — client initiates; only the server listens on UDP 51820

### Network Isolation

Each client peer gets a unique `/32` IP within the 10.200.0.0/24 subnet. WireGuard's cryptokey routing ensures a client can only send traffic from its assigned IP. The HAProxy host's iptables rules:
- MASQUERADE outbound traffic from 10.200.0.0/24 (client egress)
- FORWARD traffic between HAProxy and WireGuard peers
- No inter-peer traffic (clients cannot reach each other)

### Credential Separation

- **DynDNS credentials:** Stay on the client. HAProxy never sees them. Client calls its DNS provider directly via the tunnel.
- **WireGuard keys:** Client private key never leaves the client. Server private key never leaves the server. Only public keys are exchanged via encrypted DMs.
- **HAProxy API key:** Per-session token generated by daemon, transmitted via encrypted DM, valid only for the tunnel session lifetime.
- **Sphere SDK identity:** Per-container identity persisted in letsencrypt volume. Never transmitted — only used for signing/encryption locally.

### Threat Model

**Relay compromise:** Attacker sees encrypted event metadata but cannot read content (NIP-17). Cannot forge messages without private keys.

**WireGuard port scan:** UDP 51820 is open on HAProxy host, but WireGuard silently drops packets from unknown peers (no response = no fingerprinting). Only peers with valid public keys can initiate a handshake.

**Client impersonation:** Requires both the client's Sphere SDK private key (for DM authentication) and WireGuard private key (for tunnel authentication). Compromise of either alone is insufficient.

**DM replay:** Prevented by correlation_id + sequence numbers + timestamp window (see protocol-spec.md).

---

## 9. Configuration

### New Environment Variables (in-container)

| Variable | Default | Description |
|----------|---------|-------------|
| `REMOTE_HAPROXY_ID` | _(empty)_ | Remote daemon's Nostr npub. Enables remote tunnel mode when set. |
| `TUNNEL_RELAY_URLS` | `wss://relay.primal.net,wss://relay.damus.io` | Comma-separated Nostr relay WebSocket URLs for Sphere SDK. |
| `TUNNEL_IDENTITY_DIR` | `/etc/letsencrypt/tunnel-identity` | Directory for persisted Sphere SDK and WireGuard keypairs. |
| `TUNNEL_NEGOTIATE_TIMEOUT` | `60` | Seconds to wait for `TUNNEL_OFFER` before timeout and retry. |
| `TUNNEL_HEARTBEAT_INTERVAL` | `300` | Seconds between `TUNNEL_HEARTBEAT` DMs. |
| `TUNNEL_RECONNECT_MAX` | `10` | Maximum reconnection attempts before fatal exit. |
| `TUNNEL_TRANSPORT` | _(auto)_ | Force transport: `udp` (direct WireGuard), `wss` (WebSocket wrapper), or `auto` (try UDP first, fall back to WSS). |
| `DYNDNS_PROVIDER` | _(empty)_ | Client's DynDNS provider (e.g., `cloudflare`, `route53`). Client manages its own DNS. |
| `DYNDNS_CREDENTIALS` | _(empty)_ | Client's DynDNS API credentials (provider-specific). Never sent to HAProxy. |

### New CLI Flags (`run-lib.sh`)

| Flag | Env Var Set | Description |
|------|-------------|-------------|
| `--remote-haproxy-id <npub>` | `REMOTE_HAPROXY_ID` | Enable remote tunnel mode targeting this HAProxy daemon. |
| `--tunnel-relay <url>` | `TUNNEL_RELAY_URLS` | Override Nostr relay URLs (comma-separated). |
| `--tunnel-transport <type>` | `TUNNEL_TRANSPORT` | Force transport: `udp`, `wss`, or `auto` (default). |
| `--dyndns-provider <name>` | `DYNDNS_PROVIDER` | Client's DynDNS provider for self-managed DNS. |

When `--remote-haproxy-id` is set, `run-lib.sh` automatically:
- Suppresses `--haproxy-host` Docker network wiring (no haproxy-net)
- Removes `-p 80:80` port publishing (traffic arrives through tunnel)
- Adds `--cap-add=NET_ADMIN` (required for WireGuard)
- Adds `--sysctl net.ipv4.conf.all.src_valid_mark=1` (WireGuard routing)

### HAProxy Daemon Configuration (haproxy-tunnel-daemon)

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNNEL_DAEMON_NPUB` | _(required)_ | Daemon's Nostr npub (its Sphere SDK identity). |
| `TUNNEL_DAEMON_NSEC` | _(required)_ | Daemon's Nostr nsec (private key). |
| `TUNNEL_SUBNET` | `10.200.0.0/24` | WireGuard subnet for tunnel peers. |
| `TUNNEL_WG_PORT` | `51820` | WireGuard listen port (UDP). |
| `TUNNEL_ACL` | _(empty)_ | Comma-separated list of authorized client npubs. |
| `TUNNEL_PUBLIC_IP` | _(auto-detected)_ | HAProxy host's public IP (for DNS instructions). |
| `TUNNEL_MAX_PEERS` | `250` | Maximum simultaneous tunnel clients. |

### New Dockerfile Dependencies

- `wireguard-tools` — WireGuard CLI (`wg`, `wg-quick`). ~5MB.
- `wstunnel` — Rust binary for wrapping WireGuard UDP in WebSocket. ~5-8MB static binary. Used when direct UDP is blocked by restrictive firewalls.
- `node` + `sphere-sdk` — For Sphere SDK DM communication. Installed in base image or as optional layer.
- `iptables` — For NAT masquerade (usually already present in Debian).

---

## 10. Error Handling and Failure Modes

### New Exit Codes for ssl-setup

| Code | Meaning |
|------|---------|
| `15` | Tunnel negotiation failed (daemon rejected or timeout after all retries) |
| `16` | Tunnel establishment failed (WireGuard interface failed to come up) |
| `17` | DNS propagation timeout (tunnel live but domain not resolving to HAProxy IP) |

### Failure Scenarios

**Nostr relay unavailable at startup:** tunnel-manager (via Sphere SDK) retries relay connections with backoff. Sphere SDK handles relay failover to configured alternates. After 5 minutes total, exits with code 15.

**Daemon offline or not responding:** `TUNNEL_REQUEST` DM times out after `TUNNEL_NEGOTIATE_TIMEOUT`. Retried up to 3 times with exponential backoff. If all fail, ssl-setup exits 15.

**Client npub not in ACL:** Daemon sends `TUNNEL_REJECTED` with `ERR_ACL_DENIED`. tunnel-manager logs the rejection and exits 15. Operator must add client npub to daemon's `TUNNEL_ACL`.

**WireGuard handshake failure:** `wg-quick up` succeeds but handshake never completes (e.g., firewall blocks UDP 51820). tunnel-manager detects stale handshake after 30 seconds, retries. After 3 failures, exits 16.

**Tunnel drops during operation:** WireGuard handles brief interruptions transparently (roaming). For longer outages (>90s without handshake), tunnel-manager enters RECONNECTING. If re-negotiation needed, sends new `TUNNEL_REQUEST`.

**Client DynDNS update fails:** Client-side issue — HAProxy is not involved. Client retries according to its own DynDNS provider's error handling. ssl-setup's nonce verification will fail (exit 10) if DNS is wrong, triggering a retry.

**NAT/masquerade misconfigured:** Client can reach WireGuard peer (10.200.0.1) but not the internet. tunnel-manager detects this by attempting `curl --connect-timeout 5 https://ifconfig.me` after tunnel establishment. Logs warning; ssl-setup may fail at nonce verification.

---

## 11. Integration with Existing ssl-setup.sh Flow

### Modified ssl-setup.sh Flow

```
Step 0: SSL_DOMAIN check (unchanged)
    │
    ▼
Step 0b: NEW — Remote tunnel mode detection
    if [ -n "${REMOTE_HAPROXY_ID:-}" ]; then
        tunnel-manager --start --wait-ready --timeout 300
        # Blocks until WireGuard tunnel is ACTIVE or exit 15/16
        . /tmp/.ssl-tunnel-env
        # HAPROXY_HOST now points to WireGuard server IP (10.200.0.1)
        # All outbound traffic routes via wg0 transparently
    fi
    │
    ▼
Step 1: Start ssl-http-proxy on port 80 (unchanged)
    │   In remote mode: reachable via WireGuard at 10.200.0.N:80
    ▼
Step 2: HAProxy registration (unchanged logic, WireGuard IP used transparently)
    │   HAProxy backend points to 10.200.0.N:80 / :${SSL_HTTPS_PORT}
    │   Aliases: each registered, HAProxy routes by domain to same peer IP
    ▼
Step 3: Nonce verification (unchanged — traffic flows through tunnel)
    │
    ▼
Step 4: Certificate acquisition (unchanged — certbot outbound routes via tunnel)
    │
    ▼
Step 5: TLS verification (unchanged)
    │
    ▼
Step 6: Re-register with HTTPS port (unchanged)
    │
    ▼
Step 7: Alias handling (unchanged — each alias registered with HAProxy,
    │   certbot obtains alias certs, ssl-alias-proxy started)
    ▼
Step 8: Start ssl-renew (unchanged)
    │
    ▼
Step 9: Export /tmp/.ssl-env (unchanged)
```

### Backwards Compatibility

If `REMOTE_HAPROXY_ID` is not set, the new code path is not executed. All existing behavior is preserved. The new dependencies (wireguard-tools, Node.js/Sphere SDK) are installed in the base image but have zero runtime overhead when unused.

### Entrypoint Pattern (unchanged)

Derived image entrypoints require no modification. The ssl-setup exit code contract is preserved. `/tmp/.ssl-env` is written at the same point. Graceful shutdown with `haproxy-register unregister` works unchanged — the HAProxy API is reached via the WireGuard IP.

---

## 12. Key Architectural Decisions

**Why WireGuard over SSH port forwarding?** The requirement for bidirectional full-network transparency rules out SSH `-R`. The container must route ALL traffic (inbound and outbound) through the HAProxy host so that DynDNS calls, certbot ACME validation, and arbitrary outbound connections work as if the container is on the HAProxy's network. WireGuard provides this as a true VPN tunnel with minimal overhead. SSH would require bolting on SOCKS proxying, DNS forwarding, and per-service configuration — more complex than WireGuard.

**Why Sphere SDK for DM communication, not a custom Nostr client?** Sphere SDK is the Unicity ecosystem's standard communication layer. It already implements NIP-17 encrypted DMs, key management, relay pooling, and delivery guarantees. Writing a custom client would duplicate work, introduce bugs, and fragment the ecosystem. Both the client (tunnel-manager) and server (haproxy-tunnel-daemon) use Sphere SDK, ensuring protocol compatibility.

**Why haproxy-tunnel-daemon runs inside the HAProxy container?** The daemon needs direct access to: (1) HAProxy runtime API via Unix socket, (2) WireGuard interface via `wg` CLI, (3) iptables for NAT rules. Running inside the container avoids cross-container coordination, shared volume mounts, and Docker network namespace complexity. It's a single-container deployment — simpler to operate.

**Why the client manages its own DNS?** HAProxy MUST NOT handle client DNS credentials. The client knows its DNS provider, has its own API tokens, and is responsible for its own domain records. The tunnel provides transparent outbound connectivity so the client can call its DNS provider directly. HAProxy's only role in DNS is reporting its own public IP in the `TUNNEL_OFFER` so the client knows what value to set in the A record.

**Why Nostr/NIP-17 for the control channel?** The client is behind a firewall — the daemon cannot reach it. Both sides can connect outbound to Nostr relays. Nostr provides decentralized, encrypted, store-and-forward messaging without requiring the daemon operator to run additional infrastructure. Relay redundancy provides resilience.

---

## Appendix A: File Locations (New)

| Path | Purpose |
|------|---------|
| `/usr/local/bin/tunnel-manager` | Tunnel lifecycle orchestrator (Node.js, Sphere SDK) |
| `/etc/letsencrypt/tunnel-identity/` | Persistent Sphere SDK and WireGuard keypairs |
| `/etc/letsencrypt/tunnel-identity/sphere-identity.json` | Sphere SDK keypair (npub, nsec) |
| `/etc/letsencrypt/tunnel-identity/wg-private.key` | WireGuard client private key |
| `/etc/letsencrypt/tunnel-identity/wg-public.key` | WireGuard client public key |
| `/tmp/.ssl-tunnel-env` | Sourceable tunnel connection params |
| `/tmp/.ssl-tunnel.pid` | PID of WireGuard monitor process |
| `/tmp/.ssl-tunnel-state` | Current tunnel-manager state (for debugging) |
| `/etc/wireguard/wg0.conf` | WireGuard config (written by tunnel-manager) |

## Appendix B: HAProxy Container Changes

The HAProxy container (separate project) gains:

| Component | Description |
|-----------|-------------|
| `haproxy-tunnel-daemon` | Node.js process, Sphere SDK, runs alongside HAProxy |
| WireGuard server config | `wg0` interface on 10.200.0.1/24, listens UDP 51820 |
| iptables NAT rules | MASQUERADE for 10.200.0.0/24 egress, FORWARD for peers |
| Peer state directory | `/var/lib/haproxy-tunnel/peers/` — per-client WireGuard configs |
| ACL config | `/etc/haproxy-tunnel/acl.json` — authorized client npubs |
