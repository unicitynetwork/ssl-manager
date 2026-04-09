# Remote HAProxy Tunneling — Architecture Design

## 1. High-Level Architecture

The remote client container establishes a **full bidirectional VPN tunnel** (WireGuard) to the HAProxy host. The container operates as if it were on the HAProxy host's network — all outbound traffic (DynDNS API calls, certbot ACME validation, etc.) routes through the tunnel, and all inbound traffic (user requests, ACME challenges) arrives through it. The container sees the HAProxy host's public IP as its own egress.

```
FIREWALL-CONSTRAINED CLIENT HOST                    PUBLIC REMOTE HOST
┌────────────────────────────────────────────┐     ┌──────────────────────────────────────────────────┐
│  Docker Container (ssl-manager:tunnel)     │     │  HAProxy Container + Sidecar                     │
│                                            │     │                                                  │
│  ┌────────────────────────────────────┐   │     │  ┌────────────────────────────────────┐          │
│  │  ssl-setup (orchestration)         │   │     │  │  haproxy-tunnel-daemon (sidecar)   │          │
│  │  - Detects REMOTE_HAPROXY_ID       │   │     │  │  - Node.js / Sphere SDK            │          │
│  │  - Delegates to tunnel-manager     │   │     │  │  - Shares network ns with HAProxy  │          │
│  └──────────┬─────────────────────────┘   │     │  │  - Manages WireGuard peers          │          │
│             │                             │     │  │  - Updates HAProxy (runtime API)    │          │
│  ┌──────────▼─────────────────────────┐   │     │  │  - Configures iptables NAT          │          │
│  │  tunnel-manager (new component)    │   │     │  └──────────────┬─────────────────────┘          │
│  │  - DM negotiation via Sphere SDK   │◄──┼─────┼────────────────┘ (Nostr/NIP-17 via Sphere SDK)  │
│  │  - Establishes WireGuard tunnel    │   │     │                                                  │
│  │  - Monitors + reconnects           │   │     │  ┌────────────────────────────────────┐          │
│  │  - Signals ssl-setup on ready      │   │     │  │  HAProxy Container                 │          │
│  └──────────┬─────────────────────────┘   │     │  │  - Frontend port 80 / 443          │          │
│             │                             │     │  │  - Per-domain backend → WG peer IP  │          │
│  ┌──────────▼─────────────────────────┐   │     │  │  - Runtime API on Unix socket      │          │
│  │  WireGuard VPN (wg0 interface)     │   │     │  └────────────────────────────────────┘          │
│  │  - Client: 10.200.0.N/32           ├───┼────►│                                                  │
│  │  - Split tunnel (see Section 4)    │   │     │  ┌────────────────────────────────────┐          │
│  │  - Internet traffic via wg0        │   │     │  │  WireGuard (wg0 interface)          │          │
│  │  - Docker DNS/app-net excluded     │   │     │  │  - Server: 10.200.0.1/24            │          │
│  └──────────┬─────────────────────────┘   │     │  │  - NAT masquerade (restricted)      │          │
│             │                             │     │  └────────────────────────────────────┘          │
│  ┌──────────▼─────────────────────────┐   │     │                                                  │
│  │  ssl-http-proxy (port 80)          │   │     │  ┌────────────────────────────────────┐          │
│  │  ssl-alias-proxy (port 8444)       │   │     │  │  wstunnel (WSS transport, optional) │          │
│  │  App (port SSL_HTTPS_PORT)         │   │     │  │  - Listens on dedicated port 8443   │          │
│  │  DynDNS client, certbot (outbound) │   │     │  │  - HAProxy SNI-routes tunnel.* → wstunnel │   │
│  └────────────────────────────────────┘   │     │  └────────────────────────────────────┘          │
│                                            │     │                                                  │
│  Sphere SDK identity: client.npub          │     │  Public IP: 198.51.100.42                       │
│  /tmp/.ssl-tunnel-env                      │     │  WireGuard: UDP 51820                            │
└────────────────────────────────────────────┘     │  wstunnel: TCP 8443 (via HAProxy SNI on 443)    │
                                                   └──────────────────────────────────────────────────┘
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
wg0 interface (policy-routed, Docker subnets excluded)
    │ internet-bound traffic exits via WireGuard tunnel
    ▼
HAProxy host WireGuard server (10.200.0.1)
    │ NAT masquerade (iptables MASQUERADE, restricted egress)
    ▼
Internet (appears to originate from HAProxy's public IP)
```

**Local (container → Docker services):**
```
Container process (database query, etc.)
    │ connects to 172.18.0.x (app-net peer)
    ▼
eth0 interface (Docker bridge, NOT routed through wg0)
    │ PostUp route exclusions keep Docker traffic local
    ▼
Backend service on app-net (database, etc.)
```

**Key insight:** The tunnel uses **split routing** — internet-bound traffic goes through WireGuard, but Docker internal DNS (127.0.0.11) and container-to-container traffic on Docker bridge networks (172.16.0.0/12) stay local. This preserves Docker networking while providing transparent internet access through the HAProxy host's IP.

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

**Runtime:** Node.js (Sphere SDK requires it). Available only in the `ssl-manager:tunnel` image variant (see Image Variants below).

**Why Sphere SDK, not a custom Nostr client:** Sphere SDK already implements NIP-17 gift-wrapped DMs, key management, relay connection pooling, and message delivery — all battle-tested.

#### `haproxy-tunnel-daemon` (sidecar container)

Runs as a **sidecar container** sharing the HAProxy container's network namespace (`--network container:haproxy`). Written in Node.js using Sphere SDK for DM communication. This gives it direct access to HAProxy's runtime API (Unix socket via shared volume), the WireGuard interface, and iptables — without bloating the HAProxy container with Node.js, Sphere SDK, and their dependency trees.

Responsibilities:
- Listens for DTNP `TUNNEL_REQUEST` DMs addressed to its npub
- Validates client npub against ACL (domain-scoped, see Security Model)
- Allocates WireGuard peer IP from its subnet pool (10.200.0.0/24, 30-second cooldown after teardown)
- Generates WireGuard peer config and sends `TUNNEL_OFFER` via DM
- Adds WireGuard peer to the server's `wg0` interface
- Configures HAProxy backends via runtime API (pointing to client's WireGuard IP)
- Configures iptables NAT/masquerade with restricted egress rules
- Handles heartbeat, reconnection, and teardown
- Exposes `/v1/tunnels` REST endpoint for monitoring (see Observability)
- On teardown: removes WireGuard peer, HAProxy backends, iptables rules (30s IP cooldown before reuse)

**Why sidecar, not inside HAProxy container:** HAProxy containers are typically minimal (Alpine-based, ~20MB). Adding Node.js (+100MB), Sphere SDK, and npm dependencies would massively increase image size and attack surface. The sidecar pattern keeps HAProxy lean while sharing its network namespace for direct access to interfaces, ports, and Unix sockets.

#### `/tmp/.ssl-tunnel-env`

Sourceable file written by `tunnel-manager` when the tunnel is established:
```bash
TUNNEL_ACTIVE=true
TUNNEL_TYPE=wireguard
TUNNEL_CLIENT_IP=10.200.0.2
TUNNEL_SERVER_IP=10.200.0.1
HAPROXY_HOST=10.200.0.1
HAPROXY_API_PORT=8404
HAPROXY_API_KEY=<per-session-domain-scoped-token>
HAPROXY_REMOTE_PUBLIC_IP=198.51.100.42
```

After sourcing this file, ssl-setup's HAProxy registration calls target `10.200.0.1:8404` (the HAProxy's WireGuard IP), which is reachable through the tunnel.

### Modified Components

#### `ssl-setup.sh`

Gains a new early branch: if `REMOTE_HAPROXY_ID` is set, delegate to `tunnel-manager --start --wait-ready` before proceeding. After tunnel-manager signals readiness, ssl-setup sources `/tmp/.ssl-tunnel-env` which overrides `HAPROXY_HOST` to point at the WireGuard server IP. All subsequent steps (HAProxy registration, nonce verification, certbot, TLS verification) work unchanged — the tunnel provides transparent bidirectional connectivity.

#### `haproxy-register.sh`

Gains awareness of alias domains in the tunnel context. When registering via the tunnel, it includes all `SSL_DOMAIN_ALIASES` in the registration payload so HAProxy creates backends for each alias pointing to the client's WireGuard IP. The registration payload includes `tunnel_peer_ip` so HAProxy knows to route to the WireGuard address rather than a Docker network hostname.

#### `ssl-renew.sh`

Gains tunnel health awareness. Before attempting `certbot renew`, checks tunnel state via `wg show wg0 latest-handshake`. If the tunnel is degraded (handshake stale >3 minutes), skips the renewal attempt and logs a warning. Tracks consecutive certbot failures — backs off to max 2 failed attempts per 24 hours per domain to avoid exhausting Let's Encrypt rate limits (5 failed authorizations per hour per hostname).

#### `run-lib.sh`

Gains `--remote-haproxy-id <npub>`, `--tunnel-relay <url>`, `--tunnel-transport <type>`, and `--tunnel-mode <full|lite>` argument parsing. When `REMOTE_HAPROXY_ID` is set:
- Suppresses `--haproxy-host` Docker network wiring (no haproxy-net)
- Removes `-p 80:80` port publishing (traffic arrives through tunnel)
- Adds `--cap-add=NET_ADMIN` to Docker create (required for WireGuard)
- Adds `--device /dev/net/tun:/dev/net/tun` (required for WireGuard tun interface)
- Adds `--sysctl net.ipv4.conf.all.src_valid_mark=1` for WireGuard routing

---

## 3. Tunnel Modes

### Full Mode (default): WireGuard VPN

The primary mode provides **bidirectional full-network transparency**: the container behaves as if it's on the HAProxy host's network. All internet-bound traffic routes through the tunnel.

| Requirement | Full Mode (WireGuard) |
|------------|----------------------|
| Inbound traffic to container ports | Yes (all ports, automatic) |
| Outbound from container to internet | Yes (default route via wg0) |
| Container sees HAProxy's public IP | Yes (NAT masquerade) |
| DynDNS API calls from container | Works transparently |
| certbot outbound to ACME servers | Works (via tunnel) |
| Docker image size | ~13MB (wireguard-tools + wstunnel) |
| Kernel requirement | Linux 5.6+ (or wireguard-go userspace) |
| Container capability | `NET_ADMIN` + `/dev/net/tun` |

### Lite Mode: SSH Reverse Tunnel

For users who only need **inbound port forwarding** and already have direct internet access for outbound (certbot, DynDNS), a lightweight SSH `-R` mode is available. This covers the common case of a home server behind NAT.

| Requirement | Lite Mode (SSH -R) |
|------------|-------------------|
| Inbound traffic to container ports | Yes (explicit -R per port) |
| Outbound from container to internet | Direct (not through tunnel) |
| Container sees HAProxy's public IP | No |
| DynDNS API calls from container | Direct internet required |
| certbot outbound to ACME servers | Direct internet (works) |
| Docker image size | ~60KB (autossh) |
| Kernel requirement | None |
| Container capability | None |

Lite mode is selected via `--tunnel-mode lite` or `TUNNEL_MODE=lite`. The DTNP negotiation is the same — the client includes `tunnel_preference: ["ssh-reverse"]` in its `TUNNEL_REQUEST`, and the server responds with SSH connection details instead of WireGuard credentials.

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

### Port 443 Multiplexing

HAProxy listens on port 443 for SNI-based TLS passthrough to application backends. wstunnel also needs port 443 to look like HTTPS. These are multiplexed via **HAProxy SNI routing**:

- wstunnel clients connect using a dedicated hostname: `tunnel.<haproxy-domain>` (e.g., `tunnel.proxy.example.com`)
- HAProxy's TCP frontend on port 443 inspects the SNI field:
  - SNI matching `tunnel.*` → route to wstunnel backend on `127.0.0.1:8443`
  - All other SNI → route to normal application backends
- wstunnel server binds to `127.0.0.1:8443` (internal only, not publicly exposed)

```
Internet client → HAProxy:443
    │
    ├─ SNI = "mydomain.com"        → backend app (10.200.0.N:443)
    ├─ SNI = "alias.example.com"   → backend app (10.200.0.N:8444)
    └─ SNI = "tunnel.proxy.com"    → backend wstunnel (127.0.0.1:8443)
```

The `TUNNEL_OFFER.transports` array includes the SNI hostname:
```json
{
  "transports": [
    { "type": "udp", "endpoint": "198.51.100.42:51820" },
    { "type": "wss", "endpoint": "wss://tunnel.proxy.example.com:443/wg",
      "sni": "tunnel.proxy.example.com" }
  ]
}
```

### Transport Negotiation

tunnel-manager tries transports in order:
1. **Direct UDP** — fastest, try first (5-second handshake timeout)
2. **WSS** — if UDP fails, start wstunnel client, connect via WebSocket on port 443 with the tunnel SNI hostname
3. **WSS via HTTP proxy** — if WSS direct fails, try through `HTTP_PROXY`/`HTTPS_PROXY` environment variables

The client can force a specific transport via `TUNNEL_TRANSPORT=wss` environment variable.

The `TUNNEL_ACCEPT` message includes `accepted_transport` to inform the server which transport the client chose, allowing the server to ensure the right infrastructure is active and apply transport-specific constraints.

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

If even WebSocket traffic is fingerprinted (rare, but possible in state-level censorship), **sing-box** can be used as an alternative transport with VLESS/Trojan protocols. This is a future extension — wstunnel covers 99% of restrictive networks.

---

## 5. Split Routing: Preserving Docker Networking

### The Problem

`AllowedIPs = 0.0.0.0/0` in WireGuard hijacks the container's entire default route. This breaks:
- **Docker internal DNS** (127.0.0.11) — container can't resolve service names
- **Container-to-container networking** — can't reach backends on `app-net` (172.x.x.x)
- **Localhost services** — can't reach other processes on 127.0.0.1

### Solution: PostUp Route Exclusions

The WireGuard config uses `AllowedIPs = 0.0.0.0/0` for policy routing via fwmark, but adds `PostUp` rules to exclude Docker and local subnets:

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.200.0.2/32
# Exclude Docker bridge networks and DNS from WireGuard
PostUp = ip rule add to 127.0.0.0/8 lookup main priority 10
PostUp = ip rule add to 172.16.0.0/12 lookup main priority 11
PostUp = ip rule add to 127.0.0.11/32 lookup main priority 9

[Peer]
PublicKey = <server-public-key>
PresharedKey = <preshared-key>
Endpoint = 198.51.100.42:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

This ensures:
- `127.0.0.11` (Docker DNS) → resolved via Docker's embedded DNS, not tunneled
- `172.16.0.0/12` (Docker bridge networks) → routed via Docker bridge, not tunneled
- Everything else → tunneled through WireGuard

tunnel-manager auto-detects Docker bridge subnets by inspecting the container's network interfaces at startup and adds the appropriate exclusion rules.

---

## 6. Tunnel Lifecycle

### Establishment

1. tunnel-manager probes for WireGuard availability: `modprobe wireguard 2>/dev/null || modinfo wireguard 2>/dev/null`. If neither succeeds, checks for `wireguard-go` in PATH. If unavailable, exits 16 with: "WireGuard kernel module not found and wireguard-go not installed. Requires Linux 5.6+ or wireguard-go."
2. tunnel-manager loads or generates a Sphere SDK identity (secp256k1 keypair) and a WireGuard keypair. Both are persisted at `/etc/letsencrypt/tunnel-identity/` (permissions 0600, owned by root).
3. tunnel-manager sends `TUNNEL_REQUEST` DM via Sphere SDK to `REMOTE_HAPROXY_ID`, including:
   - Primary domain + all aliases
   - Required ports (HTTP 80, HTTPS `SSL_HTTPS_PORT`, alias proxy 8444, extra ports)
   - Client WireGuard public key
   - Client capabilities and transport preference
4. haproxy-tunnel-daemon receives the request, validates ACL (domain-scoped), allocates a WireGuard peer IP (e.g., 10.200.0.2/32), and responds with `TUNNEL_OFFER`:
   - Available transports (UDP, WSS with SNI hostname)
   - Server WireGuard public key
   - Allocated client IP
   - Preshared key (encrypted to client's npub via NIP-44)
   - HAProxy API URL (via WireGuard IP) with domain-scoped session token
5. tunnel-manager writes WireGuard config with split-routing PostUp rules and brings up `wg0`.
6. tunnel-manager verifies connectivity: pings `10.200.0.1`, then `curl http://10.200.0.1:8404/v1/health`.
7. tunnel-manager sends `TUNNEL_ESTABLISHED` DM.
8. tunnel-manager writes `/tmp/.ssl-tunnel-env` and signals ssl-setup to proceed.

### Monitoring

Two layers of health monitoring:

**WireGuard-level (fast, no relay load):**
- Every 30 seconds: check `wg show wg0 latest-handshake` — if stale (>3 minutes), consider tunnel degraded
- WireGuard's built-in `PersistentKeepalive = 25` sends keepalive packets through the tunnel
- If 3 consecutive handshake checks show stale: enter RECONNECTING

**DTNP-level (infrequent, via Sphere SDK DMs):**
- Every 15 minutes: send `TUNNEL_HEARTBEAT` DM via Sphere SDK with tunnel metrics
- This is for status reporting and presence confirmation, NOT for liveness detection
- WireGuard handshake is the authoritative liveness signal

### Reconnection

1. WireGuard handles brief interruptions automatically (roaming, transient network loss)
2. On WireGuard auto-recovery after brief outage, client MUST immediately send a `TUNNEL_HEARTBEAT` DM to cancel any pending server-side teardown
3. If `wg show wg0 latest-handshake` remains stale for >90 seconds: bring down wg0, bring it back up
4. If still unreachable after 90 seconds: send new `TUNNEL_REQUEST` DM with same idempotency key
5. Client adds random jitter (0-60 seconds) before reconnection to avoid thundering herd on HAProxy reboot
6. After `TUNNEL_RECONNECT_MAX` total failures: signal fatal error to ssl-setup (exit 16)

### Server-Initiated Changes

The server may send `TUNNEL_CONFIG_UPDATE` if its public IP changes (failover, elastic IP reassignment). The client must update its DNS records and acknowledge via heartbeat. If the client does not acknowledge within 5 minutes, the server may teardown.

The server may send `TUNNEL_MAINTENANCE_NOTICE` before planned downtime, giving the client advance warning to drain connections. After the maintenance window, the client reconnects automatically.

### Teardown

On container SIGTERM:
1. Client updates its own DNS records if needed (client-managed)
2. Send `TUNNEL_TEARDOWN` DM via Sphere SDK
3. `wg-quick down wg0`
4. Remove `/tmp/.ssl-tunnel-env`
5. HAProxy daemon receives teardown → removes WireGuard peer, removes HAProxy backends, removes iptables rules. Peer IP enters 30-second cooldown before reuse.

### State Machine

```
tunnel-manager states:

IDLE
  │ REMOTE_HAPROXY_ID set at startup
  ▼
BOOTSTRAPPING
  │ Probe WireGuard availability (kernel module or wireguard-go)
  │ Load/generate Sphere SDK identity + WireGuard keypair
  │ Set file permissions (0600, root)
  │ Connect to Nostr relays via Sphere SDK
  ▼
NEGOTIATING
  │ Send TUNNEL_REQUEST via Sphere SDK DM
  │ Wait up to 90s for TUNNEL_OFFER or TUNNEL_REJECTED
  │ On REJECTED with retry_after: sleep, retry (max 3 attempts)
  │ On timeout: retry with backoff (30s, 60s, 120s)
  ▼
ESTABLISHING
  │ Write wg0.conf with split-routing PostUp rules
  │ Try transports in order: UDP → WSS → WSS-proxy
  │ wg-quick up wg0 (if fails: send TUNNEL_ERROR immediately, don't wait 120s)
  │ Verify connectivity (ping + HAProxy API health)
  │ Send TUNNEL_ESTABLISHED DM (with accepted_transport)
  │ Write /tmp/.ssl-tunnel-env
  ▼
ACTIVE
  │ WireGuard handshake check every 30s (no relay traffic)
  │ TUNNEL_HEARTBEAT DM every 15 minutes (status only)
  │ On WireGuard auto-recovery: immediately send heartbeat DM
  ▼
RECONNECTING (on stale handshake >90s)
  │ Add random jitter (0-60s) to avoid thundering herd
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

## 7. Dynamic DNS Integration

### Principle: Client Owns Its DNS

**HAProxy MUST NOT manage client DNS credentials.** The client is responsible for its own DynDNS updates. The tunnel provides transparent network connectivity so the client can reach its DNS provider directly.

### How It Works

1. The client container has its DynDNS credentials (env vars, config files — same as without tunneling).
2. The WireGuard tunnel routes internet-bound traffic through the HAProxy host with NAT masquerade.
3. When the client calls its DynDNS provider API, the request exits through the HAProxy host's public IP — transparently.
4. The client updates its DNS A record to point to the HAProxy host's public IP (provided in `TUNNEL_OFFER.haproxy_public_ip`).
5. DNS propagation happens normally.

### Credential Security

DynDNS credentials should be provided via **Docker secrets** or a **mounted credentials file** (not environment variables, which are visible via `docker inspect` and `/proc/1/environ`). The `DYNDNS_CREDENTIALS` env var is supported for convenience but documented as less secure. Credentials should use scoped API tokens with minimal permissions (DNS record update only for the specific zone).

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

---

## 8. SSL Certificate Flow Through Tunnel

The certificate flow is **identical to local mode** because the WireGuard tunnel provides full bidirectional connectivity. From certbot's and ssl-setup's perspective, nothing has changed:

1. WireGuard tunnel established: container has IP 10.200.0.2, internet traffic routes via wg0.
2. HAProxy configured: `mydomain.com` HTTP → 10.200.0.2:80, HTTPS SNI → 10.200.0.2:${SSL_HTTPS_PORT}.
3. For each alias: HAProxy routes alias HTTP → 10.200.0.2:80, alias HTTPS → 10.200.0.2:8444.
4. DNS points all domains to HAProxy public IP.
5. ssl-setup starts ssl-http-proxy on port 80 (unchanged).
6. Nonce verification: traffic arrives through internet → HAProxy → WireGuard → container:80.
7. certbot runs webroot on port 80. certbot's outbound HTTPS to ACME servers routes via WireGuard → NAT → internet.
8. Certificate obtained. Re-register with HAProxy including HTTPS port.
9. ssl-renew checks tunnel health before each renewal attempt. Backs off on repeated certbot failures to avoid Let's Encrypt rate limits.

---

## 9. Security Model

### Identity and Authentication

Both sides use **Sphere SDK identities** (secp256k1 keypairs). All DM communication is NIP-17 gift-wrapped: encrypted to the recipient's pubkey, signed by the sender's key.

### Access Control (Domain-Scoped ACL)

The haproxy-tunnel-daemon maintains an ACL that binds each authorized client npub to specific domain patterns:

```json
{
  "acl": [
    { "npub": "npub1abc...", "domains": ["mydomain.com", "*.mydomain.com"] },
    { "npub": "npub1def...", "domains": ["other.example.com"] }
  ]
}
```

**Domain binding is mandatory**, not optional. A TUNNEL_REQUEST for a domain outside the client's authorized scope is rejected with `ERR_DOMAIN_UNAUTHORIZED`. This prevents authorized clients from claiming arbitrary domains.

### Key Compromise Response

If a client's private key is compromised:
1. Remove the client's npub from the ACL config
2. The daemon tears down any active tunnel for that npub
3. Rotate the compromised client's Sphere SDK and WireGuard keys
4. Re-add the new npub to the ACL

When a `TUNNEL_REQUEST` arrives for a client that already has an ACTIVE tunnel, the daemon sends `TUNNEL_ERROR` to the requester and alerts the operator (potential key compromise or legitimate reconnection).

### Tunnel Security

WireGuard provides:
- **Mutual authentication** via public key exchange (negotiated through encrypted DMs)
- **Perfect forward secrecy** via Noise protocol handshake
- **Minimal attack surface** (~4,000 lines of kernel code, formally verified)
- **Preshared key** (per-session, encrypted via NIP-44 — not NIP-04 which is deprecated and lacks AEAD)
- **No listening port on client** — client initiates; only the server listens on UDP 51820

### Network Isolation (Restricted NAT)

Each client peer gets a unique `/32` IP within the 10.200.0.0/24 subnet. The HAProxy host's iptables rules are **explicitly restrictive**:

```bash
# NAT masquerade for client egress
iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o eth0 -j MASQUERADE

# --- FORWARD chain rules (ORDER MATTERS — first match wins) ---

# ALLOW: WireGuard peers to HAProxy API (must be BEFORE the 10.0.0.0/8 DROP)
iptables -A FORWARD -s 10.200.0.0/24 -d 10.200.0.1 -p tcp --dport 8404 -j ACCEPT

# DENY: inter-peer traffic (clients cannot reach each other)
iptables -A FORWARD -s 10.200.0.0/24 -d 10.200.0.0/24 -j DROP

# DENY: cloud metadata endpoint (AWS/GCP/Azure instance metadata)
iptables -A FORWARD -s 10.200.0.0/24 -d 169.254.169.254 -j DROP

# DENY: private subnets (Docker networks, host services, other internal)
iptables -A FORWARD -s 10.200.0.0/24 -d 172.16.0.0/12 -j DROP
iptables -A FORWARD -s 10.200.0.0/24 -d 192.168.0.0/16 -j DROP
iptables -A FORWARD -s 10.200.0.0/24 -d 10.0.0.0/8 -j DROP

# ALLOW: internet-routable destinations (everything not matched above)
iptables -A FORWARD -s 10.200.0.0/24 -j ACCEPT
```

**Rationale:** Without these restrictions, a compromised container becomes an open proxy through the HAProxy host — able to scan Docker networks, access cloud metadata, and attack other services. The rules ensure clients can only reach the public internet and the HAProxy API.

### HAProxy Session API Key (Domain-Scoped)

The `haproxy_api.session_key` in TUNNEL_OFFER is **scoped to the domains in the original TUNNEL_REQUEST**. The HAProxy Registration API enforces:
- The session key can only register/unregister backends for the client's authorized domains
- API calls per session key are rate-limited (10 calls per minute)
- The key is valid only for the tunnel session lifetime

### Credential Storage

- **Identity files** (`sphere-identity.json`, `wg-private.key`) are stored with permissions **0600, owned by root** in `/etc/letsencrypt/tunnel-identity/`.
- **DynDNS credentials** should use Docker secrets or mounted files, not environment variables.
- **HAProxy daemon nsec** should use Docker secrets (`/run/secrets/tunnel-daemon-nsec`), not environment variables.

### Threat Model

**Relay compromise:** Attacker sees encrypted event metadata but cannot read content (NIP-17). Cannot forge messages without private keys.

**WireGuard port scan:** UDP 51820 is open on HAProxy host, but WireGuard silently drops packets from unknown peers.

**Client impersonation:** Requires both the client's Sphere SDK private key (for DM auth) and WireGuard private key (for tunnel auth). Compromise of either alone is insufficient.

**DM replay:** Prevented by NIP-17 event ID deduplication, correlation_id + sequence numbers, and 2-minute timestamp window (see protocol-spec.md).

**NAT abuse:** Restricted iptables rules prevent access to private subnets, cloud metadata, and other peers.

---

## 10. Configuration

### New Environment Variables (in-container)

| Variable | Default | Description |
|----------|---------|-------------|
| `REMOTE_HAPROXY_ID` | _(empty)_ | Remote daemon's Nostr npub. Enables remote tunnel mode when set. |
| `TUNNEL_MODE` | `full` | `full` (WireGuard VPN) or `lite` (SSH -R inbound only). |
| `TUNNEL_RELAY_URLS` | `wss://relay.primal.net,wss://relay.damus.io,wss://nos.lol,wss://relay.nostr.band` | Comma-separated Nostr relay WebSocket URLs for Sphere SDK (4+ relays for redundancy). |
| `TUNNEL_IDENTITY_DIR` | `/etc/letsencrypt/tunnel-identity` | Directory for persisted Sphere SDK and WireGuard keypairs (permissions 0600). |
| `TUNNEL_NEGOTIATE_TIMEOUT` | `60` | Seconds to wait for `TUNNEL_OFFER` before timeout and retry. |
| `TUNNEL_HEARTBEAT_INTERVAL` | `900` | Seconds between `TUNNEL_HEARTBEAT` DMs (status only; WireGuard keepalive handles liveness). |
| `TUNNEL_RECONNECT_MAX` | `10` | Maximum reconnection attempts before fatal exit. |
| `TUNNEL_RECONNECT_JITTER` | `60` | Maximum random jitter (seconds) before reconnection to avoid thundering herd. |
| `TUNNEL_TRANSPORT` | `auto` | Force transport: `udp` (direct WireGuard), `wss` (WebSocket wrapper), or `auto` (try UDP first, fall back to WSS). |
| `DYNDNS_PROVIDER` | _(empty)_ | Client's DynDNS provider (e.g., `cloudflare`, `route53`). Client manages its own DNS. |

### New CLI Flags (`run-lib.sh`)

| Flag | Env Var Set | Description |
|------|-------------|-------------|
| `--remote-haproxy-id <npub>` | `REMOTE_HAPROXY_ID` | Enable remote tunnel mode targeting this HAProxy daemon. |
| `--tunnel-mode <mode>` | `TUNNEL_MODE` | `full` (WireGuard VPN) or `lite` (SSH -R). |
| `--tunnel-relay <url>` | `TUNNEL_RELAY_URLS` | Override Nostr relay URLs (comma-separated). |
| `--tunnel-transport <type>` | `TUNNEL_TRANSPORT` | Force transport: `udp`, `wss`, or `auto` (default). |
| `--dyndns-provider <name>` | `DYNDNS_PROVIDER` | Client's DynDNS provider for self-managed DNS. |

When `--remote-haproxy-id` is set, `run-lib.sh` automatically:
- Suppresses `--haproxy-host` Docker network wiring (no haproxy-net)
- Removes `-p 80:80` port publishing (traffic arrives through tunnel)
- **Full mode only** (`TUNNEL_MODE != lite`):
  - Adds `--cap-add=NET_ADMIN` (required for WireGuard)
  - Adds `--device /dev/net/tun:/dev/net/tun` (required for WireGuard tun interface)
  - Adds `--sysctl net.ipv4.conf.all.src_valid_mark=1` (WireGuard policy routing)

### HAProxy Daemon Configuration (haproxy-tunnel-daemon sidecar)

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNNEL_DAEMON_IDENTITY` | _(required)_ | Path to Sphere SDK identity file (Docker secret recommended). |
| `TUNNEL_SUBNET` | `10.200.0.0/24` | WireGuard subnet for tunnel peers. |
| `TUNNEL_WG_PORT` | `51820` | WireGuard listen port (UDP). |
| `TUNNEL_WSS_PORT` | `8443` | wstunnel listen port (HAProxy SNI-routes tunnel.* here). |
| `TUNNEL_WSS_SNI` | `tunnel.<haproxy-domain>` | SNI hostname for WSS transport. |
| `TUNNEL_ACL_FILE` | `/etc/haproxy-tunnel/acl.json` | Path to domain-scoped ACL config. |
| `TUNNEL_PUBLIC_IP` | _(auto-detected)_ | HAProxy host's public IP (for DNS instructions). |
| `TUNNEL_MAX_PEERS` | `250` | Maximum simultaneous tunnel clients. |
| `TUNNEL_IP_COOLDOWN` | `30` | Seconds before a freed peer IP can be reused. |

### Image Variants

Two ssl-manager Docker image tags:
- **`ssl-manager:latest`** — Base image without tunnel dependencies. Includes certbot, Python, curl, openssl, etc. (~150MB compressed). For containers that only use local HAProxy or no SSL.
- **`ssl-manager:tunnel`** — Base image plus WireGuard tools, wstunnel, Node.js, Sphere SDK. (~250MB compressed). Required when using `REMOTE_HAPROXY_ID`.

Derived images choose their base:
```dockerfile
# Without tunneling:
FROM ghcr.io/unicitynetwork/ssl-manager:latest

# With tunneling:
FROM ghcr.io/unicitynetwork/ssl-manager:tunnel
```

### New Dockerfile Dependencies (tunnel variant only)

- `wireguard-tools` — WireGuard CLI (`wg`, `wg-quick`). ~5MB.
- `wireguard-go` — Userspace WireGuard (fallback for kernels <5.6). ~3MB.
- `wstunnel` — Rust binary for wrapping WireGuard UDP in WebSocket. ~5-8MB static binary.
- `node` + `sphere-sdk` — For Sphere SDK DM communication.
- `iptables` — For NAT masquerade (usually already present in Debian).
- `autossh` — For lite mode SSH -R tunneling. ~60KB.

### Platform Compatibility

| Platform | Full Mode (WireGuard) | Lite Mode (SSH -R) |
|----------|----------------------|-------------------|
| Bare Docker (Linux) | Fully supported | Fully supported |
| Docker Compose | Supported (`cap_add`, `devices` in YAML) | Fully supported |
| Kubernetes | Requires `securityContext.capabilities.add: [NET_ADMIN]` + device plugin | Fully supported |
| ECS on EC2 | Requires `privileged` task definition | Fully supported |
| Fargate / Cloud Run / ACI | **Not supported** (no CAP_NET_ADMIN) | Fully supported |

---

## 11. Error Handling and Failure Modes

### New Exit Codes for ssl-setup

| Code | Meaning |
|------|---------|
| `15` | Tunnel negotiation failed (daemon rejected or timeout after all retries) |
| `16` | Tunnel establishment failed (WireGuard unavailable or interface failed to come up) |
| `17` | DNS propagation timeout (tunnel live but domain not resolving to HAProxy IP) |

### Failure Scenarios

**WireGuard kernel module missing:** tunnel-manager probes at startup (`modprobe wireguard` / `modinfo wireguard`). If missing, checks for `wireguard-go` in PATH. If neither: clear error message and exit 16.

**/dev/net/tun not available:** `wg-quick up` fails with "Cannot open /dev/net/tun". tunnel-manager detects this and exits 16 with: "Missing /dev/net/tun device. Add --device /dev/net/tun:/dev/net/tun to docker create."

**Nostr relay unavailable at startup:** tunnel-manager (via Sphere SDK) retries relay connections with backoff. Default config includes 4 relays for redundancy. After 5 minutes total, exits with code 15.

**Daemon offline or not responding:** `TUNNEL_REQUEST` DM times out after `TUNNEL_NEGOTIATE_TIMEOUT`. Retried up to 3 times with exponential backoff. If all fail, ssl-setup exits 15.

**Client npub not in ACL:** Daemon sends `TUNNEL_REJECTED` with `ERR_ACL_DENIED`. tunnel-manager exits 15.

**Domain outside ACL scope:** Daemon sends `TUNNEL_REJECTED` with `ERR_DOMAIN_UNAUTHORIZED`. Client requested a domain not bound to its npub in the ACL.

**WireGuard handshake failure:** `wg-quick up` succeeds but handshake never completes. tunnel-manager detects stale handshake after 30 seconds. Falls back to WSS transport if in `auto` mode. After exhausting transports, exits 16.

**Docker DNS/networking broken after tunnel up:** tunnel-manager verifies Docker DNS resolution (`getent hosts` for a known Docker service name) after `wg-quick up`. If broken, PostUp route exclusions may have failed. Logs diagnostic info and proceeds (degraded mode).

**Certbot fails during renewal (tunnel flap):** ssl-renew checks tunnel health before renewal. On repeated certbot failures, backs off to max 2 attempts per 24 hours per domain.

**HAProxy reboot (thundering herd):** Clients add random jitter (0-`TUNNEL_RECONNECT_JITTER` seconds) before reconnecting. Server-side daemon rate-limits tunnel requests (max 10 per second).

---

## 12. Observability

### Server-Side (haproxy-tunnel-daemon)

**REST endpoint:** `GET /v1/tunnels` returns:
```json
{
  "active_peers": 42,
  "max_peers": 250,
  "subnet": "10.200.0.0/24",
  "peers": [
    {
      "npub": "npub1abc...",
      "peer_ip": "10.200.0.2",
      "primary_domain": "mydomain.com",
      "aliases": ["alias1.com"],
      "state": "ACTIVE",
      "transport": "udp",
      "uptime_seconds": 86400,
      "last_handshake_seconds_ago": 12,
      "rx_bytes": 1048576,
      "tx_bytes": 524288
    }
  ]
}
```

**Prometheus metrics** (exposed on `/metrics`):
- `tunnel_active_peers` — gauge
- `tunnel_handshake_age_seconds` — histogram per peer
- `tunnel_bytes_rx_total`, `tunnel_bytes_tx_total` — counters per peer
- `tunnel_negotiation_duration_seconds` — histogram
- `tunnel_reconnections_total` — counter per peer
- `tunnel_request_rate` — rate of incoming TUNNEL_REQUEST DMs

**Structured logging:** JSON format with fields: `event`, `client_npub`, `peer_ip`, `domain`, `state`, `duration_ms`.

### Client-Side (tunnel-manager)

**Extended health endpoint:** `/_ssl/health` gains tunnel fields when `TUNNEL_ACTIVE=true`:
```json
{
  "tunnel_state": "ACTIVE",
  "tunnel_peer_ip": "10.200.0.2",
  "tunnel_transport": "udp",
  "tunnel_uptime_seconds": 86400,
  "tunnel_last_handshake_seconds_ago": 12,
  "tunnel_server_ip": "10.200.0.1"
}
```

---

## 13. Integration with Existing ssl-setup.sh Flow

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
        # Internet traffic routes via wg0, Docker traffic stays local
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
    ▼
Step 4: Certificate acquisition (unchanged — certbot outbound routes via tunnel)
    ▼
Step 5: TLS verification (unchanged)
    ▼
Step 6: Re-register with HTTPS port (unchanged)
    ▼
Step 7: Alias handling (unchanged)
    ▼
Step 8: Start ssl-renew (tunnel-aware: checks health before renewal)
    ▼
Step 9: Export /tmp/.ssl-env (unchanged)
```

### Backwards Compatibility

If `REMOTE_HAPROXY_ID` is not set, the new code path is not executed. All existing behavior is preserved. Tunnel dependencies are only present in the `ssl-manager:tunnel` image variant — the `ssl-manager:latest` image is unchanged.

---

## 14. Key Architectural Decisions

**Why WireGuard over SSH port forwarding (for full mode)?** The requirement for bidirectional full-network transparency rules out SSH `-R`. WireGuard provides this as a true VPN with minimal overhead. SSH -R is offered as "lite mode" for inbound-only use cases.

**Why split routing instead of AllowedIPs=0.0.0.0/0?** Pure 0.0.0.0/0 breaks Docker internal DNS (127.0.0.11) and container-to-container networking on bridge networks. PostUp route exclusions preserve Docker networking while tunneling internet traffic.

**Why a sidecar instead of running inside HAProxy container?** HAProxy containers are minimal (~20MB Alpine). Adding Node.js (+100MB), Sphere SDK, and npm dependencies would triple the image size and increase the attack surface of a network-edge component. The sidecar shares the network namespace for direct access to interfaces and sockets.

**Why Sphere SDK for DM communication?** Sphere SDK is the Unicity ecosystem's standard. Both sides use it, ensuring protocol compatibility. Writing a custom NIP-17 client would duplicate work and diverge from the ecosystem.

**Why the client manages its own DNS?** HAProxy MUST NOT handle client DNS credentials. The tunnel provides transparent outbound connectivity for the client's DNS API calls.

**Why Nostr/NIP-17 for the control channel?** The client is behind a firewall — the daemon cannot reach it. Nostr relays provide decentralized, encrypted store-and-forward messaging. Four default relays provide redundancy. Future: support private relay deployment for production.

**Why restricted NAT rules?** Without explicit iptables restrictions, NAT masquerade creates an open proxy. Rules deny access to private subnets, cloud metadata, and inter-peer traffic.

**Why NIP-44 instead of NIP-04 for inner encryption?** NIP-04 is deprecated — it uses AES-256-CBC without authentication (no HMAC/AEAD), making it susceptible to padding oracle attacks. NIP-44 uses XChaCha20-Poly1305, a modern AEAD cipher.

---

## Appendix A: File Locations (New)

| Path | Purpose |
|------|---------|
| `/usr/local/bin/tunnel-manager` | Tunnel lifecycle orchestrator (Node.js, Sphere SDK) |
| `/etc/letsencrypt/tunnel-identity/` | Persistent keypairs (permissions 0600, root) |
| `/etc/letsencrypt/tunnel-identity/sphere-identity.json` | Sphere SDK keypair (npub, nsec) |
| `/etc/letsencrypt/tunnel-identity/wg-private.key` | WireGuard client private key |
| `/etc/letsencrypt/tunnel-identity/wg-public.key` | WireGuard client public key |
| `/tmp/.ssl-tunnel-env` | Sourceable tunnel connection params |
| `/tmp/.ssl-tunnel.pid` | PID of WireGuard monitor process |
| `/tmp/.ssl-tunnel-state` | Current tunnel-manager state (for debugging) |
| `/etc/wireguard/wg0.conf` | WireGuard config (written by tunnel-manager) |

## Appendix B: HAProxy Side Components

| Component | Deployment | Description |
|-----------|------------|-------------|
| `haproxy` | Primary container | HAProxy load balancer (unchanged, Alpine-based) |
| `haproxy-tunnel-daemon` | Sidecar container (`--network container:haproxy`) | Node.js, Sphere SDK, WireGuard management, DTNP negotiation |
| WireGuard server | Inside sidecar | `wg0` interface on 10.200.0.1/24, listens UDP 51820 |
| wstunnel server | Inside sidecar | Listens 127.0.0.1:8443, HAProxy SNI-routes `tunnel.*` here |
| iptables NAT rules | Inside sidecar | Restricted MASQUERADE + FORWARD rules |
| Peer state directory | Shared volume | `/var/lib/haproxy-tunnel/peers/` — per-client WireGuard configs |
| ACL config | Mounted config | `/etc/haproxy-tunnel/acl.json` — domain-scoped authorized client npubs |
| HAProxy runtime API | Shared Unix socket | Sidecar accesses HAProxy via shared `/var/run/haproxy/admin.sock` |
| Monitoring | Inside sidecar | `/v1/tunnels` REST + Prometheus `/metrics` |
