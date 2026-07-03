# DM Tunnel Negotiation Protocol (DTNP) v0.1

## Specification

---

## 1. Protocol Overview

The DM Tunnel Negotiation Protocol (DTNP) enables a containerized service operating behind a firewall to establish a reverse tunnel to a publicly accessible HAProxy instance. All negotiation occurs over Nostr NIP-17 encrypted direct messages using Sphere SDK, meaning neither party needs an inbound-reachable channel for negotiation itself — only the resulting tunnel requires a server-side listener.

Each party is identified by a secp256k1 keypair (Unicity identity). The server's npub is known to the client out-of-band (embedded in the container's environment or run script). The client's npub is registered with the server either at deployment time or dynamically via a signed TUNNEL_REQUEST.

### Design Principles

- **Negotiation is ephemeral.** DMs carry intent and credentials; the tunnel itself runs outside Nostr.
- **Credentials are single-use and time-limited.** Every TUNNEL_OFFER includes an expiry. Unused offers are revoked server-side after expiry.
- **The server drives tunnel type selection.** The client expresses preference order; the server makes the final choice based on its capabilities and policy.
- **DNS is client-owned.** The client manages its own DynDNS credentials and updates. HAProxy never touches DNS credentials — it only reports its public IP so the client knows what A record value to set. The tunnel provides transparent outbound connectivity for the client's DNS API calls.
- **Idempotency via correlation IDs.** Retransmitted messages with the same correlation ID are deduplicated at the receiver.
- **Full bidirectional tunnel.** The tunnel is a VPN (WireGuard), not per-port forwarding. All client traffic routes through the tunnel, making the container behave as if it's on the HAProxy host's network.

### Protocol Versioning

The `version` field in every message is a semver string. The server MUST reject messages with a major version it does not support with a TUNNEL_REJECTED citing `ERR_VERSION_MISMATCH`. Minor version differences are backward-compatible. The server SHOULD include its supported version range in TUNNEL_REJECTED and TUNNEL_OFFER responses.

Current version: `"0.1.0"`

---

## 2. Message Format

Every DTNP message is a JSON object with the following envelope:

```json
{
  "dtnp_version": "0.1.0",
  "msg_type": "<MESSAGE_TYPE>",
  "correlation_id": "<uuid-v4>",
  "sequence": 1,
  "timestamp": "<ISO-8601 UTC>",
  "sender_npub": "<bech32 npub>",
  "payload": { }
}
```

### Envelope Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `dtnp_version` | string | yes | Semver protocol version |
| `msg_type` | string | yes | One of the defined message type constants |
| `correlation_id` | string (UUID v4) | yes | Links requests to responses. The initial TUNNEL_REQUEST generates a fresh UUID; all subsequent messages in that tunnel session reuse the same correlation ID |
| `sequence` | uint64 | yes | Monotonically increasing per sender per correlation session. Resets to 0 on new correlation_id. For **heartbeat** messages: strict ordering — reject if sequence <= last accepted. For **state-transition** messages (REQUEST, OFFER, ACCEPT, ESTABLISHED, TEARDOWN): buffer out-of-order messages for up to 10 seconds before rejecting, to tolerate relay reordering (see Section 4.5) |
| `timestamp` | string (ISO-8601) | yes | UTC timestamp of message creation. Receivers MUST reject messages with a timestamp more than 2 minutes in the past or future |
| `sender_npub` | string | yes | Bech32 npub of the sending party. Receivers MUST verify this matches the NIP-17 decrypted sender key |
| `relay_hints` | string[] | no | Nostr relay URLs the sender is monitoring. Receiver SHOULD publish responses to at least one of these relays |
| `payload` | object | yes | Message-type-specific content (defined below) |

### Event Deduplication

Receivers MUST deduplicate by NIP-17 event ID. If the same NIP-17 event is received from multiple relays, only the first instance is processed. The receiver maintains a set of seen event IDs for the duration of the timestamp window (±2 minutes).

---

## 3. Message Type Specifications

### 3.1 TUNNEL_REQUEST (client → server)

```json
{
  "primary_domain": "app.example.com",
  "domain_aliases": ["www.example.com", "api.example.com"],
  "ports": [
    { "protocol": "http",  "client_port": 80,    "description": "ssl-http-proxy" },
    { "protocol": "https", "client_port": 443,   "description": "app TLS" },
    { "protocol": "https", "client_port": 8444,  "description": "ssl-alias-proxy" },
    { "protocol": "tcp",   "client_port": 50002, "label": "electrum-ssl" }
  ],
  "tunnel_preference": ["wireguard", "ssh-tun"],
  "transport_preference": ["auto", "udp", "wss"],
  "client_wg_pubkey": "<base64-wireguard-public-key>",
  "client_meta": {
    "hostname": "fulcrum-alpha-1",
    "platform": "linux/amd64",
    "ssl_manager_version": "1.2.3",
    "capabilities": ["haproxy-register-api", "sphere-sdk-dm"]
  },
  "ttl_seconds": 86400,
  "idempotency_key": "<uuid-v4>"
}
```

The `idempotency_key` is distinct from `correlation_id`. It represents the client's intent to establish a specific tunnel configuration. If the server has already accepted a request with this idempotency key and the tunnel is still ACTIVE, it MUST return the existing TUNNEL_OFFER rather than creating a duplicate.

The `client_wg_pubkey` is the client's WireGuard public key, generated and persisted locally. The private key never leaves the client.

The `domain_aliases` array lists all alias domains the client needs routed. HAProxy will create backends for the primary domain plus all aliases, all pointing to the client's WireGuard peer IP. No per-alias port allocation is needed — HAProxy routes by domain to the appropriate client port.

The `tunnel_preference` list is ordered from most preferred to least. WireGuard is the primary (full VPN, bidirectional). The server selects the first it supports.

**Note:** There is no `dns_request` field. The client manages its own DNS. HAProxy MUST NOT handle client DNS credentials. The server reports its public IP in the TUNNEL_OFFER so the client knows what A record to set.

### 3.2 TUNNEL_OFFER (server → client)

```json
{
  "tunnel_type": "wireguard",
  "transports": [
    { "type": "udp",       "endpoint": "198.51.100.42:51820" },
    { "type": "wss",       "endpoint": "wss://tunnel.proxy.example.com:443/wg",
                           "sni": "tunnel.proxy.example.com" },
    { "type": "wss-proxy", "endpoint": "wss://tunnel.proxy.example.com:443/wg",
                           "sni": "tunnel.proxy.example.com", "proxy_compatible": true }
  ],
  "auth": {
    "server_wg_pubkey": "base64-wireguard-pubkey",
    "client_ip_alloc": "10.200.0.2/32",
    "server_ip": "10.200.0.1/24",
    "preshared_key_enc": "<base64-encrypted-blob>",
    "allowed_ips": "0.0.0.0/0"
  },
  "haproxy_public_ip": "198.51.100.42",
  "haproxy_api": {
    "host": "10.200.0.1",
    "port": 8404,
    "session_key": "<per-session-bearer-token>"
  },
  "haproxy_backends": [
    { "domain": "app.example.com",     "http_target": "10.200.0.2:80", "https_target": "10.200.0.2:443" },
    { "domain": "www.example.com",     "http_target": "10.200.0.2:80", "https_target": "10.200.0.2:8444" },
    { "domain": "api.example.com",     "http_target": "10.200.0.2:80", "https_target": "10.200.0.2:8444" }
  ],
  "nat_masquerade": true,
  "offer_expires_at": "2026-04-09T13:00:00Z",
  "constraints": {
    "bandwidth_limit_mbps": null,
    "max_connections": 1000,
    "tunnel_ttl_seconds": 86400,
    "heartbeat_interval_seconds": 900,
    "heartbeat_missed_limit": 3
  },
  "server_version": "0.1.0"
}
```

Key fields:

- **`auth.preshared_key_enc`** — Encrypted to the client's npub using **NIP-44** (XChaCha20-Poly1305 AEAD). Single-use, generated per offer. NIP-04 is NOT used — it is deprecated and lacks authentication (no HMAC), making it susceptible to padding oracle attacks.
- **`auth.allowed_ips: "0.0.0.0/0"`** — Routes ALL client traffic through the tunnel, giving the container full bidirectional connectivity through the HAProxy host's network.
- **`haproxy_public_ip`** — The IP the client should use as its DNS A record value. The client updates its own DNS; the server never touches client DNS credentials.
- **`haproxy_api`** — The HAProxy Registration API endpoint, reachable via the WireGuard tunnel IP (10.200.0.1). The `session_key` is a per-tunnel bearer token **scoped to the domains in the original TUNNEL_REQUEST**. The HAProxy API MUST reject operations on domains outside the session key's scope. API calls per session key are rate-limited (10 calls per minute).
- **`haproxy_backends`** — Pre-computed backend routing for primary domain + all aliases. The server uses the client's WireGuard peer IP directly, routing by domain name.
- **`nat_masquerade: true`** — Confirms the server will NAT/masquerade client egress traffic so the container appears to originate from the HAProxy's public IP. This enables transparent DynDNS API calls, certbot ACME validation, and arbitrary outbound connections.

**DNS is client-managed.** There is no `dns_instructions` or `who_updates` field. The client receives `haproxy_public_ip` and updates its own DNS records using its own credentials via the tunnel's outbound connectivity.

### 3.3 TUNNEL_ACCEPT (client → server)

```json
{
  "accepted_tunnel_type": "wireguard",
  "accepted_transport": "wss",
  "ready_at": "2026-04-09T12:05:00Z"
}
```

- **`accepted_transport`** — Which transport from the `transports` array the client will use (`"udp"`, `"wss"`, or `"wss-proxy"`). The server uses this to ensure the appropriate server-side infrastructure is active and to apply transport-specific constraints.
- The client's WireGuard public key was already provided in `TUNNEL_REQUEST.client_wg_pubkey`, so no additional auth material is needed.

### 3.4 TUNNEL_ESTABLISHED (client → server)

```json
{
  "tunnel_up_at": "2026-04-09T12:05:45Z",
  "health_endpoint": "http://10.200.0.2:8080/_ssl/health",
  "measured_rtt_ms": 12,
  "client_tunnel_ip": "10.200.0.2"
}
```

This message is the client's confirmation that it has successfully brought up the tunnel interface and verified connectivity to the server tunnel IP (e.g., a ping to `10.200.0.1`). The server SHOULD verify health via the provided endpoint before considering the tunnel ACTIVE.

### 3.5 TUNNEL_HEARTBEAT (bidirectional)

```json
{
  "direction": "client-to-server",
  "tunnel_status": "healthy",
  "uptime_seconds": 3600,
  "metrics": {
    "rx_bytes": 1048576,
    "tx_bytes": 524288,
    "active_connections": 14,
    "rtt_ms": 11
  },
  "cert_expiry_days": 28,
  "next_heartbeat_in_seconds": 900
}
```

**DM heartbeats are for status reporting, NOT liveness detection.** WireGuard's built-in `PersistentKeepalive` (25s) and the `wg show wg0 latest-handshake` command provide authoritative tunnel liveness signals without any relay traffic. DM heartbeats are sent every 15 minutes (configurable) for status updates and metrics.

The server monitors tunnel liveness via WireGuard handshake timestamps directly (not via DM heartbeats). If a peer's WireGuard handshake is stale for longer than `tunnel_stale_threshold_seconds` (default: 2700 seconds / 45 minutes), the server enters DRAINING state (see Section 4.2). This threshold is independent of the DM heartbeat interval.

**Metrics in heartbeats are optional.** Omitting them reduces metadata leakage on public relays. If privacy is a concern, send heartbeats with `metrics: null`.

### 3.6 TUNNEL_TEARDOWN (either direction)

```json
{
  "initiated_by": "client",
  "reason": "GRACEFUL_SHUTDOWN",
  "cleanup_dns": true,
  "cleanup_haproxy": true,
  "message": "Container stopping, graceful shutdown initiated"
}
```

`reason` is one of: `GRACEFUL_SHUTDOWN`, `TIMEOUT`, `ERROR`, `EVICTION`, `CERTIFICATE_EXPIRY`, `TUNNEL_FAILURE`, `SERVER_MAINTENANCE`. When `cleanup_haproxy` is true, the server MUST deregister all HAProxy backends for this tunnel session and remove the WireGuard peer. DNS cleanup is the client's responsibility — the client should update its own DNS records as part of its shutdown procedure. `cleanup_dns` is advisory: it tells the server whether the client intends to clean up its DNS (informational only, server takes no DNS action).

### 3.7 TUNNEL_REJECTED (server → client)

```json
{
  "reason_code": "ERR_CAPACITY",
  "reason_message": "Server has reached maximum tunnel count",
  "retry_after_seconds": 300,
  "server_supported_versions": ["0.1.0"],
  "server_supported_tunnel_types": ["wireguard", "chisel"]
}
```

Reason codes: `ERR_CAPACITY`, `ERR_ACL_DENIED`, `ERR_DOMAIN_UNAUTHORIZED`, `ERR_DOMAIN_CONFLICT`, `ERR_UNSUPPORTED_TUNNEL`, `ERR_VERSION_MISMATCH`, `ERR_INVALID_CREDENTIALS`, `ERR_RATE_LIMITED`, `ERR_DOMAIN_INVALID`, `ERR_POOL_EXHAUSTED`.

### 3.8 TUNNEL_ERROR (either direction)

```json
{
  "error_code": "ERR_DNS_PROPAGATION_TIMEOUT",
  "error_message": "DNS record for app.example.com not visible after 300s",
  "recoverable": true,
  "suggested_action": "RETRY_DNS"
}
```

`recoverable` signals whether the sender believes the session can continue. If `false`, the receiver SHOULD treat this as equivalent to TUNNEL_TEARDOWN with reason `ERROR`. `suggested_action` is advisory: one of `RETRY_DNS`, `RETRY_TUNNEL`, `WAIT`, `CONTACT_ADMIN`.

### 3.9 TUNNEL_CONFIG_UPDATE (server → client)

```json
{
  "updated_fields": {
    "haproxy_public_ip": "203.0.113.10"
  },
  "reason": "IP_CHANGE",
  "message": "HAProxy public IP changed due to failover"
}
```

A **state-transition message** (buffered for reordering, see Section 4.5). Sent when the server's configuration changes in a way that affects the client (e.g., public IP change, port reallocation). The client MUST update its DNS records and acknowledge by sending a TUNNEL_HEARTBEAT with the updated config reflected. If the client does not acknowledge within 5 minutes, the server MAY send TUNNEL_TEARDOWN.

### 3.10 TUNNEL_MAINTENANCE_NOTICE (server → client)

```json
{
  "maintenance_at": "2026-04-10T02:00:00Z",
  "expected_duration_seconds": 600,
  "action": "TEARDOWN_AND_RECONNECT",
  "message": "Scheduled WireGuard key rotation"
}
```

A **state-transition message**. Advance warning of planned server maintenance. The client can use this to drain connections and prepare for a brief outage. The server will send TUNNEL_TEARDOWN at or after `maintenance_at`. The client should reconnect automatically after the maintenance window. If `maintenance_at` is in the past, the client SHOULD treat this as an immediate teardown notification.

### 3.11 SSH Reverse Tunnel Auth Schema (Lite Mode)

When `tunnel_type` is `"ssh-reverse"` (lite mode), the `auth` field in TUNNEL_OFFER uses this schema instead of the WireGuard schema:

```json
{
  "auth": {
    "ssh_host": "198.51.100.42",
    "ssh_port": 2222,
    "ssh_user": "ssl-tunnel",
    "ssh_host_key_fingerprint": "SHA256:abc123...",
    "forwarded_ports": [
      { "remote_bind": "127.0.0.1:21080", "local_port": 80, "description": "http" },
      { "remote_bind": "127.0.0.1:21443", "local_port": 443, "description": "https" },
      { "remote_bind": "127.0.0.1:21444", "local_port": 8444, "description": "alias-proxy" }
    ]
  }
}
```

The client MUST verify `ssh_host_key_fingerprint` against the SSH handshake. Mismatch MUST abort and send TUNNEL_ERROR. The `transports` array is not applicable for SSH mode (SSH provides its own transport). The client uses `autossh` for automatic reconnection.

---

## 4. State Machine

### 4.1 Client State Machine

```
                         ┌─────────────────────────────────────┐
                         │                                     │
       start             │  TUNNEL_OFFER received              │
         │               │                                     │
         v               │                                     v
      ┌──────┐   send    ┌───────────┐  send ACCEPT  ┌──────────────┐
      │ IDLE │────────►│REQUESTING │──────────────►│  ACCEPTING   │
      └──────┘ TUNNEL_   └───────────┘               └──────────────┘
                REQUEST        │                            │
                               │ TUNNEL_REJECTED            │ TUNNEL_ESTABLISHED
                               │ or timeout (90s)           │ sent
                               v                            v
                            [IDLE]                  ┌──────────────────┐
                                                    │  ESTABLISHING    │
                                                    └──────────────────┘
                                                           │
                                             tunnel up +   │
                                             TUNNEL_       │
                                             ESTABLISHED   v
                                             sent    ┌──────────┐
                                                     │  ACTIVE  │◄──────────────┐
                                                     └──────────┘               │
                                                          │  │                  │
                                             heartbeat    │  │ TUNNEL_HEARTBEAT │
                                             missed /     │  │ received/sent    │
                                             tunnel down  │  └──────────────────┘
                                                          │
                                                          v
                                                  ┌───────────────┐
                                                  │ RECONNECTING  │
                                                  └───────────────┘
                                                          │
                                                ┌─────────┴──────────┐
                                                │                    │
                                         reconnect OK         max retries (3)
                                                │             exceeded
                                                v                    v
                                            [ACTIVE]         ┌──────────────┐
                                                             │ TEARING_DOWN │
                                                             └──────────────┘
                                                                    │
                                                             send TEARDOWN
                                                                    │
                                                                    v
                                                                 [IDLE]
```

### 4.2 Server State Machine

```
       client npub         TUNNEL_REQUEST        TUNNEL_ACCEPT
       known / ACL ok      received              received
         │                     │                     │
         v                     v                     v
      ┌──────┐         ┌──────────────┐      ┌─────────────┐
      │ IDLE │────────►│   OFFERED    │─────►│  ACCEPTING  │
      └──────┘ send    └──────────────┘      └─────────────┘
               OFFER          │                     │
                         offer TTL                  │ TUNNEL_ESTABLISHED
                         expired                    │ received + health verified
                         (180s)                     │
                              │                     │  timeout (180s, no
                              v                     │  ESTABLISHED received)
                           [IDLE]                   │         │
                                                    v         v
                                            ┌──────────┐  [TEARING_DOWN]
                                            │  ACTIVE  │◄──────────┐
                                            └──────────┘           │
                                                 │  │              │
                                    WG handshake │  │ heartbeat    │
                                    stale >45min │  │ exchange     │
                                    or TEARDOWN  │  └──────────────┘
                                    received     │
                                                 v
                                         ┌──────────┐
                                         │ DRAINING │ (120s grace period)
                                         └──────────┘
                                              │  │
                              TUNNEL_REQUEST  │  │ grace period
                              with known      │  │ expired
                              correlation_id  │  │
                                    │         │  │
                                    v         │  v
                            [fast-track      ┌──────────────┐
                             re-negotiate]   │ TEARING_DOWN │
                                             └──────────────┘
                                                    │
                                       cleanup HAProxy + WG peer
                                       revoke credentials
                                       add to tombstone cache (5 min)
                                                    │
                                                    v
                                                 [IDLE]
```

**DRAINING state:** When the server detects tunnel degradation (WireGuard handshake stale beyond threshold), it enters DRAINING for 120 seconds before TEARING_DOWN. During DRAINING, if a TUNNEL_REQUEST arrives with the same correlation_id, the server fast-tracks re-negotiation (skips ACL re-validation, attempts to re-allocate the same peer IP). This accommodates brief outages where the client is reconnecting.

**Tombstone cache:** After TEARING_DOWN completes, the server stores the `correlation_id` in a tombstone cache for 5 minutes. If a message (heartbeat, etc.) arrives for a tombstoned correlation_id, the server responds with TUNNEL_TEARDOWN (reason: `TIMEOUT`) so the client knows the session is dead. If a TUNNEL_REQUEST arrives with a tombstoned correlation_id, the server fast-tracks a new session.

**At-most-one session per client:** The server enforces at most one active session per (client_npub, primary_domain) pair. A new TUNNEL_REQUEST for an existing pair tears down the old session first.

### 4.3 Timeout Reference

| State | Party | Timeout | Action on Expiry |
|-------|-------|---------|------------------|
| REQUESTING | Client | 90 seconds | Retry TUNNEL_REQUEST (max 3), then give up |
| OFFERED | Server | 180 seconds | Revoke offer, free allocated resources, return to IDLE |
| ACCEPTING | Client | 30 seconds | Retry TUNNEL_ACCEPT (max 2), then teardown |
| ACCEPTING | **Server** | **180 seconds** | **Free allocated WG peer/iptables/backends, TEARING_DOWN** |
| ESTABLISHING | Client | 120 seconds | Send TUNNEL_ERROR (recoverable=false) **immediately on wg-quick failure**, teardown |
| ACTIVE | Client | WG handshake stale >3 min | Initiate RECONNECTING |
| ACTIVE | Server | WG handshake stale > `tunnel_stale_threshold_seconds` (default 2700s / 45min) | Enter DRAINING (120s grace) |
| DRAINING | Server | 120 seconds | TEARING_DOWN |
| RECONNECTING | Client | 300 seconds | Send TUNNEL_TEARDOWN, return to IDLE |
| TEARING_DOWN | Both | 30 seconds | Force-close tunnel interface, add to tombstone cache |

**Note:** Server ACTIVE timeout uses WireGuard handshake staleness (checked via `wg show wg0 latest-handshake`), NOT DM heartbeat misses. DM heartbeats are for status reporting only. The 45-minute server threshold is intentionally longer than the client's 3-minute threshold to give the client time to reconnect before the server tears down.

**Note:** OFFERED timeout is 180 seconds (not 60) to accommodate Nostr relay latency. Both sides use the absolute `offer_expires_at` timestamp from TUNNEL_OFFER as the canonical expiry.

### 4.4 Retry Policy

All retries use truncated exponential backoff: wait `min(2^attempt * base_seconds, cap_seconds)` with ±20% jitter.

| Operation | Base (s) | Cap (s) | Max Attempts |
|-----------|----------|---------|--------------|
| TUNNEL_REQUEST | 10 | 120 | 3 |
| TUNNEL_ACCEPT | 5 | 30 | 2 |
| DNS update | 15 | 120 | 4 |
| Reconnection | 10 | 60 | 3 (then teardown) |

### 4.5 Message Ordering and Relay Reordering

Nostr relays do NOT guarantee message ordering. A message sent second may arrive first if delivered via a different relay.

**State-transition messages** (TUNNEL_REQUEST, TUNNEL_OFFER, TUNNEL_ACCEPT, TUNNEL_ESTABLISHED, TUNNEL_TEARDOWN, TUNNEL_CONFIG_UPDATE, TUNNEL_MAINTENANCE_NOTICE) are order-sensitive — processing them out of order can skip or break state transitions. Rule: if a state-transition message arrives with a sequence number higher than expected, the receiver MUST buffer it for up to **10 seconds** waiting for the missing message(s). If the gap is not filled within 10 seconds, process the buffered message and discard the missing one (it will be rejected if it arrives later due to sequence enforcement).

**Heartbeat messages** are NOT order-sensitive. Strict sequence enforcement applies — out-of-order heartbeats are silently dropped. This is safe because heartbeats are periodic and losing one is tolerable.

**Idempotency rule:** The server enforces at-most-one active session per `(client_npub, primary_domain)` pair. If a new TUNNEL_REQUEST arrives for a pair that already has a session in any non-IDLE state, the server tears down the old session first. The client MUST ignore TUNNEL_OFFERs whose correlation_id does not match its current pending request.

---

## 5. Sequence Diagrams

### 5.1 Happy Path (WireGuard + Client-Managed DNS)

```
Client                          Nostr Relay                     Server (HAProxy)
  │                                  │                                │
  │──TUNNEL_REQUEST─────────────────►│──────────────────────────────►│
  │  (primary_domain, aliases,       │                                │
  │   ports, client_wg_pubkey)       │                                │
  │                                  │                                │ validate ACL,
  │                                  │                                │ allocate WG peer IP,
  │                                  │                                │ generate preshared key,
  │                                  │                                │ configure HAProxy backends
  │◄─────────────────────────────────│◄──────TUNNEL_OFFER────────────│
  │  (wg endpoint, server pubkey,    │                                │
  │   client IP, preshared key enc,  │                                │
  │   haproxy_public_ip, api creds)  │                                │
  │                                  │                                │
  │ [write wg0.conf]                 │                                │
  │                                  │                                │
  │──TUNNEL_ACCEPT──────────────────►│──────────────────────────────►│
  │                                  │                                │ [add WG peer,
  │                                  │                                │  configure iptables NAT,
  │                                  │                                │  configure HAProxy backends]
  │ [wg-quick up wg0]               │                                │
  │ [ping 10.200.0.1 ✓]             │                                │
  │                                  │                                │
  │──TUNNEL_ESTABLISHED─────────────►│──────────────────────────────►│
  │  (health_endpoint, rtt_ms)       │                                │ [verify health via WG IP,
  │                                  │                                │  session = ACTIVE]
  │                                  │                                │
  │ [CLIENT updates own DNS:]        │                                │
  │ [curl DynDNS API via wg0→NAT]   │                                │
  │ [A record → haproxy_public_ip]   │                                │
  │                                  │                                │
  │ [ssl-setup proceeds normally:]   │                                │
  │ [nonce verify, certbot, etc.]    │                                │
  │ [all traffic via WG tunnel]      │                                │
  │                                  │                                │
  │──TUNNEL_HEARTBEAT───────────────►│──────────────────────────────►│
  │◄─────────────────────────────────│◄──TUNNEL_HEARTBEAT────────────│
  │  (every 15min, status only)      │                                │
  │  (WG keepalive every 25s for     │                                │
  │   tunnel liveness — no DMs)      │                                │
```

### 5.2 Reconnection Scenario

```
Client                                                          Server
  │                                                               │
  │  [WireGuard tunnel drops — network disruption]                │
  │                                                               │
  │  [WG handshake stale >3min]                                   │
  │  [enter RECONNECTING]                                         │
  │  [add random jitter 0-60s]                                    │
  │                                                               │  [WG handshake stale >45min]
  │                                                               │  [enter DRAINING (120s grace)]
  │                                                               │
  │──TUNNEL_REQUEST (same correlation_id, same idempotency_key)──►│
  │                                                               │ [in DRAINING: fast-track,
  │                                                               │  reuse peer IP, fresh credentials]
  │◄────────────────────────TUNNEL_OFFER (refreshed credentials)──│
  │                                                               │
  │──TUNNEL_ACCEPT────────────────────────────────────────────────►│
  │──TUNNEL_ESTABLISHED───────────────────────────────────────────►│
  │                                                               │ [cancel DRAINING → ACTIVE]
```

**Brief outage recovery (no DM needed):**
```
Client                                                          Server
  │                                                               │
  │  [WG handshake stale 30s — brief network glitch]              │
  │  [WireGuard auto-recovers via PersistentKeepalive]            │
  │  [handshake refreshed]                                        │
  │                                                               │
  │──TUNNEL_HEARTBEAT (immediate, cancel any pending teardown)───►│
  │                                                               │ [heartbeat received,
  │                                                               │  cancel DRAINING if active]
```

### 5.3 Rejection and Graceful Teardown

```
Client                                                          Server
  │                                                               │
  │──TUNNEL_REQUEST──────────────────────────────────────────────►│
  │                                                               │ [domain conflict]
  │◄─────────────────────────────TUNNEL_REJECTED──────────────────│
  │  (ERR_DOMAIN_CONFLICT, retry_after_seconds: 0)                │
  │                                                               │
  │  [user resolves conflict, retries]                            │
  ...
  │  [tunnel ACTIVE, container receives SIGTERM]                  │
  │                                                               │
  │──TUNNEL_TEARDOWN──────────────────────────────────────────────►│
  │  (GRACEFUL_SHUTDOWN, cleanup_dns: true,                       │ [remove WireGuard peer,
  │   cleanup_haproxy: true)                                      │  deregister HAProxy backends,
  │                                                               │  remove iptables NAT rules]
  │  [client updates own DNS if needed]                           │
  │  [wg-quick down wg0, exit]                                    │
```

---

## 6. Security Model

### 6.1 Identity and Authentication

Every message is NIP-17 gift-wrapped: the inner event is signed by the sender's secp256k1 key and encrypted to the recipient's key. The `sender_npub` field in the envelope MUST match the decrypted inner event's `pubkey`. Any mismatch MUST be treated as a forgery and silently dropped.

The server maintains a **domain-scoped ACL** of authorized client npubs. Each entry binds a client npub to specific domain patterns (e.g., `["mydomain.com", "*.mydomain.com"]`). Domain binding is **mandatory** — a client cannot request domains outside its authorized scope. A TUNNEL_REQUEST from an unknown npub is rejected with `ERR_ACL_DENIED`. A TUNNEL_REQUEST for a domain outside the client's scope is rejected with `ERR_DOMAIN_UNAUTHORIZED`.

### 6.2 Replay Prevention

Three layers of replay prevention:

1. **NIP-17 event ID deduplication:** Receivers deduplicate by NIP-17 event ID. Same event received from multiple relays is processed only once (see Section 2).
2. **Session-scoped sequence numbers:** `correlation_id` + `sequence` prevents replay within a session (see Section 4.5 for ordering rules).
3. **Timestamp window:** ±2-minute tolerance prevents cross-session replays of old messages.

`idempotency_key` prevents duplicate tunnel creation if a TUNNEL_REQUEST is retransmitted after a delayed TUNNEL_OFFER. Scoped to `(client_npub, primary_domain)`: a new idempotency_key for the same pair supersedes any previous one. If the server receives a retried idempotency_key while in OFFERED state, it MUST revoke the old offer (invalidate old preshared key), generate fresh credentials, and send a new TUNNEL_OFFER.

### 6.3 Credential Handling

Tunnel credentials (WireGuard preshared keys) are single-use and generated fresh per TUNNEL_OFFER. They are encrypted to the recipient's npub using **NIP-44** (XChaCha20-Poly1305 AEAD) before inclusion in the JSON payload, providing authenticated inner encryption. The outer NIP-17 gift wrap provides a second encryption layer. NIP-04 is NOT used — it lacks authentication and is deprecated.

The server MUST NOT log or persist credentials in plaintext. After tunnel teardown, the server MUST delete any credential material associated with the `correlation_id`.

**DNS credentials are never part of DTNP.** The client manages its own DNS using its own credentials via the tunnel's outbound connectivity. The server never sees, stores, or handles DNS credentials.

### 6.4 Tunnel Transport Security

The tunnel transport itself (WireGuard, SSH, chisel) provides its own cryptographic layer independent of the negotiation channel. WireGuard is preferred because it provides mutual authentication, perfect forward secrecy, and has a minimal attack surface. The negotiation protocol establishes the WireGuard peers' public keys via the encrypted DM channel, eliminating the need for an out-of-band key exchange.

For SSH-based tunnels, the client MUST verify the server's host key fingerprint (provided in TUNNEL_OFFER's `auth` field) against what the SSH handshake presents. Mismatch MUST abort the tunnel and send TUNNEL_ERROR.

---

## 7. DNS Model

### Principle: Client Owns DNS

**The server (HAProxy) MUST NOT manage, store, or handle client DNS credentials.** DNS is entirely the client's responsibility. The server's only DNS-related role is reporting its own public IP in `TUNNEL_OFFER.haproxy_public_ip`.

### How DNS Works with the Tunnel

1. Client receives `TUNNEL_OFFER` containing `haproxy_public_ip` (e.g., `198.51.100.42`).
2. Client updates its own DNS using its own credentials. Because the WireGuard tunnel provides full bidirectional connectivity with NAT masquerade, the client's outbound API calls to its DNS provider route transparently through the tunnel and appear to originate from the HAProxy host's IP.
3. For all domains (primary + aliases), the client sets A records pointing to `haproxy_public_ip`.
4. Client waits for DNS propagation, then ssl-setup proceeds with nonce verification.
5. On teardown, the client is responsible for cleaning up its own DNS records.

### No DNS Messages in DTNP

There are no `TUNNEL_DNS_REQUEST` or `TUNNEL_DNS_RESPONSE` message types. The protocol does not include DNS operations — they are handled entirely by the client through standard outbound internet connectivity provided by the tunnel.

---

## 8. Extensibility Considerations

### 8.1 Payload Evolution

Unknown fields in `payload` MUST be ignored by receivers. This allows new fields to be added without breaking existing implementations. Removing fields or changing their semantics requires a major version bump.

### 8.2 Tunnel Type Registry

The `tunnel_preference` array is an open enumeration. Implementations MUST reject unknown tunnel types gracefully (list them in `supported_tunnel_types` in TUNNEL_REJECTED). New tunnel types (e.g., `"cloudflare-tunnel"`, `"ngrok"`) can be added as minor version increments if they introduce new `auth` schema shapes.

### 8.3 Capability Negotiation

The `client_meta.capabilities` array in TUNNEL_REQUEST enables future capability negotiation without version bumps. Servers can gate features (e.g., bandwidth metering, multi-domain batch requests) on declared capabilities.

### 8.4 Sub-Protocol Extensions

Future extensions (e.g., certificate lifecycle management over DM, configuration push from server to client) can be added as new `msg_type` values with a `dtnp_extension` prefix (e.g., `"dtnp_extension.cert_renewal_notify"`). Receivers that do not recognize an extension message type MUST send TUNNEL_ERROR with `ERR_UNKNOWN_MESSAGE_TYPE` and `recoverable: true`.

### 8.5 Multi-Server Federation

A future extension could allow servers to forward TUNNEL_REQUEST to peer servers when at capacity, returning a TUNNEL_OFFER on behalf of the peer. This would be signaled by an `offered_by_npub` field in TUNNEL_OFFER distinct from the original server's npub.

---

## 9. Error Codes Reference

| Code | Direction | Meaning |
|------|-----------|---------|
| `ERR_VERSION_MISMATCH` | S→C | Client version not supported |
| `ERR_ACL_DENIED` | S→C | Client npub not on allowlist |
| `ERR_DOMAIN_UNAUTHORIZED` | S→C | Domain outside client's ACL-bound scope |
| `ERR_DOMAIN_CONFLICT` | S→C | Domain already registered to another client |
| `ERR_DOMAIN_INVALID` | S→C | Domain fails format or policy validation (blocklist, invalid FQDN) |
| `ERR_CAPACITY` | S→C | Server at tunnel limit |
| `ERR_POOL_EXHAUSTED` | S→C | WireGuard IP pool exhausted (all peer IPs allocated) |
| `ERR_UNSUPPORTED_TUNNEL` | S→C | No common tunnel type found |
| `ERR_RATE_LIMITED` | S→C | Too many requests from this client |
| `ERR_INVALID_CREDENTIALS` | S→C | WireGuard credentials malformed or cannot be decrypted |
| `ERR_TUNNEL_HEALTH_FAILED` | S→C | Health endpoint unreachable after ESTABLISHED |
| `ERR_UNKNOWN_MESSAGE_TYPE` | Both | Unrecognized extension msg_type |
| `ERR_SEQUENCE_REPLAY` | Both | Sequence number below expected |
| `ERR_TIMESTAMP_SKEW` | Both | Timestamp outside ±2 minute window |
| `ERR_SIGNATURE_MISMATCH` | Both | sender_npub does not match NIP-17 inner pubkey |
| `ERR_SESSION_CONFLICT` | S→C | Client already has an active session for this domain |
| `ERR_CONFIG_UPDATE_FAILED` | C→S | Client could not apply configuration update |
