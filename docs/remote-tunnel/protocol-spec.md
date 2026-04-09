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
| `sequence` | integer | yes | Monotonically increasing per sender per correlation session. Receivers MUST reject messages with a sequence number less than or equal to the last accepted sequence (replay prevention) |
| `timestamp` | string (ISO-8601) | yes | UTC timestamp of message creation. Receivers MUST reject messages with a timestamp more than 5 minutes in the past or future |
| `sender_npub` | string | yes | Bech32 npub of the sending party. Receivers MUST verify this matches the NIP-17 decrypted sender key |
| `payload` | object | yes | Message-type-specific content (defined below) |

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
  "endpoint": {
    "host": "198.51.100.42",
    "port": 51820
  },
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
    "heartbeat_interval_seconds": 30,
    "heartbeat_missed_limit": 3
  },
  "server_version": "0.1.0"
}
```

Key fields:

- **`auth.preshared_key_enc`** — Encrypted to the client's npub using NIP-04. Single-use, generated per offer.
- **`auth.allowed_ips: "0.0.0.0/0"`** — Routes ALL client traffic through the tunnel, giving the container full bidirectional connectivity through the HAProxy host's network.
- **`haproxy_public_ip`** — The IP the client should use as its DNS A record value. The client updates its own DNS; the server never touches client DNS credentials.
- **`haproxy_api`** — The HAProxy Registration API endpoint, reachable via the WireGuard tunnel IP (10.200.0.1). The `session_key` is a per-tunnel bearer token.
- **`haproxy_backends`** — Pre-computed backend routing for primary domain + all aliases. The server uses the client's WireGuard peer IP directly, routing by domain name.
- **`nat_masquerade: true`** — Confirms the server will NAT/masquerade client egress traffic so the container appears to originate from the HAProxy's public IP. This enables transparent DynDNS API calls, certbot ACME validation, and arbitrary outbound connections.

**DNS is client-managed.** There is no `dns_instructions` or `who_updates` field. The client receives `haproxy_public_ip` and updates its own DNS records using its own credentials via the tunnel's outbound connectivity.

### 3.3 TUNNEL_ACCEPT (client → server)

```json
{
  "accepted_tunnel_type": "wireguard",
  "ready_at": "2026-04-09T12:05:00Z"
}
```

The client's WireGuard public key was already provided in `TUNNEL_REQUEST.client_wg_pubkey`, so no additional auth material is needed in the accept message. This message confirms the client will use the offered tunnel parameters and is about to bring up its WireGuard interface.

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
  "next_heartbeat_in_seconds": 30
}
```

Either party may send TUNNEL_HEARTBEAT. If the server misses `heartbeat_missed_limit` consecutive heartbeats from the client, it MUST send TUNNEL_TEARDOWN with reason `TIMEOUT`. The client tracks server heartbeats and initiates RECONNECTING if the server side goes silent.

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

Reason codes: `ERR_CAPACITY`, `ERR_ACL_DENIED`, `ERR_DOMAIN_CONFLICT`, `ERR_UNSUPPORTED_TUNNEL`, `ERR_VERSION_MISMATCH`, `ERR_INVALID_CREDENTIALS`, `ERR_RATE_LIMITED`, `ERR_DOMAIN_INVALID`.

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
                         expired (60s)              │ received +
                              │                     │ health verified
                              v                     v
                           [IDLE]           ┌──────────────────┐
                                            │     ACTIVE       │◄─────────┐
                                            └──────────────────┘          │
                                                     │  │                 │
                                        heartbeat    │  │ heartbeat       │
                                        missed x3    │  │ exchange        │
                                        or TEARDOWN  │  └─────────────────┘
                                        received     │
                                                     v
                                             ┌──────────────┐
                                             │ TEARING_DOWN │
                                             └──────────────┘
                                                     │
                                        cleanup DNS + HAProxy
                                        revoke credentials
                                                     │
                                                     v
                                                  [IDLE]
```

### 4.3 Timeout Reference

| State | Party | Timeout | Action on Expiry |
|-------|-------|---------|------------------|
| REQUESTING | Client | 90 seconds | Retry TUNNEL_REQUEST (max 3), then give up |
| OFFERED | Server | 60 seconds | Revoke offer, return to IDLE |
| ACCEPTING | Client | 30 seconds | Retry TUNNEL_ACCEPT (max 2), then teardown |
| ESTABLISHING | Client | 120 seconds | Send TUNNEL_ERROR (recoverable=false), teardown |
| ACTIVE | Both | 3 x heartbeat interval | Initiate RECONNECTING (client) or TEARING_DOWN (server) |
| RECONNECTING | Client | 300 seconds | Send TUNNEL_TEARDOWN, return to IDLE |
| TEARING_DOWN | Both | 30 seconds | Force-close tunnel interface |

### 4.4 Retry Policy

All retries use truncated exponential backoff: wait `min(2^attempt * base_seconds, cap_seconds)` with ±20% jitter.

| Operation | Base (s) | Cap (s) | Max Attempts |
|-----------|----------|---------|--------------|
| TUNNEL_REQUEST | 10 | 120 | 3 |
| TUNNEL_ACCEPT | 5 | 30 | 2 |
| DNS update | 15 | 120 | 4 |
| Reconnection | 10 | 60 | 3 (then teardown) |

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
  │  (every 30s, bidirectional)      │                                │
```

### 5.3 Reconnection Scenario

```
Client                                                          Server
  │                                                               │
  │  [SSH tunnel drops — network disruption]                      │
  │                                                               │
  │  [missed heartbeat 1]                                         │
  │  [missed heartbeat 2]                                         │
  │  [missed heartbeat 3]                                         │
  │  [enter RECONNECTING]                                         │  [3 missed HBs → TEARING_DOWN]
  │                                                               │
  │──TUNNEL_REQUEST (same correlation_id, same idempotency_key)──►│
  │                                                               │ [correlation_id known,
  │                                                               │  reuse session, issue new offer]
  │◄────────────────────────TUNNEL_OFFER (refreshed credentials)──│
  │                                                               │
  │──TUNNEL_ACCEPT────────────────────────────────────────────────►│
  │──TUNNEL_ESTABLISHED───────────────────────────────────────────►│
  │                                                               │ [session → ACTIVE]
```

### 5.4 Rejection and Graceful Teardown

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

The server maintains an allowlist of authorized client npubs. A TUNNEL_REQUEST from an unknown npub is rejected with `ERR_ACL_DENIED`. The allowlist entry may optionally constrain which domains and ports a given client may request.

### 6.2 Replay Prevention

The combination of `correlation_id` + `sequence` prevents replay attacks within a session. The server maintains a per-correlation-id sequence counter and discards any message where `sequence <= last_seen_sequence`. The `timestamp` ±5-minute window prevents cross-session replays of old valid messages.

`idempotency_key` prevents duplicate tunnel creation if a TUNNEL_REQUEST is retransmitted after a delayed TUNNEL_OFFER. The server MUST store `idempotency_key → haproxy_backend_id` for the duration of the tunnel's configured TTL.

### 6.3 Credential Handling

Tunnel credentials (WireGuard preshared keys) are single-use and generated fresh per TUNNEL_OFFER. They are encrypted to the recipient's npub using NIP-04 before inclusion in the JSON payload, meaning they are doubly encrypted: once by NIP-04 for the credential blob, and again by NIP-17 for the message envelope.

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
| `ERR_DOMAIN_CONFLICT` | S→C | Domain already registered to another backend |
| `ERR_DOMAIN_INVALID` | S→C | Domain fails format or policy validation |
| `ERR_CAPACITY` | S→C | Server at tunnel limit |
| `ERR_UNSUPPORTED_TUNNEL` | S→C | No common tunnel type found |
| `ERR_RATE_LIMITED` | S→C | Too many requests from this client |
| `ERR_INVALID_CREDENTIALS` | S→C | WireGuard credentials malformed or cannot be decrypted |
| `ERR_TUNNEL_HEALTH_FAILED` | S→C | Health endpoint unreachable after ESTABLISHED |
| `ERR_UNKNOWN_MESSAGE_TYPE` | Both | Unrecognized extension msg_type |
| `ERR_SEQUENCE_REPLAY` | Both | Sequence number below expected |
| `ERR_TIMESTAMP_SKEW` | Both | Timestamp outside ±5 minute window |
| `ERR_SIGNATURE_MISMATCH` | Both | sender_npub does not match NIP-17 inner pubkey |
