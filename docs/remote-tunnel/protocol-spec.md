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
- **DNS is a side-channel.** DNS operations are handled as a sub-protocol within DTNP, not as a separate system.
- **Idempotency via correlation IDs.** Retransmitted messages with the same correlation ID are deduplicated at the receiver.

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
  "domains": ["app.example.com", "www.example.com"],
  "ports": [
    { "protocol": "http",  "server_port": 80,   "client_port": 8080 },
    { "protocol": "https", "server_port": 443,  "client_port": 8443 },
    { "protocol": "tcp",   "server_port": 50002,"client_port": 50002, "label": "electrum" }
  ],
  "tunnel_preference": ["wireguard", "chisel", "ssh"],
  "client_meta": {
    "hostname": "fulcrum-alpha-1",
    "platform": "linux/amd64",
    "ssl_manager_version": "1.2.3",
    "capabilities": ["haproxy-register-api", "nip17-dm"]
  },
  "dns_request": {
    "provider": "cloudflare",
    "zone_id": "abc123",
    "auto_cleanup": true,
    "credentials_enc": "<base64-encrypted-blob>"
  },
  "ttl_seconds": 86400,
  "idempotency_key": "<uuid-v4>"
}
```

The `idempotency_key` is distinct from `correlation_id`. It represents the client's intent to establish a specific tunnel configuration. If the server has already accepted a request with this idempotency key and the tunnel is still ACTIVE, it MUST return the existing TUNNEL_OFFER rather than creating a duplicate.

The `credentials_enc` field contains DynDNS provider credentials encrypted to the server's npub using NIP-04 (single-recipient encryption). This allows the server to perform DNS operations on the client's behalf without the credentials appearing in plaintext anywhere in the message chain.

The `tunnel_preference` list is ordered from most preferred to least. The server will select the first entry it supports.

### 3.2 TUNNEL_OFFER (server → client)

```json
{
  "tunnel_type": "wireguard",
  "endpoint": {
    "host": "198.51.100.42",
    "port": 51820
  },
  "auth": {
    "server_pubkey_wg": "base64-wireguard-pubkey",
    "client_ip_alloc": "10.200.0.2/32",
    "server_ip": "10.200.0.1",
    "preshared_key_enc": "<base64-encrypted-blob>",
    "allowed_ips": ["10.200.0.1/32"]
  },
  "port_mappings": [
    { "protocol": "http",  "server_port": 80,   "tunnel_dst_port": 8080 },
    { "protocol": "https", "server_port": 443,  "tunnel_dst_port": 8443 },
    { "protocol": "tcp",   "server_port": 50002,"tunnel_dst_port": 50002 }
  ],
  "dns_instructions": {
    "records_to_create": [
      { "type": "A", "name": "app.example.com", "value": "198.51.100.42", "ttl": 300 }
    ],
    "who_updates": "server",
    "estimated_propagation_seconds": 60
  },
  "haproxy_backend_id": "fulcrum-alpha-1-20260409T120000Z",
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

The `auth.preshared_key_enc` blob is encrypted to the client's npub using NIP-04. For SSH-based tunnels, `auth` would instead contain `authorized_key` (server's host key fingerprint) and `reverse_port` (the port on the SSH server that will be forwarded). The `auth` schema is polymorphic based on `tunnel_type`.

#### SSH Auth Schema

```json
{
  "auth": {
    "host_key_fingerprint": "SHA256:abc123...",
    "tunnel_user": "ssl-tunnel",
    "ssh_port": 2222,
    "reverse_forwards": [
      { "remote_bind": "127.0.0.1:21080", "description": "http" },
      { "remote_bind": "127.0.0.1:21443", "description": "https" }
    ]
  }
}
```

`who_updates` in `dns_instructions` is either `"server"` (server will call the DNS API using the credentials the client supplied) or `"client"` (server provides records and the client updates DNS directly). The default is `"server"` when credentials were provided in TUNNEL_REQUEST.

### 3.3 TUNNEL_ACCEPT (client → server)

```json
{
  "accepted_tunnel_type": "wireguard",
  "client_wg_pubkey": "base64-wireguard-client-pubkey",
  "client_wg_listen_port": 0,
  "ready_at": "2026-04-09T12:05:00Z"
}
```

For SSH tunnels, this instead carries the client's SSH public key. For chisel, it carries no additional auth material (chisel uses TLS with a pre-shared key from the offer). The field names are prefixed by tunnel type (`client_wg_pubkey`, `client_ssh_pubkey`, etc.).

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

### 3.6 TUNNEL_DNS_REQUEST (client → server)

```json
{
  "operation": "UPDATE",
  "records": [
    { "type": "A", "name": "app.example.com", "value": "198.51.100.42", "ttl": 300 }
  ],
  "provider": "cloudflare",
  "zone_id": "abc123",
  "credentials_enc": "<base64-encrypted-blob>"
}
```

`operation` is one of `CREATE`, `UPDATE`, `DELETE`. The client may send this independently of tunnel negotiation to update DNS records when its tunnel IP changes or when renewing. If credentials were already provided in TUNNEL_REQUEST, the `credentials_enc` field MAY be omitted and the server reuses cached credentials (stored encrypted, keyed to `correlation_id`).

### 3.7 TUNNEL_DNS_RESPONSE (server → client)

```json
{
  "operation": "UPDATE",
  "status": "success",
  "records_applied": [
    { "type": "A", "name": "app.example.com", "value": "198.51.100.42", "ttl": 300, "provider_record_id": "xyz789" }
  ],
  "error": null
}
```

On failure, `status` is `"error"` and `error` is a structured object `{ "code": "ERR_DNS_AUTH_FAILED", "message": "..." }`.

### 3.8 TUNNEL_TEARDOWN (either direction)

```json
{
  "initiated_by": "client",
  "reason": "GRACEFUL_SHUTDOWN",
  "cleanup_dns": true,
  "cleanup_haproxy": true,
  "message": "Container stopping, graceful shutdown initiated"
}
```

`reason` is one of: `GRACEFUL_SHUTDOWN`, `TIMEOUT`, `ERROR`, `EVICTION`, `CERTIFICATE_EXPIRY`, `TUNNEL_FAILURE`, `SERVER_MAINTENANCE`. When `cleanup_dns` is true, the server MUST delete all DNS records created for this tunnel session. When `cleanup_haproxy` is true, the server MUST deregister the backend from HAProxy.

### 3.9 TUNNEL_REJECTED (server → client)

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

### 3.10 TUNNEL_ERROR (either direction)

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

### 5.1 Happy Path (WireGuard + Cloudflare DNS)

```
Client                          Nostr Relay                     Server (HAProxy)
  │                                  │                                │
  │──TUNNEL_REQUEST─────────────────►│──────────────────────────────►│
  │  (domains, ports, wg pref,       │                                │
  │   dns creds encrypted to server) │                                │
  │                                  │                                │ validate ACL,
  │                                  │                                │ allocate WG peer,
  │                                  │                                │ generate credentials
  │◄─────────────────────────────────│◄──────TUNNEL_OFFER────────────│
  │  (wg endpoint, server pubkey,    │                                │
  │   preshared key enc to client,   │                                │
  │   dns_instructions)              │                                │
  │                                  │                                │
  │ [configure wg interface]         │                                │
  │                                  │                                │
  │──TUNNEL_ACCEPT──────────────────►│──────────────────────────────►│
  │  (client_wg_pubkey)              │                                │ [add peer to wg,
  │                                  │                                │  update HAProxy backend,
  │                                  │                                │  call Cloudflare DNS API]
  │ [bring wg up, ping 10.200.0.1]  │                                │
  │                                  │                                │
  │──TUNNEL_ESTABLISHED─────────────►│──────────────────────────────►│
  │  (health_endpoint, rtt_ms)       │                                │ [verify health endpoint,
  │                                  │                                │  update HAProxy backend HTTPS,
  │                                  │                                │  session = ACTIVE]
  │◄─────────────────────────────────│◄──TUNNEL_HEARTBEAT (initial)──│
  │                                  │                                │
  │──TUNNEL_HEARTBEAT───────────────►│──────────────────────────────►│
  │  (every 30s, bidirectional)      │                                │
```

### 5.2 Happy Path (SSH + Server-Managed DNS)

```
Client                          Nostr Relay                     Server (HAProxy)
  │                                  │                                │
  │──TUNNEL_REQUEST─────────────────►│──────────────────────────────►│
  │  (domains, ports, ssh pref,      │                                │
  │   client_ssh_pubkey)             │                                │
  │                                  │                                │ validate ACL,
  │                                  │                                │ allocate loopback ports,
  │                                  │                                │ add SSH authorized_key
  │◄─────────────────────────────────│◄──────TUNNEL_OFFER────────────│
  │  (ssh endpoint, host_key_fp,     │                                │
  │   reverse_forwards, dns_action:  │                                │
  │   managed, dns_target: pub_ip)   │                                │
  │                                  │                                │
  │──TUNNEL_ACCEPT──────────────────►│──────────────────────────────►│
  │                                  │                                │ [update DNS A record,
  │                                  │                                │  configure HAProxy HTTP backend]
  │ [verify host key fingerprint]    │                                │
  │ [autossh -R 127.0.0.1:21080:... ]│                                │
  │ [autossh -R 127.0.0.1:21443:... ]│                                │
  │                                  │                                │
  │──TUNNEL_ESTABLISHED─────────────►│──────────────────────────────►│
  │                                  │                                │ [health check, ACTIVE]
  │                                  │                                │
  │  ... ssl-setup proceeds normally ...                              │
  │  ... certbot HTTP-01 via tunnel ...                               │
  │  ... re-register with HTTPS ...                                   │
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
  │  (GRACEFUL_SHUTDOWN, cleanup_dns: true,                       │ [delete DNS record,
  │   cleanup_haproxy: true)                                      │  deregister HAProxy backend,
  │                                                               │  revoke tunnel credentials]
  │  [kill tunnel process, exit]                                  │
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

Tunnel credentials (WireGuard preshared keys, SSH keys) are single-use and generated fresh per TUNNEL_OFFER. They are encrypted to the recipient's npub using NIP-04 before inclusion in the JSON payload, meaning they are doubly encrypted: once by NIP-04 for the credential blob, and again by NIP-17 for the message envelope.

DynDNS credentials follow the same pattern. The server MUST NOT log or persist credentials in plaintext. After tunnel teardown, the server MUST delete any in-memory credential cache associated with the `correlation_id`.

### 6.4 Tunnel Transport Security

The tunnel transport itself (WireGuard, SSH, chisel) provides its own cryptographic layer independent of the negotiation channel. WireGuard is preferred because it provides mutual authentication, perfect forward secrecy, and has a minimal attack surface. The negotiation protocol establishes the WireGuard peers' public keys via the encrypted DM channel, eliminating the need for an out-of-band key exchange.

For SSH-based tunnels, the client MUST verify the server's host key fingerprint (provided in TUNNEL_OFFER's `auth` field) against what the SSH handshake presents. Mismatch MUST abort the tunnel and send TUNNEL_ERROR.

---

## 7. DNS Integration Protocol

### 7.1 Credential Flow

1. Client encrypts DynDNS API credentials to the server's npub using NIP-04 and includes the ciphertext in `TUNNEL_REQUEST.dns_request.credentials_enc`.
2. Server decrypts credentials in memory and stores them associated with the session's `correlation_id`.
3. Server performs DNS API calls directly (Cloudflare, Route53, etc.) using these credentials. The client never exposes them on a network path other than the encrypted DM.
4. The server includes `who_updates: "server"` in TUNNEL_OFFER, confirming it has accepted responsibility for DNS.
5. On TUNNEL_TEARDOWN with `cleanup_dns: true`, the server calls the DNS provider to delete records, then zeroes out the credential cache.

### 7.2 DNS Provider Abstraction

The `provider` field in `TUNNEL_DNS_REQUEST` identifies the DNS provider by a short string (`cloudflare`, `route53`, `digitalocean`, `namecheap`, `duckdns`, etc.). The server implements a provider adapter for each supported string. If the client specifies an unsupported provider, the server returns `ERR_UNSUPPORTED_TUNNEL` in TUNNEL_REJECTED with a `supported_dns_providers` list.

If no `dns_request` is included in TUNNEL_REQUEST, the server assumes the client will manage DNS out-of-band and sets `who_updates: "client"` in TUNNEL_OFFER, including the records the client should create.

### 7.3 Propagation and Verification

After creating DNS records, the server sends TUNNEL_OFFER. The `dns_instructions.estimated_propagation_seconds` field tells the client how long to wait before expecting domain-based verification to succeed. The client MUST wait at least this long before running ssl-setup's nonce-based HTTP reachability check.

If DNS propagation fails within 2x the estimated time, the client sends TUNNEL_DNS_REQUEST with `operation: UPDATE` to force a re-apply. The server acknowledges with TUNNEL_DNS_RESPONSE. After 3 failed DNS operations, the client sends TUNNEL_ERROR with `ERR_DNS_PROPAGATION_TIMEOUT` and `recoverable: false`.

### 7.4 Cleanup Semantics

On any TUNNEL_TEARDOWN (graceful or otherwise), the server evaluates `cleanup_dns`. If `true`, records are deleted. If the teardown is server-initiated (timeout, eviction), the server SHOULD attempt cleanup regardless and send a TUNNEL_TEARDOWN to notify the client. If the DNS API call fails during cleanup, the server MUST log this and MAY retry asynchronously up to 3 times.

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
| `ERR_INVALID_CREDENTIALS` | S→C | Credentials malformed or cannot be decrypted |
| `ERR_DNS_AUTH_FAILED` | S→C | DNS provider credentials rejected |
| `ERR_DNS_PROPAGATION_TIMEOUT` | C→S | DNS not visible after max wait |
| `ERR_TUNNEL_HEALTH_FAILED` | S→C | Health endpoint unreachable after ESTABLISHED |
| `ERR_UNKNOWN_MESSAGE_TYPE` | Both | Unrecognized extension msg_type |
| `ERR_SEQUENCE_REPLAY` | Both | Sequence number below expected |
| `ERR_TIMESTAMP_SKEW` | Both | Timestamp outside ±5 minute window |
| `ERR_SIGNATURE_MISMATCH` | Both | sender_npub does not match NIP-17 inner pubkey |
