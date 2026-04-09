# Secure Firewall-Traversal Tunneling: Comparative Analysis

## Executive Summary

For a containerized service behind a firewall that needs to establish client-initiated tunnels to a remote HAProxy server, we evaluated 10 major tunneling approaches.

**Recommendation Hierarchy:**
1. **Primary: WireGuard** — full bidirectional VPN, modern crypto, kernel-level performance
2. **Alternative 1: SSH tun device (`ssh -w`)** — fallback for older kernels without WireGuard
3. **Alternative 2: rathole / frp** — when both WireGuard and SSH tun are unavailable

**Critical requirement:** The container must have **full bidirectional network connectivity** through the tunnel — not just specific port forwards. The container must behave as if it is on the HAProxy host's network (outbound DynDNS calls, certbot, etc. all route through the tunnel). This rules out SSH `-R` (reverse port forwarding) as a primary option since it only forwards specific ports.

---

## Detailed Comparative Analysis

### 1. SSH Reverse Tunnel (`ssh -R`) + autossh

**Security:** Excellent. AES-256 encryption, SSH key-based authentication, 30+ years of battle-tested deployment. End-to-end encrypted tunnel transparent to applications.

**Performance:** Minimal latency overhead (~1-2ms per hop). Single TCP connection multiplexes all port forwards. Throughput limited primarily by SSH crypto overhead (moderate CPU cost).

**Docker-Friendliness:** Negligible footprint (<50KB for openssh-client, already in most base images). Fully scriptable via environment variables. Automatic reconnection via autossh wrapper.

**Automated Setup:** Trivial. Single autossh invocation:
```bash
autossh -M 0 -o ServerAliveInterval=30 \
  -R localhost:8404:localhost:8404 user@haproxy-server
```

**NAT/Firewall Traversal:** Excellent. Works through corporate proxies, firewalls, NAT layers. Only requires outbound TCP 22 (or custom port).

**Reconnection:** Robust. SSH built-in keepalive (ServerAliveInterval). autossh monitors tunnel and auto-restarts on disconnection with exponential backoff.

**Maturity:** Production-ready. OpenSSH active since 1995, billions of deployments, security vulnerabilities rare and rapidly patched.

**Limitations:** Single point of failure if autossh doesn't restart quickly. Requires privileged port binding on remote (or port ≥1024). Each service needs separate SSH connection.

---

### 2. WireGuard (+ wstunnel for restrictive networks)

**Security:** Excellent. Modern AEAD ciphers (ChaCha20, Poly1305), Ed25519 elliptic curve keys. Academic review conducted. Minimal code surface. Full tunnel isolation.

**Performance:** Ultra-low latency (0.1-0.3ms on local networks). Kernel-level implementation provides near-native throughput. Container overhead <5%. Handshake completes in 50-100ms.

**Docker-Friendliness:** ~5MB utilities. Requires Linux 5.6+ kernel module or userspace implementation. Needs CAP_NET_ADMIN or host networking mode (security tradeoff).

**Automated Setup:** Generate keypairs, bring up wg0 interface, configure routes. Straightforward but requires networking knowledge.

**NAT/Firewall Traversal:** Good natively (UDP). **Excellent with wstunnel** — wraps WireGuard UDP in WebSocket (WSS on port 443), making it indistinguishable from HTTPS traffic. Works through corporate HTTP proxies. wstunnel adds only ~2-3% overhead and ~15-20ms latency.

**Reconnection:** Robust. Peer detection and keepalive automatic. On network change, detects new IP and reconnects transparently.

**Maturity:** Production-ready. In Linux kernel since 5.6 (2020). Regular security audits. Growing enterprise adoption. wstunnel is a mature Rust binary, actively maintained.

**Limitations:** Requires networking knowledge. Kernel dependency. Docker gotcha: CAP_NET_ADMIN or host networking limits security benefits. UDP blocked in restrictive networks (mitigated by wstunnel).

**With wstunnel transport layer:**
```
Direct UDP:  Container wg0 ──UDP──► Server:51820
Via wstunnel: Container wg0 ──UDP──► localhost:51820 (wstunnel) ──WSS/443──► Server wstunnel ──UDP──► WireGuard
```

---

### 3. frp (Fast Reverse Proxy)

**Security:** Good. TLS 1.2+ control and optional data channels. Token/API key authentication. Mutual TLS support.

**Performance:** Good throughput for high-traffic deployments. Handles thousands of concurrent connections. Rich feature set (compression, load balancing, auth).

**Docker-Friendliness:** Medium footprint (10-50MB static Go binary). Official Docker images. INI/TOML configuration.

**Automated Setup:** Template-driven configuration. Built-in health check endpoint (`/api/status`). Dashboard available.

**NAT/Firewall Traversal:** Excellent. Primary use case, well-tested. Supports multiple remote servers (failover).

**Reconnection:** Built-in automatic reconnection. Backoff and retry parameters tunable.

**Maturity:** Excellent. 100,000+ GitHub stars, actively maintained. Large community, well-documented, proven at scale.

**Limitations:** Rich feature set can overwhelm simple use cases. Higher memory than rathole.

---

### 4. rathole (Rust-Based Lightweight Reverse Proxy)

**Security:** Good. Optional Noise Protocol (modern AEAD cipher, elliptic curve DH). Token-based authentication mandatory per service.

**Performance:** **Much higher throughput than frp.** Low latency. Significantly lower memory consumption. Efficient Rust implementation.

**Docker-Friendliness:** **Extremely small** (500KB-1MB static binary). No dependencies. TOML configuration.

**Automated Setup:** Configuration-driven (TOML). Single binary invocation. Supports multiple services.

**NAT/Firewall Traversal:** Excellent. Designed for NAT traversal.

**Reconnection:** Built-in automatic reconnection with configurable backoff.

**Maturity:** Production-ready, actively maintained. Growing community. Lower adoption than frp.

**Advantages Over frp:** 500KB vs. 10-50MB binary. Lower memory/CPU. Higher throughput. Simpler.

---

### 5. Chisel (HTTP-Based Tunnel)

**Security:** Good. SSH crypto library. SSH key or username/password authentication. Encrypted inside HTTP, invisible to HTTP proxies.

**Performance:** High throughput (~100MB transfer in <1 second). Low latency (~1-2ms overhead). WebSocket multiplexing.

**Docker-Friendliness:** Small (static Go binary ~10-15MB). No dependencies.

**NAT/Firewall Traversal:** **Excellent for corporate networks.** Works through HTTP proxies (penetrates corporate firewall inspection). Key advantage: HTTP inspection common in corporate environments; harder to block than port 22.

**Reconnection:** Automatic with configurable reconnect.

**Maturity:** Production-ready, actively used in security community.

---

### 6. Cloudflare Tunnel (Commercial Reference)

**Security:** Enterprise-grade. TLS 1.3 to Cloudflare edge. OAuth 2.0 authentication.

**Performance:** Variable latency (50-200ms typical). Excellent throughput (global CDN). Automatic global failover.

**Docker-Friendliness:** ~30-50MB cloudflared binary. Official Docker images.

**NAT/Firewall Traversal:** Excellent. Requires outbound HTTPS only (TCP 443).

**Maturity:** Excellent. Enterprise-grade.

**Limitations:** **Vendor lock-in.** Traffic visible to Cloudflare. Not suitable for private/internal services or compliance regimes.

---

### 7. Tor Hidden Services (.onion)

**Security:** **Exceptional for anonymity.** Triple-encrypted, end-to-end, service location hidden via zero-knowledge proofs.

**Performance:** **Extremely high latency.** Connection establishment ~24+ seconds. Throughput extremely limited by volunteer relays.

**Maturity:** Production-ready for anonymity, not for performance.

**Best For:** Only if service truly requires strong anonymity from network observers. **Not for standard production services.**

---

### 8. I2P (Invisible Internet Project)

**Security:** Good anonymity (ChaCha20, ECDH per-hop encryption). ~55,000 volunteer nodes.

**Performance:** High latency (1-3 seconds round-trip). Limited throughput (20-50KB/sec per tunnel).

**Docker-Friendliness:** ~20-30MB + Java runtime (significant overhead).

**Best For:** Specialized anonymity requirements. **Not for standard tunneling.**

---

### 9. bore (Simple Rust Tunnel)

**Security:** Minimal by default. TLS optional. No authentication on public service.

**Performance:** Very efficient (async Rust). Tiny footprint.

**Limitations:** No built-in authentication. Default plaintext. Single client per port.

**Best For:** Quick demos, testing. **Not for production services with confidential data.**

---

## Summary Comparison Matrix

| Approach | Security | Latency | Throughput | Docker Size | Complexity | Maturity |
|----------|----------|---------|-----------|-------------|-----------|----------|
| SSH + autossh | Excellent | 1-2ms | Good | <100KB | Simple | Excellent |
| WireGuard | Excellent | 0.1-0.3ms | Excellent | ~5MB | Medium | Excellent |
| frp | Good | Low | High | ~30MB | Medium | Excellent |
| rathole | Good | Low | **Very High** | ~1MB | Simple | Good |
| Chisel | Good | Low | **Very High** | ~10MB | Simple | Good |
| Cloudflare Tunnel | Good | 50-200ms | Excellent | ~40MB | Simple | Excellent |
| Tor | Excellent | **24s+** | **Very Low** | ~10MB | Simple | Excellent |
| I2P | Good | 1-3s | Low | ~25MB | Simple | Good |
| bore | Fair | Low | Good | ~3MB | Simple | Good |

---

## Recommendations for ssl-manager

### PRIMARY: WireGuard

**Why WireGuard is the clear choice for ssl-manager:**

The critical requirement is **full bidirectional network transparency** — the container must behave as if it's on the HAProxy host's network. All traffic (inbound user requests AND outbound DynDNS calls, certbot ACME validation, etc.) must route through the tunnel. This eliminates per-port forwarding solutions (SSH `-R`, rathole, frp, bore) as primary options.

- **True VPN:** `AllowedIPs = 0.0.0.0/0` routes ALL traffic through the tunnel
- **NAT masquerade:** Container egress appears from HAProxy's public IP
- **Performance:** Kernel-level, sub-millisecond latency, near-native throughput
- **Security:** Modern AEAD ciphers, minimal attack surface (~4K LOC), formally verified
- **Reconnection:** Handles roaming transparently (IP changes, brief outages)
- **No per-port config:** HAProxy routes to WireGuard peer IP directly by domain name
- **Multi-alias support:** Single peer connection serves all domains and ports

**Integration pattern:**
```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.200.0.2/32

[Peer]
PublicKey = <server-public-key>
PresharedKey = <per-session-preshared-key>
Endpoint = 198.51.100.42:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

**Trade-off:** Requires `NET_ADMIN` capability and Linux 5.6+ kernel. Adds ~5MB to base image.

### ALTERNATIVE 1: SSH tun device (`ssh -w`)

**When to use:** Older kernels without WireGuard module. SSH `-w` creates a full network tunnel (layer 3 tun device), not just port forwards. Provides the same bidirectional connectivity as WireGuard but with higher overhead.

**Trade-off:** More complex to set up (tun device, routing tables, NAT). Higher CPU overhead than WireGuard. Requires root on both sides.

### ALTERNATIVE 2: Chisel (Corporate Firewalls)

**When to use:** Both WireGuard UDP (51820) and SSH are blocked, but HTTP/HTTPS traffic is allowed. Chisel tunnels through WebSocket on port 443, penetrating corporate firewalls. Note: Chisel provides per-port forwarding, not full VPN — outbound traffic from the container would NOT route through the tunnel. Only suitable when the container has independent internet access for DynDNS/certbot.

### NOT RECOMMENDED: SSH -R (Reverse Port Forwarding)

SSH `-R` only forwards specific ports. It does NOT provide outbound routing. The container cannot make DynDNS API calls or certbot ACME requests through the tunnel. Would require bolting on SOCKS proxy, DNS forwarding, and per-service configuration — more complex than WireGuard.

---

## Decision Tree

| Question | Answer | Choose |
|----------|--------|--------|
| Need full bidirectional network? | Yes | **WireGuard** |
| Kernel supports WireGuard (5.6+)? | No | SSH tun (`ssh -w`) |
| Only HTTP/443 allowed outbound? | Yes | Chisel (limited) |
| Is anonymity critical? | Yes | Tor (accept latency) |
| OK with vendor lock-in? | Yes | Cloudflare Tunnel |
