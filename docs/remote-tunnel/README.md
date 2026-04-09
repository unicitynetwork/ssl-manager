# Remote HAProxy Tunneling — Design Documents

This directory contains the architecture and specification documents for the **Remote HAProxy Tunneling** feature, which enables ssl-manager containers running behind firewalls to tunnel traffic through a remote HAProxy instance.

## Documents

| Document | Description |
|----------|-------------|
| [architecture.md](architecture.md) | System architecture, component inventory, lifecycle, DNS integration, security model, configuration, error handling, and integration with existing ssl-setup flow |
| [protocol-spec.md](protocol-spec.md) | DM Tunnel Negotiation Protocol (DTNP) v0.1 — message formats, state machines, sequence diagrams, security model, DNS sub-protocol, extensibility |
| [tunneling-comparison.md](tunneling-comparison.md) | Comparative analysis of 10 tunneling technologies with recommendations |

## Summary

A container behind a firewall uses **Sphere SDK DMs** (Nostr NIP-17 encrypted) to negotiate a **WireGuard VPN tunnel** with a remote HAProxy daemon identified by its Unicity ID (npub). The tunnel provides **full bidirectional network connectivity** — the container behaves as if it's on the HAProxy host's network. All traffic (inbound user requests, outbound DynDNS calls, certbot ACME validation) routes through the tunnel transparently.

**Key design principles:**
- **WireGuard as primary tunnel** — full VPN, not per-port forwarding; kernel-level performance
- **Sphere SDK for all DM communication** — both client and server use Sphere SDK (Node.js)
- **Client owns its DNS** — HAProxy MUST NOT manage client DNS credentials; it only reports its public IP
- **haproxy-tunnel-daemon runs inside HAProxy container** — direct access to HAProxy runtime API, WireGuard, and iptables
- **Multiple aliases supported** — single WireGuard peer handles primary domain + all aliases

Once the tunnel is established, the existing ssl-setup flow runs unchanged — certbot HTTP-01 challenges, nonce verification, HAProxy registration, and certificate renewal all work transparently through the tunnel.

## Status

- [x] Architecture design
- [x] Protocol specification (DTNP v0.1)
- [x] Tunneling technology comparison
- [ ] Implementation (not started)
