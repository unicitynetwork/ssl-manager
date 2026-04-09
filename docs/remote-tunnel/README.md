# Remote HAProxy Tunneling — Design Documents

This directory contains the architecture and specification documents for the **Remote HAProxy Tunneling** feature, which enables ssl-manager containers running behind firewalls to tunnel traffic through a remote HAProxy instance.

## Documents

| Document | Description |
|----------|-------------|
| [architecture.md](architecture.md) | System architecture, component inventory, lifecycle, DNS integration, security model, configuration, error handling, and integration with existing ssl-setup flow |
| [protocol-spec.md](protocol-spec.md) | DM Tunnel Negotiation Protocol (DTNP) v0.1 — message formats, state machines, sequence diagrams, security model, DNS sub-protocol, extensibility |
| [tunneling-comparison.md](tunneling-comparison.md) | Comparative analysis of 10 tunneling technologies with recommendations |

## Summary

A container behind a firewall uses **Nostr NIP-17 encrypted DMs** (via Sphere SDK) to negotiate a reverse tunnel with a remote HAProxy daemon identified by its Unicity ID (npub). The daemon allocates loopback ports, configures HAProxy backends, updates Dynamic DNS, and returns tunnel credentials — all through the encrypted DM channel.

**Primary tunnel technology:** SSH reverse forwarding + autossh (proven, simple, tiny footprint).
**Alternatives:** WireGuard (max performance/privacy), rathole/frp (when SSH is blocked), Chisel (corporate HTTP-only firewalls).

Once the tunnel is established, the existing ssl-setup flow runs unchanged — certbot HTTP-01 challenges, nonce verification, HAProxy registration, and certificate renewal all work transparently through the tunnel.

## Status

- [x] Architecture design
- [x] Protocol specification (DTNP v0.1)
- [x] Tunneling technology comparison
- [ ] Implementation (not started)
