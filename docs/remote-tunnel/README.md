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
- **Two tunnel modes:** Full (WireGuard VPN, bidirectional) and Lite (SSH -R, inbound-only for when direct internet is available)
- **Split routing** — Docker DNS and container networking preserved; only internet traffic tunneled
- **Sidecar architecture** — haproxy-tunnel-daemon runs as a sidecar sharing HAProxy's network namespace, keeping HAProxy lean
- **Sphere SDK for all DM communication** — both client and server use Sphere SDK (Node.js)
- **Client owns its DNS** — HAProxy MUST NOT manage client DNS credentials; it only reports its public IP
- **Domain-scoped ACL** — each client npub is bound to specific domain patterns (mandatory, not optional)
- **Restricted NAT** — iptables rules prevent tunnel clients from accessing private subnets, cloud metadata, or other peers
- **WSS transport** — WireGuard UDP wrapped in WebSocket via wstunnel for restrictive networks; HAProxy SNI-routes tunnel traffic
- **Two image variants** — `ssl-manager:latest` (no tunnel deps) and `ssl-manager:tunnel` (with WireGuard, wstunnel, Node.js)

Once the tunnel is established, the existing ssl-setup flow runs unchanged — certbot HTTP-01 challenges, nonce verification, HAProxy registration, and certificate renewal all work transparently through the tunnel.

## Status

- [x] Architecture design
- [x] Protocol specification (DTNP v0.1)
- [x] Tunneling technology comparison
- [~] **Full mode (WireGuard + DTNP/Nostr)** — `tunnel-daemon/` (server) + `tunnel-manager/`
  (client). WireGuard path built; unit-tested; not yet verified end-to-end.
- [x] **Lite mode (SSH `-R`, inbound-only)** — **implemented and verified live**, but as a
  standalone, **negotiation-free** realization (no Nostr/DTNP): [`ssh-tunnel-endpoint/`](../../ssh-tunnel-endpoint)
  (restricted sshd on `haproxy-net`) + [`ssh-tunnel-client/`](../../ssh-tunnel-client)
  (a dependency-free shell client). It talks to the haproxy Registration API directly over an
  SSH `-L` forward. The DTNP client's earlier SSH-reverse stub (`tunnel-manager/src/ssh-tunnel.mjs`)
  was retired in favor of it; the DTNP client is now WireGuard-only.

> **Two realizations of the lite mode.** The DTNP design negotiates transports over Nostr and
> was to select `ssh-reverse` for lite mode. In practice the daemon only ever offered
> WireGuard, so the negotiated SSH path never worked. The standalone `ssh-tunnel-*` components
> deliver the same inbound-only capability today without the negotiation layer — the pragmatic
> choice for "just expose this firewalled http/https service." A future DTNP integration could
> negotiate *either* transport and hand off to the same endpoint.
