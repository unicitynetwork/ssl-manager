#!/usr/bin/env node
/**
 * haproxy-tunnel-daemon — Server-side tunnel management sidecar.
 *
 * Runs as a sidecar container sharing HAProxy's network namespace.
 * Listens for DTNP TUNNEL_REQUEST messages via Nostr DMs, manages
 * WireGuard peers, configures HAProxy backends, and handles
 * tunnel lifecycle.
 *
 * Usage:
 *   haproxy-tunnel-daemon
 *
 * Configuration via environment variables (see config.mjs).
 */

import { randomUUID } from 'node:crypto';
import { loadConfig, loadAcl, checkAcl } from './config.mjs';
import { IpPool } from './ip-pool.mjs';
import { SessionManager } from './session-manager.mjs';
import * as wgManager from './wg-manager.mjs';
import * as haproxyApi from './haproxy-api.mjs';
import { startMonitorServer } from './monitor.mjs';

const LOG_PREFIX = '[tunnel-daemon]';
const DTNP_VERSION = '0.1.0';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }
function err(msg) { console.error(`${LOG_PREFIX} ERROR: ${msg}`); }

async function main() {
  log('Starting haproxy-tunnel-daemon');

  const config = loadConfig();
  const acl = loadAcl(config.aclFile);

  log(`Public IP: ${config.tunnelPublicIp}`);
  log(`Subnet: ${config.tunnelSubnet}`);
  log(`Max peers: ${config.tunnelMaxPeers}`);
  log(`ACL entries: ${acl.acl?.length || 0}`);

  // Initialize components
  const ipPool = new IpPool(config.tunnelSubnet, config.tunnelIpCooldown);
  const sessionManager = new SessionManager(config);

  // Initialize WireGuard server
  if (!wgManager.initWireGuardServer(config)) {
    err('Failed to initialize WireGuard server');
    process.exit(1);
  }

  const serverPubKey = wgManager.getServerPublicKey();
  log(`WireGuard server public key: ${serverPubKey.substring(0, 20)}...`);

  // Set up iptables
  wgManager.setupIptablesRules(config.tunnelSubnet, config.haproxyApiPort);

  // Start monitor server
  startMonitorServer(config.monitorPort, sessionManager, ipPool, wgManager);

  // Connect to Nostr relays
  // NOTE: In production, this uses Sphere SDK for NIP-17 gift-wrapped DMs.
  // The current implementation uses a minimal Nostr client.
  log('Connecting to Nostr relays...');
  let nostrClient;
  try {
    // Dynamic import for nostr client
    const { NostrClient } = await import('./nostr-client.mjs');
    nostrClient = new NostrClient(config);
    await nostrClient.connect();
  } catch (e) {
    warn(`Nostr client not fully initialized: ${e.message}`);
    warn('Running in local-only mode (no DM negotiation)');
  }

  // Handle incoming DTNP messages
  const handleMessage = async (senderNpub, message) => {
    if (!message || !message.msg_type) {
      warn('Received invalid message (no msg_type)');
      return;
    }

    log(`Received ${message.msg_type} from ${senderNpub.substring(0, 12)}...`);

    switch (message.msg_type) {
      case 'TUNNEL_REQUEST':
        await handleTunnelRequest(senderNpub, message, config, acl, ipPool,
          sessionManager, serverPubKey, nostrClient);
        break;

      case 'TUNNEL_ACCEPT':
        await handleTunnelAccept(senderNpub, message, sessionManager, config,
          ipPool, nostrClient);
        break;

      case 'TUNNEL_ESTABLISHED':
        await handleTunnelEstablished(senderNpub, message, sessionManager);
        break;

      case 'TUNNEL_HEARTBEAT':
        await handleTunnelHeartbeat(senderNpub, message, sessionManager);
        break;

      case 'TUNNEL_TEARDOWN':
        await handleTunnelTeardown(senderNpub, message, sessionManager, ipPool,
          config, nostrClient);
        break;

      default:
        warn(`Unknown message type: ${message.msg_type}`);
    }
  };

  // Subscribe to DMs if Nostr client is available
  if (nostrClient) {
    await nostrClient.subscribeDMs(null, (senderNpub, msg) => {
      handleMessage(senderNpub, msg).catch(e => {
        err(`Error handling message: ${e.message}`);
      });
    });
  }

  // Start health monitor loop (checks WireGuard handshake staleness)
  startHealthMonitor(sessionManager, ipPool, config, nostrClient);

  // Handle shutdown
  const shutdown = async () => {
    log('Shutting down...');

    // Teardown all active sessions
    for (const session of sessionManager.getActiveSessions()) {
      sessionCleanup(session, ipPool, config);
    }

    sessionManager.destroy();
    ipPool.destroy();

    if (nostrClient) {
      await nostrClient.disconnect();
    }

    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  log('Tunnel daemon ready');
}

/**
 * Handle TUNNEL_REQUEST.
 */
async function handleTunnelRequest(senderNpub, message, config, acl, ipPool,
  sessionManager, serverPubKey, nostrClient) {

  const payload = message.payload;
  const primaryDomain = payload.primary_domain;
  const aliases = payload.domain_aliases || [];

  // Validate ACL
  const aclResult = checkAcl(acl, senderNpub, primaryDomain, aliases);
  if (!aclResult.authorized) {
    log(`ACL denied: ${senderNpub.substring(0, 12)}... for ${primaryDomain} (${aclResult.error})`);
    if (nostrClient) {
      await nostrClient.sendDM(senderNpub, {
        dtnp_version: DTNP_VERSION,
        msg_type: 'TUNNEL_REJECTED',
        correlation_id: message.correlation_id,
        sequence: 1,
        timestamp: new Date().toISOString(),
        sender_npub: '',
        payload: {
          reason_code: aclResult.error,
          reason_message: `Domain ${aclResult.domain || primaryDomain} not authorized`,
          retry_after_seconds: 0,
          server_supported_versions: [DTNP_VERSION],
          server_supported_tunnel_types: ['wireguard'],
        },
      });
    }
    return;
  }

  // Allocate IP
  const existingIp = ipPool.findByClient(senderNpub, primaryDomain);
  const peerIp = ipPool.allocate(senderNpub, primaryDomain, existingIp);
  if (!peerIp) {
    log(`IP pool exhausted for ${primaryDomain}`);
    if (nostrClient) {
      await nostrClient.sendDM(senderNpub, {
        dtnp_version: DTNP_VERSION,
        msg_type: 'TUNNEL_REJECTED',
        correlation_id: message.correlation_id,
        sequence: 1,
        timestamp: new Date().toISOString(),
        sender_npub: '',
        payload: {
          reason_code: 'ERR_POOL_EXHAUSTED',
          reason_message: 'No available WireGuard peer IPs',
          retry_after_seconds: 60,
        },
      });
    }
    return;
  }

  // Create session
  const session = sessionManager.getOrCreate(senderNpub, primaryDomain, message.correlation_id);
  session.peerIp = peerIp;
  session.clientWgPubkey = payload.client_wg_pubkey;
  session.aliases = aliases;
  session.ports = payload.ports || [];
  session.tunnelType = 'wireguard';

  // Generate preshared key
  const presharedKey = wgManager.generatePresharedKey();

  // Build transports
  const transports = [
    { type: 'udp', endpoint: `${config.tunnelPublicIp}:${config.tunnelWgPort}` },
  ];
  if (config.tunnelWssSni) {
    transports.push({
      type: 'wss',
      endpoint: `wss://${config.tunnelWssSni}:443/wg`,
      sni: config.tunnelWssSni,
    });
  }

  // Build backends list
  const backends = [
    {
      domain: primaryDomain,
      http_target: `${peerIp}:80`,
      https_target: `${peerIp}:${payload.ports?.find(p => p.protocol === 'https')?.client_port || 443}`,
    },
  ];
  for (const alias of aliases) {
    backends.push({
      domain: alias,
      http_target: `${peerIp}:80`,
      https_target: `${peerIp}:8444`, // alias proxy port
    });
  }

  // Send TUNNEL_OFFER
  const offer = {
    dtnp_version: DTNP_VERSION,
    msg_type: 'TUNNEL_OFFER',
    correlation_id: message.correlation_id,
    sequence: 1,
    timestamp: new Date().toISOString(),
    sender_npub: '',
    payload: {
      tunnel_type: 'wireguard',
      transports,
      auth: {
        server_wg_pubkey: serverPubKey,
        client_ip_alloc: `${peerIp}/32`,
        server_ip: config.tunnelSubnet.replace(/\.0\//, '.1/'),
        preshared_key_enc: presharedKey, // In production: NIP-44 encrypted
        allowed_ips: '0.0.0.0/0',
      },
      haproxy_public_ip: config.tunnelPublicIp,
      haproxy_api: {
        host: config.tunnelSubnet.replace(/\.0\/.*/, '.1'),
        port: config.haproxyApiPort,
        session_key: session.sessionKey,
      },
      haproxy_backends: backends,
      nat_masquerade: true,
      offer_expires_at: new Date(Date.now() + 180_000).toISOString(),
      constraints: {
        bandwidth_limit_mbps: null,
        max_connections: 1000,
        tunnel_ttl_seconds: 86400,
        heartbeat_interval_seconds: 900,
        heartbeat_missed_limit: 3,
      },
      server_version: DTNP_VERSION,
    },
  };

  if (nostrClient) {
    await nostrClient.sendDM(senderNpub, offer);
  }

  // Store preshared key temporarily for peer addition
  session._presharedKey = presharedKey;

  sessionManager.setOffered(session);
  log(`Sent TUNNEL_OFFER to ${senderNpub.substring(0, 12)}... (peer IP: ${peerIp})`);
}

/**
 * Handle TUNNEL_ACCEPT.
 */
async function handleTunnelAccept(senderNpub, message, sessionManager, config,
  ipPool, nostrClient) {

  const session = sessionManager.findByCorrelation(message.correlation_id);
  if (!session) {
    warn(`No session for correlation ${message.correlation_id}`);
    return;
  }

  session.transport = message.payload?.accepted_transport || 'udp';

  // Add WireGuard peer
  const peerAdded = wgManager.addPeer(
    session.clientWgPubkey,
    session.peerIp,
    session._presharedKey
  );

  if (!peerAdded) {
    err(`Failed to add WireGuard peer for ${session.primaryDomain}`);
    sessionManager.teardown(session, (s) => sessionCleanup(s, ipPool, config));
    return;
  }

  // Register HAProxy backends
  haproxyApi.registerSessionBackends(
    session,
    session.peerIp,
    'localhost',
    config.haproxyApiPort
  );

  // Clean up temp key
  delete session._presharedKey;

  sessionManager.setAccepting(session);
}

/**
 * Handle TUNNEL_ESTABLISHED.
 */
async function handleTunnelEstablished(senderNpub, message, sessionManager) {
  const session = sessionManager.findByCorrelation(message.correlation_id);
  if (!session) {
    warn(`No session for correlation ${message.correlation_id}`);
    return;
  }

  // Verify health via the client's health endpoint
  const healthEndpoint = message.payload?.health_endpoint;
  if (healthEndpoint) {
    log(`Client health endpoint: ${healthEndpoint}`);
    // TODO: Verify health via HTTP GET
  }

  sessionManager.setActive(session);
  log(`Tunnel ACTIVE: ${session.primaryDomain} -> ${session.peerIp} (RTT: ${message.payload?.measured_rtt_ms || '?'}ms)`);
}

/**
 * Handle TUNNEL_HEARTBEAT.
 */
async function handleTunnelHeartbeat(senderNpub, message, sessionManager) {
  const session = sessionManager.findByCorrelation(message.correlation_id);
  if (!session) return;

  sessionManager.recordHeartbeat(session);

  // If in DRAINING state, cancel draining
  if (session.state === 'DRAINING') {
    sessionManager.cancelDraining(session);
  }
}

/**
 * Handle TUNNEL_TEARDOWN.
 */
async function handleTunnelTeardown(senderNpub, message, sessionManager, ipPool,
  config, nostrClient) {

  const session = sessionManager.findByCorrelation(message.correlation_id);
  if (!session) {
    warn(`No session for teardown correlation ${message.correlation_id}`);
    return;
  }

  log(`Teardown requested by client: ${session.primaryDomain} (reason: ${message.payload?.reason})`);
  sessionManager.teardown(session, (s) => sessionCleanup(s, ipPool, config));
}

/**
 * Clean up resources for a torn-down session.
 */
function sessionCleanup(session, ipPool, config) {
  // Remove WireGuard peer
  if (session.clientWgPubkey) {
    wgManager.removePeer(session.clientWgPubkey);
  }

  // Deregister HAProxy backends
  haproxyApi.deregisterSessionBackends(session, 'localhost', config.haproxyApiPort);

  // Remove iptables rules
  if (session.peerIp) {
    wgManager.removeClientIptables(session.peerIp);
  }

  // Free IP (enters cooldown)
  if (session.peerIp) {
    ipPool.free(session.peerIp);
  }

  log(`Cleaned up session: ${session.primaryDomain}`);
}

/**
 * Start the health monitor loop.
 * Checks WireGuard handshake staleness and initiates draining.
 */
function startHealthMonitor(sessionManager, ipPool, config, nostrClient) {
  setInterval(() => {
    const handshakes = wgManager.getPeerHandshakes();
    const now = Math.floor(Date.now() / 1000);

    for (const session of sessionManager.getActiveSessions()) {
      if (!session.clientWgPubkey) continue;

      const lastHandshake = handshakes.get(session.clientWgPubkey) || 0;
      const staleSecs = lastHandshake > 0 ? now - lastHandshake : Infinity;

      if (staleSecs > config.tunnelStaleThreshold && session.state === 'ACTIVE') {
        log(`Peer ${session.peerIp} handshake stale for ${staleSecs}s (threshold: ${config.tunnelStaleThreshold}s)`);
        sessionManager.setDraining(session);
      }
    }
  }, 60_000); // Check every minute
}

// Minimal Nostr client for the daemon (same interface as tunnel-manager's)
class NostrClient {
  constructor(config) {
    this.config = config;
    this.relays = [];
    this.connected = false;
  }

  async connect() {
    log(`Connecting to ${this.config.relayUrls.length} relay(s)...`);
    // Minimal implementation - will be replaced by Sphere SDK
    this.connected = true;
    log('Nostr client initialized (minimal mode)');
  }

  async sendDM(recipientNpub, message) {
    if (!this.connected) throw new Error('Not connected');
    log(`[DM -> ${recipientNpub.substring(0, 12)}...] ${message.msg_type}`);
  }

  async subscribeDMs(senderFilter, handler) {
    log('Subscribed to DMs');
    this._handler = handler;
  }

  async disconnect() {
    this.connected = false;
  }
}

main().catch((e) => {
  err(`Fatal error: ${e.message}`);
  console.error(e.stack);
  process.exit(1);
});
