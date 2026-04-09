/**
 * DTNP Message builder and parser.
 *
 * Constructs and validates DTNP protocol messages.
 */

import { randomUUID } from 'node:crypto';
import { DTNP_VERSION, MSG, TIMEOUTS } from './constants.mjs';

const LOG_PREFIX = '[tunnel-manager:dtnp]';

/**
 * Create a DTNP envelope.
 */
export function createEnvelope(msgType, payload, opts = {}) {
  return {
    dtnp_version: DTNP_VERSION,
    msg_type: msgType,
    correlation_id: opts.correlationId || randomUUID(),
    sequence: opts.sequence || 0,
    timestamp: new Date().toISOString(),
    sender_npub: opts.senderNpub || '',
    relay_hints: opts.relayHints || [],
    payload,
  };
}

/**
 * Build a TUNNEL_REQUEST message.
 */
export function buildTunnelRequest(config, identity, wgKeys) {
  const ports = [
    { protocol: 'http', client_port: 80, description: 'ssl-http-proxy' },
    { protocol: 'https', client_port: config.sslHttpsPort, description: 'app TLS' },
  ];

  if (config.sslDomainAliases.length > 0) {
    ports.push({
      protocol: 'https',
      client_port: config.sslAliasProxyPort,
      description: 'ssl-alias-proxy',
    });
  }

  if (config.extraPorts && config.extraPorts.length > 0) {
    for (const ep of config.extraPorts) {
      ports.push({
        protocol: ep.protocol || 'tcp',
        client_port: ep.target || ep.port,
        label: ep.label || ep.description || '',
      });
    }
  }

  const tunnelPref = config.tunnelMode === 'lite'
    ? ['ssh-reverse']
    : ['wireguard', 'ssh-tun'];

  const transportPref = config.tunnelTransport === 'auto'
    ? ['auto', 'udp', 'wss']
    : [config.tunnelTransport];

  const payload = {
    primary_domain: config.sslDomain,
    domain_aliases: config.sslDomainAliases,
    ports,
    tunnel_preference: tunnelPref,
    transport_preference: transportPref,
    client_wg_pubkey: wgKeys.publicKey,
    client_meta: {
      hostname: getHostname(),
      platform: `${process.platform}/${process.arch}`,
      ssl_manager_version: '0.1.0',
      capabilities: ['haproxy-register-api', 'sphere-sdk-dm'],
    },
    ttl_seconds: 86400,
    idempotency_key: randomUUID(),
  };

  return createEnvelope(MSG.TUNNEL_REQUEST, payload, {
    correlationId: randomUUID(),
    sequence: 1,
    senderNpub: identity.npub || '',
    relayHints: config.tunnelRelayUrls,
  });
}

/**
 * Build a TUNNEL_ACCEPT message.
 */
export function buildTunnelAccept(correlationId, sequence, senderNpub, tunnelType, transport) {
  return createEnvelope(MSG.TUNNEL_ACCEPT, {
    accepted_tunnel_type: tunnelType,
    accepted_transport: transport,
    ready_at: new Date().toISOString(),
  }, { correlationId, sequence, senderNpub });
}

/**
 * Build a TUNNEL_ESTABLISHED message.
 */
export function buildTunnelEstablished(correlationId, sequence, senderNpub, clientIp, rttMs) {
  return createEnvelope(MSG.TUNNEL_ESTABLISHED, {
    tunnel_up_at: new Date().toISOString(),
    health_endpoint: `http://${clientIp}:80/_ssl/health`,
    measured_rtt_ms: rttMs,
    client_tunnel_ip: clientIp,
  }, { correlationId, sequence, senderNpub });
}

/**
 * Build a TUNNEL_HEARTBEAT message.
 */
export function buildTunnelHeartbeat(correlationId, sequence, senderNpub, metrics) {
  return createEnvelope(MSG.TUNNEL_HEARTBEAT, {
    direction: 'client-to-server',
    tunnel_status: metrics.tunnelStatus || 'healthy',
    uptime_seconds: metrics.uptimeSeconds || 0,
    metrics: {
      rx_bytes: metrics.rxBytes || 0,
      tx_bytes: metrics.txBytes || 0,
      active_connections: metrics.activeConnections || 0,
      rtt_ms: metrics.rttMs || 0,
    },
    cert_expiry_days: metrics.certExpiryDays || null,
    next_heartbeat_in_seconds: Math.round(TIMEOUTS.HEARTBEAT_INTERVAL / 1000),
  }, { correlationId, sequence, senderNpub });
}

/**
 * Build a TUNNEL_TEARDOWN message.
 */
export function buildTunnelTeardown(correlationId, sequence, senderNpub, reason, message) {
  return createEnvelope(MSG.TUNNEL_TEARDOWN, {
    initiated_by: 'client',
    reason: reason || 'GRACEFUL_SHUTDOWN',
    cleanup_dns: true,
    cleanup_haproxy: true,
    message: message || 'Container stopping, graceful shutdown initiated',
  }, { correlationId, sequence, senderNpub });
}

/**
 * Build a TUNNEL_ERROR message.
 */
export function buildTunnelError(correlationId, sequence, senderNpub, errorCode, errorMessage, recoverable) {
  return createEnvelope(MSG.TUNNEL_ERROR, {
    error_code: errorCode,
    error_message: errorMessage,
    recoverable: recoverable !== false,
    suggested_action: recoverable !== false ? 'RETRY_TUNNEL' : null,
  }, { correlationId, sequence, senderNpub });
}

/**
 * Validate a received DTNP message envelope.
 * Returns { valid: boolean, error?: string }.
 */
export function validateEnvelope(msg) {
  if (!msg || typeof msg !== 'object') {
    return { valid: false, error: 'Message is not an object' };
  }

  if (!msg.dtnp_version) {
    return { valid: false, error: 'Missing dtnp_version' };
  }

  const majorVersion = msg.dtnp_version.split('.')[0];
  const expectedMajor = DTNP_VERSION.split('.')[0];
  if (majorVersion !== expectedMajor) {
    return { valid: false, error: `Version mismatch: got ${msg.dtnp_version}, expected ${DTNP_VERSION}` };
  }

  if (!msg.msg_type || !Object.values(MSG).includes(msg.msg_type)) {
    return { valid: false, error: `Unknown message type: ${msg.msg_type}` };
  }

  if (!msg.correlation_id) {
    return { valid: false, error: 'Missing correlation_id' };
  }

  if (typeof msg.sequence !== 'number') {
    return { valid: false, error: 'Missing or invalid sequence number' };
  }

  if (!msg.timestamp) {
    return { valid: false, error: 'Missing timestamp' };
  }

  // Timestamp skew check
  const msgTime = new Date(msg.timestamp).getTime();
  const now = Date.now();
  if (Math.abs(now - msgTime) > TIMEOUTS.TIMESTAMP_SKEW) {
    return { valid: false, error: `Timestamp skew: message time ${msg.timestamp} is too far from current time` };
  }

  if (!msg.payload || typeof msg.payload !== 'object') {
    return { valid: false, error: 'Missing or invalid payload' };
  }

  // Per-message-type payload validation
  try {
    validatePayload(msg.msg_type, msg.payload);
  } catch (e) {
    return { valid: false, error: `Payload validation failed: ${e.message}` };
  }

  return { valid: true };
}

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const WG_PUBKEY_RE = /^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]=$/;

/**
 * Validate payload fields based on message type.
 * Throws on invalid payload.
 */
function validatePayload(msgType, payload) {
  switch (msgType) {
    case MSG.TUNNEL_REQUEST:
      validateTunnelRequestPayload(payload);
      break;
    case MSG.TUNNEL_OFFER:
      validateTunnelOfferPayload(payload);
      break;
    case MSG.TUNNEL_ACCEPT:
      validateTunnelAcceptPayload(payload);
      break;
    case MSG.TUNNEL_TEARDOWN:
      validateTunnelTeardownPayload(payload);
      break;
    case MSG.TUNNEL_ERROR:
      validateTunnelErrorPayload(payload);
      break;
    // TUNNEL_ESTABLISHED, TUNNEL_HEARTBEAT — minimal validation, mostly metrics
    default:
      break;
  }
}

function validateTunnelRequestPayload(payload) {
  if (typeof payload.primary_domain !== 'string' || !DOMAIN_RE.test(payload.primary_domain)) {
    throw new Error('Invalid primary_domain format');
  }
  if (payload.domain_aliases !== undefined) {
    if (!Array.isArray(payload.domain_aliases)) {
      throw new Error('domain_aliases must be array');
    }
    for (const alias of payload.domain_aliases) {
      if (typeof alias !== 'string' || !DOMAIN_RE.test(alias)) {
        throw new Error(`Invalid domain alias format: ${alias}`);
      }
    }
  }
  if (typeof payload.client_wg_pubkey !== 'string' || !WG_PUBKEY_RE.test(payload.client_wg_pubkey)) {
    throw new Error('Invalid client_wg_pubkey format');
  }
  if (!Array.isArray(payload.ports)) {
    throw new Error('ports must be an array');
  }
}

function validateTunnelOfferPayload(payload) {
  if (typeof payload.tunnel_type !== 'string') {
    throw new Error('Missing tunnel_type');
  }
  if (!Array.isArray(payload.transports) || payload.transports.length === 0) {
    throw new Error('transports must be a non-empty array');
  }
  if (!payload.auth || typeof payload.auth !== 'object') {
    throw new Error('Missing auth object');
  }
}

function validateTunnelAcceptPayload(payload) {
  if (typeof payload.accepted_tunnel_type !== 'string') {
    throw new Error('Missing accepted_tunnel_type');
  }
  if (typeof payload.accepted_transport !== 'string') {
    throw new Error('Missing accepted_transport');
  }
}

function validateTunnelTeardownPayload(payload) {
  if (typeof payload.reason !== 'string') {
    throw new Error('Missing teardown reason');
  }
}

function validateTunnelErrorPayload(payload) {
  if (typeof payload.error_code !== 'string') {
    throw new Error('Missing error_code');
  }
}

import { hostname as _getHostname } from 'node:os';

function getHostname() {
  try {
    return _getHostname();
  } catch {
    return 'unknown';
  }
}
