import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  createEnvelope,
  buildTunnelRequest,
  buildTunnelAccept,
  buildTunnelEstablished,
  buildTunnelHeartbeat,
  buildTunnelTeardown,
  buildTunnelError,
  validateEnvelope,
} from '../dtnp.mjs';
import { MSG, DTNP_VERSION } from '../constants.mjs';

describe('DTNP Message Builder', () => {
  it('creates a valid envelope', () => {
    const env = createEnvelope(MSG.TUNNEL_REQUEST, { test: true }, {
      correlationId: 'test-corr-id',
      sequence: 1,
      senderNpub: 'npub1test',
    });

    assert.equal(env.dtnp_version, DTNP_VERSION);
    assert.equal(env.msg_type, MSG.TUNNEL_REQUEST);
    assert.equal(env.correlation_id, 'test-corr-id');
    assert.equal(env.sequence, 1);
    assert.equal(env.sender_npub, 'npub1test');
    assert.deepEqual(env.payload, { test: true });
    assert.ok(env.timestamp);
  });

  it('builds a TUNNEL_REQUEST with correct structure', () => {
    const config = {
      sslDomain: 'test.example.com',
      sslDomainAliases: ['www.example.com'],
      sslHttpsPort: 443,
      sslAliasProxyPort: 8444,
      extraPorts: [],
      tunnelMode: 'full',
      tunnelTransport: 'auto',
      tunnelRelayUrls: ['wss://relay.test.com'],
    };
    const identity = { npub: 'npub1test' };
    const wgKeys = { publicKey: 'test-pubkey' };

    const msg = buildTunnelRequest(config, identity, wgKeys);

    assert.equal(msg.msg_type, MSG.TUNNEL_REQUEST);
    assert.equal(msg.payload.primary_domain, 'test.example.com');
    assert.deepEqual(msg.payload.domain_aliases, ['www.example.com']);
    assert.equal(msg.payload.client_wg_pubkey, 'test-pubkey');
    assert.ok(msg.payload.ports.length >= 2); // http + https
    assert.ok(msg.payload.ports.length >= 3); // + alias proxy
    assert.deepEqual(msg.payload.tunnel_preference, ['wireguard', 'ssh-tun']);
    assert.ok(msg.payload.idempotency_key);
    assert.ok(msg.correlation_id);
  });

  it('builds a TUNNEL_REQUEST in lite mode', () => {
    const config = {
      sslDomain: 'test.example.com',
      sslDomainAliases: [],
      sslHttpsPort: 443,
      sslAliasProxyPort: 8444,
      extraPorts: [],
      tunnelMode: 'lite',
      tunnelTransport: 'auto',
      tunnelRelayUrls: [],
    };

    const msg = buildTunnelRequest(config, { npub: '' }, { publicKey: '' });
    assert.deepEqual(msg.payload.tunnel_preference, ['ssh-reverse']);
  });

  it('builds a TUNNEL_ACCEPT', () => {
    const msg = buildTunnelAccept('corr-123', 2, 'npub1test', 'wireguard', 'udp');

    assert.equal(msg.msg_type, MSG.TUNNEL_ACCEPT);
    assert.equal(msg.correlation_id, 'corr-123');
    assert.equal(msg.sequence, 2);
    assert.equal(msg.payload.accepted_tunnel_type, 'wireguard');
    assert.equal(msg.payload.accepted_transport, 'udp');
  });

  it('builds a TUNNEL_ESTABLISHED', () => {
    const msg = buildTunnelEstablished('corr-123', 3, 'npub1test', '10.200.0.2', 12.5);

    assert.equal(msg.msg_type, MSG.TUNNEL_ESTABLISHED);
    assert.equal(msg.payload.client_tunnel_ip, '10.200.0.2');
    assert.equal(msg.payload.measured_rtt_ms, 12.5);
    assert.ok(msg.payload.health_endpoint.includes('10.200.0.2'));
  });

  it('builds a TUNNEL_HEARTBEAT', () => {
    const msg = buildTunnelHeartbeat('corr-123', 4, 'npub1test', {
      tunnelStatus: 'healthy',
      uptimeSeconds: 3600,
      rxBytes: 1024,
      txBytes: 512,
    });

    assert.equal(msg.msg_type, MSG.TUNNEL_HEARTBEAT);
    assert.equal(msg.payload.direction, 'client-to-server');
    assert.equal(msg.payload.tunnel_status, 'healthy');
    assert.equal(msg.payload.metrics.rx_bytes, 1024);
  });

  it('builds a TUNNEL_TEARDOWN', () => {
    const msg = buildTunnelTeardown('corr-123', 5, 'npub1test', 'GRACEFUL_SHUTDOWN', 'stopping');

    assert.equal(msg.msg_type, MSG.TUNNEL_TEARDOWN);
    assert.equal(msg.payload.initiated_by, 'client');
    assert.equal(msg.payload.reason, 'GRACEFUL_SHUTDOWN');
    assert.equal(msg.payload.cleanup_haproxy, true);
  });

  it('builds a TUNNEL_ERROR', () => {
    const msg = buildTunnelError('corr-123', 6, 'npub1test', 'ERR_TUNNEL_SETUP_FAILED', 'wg-quick failed', false);

    assert.equal(msg.msg_type, MSG.TUNNEL_ERROR);
    assert.equal(msg.payload.error_code, 'ERR_TUNNEL_SETUP_FAILED');
    assert.equal(msg.payload.recoverable, false);
  });
});

describe('DTNP Message Validator', () => {
  it('accepts a valid envelope', () => {
    const env = createEnvelope(MSG.TUNNEL_REQUEST, { test: true }, {
      correlationId: 'test-id',
      sequence: 1,
    });
    const result = validateEnvelope(env);
    assert.equal(result.valid, true);
  });

  it('rejects null message', () => {
    assert.equal(validateEnvelope(null).valid, false);
  });

  it('rejects missing dtnp_version', () => {
    const env = { msg_type: MSG.TUNNEL_REQUEST, correlation_id: 'x', sequence: 1, timestamp: new Date().toISOString(), payload: {} };
    assert.equal(validateEnvelope(env).valid, false);
  });

  it('rejects unknown message type', () => {
    const env = createEnvelope('UNKNOWN_TYPE', {}, { correlationId: 'x', sequence: 1 });
    assert.equal(validateEnvelope(env).valid, false);
  });

  it('rejects missing correlation_id', () => {
    const env = { dtnp_version: DTNP_VERSION, msg_type: MSG.TUNNEL_REQUEST, sequence: 1, timestamp: new Date().toISOString(), payload: {} };
    assert.equal(validateEnvelope(env).valid, false);
  });

  it('rejects stale timestamp (>2 min ago)', () => {
    const env = createEnvelope(MSG.TUNNEL_REQUEST, {}, { correlationId: 'x', sequence: 1 });
    env.timestamp = new Date(Date.now() - 3 * 60 * 1000).toISOString(); // 3 min ago
    const result = validateEnvelope(env);
    assert.equal(result.valid, false);
    assert.ok(result.error.includes('Timestamp'));
  });

  it('rejects future timestamp (>2 min ahead)', () => {
    const env = createEnvelope(MSG.TUNNEL_REQUEST, {}, { correlationId: 'x', sequence: 1 });
    env.timestamp = new Date(Date.now() + 3 * 60 * 1000).toISOString(); // 3 min ahead
    assert.equal(validateEnvelope(env).valid, false);
  });

  it('accepts version with same major, different minor', () => {
    const env = createEnvelope(MSG.TUNNEL_REQUEST, {}, { correlationId: 'x', sequence: 1 });
    env.dtnp_version = '0.2.0'; // minor bump OK
    assert.equal(validateEnvelope(env).valid, true);
  });

  it('rejects version with different major', () => {
    const env = createEnvelope(MSG.TUNNEL_REQUEST, {}, { correlationId: 'x', sequence: 1 });
    env.dtnp_version = '1.0.0'; // major bump NOT OK
    assert.equal(validateEnvelope(env).valid, false);
  });
});
