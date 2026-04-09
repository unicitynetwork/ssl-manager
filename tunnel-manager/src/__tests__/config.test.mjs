import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig, parseCli } from '../config.mjs';

describe('Config Loader', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    // Restore original env
    for (const key of Object.keys(process.env)) {
      if (!(key in originalEnv)) {
        delete process.env[key];
      }
    }
    Object.assign(process.env, originalEnv);
  });

  it('loads defaults when no env vars set', () => {
    delete process.env.REMOTE_HAPROXY_ID;
    delete process.env.TUNNEL_MODE;
    delete process.env.TUNNEL_TRANSPORT;

    const config = loadConfig();

    assert.equal(config.remoteHaproxyId, '');
    assert.equal(config.tunnelMode, 'full');
    assert.equal(config.tunnelTransport, 'auto');
    assert.equal(config.tunnelHeartbeatInterval, 900_000);
    assert.equal(config.tunnelReconnectMax, 10);
    assert.equal(config.sslHttpsPort, 443);
    assert.ok(config.tunnelRelayUrls.length >= 4);
  });

  it('reads env vars correctly', () => {
    process.env.REMOTE_HAPROXY_ID = 'npub1test123';
    process.env.SSL_DOMAIN = 'test.example.com';
    process.env.TUNNEL_MODE = 'lite';
    process.env.TUNNEL_TRANSPORT = 'wss';
    process.env.SSL_HTTPS_PORT = '3443';
    process.env.SSL_DOMAIN_ALIASES = 'www.test.com,api.test.com';
    process.env.TUNNEL_HEARTBEAT_INTERVAL = '300';

    const config = loadConfig();

    assert.equal(config.remoteHaproxyId, 'npub1test123');
    assert.equal(config.sslDomain, 'test.example.com');
    assert.equal(config.tunnelMode, 'lite');
    assert.equal(config.tunnelTransport, 'wss');
    assert.equal(config.sslHttpsPort, 3443);
    assert.deepEqual(config.sslDomainAliases, ['www.test.com', 'api.test.com']);
    assert.equal(config.tunnelHeartbeatInterval, 300_000);
  });

  it('handles empty aliases', () => {
    process.env.SSL_DOMAIN_ALIASES = '';
    const config = loadConfig();
    assert.deepEqual(config.sslDomainAliases, []);
  });

  it('parses custom relay URLs', () => {
    process.env.TUNNEL_RELAY_URLS = 'wss://relay1.test,wss://relay2.test';
    const config = loadConfig();
    assert.deepEqual(config.tunnelRelayUrls, ['wss://relay1.test', 'wss://relay2.test']);
  });

  it('parses EXTRA_PORTS JSON', () => {
    process.env.EXTRA_PORTS = '[{"protocol":"tcp","target":50002,"label":"electrum"}]';
    const config = loadConfig();
    assert.equal(config.extraPorts.length, 1);
    assert.equal(config.extraPorts[0].target, 50002);
  });
});

describe('CLI Parser', () => {
  it('parses --start', () => {
    const cli = parseCli(['--start']);
    assert.equal(cli.action, 'start');
  });

  it('parses --teardown', () => {
    const cli = parseCli(['--teardown']);
    assert.equal(cli.action, 'teardown');
  });

  it('parses --status', () => {
    const cli = parseCli(['--status']);
    assert.equal(cli.action, 'status');
  });

  it('parses --wait-ready', () => {
    const cli = parseCli(['--start', '--wait-ready']);
    assert.equal(cli.waitReady, true);
  });

  it('parses --timeout', () => {
    const cli = parseCli(['--start', '--timeout', '600']);
    assert.equal(cli.timeout, 600);
  });

  it('defaults to start action', () => {
    const cli = parseCli([]);
    assert.equal(cli.action, 'start');
    assert.equal(cli.waitReady, false);
    assert.equal(cli.timeout, 300);
  });
});
