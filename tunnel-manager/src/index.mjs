#!/usr/bin/env node
/**
 * tunnel-manager — Client-side tunnel lifecycle orchestrator.
 *
 * Manages the complete lifecycle of a remote HAProxy tunnel:
 *   1. Bootstrap: check WireGuard/SSH availability, load identity
 *   2. Negotiate: send TUNNEL_REQUEST via Nostr DM, receive TUNNEL_OFFER
 *   3. Establish: configure and bring up WireGuard or SSH tunnel
 *   4. Monitor: periodic health checks and heartbeats
 *   5. Teardown: graceful shutdown on SIGTERM
 *
 * Usage:
 *   tunnel-manager --start --wait-ready --timeout 300
 *   tunnel-manager --teardown
 *   tunnel-manager --status
 *
 * Exit codes:
 *    0  — success (tunnel established)
 *   15  — negotiation failed
 *   16  — tunnel establishment failed
 *   17  — DNS propagation timeout
 */

import { loadConfig, parseCli } from './config.mjs';
import { loadOrCreateNostrIdentity, loadOrCreateWireguardKeys } from './identity.mjs';
import { NostrClient } from './nostr-client.mjs';
import { TunnelStateMachine } from './state-machine.mjs';
import { EXIT_CODES, TEARDOWN_REASONS } from './constants.mjs';

const LOG_PREFIX = '[tunnel-manager]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function err(msg) { console.error(`${LOG_PREFIX} ERROR: ${msg}`); }

async function main() {
  const config = loadConfig();
  const cli = parseCli(process.argv.slice(2));

  // Validate required config
  if (!config.remoteHaproxyId) {
    err('REMOTE_HAPROXY_ID is required');
    process.exit(EXIT_CODES.NEGOTIATION_FAILED);
  }

  if (!config.sslDomain) {
    err('SSL_DOMAIN is required');
    process.exit(EXIT_CODES.NEGOTIATION_FAILED);
  }

  log(`Starting tunnel-manager for ${config.sslDomain}`);
  log(`  Remote HAProxy: ${config.remoteHaproxyId.substring(0, 16)}...`);
  log(`  Tunnel mode: ${config.tunnelMode}`);
  log(`  Transport: ${config.tunnelTransport}`);
  log(`  Relays: ${config.tunnelRelayUrls.length}`);

  // Handle --status
  if (cli.action === 'status') {
    try {
      const { readFileSync } = await import('node:fs');
      const state = JSON.parse(readFileSync('/tmp/.ssl-tunnel-state', 'utf-8'));
      console.log(JSON.stringify(state, null, 2));
      process.exit(0);
    } catch {
      console.log('{ "state": "IDLE" }');
      process.exit(0);
    }
  }

  // Load or create identity
  const identity = loadOrCreateNostrIdentity(config.tunnelIdentityDir);
  const wgKeys = config.tunnelMode === 'full'
    ? loadOrCreateWireguardKeys(config.tunnelIdentityDir)
    : { privateKey: '', publicKey: '' };

  // Create Nostr client
  const nostrClient = new NostrClient(config, identity);

  // Create state machine
  const sm = new TunnelStateMachine(config, identity, wgKeys, nostrClient);

  // Handle --teardown
  if (cli.action === 'teardown') {
    // Load existing correlation_id from state file
    try {
      const { readFileSync } = await import('node:fs');
      const state = JSON.parse(readFileSync('/tmp/.ssl-tunnel-state', 'utf-8'));
      sm.correlationId = state.correlationId;
    } catch {}

    await nostrClient.connect();
    await sm.teardown(TEARDOWN_REASONS.GRACEFUL_SHUTDOWN);
    process.exit(0);
  }

  // Handle SIGTERM/SIGINT for graceful shutdown
  const shutdown = async (signal) => {
    log(`Received ${signal}, initiating graceful teardown...`);
    await sm.teardown(TEARDOWN_REASONS.GRACEFUL_SHUTDOWN, `Received ${signal}`);
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // Start the tunnel
  const exitCode = await sm.start();

  if (exitCode !== EXIT_CODES.SUCCESS) {
    err(`Tunnel startup failed with exit code ${exitCode}`);
    process.exit(exitCode);
  }

  // If --wait-ready was specified, we've already waited (start() blocks until ACTIVE)
  log('Tunnel manager running. Monitoring tunnel health...');

  // Keep the process alive (timers in state machine handle monitoring)
  // The process will exit on SIGTERM or fatal tunnel failure
  if (cli.waitReady) {
    // In wait-ready mode, we just need to return success
    // The state machine's timers will keep running in the background
    // since ssl-setup will source the env and continue
    log('Tunnel ready — returning control to ssl-setup');
  }

  // Set up a timeout if specified
  if (cli.timeout > 0 && !cli.waitReady) {
    setTimeout(() => {
      log(`Timeout (${cli.timeout}s) reached`);
    }, cli.timeout * 1000);
  }
}

main().catch((e) => {
  err(`Unhandled error: ${e.message}`);
  console.error(e.stack);
  process.exit(EXIT_CODES.TUNNEL_FAILED);
});
