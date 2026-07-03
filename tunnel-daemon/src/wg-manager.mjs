/**
 * Server-side WireGuard peer management.
 *
 * Adds/removes WireGuard peers, configures iptables NAT rules,
 * and monitors peer health via handshake timestamps.
 */

import { execSync, execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import * as crypto from 'node:crypto';
import { join } from 'node:path';

const LOG_PREFIX = '[tunnel-daemon:wg]';

/**
 * Input validation functions to prevent command injection.
 */
function validateWgKey(key) {
  if (typeof key !== 'string' || !/^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]=$/.test(key)) {
    throw new Error('Invalid WireGuard key format');
  }
}

function validateIpv4(ip) {
  if (typeof ip !== 'string' || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    throw new Error('Invalid IPv4 address format');
  }
  const parts = ip.split('.').map(Number);
  if (parts.some(p => p < 0 || p > 255)) throw new Error('IPv4 octet out of range');
}

function validateSubnet(subnet) {
  if (typeof subnet !== 'string') throw new Error('Invalid subnet format');
  const match = subnet.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if (!match) throw new Error('Invalid subnet format');
  validateIpv4(match[1]);
  const prefix = parseInt(match[2], 10);
  if (prefix < 8 || prefix > 30) throw new Error('Subnet prefix out of range');
}

function validatePort(port) {
  const p = parseInt(port, 10);
  if (isNaN(p) || p < 1 || p > 65535) throw new Error('Invalid port number');
  return p;
}

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }
function err(msg) { console.error(`${LOG_PREFIX} ERROR: ${msg}`); }

/**
 * Initialize the WireGuard server interface.
 */
export function initWireGuardServer(config) {
  try {
    // Check if wg0 already exists
    try {
      execFileSync('ip', ['link', 'show', 'wg0'], { stdio: 'pipe', timeout: 30000 });
      log('WireGuard interface wg0 already exists');
      return true;
    } catch {}

    // Generate server key if not exists
    const keyDir = '/var/lib/haproxy-tunnel';
    mkdirSync(keyDir, { recursive: true, mode: 0o700 });

    let serverPrivateKey, serverPublicKey;
    try {
      serverPrivateKey = readFileSync(join(keyDir, 'server-private.key'), 'utf-8').trim();
      serverPublicKey = readFileSync(join(keyDir, 'server-public.key'), 'utf-8').trim();
    } catch {
      serverPrivateKey = execFileSync('wg', ['genkey'], { encoding: 'utf-8', timeout: 30000 }).trim();
      serverPublicKey = execSync('wg pubkey', {
        input: serverPrivateKey + '\n',
        encoding: 'utf-8',
        timeout: 30000,
      }).trim();
      writeFileSync(join(keyDir, 'server-private.key'), serverPrivateKey + '\n', { mode: 0o600 });
      writeFileSync(join(keyDir, 'server-public.key'), serverPublicKey + '\n', { mode: 0o600 });
    }

    // Create wg0 interface
    validateSubnet(config.tunnelSubnet);
    const serverIp = config.tunnelSubnet.replace(/\.0\//, '.1/');
    const wgPort = validatePort(config.tunnelWgPort);
    execFileSync('ip', ['link', 'add', 'wg0', 'type', 'wireguard'], { stdio: 'pipe', timeout: 30000 });
    execFileSync('ip', ['addr', 'add', serverIp, 'dev', 'wg0'], { stdio: 'pipe', timeout: 30000 });
    execFileSync('wg', ['set', 'wg0', 'private-key', join(keyDir, 'server-private.key'), 'listen-port', String(wgPort)], {
      stdio: 'pipe', timeout: 30000,
    });
    execFileSync('ip', ['link', 'set', 'wg0', 'up'], { stdio: 'pipe', timeout: 30000 });

    log(`WireGuard server initialized: ${serverIp}, port ${wgPort}`);
    return true;
  } catch (e) {
    err(`Failed to initialize WireGuard: ${e.message}`);
    return false;
  }
}

/**
 * Get the server's WireGuard public key.
 */
export function getServerPublicKey() {
  try {
    return readFileSync('/var/lib/haproxy-tunnel/server-public.key', 'utf-8').trim();
  } catch {
    return '';
  }
}

/**
 * Add a WireGuard peer.
 */
export function addPeer(clientPublicKey, clientIp, presharedKey = null) {
  validateWgKey(clientPublicKey);
  validateIpv4(clientIp);

  let pskTempFile = null;
  try {
    const args = ['set', 'wg0', 'peer', clientPublicKey, 'allowed-ips', `${clientIp}/32`];
    if (presharedKey) {
      validateWgKey(presharedKey);
      pskTempFile = join('/tmp', `.wg-psk-${crypto.randomUUID()}`);
      writeFileSync(pskTempFile, presharedKey + '\n', { mode: 0o600 });
      args.push('preshared-key', pskTempFile);
    }
    execFileSync('wg', args, { stdio: 'pipe', timeout: 30000 });

    log(`Added peer: ${clientPublicKey.substring(0, 12)}... -> ${clientIp}`);
    return true;
  } catch (e) {
    err(`Failed to add peer: ${e.message}`);
    return false;
  } finally {
    if (pskTempFile) {
      try { unlinkSync(pskTempFile); } catch {}
    }
  }
}

/**
 * Remove a WireGuard peer.
 */
export function removePeer(clientPublicKey) {
  validateWgKey(clientPublicKey);
  try {
    execFileSync('wg', ['set', 'wg0', 'peer', clientPublicKey, 'remove'], { stdio: 'pipe', timeout: 30000 });
    log(`Removed peer: ${clientPublicKey.substring(0, 12)}...`);
    return true;
  } catch (e) {
    warn(`Failed to remove peer: ${e.message}`);
    return false;
  }
}

/**
 * Get handshake timestamps for all peers.
 * Returns Map<publicKey, lastHandshakeEpoch>.
 */
export function getPeerHandshakes() {
  const handshakes = new Map();
  try {
    const output = execFileSync('wg', ['show', 'wg0', 'latest-handshakes'], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 30000,
    });

    for (const line of output.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2) {
        handshakes.set(parts[0], parseInt(parts[1], 10));
      }
    }
  } catch {}
  return handshakes;
}

/**
 * Get transfer stats for all peers.
 * Returns Map<publicKey, { rx, tx }>.
 */
export function getPeerTransfer() {
  const stats = new Map();
  try {
    const output = execFileSync('wg', ['show', 'wg0', 'transfer'], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 30000,
    });

    for (const line of output.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        stats.set(parts[0], {
          rx: parseInt(parts[1], 10) || 0,
          tx: parseInt(parts[2], 10) || 0,
        });
      }
    }
  } catch {}
  return stats;
}

/**
 * Set up iptables NAT rules for tunnel clients.
 */
export function setupIptablesRules(subnet, haproxyApiPort = 8404) {
  validateSubnet(subnet);
  const port = validatePort(haproxyApiPort);
  const serverIpForSubnet = subnet.replace(/\.0\//, '.1');

  const rules = [
    // NAT masquerade for client egress
    ['-t', 'nat', '-A', 'POSTROUTING', '-s', subnet, '-o', 'eth0', '-j', 'MASQUERADE'],
    // ALLOW: WireGuard peers to HAProxy API
    ['-A', 'FORWARD', '-s', subnet, '-d', serverIpForSubnet, '-p', 'tcp', '--dport', String(port), '-j', 'ACCEPT'],
    // DENY: inter-peer traffic
    ['-A', 'FORWARD', '-s', subnet, '-d', subnet, '-j', 'DROP'],
    // DENY: cloud metadata endpoint
    ['-A', 'FORWARD', '-s', subnet, '-d', '169.254.169.254', '-j', 'DROP'],
    // DENY: private subnets
    ['-A', 'FORWARD', '-s', subnet, '-d', '172.16.0.0/12', '-j', 'DROP'],
    ['-A', 'FORWARD', '-s', subnet, '-d', '192.168.0.0/16', '-j', 'DROP'],
    ['-A', 'FORWARD', '-s', subnet, '-d', '10.0.0.0/8', '-j', 'DROP'],
    // ALLOW: internet-routable destinations
    ['-A', 'FORWARD', '-s', subnet, '-j', 'ACCEPT'],
  ];

  // Enable IP forwarding
  try {
    execFileSync('sysctl', ['-w', 'net.ipv4.ip_forward=1'], { stdio: 'pipe', timeout: 30000 });
  } catch (e) {
    warn(`Failed to enable IP forwarding: ${e.message}`);
  }

  for (const ruleArgs of rules) {
    try {
      // Check if rule already exists (idempotent)
      const checkArgs = ruleArgs.map(a => a === '-A' ? '-C' : a);
      try {
        execFileSync('iptables', checkArgs, { stdio: 'pipe', timeout: 30000 });
        continue; // Rule already exists
      } catch {}

      execFileSync('iptables', ruleArgs, { stdio: 'pipe', timeout: 30000 });
    } catch (e) {
      warn(`Failed to add iptables rule: ${ruleArgs.join(' ')} -- ${e.message}`);
    }
  }

  log('iptables NAT rules configured');
}

/**
 * Remove iptables rules for a specific client IP.
 */
export function removeClientIptables(clientIp) {
  validateIpv4(clientIp);
  // Individual client rules are handled by the FORWARD chain subnet rules
  // No per-client iptables management needed with the current design
  log(`Cleaned up iptables for ${clientIp}`);
}

/**
 * Generate a random preshared key.
 */
export function generatePresharedKey() {
  try {
    return execFileSync('wg', ['genpsk'], { encoding: 'utf-8', timeout: 30000 }).trim();
  } catch {
    // Fallback to openssl
    return execFileSync('openssl', ['rand', '-base64', '32'], { encoding: 'utf-8', timeout: 30000 }).trim();
  }
}
