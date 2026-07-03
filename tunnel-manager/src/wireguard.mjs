/**
 * WireGuard tunnel management.
 *
 * Handles WireGuard interface configuration, split routing, tunnel
 * health monitoring, and reconnection.
 */

import { execSync, execFileSync, exec } from 'node:child_process';
import { writeFileSync, existsSync, unlinkSync, mkdirSync } from 'node:fs';
import { hostname } from 'node:os';

const LOG_PREFIX = '[tunnel-manager:wireguard]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }
function err(msg) { console.error(`${LOG_PREFIX} ERROR: ${msg}`); }

const WG_CONF_PATH = '/etc/wireguard/wg0.conf';

/**
 * Input validation functions.
 */
function validateIpv4(ip) {
  if (typeof ip !== 'string' || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    throw new Error('Invalid IPv4 address format');
  }
  const parts = ip.split('.').map(Number);
  if (parts.some(p => p < 0 || p > 255)) throw new Error('IPv4 octet out of range');
}

function validatePort(port) {
  const p = parseInt(port, 10);
  if (isNaN(p) || p < 1 || p > 65535) throw new Error('Invalid port number');
  return p;
}

/**
 * Check if WireGuard is available (kernel module or wireguard-go).
 * Returns { available: boolean, method: string }.
 */
export function checkWireGuardAvailability() {
  // Try kernel module -- need shell for the || fallback
  try {
    execSync('modprobe wireguard 2>/dev/null || modinfo wireguard 2>/dev/null', {
      stdio: 'pipe',
      shell: '/bin/bash',
      timeout: 30000,
    });
    return { available: true, method: 'kernel' };
  } catch {}

  // Try wireguard-go
  try {
    execFileSync('which', ['wireguard-go'], { stdio: 'pipe', timeout: 30000 });
    return { available: true, method: 'wireguard-go' };
  } catch {}

  return { available: false, method: 'none' };
}

/**
 * Detect Docker bridge subnets by inspecting network interfaces.
 * Returns array of CIDR strings to exclude from WireGuard routing.
 */
export function detectDockerSubnets() {
  const subnets = new Set([
    '127.0.0.0/8',       // loopback (always exclude)
    '172.16.0.0/12',     // Docker default bridge range
  ]);

  try {
    const output = execFileSync('ip', ['-o', 'addr', 'show'], {
      encoding: 'utf-8',
      timeout: 30000,
    });

    for (const line of output.split('\n')) {
      // Extract CIDR from ip -o addr show output (field 4)
      const fields = line.trim().split(/\s+/);
      const cidr = fields[3] || '';
      if (!cidr || cidr.includes(':')) continue; // skip IPv6

      // If it's in a Docker range, add the subnet
      if (cidr.startsWith('172.') || cidr.startsWith('10.') || cidr.startsWith('192.168.')) {
        // Convert host address to subnet
        const parts = cidr.split('/');
        if (parts.length === 2) {
          subnets.add(cidr);
        }
      }
    }
  } catch (e) {
    warn(`Failed to detect Docker subnets: ${e.message}`);
  }

  return Array.from(subnets);
}

/**
 * Write WireGuard configuration with split-routing PostUp rules.
 */
export function writeWireGuardConfig(offer, clientPrivateKey) {
  const auth = offer.payload.auth;
  const transports = offer.payload.transports || [];

  // Determine endpoint based on selected transport
  let endpoint = '';
  for (const t of transports) {
    if (t.type === 'udp') {
      endpoint = t.endpoint;
      break;
    }
  }
  if (!endpoint && transports.length > 0) {
    endpoint = transports[0].endpoint;
  }

  // Detect subnets to exclude from WireGuard routing
  const excludedSubnets = detectDockerSubnets();

  // Build PostUp rules for split routing
  const postUpRules = [
    // Docker DNS must stay local (highest priority)
    'ip rule add to 127.0.0.11/32 lookup main priority 9',
    // Loopback stays local
    'ip rule add to 127.0.0.0/8 lookup main priority 10',
    // Docker bridge networks stay local
    'ip rule add to 172.16.0.0/12 lookup main priority 11',
  ];

  // PostDown rules to clean up
  const postDownRules = [
    'ip rule del to 127.0.0.11/32 lookup main priority 9 2>/dev/null || true',
    'ip rule del to 127.0.0.0/8 lookup main priority 10 2>/dev/null || true',
    'ip rule del to 172.16.0.0/12 lookup main priority 11 2>/dev/null || true',
  ];

  const config = `[Interface]
PrivateKey = ${clientPrivateKey}
Address = ${auth.client_ip_alloc}
${postUpRules.map(r => `PostUp = ${r}`).join('\n')}
${postDownRules.map(r => `PostDown = ${r}`).join('\n')}

[Peer]
PublicKey = ${auth.server_wg_pubkey}
${auth.preshared_key_enc ? `PresharedKey = ${auth.preshared_key_enc}` : ''}
Endpoint = ${endpoint}
AllowedIPs = ${auth.allowed_ips || '0.0.0.0/0'}
PersistentKeepalive = 25
`;

  // Ensure directory exists
  mkdirSync('/etc/wireguard', { recursive: true, mode: 0o700 });

  writeFileSync(WG_CONF_PATH, config, { mode: 0o600 });
  log(`WireGuard config written to ${WG_CONF_PATH}`);

  return WG_CONF_PATH;
}

/**
 * Bring up the WireGuard interface.
 */
export function wgUp() {
  try {
    execFileSync('wg-quick', ['up', 'wg0'], { stdio: 'pipe', timeout: 30000 });
    log('WireGuard interface wg0 is up');
    return true;
  } catch (e) {
    err(`Failed to bring up wg0: ${e.stderr?.toString() || e.message}`);
    return false;
  }
}

/**
 * Bring down the WireGuard interface.
 */
export function wgDown() {
  try {
    // wg-quick down can fail if interface doesn't exist; that's ok
    execSync('wg-quick down wg0 2>/dev/null || true', { stdio: 'pipe', shell: '/bin/bash', timeout: 30000 });
    log('WireGuard interface wg0 is down');
  } catch (e) {
    warn(`Error bringing down wg0: ${e.message}`);
  }
}

/**
 * Get the latest WireGuard handshake timestamp (seconds since epoch).
 * Returns null if no handshake has occurred.
 */
export function getLatestHandshake() {
  try {
    const output = execFileSync('wg', ['show', 'wg0', 'latest-handshakes'], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 30000,
    });

    for (const line of output.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2) {
        const ts = parseInt(parts[1], 10);
        if (ts > 0) return ts;
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Check if the WireGuard handshake is fresh (within staleThresholdMs).
 */
export function isHandshakeFresh(staleThresholdMs = 180_000) {
  const lastHandshake = getLatestHandshake();
  if (lastHandshake === null) return false;

  const ageMs = (Date.now() / 1000 - lastHandshake) * 1000;
  return ageMs < staleThresholdMs;
}

/**
 * Get WireGuard interface statistics.
 * Returns { rxBytes, txBytes, latestHandshake }.
 */
export function getWgStats() {
  try {
    const output = execFileSync('wg', ['show', 'wg0', 'transfer'], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 30000,
    });

    for (const line of output.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        return {
          rxBytes: parseInt(parts[1], 10) || 0,
          txBytes: parseInt(parts[2], 10) || 0,
          latestHandshake: getLatestHandshake(),
        };
      }
    }
  } catch {}

  return { rxBytes: 0, txBytes: 0, latestHandshake: null };
}

/**
 * Verify connectivity through the tunnel by pinging the server IP.
 * Returns RTT in milliseconds or null on failure.
 */
export function verifyConnectivity(serverIp, timeoutSeconds = 5) {
  validateIpv4(serverIp);
  try {
    const output = execFileSync('ping', ['-c', '1', '-W', String(timeoutSeconds), serverIp], {
      encoding: 'utf-8',
      timeout: (timeoutSeconds + 5) * 1000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const match = output.match(/time=([0-9.]+)/);
    const rtt = match ? parseFloat(match[1]) : NaN;
    return isNaN(rtt) ? null : rtt;
  } catch {
    return null;
  }
}

/**
 * Verify HAProxy API reachability through the tunnel.
 */
export function verifyHaproxyApi(serverIp, apiPort = 8404) {
  validateIpv4(serverIp);
  const port = validatePort(apiPort);
  try {
    execFileSync('curl', ['-sf', '--max-time', '5', `http://${serverIp}:${port}/v1/health`], {
      stdio: 'pipe',
      timeout: 10000,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify Docker DNS still works after tunnel setup.
 */
export function verifyDockerDns() {
  try {
    execFileSync('getent', ['hosts', 'localhost'], { stdio: 'pipe', timeout: 30000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Clean up WireGuard configuration file.
 */
export function cleanupWgConfig() {
  try {
    if (existsSync(WG_CONF_PATH)) {
      unlinkSync(WG_CONF_PATH);
    }
  } catch {}
}
