/**
 * WireGuard tunnel management.
 *
 * Handles WireGuard interface configuration, split routing, tunnel
 * health monitoring, and reconnection.
 */

import { execSync, exec } from 'node:child_process';
import { writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { hostname } from 'node:os';

const LOG_PREFIX = '[tunnel-manager:wireguard]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }
function err(msg) { console.error(`${LOG_PREFIX} ERROR: ${msg}`); }

const WG_CONF_PATH = '/etc/wireguard/wg0.conf';

/**
 * Check if WireGuard is available (kernel module or wireguard-go).
 * Returns { available: boolean, method: string }.
 */
export function checkWireGuardAvailability() {
  // Try kernel module
  try {
    execSync('modprobe wireguard 2>/dev/null || modinfo wireguard 2>/dev/null', {
      stdio: 'pipe',
      shell: '/bin/bash',
    });
    return { available: true, method: 'kernel' };
  } catch {}

  // Try wireguard-go
  try {
    execSync('which wireguard-go', { stdio: 'pipe' });
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
    const output = execSync("ip -o addr show | awk '{print $4}'", {
      encoding: 'utf-8',
      shell: '/bin/bash',
    });

    for (const line of output.split('\n')) {
      const cidr = line.trim();
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
  try {
    execSync('mkdir -p /etc/wireguard', { stdio: 'pipe' });
  } catch {}

  writeFileSync(WG_CONF_PATH, config, { mode: 0o600 });
  log(`WireGuard config written to ${WG_CONF_PATH}`);

  return WG_CONF_PATH;
}

/**
 * Bring up the WireGuard interface.
 */
export function wgUp() {
  try {
    execSync('wg-quick up wg0', { stdio: 'pipe', shell: '/bin/bash' });
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
    execSync('wg-quick down wg0 2>/dev/null || true', { stdio: 'pipe', shell: '/bin/bash' });
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
    const output = execSync('wg show wg0 latest-handshakes', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
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
    const output = execSync('wg show wg0 transfer', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
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
  try {
    const output = execSync(
      `ping -c 1 -W ${timeoutSeconds} ${serverIp} 2>/dev/null | grep 'time=' | sed 's/.*time=\\([0-9.]*\\).*/\\1/'`,
      { encoding: 'utf-8', shell: '/bin/bash' }
    );
    const rtt = parseFloat(output.trim());
    return isNaN(rtt) ? null : rtt;
  } catch {
    return null;
  }
}

/**
 * Verify HAProxy API reachability through the tunnel.
 */
export function verifyHaproxyApi(serverIp, apiPort = 8404) {
  try {
    execSync(`curl -sf --max-time 5 http://${serverIp}:${apiPort}/v1/health >/dev/null 2>&1`, {
      stdio: 'pipe',
      shell: '/bin/bash',
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
    execSync('getent hosts localhost >/dev/null 2>&1', { stdio: 'pipe' });
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
