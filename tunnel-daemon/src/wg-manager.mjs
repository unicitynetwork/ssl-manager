/**
 * Server-side WireGuard peer management.
 *
 * Adds/removes WireGuard peers, configures iptables NAT rules,
 * and monitors peer health via handshake timestamps.
 */

import { execSync } from 'node:child_process';

const LOG_PREFIX = '[tunnel-daemon:wg]';

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
      execSync('ip link show wg0', { stdio: 'pipe' });
      log('WireGuard interface wg0 already exists');
      return true;
    } catch {}

    // Generate server key if not exists
    const keyDir = '/var/lib/haproxy-tunnel';
    execSync(`mkdir -p ${keyDir}`, { stdio: 'pipe' });

    let serverPrivateKey, serverPublicKey;
    try {
      serverPrivateKey = execSync(`cat ${keyDir}/server-private.key`, { encoding: 'utf-8' }).trim();
      serverPublicKey = execSync(`cat ${keyDir}/server-public.key`, { encoding: 'utf-8' }).trim();
    } catch {
      serverPrivateKey = execSync('wg genkey', { encoding: 'utf-8' }).trim();
      serverPublicKey = execSync(`echo "${serverPrivateKey}" | wg pubkey`, {
        encoding: 'utf-8', shell: '/bin/bash',
      }).trim();
      execSync(`echo "${serverPrivateKey}" > ${keyDir}/server-private.key && chmod 600 ${keyDir}/server-private.key`, {
        shell: '/bin/bash',
      });
      execSync(`echo "${serverPublicKey}" > ${keyDir}/server-public.key`, { shell: '/bin/bash' });
    }

    // Create wg0 interface
    const serverIp = config.tunnelSubnet.replace(/\.0\//, '.1/');
    execSync(`ip link add wg0 type wireguard`, { stdio: 'pipe' });
    execSync(`ip addr add ${serverIp} dev wg0`, { stdio: 'pipe' });
    execSync(`wg set wg0 private-key ${keyDir}/server-private.key listen-port ${config.tunnelWgPort}`, {
      stdio: 'pipe',
    });
    execSync(`ip link set wg0 up`, { stdio: 'pipe' });

    log(`WireGuard server initialized: ${serverIp}, port ${config.tunnelWgPort}`);
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
    return execSync('cat /var/lib/haproxy-tunnel/server-public.key', {
      encoding: 'utf-8',
    }).trim();
  } catch {
    return '';
  }
}

/**
 * Add a WireGuard peer.
 */
export function addPeer(clientPublicKey, clientIp, presharedKey = null) {
  try {
    let cmd = `wg set wg0 peer ${clientPublicKey} allowed-ips ${clientIp}/32`;
    if (presharedKey) {
      // Write preshared key to temp file
      execSync(`echo "${presharedKey}" > /tmp/.wg-psk-temp && chmod 600 /tmp/.wg-psk-temp`, {
        shell: '/bin/bash',
      });
      cmd += ` preshared-key /tmp/.wg-psk-temp`;
    }
    execSync(cmd, { stdio: 'pipe', shell: '/bin/bash' });

    // Clean up temp file
    if (presharedKey) {
      execSync('rm -f /tmp/.wg-psk-temp', { stdio: 'pipe' });
    }

    log(`Added peer: ${clientPublicKey.substring(0, 12)}... -> ${clientIp}`);
    return true;
  } catch (e) {
    err(`Failed to add peer: ${e.message}`);
    return false;
  }
}

/**
 * Remove a WireGuard peer.
 */
export function removePeer(clientPublicKey) {
  try {
    execSync(`wg set wg0 peer ${clientPublicKey} remove`, { stdio: 'pipe' });
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
    const output = execSync('wg show wg0 latest-handshakes', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
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
    const output = execSync('wg show wg0 transfer', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
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
  const rules = [
    // NAT masquerade for client egress
    `-t nat -A POSTROUTING -s ${subnet} -o eth0 -j MASQUERADE`,

    // ALLOW: WireGuard peers to HAProxy API
    `-A FORWARD -s ${subnet} -d ${subnet.replace(/\.0\//, '.1')} -p tcp --dport ${haproxyApiPort} -j ACCEPT`,

    // DENY: inter-peer traffic
    `-A FORWARD -s ${subnet} -d ${subnet} -j DROP`,

    // DENY: cloud metadata endpoint
    `-A FORWARD -s ${subnet} -d 169.254.169.254 -j DROP`,

    // DENY: private subnets
    `-A FORWARD -s ${subnet} -d 172.16.0.0/12 -j DROP`,
    `-A FORWARD -s ${subnet} -d 192.168.0.0/16 -j DROP`,
    `-A FORWARD -s ${subnet} -d 10.0.0.0/8 -j DROP`,

    // ALLOW: internet-routable destinations
    `-A FORWARD -s ${subnet} -j ACCEPT`,
  ];

  // Enable IP forwarding
  try {
    execSync('sysctl -w net.ipv4.ip_forward=1', { stdio: 'pipe' });
  } catch (e) {
    warn(`Failed to enable IP forwarding: ${e.message}`);
  }

  for (const rule of rules) {
    try {
      // Check if rule already exists (idempotent)
      const checkRule = rule.replace('-A ', '-C ').replace('-t nat -A ', '-t nat -C ');
      try {
        execSync(`iptables ${checkRule}`, { stdio: 'pipe' });
        continue; // Rule already exists
      } catch {}

      execSync(`iptables ${rule}`, { stdio: 'pipe' });
    } catch (e) {
      warn(`Failed to add iptables rule: ${rule} — ${e.message}`);
    }
  }

  log('iptables NAT rules configured');
}

/**
 * Remove iptables rules for a specific client IP.
 */
export function removeClientIptables(clientIp) {
  // Individual client rules are handled by the FORWARD chain subnet rules
  // No per-client iptables management needed with the current design
  log(`Cleaned up iptables for ${clientIp}`);
}

/**
 * Generate a random preshared key.
 */
export function generatePresharedKey() {
  try {
    return execSync('wg genpsk', { encoding: 'utf-8' }).trim();
  } catch {
    // Fallback to openssl
    return execSync('openssl rand -base64 32', { encoding: 'utf-8' }).trim();
  }
}
