/**
 * Server-side daemon configuration.
 */

import { readFileSync, existsSync } from 'node:fs';
import { execSync, execFileSync } from 'node:child_process';

export function loadConfig() {
  const config = {
    // Identity
    identityFile: process.env.TUNNEL_DAEMON_IDENTITY || '/run/secrets/tunnel-daemon-identity',

    // Network
    tunnelSubnet: process.env.TUNNEL_SUBNET || '10.200.0.0/24',
    tunnelWgPort: parseInt(process.env.TUNNEL_WG_PORT || '51820', 10),
    tunnelWssPort: parseInt(process.env.TUNNEL_WSS_PORT || '8443', 10),
    tunnelWssSni: process.env.TUNNEL_WSS_SNI || '',

    // ACL
    aclFile: process.env.TUNNEL_ACL_FILE || '/etc/haproxy-tunnel/acl.json',

    // Limits
    tunnelPublicIp: process.env.TUNNEL_PUBLIC_IP || '',
    tunnelMaxPeers: parseInt(process.env.TUNNEL_MAX_PEERS || '250', 10),
    tunnelIpCooldown: parseInt(process.env.TUNNEL_IP_COOLDOWN || '30', 10),

    // HAProxy
    haproxyApiSocket: process.env.HAPROXY_API_SOCKET || '/var/run/haproxy/admin.sock',
    haproxyApiPort: parseInt(process.env.HAPROXY_API_PORT || '8404', 10),

    // Nostr relays
    relayUrls: (process.env.TUNNEL_RELAY_URLS || 'wss://relay.primal.net,wss://relay.damus.io,wss://nos.lol,wss://relay.nostr.band')
      .split(',').map(s => s.trim()).filter(Boolean),

    // Monitoring
    monitorPort: parseInt(process.env.TUNNEL_MONITOR_PORT || '9100', 10),

    // Tunnel health
    tunnelStaleThreshold: parseInt(process.env.TUNNEL_STALE_THRESHOLD || '2700', 10), // 45 min
    drainingGracePeriod: parseInt(process.env.TUNNEL_DRAINING_GRACE || '120', 10), // 2 min
  };

  // Auto-detect public IP if not set
  if (!config.tunnelPublicIp) {
    try {
      config.tunnelPublicIp = execFileSync('curl', ['-sf', 'https://ifconfig.me'], {
        encoding: 'utf-8',
        timeout: 10000,
      }).trim();
    } catch {
      config.tunnelPublicIp = '0.0.0.0';
    }
  }

  return config;
}

/**
 * Load the domain-scoped ACL configuration.
 */
export function loadAcl(aclFile) {
  if (!existsSync(aclFile)) {
    console.error(`[tunnel-daemon] ACL file not found: ${aclFile}`);
    return { acl: [] };
  }

  try {
    return JSON.parse(readFileSync(aclFile, 'utf-8'));
  } catch (e) {
    console.error(`[tunnel-daemon] Failed to parse ACL: ${e.message}`);
    return { acl: [] };
  }
}

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

/**
 * Validate a domain name per RFC 1123.
 */
function validateDomain(domain) {
  if (typeof domain !== 'string') return false;
  return DOMAIN_RE.test(domain);
}

/**
 * Check if a client npub is authorized for the given domains.
 */
export function checkAcl(acl, clientNpub, primaryDomain, aliases = []) {
  const entry = acl.acl?.find(e => e.npub === clientNpub);
  if (!entry) {
    return { authorized: false, error: 'ERR_ACL_DENIED' };
  }

  const allDomains = [primaryDomain, ...aliases];
  for (const domain of allDomains) {
    // Validate domain format before ACL check
    if (!validateDomain(domain)) {
      return { authorized: false, error: 'ERR_DOMAIN_INVALID', domain };
    }
    if (!domainMatchesPatterns(domain, entry.domains)) {
      return { authorized: false, error: 'ERR_DOMAIN_UNAUTHORIZED', domain };
    }
  }

  return { authorized: true };
}

/**
 * Check if a domain matches any of the patterns.
 * Supports exact match and wildcard (*.example.com).
 */
function domainMatchesPatterns(domain, patterns) {
  for (const pattern of patterns) {
    if (pattern === domain) return true;
    if (pattern.startsWith('*.')) {
      // Keep the dot: ".example.com" so "evil-example.com" doesn't match
      const suffix = pattern.substring(1); // e.g., ".example.com"
      if (domain.endsWith(suffix) && domain.length > suffix.length - 1) {
        return true;
      }
    }
  }
  return false;
}
