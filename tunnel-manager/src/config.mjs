/**
 * Configuration loader — reads environment variables and CLI args.
 */

import { DEFAULT_RELAY_URLS } from './constants.mjs';

export function loadConfig() {
  const config = {
    // Required
    remoteHaproxyId: process.env.REMOTE_HAPROXY_ID || '',
    sslDomain: process.env.SSL_DOMAIN || '',

    // Tunnel settings
    tunnelMode: process.env.TUNNEL_MODE || 'full',
    tunnelTransport: process.env.TUNNEL_TRANSPORT || 'auto',
    tunnelRelayUrls: (process.env.TUNNEL_RELAY_URLS || DEFAULT_RELAY_URLS.join(',')).split(',').map(s => s.trim()).filter(Boolean),
    tunnelIdentityDir: process.env.TUNNEL_IDENTITY_DIR || '/etc/letsencrypt/tunnel-identity',
    tunnelNegotiateTimeout: parseInt(process.env.TUNNEL_NEGOTIATE_TIMEOUT || '60', 10) * 1000,
    tunnelHeartbeatInterval: parseInt(process.env.TUNNEL_HEARTBEAT_INTERVAL || '900', 10) * 1000,
    tunnelReconnectMax: parseInt(process.env.TUNNEL_RECONNECT_MAX || '10', 10),
    tunnelReconnectJitter: parseInt(process.env.TUNNEL_RECONNECT_JITTER || '60', 10),

    // SSL settings
    sslHttpsPort: parseInt(process.env.SSL_HTTPS_PORT || '443', 10),
    appHttpPort: parseInt(process.env.APP_HTTP_PORT || '0', 10),
    sslDomainAliases: (process.env.SSL_DOMAIN_ALIASES || '').split(',').map(s => s.trim()).filter(Boolean),
    sslAliasProxyPort: parseInt(process.env.SSL_ALIAS_PROXY_PORT || '8444', 10),
    extraPorts: process.env.EXTRA_PORTS ? JSON.parse(process.env.EXTRA_PORTS) : [],

    // DynDNS
    dyndnsProvider: process.env.DYNDNS_PROVIDER || '',

    // HAProxy
    haproxyApiPort: parseInt(process.env.HAPROXY_API_PORT || '8404', 10),
  };

  return config;
}

/**
 * Parse CLI arguments (--start, --wait-ready, --timeout, --teardown).
 */
export function parseCli(args) {
  const cli = {
    action: 'start',  // start | teardown | status
    waitReady: false,
    timeout: 300,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--start':
        cli.action = 'start';
        break;
      case '--teardown':
        cli.action = 'teardown';
        break;
      case '--status':
        cli.action = 'status';
        break;
      case '--wait-ready':
        cli.waitReady = true;
        break;
      case '--timeout':
        cli.timeout = parseInt(args[++i], 10);
        break;
    }
  }

  return cli;
}
