/**
 * HAProxy runtime API integration.
 *
 * Manages HAProxy backends via the runtime API for tunnel peers.
 * Uses the HAProxy Runtime API (Unix socket or HTTP) to add/remove
 * backends pointing to WireGuard peer IPs.
 */

import { execSync } from 'node:child_process';

const LOG_PREFIX = '[tunnel-daemon:haproxy]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }
function err(msg) { console.error(`${LOG_PREFIX} ERROR: ${msg}`); }

/**
 * Register a backend with HAProxy for a tunnel peer.
 *
 * @param {Object} opts
 * @param {string} opts.domain - Domain name
 * @param {string} opts.peerIp - WireGuard peer IP
 * @param {number} opts.httpPort - HTTP port (usually 80)
 * @param {number|null} opts.httpsPort - HTTPS port (null for HTTP-only)
 * @param {Array} opts.extraPorts - Extra port mappings
 * @param {string} opts.apiHost - HAProxy API host (usually 10.200.0.1 or localhost)
 * @param {number} opts.apiPort - HAProxy API port
 * @param {string} opts.sessionKey - Session bearer token
 */
export function registerBackend(opts) {
  const {
    domain,
    peerIp,
    httpPort = 80,
    httpsPort = null,
    extraPorts = [],
    apiHost = 'localhost',
    apiPort = 8404,
    sessionKey = '',
  } = opts;

  const payload = JSON.stringify({
    domain,
    container: peerIp, // Use WireGuard IP as "container" identifier
    http_port: httpPort,
    https_port: httpsPort,
    extra_ports: extraPorts.length > 0 ? extraPorts : null,
    tunnel_peer_ip: peerIp, // Mark as tunnel backend
  });

  const authHeader = sessionKey ? `-H "Authorization: Bearer ${sessionKey}"` : '';

  try {
    const result = execSync(
      `curl -sf -o /dev/null -w '%{http_code}' -X POST "http://${apiHost}:${apiPort}/v1/backends" ` +
      `-H "Content-Type: application/json" ${authHeader} -d '${payload}' --max-time 10`,
      { encoding: 'utf-8', shell: '/bin/bash', stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();

    if (result === '200' || result === '201') {
      log(`Registered backend: ${domain} -> ${peerIp}:${httpPort}/${httpsPort || 'null'}`);
      return true;
    }

    warn(`Backend registration returned status ${result} for ${domain}`);
    return false;
  } catch (e) {
    err(`Failed to register backend ${domain}: ${e.message}`);
    return false;
  }
}

/**
 * Deregister a backend from HAProxy.
 */
export function deregisterBackend(domain, apiHost = 'localhost', apiPort = 8404, sessionKey = '') {
  const authHeader = sessionKey ? `-H "Authorization: Bearer ${sessionKey}"` : '';

  try {
    execSync(
      `curl -sf -o /dev/null -X DELETE "http://${apiHost}:${apiPort}/v1/backends/${domain}" ` +
      `${authHeader} --max-time 10`,
      { shell: '/bin/bash', stdio: 'pipe' }
    );
    log(`Deregistered backend: ${domain}`);
    return true;
  } catch (e) {
    warn(`Failed to deregister backend ${domain}: ${e.message}`);
    return false;
  }
}

/**
 * Register all backends for a tunnel session.
 */
export function registerSessionBackends(session, peerIp, apiHost, apiPort) {
  const results = [];

  // Primary domain
  results.push({
    domain: session.primaryDomain,
    success: registerBackend({
      domain: session.primaryDomain,
      peerIp,
      httpPort: 80,
      httpsPort: null, // HTTP-only initially
      apiHost,
      apiPort,
      sessionKey: session.sessionKey,
    }),
  });

  // Aliases
  for (const alias of session.aliases) {
    results.push({
      domain: alias,
      success: registerBackend({
        domain: alias,
        peerIp,
        httpPort: 80,
        httpsPort: null,
        apiHost,
        apiPort,
        sessionKey: session.sessionKey,
      }),
    });
  }

  return results;
}

/**
 * Deregister all backends for a tunnel session.
 */
export function deregisterSessionBackends(session, apiHost, apiPort) {
  deregisterBackend(session.primaryDomain, apiHost, apiPort, session.sessionKey);
  for (const alias of session.aliases) {
    deregisterBackend(alias, apiHost, apiPort, session.sessionKey);
  }
}

/**
 * Check HAProxy health.
 */
export function checkHealth(apiHost = 'localhost', apiPort = 8404) {
  try {
    const result = execSync(
      `curl -sf --max-time 5 "http://${apiHost}:${apiPort}/v1/health"`,
      { encoding: 'utf-8', shell: '/bin/bash', stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();
    return JSON.parse(result);
  } catch {
    return null;
  }
}
