/**
 * HAProxy runtime API integration.
 *
 * Manages HAProxy backends via the runtime API for tunnel peers.
 * Uses Node.js native http module instead of shell curl to prevent
 * command injection vulnerabilities.
 */

import * as http from 'node:http';
import { execFileSync } from 'node:child_process';

const LOG_PREFIX = '[tunnel-daemon:haproxy]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }
function err(msg) { console.error(`${LOG_PREFIX} ERROR: ${msg}`); }

/**
 * Synchronous HTTP request using a Node child process.
 * Avoids shell interpolation entirely -- no command injection possible.
 * Returns { statusCode, body }.
 */
function httpRequestSync(method, urlStr, options = {}) {
  const { body = null, headers = {}, timeout = 10000 } = options;

  // Build a self-contained Node script that reads payload from stdin (avoids
  // template literal injection -- JSON.stringify does not escape backticks)
  const scriptPayload = JSON.stringify({ method, urlStr, headers, body, timeout });
  const script = `
    const http = require('node:http');
    const input = JSON.parse(require('node:fs').readFileSync('/dev/stdin', 'utf-8'));
    const parsed = new URL(input.urlStr);
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 80,
      path: parsed.pathname + parsed.search,
      method: input.method,
      headers: input.headers,
      timeout: input.timeout,
    };
    const req = http.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        process.stdout.write(JSON.stringify({
          statusCode: res.statusCode,
          body: Buffer.concat(chunks).toString('utf-8'),
        }));
      });
    });
    req.on('error', (e) => {
      process.stderr.write(e.message);
      process.exit(1);
    });
    req.on('timeout', () => {
      req.destroy(new Error('Request timed out'));
    });
    if (input.body !== null) {
      req.write(input.body);
    }
    req.end();
  `;

  const result = execFileSync('node', ['-e', script], {
    input: scriptPayload,
    encoding: 'utf-8',
    timeout: timeout + 5000,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  return JSON.parse(result);
}

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

  const headers = { 'Content-Type': 'application/json' };
  if (sessionKey) {
    headers['Authorization'] = `Bearer ${sessionKey}`;
  }

  try {
    const result = httpRequestSync('POST', `http://${apiHost}:${apiPort}/v1/backends`, {
      body: payload,
      headers,
      timeout: 10000,
    });

    if (result.statusCode === 200 || result.statusCode === 201) {
      log(`Registered backend: ${domain} -> ${peerIp}:${httpPort}/${httpsPort || 'null'}`);
      return true;
    }

    warn(`Backend registration returned status ${result.statusCode} for ${domain}`);
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
  const headers = {};
  if (sessionKey) {
    headers['Authorization'] = `Bearer ${sessionKey}`;
  }

  try {
    const result = httpRequestSync('DELETE', `http://${apiHost}:${apiPort}/v1/backends/${encodeURIComponent(domain)}`, {
      headers,
      timeout: 10000,
    });

    if (result.statusCode === 204 || result.statusCode === 200 || result.statusCode === 404) {
      log(`Deregistered backend: ${domain}`);
      return true;
    }

    warn(`Deregister returned status ${result.statusCode} for ${domain}`);
    return false;
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
    const result = httpRequestSync('GET', `http://${apiHost}:${apiPort}/v1/health`, {
      timeout: 5000,
    });
    return JSON.parse(result.body);
  } catch {
    return null;
  }
}
