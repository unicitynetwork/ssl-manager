/**
 * Monitoring and metrics server.
 *
 * Exposes REST API at /v1/tunnels and Prometheus metrics at /metrics.
 */

import { createServer } from 'node:http';

const LOG_PREFIX = '[tunnel-daemon:monitor]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }

/**
 * Start the monitoring HTTP server.
 */
export function startMonitorServer(port, sessionManager, ipPool, wgManagerModule) {
  const server = createServer((req, res) => {
    const url = new URL(req.url, `http://localhost:${port}`);

    if (url.pathname === '/v1/tunnels' && req.method === 'GET') {
      handleTunnelsList(res, sessionManager, ipPool, wgManagerModule);
    } else if (url.pathname === '/metrics' && req.method === 'GET') {
      handleMetrics(res, sessionManager, ipPool);
    } else if (url.pathname === '/v1/health' && req.method === 'GET') {
      handleHealth(res, sessionManager, ipPool);
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    }
  });

  server.listen(port, '0.0.0.0', () => {
    log(`Monitor server listening on port ${port}`);
  });

  return server;
}

function handleTunnelsList(res, sessionManager, ipPool, wgManager) {
  const handshakes = wgManager.getPeerHandshakes();
  const transfers = wgManager.getPeerTransfer();
  const sessions = sessionManager.getActiveSessions();
  const poolStats = ipPool.stats();

  const peers = sessions.map(session => {
    const wgKey = session.clientWgPubkey || '';
    const lastHandshake = handshakes.get(wgKey) || 0;
    const transfer = transfers.get(wgKey) || { rx: 0, tx: 0 };
    const handshakeAge = lastHandshake > 0 ? Math.floor(Date.now() / 1000 - lastHandshake) : -1;

    return {
      npub: session.clientNpub,
      peer_ip: session.peerIp,
      primary_domain: session.primaryDomain,
      aliases: session.aliases,
      state: session.state,
      transport: session.transport || 'udp',
      uptime_seconds: session.establishedAt
        ? Math.floor((Date.now() - session.establishedAt) / 1000)
        : 0,
      last_handshake_seconds_ago: handshakeAge,
      rx_bytes: transfer.rx,
      tx_bytes: transfer.tx,
    };
  });

  const body = {
    active_peers: peers.length,
    max_peers: poolStats.total,
    subnet: ipPool.prefix ? `${ipPool.baseIpParts.join('.')}/${ipPool.prefix}` : 'unknown',
    peers,
  };

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body, null, 2));
}

function handleMetrics(res, sessionManager, ipPool) {
  const stats = sessionManager.getStats();
  const poolStats = ipPool.stats();

  const lines = [
    `# HELP tunnel_active_peers Number of active tunnel peers`,
    `# TYPE tunnel_active_peers gauge`,
    `tunnel_active_peers ${stats.byState?.ACTIVE || 0}`,
    ``,
    `# HELP tunnel_draining_peers Number of draining tunnel peers`,
    `# TYPE tunnel_draining_peers gauge`,
    `tunnel_draining_peers ${stats.byState?.DRAINING || 0}`,
    ``,
    `# HELP tunnel_total_sessions Total number of tracked sessions`,
    `# TYPE tunnel_total_sessions gauge`,
    `tunnel_total_sessions ${stats.total}`,
    ``,
    `# HELP tunnel_ip_pool_available Available IPs in the pool`,
    `# TYPE tunnel_ip_pool_available gauge`,
    `tunnel_ip_pool_available ${poolStats.available}`,
    ``,
    `# HELP tunnel_ip_pool_allocated Allocated IPs in the pool`,
    `# TYPE tunnel_ip_pool_allocated gauge`,
    `tunnel_ip_pool_allocated ${poolStats.allocated}`,
    ``,
    `# HELP tunnel_tombstones Active tombstone entries`,
    `# TYPE tunnel_tombstones gauge`,
    `tunnel_tombstones ${stats.tombstones}`,
  ];

  res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
  res.end(lines.join('\n') + '\n');
}

function handleHealth(res, sessionManager, ipPool) {
  const stats = sessionManager.getStats();
  const poolStats = ipPool.stats();

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status: 'ok',
    active_peers: stats.byState?.ACTIVE || 0,
    available_ips: poolStats.available,
    uptime_seconds: Math.floor(process.uptime()),
  }));
}
