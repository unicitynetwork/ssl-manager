/**
 * Client-side DTNP state machine.
 *
 * Manages the tunnel lifecycle: IDLE -> BOOTSTRAPPING -> NEGOTIATING ->
 * ESTABLISHING -> ACTIVE -> RECONNECTING -> TEARING_DOWN -> IDLE
 */

import { writeFileSync, unlinkSync } from 'node:fs';
import { CLIENT_STATE, MSG, TIMEOUTS, RETRY, EXIT_CODES, TEARDOWN_REASONS } from './constants.mjs';
import {
  buildTunnelRequest,
  buildTunnelAccept,
  buildTunnelEstablished,
  buildTunnelHeartbeat,
  buildTunnelTeardown,
  buildTunnelError,
  validateEnvelope,
} from './dtnp.mjs';
import {
  checkWireGuardAvailability,
  writeWireGuardConfig,
  wgUp,
  wgDown,
  isHandshakeFresh,
  getWgStats,
  verifyConnectivity,
  verifyHaproxyApi,
  verifyDockerDns,
  cleanupWgConfig,
} from './wireguard.mjs';
import {
  checkSshAvailability,
  establishSshTunnel,
  killSshTunnel,
  verifySshTunnel,
} from './ssh-tunnel.mjs';

const LOG_PREFIX = '[tunnel-manager]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }
function err(msg) { console.error(`${LOG_PREFIX} ERROR: ${msg}`); }

/**
 * TunnelStateMachine orchestrates the complete tunnel lifecycle.
 */
export class TunnelStateMachine {
  constructor(config, identity, wgKeys, nostrClient) {
    this.config = config;
    this.identity = identity;
    this.wgKeys = wgKeys;
    this.nostrClient = nostrClient;

    this.state = CLIENT_STATE.IDLE;
    this.correlationId = null;
    this.sequence = 0;
    this.offer = null;
    this.tunnelType = null;
    this.transport = null;
    this.serverIp = null;
    this.clientIp = null;
    this.sshProcess = null;
    this.startedAt = null;
    this.reconnectCount = 0;

    this._heartbeatTimer = null;
    this._healthCheckTimer = null;
    this._shutdownRequested = false;
  }

  /**
   * Transition to a new state.
   */
  _setState(newState) {
    const prev = this.state;
    this.state = newState;
    log(`State: ${prev} -> ${newState}`);
    this._writeStateFile();
  }

  /**
   * Write current state to /tmp/.ssl-tunnel-state for debugging.
   */
  _writeStateFile() {
    try {
      writeFileSync('/tmp/.ssl-tunnel-state', JSON.stringify({
        state: this.state,
        correlationId: this.correlationId,
        tunnelType: this.tunnelType,
        transport: this.transport,
        clientIp: this.clientIp,
        serverIp: this.serverIp,
        reconnectCount: this.reconnectCount,
        uptimeSeconds: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0,
        timestamp: new Date().toISOString(),
      }, null, 2));
    } catch {}
  }

  /**
   * Get the next sequence number for this session.
   */
  _nextSeq() {
    return ++this.sequence;
  }

  /**
   * Execute the full tunnel startup sequence.
   * Blocks until the tunnel is ACTIVE or fails.
   */
  async start() {
    // ---- BOOTSTRAPPING ----
    this._setState(CLIENT_STATE.BOOTSTRAPPING);

    // Check tunnel capability
    if (this.config.tunnelMode === 'full') {
      const wgCheck = checkWireGuardAvailability();
      if (!wgCheck.available) {
        err('WireGuard kernel module not found and wireguard-go not installed.');
        err('Requires Linux 5.6+ or wireguard-go.');
        return EXIT_CODES.TUNNEL_FAILED;
      }
      log(`WireGuard available via: ${wgCheck.method}`);
    } else {
      const sshCheck = checkSshAvailability();
      if (!sshCheck.available) {
        err('Neither autossh nor ssh found. Required for lite mode.');
        return EXIT_CODES.TUNNEL_FAILED;
      }
      log(`SSH available via: ${sshCheck.method}`);
    }

    // Connect to Nostr relays
    try {
      await this.nostrClient.connect();
    } catch (e) {
      err(`Failed to connect to Nostr relays: ${e.message}`);
      return EXIT_CODES.NEGOTIATION_FAILED;
    }

    // ---- NEGOTIATING ----
    const negotiateResult = await this._negotiate();
    if (negotiateResult !== EXIT_CODES.SUCCESS) {
      return negotiateResult;
    }

    // ---- ESTABLISHING ----
    const establishResult = await this._establish();
    if (establishResult !== EXIT_CODES.SUCCESS) {
      return establishResult;
    }

    // ---- ACTIVE ----
    this._setState(CLIENT_STATE.ACTIVE);
    this.startedAt = Date.now();
    this.reconnectCount = 0;

    // Write tunnel env file for ssl-setup
    this._writeTunnelEnv();

    // Start background monitors
    this._startHealthCheck();
    this._startHeartbeat();

    log('Tunnel is ACTIVE');
    return EXIT_CODES.SUCCESS;
  }

  /**
   * Negotiate with the remote daemon.
   */
  async _negotiate() {
    this._setState(CLIENT_STATE.NEGOTIATING);

    let attempt = 0;
    while (attempt < RETRY.REQUEST_MAX) {
      attempt++;
      this.sequence = 0;

      // Build and send TUNNEL_REQUEST
      const request = buildTunnelRequest(this.config, this.identity, this.wgKeys);
      this.correlationId = request.correlation_id;

      try {
        await this.nostrClient.sendDM(this.config.remoteHaproxyId, request);
      } catch (e) {
        warn(`Failed to send TUNNEL_REQUEST (attempt ${attempt}): ${e.message}`);
        if (attempt < RETRY.REQUEST_MAX) {
          const backoff = Math.min(
            RETRY.REQUEST_BASE_S * Math.pow(2, attempt - 1),
            RETRY.REQUEST_CAP_S
          );
          const jitter = backoff * 0.2 * (Math.random() * 2 - 1);
          await sleep((backoff + jitter) * 1000);
          continue;
        }
        return EXIT_CODES.NEGOTIATION_FAILED;
      }

      log(`TUNNEL_REQUEST sent (attempt ${attempt}/${RETRY.REQUEST_MAX})`);

      // Wait for TUNNEL_OFFER or TUNNEL_REJECTED
      const response = await this.nostrClient.waitForMessage(
        this.config.remoteHaproxyId,
        null, // any type
        this.correlationId,
        this.config.tunnelNegotiateTimeout
      );

      if (!response) {
        warn(`No response received (attempt ${attempt}/${RETRY.REQUEST_MAX})`);
        if (attempt < RETRY.REQUEST_MAX) {
          const backoff = Math.min(
            RETRY.REQUEST_BASE_S * Math.pow(2, attempt - 1),
            RETRY.REQUEST_CAP_S
          );
          await sleep(backoff * 1000);
          continue;
        }
        err('Tunnel negotiation timed out after all retries');
        return EXIT_CODES.NEGOTIATION_FAILED;
      }

      // Validate response
      const validation = validateEnvelope(response);
      if (!validation.valid) {
        warn(`Invalid response: ${validation.error}`);
        continue;
      }

      if (response.msg_type === MSG.TUNNEL_REJECTED) {
        const reason = response.payload?.reason_code || 'unknown';
        const message = response.payload?.reason_message || '';
        err(`Tunnel request rejected: ${reason} — ${message}`);

        if (response.payload?.retry_after_seconds && attempt < RETRY.REQUEST_MAX) {
          log(`Retrying after ${response.payload.retry_after_seconds}s...`);
          await sleep(response.payload.retry_after_seconds * 1000);
          continue;
        }
        return EXIT_CODES.NEGOTIATION_FAILED;
      }

      if (response.msg_type === MSG.TUNNEL_OFFER) {
        this.offer = response;
        this.tunnelType = response.payload?.tunnel_type;
        log(`TUNNEL_OFFER received: type=${this.tunnelType}`);

        // Send TUNNEL_ACCEPT
        const selectedTransport = this._selectTransport(response.payload?.transports);
        this.transport = selectedTransport;

        const accept = buildTunnelAccept(
          this.correlationId,
          this._nextSeq(),
          this.identity.npub || '',
          this.tunnelType,
          selectedTransport
        );

        try {
          await this.nostrClient.sendDM(this.config.remoteHaproxyId, accept);
          log(`TUNNEL_ACCEPT sent: transport=${selectedTransport}`);
        } catch (e) {
          warn(`Failed to send TUNNEL_ACCEPT: ${e.message}`);
          continue;
        }

        return EXIT_CODES.SUCCESS;
      }

      warn(`Unexpected message type: ${response.msg_type}`);
    }

    return EXIT_CODES.NEGOTIATION_FAILED;
  }

  /**
   * Select the best transport from the offer's transport list.
   */
  _selectTransport(transports) {
    if (!transports || transports.length === 0) return 'udp';

    if (this.config.tunnelTransport !== 'auto') {
      // User forced a specific transport
      const forced = transports.find(t => t.type === this.config.tunnelTransport);
      if (forced) return forced.type;
      warn(`Forced transport '${this.config.tunnelTransport}' not in offer, using first available`);
    }

    // Auto: prefer UDP, fall back to WSS
    const udp = transports.find(t => t.type === 'udp');
    if (udp) return 'udp';

    const wss = transports.find(t => t.type === 'wss');
    if (wss) return 'wss';

    return transports[0].type;
  }

  /**
   * Establish the tunnel based on negotiated type.
   */
  async _establish() {
    this._setState(CLIENT_STATE.ESTABLISHING);

    if (!this.offer || !this.offer.payload) {
      err('No TUNNEL_OFFER to establish from');
      return EXIT_CODES.TUNNEL_FAILED;
    }

    const auth = this.offer.payload.auth;
    const haproxyApi = this.offer.payload.haproxy_api;

    if (this.tunnelType === 'wireguard') {
      return await this._establishWireGuard(auth, haproxyApi);
    } else if (this.tunnelType === 'ssh-reverse') {
      return await this._establishSshReverse(auth, haproxyApi);
    } else {
      err(`Unsupported tunnel type: ${this.tunnelType}`);
      return EXIT_CODES.TUNNEL_FAILED;
    }
  }

  /**
   * Establish WireGuard tunnel.
   */
  async _establishWireGuard(auth, haproxyApi) {
    // Write WireGuard config
    writeWireGuardConfig(this.offer, this.wgKeys.privateKey);

    // Bring up the interface
    if (!wgUp()) {
      err('Failed to bring up WireGuard interface');

      // Send immediate error (don't wait 120s as per spec)
      const errorMsg = buildTunnelError(
        this.correlationId,
        this._nextSeq(),
        this.identity.npub || '',
        'ERR_TUNNEL_SETUP_FAILED',
        'wg-quick up failed',
        false
      );
      await this.nostrClient.sendDM(this.config.remoteHaproxyId, errorMsg).catch(() => {});

      return EXIT_CODES.TUNNEL_FAILED;
    }

    // Extract IPs
    this.clientIp = auth.client_ip_alloc?.split('/')[0];
    this.serverIp = auth.server_ip?.split('/')[0] || haproxyApi?.host;

    // Verify connectivity
    log('Verifying tunnel connectivity...');
    const rtt = verifyConnectivity(this.serverIp);
    if (rtt === null) {
      err(`Cannot reach server ${this.serverIp} through tunnel`);
      wgDown();

      // Try WSS transport if we were on UDP
      if (this.transport === 'udp' && this.config.tunnelTransport === 'auto') {
        log('UDP failed, attempting WSS transport...');
        // TODO: Start wstunnel client and retry
        warn('WSS fallback not yet implemented');
      }

      return EXIT_CODES.TUNNEL_FAILED;
    }
    log(`Tunnel connectivity verified (RTT: ${rtt.toFixed(1)}ms)`);

    // Verify HAProxy API
    if (haproxyApi) {
      const apiOk = verifyHaproxyApi(haproxyApi.host, haproxyApi.port);
      if (apiOk) {
        log(`HAProxy API reachable at ${haproxyApi.host}:${haproxyApi.port}`);
      } else {
        warn(`HAProxy API not reachable at ${haproxyApi.host}:${haproxyApi.port}`);
      }
    }

    // Verify Docker DNS still works
    if (!verifyDockerDns()) {
      warn('Docker DNS may be affected by tunnel routing');
    }

    // Send TUNNEL_ESTABLISHED
    const established = buildTunnelEstablished(
      this.correlationId,
      this._nextSeq(),
      this.identity.npub || '',
      this.clientIp,
      rtt
    );
    await this.nostrClient.sendDM(this.config.remoteHaproxyId, established).catch(e => {
      warn(`Failed to send TUNNEL_ESTABLISHED: ${e.message}`);
    });

    return EXIT_CODES.SUCCESS;
  }

  /**
   * Establish SSH reverse tunnel (lite mode).
   */
  async _establishSshReverse(auth, haproxyApi) {
    try {
      this.sshProcess = establishSshTunnel(auth);
    } catch (e) {
      err(`SSH tunnel failed: ${e.message}`);
      return EXIT_CODES.TUNNEL_FAILED;
    }

    // Wait briefly for the tunnel to establish
    await sleep(3000);

    // Verify ports are forwarded
    if (!verifySshTunnel(auth.forwarded_ports || [])) {
      warn('Some SSH forwarded ports are not accessible');
    }

    // Set IPs for env file
    this.serverIp = haproxyApi?.host || auth.ssh_host;
    this.clientIp = 'localhost'; // SSH -R, no VPN IP

    // Send TUNNEL_ESTABLISHED
    const established = buildTunnelEstablished(
      this.correlationId,
      this._nextSeq(),
      this.identity.npub || '',
      this.clientIp,
      0
    );
    await this.nostrClient.sendDM(this.config.remoteHaproxyId, established).catch(() => {});

    return EXIT_CODES.SUCCESS;
  }

  /**
   * Write /tmp/.ssl-tunnel-env for ssl-setup to source.
   */
  _writeTunnelEnv() {
    const haproxyApi = this.offer?.payload?.haproxy_api;

    const env = [
      'TUNNEL_ACTIVE=true',
      `TUNNEL_TYPE=${this.tunnelType}`,
      `TUNNEL_CLIENT_IP=${this.clientIp}`,
      `TUNNEL_SERVER_IP=${this.serverIp}`,
      `HAPROXY_HOST=${haproxyApi?.host || this.serverIp}`,
      `HAPROXY_API_PORT=${haproxyApi?.port || this.config.haproxyApiPort}`,
      `HAPROXY_API_KEY=${haproxyApi?.session_key || ''}`,
      `HAPROXY_REMOTE_PUBLIC_IP=${this.offer?.payload?.haproxy_public_ip || ''}`,
    ].join('\n') + '\n';

    writeFileSync('/tmp/.ssl-tunnel-env', env);
    log('Tunnel environment written to /tmp/.ssl-tunnel-env');
  }

  /**
   * Start periodic health checks (WireGuard handshake monitoring).
   */
  _startHealthCheck() {
    if (this.tunnelType !== 'wireguard') return;

    let consecutiveStale = 0;
    this._healthCheckTimer = setInterval(async () => {
      if (this._shutdownRequested) return;

      if (isHandshakeFresh()) {
        if (consecutiveStale > 0) {
          log('WireGuard handshake recovered');
          // Send immediate heartbeat to cancel any pending server teardown
          await this._sendHeartbeat();
        }
        consecutiveStale = 0;
      } else {
        consecutiveStale++;
        warn(`WireGuard handshake stale (${consecutiveStale} consecutive checks)`);

        if (consecutiveStale >= 3) {
          log('Entering RECONNECTING state');
          await this._reconnect();
        }
      }
    }, TIMEOUTS.WG_HANDSHAKE_CHECK);
  }

  /**
   * Start periodic heartbeat DMs.
   */
  _startHeartbeat() {
    this._heartbeatTimer = setInterval(() => {
      if (!this._shutdownRequested) {
        this._sendHeartbeat();
      }
    }, this.config.tunnelHeartbeatInterval);
  }

  /**
   * Send a heartbeat DM.
   */
  async _sendHeartbeat() {
    const stats = this.tunnelType === 'wireguard' ? getWgStats() : { rxBytes: 0, txBytes: 0 };
    const heartbeat = buildTunnelHeartbeat(
      this.correlationId,
      this._nextSeq(),
      this.identity.npub || '',
      {
        tunnelStatus: this.state === CLIENT_STATE.ACTIVE ? 'healthy' : 'degraded',
        uptimeSeconds: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0,
        rxBytes: stats.rxBytes,
        txBytes: stats.txBytes,
      }
    );

    await this.nostrClient.sendDM(this.config.remoteHaproxyId, heartbeat).catch(e => {
      warn(`Failed to send heartbeat: ${e.message}`);
    });
  }

  /**
   * Reconnection logic.
   */
  async _reconnect() {
    this._setState(CLIENT_STATE.RECONNECTING);
    this.reconnectCount++;

    if (this.reconnectCount > this.config.tunnelReconnectMax) {
      err(`Maximum reconnection attempts (${this.config.tunnelReconnectMax}) exceeded`);
      await this.teardown(TEARDOWN_REASONS.TUNNEL_FAILURE, 'Max reconnect attempts exceeded');
      return EXIT_CODES.TUNNEL_FAILED;
    }

    // Add random jitter to avoid thundering herd
    const jitter = Math.floor(Math.random() * this.config.tunnelReconnectJitter * 1000);
    log(`Reconnecting (attempt ${this.reconnectCount}, jitter ${Math.round(jitter / 1000)}s)...`);
    await sleep(jitter);

    if (this.tunnelType === 'wireguard') {
      // Try interface restart first
      wgDown();
      await sleep(2000);

      if (wgUp()) {
        await sleep(5000);
        if (isHandshakeFresh()) {
          log('WireGuard reconnected via interface restart');
          this._setState(CLIENT_STATE.ACTIVE);
          await this._sendHeartbeat();
          return EXIT_CODES.SUCCESS;
        }
      }

      // Interface restart didn't work - re-negotiate
      log('Interface restart failed, re-negotiating...');
      wgDown();

      const result = await this._negotiate();
      if (result !== EXIT_CODES.SUCCESS) {
        err('Re-negotiation failed');
        await this.teardown(TEARDOWN_REASONS.TUNNEL_FAILURE, 'Re-negotiation failed');
        return EXIT_CODES.TUNNEL_FAILED;
      }

      const estResult = await this._establish();
      if (estResult !== EXIT_CODES.SUCCESS) {
        err('Re-establishment failed');
        await this.teardown(TEARDOWN_REASONS.TUNNEL_FAILURE, 'Re-establishment failed');
        return EXIT_CODES.TUNNEL_FAILED;
      }

      this._setState(CLIENT_STATE.ACTIVE);
      this._writeTunnelEnv();
      log('Tunnel re-established');
      return EXIT_CODES.SUCCESS;
    }

    // SSH mode: just restart the process
    if (this.sshProcess) {
      killSshTunnel(this.sshProcess);
      await sleep(2000);
      const auth = this.offer?.payload?.auth;
      if (auth) {
        try {
          this.sshProcess = establishSshTunnel(auth);
          await sleep(3000);
          this._setState(CLIENT_STATE.ACTIVE);
          return EXIT_CODES.SUCCESS;
        } catch (e) {
          err(`SSH reconnect failed: ${e.message}`);
        }
      }
    }

    return EXIT_CODES.TUNNEL_FAILED;
  }

  /**
   * Graceful teardown.
   */
  async teardown(reason = TEARDOWN_REASONS.GRACEFUL_SHUTDOWN, message = '') {
    if (this.state === CLIENT_STATE.TEARING_DOWN || this.state === CLIENT_STATE.IDLE) {
      return;
    }

    this._shutdownRequested = true;
    this._setState(CLIENT_STATE.TEARING_DOWN);

    // Stop timers
    if (this._heartbeatTimer) clearInterval(this._heartbeatTimer);
    if (this._healthCheckTimer) clearInterval(this._healthCheckTimer);

    // Send TUNNEL_TEARDOWN DM
    if (this.correlationId) {
      const teardown = buildTunnelTeardown(
        this.correlationId,
        this._nextSeq(),
        this.identity.npub || '',
        reason,
        message || `Tunnel teardown: ${reason}`
      );
      await this.nostrClient.sendDM(this.config.remoteHaproxyId, teardown).catch(e => {
        warn(`Failed to send TUNNEL_TEARDOWN: ${e.message}`);
      });
    }

    // Tear down tunnel
    if (this.tunnelType === 'wireguard') {
      wgDown();
      cleanupWgConfig();
    } else if (this.sshProcess) {
      killSshTunnel(this.sshProcess);
    }

    // Remove env file
    try {
      unlinkSync('/tmp/.ssl-tunnel-env');
    } catch {}

    // Disconnect Nostr
    await this.nostrClient.disconnect();

    this._setState(CLIENT_STATE.IDLE);
    log('Teardown complete');
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
