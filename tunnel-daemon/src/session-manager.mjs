/**
 * Tunnel session manager.
 *
 * Manages the server-side state machine for tunnel sessions.
 * Enforces at-most-one session per (client_npub, primary_domain) pair.
 */

import { randomUUID } from 'node:crypto';

const LOG_PREFIX = '[tunnel-daemon:session]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }

// Server states
const SERVER_STATE = {
  IDLE: 'IDLE',
  OFFERED: 'OFFERED',
  ACCEPTING: 'ACCEPTING',
  ACTIVE: 'ACTIVE',
  DRAINING: 'DRAINING',
  TEARING_DOWN: 'TEARING_DOWN',
};

export class SessionManager {
  constructor(config) {
    this.config = config;
    this.sessions = new Map(); // key: `${clientNpub}:${primaryDomain}` -> session
    this.tombstones = new Map(); // correlationId -> { expiry }
    this._cleanupInterval = setInterval(() => this._cleanup(), 30_000);
  }

  /**
   * Get or create a session for a client + domain pair.
   * If an existing session is active, tears it down first.
   */
  getOrCreate(clientNpub, primaryDomain, correlationId) {
    const key = `${clientNpub}:${primaryDomain}`;
    const existing = this.sessions.get(key);

    if (existing && existing.state !== SERVER_STATE.IDLE) {
      // At-most-one: tear down existing session
      log(`Tearing down existing session for ${key}`);
      this._teardownSession(existing);
    }

    const session = {
      id: randomUUID(),
      key,
      clientNpub,
      primaryDomain,
      correlationId,
      state: SERVER_STATE.IDLE,
      peerIp: null,
      clientWgPubkey: null,
      aliases: [],
      ports: [],
      tunnelType: null,
      transport: null,
      sessionKey: randomUUID(), // domain-scoped API key
      createdAt: Date.now(),
      offeredAt: null,
      acceptedAt: null,
      establishedAt: null,
      lastHeartbeat: null,
      sequence: 0,
      offerTimer: null,
      acceptTimer: null,
      drainingTimer: null,
    };

    this.sessions.set(key, session);
    return session;
  }

  /**
   * Find a session by correlation ID.
   */
  findByCorrelation(correlationId) {
    for (const session of this.sessions.values()) {
      if (session.correlationId === correlationId) {
        return session;
      }
    }
    return null;
  }

  /**
   * Check if a correlation ID is in the tombstone cache.
   */
  isTombstoned(correlationId) {
    const entry = this.tombstones.get(correlationId);
    if (!entry) return false;
    if (Date.now() > entry.expiry) {
      this.tombstones.delete(correlationId);
      return false;
    }
    return true;
  }

  /**
   * Transition a session to OFFERED state.
   */
  setOffered(session) {
    session.state = SERVER_STATE.OFFERED;
    session.offeredAt = Date.now();
    session.sequence++;

    // Set offer expiry timer (180 seconds)
    session.offerTimer = setTimeout(() => {
      if (session.state === SERVER_STATE.OFFERED) {
        log(`Offer expired for ${session.key}`);
        this._teardownSession(session);
      }
    }, 180_000);

    log(`Session ${session.key}: OFFERED`);
  }

  /**
   * Transition to ACCEPTING state.
   */
  setAccepting(session) {
    if (session.offerTimer) clearTimeout(session.offerTimer);
    session.state = SERVER_STATE.ACCEPTING;
    session.acceptedAt = Date.now();
    session.sequence++;

    // Set accept timeout (180 seconds for TUNNEL_ESTABLISHED)
    session.acceptTimer = setTimeout(() => {
      if (session.state === SERVER_STATE.ACCEPTING) {
        log(`Accept timeout for ${session.key}`);
        this._teardownSession(session);
      }
    }, 180_000);

    log(`Session ${session.key}: ACCEPTING`);
  }

  /**
   * Transition to ACTIVE state.
   */
  setActive(session) {
    if (session.acceptTimer) clearTimeout(session.acceptTimer);
    session.state = SERVER_STATE.ACTIVE;
    session.establishedAt = Date.now();
    session.lastHeartbeat = Date.now();

    log(`Session ${session.key}: ACTIVE (peer: ${session.peerIp})`);
  }

  /**
   * Transition to DRAINING state.
   */
  setDraining(session) {
    session.state = SERVER_STATE.DRAINING;

    // Grace period (120 seconds)
    session.drainingTimer = setTimeout(() => {
      if (session.state === SERVER_STATE.DRAINING) {
        log(`Draining grace expired for ${session.key}`);
        this._teardownSession(session);
      }
    }, this.config.drainingGracePeriod * 1000);

    log(`Session ${session.key}: DRAINING`);
  }

  /**
   * Cancel draining (peer reconnected).
   */
  cancelDraining(session) {
    if (session.drainingTimer) clearTimeout(session.drainingTimer);
    session.state = SERVER_STATE.ACTIVE;
    session.lastHeartbeat = Date.now();
    log(`Session ${session.key}: DRAINING cancelled, back to ACTIVE`);
  }

  /**
   * Record a heartbeat.
   */
  recordHeartbeat(session) {
    session.lastHeartbeat = Date.now();
  }

  /**
   * Teardown a session and add to tombstone cache.
   */
  teardown(session, onCleanup) {
    this._teardownSession(session, onCleanup);
  }

  /**
   * Get all active sessions.
   */
  getActiveSessions() {
    return Array.from(this.sessions.values()).filter(
      s => s.state === SERVER_STATE.ACTIVE || s.state === SERVER_STATE.DRAINING
    );
  }

  /**
   * Get session stats.
   */
  getStats() {
    const states = {};
    for (const s of this.sessions.values()) {
      states[s.state] = (states[s.state] || 0) + 1;
    }
    return {
      total: this.sessions.size,
      tombstones: this.tombstones.size,
      byState: states,
    };
  }

  // ---- Internal ----

  _teardownSession(session, onCleanup) {
    // Clear timers
    if (session.offerTimer) clearTimeout(session.offerTimer);
    if (session.acceptTimer) clearTimeout(session.acceptTimer);
    if (session.drainingTimer) clearTimeout(session.drainingTimer);

    session.state = SERVER_STATE.TEARING_DOWN;

    // Invoke cleanup callback
    if (onCleanup) {
      try {
        onCleanup(session);
      } catch (e) {
        warn(`Cleanup error for ${session.key}: ${e.message}`);
      }
    }

    // Add to tombstone cache (5 minutes)
    this.tombstones.set(session.correlationId, {
      expiry: Date.now() + 5 * 60 * 1000,
      key: session.key,
    });

    // Set state to IDLE
    session.state = SERVER_STATE.IDLE;
    log(`Session ${session.key}: TORN DOWN`);
  }

  _cleanup() {
    // Clean expired tombstones
    const now = Date.now();
    for (const [id, entry] of this.tombstones.entries()) {
      if (now > entry.expiry) {
        this.tombstones.delete(id);
      }
    }

    // Clean IDLE sessions older than 10 minutes
    for (const [key, session] of this.sessions.entries()) {
      if (session.state === SERVER_STATE.IDLE && now - session.createdAt > 600_000) {
        this.sessions.delete(key);
      }
    }
  }

  destroy() {
    if (this._cleanupInterval) clearInterval(this._cleanupInterval);
    for (const session of this.sessions.values()) {
      if (session.offerTimer) clearTimeout(session.offerTimer);
      if (session.acceptTimer) clearTimeout(session.acceptTimer);
      if (session.drainingTimer) clearTimeout(session.drainingTimer);
    }
  }
}

export { SERVER_STATE };
