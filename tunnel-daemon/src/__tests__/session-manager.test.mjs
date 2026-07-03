import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { SessionManager, SERVER_STATE } from '../session-manager.mjs';

describe('Session Manager', () => {
  let sm;

  afterEach(() => {
    if (sm) sm.destroy();
  });

  it('creates a new session', () => {
    sm = new SessionManager({ drainingGracePeriod: 120 });
    const session = sm.getOrCreate('npub1a', 'test.com', 'corr-1');

    assert.ok(session.id);
    assert.equal(session.clientNpub, 'npub1a');
    assert.equal(session.primaryDomain, 'test.com');
    assert.equal(session.correlationId, 'corr-1');
    assert.equal(session.state, SERVER_STATE.IDLE);
    assert.ok(session.sessionKey);
  });

  it('enforces at-most-one session per client+domain', () => {
    sm = new SessionManager({ drainingGracePeriod: 120 });
    const s1 = sm.getOrCreate('npub1a', 'test.com', 'corr-1');
    sm.setOffered(s1);
    sm.setAccepting(s1);
    sm.setActive(s1);

    // Creating a new session for same client+domain tears down old one
    const s2 = sm.getOrCreate('npub1a', 'test.com', 'corr-2');
    assert.equal(s2.correlationId, 'corr-2');
    assert.notEqual(s2.id, s1.id);
  });

  it('finds session by correlation ID', () => {
    sm = new SessionManager({ drainingGracePeriod: 120 });
    const s1 = sm.getOrCreate('npub1a', 'test.com', 'corr-1');
    sm.getOrCreate('npub1b', 'other.com', 'corr-2');

    const found = sm.findByCorrelation('corr-1');
    assert.equal(found.clientNpub, 'npub1a');
    assert.equal(found.primaryDomain, 'test.com');
  });

  it('transitions through state machine', () => {
    sm = new SessionManager({ drainingGracePeriod: 120 });
    const session = sm.getOrCreate('npub1a', 'test.com', 'corr-1');

    assert.equal(session.state, SERVER_STATE.IDLE);

    sm.setOffered(session);
    assert.equal(session.state, SERVER_STATE.OFFERED);
    assert.ok(session.offeredAt);

    sm.setAccepting(session);
    assert.equal(session.state, SERVER_STATE.ACCEPTING);

    sm.setActive(session);
    assert.equal(session.state, SERVER_STATE.ACTIVE);
    assert.ok(session.establishedAt);
  });

  it('handles draining and cancellation', () => {
    sm = new SessionManager({ drainingGracePeriod: 120 });
    const session = sm.getOrCreate('npub1a', 'test.com', 'corr-1');
    sm.setOffered(session);
    sm.setAccepting(session);
    sm.setActive(session);

    sm.setDraining(session);
    assert.equal(session.state, SERVER_STATE.DRAINING);

    sm.cancelDraining(session);
    assert.equal(session.state, SERVER_STATE.ACTIVE);
  });

  it('records heartbeats', () => {
    sm = new SessionManager({ drainingGracePeriod: 120 });
    const session = sm.getOrCreate('npub1a', 'test.com', 'corr-1');
    sm.setOffered(session);
    sm.setAccepting(session);
    sm.setActive(session);

    const before = session.lastHeartbeat;
    sm.recordHeartbeat(session);
    assert.ok(session.lastHeartbeat >= before);
  });

  it('teardown adds tombstone', () => {
    sm = new SessionManager({ drainingGracePeriod: 120 });
    const session = sm.getOrCreate('npub1a', 'test.com', 'corr-1');
    sm.setOffered(session);
    sm.setAccepting(session);
    sm.setActive(session);

    let cleanupCalled = false;
    sm.teardown(session, () => { cleanupCalled = true; });

    assert.equal(cleanupCalled, true);
    assert.equal(session.state, SERVER_STATE.IDLE);
    assert.equal(sm.isTombstoned('corr-1'), true);
  });

  it('tombstone expires after 5 minutes', () => {
    sm = new SessionManager({ drainingGracePeriod: 120 });
    const session = sm.getOrCreate('npub1a', 'test.com', 'corr-1');

    // Manually add an expired tombstone
    sm.tombstones.set('old-corr', { expiry: Date.now() - 1000 });
    assert.equal(sm.isTombstoned('old-corr'), false);
  });

  it('gets active sessions', () => {
    sm = new SessionManager({ drainingGracePeriod: 120 });

    const s1 = sm.getOrCreate('npub1a', 'a.com', 'corr-1');
    sm.setOffered(s1);
    sm.setAccepting(s1);
    sm.setActive(s1);

    const s2 = sm.getOrCreate('npub1b', 'b.com', 'corr-2');
    sm.setOffered(s2);
    sm.setAccepting(s2);
    sm.setActive(s2);

    const s3 = sm.getOrCreate('npub1c', 'c.com', 'corr-3');
    // s3 is still IDLE

    const active = sm.getActiveSessions();
    assert.equal(active.length, 2);
  });

  it('reports stats', () => {
    sm = new SessionManager({ drainingGracePeriod: 120 });

    const s1 = sm.getOrCreate('npub1a', 'a.com', 'corr-1');
    sm.setOffered(s1);
    sm.setAccepting(s1);
    sm.setActive(s1);

    const s2 = sm.getOrCreate('npub1b', 'b.com', 'corr-2');
    sm.setOffered(s2);

    const stats = sm.getStats();
    assert.equal(stats.total, 2);
    assert.equal(stats.byState[SERVER_STATE.ACTIVE], 1);
    assert.equal(stats.byState[SERVER_STATE.OFFERED], 1);
  });
});
