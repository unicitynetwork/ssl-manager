/**
 * Nostr DM client for DTNP message exchange.
 *
 * Wraps nostr-tools for NIP-17 gift-wrapped DM communication.
 * Handles relay connections, message sending/receiving, and deduplication.
 */

import { randomUUID } from 'node:crypto';

const LOG_PREFIX = '[tunnel-manager:nostr]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }

/**
 * NostrClient manages relay connections and DM messaging.
 *
 * NOTE: This is a minimal implementation. In production, this would use
 * Sphere SDK for full NIP-17 gift-wrapped DM support. The current
 * implementation provides a compatible interface that can be swapped
 * for Sphere SDK once available in the tunnel image.
 */
export class NostrClient {
  constructor(config, identity) {
    this.config = config;
    this.identity = identity;
    this.relayUrls = config.tunnelRelayUrls;
    this.relays = [];
    this.connected = false;
    this.messageHandlers = [];
    this.seenEventIds = new Map(); // eventId -> timestamp for per-entry expiry
    this.eventIdExpiry = 120_000; // 2 minutes
    this._cleanupInterval = null;
    this._nostrTools = null;
  }

  /**
   * Connect to configured Nostr relays.
   */
  async connect() {
    log(`Connecting to ${this.relayUrls.length} relay(s)...`);

    // Dynamic import for nostr-tools (may not be available in all contexts)
    let nostrTools;
    try {
      nostrTools = await import('nostr-tools');
    } catch (err) {
      if (process.env.SSL_TEST_MODE !== 'true') {
        throw new Error('nostr-tools not available — cannot operate in production without Nostr messaging');
      }
      warn(`nostr-tools not available: ${err.message}`);
      warn('Falling back to simulated relay mode (for development/testing)');
      this.connected = true;
      this._simulated = true;
      return;
    }

    const connected = [];
    for (const url of this.relayUrls) {
      try {
        const relay = await nostrTools.Relay.connect(url);
        connected.push({ url, relay });
        log(`Connected to relay: ${url}`);
      } catch (err) {
        warn(`Failed to connect to relay ${url}: ${err.message}`);
      }
    }

    if (connected.length === 0) {
      throw new Error('Failed to connect to any Nostr relay');
    }

    this.relays = connected;
    this.connected = true;
    this._nostrTools = nostrTools;
    log(`Connected to ${connected.length}/${this.relayUrls.length} relay(s)`);

    // Start event ID cleanup — expire individual entries rather than clearing all
    this._cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [id, ts] of this.seenEventIds.entries()) {
        if (now - ts > this.eventIdExpiry) {
          this.seenEventIds.delete(id);
        }
      }
    }, this.eventIdExpiry);
  }

  /**
   * Send a DTNP message to a recipient npub.
   */
  async sendDM(recipientNpub, message) {
    if (!this.connected) {
      throw new Error('Not connected to any relay');
    }

    const msgJson = JSON.stringify(message);
    log(`Sending ${message.msg_type} to ${recipientNpub.substring(0, 12)}... (correlation: ${message.correlation_id.substring(0, 8)})`);

    if (this._simulated) {
      log('[SIMULATED] Message queued for delivery');
      return { eventId: randomUUID(), relayCount: 0 };
    }

    // TODO: Upgrade to NIP-17 gift-wrap when Sphere SDK integration is ready
    // For now, we use NIP-04 encrypted direct messages as a minimum security baseline.
    let publishedCount = 0;
    let eventId = null;

    // Resolve recipient hex pubkey for NIP-04 encryption
    const recipientPubkeyHex = recipientNpub;
    const senderPrivkeyHex = this.identity.privkeyHex;

    // Encrypt content using NIP-04
    let encrypted;
    try {
      const { nip04, finalizeEvent, getPublicKey } = this._nostrTools;
      encrypted = await nip04.encrypt(senderPrivkeyHex, recipientPubkeyHex, msgJson);
    } catch (encErr) {
      throw new Error(`NIP-04 encryption failed: ${encErr.message}`);
    }

    for (const { url, relay } of this.relays) {
      try {
        // Create and sign the NIP-04 encrypted event
        const { finalizeEvent } = this._nostrTools;
        const event = finalizeEvent({
          kind: 4,
          content: encrypted,
          tags: [['p', recipientPubkeyHex]],
          created_at: Math.floor(Date.now() / 1000),
        }, senderPrivkeyHex);
        await relay.publish(event);
        eventId = event.id;
        publishedCount++;
      } catch (err) {
        warn(`Failed to publish to ${url}: ${err.message}`);
      }
    }

    if (publishedCount === 0) {
      throw new Error('Failed to publish message to any relay');
    }

    log(`Published to ${publishedCount} relay(s)`);
    return { eventId, relayCount: publishedCount };
  }

  /**
   * Subscribe to incoming DMs from a specific sender npub.
   * Calls handler(message) for each received DTNP message.
   */
  async subscribeDMs(senderNpub, handler) {
    if (this._simulated) {
      this.messageHandlers.push({ senderNpub, handler });
      return;
    }

    for (const { url, relay } of this.relays) {
      try {
        const sub = relay.subscribe([
          {
            kinds: [4], // NIP-04 DM (should be NIP-17 in production)
            '#p': [this.identity.pubkeyHex || ''],
            authors: [senderNpub],
          }
        ], {
          onevent: async (event) => {
            // Verify event signature before processing
            const { verifyEvent, nip04 } = this._nostrTools;
            if (!verifyEvent(event)) {
              warn('Rejecting event with invalid signature');
              return;
            }

            // Deduplicate by event ID
            if (this.seenEventIds.has(event.id)) return;
            this.seenEventIds.set(event.id, Date.now());

            try {
              // Decrypt NIP-04 content
              const decrypted = await nip04.decrypt(this.identity.privkeyHex, event.pubkey, event.content);
              const msg = JSON.parse(decrypted);
              handler(msg);
            } catch (err) {
              warn(`Failed to decrypt/parse DM content: ${err.message}`);
            }
          }
        });
      } catch (err) {
        warn(`Failed to subscribe on ${url}: ${err.message}`);
      }
    }

    this.messageHandlers.push({ senderNpub, handler });
  }

  /**
   * Wait for a specific message type with timeout.
   * Returns the message payload or null on timeout.
   */
  waitForMessage(senderNpub, msgType, correlationId, timeoutMs) {
    return new Promise((resolve) => {
      let settled = false;

      const removeHandler = () => {
        const idx = this.messageHandlers.findIndex(h => h.handler === handler);
        if (idx !== -1) this.messageHandlers.splice(idx, 1);
      };

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          removeHandler();
          resolve(null);
        }
      }, timeoutMs);

      const handler = (msg) => {
        if (settled) return;
        const typeMatch = !msgType || msg.msg_type === msgType;
        const corrMatch = !correlationId || msg.correlation_id === correlationId;
        if (typeMatch && corrMatch) {
          settled = true;
          clearTimeout(timer);
          removeHandler();
          resolve(msg);
        }
      };

      this.subscribeDMs(senderNpub, handler).catch((err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          removeHandler();
          resolve(null);
        }
      });
    });
  }

  /**
   * Inject a message for testing (simulated mode only).
   */
  _injectMessage(senderNpub, message) {
    if (!this._simulated) return;
    for (const { senderNpub: s, handler } of this.messageHandlers) {
      if (!s || s === senderNpub) {
        handler(message);
      }
    }
  }

  /**
   * Disconnect from all relays.
   */
  async disconnect() {
    if (this._cleanupInterval) {
      clearInterval(this._cleanupInterval);
    }
    for (const { relay } of this.relays) {
      try {
        relay.close();
      } catch {}
    }
    this.relays = [];
    this.connected = false;
    log('Disconnected from all relays');
  }
}
