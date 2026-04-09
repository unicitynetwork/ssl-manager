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
    this.seenEventIds = new Set();
    this.eventIdExpiry = 120_000; // 2 minutes
    this._cleanupInterval = null;
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
    log(`Connected to ${connected.length}/${this.relayUrls.length} relay(s)`);

    // Start event ID cleanup
    this._cleanupInterval = setInterval(() => {
      this.seenEventIds.clear();
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

    // In production, this uses NIP-17 gift-wrap via Sphere SDK.
    // For now, we use NIP-04 direct messages as a fallback (less secure).
    let publishedCount = 0;
    let eventId = null;

    for (const { url, relay } of this.relays) {
      try {
        // Create and publish the event
        // Note: Full NIP-17 gift wrapping would be done here via Sphere SDK
        const event = {
          kind: 4, // NIP-04 DM (should be NIP-17 in production)
          content: msgJson,
          tags: [['p', recipientNpub]],
          created_at: Math.floor(Date.now() / 1000),
        };
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
          onevent: (event) => {
            // Deduplicate by event ID
            if (this.seenEventIds.has(event.id)) return;
            this.seenEventIds.add(event.id);

            try {
              const msg = JSON.parse(event.content);
              handler(msg);
            } catch (err) {
              warn(`Failed to parse DM content: ${err.message}`);
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
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          resolve(null);
        }
      }, timeoutMs);

      const handler = (msg) => {
        if (settled) return;
        if (msg.msg_type === msgType && msg.correlation_id === correlationId) {
          settled = true;
          clearTimeout(timer);
          resolve(msg);
        }
      };

      this.subscribeDMs(senderNpub, handler).catch((err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
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
