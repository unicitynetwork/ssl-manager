/**
 * WireGuard IP address pool manager.
 *
 * Manages allocation and deallocation of peer IPs within the tunnel subnet.
 * Implements cooldown period to prevent IP reuse issues.
 */

const LOG_PREFIX = '[tunnel-daemon:ip-pool]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }

export class IpPool {
  /**
   * @param {string} subnet - CIDR notation (e.g., '10.200.0.0/24')
   * @param {number} cooldownSeconds - Seconds before a freed IP can be reused
   */
  constructor(subnet, cooldownSeconds = 30) {
    this.cooldownSeconds = cooldownSeconds;

    // Parse subnet
    const [baseIp, prefix] = subnet.split('/');
    this.prefix = parseInt(prefix, 10);
    this.baseIpParts = baseIp.split('.').map(Number);

    // Calculate range (skip .0 network and .1 server, and .255 broadcast)
    this.startOffset = 2; // .2 is first client
    this.maxOffset = Math.pow(2, 32 - this.prefix) - 2; // exclude broadcast

    // Track allocations: ip -> { clientNpub, domain, allocatedAt }
    this.allocated = new Map();

    // Track cooldowns: ip -> freedAt timestamp
    this.cooldowns = new Map();

    // Cleanup timer for expired cooldowns
    this._cleanupInterval = setInterval(() => this._cleanupCooldowns(), 10_000);
  }

  /**
   * Allocate an IP for a client.
   * @param {string} clientNpub
   * @param {string} domain
   * @param {string} [preferredIp] - Try to reuse this IP if available
   * @returns {string|null} Allocated IP or null if pool exhausted
   */
  allocate(clientNpub, domain, preferredIp = null) {
    // Try preferred IP first (for reconnection)
    if (preferredIp && this._isAvailable(preferredIp)) {
      this._assign(preferredIp, clientNpub, domain);
      return preferredIp;
    }

    // Find next available IP
    for (let offset = this.startOffset; offset <= this.maxOffset; offset++) {
      const ip = this._offsetToIp(offset);
      if (this._isAvailable(ip)) {
        this._assign(ip, clientNpub, domain);
        return ip;
      }
    }

    warn('IP pool exhausted');
    return null;
  }

  /**
   * Free an allocated IP (enters cooldown).
   */
  free(ip) {
    if (this.allocated.has(ip)) {
      const info = this.allocated.get(ip);
      this.allocated.delete(ip);
      this.cooldowns.set(ip, Date.now());
      log(`Freed ${ip} (was: ${info.clientNpub.substring(0, 12)}..., domain: ${info.domain})`);
    }
  }

  /**
   * Get allocation info for an IP.
   */
  getInfo(ip) {
    return this.allocated.get(ip) || null;
  }

  /**
   * Find the IP allocated to a client npub + domain pair.
   */
  findByClient(clientNpub, domain) {
    for (const [ip, info] of this.allocated.entries()) {
      if (info.clientNpub === clientNpub && info.domain === domain) {
        return ip;
      }
    }
    return null;
  }

  /**
   * Get pool statistics.
   */
  stats() {
    return {
      allocated: this.allocated.size,
      cooldown: this.cooldowns.size,
      available: this.maxOffset - this.startOffset + 1 - this.allocated.size - this.cooldowns.size,
      total: this.maxOffset - this.startOffset + 1,
    };
  }

  /**
   * Get all active allocations.
   */
  getAllocations() {
    return Array.from(this.allocated.entries()).map(([ip, info]) => ({
      ip,
      ...info,
    }));
  }

  // ---- Internal ----

  _isAvailable(ip) {
    if (this.allocated.has(ip)) return false;
    if (this.cooldowns.has(ip)) {
      const freedAt = this.cooldowns.get(ip);
      if (Date.now() - freedAt < this.cooldownSeconds * 1000) {
        return false;
      }
      this.cooldowns.delete(ip);
    }
    return true;
  }

  _assign(ip, clientNpub, domain) {
    this.cooldowns.delete(ip);
    this.allocated.set(ip, {
      clientNpub,
      domain,
      allocatedAt: Date.now(),
    });
    log(`Allocated ${ip} to ${clientNpub.substring(0, 12)}... (${domain})`);
  }

  _offsetToIp(offset) {
    const base = (this.baseIpParts[0] << 24) |
                 (this.baseIpParts[1] << 16) |
                 (this.baseIpParts[2] << 8) |
                 this.baseIpParts[3];
    const ip = base + offset;
    return `${(ip >> 24) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 8) & 0xFF}.${ip & 0xFF}`;
  }

  _cleanupCooldowns() {
    const now = Date.now();
    for (const [ip, freedAt] of this.cooldowns.entries()) {
      if (now - freedAt >= this.cooldownSeconds * 1000) {
        this.cooldowns.delete(ip);
      }
    }
  }

  destroy() {
    if (this._cleanupInterval) {
      clearInterval(this._cleanupInterval);
    }
  }
}
