'use strict';

/**
 * Section 15.4 - Offline revocation.
 *
 * Devices download a compressed revocation list (Bloom filter / Merkle-set
 * style structure) every time they're online, and check incoming payer
 * certs against the cached copy before accepting a token offline. A
 * revoked device can still cheat a payee against a stale cache - that is
 * an accepted, bounded risk (same logic as reconciliation, Section 8.4).
 *
 * Section 19 - SCALING MODEL: distribution is a CDN-style push/pull of an
 * immutable compressed snapshot, not a live per-device query, so building
 * the snapshot (buildSnapshot) is decoupled from serving individual
 * lookups server-side (isRevoked).
 */

const { BloomFilter } = require('../common/bloomFilter');

class RevocationRegistry {
  constructor(db) {
    this.db = db;
    this._snapshot = null;
    this.rebuild();
  }

  revoke(deviceId) {
    this.db
      .prepare('INSERT OR REPLACE INTO revocation_list (device_id, revoked_at) VALUES (?, ?)')
      .run(deviceId, Date.now());
    this.rebuild();
  }

  isRevoked(deviceId) {
    // Server-side is the source of truth: exact check, not the Bloom
    // approximation (that's only for the offline device cache).
    const row = this.db.prepare('SELECT 1 FROM revocation_list WHERE device_id = ?').get(deviceId);
    return !!row;
  }

  rebuild() {
    const rows = this.db.prepare('SELECT device_id FROM revocation_list').all();
    const filter = new BloomFilter();
    for (const row of rows) filter.add(row.device_id);
    this._snapshot = filter.serialize();
  }

  getSnapshot() {
    return this._snapshot;
  }
}

module.exports = { RevocationRegistry };
