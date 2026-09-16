'use strict';

/**
 * Section 10 - DATA MODEL: audit_log is hash-chained (each entry includes
 * the hash of the previous one) so any tampering - local or server-side -
 * with the history is detectable. Also used server-side as the canonical
 * event trail for Section 20 - OPERATIONS (support/runbook investigations).
 */

const { sha256Hex } = require('../crypto/keys');

const GENESIS_HASH = '0'.repeat(64);

class AuditLog {
  constructor(db) {
    this.db = db;
    this._insert = db.prepare(
      `INSERT INTO audit_log (device_id, prev_hash, this_hash, event, timestamp)
       VALUES (@device_id, @prev_hash, @this_hash, @event, @timestamp)`
    );
    this._lastForDevice = db.prepare(
      `SELECT this_hash FROM audit_log WHERE device_id = ? ORDER BY entry_id DESC LIMIT 1`
    );
  }

  append(deviceId, eventObj) {
    const prevRow = this._lastForDevice.get(deviceId);
    const prevHash = prevRow ? prevRow.this_hash : GENESIS_HASH;
    const timestamp = Date.now();
    const eventJson = JSON.stringify(eventObj);
    const thisHash = sha256Hex(`${prevHash}|${eventJson}|${timestamp}`);
    this._insert.run({
      device_id: deviceId,
      prev_hash: prevHash,
      this_hash: thisHash,
      event: eventJson,
      timestamp
    });
    return thisHash;
  }

  verifyChain(deviceId) {
    const rows = this.db
      .prepare('SELECT prev_hash, this_hash, event, timestamp FROM audit_log WHERE device_id = ? ORDER BY entry_id ASC')
      .all(deviceId);
    let expectedPrev = GENESIS_HASH;
    for (const row of rows) {
      if (row.prev_hash !== expectedPrev) return { valid: false, brokenAt: row };
      const recomputed = sha256Hex(`${row.prev_hash}|${row.event}|${row.timestamp}`);
      if (recomputed !== row.this_hash) return { valid: false, brokenAt: row };
      expectedPrev = row.this_hash;
    }
    return { valid: true, entries: rows.length };
  }

  history(deviceId) {
    return this.db
      .prepare('SELECT * FROM audit_log WHERE device_id = ? ORDER BY entry_id ASC')
      .all(deviceId);
  }
}

module.exports = { AuditLog, GENESIS_HASH };
