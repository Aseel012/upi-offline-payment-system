'use strict';

/**
 * Section 5 - Fraud Engine: reads reconciliation outcomes, flags/freezes
 * devices. Never touches the ledger itself (Section 5 rule: only
 * Reconciliation Service mutates balance) - it only mutates device.status
 * and the revocation list.
 *
 * Section 8.4: a duplicate-counter (replayed/double-spent) token at
 * reconciliation is exactly the "caught after reconnect" moment the whole
 * design is built around (Section 1). Section 15.3: velocity/cap limits
 * bound total damage from a compromised device spamming transactions.
 */

const { FRAUD_DUPLICATE_THRESHOLD } = require('../common/constants');

class FraudEngine {
  constructor(db, { auditLog, revocationRegistry }) {
    this.db = db;
    this.auditLog = auditLog;
    this.revocationRegistry = revocationRegistry;
    this._bumpStrikes = db.prepare(
      'UPDATE devices SET fraud_strikes = fraud_strikes + 1 WHERE device_id = ?'
    );
    this._getDevice = db.prepare('SELECT * FROM devices WHERE device_id = ?');
    this._freeze = db.prepare("UPDATE devices SET status = 'FROZEN' WHERE device_id = ?");
  }

  onDuplicate(deviceId) {
    this._bumpStrikes.run(deviceId);
    const device = this._getDevice.get(deviceId);
    this.auditLog.append(deviceId, {
      type: 'FRAUD_SIGNAL',
      reason: 'DUPLICATE_COUNTER',
      strikes: device.fraud_strikes
    });
    if (device.fraud_strikes >= FRAUD_DUPLICATE_THRESHOLD) {
      this.freeze(deviceId, 'DUPLICATE_COUNTER_THRESHOLD_EXCEEDED');
    }
  }

  onRejected(deviceId, reason) {
    this.auditLog.append(deviceId, { type: 'RECONCILIATION_REJECTION', reason });
  }

  freeze(deviceId, reason) {
    this._freeze.run(deviceId);
    this.revocationRegistry.revoke(deviceId);
    this.auditLog.append(deviceId, { type: 'DEVICE_FROZEN', reason });
  }
}

module.exports = { FraudEngine };
