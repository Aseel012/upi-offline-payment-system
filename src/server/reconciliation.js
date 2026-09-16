'use strict';

/**
 * Section 5: "Ingest API must never touch the ledger directly - only
 * Reconciliation Service does, so there's exactly one code path that can
 * ever mutate balance."
 *
 * Section 12 - TRANSACTION MODEL:
 *   BEGIN
 *     INSERT INTO wallet_tokens (...)   -- unique (device_id, counter) either
 *                                          succeeds or throws
 *     IF succeeds: UPDATE devices.last_synced_counter (monotonic guard)
 *     IF uniqueness violation: mark REJECTED_DUPLICATE, do not touch balance
 *   COMMIT
 *
 * Section 13 - CONCURRENCY MODEL: the correctness guarantee here is the
 * UNIQUE(device_id, counter) index, not the isolation level. READ COMMITTED
 * is sufficient because the constraint itself makes duplicate-counter
 * insertion atomic and mutually exclusive - two concurrent inserts for the
 * same (device_id, counter) can never both succeed, no app-level lock
 * required (and app-level locks wouldn't hold across multiple server
 * instances anyway).
 */

const { verifyPayload } = require('../crypto/keys');
const { TOKEN_STATE } = require('../common/constants');

class ReconciliationService {
  constructor(db, { auditLog, fraudEngine, revocationRegistry }) {
    this.db = db;
    this.auditLog = auditLog;
    this.fraudEngine = fraudEngine;
    this.revocationRegistry = revocationRegistry;

    this._getDevice = db.prepare('SELECT * FROM devices WHERE device_id = ?');
    this._insertToken = db.prepare(`
      INSERT INTO wallet_tokens
        (token_id, device_id, counter, amount, payer_id, payee_id, nonce, signature, expiry, status, created_at, settled_at)
      VALUES
        (@token_id, @device_id, @counter, @amount, @payer_id, @payee_id, @nonce, @signature, @expiry, @status, @created_at, @settled_at)
    `);
    this._sumSettled = db.prepare(`
      SELECT COALESCE(SUM(amount), 0) AS total
      FROM wallet_tokens
      WHERE device_id = ? AND payer_id = ? AND status = 'SETTLED'
    `);
    this._updateDeviceCounter = db.prepare(`
      UPDATE devices
      SET last_synced_counter = ?, last_seen_at = ?
      WHERE device_id = ? AND last_synced_counter < ?
    `);

    // Wrapping in db.transaction() gives ACID semantics: the WAL entry is
    // fsynced and a commit record written before this function returns
    // (Section 12) - callers (the HTTP handler) must wait for this, not
    // just an in-memory write, or the client could be told "settled" for
    // something a crash immediately after loses.
    this._reconcileTxn = db.transaction((token) => this._reconcileInner(token));
  }

  reconcileToken(token) {
    return this._reconcileTxn(token);
  }

  _rejectPreLedger(token, status) {
    this.auditLog.append(token.device_id, {
      type: 'TOKEN_REJECTED_PRE_LEDGER',
      reason: status,
      token_id: token.token_id,
      counter: token.counter
    });
    return { outcome: status, token_id: token.token_id };
  }

  _reconcileInner(token) {
    const device = this._getDevice.get(token.device_id);

    if (!device) {
      return this._rejectPreLedger(token, 'REJECTED_UNKNOWN_DEVICE');
    }
    if (device.status === 'FROZEN') {
      return this._rejectPreLedger(token, 'REJECTED_DEVICE_FROZEN');
    }
    if (this.revocationRegistry.isRevoked(token.device_id)) {
      return this._rejectPreLedger(token, TOKEN_STATE.REJECTED_REVOKED);
    }

    // Section 17: "Malicious device injects forged signature -> Signature
    // verification fails, rejected before touching the ledger."
    const { signature, ...body } = token;
    const signatureValid = verifyPayload(device.public_key, body, signature);
    if (!signatureValid) {
      return this._rejectPreLedger(token, TOKEN_STATE.REJECTED_INVALID_SIGNATURE);
    }

    // Timestamp is advisory only (Section 8.2) - expiry is the enforced
    // window. An expired-but-validly-signed token still consumed a counter
    // slot, so it still goes through the unique-insert path below.
    let status = TOKEN_STATE.SETTLED;
    if (Date.now() > token.expiry) {
      status = TOKEN_STATE.REJECTED_EXPIRED;
    }

    // Section 15.6 / 8.1: wallet cap is the economic backstop for what
    // crypto alone can't stop offline - enforced again here server-side
    // (Section 17: "regulatory cap breach ... rejected again at
    // reconciliation").
    if (status === TOKEN_STATE.SETTLED) {
      const { total } = this._sumSettled.get(token.device_id, token.payer_id);
      if (total + token.amount > device.wallet_cap) {
        status = TOKEN_STATE.REJECTED_CAP_EXCEEDED;
      }
    }

    const now = Date.now();
    try {
      this._insertToken.run({
        token_id: token.token_id,
        device_id: token.device_id,
        counter: token.counter,
        amount: token.amount,
        payer_id: token.payer_id,
        payee_id: token.payee_id,
        nonce: token.nonce,
        signature,
        expiry: token.expiry,
        status,
        created_at: now,
        settled_at: status === TOKEN_STATE.SETTLED ? now : null
      });
    } catch (err) {
      if (String(err.code || '').startsWith('SQLITE_CONSTRAINT')) {
        // Section 8.4 / 13: the exact "same counter reached reconciliation
        // twice" race - the DB unique index is what resolves it, not app
        // logic ordering.
        this.auditLog.append(token.device_id, {
          type: 'DUPLICATE_COUNTER_REJECTED',
          token_id: token.token_id,
          counter: token.counter
        });
        this.fraudEngine.onDuplicate(token.device_id);
        return { outcome: TOKEN_STATE.REJECTED_DUPLICATE, token_id: token.token_id };
      }
      throw err;
    }

    if (status === TOKEN_STATE.SETTLED) {
      this._updateDeviceCounter.run(token.counter, now, token.device_id, token.counter);
    } else {
      this.fraudEngine.onRejected(token.device_id, status);
    }

    this.auditLog.append(token.device_id, {
      type: 'TOKEN_RECONCILED',
      token_id: token.token_id,
      counter: token.counter,
      status
    });

    return { outcome: status, token_id: token.token_id };
  }
}

module.exports = { ReconciliationService };
