'use strict';

/**
 * Section 5 - Wallet Manager (on-device): balance, counter, signing.
 * Section 3 - SYSTEM BOUNDARY: everything here is provisional truth.
 * Nothing on-device is ever final - it's provisional until the server
 * (permanent truth) reconciles it.
 */
const { v4: uuidv4 } = require('uuid');
const { KeyStore, verifyPayload } = require('../crypto/keys');
const { buildTokenBody, isShapeValid } = require('../common/tokenSchema');
const { verifyDeviceCert } = require('../common/certVerify');
const { BloomFilter } = require('../common/bloomFilter');
const { DEVICE_STATE, DEFAULT_WALLET_CAP } = require('../common/constants');

class Wallet {
  constructor({ userId, walletCap = DEFAULT_WALLET_CAP } = {}) {
    this.deviceId = uuidv4();
    this.userId = userId;
    this.walletCap = walletCap;
    this.keyStore = new KeyStore();

    this.balance = 0; // offline wallet balance (Section 8.1)
    this.counter = -1; // monotonic per-device counter, never reused
    this.status = DEVICE_STATE.ONLINE_NATIVE;

    this.outbox = []; // signed tokens queued for sync (payer side)
    this.ledger = []; // tokens received as payee, provisional until settled
    this.provisionalBalance = 0;

    this.cert = null;
    this.rootPublicKey = null;
    this.revocationSnapshot = null; // cached Bloom filter, refreshed while online
  }

  /**
   * Section 8.1: "This load-in step requires internet, once. After that,
   * offline spending only ever draws down this pre-loaded balance - never
   * the real bank account."
   */
  loadFunds(amount) {
    if (amount <= 0) throw new Error('INVALID_LOAD_AMOUNT');
    this.balance += amount;
  }

  applyProvisioningResult({ cert, rootPublicKey }) {
    this.cert = cert;
    this.rootPublicKey = rootPublicKey;
    this.status = DEVICE_STATE.ONLINE_NATIVE;
  }

  cacheRevocationSnapshot(snapshot) {
    this.revocationSnapshot = snapshot;
  }

  /** Section 15.4: bounded, stale-cache risk accepted by design. */
  isPeerPossiblyRevoked(peerDeviceId) {
    if (!this.revocationSnapshot) return false; // never fetched a snapshot yet
    const filter = BloomFilter.deserialize(this.revocationSnapshot);
    return filter.mightContain(peerDeviceId);
  }

  /**
   * Section 8.3 step 1 + Section 15.5 (local auth gate).
   * On-device balance check is a *soft* check - it stops honest mistakes,
   * not a tampered device (Section 8.2).
   */
  async createPaymentToken(payeeId, amount, { authGateOk = true } = {}) {
    if (!Number.isFinite(amount) || amount <= 0) throw new Error('INVALID_AMOUNT');
    if (amount > this.balance) throw new Error('INSUFFICIENT_LOCAL_BALANCE');

    const nextCounter = this.counter + 1;
    const body = buildTokenBody({
      payerId: this.deviceId,
      payeeId,
      amount,
      deviceId: this.deviceId,
      counter: nextCounter
    });
    const signature = await this.keyStore.sign(body, { authGateOk });
    const token = { ...body, signature };

    // Commit the local, provisional state only after a successful sign.
    this.balance -= amount;
    this.counter = nextCounter;
    this.status = DEVICE_STATE.OFFLINE_SPENDING;
    this.outbox.push(token);
    return token;
  }

  /**
   * Section 8.3 step 3: payee verifies signature + expiry (all it can
   * check offline), credits its own wallet provisionally, stores the
   * token. Also implements the offline half of the cert chain
   * (Section 15.1) and the revocation check (Section 15.4).
   */
  receiveToken(token, payerCert) {
    if (!isShapeValid(token)) {
      return { accepted: false, reason: 'MALFORMED_TOKEN' };
    }
    if (!this.rootPublicKey) {
      return { accepted: false, reason: 'NO_CACHED_ROOT_KEY' };
    }
    if (!verifyDeviceCert(this.rootPublicKey, payerCert)) {
      return { accepted: false, reason: 'INVALID_PAYER_CERT' };
    }
    if (payerCert.device_id !== token.device_id) {
      return { accepted: false, reason: 'CERT_DEVICE_MISMATCH' };
    }
    if (this.isPeerPossiblyRevoked(token.device_id)) {
      return { accepted: false, reason: 'PAYER_POSSIBLY_REVOKED' };
    }
    const { signature, ...body } = token;
    if (!verifyPayload(payerCert.public_key, body, signature)) {
      return { accepted: false, reason: 'INVALID_SIGNATURE' };
    }
    if (Date.now() > token.expiry) {
      return { accepted: false, reason: 'EXPIRED' };
    }

    this.provisionalBalance += token.amount;
    this.ledger.push(token);
    return { accepted: true, token };
  }

  /** Section 8.3 step 4: queue for sync once a connection is available. */
  drainOutbox() {
    const batch = this.outbox.slice();
    this.outbox = [];
    return batch;
  }

  requeue(tokens) {
    this.outbox.push(...tokens);
  }
}

module.exports = { Wallet };
