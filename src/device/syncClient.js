'use strict';
const { v4: uuidv4 } = require('uuid');
const { DEVICE_STATE } = require('../common/constants');

class SyncClient {
  constructor({ baseUrl }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async provisionDevice(wallet) {
    const body = {
      device_id: wallet.deviceId,
      user_id: wallet.userId,
      public_key: wallet.keyStore.getPublicKey(),
      wallet_cap: wallet.walletCap,
      attested: true
    };
    const res = await fetch(`${this.baseUrl}/api/v1/provision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(`PROVISION_FAILED: ${JSON.stringify(data)}`);
    wallet.applyProvisioningResult({ cert: data.cert, rootPublicKey: data.root_public_key });
    return data;
  }

  async fetchRevocationSnapshot(wallet) {
    const res = await fetch(`${this.baseUrl}/api/v1/revocation`);
    const snapshot = await res.json();
    wallet.cacheRevocationSnapshot(snapshot);
    return snapshot;
  }

  /**
   * Section 8.4 - what happens at reconnect. Drains the outbox, signs the
   * batch request, and posts it to the Ingest API. On a network-level
   * failure the tokens are requeued (Section 14 - per-token idempotency
   * means a retry only ever resends what wasn't acknowledged; here the
   * whole batch failed to reach the server, so the whole batch is
   * requeued).
   */
  async syncBatch(wallet) {
    const tokens = wallet.drainOutbox();
    if (tokens.length === 0) return { batch_id: null, results: [] };

    wallet.status = DEVICE_STATE.SYNCING;
    const batchId = uuidv4();
    const body = { batch_id: batchId, device_id: wallet.deviceId, tokens };
    const signature = await wallet.keyStore.sign(body);

    let res;
    try {
      res = await fetch(`${this.baseUrl}/api/v1/sync`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-device-id': wallet.deviceId,
          'x-request-signature': signature
        },
        body: JSON.stringify(body)
      });
    } catch (networkErr) {
      wallet.requeue(tokens);
      throw networkErr;
    }

    const data = await res.json();
    if (!res.ok) {
      wallet.requeue(tokens);
      throw new Error(`SYNC_FAILED (${res.status}): ${JSON.stringify(data)}`);
    }

    wallet.status = DEVICE_STATE.RECONCILED;
    return data;
  }

  async getDeviceStatus(deviceId) {
    const res = await fetch(`${this.baseUrl}/api/v1/device/${deviceId}`);
    return res.json();
  }

  async getAuditTrail(deviceId) {
    const res = await fetch(`${this.baseUrl}/api/v1/audit/${deviceId}`);
    return res.json();
  }
}

module.exports = { SyncClient };
