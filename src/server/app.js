'use strict';

/**
 * Section 7 - REQUEST LIFECYCLE:
 *   Load balancer -> Auth middleware -> Rate-limit middleware -> Controller
 *   -> Service layer (Reconciliation) -> Repository layer (SQL) ->
 *   Transaction commit -> Response
 *
 * Ordering note (Section 7): auth runs before rate-limiting so anonymous
 * garbage is rejected cheaply; rate-limiting before auth would let an
 * attacker burn CPU on invalid signatures at scale.
 */

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { verifyPayload } = require('../crypto/keys');
const { CertAuthority } = require('./certAuthority');
const { RATE_LIMIT } = require('../common/constants');

function rateLimiter() {
  const hits = new Map(); // device_id -> [timestamps]
  return function rateLimitMiddleware(req, res, next) {
    const deviceId = req.headers['x-device-id'] || req.body?.device_id || 'anonymous';
    const now = Date.now();
    const windowStart = now - RATE_LIMIT.WINDOW_MS;
    const list = (hits.get(deviceId) || []).filter((t) => t > windowStart);
    list.push(now);
    hits.set(deviceId, list);
    if (list.length > RATE_LIMIT.MAX_REQUESTS) {
      return res.status(429).json({ error: 'RATE_LIMITED' });
    }
    next();
  };
}

function authMiddleware(db) {
  return function requireDeviceSignature(req, res, next) {
    const deviceId = req.headers['x-device-id'];
    const signature = req.headers['x-request-signature'];
    if (!deviceId || !signature) {
      return res.status(401).json({ error: 'MISSING_AUTH_HEADERS' });
    }
    const device = db.prepare('SELECT * FROM devices WHERE device_id = ?').get(deviceId);
    if (!device) {
      return res.status(401).json({ error: 'UNKNOWN_DEVICE' });
    }
    if (device.status === 'FROZEN') {
      return res.status(403).json({ error: 'DEVICE_FROZEN' });
    }
    // The request itself must be signed - it's moving money (Section 7).
    const ok = verifyPayload(device.public_key, req.body, signature);
    if (!ok) {
      return res.status(401).json({ error: 'INVALID_REQUEST_SIGNATURE' });
    }
    req.device = device;
    next();
  };
}

function createApp({ db, certAuthority, reconciliationService, revocationRegistry, auditLog }) {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  const auth = authMiddleware(db);
  const rateLimit = rateLimiter();

  // One-time online provisioning (Section 15.1). Not on the offline path.
  app.post('/api/v1/provision', (req, res) => {
    const { device_id, user_id, public_key, wallet_cap, attested } = req.body || {};
    if (!device_id || !user_id || !public_key || !wallet_cap) {
      return res.status(400).json({ error: 'MISSING_FIELDS' });
    }
    const existing = db.prepare('SELECT 1 FROM devices WHERE device_id = ?').get(device_id);
    if (existing) {
      return res.status(409).json({ error: 'DEVICE_ALREADY_PROVISIONED' });
    }
    let cert;
    try {
      cert = certAuthority.issueDeviceCert({
        deviceId: device_id,
        publicKeyPem: public_key,
        walletCap: wallet_cap,
        attested: attested !== false
      });
    } catch (err) {
      return res.status(403).json({ error: err.message });
    }
    const now = Date.now();
    db.prepare(
      `INSERT INTO devices (device_id, user_id, public_key, cert, wallet_cap, status, last_synced_counter, fraud_strikes, last_seen_at, created_at)
       VALUES (?, ?, ?, ?, ?, 'ONLINE_NATIVE', -1, 0, ?, ?)`
    ).run(device_id, user_id, public_key, JSON.stringify(cert), wallet_cap, now, now);
    auditLog.append(device_id, { type: 'DEVICE_PROVISIONED', wallet_cap });
    res.status(201).json({ cert, root_public_key: certAuthority.getRootPublicKey() });
  });

  // Ingest API: validation + enqueue only. No business logic lives here -
  // every token is handed straight to the Reconciliation Service, which is
  // the only code path allowed to mutate the ledger (Section 5).
  app.post('/api/v1/sync', auth, rateLimit, (req, res) => {
    const { batch_id, device_id, tokens } = req.body || {};
    if (!batch_id || !device_id || !Array.isArray(tokens)) {
      return res.status(400).json({ error: 'MALFORMED_BATCH' });
    }
    if (device_id !== req.device.device_id) {
      return res.status(403).json({ error: 'DEVICE_ID_MISMATCH' });
    }

    const receivedAt = Date.now();
    db.prepare(
      `INSERT INTO reconciliation_batches (batch_id, device_id, received_at, processed_at, outcome)
       VALUES (?, ?, ?, NULL, NULL)`
    ).run(batch_id, device_id, receivedAt);

    const results = tokens.map((token) => {
      const outcome = reconciliationService.reconcileToken(token);
      return { token_id: token.token_id, counter: token.counter, ...outcome };
    });

    const outcomeSummary = results.map((r) => r.outcome).join(',');
    db.prepare(
      `UPDATE reconciliation_batches SET processed_at = ?, outcome = ? WHERE batch_id = ?`
    ).run(Date.now(), outcomeSummary, batch_id);

    res.json({ batch_id, results });
  });

  // Section 19 - revocation list distributed as an immutable compressed
  // snapshot (Bloom filter), not a live per-device query.
  app.get('/api/v1/revocation', (req, res) => {
    res.json(revocationRegistry.getSnapshot());
  });

  app.get('/api/v1/device/:deviceId', (req, res) => {
    const device = db.prepare('SELECT * FROM devices WHERE device_id = ?').get(req.params.deviceId);
    if (!device) return res.status(404).json({ error: 'NOT_FOUND' });
    res.json(device);
  });

  app.get('/api/v1/audit/:deviceId', (req, res) => {
    res.json({
      history: auditLog.history(req.params.deviceId),
      chain: auditLog.verifyChain(req.params.deviceId)
    });
  });

  return app;
}

module.exports = { createApp, uuidv4 };
