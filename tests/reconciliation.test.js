'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { buildServer } = require('../src/server/index');
const { KeyStore, verifyPayload } = require('../src/crypto/keys');
const { buildTokenBody } = require('../src/common/tokenSchema');
const { TOKEN_STATE } = require('../src/common/constants');

function freshServer() {
  return buildServer(':memory:');
}

async function provisionDevice(server, { walletCap = 200000 } = {}) {
  const keyStore = new KeyStore();
  const deviceId = `dev-${Math.random().toString(36).slice(2)}`;
  const cert = server.certAuthority.issueDeviceCert({
    deviceId,
    publicKeyPem: keyStore.getPublicKey(),
    walletCap,
    attested: true
  });
  const now = Date.now();
  server.db
    .prepare(
      `INSERT INTO devices (device_id, user_id, public_key, cert, wallet_cap, status, last_synced_counter, fraud_strikes, last_seen_at, created_at)
       VALUES (?, 'test-user', ?, ?, ?, 'ONLINE_NATIVE', -1, 0, ?, ?)`
    )
    .run(deviceId, keyStore.getPublicKey(), JSON.stringify(cert), walletCap, now, now);
  return { deviceId, keyStore, cert };
}

async function makeToken(device, { payeeId, amount, counter, expiryMs }) {
  const body = buildTokenBody({
    payerId: device.deviceId,
    payeeId,
    amount,
    deviceId: device.deviceId,
    counter,
    expiryMs
  });
  const signature = await device.keyStore.sign(body);
  return { ...body, signature };
}

test('a fresh, validly signed token settles', async () => {
  const server = freshServer();
  const payer = await provisionDevice(server);
  const token = await makeToken(payer, { payeeId: 'payee-1', amount: 1000, counter: 0 });

  const result = server.reconciliationService.reconcileToken(token);
  assert.equal(result.outcome, TOKEN_STATE.SETTLED);
});

test('replaying the exact same counter is rejected by the unique constraint, not app logic', async () => {
  const server = freshServer();
  const payer = await provisionDevice(server);
  const tokenA = await makeToken(payer, { payeeId: 'payee-1', amount: 1000, counter: 0 });
  const tokenB = await makeToken(payer, { payeeId: 'payee-2', amount: 1000, counter: 0 }); // same counter, different payee

  const first = server.reconciliationService.reconcileToken(tokenA);
  const second = server.reconciliationService.reconcileToken(tokenB);

  assert.equal(first.outcome, TOKEN_STATE.SETTLED);
  assert.equal(second.outcome, TOKEN_STATE.REJECTED_DUPLICATE);

  const device = server.db.prepare('SELECT * FROM devices WHERE device_id = ?').get(payer.deviceId);
  assert.equal(device.status, 'FROZEN', 'fraud engine should auto-freeze after threshold duplicate strikes');
});

test('a forged signature is rejected before touching the ledger', async () => {
  const server = freshServer();
  const payer = await provisionDevice(server);
  const attacker = new KeyStore(); // different keypair entirely

  const body = buildTokenBody({
    payerId: payer.deviceId,
    payeeId: 'payee-1',
    amount: 1000,
    deviceId: payer.deviceId,
    counter: 0
  });
  const forgedSignature = await attacker.sign(body); // signed with the WRONG key
  const forgedToken = { ...body, signature: forgedSignature };

  const result = server.reconciliationService.reconcileToken(forgedToken);
  assert.equal(result.outcome, TOKEN_STATE.REJECTED_INVALID_SIGNATURE);

  const row = server.db.prepare('SELECT * FROM wallet_tokens WHERE token_id = ?').get(forgedToken.token_id);
  assert.equal(row, undefined, 'a forged token must never reach the ledger table');
});

test('an expired token is rejected but still consumes its counter slot', async () => {
  const server = freshServer();
  const payer = await provisionDevice(server);
  const expiredToken = await makeToken(payer, {
    payeeId: 'payee-1',
    amount: 1000,
    counter: 0,
    expiryMs: -1000 // already expired at creation
  });

  const result = server.reconciliationService.reconcileToken(expiredToken);
  assert.equal(result.outcome, TOKEN_STATE.REJECTED_EXPIRED);

  // The counter slot is consumed - a second token at counter=0 is a
  // duplicate, not a fresh settle, even though the first was rejected.
  const secondToken = await makeToken(payer, { payeeId: 'payee-2', amount: 1000, counter: 0 });
  const secondResult = server.reconciliationService.reconcileToken(secondToken);
  assert.equal(secondResult.outcome, TOKEN_STATE.REJECTED_DUPLICATE);
});

test('a token exceeding the device wallet cap is rejected server-side', async () => {
  const server = freshServer();
  const payer = await provisionDevice(server, { walletCap: 1000 });
  const token = await makeToken(payer, { payeeId: 'payee-1', amount: 5000, counter: 0 });

  const result = server.reconciliationService.reconcileToken(token);
  assert.equal(result.outcome, TOKEN_STATE.REJECTED_CAP_EXCEEDED);
});

test('a revoked device is rejected before signature/ledger checks', async () => {
  const server = freshServer();
  const payer = await provisionDevice(server);
  server.fraudEngine.freeze(payer.deviceId, 'TEST_REVOKE');

  const token = await makeToken(payer, { payeeId: 'payee-1', amount: 1000, counter: 0 });
  const result = server.reconciliationService.reconcileToken(token);
  assert.equal(result.outcome, 'REJECTED_DEVICE_FROZEN');
  assert.ok(server.revocationRegistry.isRevoked(payer.deviceId));
});

test('the audit log hash chain detects tampering', async () => {
  const server = freshServer();
  const payer = await provisionDevice(server);
  const token = await makeToken(payer, { payeeId: 'payee-1', amount: 1000, counter: 0 });
  server.reconciliationService.reconcileToken(token);

  const before = server.auditLog.verifyChain(payer.deviceId);
  assert.equal(before.valid, true);

  // Tamper with a historical entry directly in the DB.
  server.db
    .prepare(
      `UPDATE audit_log SET event = '{"type":"TAMPERED"}'
       WHERE entry_id = (SELECT MIN(entry_id) FROM audit_log WHERE device_id = ?)`
    )
    .run(payer.deviceId);

  const after = server.auditLog.verifyChain(payer.deviceId);
  assert.equal(after.valid, false);
});

test('canonicalized signing is stable regardless of key order', () => {
  const keyStore = new KeyStore();
  const a = { z: 1, a: 2, nested: { b: 1, a: 2 } };
  const b = { a: 2, z: 1, nested: { a: 2, b: 1 } };
  // Not async here - just checking verifyPayload agrees for both orderings
  // once signed via the same canonicalization path.
  return keyStore.sign(a).then((sig) => {
    assert.equal(verifyPayload(keyStore.getPublicKey(), b, sig), true);
  });
});
