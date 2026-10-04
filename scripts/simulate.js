'use strict';


const path = require('path');
const fs = require('fs');
const { buildServer } = require('../src/server/index');
const { Wallet, SyncClient, NfcTransport, BluetoothTransport, SoundTransport } = require('../src/device/index');
const { buildTokenBody } = require('../src/common/tokenSchema');

function line(title) {
  console.log('\n' + '='.repeat(70));
  console.log(title);
  console.log('='.repeat(70));
}

function show(label, obj) {
  console.log(`  ${label}:`, JSON.stringify(obj));
}


async function craftTokenBypassingSoftChecks(wallet, payeeId, amount, counterOverride) {

  const body = buildTokenBody({
    payerId: wallet.deviceId,
    payeeId,
    amount,
    deviceId: wallet.deviceId,
    counter: counterOverride
  });
  const signature = await wallet.keyStore.sign(body);
  return { ...body, signature };
}

async function main() {
  const dbPath = path.join(__dirname, '..', 'data', 'simulation.db');
  for (const suffix of ['', '-wal', '-shm']) {
    const p = dbPath + suffix;
    if (fs.existsSync(p)) fs.unlinkSync(p);
  }

  const { app } = buildServer(dbPath);
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`Reconciliation Service up at ${baseUrl}`);

  const syncClient = new SyncClient({ baseUrl });
  const nfc = new NfcTransport();
  const bluetooth = new BluetoothTransport();
  const sound = new SoundTransport({ corruptionRate: 0.0012 });
  const noisySound = new SoundTransport({ corruptionRate: 0.35 });

  // ---- Provisioning (Section 15.1 - one-time online step) ----
  line('PROVISIONING (bank issues hardware-backed device certs)');
  const alice = new Wallet({ userId: 'user-alice', walletCap: 200000 }); // ₹2,000 cap
  const bob = new Wallet({ userId: 'user-bob', walletCap: 200000 });
  const carol = new Wallet({ userId: 'user-carol', walletCap: 200000 });
  const dave = new Wallet({ userId: 'user-dave', walletCap: 1000 }); // ₹10 cap, for the breach demo

  for (const [name, wallet] of [['Alice', alice], ['Bob', bob], ['Carol', carol], ['Dave', dave]]) {
    await syncClient.provisionDevice(wallet);
    console.log(`  ${name} provisioned. device_id=${wallet.deviceId}`);
  }

  // Section 8.1: one-time online load-in from the real bank account.
  alice.loadFunds(150000); // ₹1,500
  bob.loadFunds(50000);
  dave.loadFunds(1000);

  // Devices cache the revocation snapshot while online (Section 15.4).
  for (const wallet of [alice, bob, carol, dave]) {
    await syncClient.fetchRevocationSnapshot(wallet);
  }

  // ---- Scenario 1: honest NFC tap-to-pay, Alice -> Bob ----
  line('SCENARIO 1: NFC tap-to-pay, Alice -> Bob, ₹500 (fully offline)');
  const token1 = await alice.createPaymentToken(bob.deviceId, 50000);
  await nfc.send(token1, (received) => {
    const outcome = bob.receiveToken(received, alice.cert);
    console.log('  Bob offline verification:', outcome.accepted ? 'ACCEPTED (provisional)' : `REJECTED (${outcome.reason})`);
  });
  console.log(`  Alice local balance after send: ${alice.balance} paise, counter=${alice.counter}`);
  console.log(`  Bob provisional balance: ${bob.provisionalBalance} paise`);

  // ---- Scenario 2: Bluetooth transfer, Alice -> Carol ----
  line('SCENARIO 2: Bluetooth transfer, Alice -> Carol, ₹300 (fully offline)');
  const token2 = await alice.createPaymentToken(carol.deviceId, 30000);
  await bluetooth.send(token2, (received) => {
    const outcome = carol.receiveToken(received, alice.cert);
    console.log('  Carol offline verification:', outcome.accepted ? 'ACCEPTED (provisional)' : `REJECTED (${outcome.reason})`);
  });

  // ---- Scenario 3: sound/ultrasonic transfer, Bob -> Alice ----
  line('SCENARIO 3: sound/ultrasonic transfer, Bob -> Alice, ₹100 (bandwidth-limited channel)');
  const token3 = await bob.createPaymentToken(alice.deviceId, 10000);
  // Real device behavior on a lossy audio channel: retry the chirp. Two
  // independent safety nets have to both be satisfied for the token to be
  // accepted - the repetition-code decode AND the signature check
  // (Section 15.3: "signature covers the whole payload; any modification
  // invalidates it"), so even bit-noise that slips past decode-level
  // correction is still caught cryptographically, not silently accepted.
  for (let attempt = 1; attempt <= 3; attempt++) {
    let done = false;
    await sound.send(token3, (received) => {
      if (!received) {
        console.log(`  Attempt ${attempt}: decode FAILED after error correction - safe failure, no token created. Retrying chirp...`);
        return;
      }
      const outcome = alice.receiveToken(received, bob.cert);
      if (outcome.accepted) {
        console.log(`  Attempt ${attempt}: decoded and ACCEPTED (provisional).`);
        done = true;
      } else if (outcome.reason === 'INVALID_SIGNATURE') {
        console.log(`  Attempt ${attempt}: decode looked clean but signature check caught residual corruption - defense in depth. Retrying chirp...`);
      } else {
        console.log(`  Attempt ${attempt}: REJECTED (${outcome.reason})`);
      }
    });
    if (done) break;
  }

  // Deliberately hostile channel: demonstrates the fail-closed path from
  // Section 17 ("failed decode = no token created, safe failure") on its
  // own, without relying on getting unlucky above.
  console.log('  Separately, a deliberately noisy channel to show the fail-closed decode path:');
  const noisyToken = await bob.createPaymentToken(alice.deviceId, 1000);
  // Note: createPaymentToken already committed this token locally (balance
  // decremented, counter consumed, queued in bob.outbox) the moment it was
  // signed - that commit is independent of whether the over-the-air
  // transmission below succeeds. A failed chirp just means Alice never
  // received a provisional credit for it; Bob's token still syncs and
  // settles normally, matching real hardware where signing and
  // transmission are separate steps.
  await noisySound.send(noisyToken, (received) => {
    if (!received) {
      console.log('    Decode FAILED under heavy channel noise - safe failure, no token created on the receiving side.');
      return;
    }
    console.log('    Unexpectedly decoded cleanly despite heavy noise.');
  });

  // ---- Scenario 4: sync everyone (Section 8.4 - reconnect) ----
  line('SCENARIO 4: all devices reconnect and sync (Section 8.4)');
  for (const [name, wallet] of [['Alice', alice], ['Bob', bob], ['Carol', carol]]) {
    const result = await syncClient.syncBatch(wallet);
    console.log(`  ${name} sync result:`);
    for (const r of result.results) show('    token', r);
  }

  // ---- Scenario 5: double-spend attempt (Section 8.4/13) ----
  line('SCENARIO 5: double-spend - Alice (tampered device) reuses counter=2 for two different payees');
  const dupCounter = alice.counter + 1; // next legitimate counter slot
  const fraudTokenToCarol = await craftTokenBypassingSoftChecks(alice, carol.deviceId, 40000, dupCounter);
  const fraudTokenToBob = await craftTokenBypassingSoftChecks(alice, bob.deviceId, 40000, dupCounter);

  await nfc.send(fraudTokenToCarol, (received) => {
    const outcome = carol.receiveToken(received, alice.cert);
    console.log('  Carol accepts offline copy 1:', outcome.accepted ? 'ACCEPTED (provisional)' : outcome.reason);
    if (outcome.accepted) carol.outbox.push(received); // queue for sync manually since it bypassed createPaymentToken
  });
  await bluetooth.send(fraudTokenToBob, (received) => {
    const outcome = bob.receiveToken(received, alice.cert);
    console.log('  Bob accepts offline copy 2:  ', outcome.accepted ? 'ACCEPTED (provisional)' : outcome.reason);
    if (outcome.accepted) bob.outbox.push(received);
  });

  console.log('  Both payees accepted offline - this is the "no live check possible" moment (Section 1/8.4).');
  console.log('  Now both sync to the server - only one can settle:');
  const carolSync = await syncClient.syncBatch(carol);
  for (const r of carolSync.results) show('    Carol sync token', r);
  const bobSync = await syncClient.syncBatch(bob);
  for (const r of bobSync.results) show('    Bob sync token', r);

  const aliceStatus = await syncClient.getDeviceStatus(alice.deviceId);
  console.log(`  Alice device status after fraud detection: ${aliceStatus.status} (fraud_strikes=${aliceStatus.fraud_strikes})`);

  // ---- Scenario 6: revoked device rejected offline, once cache refreshes ----
  line('SCENARIO 6: offline revocation - stale cache vs refreshed cache (Section 15.4)');
  const oneMoreToken = await craftTokenBypassingSoftChecks(alice, dave.deviceId, 500, dupCounter + 1);
  await nfc.send(oneMoreToken, (received) => {
    const outcome = dave.receiveToken(received, alice.cert);
    console.log('  Dave with STALE revocation cache:', outcome.accepted ? 'ACCEPTED (bounded, stale-cache risk)' : outcome.reason);
  });
  await syncClient.fetchRevocationSnapshot(dave); // Dave comes online briefly, refreshes cache
  await nfc.send(oneMoreToken, (received) => {
    const outcome = dave.receiveToken(received, alice.cert);
    console.log('  Dave with REFRESHED revocation cache:', outcome.accepted ? 'ACCEPTED' : `REJECTED (${outcome.reason})`);
  });

  // ---- Scenario 7: expired token still consumes a counter slot ----
  line('SCENARIO 7: expired token (Section 8.2/9) - rejected, but its counter slot is consumed');
  const expiredToken = await craftTokenBypassingSoftChecks(bob, carol.deviceId, 5000, bob.counter + 1);
  expiredToken.expiry = Date.now() - 1000; // force it into the past
  expiredToken.signature = await bob.keyStore.sign(
    (({ signature, ...rest }) => rest)(expiredToken)
  );
  bob.outbox.push(expiredToken);
  const expiredSync = await syncClient.syncBatch(bob);
  for (const r of expiredSync.results) show('  Bob sync (expired token)', r);

  // ---- Scenario 8: wallet cap breach (Section 15.6/17) ----
  line("SCENARIO 8: wallet-cap breach on Dave's device (cap=₹10, attempted amount=₹20)");
  const overCapToken = await craftTokenBypassingSoftChecks(dave, bob.deviceId, 2000, dave.counter + 1);
  dave.outbox.push(overCapToken);
  const capSync = await syncClient.syncBatch(dave);
  for (const r of capSync.results) show('  Dave sync (over cap)', r);

  // ---- Final state + tamper-evident audit trail ----
  line('FINAL DEVICE STATES');
  for (const [name, wallet] of [['Alice', alice], ['Bob', bob], ['Carol', carol], ['Dave', dave]]) {
    const status = await syncClient.getDeviceStatus(wallet.deviceId);
    console.log(`  ${name}: status=${status.status} last_synced_counter=${status.last_synced_counter} fraud_strikes=${status.fraud_strikes}`);
  }

  line("ALICE'S HASH-CHAINED AUDIT LOG (Section 10) - tamper-evidence check");
  const aliceAudit = await syncClient.getAuditTrail(alice.deviceId);
  console.log(`  chain valid: ${aliceAudit.chain.valid}, entries: ${aliceAudit.chain.entries}`);
  for (const entry of aliceAudit.history) {
    const ev = JSON.parse(entry.event);
    console.log(`    [${new Date(entry.timestamp).toISOString()}] ${ev.type} ${ev.reason || ev.status || ''}`);
  }

  server.close();
  console.log('\nSimulation complete. Server stopped.');
}

main().catch((err) => {
  console.error('Simulation failed:', err);
  process.exit(1);
});
