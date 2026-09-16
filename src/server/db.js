'use strict';

/**
 * Section 10 - DATA MODEL / Section 11 - DATABASE EXECUTION.
 *
 * journal_mode = WAL: writes go to the write-ahead log sequentially before
 * the table page is updated; fsync of the WAL is what actually gives
 * durability (Section 11). On crash, SQLite replays the WAL from the last
 * checkpoint on next open - no external recovery step needed.
 *
 * The UNIQUE(device_id, counter) index on wallet_tokens is a *correctness*
 * mechanism (Section 11/13), not just a performance one: it is what turns
 * "check then insert" from a race-prone two-step app operation into a
 * race-proof single DB operation enforced by SQLite's own locking on that
 * index entry.
 */

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

function openDb(dbPath) {
  const dir = path.dirname(dbPath);
  if (dbPath !== ':memory:' && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = FULL'); // fsync on commit - no "committed" txn may vanish on crash
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS devices (
      device_id            TEXT PRIMARY KEY,
      user_id              TEXT NOT NULL,
      public_key            TEXT NOT NULL,
      cert                  TEXT NOT NULL,
      wallet_cap             INTEGER NOT NULL,
      status                 TEXT NOT NULL DEFAULT 'ONLINE_NATIVE',
      last_synced_counter     INTEGER NOT NULL DEFAULT -1,
      fraud_strikes           INTEGER NOT NULL DEFAULT 0,
      last_seen_at             INTEGER NOT NULL,
      created_at               INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS wallet_tokens (
      token_id      TEXT PRIMARY KEY,
      device_id      TEXT NOT NULL REFERENCES devices(device_id),
      counter         INTEGER NOT NULL,
      amount           INTEGER NOT NULL,
      payer_id         TEXT NOT NULL,
      payee_id         TEXT NOT NULL,
      nonce             TEXT NOT NULL,
      signature         TEXT NOT NULL,
      expiry             INTEGER NOT NULL,
      status             TEXT NOT NULL,
      created_at         INTEGER NOT NULL,
      settled_at          INTEGER,
      UNIQUE(device_id, counter)
    );

    CREATE INDEX IF NOT EXISTS idx_wallet_tokens_device_counter
      ON wallet_tokens(device_id, counter);

    CREATE TABLE IF NOT EXISTS reconciliation_batches (
      batch_id      TEXT PRIMARY KEY,
      device_id      TEXT NOT NULL REFERENCES devices(device_id),
      received_at     INTEGER NOT NULL,
      processed_at     INTEGER,
      outcome           TEXT
    );

    CREATE TABLE IF NOT EXISTS revocation_list (
      device_id   TEXT PRIMARY KEY,
      revoked_at   INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      entry_id     INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id     TEXT NOT NULL,
      prev_hash      TEXT NOT NULL,
      this_hash       TEXT NOT NULL,
      event            TEXT NOT NULL,
      timestamp         INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_log_device ON audit_log(device_id);
  `);

  return db;
}

module.exports = { openDb };
