'use strict';

module.exports = {
  // Token lifecycle states (Section 9 - STATE MODEL)
  TOKEN_STATE: {
    SIGNED_LOCAL: 'SIGNED_LOCAL',
    TRANSMITTED: 'TRANSMITTED',
    QUEUED_FOR_SYNC: 'QUEUED_FOR_SYNC',
    RECONCILING: 'RECONCILING',
    SETTLED: 'SETTLED',
    REJECTED_DUPLICATE: 'REJECTED_DUPLICATE',
    REJECTED_EXPIRED: 'REJECTED_EXPIRED',
    REJECTED_INVALID_SIGNATURE: 'REJECTED_INVALID_SIGNATURE',
    REJECTED_CAP_EXCEEDED: 'REJECTED_CAP_EXCEEDED',
    REJECTED_REVOKED: 'REJECTED_REVOKED'
  },

  // Device lifecycle states (Section 9 - STATE MODEL)
  DEVICE_STATE: {
    ONLINE_NATIVE: 'ONLINE_NATIVE',
    OFFLINE_SPENDING: 'OFFLINE_SPENDING',
    SYNCING: 'SYNCING',
    RECONCILED: 'RECONCILED',
    FROZEN: 'FROZEN'
  },

  // Default token expiry window (Section 8.2): short window, advisory timestamp,
  // enforced expiry.
  TOKEN_EXPIRY_MS: 5 * 60 * 1000,

  // Default per-device offline wallet cap (Section 8.1). Mirrors the UPI Lite
  // style regulatory cap used as the economic backstop (Section 15.6).
  DEFAULT_WALLET_CAP: 200000, // paise (₹2,000.00)

  // Fraud engine: number of REJECTED_DUPLICATE events before a device is
  // auto-frozen (Section 5 - Fraud Engine, Section 15.3).
  FRAUD_DUPLICATE_THRESHOLD: 1,

  // Reconnect window after which an un-synced device is auto-frozen from the
  // bank side (Section 8.4).
  RECONNECT_FREEZE_WINDOW_MS: 48 * 60 * 60 * 1000,

  // Provisional credit auto-void cutoff for a payee whose counterpart never
  // reconnects (Section 14 - FAILURE MODEL).
  PROVISIONAL_VOID_CUTOFF_MS: 30 * 24 * 60 * 60 * 1000,

  // Simple per-device velocity limit: max sync requests per window
  // (Section 7 - rate-limit middleware).
  RATE_LIMIT: {
    WINDOW_MS: 60 * 1000,
    MAX_REQUESTS: 30
  }
};
