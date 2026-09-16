'use strict';

/**
 * Section 8.2 - The Transaction Token.
 *
 *   Token {
 *     payer_id, payee_id, amount, device_id (payer's)
 *     counter    <- monotonically increasing, per device, never reused
 *     nonce      <- random, prevents replay even if counter is guessed
 *     timestamp  <- advisory only, never trusted for security
 *     expiry     <- short window, e.g. 5 minutes
 *     signature  = Sign(payer_private_key, all_of_the_above)
 *   }
 *
 * The counter is what makes a replayed token instantly detectable at
 * reconciliation. The signature is what lets a payee trust a payer's
 * authorization with zero live connection.
 */

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { TOKEN_EXPIRY_MS } = require('./constants');

function randomNonce() {
  return crypto.randomBytes(16).toString('hex');
}

function buildTokenBody({ payerId, payeeId, amount, deviceId, counter, expiryMs = TOKEN_EXPIRY_MS }) {
  const now = Date.now();
  return {
    token_id: uuidv4(),
    payer_id: payerId,
    payee_id: payeeId,
    amount,
    device_id: deviceId,
    counter,
    nonce: randomNonce(),
    timestamp: now, // advisory only - never trusted for security
    expiry: now + expiryMs
  };
}

function isShapeValid(token) {
  const requiredFields = [
    'token_id',
    'payer_id',
    'payee_id',
    'amount',
    'device_id',
    'counter',
    'nonce',
    'timestamp',
    'expiry',
    'signature'
  ];
  return (
    token &&
    typeof token === 'object' &&
    requiredFields.every((f) => Object.prototype.hasOwnProperty.call(token, f)) &&
    Number.isInteger(token.counter) &&
    token.counter >= 0 &&
    Number.isFinite(token.amount) &&
    token.amount > 0
  );
}

module.exports = { buildTokenBody, isShapeValid, randomNonce };
