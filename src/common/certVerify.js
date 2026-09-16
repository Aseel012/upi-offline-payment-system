'use strict';

/**
 * Section 15.1: "Payees trust the cert chain - bank root -> device cert ->
 * transaction token signature - entirely offline, once the cert and root
 * public key are cached."
 *
 * This is the payee-side half of that chain (bank root -> device cert).
 * The second half (device cert -> token signature) is checked directly in
 * Wallet.receiveToken with verifyPayload().
 */

const { verifyPayload } = require('../crypto/keys');

function verifyDeviceCert(rootPublicKeyPem, cert) {
  if (!cert || typeof cert !== 'object') return false;
  if (Date.now() > cert.expiry) return false;
  const { signature, ...body } = cert;
  return verifyPayload(rootPublicKeyPem, body, signature);
}

module.exports = { verifyDeviceCert };
