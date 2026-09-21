'use strict';



const { verifyPayload } = require('../crypto/keys');

function verifyDeviceCert(rootPublicKeyPem, cert) {
  if (!cert || typeof cert !== 'object') return false;
  if (Date.now() > cert.expiry) return false;
  const { signature, ...body } = cert;
  return verifyPayload(rootPublicKeyPem, body, signature);
}

module.exports = { verifyDeviceCert };
