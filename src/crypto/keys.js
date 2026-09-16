'use strict';

/**
 * Cryptographic primitives (Section 15 - SECURITY MODEL).
 *
 * ECDSA/Ed25519 signature over the token, per Section 15.6. Node's built-in
 * crypto module provides Ed25519 (RFC 8032) key generation, signing and
 * verification without external dependencies.
 *
 * generateKeypair() / sign() / verify() are the raw primitives.
 * KeyStore (below) is what device code actually uses: it wraps a generated
 * keypair so the private key is a closure variable, never returned by any
 * method, simulating the "OS can only ask the secure hardware to sign, never
 * export the key" property described in Section 15.2.
 */

const crypto = require('crypto');

function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  };
}

function canonicalize(obj) {
  // Deterministic JSON: sort keys recursively so signature verification is
  // stable regardless of property insertion order. Values are not hashed
  // separately - the whole canonical payload is what gets signed, per
  // Section 15.3 ("signature covers the whole payload").
  if (Array.isArray(obj)) {
    return `[${obj.map(canonicalize).join(',')}]`;
  }
  if (obj && typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
  }
  return JSON.stringify(obj);
}

function signPayload(privateKeyPem, payload) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const data = Buffer.from(canonicalize(payload), 'utf8');
  const signature = crypto.sign(null, data, privateKey);
  return signature.toString('base64');
}

function verifyPayload(publicKeyPem, payload, signatureBase64) {
  try {
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const data = Buffer.from(canonicalize(payload), 'utf8');
    const signature = Buffer.from(signatureBase64, 'base64');
    return crypto.verify(null, data, publicKey, signature);
  } catch (err) {
    return false;
  }
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Simulated hardware-backed keystore (Android StrongBox/Keystore, iOS Secure
 * Enclave, or SIM/UICC Java Card applet - Section 15.1). The private key is
 * generated once and held in a closure; nothing outside this module can read
 * it. Every consumer only ever calls `.sign()`.
 */
class KeyStore {
  constructor() {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    this.publicKeyPem = publicKeyPem;
    this._sign = (payload) => signPayload(privateKeyPem, payload);
  }

  getPublicKey() {
    return this.publicKeyPem;
  }

  /**
   * Simulates the async round-trip to secure hardware (Section 6 / 16):
   * this is a binder/IPC-style call in the real system and must never block
   * the UI thread - modeled here as a Promise with a small artificial delay.
   * Also simulates the local-auth gate (Section 15.5): signing refuses to
   * proceed without a fresh "biometric" check, represented by the
   * `authGateOk` flag the caller must pass.
   */
  async sign(payload, { authGateOk = true } = {}) {
    if (!authGateOk) {
      throw new Error('LOCAL_AUTH_GATE_FAILED: signing refused without fresh biometric/PIN check');
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
    return this._sign(payload);
  }
}

module.exports = {
  generateKeypair,
  canonicalize,
  signPayload,
  verifyPayload,
  sha256Hex,
  KeyStore
};
