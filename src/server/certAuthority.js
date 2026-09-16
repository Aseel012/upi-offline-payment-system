'use strict';

/**
 * Section 15.1 - Key provisioning.
 *
 * The bank holds a root keypair and, during first app setup (online,
 * one-time), signs back a device certificate binding device_id, the
 * device's hardware-backed public key, and its wallet_cap:
 *
 *   Cert = Sign(bank_private_key, {device_id, public_key, wallet_cap,
 *                                    issue_date, expiry})
 *
 * Payees verify the chain bank root -> device cert -> token signature
 * entirely offline, once the cert and root public key are cached
 * (Section 15.1, 8.6).
 */

const { generateKeypair, signPayload } = require('../crypto/keys');
const { verifyDeviceCert } = require('../common/certVerify');

const CERT_VALIDITY_MS = 365 * 24 * 60 * 60 * 1000; // 1 year

class CertAuthority {
  constructor() {
    const { publicKeyPem, privateKeyPem } = generateKeypair();
    this.rootPublicKeyPem = publicKeyPem;
    this._rootPrivateKeyPem = privateKeyPem;
  }

  getRootPublicKey() {
    return this.rootPublicKeyPem;
  }

  /**
   * Issues a device certificate. Requires hardware attestation to have
   * already passed (Section 15.3 - "Cert issuance requires hardware
   * attestation") - modeled here as the `attested` boolean the caller must
   * supply from the device's attestation flow.
   */
  issueDeviceCert({ deviceId, publicKeyPem, walletCap, attested }) {
    if (!attested) {
      throw new Error('ATTESTATION_FAILED: cannot issue certificate for unattested hardware');
    }
    const issueDate = Date.now();
    const body = {
      device_id: deviceId,
      public_key: publicKeyPem,
      wallet_cap: walletCap,
      issue_date: issueDate,
      expiry: issueDate + CERT_VALIDITY_MS
    };
    const signature = signPayload(this._rootPrivateKeyPem, body);
    return { ...body, signature };
  }

  /**
   * Offline-verifiable: only needs the cached root public key, not a live
   * call to the bank (Section 15.1).
   */
  static verifyDeviceCert(rootPublicKeyPem, cert) {
    return verifyDeviceCert(rootPublicKeyPem, cert);
  }
}

module.exports = { CertAuthority, CERT_VALIDITY_MS };
