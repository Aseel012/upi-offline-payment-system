'use strict';

/**
 * Section 5 - Transport Adapter: NFC/BT/sound-specific send/receive -
 * doesn't know about money logic, just moves bytes.
 *
 * Section 6 - RUNTIME MODEL (drilled): App -> Wallet Manager signs via a
 * secure-hardware IPC call -> Transport Adapter hands signed bytes to the
 * OS NFC stack (Host Card Emulation) -> NFC controller chip -> radio field
 * -> other device's NFC controller -> HCE stack -> app callback.
 *
 * This module simulates that hop: it is a pure byte-mover with a small
 * artificial radio-range latency, nothing more.
 */

class NfcTransport {
  constructor({ latencyMs = 15 } = {}) {
    this.latencyMs = latencyMs;
  }

  /**
   * `receiver` is the other device's onReceive(bytes) callback - stands in
   * for "tap-to-pay" proximity. Real NFC HCE would go through the OS/kernel
   * stack described in Section 6; that layer is out of scope for this
   * user-space simulation.
   */
  async send(payloadObj, receiver) {
    const bytes = Buffer.from(JSON.stringify(payloadObj), 'utf8');
    await new Promise((resolve) => setTimeout(resolve, this.latencyMs));
    const receivedBytes = Buffer.from(bytes); // radio field hop
    return receiver(JSON.parse(receivedBytes.toString('utf8')));
  }
}

module.exports = { NfcTransport };
