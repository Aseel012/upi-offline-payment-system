'use strict';

/**
 * Section 4: Bluetooth offline transfer - BLE pairing, longer range than
 * NFC. Section 5: still just a byte-mover, no money logic here.
 */


class BluetoothTransport {
  constructor({ latencyMs = 80, pairingDelayMs = 120 } = {}) {
    this.latencyMs = latencyMs;
    this.pairingDelayMs = pairingDelayMs;
  }

  async pair() {
    // Simulates BLE pairing handshake before any payload can move.
    await new Promise((resolve) => setTimeout(resolve, this.pairingDelayMs));
    return true;
  }

  async send(payloadObj, receiver) {
    await this.pair();
    const bytes = Buffer.from(JSON.stringify(payloadObj), 'utf8');
    await new Promise((resolve) => setTimeout(resolve, this.latencyMs));
    return receiver(JSON.parse(bytes.toString('utf8')));
  }
}

module.exports = { BluetoothTransport };
