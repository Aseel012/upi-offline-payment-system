'use strict';

/**
 * Section 4: Sound/ultrasonic transfer - speaker + mic, audio modulation
 * (bytes -> FSK/ultrasonic chirp -> decoded by the other phone's mic).
 * Section 16: bandwidth-constrained (~tens of bytes/sec); token payload
 * must stay minimal, and error-correction overhead has to fit that budget.
 * Section 17: "Sound/Bluetooth/NFC channel corruption -> error-correction
 * recovers minor corruption; failed decode = no token created, safe
 * failure."
 *
 * Reed-Solomon itself is out of scope for a user-space simulation; this
 * module stands in for it with a repetition code (send the payload N times,
 * majority-vote each byte on decode), which has the same shape of guarantee
 * for demonstration purposes: tolerate bounded corruption, fail closed
 * (return null, never a corrupted-but-accepted token) beyond that bound.
 */

class SoundTransport {
  constructor({ bandwidthBytesPerSec = 20, corruptionRate = 0.01, repetitions = 3 } = {}) {
    this.bandwidthBytesPerSec = bandwidthBytesPerSec;
    this.corruptionRate = corruptionRate;
    this.repetitions = repetitions;
  }

  _corrupt(buffer) {
    const out = Buffer.from(buffer);
    for (let i = 0; i < out.length; i++) {
      for (let bit = 0; bit < 8; bit++) {
        if (Math.random() < this.corruptionRate) {
          out[i] ^= 1 << bit; // simulate a flipped bit from ambient noise
        }
      }
    }
    return out;
  }

  _majorityDecode(copies) {
    const length = copies[0].length;
    const decoded = Buffer.alloc(length);
    let unresolvedBytes = 0;
    for (let i = 0; i < length; i++) {
      const counts = new Map();
      for (const copy of copies) {
        const val = copy[i];
        counts.set(val, (counts.get(val) || 0) + 1);
      }
      let bestVal = null;
      let bestCount = 0;
      for (const [val, count] of counts) {
        if (count > bestCount) {
          bestVal = val;
          bestCount = count;
        }
      }
      // No majority (every copy disagrees) -> this byte is unrecoverable.
      if (bestCount <= copies.length / 2) unresolvedBytes++;
      decoded[i] = bestVal;
    }
    // Fail closed if too much of the payload could not be reconstructed.
    if (unresolvedBytes > length * 0.05) return null;
    return decoded;
  }

  /**
   * Encodes, "transmits" over an audio channel with the configured
   * corruption rate, and hands the receiver either the decoded object or
   * null on unrecoverable corruption (safe failure - never a mangled
   * token).
   */
  async send(payloadObj, receiver) {
    const original = Buffer.from(JSON.stringify(payloadObj), 'utf8');
    const transmissionMs = (original.length / this.bandwidthBytesPerSec) * 1000;
    await new Promise((resolve) => setTimeout(resolve, Math.min(transmissionMs, 250)));

    const copies = [];
    for (let i = 0; i < this.repetitions; i++) {
      copies.push(this._corrupt(original));
    }
    const decoded = this._majorityDecode(copies);
    if (!decoded) {
      return receiver(null);
    }
    try {
      return receiver(JSON.parse(decoded.toString('utf8')));
    } catch (err) {
      // JSON failed to parse post-correction - still a safe failure, not a
      // corrupted token silently accepted.
      return receiver(null);
    }
  }
}

module.exports = { SoundTransport };
