'use strict';

/**
 * Section 15.4 / 19: compact, offline-cacheable revocation snapshot.
 * Shared between server (builds it from revocation_list) and device
 * (deserializes the cached snapshot to check a payer's cert before
 * accepting a token offline).
 */

const crypto = require('crypto');


function djb2(str) {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash + str.charCodeAt(i)) >>> 0;
  }
  return hash;
}

function fnv1a(str) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash;
}

class BloomFilter {
  constructor(sizeBits = 4096, hashFns = [djb2, fnv1a]) {
    this.sizeBits = sizeBits;
    this.hashFns = hashFns;
    this.bits = new Uint8Array(Math.ceil(sizeBits / 8));
  }

  _positions(key) {
    return this.hashFns.map((fn) => fn(key) % this.sizeBits);
  }

  add(key) {
    for (const pos of this._positions(key)) {
      this.bits[pos >> 3] |= 1 << (pos & 7);
    }
  }

  mightContain(key) {
    return this._positions(key).every((pos) => (this.bits[pos >> 3] & (1 << (pos & 7))) !== 0);
  }

  serialize() {
    return {
      sizeBits: this.sizeBits,
      bits: Buffer.from(this.bits).toString('base64'),
      builtAt: Date.now(),
      checksum: crypto.createHash('sha256').update(this.bits).digest('hex')
    };
  }

  static deserialize(snapshot) {
    const filter = new BloomFilter(snapshot.sizeBits);
    filter.bits = new Uint8Array(Buffer.from(snapshot.bits, 'base64'));
    return filter;
  }
}

module.exports = { BloomFilter };
