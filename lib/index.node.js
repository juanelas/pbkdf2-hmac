'use strict'

/**
 * PBKDF2 following RFC 2898 using HMAC (with SHA-1, SHA-256, SHA-384, SHA-512) as the PRF
 * @module pbkdf2-hmac
 */

/**
 * A TypedArray object describes an array-like view of an underlying binary data buffer.
 * @typedef {Int8Array|Uint8Array|Uint8ClampedArray|Int16Array|Uint16Array|Int32Array|Uint32Array|Float32Array|Float64Array|BigInt64Array|BigUint64Array} TypedArray
 */

const HASHALGS = { // length in octets of the output of the chosen PRF
  'SHA-1': { outputLength: 20, blockSize: 64 },
  'SHA-256': { outputLength: 32, blockSize: 64 },
  'SHA-384': { outputLength: 48, blockSize: 128 },
  'SHA-512': { outputLength: 64, blockSize: 128 }
}

/**
 * The PBKDF2-HMAC function used below denotes the PBKDF2 algorithm (RFC2898)
 * used with one of the SHA algorithms as the hash function for the HMAC
 *
 * @param {string | ArrayBuffer | TypedArray | DataView} P - A unicode string with a password
 * @param {string | ArrayBuffer | TypedArray | DataView} S - A salt. This should be a random or pseudo-random value of at least 16 bytes. You can easily get one with crypto.getRandomValues(new Uint8Array(16))
 * @param {number} c - iteration count, a positive integer
 * @param {number} dkLen - intended length in octets of the derived key
 * @param {string} hash - hash function to use for the HMAC. One of 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'
 *
 * @returns {Promise<ArrayBuffer>}
 */
function pbkdf2Hmac (P, S, c, dkLen, hash = 'SHA-256') {
  return new Promise((resolve, reject) => {
    if (!(hash in HASHALGS)) {
      reject(new RangeError(`Valid hash algorithm values are any of ${Object.keys(HASHALGS)}`))
    }

    if (typeof P === 'string') P = new TextEncoder().encode(P) // encode S as UTF-8
    else if (P instanceof ArrayBuffer) P = new Uint8Array(P)
    else if (!ArrayBuffer.isView(P)) reject(RangeError('P should be string, ArrayBuffer, TypedArray, DataView'))

    if (typeof S === 'string') S = new TextEncoder().encode(S) // encode S as UTF-8
    else if (S instanceof ArrayBuffer) S = new Uint8Array(S)
    else if (!ArrayBuffer.isView(S)) reject(RangeError('S should be string, ArrayBuffer, TypedArray, DataView'))

    /* eslint-disable no-lone-blocks */
    {
      const nodeAlg = hash.toLowerCase().replace('-', '')
      const crypto = require('crypto')
      crypto.pbkdf2(P, S, c, dkLen, nodeAlg, (err, derivedKey) => {
        if (err) reject(err)
        else resolve(derivedKey.buffer)
      })
    }
    /* eslint-enable no-lone-blocks */
  })
}

module.exports = pbkdf2Hmac
