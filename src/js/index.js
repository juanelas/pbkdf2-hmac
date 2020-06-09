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
export default function pbkdf2Hmac (P, S, c, dkLen, hash = 'SHA-256') {
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
    if (process.browser) {
      crypto.subtle.importKey('raw', P, 'PBKDF2', false, ['deriveBits']).then(
        PKey => {
          const params = { name: 'PBKDF2', hash: hash, salt: S, iterations: c } // pbkdf2 params
          crypto.subtle.deriveBits(params, PKey, dkLen * 8).then(
            derivedKey => resolve(derivedKey),
            // eslint-disable-next-line handle-callback-err
            err => {
              // Try our native implementation if browser's native one fails (firefox one fails when dkLen > 256)
              _pbkdf2(P, S, c, dkLen, hash).then(
                derivedKey => resolve(derivedKey),
                error => reject(error)
              )
            }
          )
        },
        err => reject(err)
      )
    } else {
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

async function _pbkdf2 (P, S, c, dkLen, hash) {
  if (!(hash in HASHALGS)) {
    throw new RangeError(`Valid hash algorithm values are any of ${Object.keys(HASHALGS)}`)
  }

  if (!Number.isInteger(c) || c <= 0) throw new RangeError('c must be a positive integer')

  /*
  1.  If dkLen > (2^32 - 1) * hLen, output "derived key too long"
          and stop.
  */
  const hLen = HASHALGS[hash].outputLength
  if (!Number.isInteger(dkLen) || dkLen <= 0 || dkLen >= (2 ** 32 - 1) * hLen) throw new RangeError('dkLen must be a positive integer < (2 ** 32 - 1) * hLen')

  /*
  2.  Let l be the number of hLen-octet blocks in the derived key,
      rounding up, and let r be the number of octets in the last
      block:
        l = CEIL (dkLen / hLen)
        r = dkLen - (l - 1) * hLen
  */
  const l = Math.ceil(dkLen / hLen)
  const r = dkLen - (l - 1) * hLen

  /*
  3.  For each block of the derived key apply the function F defined
      below to the password P, the salt S, the iteration count c,
      and the block index to compute the block:

                T_1 = F (P, S, c, 1) ,
                T_2 = F (P, S, c, 2) ,
                ...
                T_l = F (P, S, c, l) ,
  */
  const T = new Array(l)

  if (P.length === 0) P = new Uint8Array(HASHALGS[hash].blockSize) // HMAC does not accept an empty ArrayVecor

  P = await crypto.subtle.importKey(
    'raw',
    P,
    {
      name: 'HMAC',
      hash: { name: hash }
    },
    true,
    ['sign']
  )

  const HMAC = async function (key, arr) {
    const hmac = await crypto.subtle.sign(
      'HMAC',
      key,
      arr
    )
    return new Uint8Array(hmac)
  }
  for (let i = 0; i < l; i++) {
    T[i] = await F(P, S, c, i + 1)
  }
  /*
      where the function F is defined as the exclusive-or sum of the
      first c iterates of the underlying pseudorandom function PRF
      applied to the password P and the concatenation of the salt S
      and the block index i:

                F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c

      where
                U_1 = PRF (P, S || INT (i)) ,
                U_2 = PRF (P, U_1) ,
                ...
                U_c = PRF (P, U_{c-1}) .

      Here, INT (i) is a four-octet encoding of the integer i, most
      significant octet first.
  */
  /**
   *
   * @param {Uint8Array | CryptoKey} P - password
   * @param {Uint8Array} S - salt
   * @param {number} c - iterations
   * @param {number} i - block index
   */
  async function F (P, S, c, i) {
    function INT (i) {
      const buf = new ArrayBuffer(4)
      const view = new DataView(buf)
      view.setUint32(0, i, false)
      return new Uint8Array(buf)
    }

    const Uacc = await HMAC(P, concat(S, INT(i)))
    let UjMinus1 = Uacc
    for (let j = 1; j < c; j++) {
      UjMinus1 = await HMAC(P, UjMinus1)
      xorMe(Uacc, UjMinus1)
    }

    return Uacc
  }

  /*
  4.  Concatenate the blocks and extract the first dkLen octets to
      produce a derived key DK:
                DK = T_1 || T_2 ||  ...  || T_l<0..r-1>

  5.  Output the derived key DK.
  */
  T[l - 1] = T[l - 1].slice(0, r)

  return concat(...T)
}

/**
 * Concatenates several UInt8Array
 *
 * @param  {...Uint8Array} arrs
 */
function concat (...arrs) {
  // sum of individual array lengths
  const totalLength = arrs.reduce((acc, value) => acc + value.length, 0)

  if (!arrs.length) throw new RangeError('Cannot concat no arrays')

  const result = new Uint8Array(totalLength)

  // for each array - copy it over result
  // next array is copied right after the previous one
  let length = 0
  for (const array of arrs) {
    result.set(array, length)
    length += array.length
  }

  return result
}

/**
 * arr2 is xor-ed to arr1
 * @param  {TypedArray} arr1
 * @param  {TypedArray} arr2
 */
function xorMe (arr1, arr2) {
  for (let i = 0; i < arr1.length; i++) {
    arr1[i] ^= arr2[i]
  }
}
