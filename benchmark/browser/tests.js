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
};

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
      reject(new RangeError(`Valid hash algorithm values are any of ${Object.keys(HASHALGS)}`));
    }

    if (typeof P === 'string') P = new TextEncoder().encode(P); // encode S as UTF-8
    else if (P instanceof ArrayBuffer) P = new Uint8Array(P);
    else if (!ArrayBuffer.isView(P)) reject(RangeError('P should be string, ArrayBuffer, TypedArray, DataView'));

    if (typeof S === 'string') S = new TextEncoder().encode(S); // encode S as UTF-8
    else if (S instanceof ArrayBuffer) S = new Uint8Array(S);
    else if (!ArrayBuffer.isView(S)) reject(RangeError('S should be string, ArrayBuffer, TypedArray, DataView'));

    /* eslint-disable no-lone-blocks */
    {
      crypto.subtle.importKey('raw', P, 'PBKDF2', false, ['deriveBits']).then(
        PKey => {
          const params = { name: 'PBKDF2', hash: hash, salt: S, iterations: c }; // pbkdf2 params
          crypto.subtle.deriveBits(params, PKey, dkLen * 8).then(
            derivedKey => resolve(derivedKey),
            // eslint-disable-next-line handle-callback-err
            err => {
              // Try our native implementation if browser's native one fails (firefox one fails when dkLen > 256)
              _pbkdf2(P, S, c, dkLen, hash).then(
                derivedKey => resolve(derivedKey),
                error => reject(error)
              );
            }
          );
        },
        err => reject(err)
      );
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
  const hLen = HASHALGS[hash].outputLength;
  if (!Number.isInteger(dkLen) || dkLen <= 0 || dkLen >= (2 ** 32 - 1) * hLen) throw new RangeError('dkLen must be a positive integer < (2 ** 32 - 1) * hLen')

  /*
  2.  Let l be the number of hLen-octet blocks in the derived key,
      rounding up, and let r be the number of octets in the last
      block:
        l = CEIL (dkLen / hLen)
        r = dkLen - (l - 1) * hLen
  */
  const l = Math.ceil(dkLen / hLen);
  const r = dkLen - (l - 1) * hLen;

  /*
  3.  For each block of the derived key apply the function F defined
      below to the password P, the salt S, the iteration count c,
      and the block index to compute the block:

                T_1 = F (P, S, c, 1) ,
                T_2 = F (P, S, c, 2) ,
                ...
                T_l = F (P, S, c, l) ,
  */
  const T = new Array(l);

  if (P.length === 0) P = new Uint8Array(HASHALGS[hash].blockSize); // HMAC does not accept an empty ArrayVecor

  P = await crypto.subtle.importKey(
    'raw',
    P,
    {
      name: 'HMAC',
      hash: { name: hash }
    },
    true,
    ['sign']
  );

  const HMAC = async function (key, arr) {
    const hmac = await crypto.subtle.sign(
      'HMAC',
      key,
      arr
    );
    return new Uint8Array(hmac)
  };
  for (let i = 0; i < l; i++) {
    T[i] = await F(P, S, c, i + 1);
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
      const buf = new ArrayBuffer(4);
      const view = new DataView(buf);
      view.setUint32(0, i, false);
      return new Uint8Array(buf)
    }

    const Uacc = await HMAC(P, concat(S, INT(i)));
    let UjMinus1 = Uacc;
    for (let j = 1; j < c; j++) {
      UjMinus1 = await HMAC(P, UjMinus1);
      xorMe(Uacc, UjMinus1);
    }

    return Uacc
  }

  /*
  4.  Concatenate the blocks and extract the first dkLen octets to
      produce a derived key DK:
                DK = T_1 || T_2 ||  ...  || T_l<0..r-1>

  5.  Output the derived key DK.
  */
  T[l - 1] = T[l - 1].slice(0, r);

  return concat(...T).buffer
}

function concat (...arrs) {
  // sum of individual array lengths
  const totalLength = arrs.reduce((acc, value) => acc + value.length, 0);

  if (!arrs.length) throw new RangeError('Cannot concat no arrays')

  const result = new Uint8Array(totalLength);

  // for each array - copy it over result
  // next array is copied right after the previous one
  let length = 0;
  for (const array of arrs) {
    result.set(array, length);
    length += array.length;
  }

  return result
}

function xorMe (arr1, arr2) {
  for (let i = 0; i < arr1.length; i++) {
    arr1[i] ^= arr2[i];
  }
}

/**
 * A TypedArray object describes an array-like view of an underlying binary data buffer.
 * @typedef {Int8Array|Uint8Array|Uint8ClampedArray|Int16Array|Uint16Array|Int32Array|Uint32Array|Float32Array|Float64Array|BigInt64Array|BigUint64Array} TypedArray
 */

/**
 * Converts a bigint to an ArrayBuffer or a Buffer (default for Node.js)
 *
 * @param {bigint} a
 * @param {boolean} [returnArrayBuffer = false] In Node JS forces the output to be an ArrayBuffer instead of a Buffer (default).
 *
 * @returns {ArrayBuffer|Buffer} An ArrayBuffer or a Buffer with a binary representation of the input bigint
 */
function bigintToBuf (a, returnArrayBuffer = false) {
  return hexToBuf(bigintToHex(a), returnArrayBuffer)
}

/**
 * Converts an ArrayBuffer, TypedArray or Buffer (node.js) to a bigint
 *
 * @param {ArrayBuffer|TypedArray|Buffer} buf
 *
 * @returns {bigint} A BigInt
 */
function bufToBigint (buf) {
  // return BigInt('0x' + bufToHex(buf))
  let bits = 8n;
  if (ArrayBuffer.isView(buf)) bits = BigInt(buf.BYTES_PER_ELEMENT * 8);
  else buf = new Uint8Array(buf);

  let ret = 0n;
  for (const i of buf.values()) {
    const bi = BigInt(i);
    ret = (ret << bits) + bi;
  }
  return ret
}

/**
 * Converts a bigint to a hexadecimal string
 *
 * @param {bigint} a
 *
 * @returns {str} A hexadecimal representation of the input bigint
 */
function bigintToHex (a) {
  return a.toString(16)
}

/**
 * Converts a hexadecimal string to a bigint
 *
 * @param {string} hexStr
 *
 * @returns {bigint} A BigInt
 */
function hexToBigint (hexStr) {
  return BigInt('0x' + hexStr)
}

/**
 * Converts a bigint representing a binary array of utf-8 encoded text to a string of utf-8 text
 *
 * @param {bigint} a A bigint representing a binary array of utf-8 encoded text.
 *
 * @returns {string} A string text with utf-8 encoding
 */
function bigintToText (a) {
  return bufToText(hexToBuf(a.toString(16)))
}

/**
 * Converts a utf-8 string to a bigint (from its binary representaion)
 *
 * @param {string} text A string text with utf-8 encoding
 *
 * @returns {bigint} A bigint representing a binary array of the input utf-8 encoded text
 */
function textToBigint (text) {
  return hexToBigint(bufToHex(textToBuf(text)))
}

/**
 *Converts an ArrayBuffer, TypedArray or Buffer (in Node.js) containing utf-8 encoded text to a string of utf-8 text
 *
 * @param {ArrayBuffer|TypedArray|Buffer} buf A buffer containing utf-8 encoded text
 *
 * @returns {string} A string text with utf-8 encoding
 */
function bufToText (buf) {
  return new TextDecoder().decode(new Uint8Array(buf))
}

/**
 * Converts a string of utf-8 encoded text to an ArrayBuffer or a Buffer (default in Node.js)
 *
 * @param {string} str A string of text (with utf-8 encoding)
 * @param {boolean} [returnArrayBuffer = false] In Node JS forces the output to be an ArrayBuffer instead of a Buffer (default).
 *
 * @returns {ArrayBuffer|Buffer} An ArrayBuffer or a Buffer containing the utf-8 encoded text
 */
function textToBuf (str, returnArrayBuffer = false) {
  return new TextEncoder().encode(str).buffer
}

/**
 * Returns the hexadecimal representation of a buffer.
 *
 * @param {ArrayBuffer|TypedArray|Buffer} buf
 *
 * @returns {string} A string with a hexadecimal representation of the input buffer
 */
function bufToHex (buf) {
  /* eslint-disable no-lone-blocks */
  {
    let s = '';
    const h = '0123456789abcdef';
    if (ArrayBuffer.isView(buf)) buf = new Uint8Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
    else buf = new Uint8Array(buf);
    buf.forEach((v) => {
      s += h[v >> 4] + h[v & 15];
    });
    return s
  }
  /* eslint-enable no-lone-blocks */
}

/**
 * Converts a hexadecimal string to a buffer
 *
 * @param {string} hexStr A string representing a number with hexadecimal notation
 * @param {boolean} [returnArrayBuffer = false] In Node JS forces the output to be an ArrayBuffer instead of a Buffer (default).
 *
 * @returns {ArrayBuffer|Buffer} An ArrayBuffer or a Buffer
 */
function hexToBuf (hexStr, returnArrayBuffer = false) {
  hexStr = !(hexStr.length % 2) ? hexStr : '0' + hexStr;
  /* eslint-disable no-lone-blocks */
  {
    return Uint8Array.from(hexStr.trimLeft('0x').match(/[\da-f]{2}/gi).map((h) => {
      return parseInt(h, 16)
    })).buffer
  }
  /* eslint-enable no-lone-blocks */
}

var index_browser_mod = /*#__PURE__*/Object.freeze({
  __proto__: null,
  bigintToBuf: bigintToBuf,
  bigintToHex: bigintToHex,
  bigintToText: bigintToText,
  bufToBigint: bufToBigint,
  bufToHex: bufToHex,
  bufToText: bufToText,
  hexToBigint: hexToBigint,
  hexToBuf: hexToBuf,
  textToBigint: textToBigint,
  textToBuf: textToBuf
});

var pbkdf2 = [
  {
    comment: 'Bad hash algorithm',
    input: {
      P: 'passwd',
      S: 'salt',
      c: 1,
      dkLen: 64,
      hash: 'MD5'
    },
    output: '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783',
    error: RangeError
  },
  {
    comment: 'Password not BinaryLike or string',
    input: {
      P: 17,
      S: 'salt',
      c: 1,
      dkLen: 64,
      hash: 'MD5'
    },
    output: '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783',
    error: RangeError
  },
  {
    comment: 'Salt not BinaryLike or string',
    input: {
      P: 'passwd',
      S: 123,
      c: 1,
      dkLen: 64,
      hash: 'MD5'
    },
    output: '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783',
    error: RangeError
  },
  {
    comment: 'https://tools.ietf.org/html/rfc7914#section-11 #1',
    input: {
      P: 'passwd',
      S: 'salt',
      c: 1,
      dkLen: 64,
      hash: 'SHA-256'
    },
    output: '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783'
  },
  {
    comment: 'https://tools.ietf.org/html/rfc7914#section-11 #2',
    input: {
      P: 'Password',
      S: 'NaCl',
      c: 80000,
      dkLen: 64,
      hash: 'SHA-256'
    },
    output: '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d'
  },
  {
    comment: 'http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors/5136918#5136918 #1',
    input: {
      P: new TextEncoder().encode('password'),
      S: 'salt',
      c: 1,
      dkLen: 32,
      hash: 'SHA-256'
    },
    output: '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
  },
  {
    comment: 'http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors/5136918#5136918 #2',
    input: {
      P: 'password',
      S: new TextEncoder().encode('salt'),
      c: 2,
      dkLen: 32,
      hash: 'SHA-256'
    },
    output: 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'
  },
  {
    comment: 'http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors/5136918#5136918 #3',
    input: {
      P: 'password',
      S: new TextEncoder().encode('salt'),
      c: 4096,
      dkLen: 32,
      hash: 'SHA-256'
    },
    output: 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'
  },
  {
    comment: 'http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors/5136918#5136918 #5',
    input: {
      P: 'passwordPASSWORDpassword',
      S: new TextEncoder().encode('saltSALTsaltSALTsaltSALTsaltSALTsalt'),
      c: 4096,
      dkLen: 40,
      hash: 'SHA-256'
    },
    output: '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9'
  },
  {
    input: {
      P: new ArrayBuffer(),
      S: new TextEncoder().encode('salt'),
      c: 1024,
      dkLen: 32,
      hash: 'SHA-256'
    },
    output: '9e83f279c040f2a11aa4a02b24c418f2d3cb39560c9627fa4f47e3bcc2897c3d'
  },
  {
    input: {
      P: 'password',
      S: new ArrayBuffer(),
      c: 1024,
      dkLen: 32,
      hash: 'SHA-256'
    },
    output: 'ea5808411eb0c7e830deab55096cee582761e22a9bc034e3ece925225b07bf46'
  },
  { input: { P: new Uint8Array(index_browser_mod.hexToBuf('c4be2077aff5c0d66d43c979d030e7f57347ec15b0652b9a9e2162a36f70d3eef1f36ed99d3d6bf8f36a8fc887183753df2ac7cb1ea62033d208675840852934690d4db8a1073b1f480be63d9a3bf5933f9ebbc06a427575e4739e1cc66a593514f4fdc3f0832c4e700c084f23ba25b41a589a8f65f8e94a003dfabc69c874ddcc3c0a1415093a66803621f07bde74532b4055db82aa6de6')), S: new Uint8Array(index_browser_mod.hexToBuf('371946850cc27ce0991b5a79f9f11a88')), c: 505, dkLen: 64, hash: 'SHA-1' }, output: 'f738b19376fae2ddf94b775a6400a5541bf6e99eec0b9033ef43d9e4b86c66c37d572bc7406296c60ecd91d00bef5562ea6564934f976504fb22223ee52a3006' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('c4be2077aff5c0d66d43c979d030e7f57347ec15b0652b9a9e2162a36f70d3eef1f36ed99d3d6bf8f36a8fc887183753df2ac7cb1ea62033d208675840852934690d4db8a1073b1f480be63d9a3bf5933f9ebbc06a427575e4739e1cc66a593514f4fdc3f0832c4e700c084f23ba25b41a589a8f65f8e94a003dfabc69c874ddcc3c0a1415093a66803621f07bde74532b4055db82aa6de6')), S: new Uint8Array(index_browser_mod.hexToBuf('371946850cc27ce0991b5a79f9f11a88')), c: 505, dkLen: 64, hash: 'SHA-256' }, output: 'bc1380a25dc4c0b3032c8ecb50ae79b4fa770b2baa4cd3b2c10f63970c2409f032871589e3e1dbe6340a42993b146134284f585bd4812ffa0159ff8de17302b9' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('c4be2077aff5c0d66d43c979d030e7f57347ec15b0652b9a9e2162a36f70d3eef1f36ed99d3d6bf8f36a8fc887183753df2ac7cb1ea62033d208675840852934690d4db8a1073b1f480be63d9a3bf5933f9ebbc06a427575e4739e1cc66a593514f4fdc3f0832c4e700c084f23ba25b41a589a8f65f8e94a003dfabc69c874ddcc3c0a1415093a66803621f07bde74532b4055db82aa6de6')), S: new Uint8Array(index_browser_mod.hexToBuf('371946850cc27ce0991b5a79f9f11a88')), c: 505, dkLen: 64, hash: 'SHA-384' }, output: '2c97de18d6a0a74a8998a63740b52db2539e741400efd17a6cfe86c0ec2be3438277021359d17c4c4794094dee0ca4b90a8e4ce54c4dca31fb70bf9753910e63' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('c4be2077aff5c0d66d43c979d030e7f57347ec15b0652b9a9e2162a36f70d3eef1f36ed99d3d6bf8f36a8fc887183753df2ac7cb1ea62033d208675840852934690d4db8a1073b1f480be63d9a3bf5933f9ebbc06a427575e4739e1cc66a593514f4fdc3f0832c4e700c084f23ba25b41a589a8f65f8e94a003dfabc69c874ddcc3c0a1415093a66803621f07bde74532b4055db82aa6de6')), S: new Uint8Array(index_browser_mod.hexToBuf('371946850cc27ce0991b5a79f9f11a88')), c: 505, dkLen: 64, hash: 'SHA-512' }, output: 'e1bac65c6f5772fd1621087170f622ae4c1a70985443cd97939bce04569fa4fc6616d65a4d1ca6a33ae76bffb1b7c13e2bc916e840f3a6328e5967c2e9f35cf4' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('e7728bbaee38783b392d0ddbb7f1e6c61e05ef12c933f7aa4ea14f366c542126ad85271138e6dfcdbbb5681f05a82bb72f5df4374de373f05948228d0d7d3bc7afb6002ad078b1b6006ea4208c61e60da09e8748b62756aa2848ee497eb137feb476ca0c0b48637e30f9a7feb9a8d149b65e633d9cadd78579547618490342d0c0bb0c481816dc085087c61756b03ca74be47fe6f30ccfd13af50b492fd963a31b4f3e2ca6b413d4306a8fa96e0e4c73d2293fadef82ff8731d883ebb2508165a7382ae29b690959efa73ee4ff341178816f44bb4ba9ad09fdc75751cacf55fbb0d8c6585b81c8668f466b299b9227cb5c2dd58161f5378e2e6a7c1bcf731822add3d7677754bb99068d0bfe249c74671f30f9b97933f5384a8aa93bfa438c43c9b2480f703f5bd9cfeae67ebf826e0139b9ee311ac382fc64')), S: new Uint8Array(index_browser_mod.hexToBuf('cec09bb99ab546462300ad990352ec27')), c: 84, dkLen: 128, hash: 'SHA-1' }, output: '7cc3f367ebbccfc39e30742fff4167fd3fe861b3e5f2f497b1557d7c8c43d6e43110b3e186cb5b2e2e1809009f363e070dcae82f8927805da9ea89954f26fd539b1be691f18085ab1113c3c3afc5ef2f426b237396188bb9cabc0231409f7bb482253391d43da9399f1ba7ff8d713d426bd2cda93f1c40a5aec3f8f027bfa1c5' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('e7728bbaee38783b392d0ddbb7f1e6c61e05ef12c933f7aa4ea14f366c542126ad85271138e6dfcdbbb5681f05a82bb72f5df4374de373f05948228d0d7d3bc7afb6002ad078b1b6006ea4208c61e60da09e8748b62756aa2848ee497eb137feb476ca0c0b48637e30f9a7feb9a8d149b65e633d9cadd78579547618490342d0c0bb0c481816dc085087c61756b03ca74be47fe6f30ccfd13af50b492fd963a31b4f3e2ca6b413d4306a8fa96e0e4c73d2293fadef82ff8731d883ebb2508165a7382ae29b690959efa73ee4ff341178816f44bb4ba9ad09fdc75751cacf55fbb0d8c6585b81c8668f466b299b9227cb5c2dd58161f5378e2e6a7c1bcf731822add3d7677754bb99068d0bfe249c74671f30f9b97933f5384a8aa93bfa438c43c9b2480f703f5bd9cfeae67ebf826e0139b9ee311ac382fc64')), S: new Uint8Array(index_browser_mod.hexToBuf('cec09bb99ab546462300ad990352ec27')), c: 84, dkLen: 128, hash: 'SHA-256' }, output: '2406643a7df603802023caf03271323803505adcedf63ae7ffec14d94c687af3a80af178054b2026e4e80fa7b8c00f2e91ad46bb9d0da06f5da2369e27eb9abad1f438f349d9db9f8580a43104c9203ad5fa8be5b60f57a10a08344d028fefa232874bfc7d14d0e4f9a3fccef2a595ef11754c08b827844c79929afff17e200f' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('e7728bbaee38783b392d0ddbb7f1e6c61e05ef12c933f7aa4ea14f366c542126ad85271138e6dfcdbbb5681f05a82bb72f5df4374de373f05948228d0d7d3bc7afb6002ad078b1b6006ea4208c61e60da09e8748b62756aa2848ee497eb137feb476ca0c0b48637e30f9a7feb9a8d149b65e633d9cadd78579547618490342d0c0bb0c481816dc085087c61756b03ca74be47fe6f30ccfd13af50b492fd963a31b4f3e2ca6b413d4306a8fa96e0e4c73d2293fadef82ff8731d883ebb2508165a7382ae29b690959efa73ee4ff341178816f44bb4ba9ad09fdc75751cacf55fbb0d8c6585b81c8668f466b299b9227cb5c2dd58161f5378e2e6a7c1bcf731822add3d7677754bb99068d0bfe249c74671f30f9b97933f5384a8aa93bfa438c43c9b2480f703f5bd9cfeae67ebf826e0139b9ee311ac382fc64')), S: new Uint8Array(index_browser_mod.hexToBuf('cec09bb99ab546462300ad990352ec27')), c: 84, dkLen: 128, hash: 'SHA-384' }, output: 'aeee4def47ccb5450cc380b19d514087dd590bedbf4466ae723adc7154a3573170b8597786256b43e9fb54f269dd42ada26a27c5f2fa64d10ffe76d16a31d16f8ecdcfd650d3d70cbe2bdd85e1fac50add873c8abae7cfafc159782e2d21bd8b3222ee1efc3e08260b2c30cab8acfacb7cdd41e637694e0fbbb2733629d79350' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('e7728bbaee38783b392d0ddbb7f1e6c61e05ef12c933f7aa4ea14f366c542126ad85271138e6dfcdbbb5681f05a82bb72f5df4374de373f05948228d0d7d3bc7afb6002ad078b1b6006ea4208c61e60da09e8748b62756aa2848ee497eb137feb476ca0c0b48637e30f9a7feb9a8d149b65e633d9cadd78579547618490342d0c0bb0c481816dc085087c61756b03ca74be47fe6f30ccfd13af50b492fd963a31b4f3e2ca6b413d4306a8fa96e0e4c73d2293fadef82ff8731d883ebb2508165a7382ae29b690959efa73ee4ff341178816f44bb4ba9ad09fdc75751cacf55fbb0d8c6585b81c8668f466b299b9227cb5c2dd58161f5378e2e6a7c1bcf731822add3d7677754bb99068d0bfe249c74671f30f9b97933f5384a8aa93bfa438c43c9b2480f703f5bd9cfeae67ebf826e0139b9ee311ac382fc64')), S: new Uint8Array(index_browser_mod.hexToBuf('cec09bb99ab546462300ad990352ec27')), c: 84, dkLen: 128, hash: 'SHA-512' }, output: 'dda444bb1f1b60438d925d484e9fcd661670e470c7d944c8048fc58c62375161a29757f2a3d7df007dfe2d2e97be6fe68105f2d3e0bc7594e80646c63a7d388e1d46caf5d0f922d646625913d8b00e79f68580b5e369496c0f44466d2b4f86ad638fcc6007202c7880d1732678fe97ec9a2e7c69f6bb1db69f2f659f6c773f64' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('8ca73faa1885e7ac0e3d93ac83071c56dc7a888b373d53123348e94da3e2dac1d625d406f2cd9f7d5c23ea1a6d9a8a85875e503cd442aa68aea4f715512f89c57031d1a27d2b8298d1264b371185e150d5301b53a56dae')), S: new Uint8Array(index_browser_mod.hexToBuf('348d43e1de79518afec894758f7418e0')), c: 124, dkLen: 256, hash: 'SHA-1' }, output: 'd751df227f87e478aae711d6da99939f2e5162e1608252136e4db094f7511fb948b38ffa14d1ed1cad83dceaddc19ded5972e691e141b7fbbffde921af52394fe3d65b2cde583ce8abc1dc790d51dc255f6198f10de2af7b7d8b58a50c9860d77497c3174e29fcd348a9e2254e7fd57eb620a27a054348872986b8c8715453b200d8279c403bf48699f84fe47d5f3bd503af18f5c35e7c4f487188dd1454725186f8a3bc60b1dad01717e01dbb4548e387b1d91871254d447496b46475e4b10857c947e1a8e1bc8a882f188c2d9b743edb64370f3055d88608233ac8ea0ce342d3c2f2ae379e335a942c79661d2e8f1c0e1ead4899ce252702ce34062a083fdb' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('8ca73faa1885e7ac0e3d93ac83071c56dc7a888b373d53123348e94da3e2dac1d625d406f2cd9f7d5c23ea1a6d9a8a85875e503cd442aa68aea4f715512f89c57031d1a27d2b8298d1264b371185e150d5301b53a56dae')), S: new Uint8Array(index_browser_mod.hexToBuf('348d43e1de79518afec894758f7418e0')), c: 124, dkLen: 256, hash: 'SHA-256' }, output: '8244c3fd84a220b1de5cd410fe4ce446598064d1ef0117880781e92b7e57b02a192cb684bc1d59135f81bf03f50f84e08852e3e615f6157dd4fece33ced183fe4d66d922c9cb3bb02fd5ca7fb0a76ea2e2529be2cbddf5fc44246e81bd29d1caa9b85e0b536cb3dbd69d55fd3d7de0eeb4a3bd6c8b45b9b44fc0b1e37453a4a66298a1732b0c00d59097e3fca56c235cc385fcdd2a0ab7d9d028f715c4abb4bde72c83bcb49b7f3932fa8fa58af269e3249df8cfd0aa23665ab283357e83e93543ee266b69b04b14a5b0feb264c7e896a22c7fcd0bd53a4e1cabc7f8ebbc0ad53c77e3123b82daf0906d9f6aa53a573e4d4194bdb9c450123247e7ba58ad38a7' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('8ca73faa1885e7ac0e3d93ac83071c56dc7a888b373d53123348e94da3e2dac1d625d406f2cd9f7d5c23ea1a6d9a8a85875e503cd442aa68aea4f715512f89c57031d1a27d2b8298d1264b371185e150d5301b53a56dae')), S: new Uint8Array(index_browser_mod.hexToBuf('348d43e1de79518afec894758f7418e0')), c: 124, dkLen: 256, hash: 'SHA-384' }, output: 'c50175c14a6080a83182f6f5bf8581f09489101be8af4e6acb2acf723aa74392a9df2a91b636d34417dcab4b0cdda698fd54fa27132b3f3ee273400cf2430d4a48ccd63eae5f2e4964d901eaa34228e2ff33ecd197ecc9c3ab7dee447273b7daa8335e12fdeefe6600567e1c4a8e41dffc1d583ced1df4fd08e323fb23dab30c74e39968542412ab3292b14708d8b8dc1ab681ab57f9b31d1a35a13fa380b5f8cb96aee0595ef366b3e83067171ee19fe1c1ee1d581339f4a25a201b765d90e543cdd9ad0fffbbd125eb4702a853461b49daed980534742638299292e46ad75aee4cd5edb91f2d722216f9925b83cb44e25d05a51e4f23797a239c3d2d54b309' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('8ca73faa1885e7ac0e3d93ac83071c56dc7a888b373d53123348e94da3e2dac1d625d406f2cd9f7d5c23ea1a6d9a8a85875e503cd442aa68aea4f715512f89c57031d1a27d2b8298d1264b371185e150d5301b53a56dae')), S: new Uint8Array(index_browser_mod.hexToBuf('348d43e1de79518afec894758f7418e0')), c: 124, dkLen: 256, hash: 'SHA-512' }, output: 'f9613a880e63d6f050d173e5270d60f6a8ea4944ea1b7e775771514e9507b593db35ca242d930c94b86718bc260a79d4d0d9dad9055d48ccde48e48e6522e959499bf8440596359aee463472f69218f4be5c9b5e7cf4f183832573abd01e72ced164def5230d3cf7f73c20b8d996f041b0447147d7d25b345761df15a8eb3d7a2cb3b49ac2ecea966e19758d48ef00252f7e700fe24de655930ea19815630e362faf08b93a60bfb6d966a5199f0ebebfda27a1ca077af36375288cf237d379172b2527cfeca31d3acde614ead0e73f77ee7f0e1244d787ff2c08959a16ce0e7626a2c26537582a9fa2767511b581b9020d98fd8372379bab68e088ab088959ff' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('6c450e20c616874168e875aebba31b2582024de19c90927dcc4046bc202512abc2e0656a19925cfe7705652f0c3595dcf67c3d4283352f085f118c5e01f6efdbf2b427a5f682ac43e3cf594a6e8bea5aaf67bc6c7bb0bd4b270a5119740a9bd628a62872b7d8dc7b1255bfd1cdb5aa5db5c859ba86e3f7e31aa1e74b9b52f3a5530af11db97d7e3e6e8bffec210ae8031613584f3c7020abe43a589826ee70cba6fa0bad0b46a84e6f493c')), S: new Uint8Array(index_browser_mod.hexToBuf('41e7f80ccde6ed62564a8825aff96e6c')), c: 394, dkLen: 1024, hash: 'SHA-1' }, output: 'a74d14dbf3a9e1625911159a4c5c63e80e9b4be62a5a31dd32a29dced8c6873000cd5cad0be5fdb12d5feaa38e119f1c87de0acc322d51266fd2c590fc8d94a1f05fbaac80ccb1e52569ca9fdf100f6187bf80d9ee451962fd59c640c9d166111d201d5149577a2781b8baa8a4ed3bfa94b90725e270961bab9266f2a8a4a7142783670fd0864f1e7a7a3663cf41f64ff34c701399d7a59d6913d85c90042538a1dac3d56a93dc3422c45d115afc4506face57baf6aad78e9adf8a48dc8ca0ede6fec22ec47777ad04844c9a371742507f39a87799391484cc0999bf6da8ca97b27f3168c4220d35e39eee0752bfc210867722b063ce99f6e2c8ae699033d3185373ddd09fa46452ba23788409b56999fab267849ddcf32d111b457cdf72a2f57344af037bbf2b49b05a7e7b6892d8df45f5899c13e7578e7b4ebe23044b5bf286d6815a1712cc730787a48e9a9f75402d93362c95d3a44c52acff0743b001dec293416fd6039be4c7f912433853a396c2d72865633404c09f6b0817ed147b01080a3ce50a20c3dcf9b5f725451e32d1c38431e79a83977a5e1019960d93605fb8d4b7fc3e89517b4ba8849c9b6c661a1eac534f42b3a45654ea96ac187fef24311329c400fe088eb2e5c54deed1a281ef8dacced42c98b654f1f9702d30b789615135d9535158abe8e4a3028076bb1f4d2547f8da487f26b2f40cb72d61f4aa56ac96f99a62d06d287d24fd7165ac59b100e3cb1855f473fdcb616093edc0778583ed542d64718f0fdd52e3206427b7b24621a60a3ee40e075e93c42a1e7ff0e2762659b32f90c165573a1afb97dc3c1772ac50567295a44b52a695fd3c75aedc525f80bf247d4d362bab13376a7b580a3b8e5e682f304474a09dab2c5934ae07cc384b631de539dd07ca38be1a620c6011f926ac8c0fd61919437551ec3742514ce4b27242ef792010a87e1e1c043f0e3d72893ed48c2f60f01f4c23996049b8637b7a6ede1560c4b533d6891866e7a566b0ae4dff947d8f34a6790405b483d662570ff3ab91fbd403fb09ece1d2983332f0b97f94415a56225e042e1a63134b38cdab567c46353213dc9b71da55bd1bc2e0d704e1b458084c103ba1ecfcd08b377d119c3fcf67b8fa7c38c857bf3fd26fc68a1c73fafb14ada3f64c849faa5641c573b4cb585f52336801f708f0ae7399ef8f69bd9953ee417e58976a74e558ea78cbbfb71f28919acf88e798d0e65edefb50979d909604dfe00976c79662991656942c4f231cc00dd3bc4f3bd6668e04a44fa2b684b9fe08d627ae7c85d193131b71e6f272d1ab8f02ee8432469c041449ec88fb9788bf6f5e025a8b4182596218f2da2c08e1b44b1f77aefdaf173303c8cbd260ce3ea3804a752911c73927be98778cb62a0a13f51932b724b86122efbbab75fc356b44bf5998515a575d' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('6c450e20c616874168e875aebba31b2582024de19c90927dcc4046bc202512abc2e0656a19925cfe7705652f0c3595dcf67c3d4283352f085f118c5e01f6efdbf2b427a5f682ac43e3cf594a6e8bea5aaf67bc6c7bb0bd4b270a5119740a9bd628a62872b7d8dc7b1255bfd1cdb5aa5db5c859ba86e3f7e31aa1e74b9b52f3a5530af11db97d7e3e6e8bffec210ae8031613584f3c7020abe43a589826ee70cba6fa0bad0b46a84e6f493c')), S: new Uint8Array(index_browser_mod.hexToBuf('41e7f80ccde6ed62564a8825aff96e6c')), c: 394, dkLen: 1024, hash: 'SHA-256' }, output: 'eb035395128b91a7c8b21a33108d08599d6f9532086a0c166e7878862907f9678a06de174de371b50d459161ec389f0e85f7daa1bf2f7ee367da1ac8093e78b2afd8ef57b2c7e6a966f24b55d95c84c119ee21d543221bb796007d05d258ff33c5717d58630d919b94aa5933c726fb0bae0dab0249db90ed7f7f5581acb57d4feff0dcc0fdeafcef9577dd5340cbf7860f467146be55cd4af060c0de1caff2f38512be69205ddba916c7748ccf69b01bf0e914078069af51e0c8853319524b219ae7dc1fee53a5ac2d79a327889ae6528d4bab514cf19579b507791ab4a855e11658716fc86ac775a042619c26ffc62c36dcc5224010954f27e03b3506c77c24f95922bc6518d19a2184eccfed8d100644710c759d8f9bad862ec249f4325ef721c05bfb3c633f36b46ce67d1680e9a75ec099aae064e2f689b53dec939d35fa5787ded5ea69e243ef65016c7d3e1a49219c047edd028049c7d9ed2a13e929767d7e1f42d26fddcf6b8f8491ab35898d996723252dbeab4050a684a0a5e5523a385a19878f606fb3c9004c3fb7ed9df5b95da32b2fe83fa75ce365d0d011bf99121535b582600e60b780020ec835d24b2670774981f62d5de6a704e8713e3f2dce25b9e703bd6f7548eeb5d9dab6824ded3d046fb6f90c421735c845f4e2bed1ac1d9d1e409793290d544fd501a7998b081948f726f3b654ffeebf6545817d3c84a85939cfb6dd17c46abb5674491224e740ce9edddfb5625b8396ee7318ff38905241ce44942e25a7d27024fb9393a926de5a1d7c661f7141d05e647464d685be44b7e04a19f6563bd5ae7eba94c5fde0d08b0ddb82796c63c8f5d088ec1f715939a4aad1407aef0fc8180ce48617439d3e2eb3b25a9af143fbcfbf90bda4dc390624f6fb5cbf8b644ad4dc57375c54278849b3fc1ee0d3b967a44ff37f44e650dbab706b16c5f5b4c7f9f66d14d905bce8d68e6bce93bbd540271cfb352f17441248b8f6b6522bba7ceed54e324237a33a01213672a368c082cd0a3131bef273ecf8f6b6d28c11a29107146cf465dbd7456d52cb5cec0d28c22fc1f7fd9e5981f90869b53aa496cb3aa791fca77920709b7f9f4756f501c1dfabdc420be1e104ed7906f76a778aaa07116ca4db13ce02e0de26298235a9bec9cde3b6b35aa677d984074a8e74ba598a7b0393af50f602075c37dc5099643498e91aa8254ca2c533a437cb0dfc032a45c1aa15c18d1dc8e2bb6c20cc08ef306803557844b29a9406395ba0a76ffa2dc82a718f76dd22753183dc1df4d4341db3dfa4b5cb6b3fad19af5e283b97bd4b7b48951d2d2bb3dce8503a42f120297f09950c3fd7a4d5f03f8da574cc4f03abeb4adf08c7b42278c26c2e3a9dad8bf375004fecc45bb385394b6a49db9fa933181c67951122ea5f4330bb256c1934fe4ced2f31d0d144' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('6c450e20c616874168e875aebba31b2582024de19c90927dcc4046bc202512abc2e0656a19925cfe7705652f0c3595dcf67c3d4283352f085f118c5e01f6efdbf2b427a5f682ac43e3cf594a6e8bea5aaf67bc6c7bb0bd4b270a5119740a9bd628a62872b7d8dc7b1255bfd1cdb5aa5db5c859ba86e3f7e31aa1e74b9b52f3a5530af11db97d7e3e6e8bffec210ae8031613584f3c7020abe43a589826ee70cba6fa0bad0b46a84e6f493c')), S: new Uint8Array(index_browser_mod.hexToBuf('41e7f80ccde6ed62564a8825aff96e6c')), c: 394, dkLen: 1024, hash: 'SHA-384' }, output: '4126c44feff766e10de1dd4bd1eed1976c8fee39e296069a637a341d8e8f00cdec2626746c3b919ac292cf90a12dd3c7edfe81d2305c1fa771310408f3eb4b7d03226bda158b095639542622005f9decf854a31e1525a6ff4ca2f4980e1050d1e12b6738d107c435e96608aa9b35a87cef1fe0bce738babe55c39a42537bbe022b125307b712f5526ded8b6d06f13b8f3bcd7ddc12b3b593759c34abad5d87d43a67830893139fdfa5cfc2acb3cb42a1290b810699b6c1042a97156b9403d7cac4821abd371a206dfa467a0b9f363618e6a9c92eee24f6623ee879f94f9d6780f9b01c6849a212e6db16744fa05f5a706dc7d25f7ad0041c9e6246027bbf3dcd9ef2e23b7bcfcb99b9e04ac2c65bd777a40aa39c046dc991c56d29f7da1b3dc09984ae08c626e157d326ab4d53deace28abeecd1ab642036e818de4524abf3b4dafa4b9b4ab9e01d9be58d49f0999133273cb7a8239182ff8f767a21eb462201bbda7526a5f2b950107d1ef26e20ee27179d3124e446f5a8953a3850f9932c70e3604b0c5a977d6c48731f5029d155c651c7ccd5e7b2b577a1f8197edf2f67a6322350ac8a993ca0bc0275636d489d9c124e5a7dc3f272150f7a1ec4da49116c6bc04ea70a0ba9eda4da5ff347035c3137c3aa7658320d6447150bf8c9108a05b382b9c5f593364d14d9fe7be119da50e212338f54061faba5a0edd3a8fbba56da1e54fd54321247bb77273b206d733f9af6b0a4271270103ee2e4c71419f9f0950bc1c0202161f062d1b4117977366fc1a283bd288cc83ce8c2380b59b387a6036745feef3c5751eb5b1adf67979242e53efac26d5cec2bfffb62b9b4e4b89499fa61054e9a46b63ffef0611c57e3b6bea8ef35c0ddac941036490907fca5aae5c3ff7ba68963e0f1acbc8ed884845ca5726de15e2146d4c66327ad67bf248594ba48b2579be190ad7bf8267fb846a7d022427009afe01b729d25a70845decea378a6d3dee4fe6e9572234bd45d9217ab098cb4205da9928e8ab5b08b81ef61d3dcddec421017d631e48b06e081f3d0d419f4ee54dc1b93b2b653b8f75199faec60c820aa229d481f74fe7dc2443dba622040c6f400791a9971b2d895f8132c4f28cde36a5be0d6f6863c925f25cc73ecbe55b0707e4cab969f81fc44dae1882c0466c70b1777e788f398a31048e1ab3c934b30791386ba67cc63486d968d9a1f91535229024ac76bb6e251ebe5a86a09714d4d968a22a22da214c389d72b3104c8754dc2281013a39d3bd06ab98a7c1e4410dde69d14c79e9cb356fd07d4f5fcb08b4c5c2973a21eabfd6b7c9077840c023650616f3fb703ce05603ec9008d1d51bb1364531d520e735318f2cb47d9e8a82ae45fe7e60e32b0aa2b369acc42dc8fae514393f0a3bb420b5538012ce1d0836ec19bf126360dc14fcb2fc8851c' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('6c450e20c616874168e875aebba31b2582024de19c90927dcc4046bc202512abc2e0656a19925cfe7705652f0c3595dcf67c3d4283352f085f118c5e01f6efdbf2b427a5f682ac43e3cf594a6e8bea5aaf67bc6c7bb0bd4b270a5119740a9bd628a62872b7d8dc7b1255bfd1cdb5aa5db5c859ba86e3f7e31aa1e74b9b52f3a5530af11db97d7e3e6e8bffec210ae8031613584f3c7020abe43a589826ee70cba6fa0bad0b46a84e6f493c')), S: new Uint8Array(index_browser_mod.hexToBuf('41e7f80ccde6ed62564a8825aff96e6c')), c: 394, dkLen: 1024, hash: 'SHA-512' }, output: 'c5ab39a571f9e281e672588497cf1daebd093651cc13cd8daab0bada6a16b19d330b144b490c11358023aca664d49548918719d7d7abda8ced22f58c4677e239ba9f6975323bc76155a1249e30cdcf1de74224dd485067b382901c269dd3b2aae97828aac30e9c73e13a9ac0a32c7045b824c60b1fad9ae90ef454abd45df33223432070d3f73a3e2ab58d5a01cfb7345808b1b5dc13b9df27258a56479962141d1cb99b0a31247447f7fc90ba61ddb766e22e847601fd9a8216cd577c30ec12b925066b4b014280aeaa8d9189ae0e36da2499cbde1dc2003aa7b3af834ae4cb69de3301581216199d1a11a453795e312252b4a48bd8b881d296920776ba030d53f91c7d688b3f570b8435e383d286df85f217c942a83e0093fee26c7896bebacc50200b54ca2d9eb5a6a2fe4d41fd9c08b1dc8ed7e081ac2fc3c76012a7afede9b134de65ee427720a1b8584d047385f281469613769d8c66f01cbf86c1ef665e2cd65a13a853a0377191aab981f14fc9c3928421b87c25d39a42468e3d6b38cc6cdd62379755ff03ab0398f61decd4f2248910d53751e6310a54a6d8df487953cb2b9f15fce575b079096dffcdb18879d91f32dc83dc441a21bebe19b7b403d035f23649934ecc6f58460a01e3f5c7cfac8b75efbc16667a3e13b246d8c0547d69229d9800e3d5e338088f78bea143061a23fec8d06fd4e7098f0d84efabb218b6cdab66d587e8ea3edd065f08fad2c6c1bd2d2973e6b56c48f41ed03865a98ca118b8b1c8c197a0769fc9f63df03880e108b6f8805f35ff54b0364c6a57a7ba25c8a23ac9e711ab7be3642df6bb30026bf932f7fae879d3e2dbff088ba981c524be62c606614793709c56530aa761cf060eada27fd4eb9b2043da8ff27b0ffb7a681175ddd282f59ed8ca4b99f429b2a90abeccc5f9f0c1ccbbe786a8014f7b417b0702a4f2a9268caeb33119bb61f51e16bb25bb4a49f62ec80eb5008b26cf8f7fcfd604e7e58d5a29a6f85c984041aa098abbc91c3fcb50391a618a32aad24e1755bfe229146933c33ff781240e0dcfc47190ccfe05bd8eeede5f8ec85380fcfeeebb3e034e9735f2971088dd25fc86545afc34fd19382f24bb45f9a6dece9d366f52c3ec54259a880dbb88b589f68a1166bfa71b911cfc46e903ccf4dbbe81ff095785cfc05bab943daab0e59b0b37e4df4d1f541a74c7b73eee9c6e1071f132097b032725393899bb6c3d3be452a91089431f91f3860493a4b1ac7fc4fde11bd58ddff2c00b013b3aafe5431255d45dce0deef348e9621a47665b6cf0697931df0850c24daf38073232dc773ee45c1b1fc53be80b1f540d3eb446ad5ec12bf9ad6adf0b9760357592994225bbbcb3bf628545d596dbb8db758ff40c4d688b2716c0f50506eccf56029066341625a3d825fdb8146e30315426306ef7e7' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('73c7d15094e710df0dea9ad14fb6ac91c68cc5720f69b9041a681465cfbef80c1002ead9502d4c71d9b074f666b9b848a40fe6ff912d3594d1dee0d846b623b8eaf24111ba94c1385caa3d0f2dd716e3c996f69ca83ed78a848d14429e0b6dc3efa6f86f6292dedcee08623466ab18b2dcc84504294d0ac66e61e52d07d1d9ab972b17d38b94beb83f2fb8864639fc0f33f3ee576f53a10760bd8f414b2aca6c9dc271ad0249b2d07c252132951dee4076c59de55498053b3efd3ce9caf5455b07122863e80be68c18bb053edda1a8c1fc8f733caa6caa9e5441b077a3feda054e076421e8f78dcb80ff498514053dc231b172b8a095b9a77932c6eb0107c285b053bf93dd5f4db0060fcd098861781a6b92f9708a3aa6a3bd5a233bf8ddff5a54d31bf6bbbcbc07eb9b6b21eb5489715e1731fb967233b32ff2276818485c2eba2ee9d9f2539876acb02ee591351a7c059dfe9bc38e8b983defc7f76ba0a05964d3ed8c1583b36bf5c3753b093495d361d15f6db5082845d7bc1ccf7065e9579660083b50c4892c49be8c3ed2b0db48f693e6fbee72f1defde0e9fb2fd1948f4e98b5bbcc41ead2959594600b931b69387c386c59875824d23fd23582346853d626ea716364d484306b118dc510c10913283f6be0eee2f0dfee096d62052696c55efe32ba58148fc4345541facade49e6041e978aca4dc7a4b6c7cf547081c33aa00ae7cde27e17944be83ef12d6607c4f863ab862ef5b1ae3c52664a1cc556455a6c6f96dd74667f652c8bc675cbd24819098f3a5b434f2eeee4f77e303787d6f7e7e8adc08eaa5ef5d0c067f50c8a101234e2')), S: new Uint8Array(index_browser_mod.hexToBuf('e647760849a8c1703b2db2156971ce0d')), c: 187, dkLen: 2048, hash: 'SHA-1' }, output: '3116f03f238096b0ca3e4ebb0b2beacddfbe0fbdad5f889936bb9e2a50da8ecfd2cfc1ab0777ea2b9eef715d9659af46bc9028f286de5ef3468a1ef97cf8d3bf7fe649318dc2d8f784f317ede8f4395d7dd9fe9d1d9a2d3a5063d675bd757318cd37d818ea3010411a3f825f76f7c412e966ddc75811aa933722de05a0aabdc90b6468c8d8e77464088a50ad5f822f34ec323c7a0edcf6b72f822604c8b3d2f70e52deb1860c44904017bb08454856c660b014b408b90011030fb149426966d49a0370d088117025359fd4ff1f845ec9e5f87a455f5605a874d16c075262c9fb55095b2385bb5320bd62b1e2a2070b6daa921ccc35ef2e2bb5e52729d75e25ce62f4df7bb9720bb3abf204a5d0035737d1407785c0819410dde8e952f8194ca187ad11fb96f0065b528ea7b494f83b1a74d41b2c5ac71bffe7e898aaa3e5c6f6c390cefdd43ced1339b8c76b3bc12756936b5c6ed87848eab5bc724007e479d4fb28db496f4a1d3dd5f64f8e14974cfe9aeff9cf1a8b78870e6e628f4d138d4407c23ae78e26381b2e404de246927fab82d81acd03969d6e79870750c8c938dd518a6ac8720442c5ee2d8731a7c449204b0a225d57083e5d28bcd0b5dcf4762b81831be70b22bd7f58e0113083d425d9d5c00cd1c557fd5e4a9064bced3fd9895015ea28d857ef1c8652c37624bc65c437615946daf08c2b943dfb9d492c860be48b884e1289e1570d1f1b7ca9792d1b62633952c9603eaa7862952e0cf80b97896d1081af98f45d0e1313bfe093e29a63866beb04bf05cef22b17889685812e1847595b28a0715bb5e9e12601309c33926219df25e7d7483119ae72ec56538be9e1edba2566ad2e3fc4cf48fd75a72e01947abde419b0446f37025a541d2c4b6e325f29b4631af91e8944da0a69e296acc5c799ea7c67e899fab297e196ed3eec42b289f0e94e68b696fc932ca17cd3c561536e7419cc6bae46d8532d4b66a69c8280419926a0ee20f85674ffa5c1ff61fc9f0a5600d7ba617ed4cc91ab5eaf5c3d169bb8a8f3371510b949169778e6f8344b57890aed197c82d6594cbef847c823dce30f01eb865de31a2076d6dac69ba481fc77f45bf76c0cc5cf747047ccf27722242fae87bdee85e0e02b232821e251df88d96b1ef59bf01b4bda9aeb6533f7f7cddd7026b8175477156af7c287661e5759135433fa3c330656dd2140763bcca73ce2e2bf2c807c326b69622bd2118cf826f2fdb1390be0c12d3a13669be3bfcaf4efeda9d7594c016842a94f87e6c472a4a41fe64d27da57d3291204fb525df950322d7133e59719612ffabb9af6e920ef40ccb61c75f8b5925cd1f462e3611c745e8849473ffc969461f0df9d88985e3627fa35bb70461ed99e6d89261594ee6b001f8864fe39f5709a11e5016e486f9dc9480659f8c157628efd274d6d9eeac7fdec8cb01dff67b2f9f78a34b39a57c9ae98c43dfb7a6373e921d65150ce8666c71dce1813daa1552d04ac730b1b4b63cc8deb314fe9f62a16c11ca1270dbe6a81bed24c79840ca872537ee9e35b3c8440425f5da53cd7c02be83d6df3f2ebe429f414b9401bdf543130a8e1f6e3a35f4a60c561212834087d40ca27c02e08e23089b0ac313076cb5f3e774ea7e779a1e2e674536cf6853381b615f2208e250945b979d71bdb0e91df6d063c1048dc71194ca739ff2065c1414b0093e9a4c0ec08d93066b56cd03258163cbd1afeaab739f18b1b87eea6379526b6b2e8cb609f2963dd99bb8679c6e1927213b0f89033f2d66b0fda81cc709a3584fd56ca24211ba14db37657e5e66d5f2cc2894e12173248cff27b9774ed04e29ddfff020e34a29e2b1efd6b7b4e62a85a65fa568be3896fc83745e32c1c4a59259755df7d0993f54536fb91f72cf18861f8efe78a613bbe789d380f4b5be654acc00730f0aa29e14e9fa25669c3cd0f57fe911c2923ebc50e0d679930ed63b70c5c0024b85157406e0aa9ced37e0161b5dc8484a184fd3f97d358db999720801c7d908566887344a30fbeee618b4351d3675b8796dc37f3779f7600ef775f515b0ccd3942b305c82a4a564c8f7ccc4bbece39754e9b167f8afbfea4e759ddafa3911c9e5572925891ef97e9fb883f3de57cb504c68eb5a5e89bc686e47552c9bee13d933c83b09c795542bee8fa20c18ed264a06ee07222d465afe5089883d17689f4ecf05bcc32a18712fad52b3aeda3ceba1fe0f91840449d85ebf7ee93b0823f7db2ccc8713f51f3973928b9e152bc4857eb915cc8a094cc60b79e1a7ccc1219cf593fbb6932ae3484db098392ed5186f9bb01ec6d3c4e2913976bf812c1592bb7251ac65a04ba0e322e944a07512a55f1765fe30ce4fae78360d7be4bed38050f5643818ff18331926b8d2c3e17741bdcccb9fff98d669e926828a1ed11c23a517a8bfc56d920942f0b0d1c48949c7e346718666cc39cef571ded8aac8098c04a7c5f9c401850d9cef245025aa0109d2a2e650deb1045042436e9db573277bde70f997a5aa157db1c627b17554a24293ba393ad9082896a35659315770556951315577858b29293431b3b635f2a48ba3570e2a78cc6f01c03b21cbfc8def3735d865cc1bdb1d8be5fa208a7e118d26c7d9d54860466c806414e2f1d3ab9801d5ecaf221344a477d45ad430721c5d1b252fb24cb990937de4f139a917ebcd15bbe145ef9d5a9fb0d63f88c968b550e7c0d3b11453226cf807fb358abf1cf39c2075d5ec9470d2c18d58090e124cb727cb06e15e0aab0c0b2eeda554e3a4e2d075c0643598987d5a91c32ff480f8cbc276914d67c0e5c445e0e0d51e2a54a022d1e073cf4338a22b6833e0098165ba7f74b650518dc66f997b7520e8bf74f0b7f' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('73c7d15094e710df0dea9ad14fb6ac91c68cc5720f69b9041a681465cfbef80c1002ead9502d4c71d9b074f666b9b848a40fe6ff912d3594d1dee0d846b623b8eaf24111ba94c1385caa3d0f2dd716e3c996f69ca83ed78a848d14429e0b6dc3efa6f86f6292dedcee08623466ab18b2dcc84504294d0ac66e61e52d07d1d9ab972b17d38b94beb83f2fb8864639fc0f33f3ee576f53a10760bd8f414b2aca6c9dc271ad0249b2d07c252132951dee4076c59de55498053b3efd3ce9caf5455b07122863e80be68c18bb053edda1a8c1fc8f733caa6caa9e5441b077a3feda054e076421e8f78dcb80ff498514053dc231b172b8a095b9a77932c6eb0107c285b053bf93dd5f4db0060fcd098861781a6b92f9708a3aa6a3bd5a233bf8ddff5a54d31bf6bbbcbc07eb9b6b21eb5489715e1731fb967233b32ff2276818485c2eba2ee9d9f2539876acb02ee591351a7c059dfe9bc38e8b983defc7f76ba0a05964d3ed8c1583b36bf5c3753b093495d361d15f6db5082845d7bc1ccf7065e9579660083b50c4892c49be8c3ed2b0db48f693e6fbee72f1defde0e9fb2fd1948f4e98b5bbcc41ead2959594600b931b69387c386c59875824d23fd23582346853d626ea716364d484306b118dc510c10913283f6be0eee2f0dfee096d62052696c55efe32ba58148fc4345541facade49e6041e978aca4dc7a4b6c7cf547081c33aa00ae7cde27e17944be83ef12d6607c4f863ab862ef5b1ae3c52664a1cc556455a6c6f96dd74667f652c8bc675cbd24819098f3a5b434f2eeee4f77e303787d6f7e7e8adc08eaa5ef5d0c067f50c8a101234e2')), S: new Uint8Array(index_browser_mod.hexToBuf('e647760849a8c1703b2db2156971ce0d')), c: 187, dkLen: 2048, hash: 'SHA-256' }, output: '345361e119cab8ec513738ff9ab2815e40f6a271ef3b26da018c622dafa806b88178cbcaa5e4b18b769dcb221572d387aafd9d185769dac7eaf051a72ba325fe292ce0eb65e1cae2c2f32c5becd73825cb8f9ca55a10d0dd6344715ddb45c615fae0e0885a62337394eebe6efb20c5828b02a9919cd3e0bdeacf927873947a2d4e4e4a2e6ae5133ae5d430a069c2ad93e433b7097d56fe403b47b971cfdf3c9cb655ce5fb8d7bab0acf233d8f286890b3c3c65633de07dfc41233011f831a94b4e14812cd91ae0f27454c58029d3cea62ec9951346f847d2bb30ebf06346e98b627277286b8ae1c69a9ae33423277a218fc24800ea48a2417fcae56f759e9b25edb060e0bf4a24d4bbce5952e4e8b075ee7b0d5d3515bba836430238df57ee0865d692aab4ba10bdec2eaede20ca1e3ddb932ea62963744b95ef39aedcc74a4270b81322db974c1d440dd82b7d23178d15fdbcbd99166b5758e0b8ea95bdb4db1b5cdbcff1e6d29b295ded0cec704c53500af5c4f59a6bed13c26d077c37bb7ef8e7f9e4488e8da412c9e548bf4c9bc9879cdcadd2e3fdd4e8eb51d4166ee5ced27510a0ce9e1b3455a43d52aa10306139bcc99c85ab998f8889088ce2dc2e203a504e72323fdbd926e27010780cae4bc8ace788f8f9dcd7c6747f3e1d4ded37335c1017a53d925b4a39cd0535c7d1ed4e50842f4ba39d904637a3f737ae93c40d087452ccdf80f14a4f0a581ee20b9e79d25446945f033b07d8eb5a7f20d07ada168f7f7254db9e8f595183f99330e6eb06c14016a6b2248f6c0f69ecc4492ab2dc8b1080e4236c235e68246e875b9a2741b2aef64a5f821d260787e87fc8736cd1af27943867f6365b49517b54e9e4650d8f8b80778c7c3e0e2907e1b138da636fc6ae95ec4799935a887ef8881f346f349f312c56963cea2aa904ecfa77207381726b4c1129742ef053986d6657a876fad80c17ec804416032ff1056d6fde3671fb7d2064b3edb8d0757a7fdeb1e82852729ebb31b0e4d292d4c486eac7e52f82006452643b78fb4e6dea777b78950ec2cde175963892914e8b88209a5856eee90d1db6cd91d34f15980d7e8ec3f07df65304f3e714eb6990c2b2f47bedfcaf40fa8f62a1e083e4b00ba12b1b2c7af78cbd2fc9d6247685f61a3a535b7026a282ad01448bd796f83cbe8e503f6830c55a2f512ca58cfad21f3f52c01648043b083d26f4ecb6f4886aa83c42504b8fcbd09a25ebb9e91766eca862d1a5f91ca7a54247e9a6a65543e7f4f3fb9d77fc75a29d5098711a78f3b6a4fd9b0551c1e0044332bbba6e7700148af47596218359419d67bae3f9e7b90cfcfd812aa63693c5b67b5daba52198d01c4d42cb96c9617a34bd38cfc392a1c687773045961f6c284ad9a44c84d451179e7dee12b8a72e392cef88acaf1a778296e7cc88301a82d1517218770f24ece95a549efc031df0f35c38533012ab6cfc08c39abdb14741dea6458bdb5f4bd403eebf97edbaf3e9180753a6a0e7fa6ac554e29aa21f8fd3880e443ec3faf99bdea9efd369ac3f97a6c41c8d85511146fd98855abd30673b3af622021a59df20890b5e9f8146ab94ca6d96e940b49527c5db5437cbb4479d65350ab44d74e20242f4a5dcaf91e740833fed90bc58d7e9c85eb6e94ebbaf7d2a61c5a5cdd9709338ca92b8391374c75c5875674a4b012dc2f94f8521101ab4de8b93907629a101b981a90233828affb27db3c163abfef578f7a4927ea998cc1aa9527e298be2b7c88078239521d0be66679d77cb915128fd7ae870e2d92e0ced5f80a9bcf74ddaa485877008f585efbfe95c42cd9d4e1ee8db7fa2037801cf9a3f86aafb01cbffc83db98f2631823b60fc5d60b1c1412eb815a46c4183b94f5b53f378814b1d8e1a27f655d4763059b82892dbfb1de88ad03786ff66f5cc1d3d04898b7c70eef7b2adac57cc71262b017c1346cee1c9e9436b60b45b2269aadc10414313b2c39f5a34483aa5dd0d027b52bddbb52351c606096014751657dcb569e30e6ad3210d745aeece8dfe74562335c35b8ba31ef6a1920104050f861169cb8b795db7850b21c9c10e049ebf69efd73d1168420d87ab958ec9910bfa3ee379720e5dc4146baeb3ed7344382a8acad8715388392c5d6eb7d0a0bcb30082142ba579594f002a35117edbe236a1c57064c2503afda6ca8193b439ab6193d1d124542d1a3aee2fb403018258acec75bfcbdc80d01b511b5cd724978246eead13345ad0ce076754ea933f7d35e18d9e97b6308322bfbf247cf267eae6838a575cf6e2c2708edf779d1c8bbaea0c8426c3267c77b2aeed1c281836475936681e5d3595f5505901ee3b99a232bbb395af5d6ebe7d0ceac913e399998d283d87f1d12785ec0c576c416d4cc907338d3a197701b7f9e12d1d2a83f864424c28b119e8126c07c23e942d858313bb2106ae78e3281cd00aed1d23f81b16d42cb95cf6e1384f0ea80588a3bcfa5ed83e30595014fc7e1e5009d5834b32acedc6ad74054fd323f69620436874ceb6b2f7d31e92ff3918ec87de0ebcf056fea201f39e34454665623d3b8cc87af0c4cd562ed00b7bac60e01c15af82e6f7bc65e4544ee2f98ef285fc78c59346e63111f64695277ad018669929e16dc3f40c4481084d1255a73b2f0a0d1722e615905b57258bfac1da827546343701d062088fe6bdbb00e94e02eff6b1e658c7f2bbcd0bf731d1ad47cbe2bda7310131685043f27306536e6313896193bc01ade5505c45218fd6dbd6fc08937b49042f189649f4eac55dc0f84ffb2708505e1d670a08badba8475ee6db7f5fce446283a8618f69e6068cd3f55449e529d5f735a1f1fff5766bd1c41e2c815ec311d229b2667bddb78a' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('73c7d15094e710df0dea9ad14fb6ac91c68cc5720f69b9041a681465cfbef80c1002ead9502d4c71d9b074f666b9b848a40fe6ff912d3594d1dee0d846b623b8eaf24111ba94c1385caa3d0f2dd716e3c996f69ca83ed78a848d14429e0b6dc3efa6f86f6292dedcee08623466ab18b2dcc84504294d0ac66e61e52d07d1d9ab972b17d38b94beb83f2fb8864639fc0f33f3ee576f53a10760bd8f414b2aca6c9dc271ad0249b2d07c252132951dee4076c59de55498053b3efd3ce9caf5455b07122863e80be68c18bb053edda1a8c1fc8f733caa6caa9e5441b077a3feda054e076421e8f78dcb80ff498514053dc231b172b8a095b9a77932c6eb0107c285b053bf93dd5f4db0060fcd098861781a6b92f9708a3aa6a3bd5a233bf8ddff5a54d31bf6bbbcbc07eb9b6b21eb5489715e1731fb967233b32ff2276818485c2eba2ee9d9f2539876acb02ee591351a7c059dfe9bc38e8b983defc7f76ba0a05964d3ed8c1583b36bf5c3753b093495d361d15f6db5082845d7bc1ccf7065e9579660083b50c4892c49be8c3ed2b0db48f693e6fbee72f1defde0e9fb2fd1948f4e98b5bbcc41ead2959594600b931b69387c386c59875824d23fd23582346853d626ea716364d484306b118dc510c10913283f6be0eee2f0dfee096d62052696c55efe32ba58148fc4345541facade49e6041e978aca4dc7a4b6c7cf547081c33aa00ae7cde27e17944be83ef12d6607c4f863ab862ef5b1ae3c52664a1cc556455a6c6f96dd74667f652c8bc675cbd24819098f3a5b434f2eeee4f77e303787d6f7e7e8adc08eaa5ef5d0c067f50c8a101234e2')), S: new Uint8Array(index_browser_mod.hexToBuf('e647760849a8c1703b2db2156971ce0d')), c: 187, dkLen: 2048, hash: 'SHA-384' }, output: '6a108cbe9c2dcee71d4034144757f028c7cab1ecb286e708f64d87cd1116f490d877691461f68af703846fdf6a8697f6b75e492cbc397d2f5bcdb6ec4f2509da367686e6fe7376e0d72124fd1ed9332cf0357b634881c3a911f1fb4856e6ce53e82ab745ffac9df6f4568f598e35dae0da00b7c913e21780174bd54c21ae67cb17eab1b746e26faabd7c1be87b2f4cf5e8b83edb1b38e3d28961205fe80f53b69b4595e47521b0ce7205c4363f8ddda7f965a46bbc5d947ed90d93cd519731051a65c904be3fed8c9d140b639a0fd1843888edbd186ba31e0f506f9f13a2670052107c27f6bcc7f596a551e7a24a8a9e4a862b1cac87e05914af596219a1a2ae7905b2a21a13f207096ebb01774a03983adf87801eff263c3b70d4569368f50b19acbe7a7316fc675e1460ed0bfb5ba018907b2744dc7c07bfbe3d1a1795ed2039dec7d340b09f842ff381eae69fb846fe35547538a425389517498371450f797c5a0957aa648735d101dfc2f553274a584baadb38d110cb7f96a84bf235960e6e54c9011afdd948f76d22eca3c835822482cd4d86a7d398cba27f9b1ed48c54adbc8452d6396c72a4a16ff8dc430cbb305b7fb14f03da3b0f6edee2b5139eb9aad77a2874eb6651c6e669a8e2728be56bdf7616fd725ffef886dd16e0776130e91b4f24a0b98eb51a0bf1dacc2b655b8f0122502a7c01d4cd20e97eca433a11c23e28deab40e060e25af80a5eccb9447500eb3d041cb3d519ea2012a153a9dda3ecacc9eb2e2729589650cf27a2809e9c91806a10b49533a76eff8a305efa41b0bb6743141599c9b469b82669b5a0652b4952aafdc23ed34e377c49b9829a0358a63e3f606aefe4280c639167d6c836bd517ea3c5a90e5efe32690a7591cd149af01bd3387d0348df7478833b2c86f4ed656246eacaa92024ff71cd52e572629f43d652c72db0108d4e766bace79f71518e4f26d79e8c362beef4270c9503185bab9de78b7ef908ff2c995e0fab7200c1dce9831b8c8d804b57e5e0f5c6b0e90c5b7714b814300d37e277a56bbcf4d3fe1ad3c3495c0cfb42b54028d33a2f623adfd576a3d4a80499e037168cf1c7ba02502ef490dc66a4a572e19b785a79f803c711b954fd0116463f262f2804a85f61ef27609614f0fd20f3d38e73c7b363707c84e04b359b360bb00673050d1c90a43b8f2d5414d61bcda44ff92f53c3530e12ffc95111668e9dadd8ce59a1b0938da1559d3ed294ce7bda7493baa3c9d105c94fdfc172099ddb962df05c7bd4451f5b39702cd3e1376b6da8f32ca9d2ae737d19baf25335fa7ebab72fd0c8613c856f525bd8291204505a65f55b0adb5cf97db289d5a59aab7a6f6c0d5663e09a923351b7eaeb57bdee950ef3ae3e47db82ce5cf65a12382a778200d663b89b00bdee409ec7dc0eb140312ffc9736131ab317e1e49a74477281f448825a3bf54d0d956c39e49f62feb9b8aa9f642138259e3e21d855f8ef65ee2a4482c4dd3323121f686e322e4573474c3243f7b02b8d9eff46e42f05b92a7a16fcb21a06654231fe1a7b04c1ad19083ec7e50f9a635e6060940efbc8341e6e91a1843c3a4614277ca2c0a700cdfe2e60f567dbbb633919b12dbb9605ad33a8cc20130df408b4273d7b21c90f2910d699546550485ca32f4d6c880d14be4e5f71c71929e1942f4cfe78959fffc484436aa09b1ca3b53f953cc5d34fb5287568314c0285fc60cced9d510968b14e0adb8028bc62276cf5db9adcaae95e69720cb3ba7454e4ac4cf90be19b438cd24f66a5ab47e23c61205455691b3462d9864b64736b984213a2066f2d556a5cee7a0ed57d6b8a2d0f5b3e7df58aef394179b7622a7a66470e26685033ecdfc6905bffc966e469bbcfab7833e8318679f7065a8b7903a5845e68fcf07f4e91042b51e28466474699cc650989c92c091e920d71b3380f8c28d51a21aaec5841719783501802c55af3545763984dfced034426a78de28b3c289d0aafc0fdb9cb270f264d70d46ca4ead2e6cfeeda5d1c4ed7be9016151701a5b2edf022e5f169d2587a0bcaeb2413c52d70a2977e1b3af0f14e638b791c2c8aa1829425fe62802b4774a00e94f05e5f580f026fe77202689a73af78b83a3c82a24f07a54eed4ca7b3a67a24ce6421597135b7ad112ec5aef341a800189f970b792b5003dfba6f40a6952b525cba127327c4a29c5014611aefc57a20f887986f817652ce6d4e47fb8ec963025aca015f53f1cd61ce4317858a537aa92d8307e77e1e5aca5c5abbe13c3572dfb11e687208c05b340a739dfd0fbb97b928e6cf589fbbf40dff820cf349804a94415b8e2ef0fe941f2cef90c8e7e83dabbc276cc05f9108df628e9177bc846400286b246915bb1226d7fea043d1a292607e9d31533134c0edac9e56f57c2076cbf8d65225b1250ea92b13bdb38b2e31f487ee918414b2d54cf0be703542ab2a87ceebc1c945c657b07fb41f8390c5a76524ffc27b3e6a030c87888c18cfbe3d230340ae843e466b16f6346be17c4cf5467a6e0e7d1099fdc237c1307431bf50c0484cb7771808f447612d26b2b6431fa75b6b3376f9053fef8e407260daac7d136e852fad2a5f95db0ffc048ed309722afb6f9cb6fb7572f02ef2245f98f8586e75b7b0ab4df042a36572ba6ba21407c31d0910f60320d39d20283e242de565407e8542d56b90c72c1770a3436c1932d8bf19b65a5f55a49bafdd0cc638b4a3ddc325182e7d8e4f7c75ece2b7c0032b514741ec21850807d405b4a4a6612b6f2acca0b7bb7699f5baa1da2d3d0dda4dda2c5aa0e79bc1073d61bcb9c9c0d81ef87d7b2d88e12ecb86f99b7f6bffbac6d713fe377b510ca1682391cac447e20f16eede7c3b313a' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('73c7d15094e710df0dea9ad14fb6ac91c68cc5720f69b9041a681465cfbef80c1002ead9502d4c71d9b074f666b9b848a40fe6ff912d3594d1dee0d846b623b8eaf24111ba94c1385caa3d0f2dd716e3c996f69ca83ed78a848d14429e0b6dc3efa6f86f6292dedcee08623466ab18b2dcc84504294d0ac66e61e52d07d1d9ab972b17d38b94beb83f2fb8864639fc0f33f3ee576f53a10760bd8f414b2aca6c9dc271ad0249b2d07c252132951dee4076c59de55498053b3efd3ce9caf5455b07122863e80be68c18bb053edda1a8c1fc8f733caa6caa9e5441b077a3feda054e076421e8f78dcb80ff498514053dc231b172b8a095b9a77932c6eb0107c285b053bf93dd5f4db0060fcd098861781a6b92f9708a3aa6a3bd5a233bf8ddff5a54d31bf6bbbcbc07eb9b6b21eb5489715e1731fb967233b32ff2276818485c2eba2ee9d9f2539876acb02ee591351a7c059dfe9bc38e8b983defc7f76ba0a05964d3ed8c1583b36bf5c3753b093495d361d15f6db5082845d7bc1ccf7065e9579660083b50c4892c49be8c3ed2b0db48f693e6fbee72f1defde0e9fb2fd1948f4e98b5bbcc41ead2959594600b931b69387c386c59875824d23fd23582346853d626ea716364d484306b118dc510c10913283f6be0eee2f0dfee096d62052696c55efe32ba58148fc4345541facade49e6041e978aca4dc7a4b6c7cf547081c33aa00ae7cde27e17944be83ef12d6607c4f863ab862ef5b1ae3c52664a1cc556455a6c6f96dd74667f652c8bc675cbd24819098f3a5b434f2eeee4f77e303787d6f7e7e8adc08eaa5ef5d0c067f50c8a101234e2')), S: new Uint8Array(index_browser_mod.hexToBuf('e647760849a8c1703b2db2156971ce0d')), c: 187, dkLen: 2048, hash: 'SHA-512' }, output: 'ba6f755e3ff2d48b7134febfd1971a7b7dcd296fa9ed796f0114f284b1cb95f99aa5db6e6ec5f658bff2afa422eece9c4f72cd20ba8581ea98ce554a54b83bce64fb06c7664ce58b8cb07458ed6aacb57e80a5a31e7b9cd688fdd5e1c9faf11e9cc5c777caa12406befddf60eb01b2411614858c565f1585baa8e42d7e5d03ef775d3c209f27fb193ddd25840db131382a70669039763291be4b82562b73709702ab8793edc79c92409235a463a732e1f27fb8787987858c1f527513127696ae9baffbf09f54afe14f9b3f5f5c80facd5f0075ebd5b5614761707b096d13f542366372088fd2149ac8ed5334285e0b13c709ea43d4bcb028ff8e3ecb65ed2c2c47091d84f7f6b67071b7fe52db90d30f1859295fbd25b935ceb7683b22d637bacddaf0a4f0c7903904c35a6b5c4d0e6f2bb762f8cfa3be40110dbe0cb888af653f3bb755bc137cfd980ae8f44b9ad5bd21a8a4230d6a3a23f29fabde6ebb67889edccc0dece0fd4c21bd47bbc99fdcc0e29ff0e7222ff2b43b8322412ee701b864e6c324437ca893e83da7dd5db4eb7ab3a276d112a3ec1a06e6d6ead26fd309c2ee8ede009ec5fe94c99c1c0cdbfc67fc9551a5f66c5e6923b86ade581fd7a09dd223d99020fa785cd567c69047ea93b6b4da03ab1db7664ac73dd2be59eb5a2cbd765d5b345017849976be40f44f6f7d69b9ae283b94b1b60997265ab99bf82eb8f02bc2989b5c528026b978efd46aa1a14a3f740579a1918d28f969f8c05a8a544830398695af11fdf97aa9674fd9b9c3486e0e74c174ed71fbb4274692f018b0c12475a86432726b72ce14b8131c34263f559fd9e543b698cac9f51f2256742637e6ca6f56c2254f8ccd4296366a75a169ab277b18cda54b82f93cf2fb09f84492f32efb211d001d16bf84e5a6d9a5cdb0110ee79ebdbb6018cc0bc7d0c6a25266a5cf0cb4c8cb28b01ed4dc39c502658ee273131c48c293eec2aacbc71dd1f5b41682415cf0770a1a7579ddc78376fa99052de3e726137f5ba1dc7e0ea4129651380beb48501ecaa48e8e8d97e0b1149535898263e761cb8180934d8bc4b2b82e8c4cbacdb57e6e06869b8623898f47aab3c1b633bb16f83b0fb5626fad85e7aee1612bc8143ad173b764c797cc96d27370b7df67a4836e11368f77f718712306afdc11ce9e900d8ff5da15532311d9d4b97d0cdb29ab5ee75186ae9427d0323e3edbe6364694cef53a7f8339cc7602cd210dce7841369d06297df1178da4df78aa1fb739c123a7677e653455df377dd653f1fa291aa14dd6c45e0cc2bdedff2cdaf1801cbb43466c7359b88b27260005a8ba61bd80b25226b3d5b176c08373fb49bad924e8f65eb04a45efa2bf22dcca4019d6cba3061c9b62fb341171d8d7ce889d8108efb2c97c19202cc6eb996ea9496d06017cecfd3028f6a1450eac025a16f2d30fa891fe7fbc073a9243694a7ca2d94251440cde90341a06ec0262482dbe96aeefd488b8af84603f3d5eeb9345cf05d5a93b3409641c0d38cc83d4850ccb17cd9e47e8b77a94b41f3799a941101ec7c3b3d202b578bfbc7ab9dbac62ff9f0fec84ba1ac21394c7e534ac5311be8c6aaca4c22300bc6f5d1ae7f56c27e830f28be1000f35016ae80d5045f1c0c9497102ebccc7d946001b7a32ed145953e112dfb7e7f22811ba88f2c7afc9424476f794c8f2e8b9f9547b6a3d9a12289b762731d8ad9c8efb0de36272857163c2e0d03b52c182c549a030e8dc226a40274d27a450d91228df758393553eac265d2b9d485b971c0b94212af31a10ed76395c9ec87d15f7afe4150615c75199e6f34f86167dc83b7faa2c420db9d858ce68533a619622820377b2fe02ae9842d9b937fc98812a60b893c13a745eead74f40e8098b4eeeba0975da32f0ebcbf7d691e5210743a6c792ac58a245f278f6ec0172c0ab07e1e262d76d80fb67b5f9d33cccab6ae1c71fdc760bbf33df15fb14f4f7f2c45277e300755984b5b02ed38141083a2be1b4634c46034cfb3be2266e4bc56b7f689859304fbf1a8d05b745b9d29c28804ea659d515772c36e5aad7cd76baed2b5efd720c716dc5249b978b1aa47096e0ea34202aada5e7b226b4f5c969e1b4fa902be521e484beb726eb79f7f5502e9955be33377bfa126aca7b6b0bdd89b1fde0809c72260c0da72eb7b61f61cc5f7d1be4a6048740a1b90d244e45bfe45d27edfc0a333a4d9677670478a8043f220f04de06675181d703e0b05eede7614c552a6f4827e178d96cc8f0727e3e4c0ce32bbd489784dc4595dce944cd26dcd86c2165fe9dd951fd3968ee4bc349a190efb7c00addff9b011790395a9fb0fafd8d491833c16ee4ee91c872ce9a57a26e8c1dfdde46ba14e72e1135161dce9a26f35f924846b27640ac2facf624dd088f46ab9abd963938ec2324c55f9eb26c1b0282d6a0339b3affab47af203a55298cdbbc1de68e7707b4b77077737a9ef915608cd41c49819fa37cac420b26629effb44a21e2b4fb85e9023ebc7d7c3dc103c71d43e09f24a275e325f7ecb25787b43a3dd66b99ded62e150c780a7abf42bcc254af1824e737acff31a4a039ac33eac5a2cd68b629d3d28e3350d58483842bef05861368657f8f030bbb55ab7b6bf1032d8f6f479cb83b791964b9e18dae64f8dc64112b07b860be6ba5f8e72f305ae6ce3fa7326b5f002f7aa5bc05953e118a259ee953a597d95cac5ab7440f7a46be5fa211eba5272702d6e61b020246e1909b35923b3b57fb042bb0cdf4a4f2c47d3a604d8e147970cb42ff8629e485b6d36796658c1d210fb2bbabb34e04fd77a14de0a79b186505ab5f672e2d99194431f1b8ae85e0a24d811ab648de1f706ba645bd193e24293ce40eb0' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('cf8b53ec957edd0f4cc547460b75e80820d9db25cfe28f691516e376bc94bfcdf624e1a7bb693fa2b2b513b32ba36c7dc2324caf79b7d1e3ec29a757a4a040ceda471d34fc1bbd9ef52b535f1d6568c72039c6eea16d495d8d42e15009cdf0fb2a688b8a07b6b86e13cdb36711f91274457743d8ec701653750cd2b9bdd739e00a96f0b66d0dd1e40a8fe1a64a4e51c40063b08bff66d3cf3e9ca13e9ea018dbb31b8e9f923de1f96a9879708a2476efba8542992bbebe067a78e0e01cef573b49455996f41673')), S: new Uint8Array(index_browser_mod.hexToBuf('9149d9aee88a27660c929457dab1491b')), c: 188, dkLen: 3072, hash: 'SHA-1' }, output: 'e7e7f989c00ad15f78bb6b357cf38bd2ab61cd4c61f36daf914b2bd5f9a269cda64b6a6f079431682fe46a8061d1d9bdc0f48fe82f613d2d8c57cb016181e5af252bcc615b2a15a89cb53ea62c9e8a2d6dda0ccf4b87efd2bd523522f33d186bbbcc53faf3636a837db212a4fb4bc95b3afa9fbb3b09b091b5b316f5f9f35e9182f7a624afba01da3face8376ddffb666ce3f14dc2430da1e93a081a7e7a2b8b11d1a69a632f39a5fb013691cac606a21951b546555cf717d367e4f966b1aaf4b1a81caa14ff8f12b95e547da4be6c4c6d39c130647dc81aeeb6944490677649afbb4d5108141ad340a6d27b3dd9e9b058a244a2cae6c11a212f9c7c2141f49520cda4ae49d993c87c02b60a2b0ef82621176f4e3e34eaadd01696c9f38ce906da0eb7451904be7a8348f965932ef8fbdfa8860ba84580036a773660fee5563820648f4b5e665f02162ef8839263ef8319f93215a80654cdc538e5a3203b398df7a717cf920560e395d8cbb54a384b0d370e058166fae95508d2e03b0dc15b1e140b75ef5cc9cb79d68cac8828081b7e72692741a05c7f030d879d9a8923d72046dffd03d65ca3fd0c4c770ebf8f314cbc0c69626cb5a764b1a4e0d953aa077602ad074161ca2d4df910697e3a1f0a3d1d5ab5394a4ac4c82cd17f9ee92fa3f5e3b88dabcbd2625426ff58cf3745e16b367311b1134ff9085f7af08c1f39e98c2e13a8a397c83cfbb53be68e8b0d023e28500b2aa60f0074b7e1fe0f418088ff42db1759b57ccbc3ffde861824b9d815830518405205cbc9f475893a68616de9da5f077f91f8a9c39991c4885cdfc17ba7d648e7c08b3ecf00c5ff446d399f030f77c1378354f31f77cd27cef37f1d3e80e6feb14b23e9d9845d2a3e3fb871b9c7844a00202d629e01b9f5bed8d5a3e63700d9b0c05ddb0c9e5ba0c7dce569c79388b7a02af6225806d62bfe61be05b432fde324800edf36ce4ca21c83d56de69204c36e899fd43e61c33adf79b0096a45ef3273b0aa63be4e979c23e2d24bfcd4930bb72d3052a2e5f4cdce915e05f446f4ef939f33136d3e34de674b6ae51e76e450a04539649ce8e59f9278e155bb1a093a960efc70e26eb13b00c16b5453372159cdb6e150d804e1497f7f2fbadadc59947b2190c232d179b2f8a6850c3ab506e23bcd9196ad82b7c24ec3ec5ec0d59114f0c812e17eadf3eb9fc09e96f85f1e9fb93fc809fd0cbc73b823ffcef9d7496b4adcb34dce35c00dbb148909b327b42f81775e306a3d1469181f7a7d6b2271d090ace4b2ce8181de66b2f5569b45506f4db39883c96719bd6fb0037151edf5202ff5207643e9e9d39ef9efe1add25018f19319379cbbaf12458ec2c213a98c6b6c2a663ae2cf1cfeb496606e987b5db9a74ee982ce47cba919ef95ae0a0c1dfedd00a6c2edfe81163ff9703b187b4cb59b53d920e008bec8c940a977c98289da1c1b9b0f863233fe3f008b853440a184108334c3e1b7f106f5ced255d6fde228fed12da5c3414933b8a5288803c00dcd3cf846b2e02f559ddf7241928af3b304314c451b53002909338f5e3d4b736209ba00570731286fde746f5db32f0e4cd22bcd7e0fa669e41270a50e4ff403ec51e6feab97689dada49192edade4551f48d6b52e55d6b56d0ed1f2a4ec25fb6538778b6ffffbb2864b58b71fa36722b157cc2d539fe234819437adce5c25e1f6fa3f993f3a33ca0ad3dea907e31704448c168531f49f7133dfa590e163f9d1153959616346084fed53c8d0a528d2e7559b31a0ae7253fb8ad0520f904aeb235c3b6306d949f7e608008ae25e2e1b8085f567a13705a266b723a6c44ab4a154f8a3463ade147d39e67a815824c337cfcd6bbaafe3d842603b40e81cc7657036599afcafa7467669188bdf33eac57cfdf1483e6f455a9d41da182d361cf3fd49a57e10955233647ec05c46c1badd1849b90e8bdc76e3901bdfe534d232c352e1c6b78a74111c23d1e902ce8a995f1861fdc4b3454b7ca019759017a1dc1d93737dd97b301e4bb822b70d784bb470c1f0f850aec84db6c1e82554ba99158b44d9ee16341e6b2104f978555cf3321677aef8ecb54118e9479d326e89b44c4613faaecf5b13beab60808de96654afaecd7abd8fac19f86e1c48b2a0d082052cff3e7fa025dfdada7dee9e200095dca89f21115dc9c34a8e431111501af543ef55db1a23439b8ff9949b8045b542d8d1da71772429e899f31eb8c2d97a634ed30b652b6b5140d81015de75ca306b03567e0aca7ff5077f196200e190bd9649cdc7f9f821929bd276dfadd1c68dc4e1779a5f734a71e7a3aa5fe36d463d7f6b2638c9567df0fcb7a5162dbffa3bbda70e672f9a6b3998774819baf37b3835315046bd0dba19a492771b5029f0dc70038de3225e0923145bf37d5dae8a02be424580d55c1a19709b760bbc911df6410c9b6348e510c830ab7ab902965ef057d8822c43b2f772e39d61a5a48f9a94283d5301dde222480eb125296b691d702515af57338b574ceb350c5686900d181a8efc770b4f5d59598f310b5d06741156f465cb249ed197439e7ff9ccb6494df9d6992997a4bae9c0ff61dd1917fd71f8831864d687c1e7c641cf3ab1ab3d0481136fe491111d533e24706f74cfb4bbf8f76024f006bfba56de8b037b60688167538d73aaecd329c2cf693fd19bb93d5cceb8ba93653ff0e375b9cd610505dacbeae8e57d46ee8f5818b445205c860fc33ee16ffe788d3ae1fef3bb6900800853a91e68fdcc83b013c8eda54446649f5fb77376af3ab02649310ff0cf3fc91b6a783031b26756ffad5bd3acb3fdb99b7338914c5a40f27a73b6b97e172d2641c36fbab6a0d0999aecf0aae65c0a9d28ae96fc2f99ada719106f75739b55195105035aeff5b32dba4093cef40a608557367f1612990100daca44fcc10bbcd0f0a6a64c5a708df9cc8c3d3c4630eb5a2a711354855a3007d170020f0fb7318ce21c6f1e46584976f279d4d9e9392af194a8a63f8816b4faa4a0b0754eeba26b310f7907483899bddd5d63a0f507a0bdcdf65a94bc4f0e9e0fa28fd7853d6fbb4f23e0e8628e08fcbedd3a3b4e3c1b5b7d966a3eaa6ecb7b4163dc16f29b8b3dff19a0c22a4c626fa83d03ac307faa6e46fc57bb163f3a05e186589bdb727de02ff5fd493b6096fd43e371aca9d75620fc6289ad267fe8186a795965ab3426f94032a3488c5597101620e136d5c898311493946ed109f60e02ebd32e809bddb354aa42ed0517fda4f94749dc3b57a1c5aa90b81d207a92ec54adfc2f07aeb081b020c394b73d215912e8eac35f6e6443ed94cffc33ad787ba4b888d50cfd554eff395ffdc4506456658701a33bc2d8579e9d5aa542684a5cedab2b91b46fefc2a832ca6c3c7dec7ffb226c222344d3f6988a7ffad283500ef166b9406c92c69933ad9a7dca194a4f530f0134d077a159baefda2b764495adb29a7dba6c5aae6d53d99e6a4efcae99ca5a8e7f84a3cd1b5cf0921df0d8938ae0b00281356de7852be5c18626ddc4c43aca160a8cc410159b15f47f03c3bd493eb49847ab1e7836883d6fcb528d353d0cf3966654b0dc83f1e7e3feabe993f06e4d0bed78fbe52658c0cfbc9b44b51febd0902f10f7dd4ba44a683a59f2f37db8e9131c37a526888313326f00db577480a2d96d80b566b52e4daaf14580e3e01bd46bcc43960fd753e9e775aa08be24026aa1db35de2889e5234cba1c53d8440fd4e4e6f43260ee444e29355d3c928c902fc92118c5fdb37ac695201b0820fb355875f99923bc7d6a9f9da80e2ec44ca31d802cdd611b6a8c6ff65c4f0ab21af43056c3fa0fa7958b5a682e2458cdda08e7702de5d668d8b98a6039334b81a35fc2a2522dbc06bd8f0ec866c2f957efb8f8394583397ead76404b7e9ab7485cd25515b4fc968e210cf364e5cab724d392c1b7ef989715fc37dc1867e91ea5b9006f2537fd3a904992caa36158b41eca1b623b9be41c29dfd349d86c93a7cb6deb8c8297a0f27c2da5ad7114241b79868a822e58dc00bbb7218d3b5856a35b46f1afad8ddd514e2d18c4624be28419c22f47b131afee1c6f8cb5b3eecd254774d3eb3777719257a9267547f05c2749b5cc45258ef46c05e72030ae597a7912db562fb6462c09e9f37f5002ac47aba2051fb16dde8c8c986743e32bd8bf0fa036bf18b25b522411fa4a45b17806a0449e7ddb7e621948c41a4ba9896635a9a2b67feb3f19446736f3bc04741216737b05bd75ec0b28833db4b091a63034330d106b0180ffbff0e4d1073611ec62909712f127ab64f04f57d88f144ca9d0' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('cf8b53ec957edd0f4cc547460b75e80820d9db25cfe28f691516e376bc94bfcdf624e1a7bb693fa2b2b513b32ba36c7dc2324caf79b7d1e3ec29a757a4a040ceda471d34fc1bbd9ef52b535f1d6568c72039c6eea16d495d8d42e15009cdf0fb2a688b8a07b6b86e13cdb36711f91274457743d8ec701653750cd2b9bdd739e00a96f0b66d0dd1e40a8fe1a64a4e51c40063b08bff66d3cf3e9ca13e9ea018dbb31b8e9f923de1f96a9879708a2476efba8542992bbebe067a78e0e01cef573b49455996f41673')), S: new Uint8Array(index_browser_mod.hexToBuf('9149d9aee88a27660c929457dab1491b')), c: 188, dkLen: 3072, hash: 'SHA-256' }, output: 'baad4926c5da0cf2290908cd26ffaa78f47c832138e373c0bc625a5299063de082a28aa1a4b3e394c7387a8d45f13cf7439bc6ceb449157b64f9d311f7bd295ee7ef999b3dc51fa06d83390aea43fefa7c7e8914a2acc0f03ed99dcdd205d92f27c2d47c171103a413df50a372b2860f14946c862ad625db3bbc3c9882c28b42942c0a1f1839ded4c148614cbc29fbde401b2e222af2bb56d6173f29429989aa86724f0452185aedd54590a98a40c5170a9af3deb743b5fbe409486a90adf06915dd1a08c2bc0e82b902159e8d70000b8cc9dd15799a2c142525bfe665be27f9fa50c2ee985e84ad84ff90f745eb36fa3160e5b6330332159a2e038510f8a30584304da7d5ec4c108eb68c3e0004db3fe52111ee74537f892f260ff0910772639f3337d8e7f3fa6c292c987e73e8da6970c0a06cc40fcb6de49d7c09c9154f60307b3db9c65a91041c5f74b92a97d3528daa0a644d61153f4bb95ae6bd9811501a8c734aa1ae0bd1702e675d315245a64ed78cb31c65e5de71bcf510f8a35995cdefd08921b5f4ea321d45400b4771fedb90d7f89caee72c1fb1425d354a29703415844c3857028eb8cb8fa1c72ea9590802dc53dea0da5f688ebc3c9f8b567f2ef02a00ca3e4857f5fe39fb7000883054ce5f662d71836f416ea3bc4c684a1f73c8c9afe67332822881b374f1560d7c81c755baf8389304ec3138c74487a570e26910a15fc7d230bfd24e5cc058c9e18fdb50dde559ff6290b5ca530dc7e22e082e37905574c1aa4e74cda6915ed1fb245d8445c09880299d5651e48f5a109169e8d451ddc46292f6d1c6c94afef56490aece0d63505232c4e8027f60ec7b64868b0b059b27307e490edcbb8b0da0d310dc3b01163b4058915d48ca48462f5f23944a2bc82cdec4d0de263ec4e7e1a6b2f5c65b72d365509f1756d9eaea029b6da94a82c6a605bc62fcb539857606d98b4f461803222b8bdd87e5229a4baa02b5a952c2610ddb99fedbb6fdbd42fb824b869c45483b2cc6814a7ee3a872172ec8c4fb8695b0dd691db62b44a15f263f54fda6981d4be50c59e5cf1ad0ed5285fdf219c1cc94deab062b040b4662c1ffffeca282f3792eb2dd25847cf5ba70994cc806a2445835b15dd935f6bbb7799dc9b97577dfdbf9fa130411f41f0788e25dc9aba52315a9df24475f2daa957d22a190aebd99d28d0d5dc481058c8c35b19838dad52daa9710e1b04cdda5da15e7bd75fd7c5903694863a679c408dfcfc07de968fbb2b9307f50d2b670e8211eeafbe73d868c36993f06d0572c9399f471e9bfefd420370d3df5ca8d360f36b48e68b75627d9919aec394ad595f600859ed554fb738284a1054245ae18d5aa5be362741cee7d39419d07488191b7fae419ca10f86404d4f5a1741029097f54fe64300105ca28e7a9fb687fc53f71458b3d2b8c1de3cc2cd4ba7ba6cf72e2ffee0d5136b243f446cb64ad7c57f716170906eeadc47b210ae59c698368957add8173c3746e7f4b99d07ed1fe93a3d0c28aaa980dba551a3edbd3dba33e9a714714cba296da3c53ca436515633fd00cad105ef5d80dd58359b872c2f833ab852bc56e6fb47603385aecbb1b8706ce3deadfe8a68401a71d2c96e4be683aed8369a3da4de11bfcb0e9f51b897b4e4f5476ea1fdb14664282747e56839e5ce30569430083168ed36317fe3ce0e144c6cf787fac760fae8517847744428f9807163dd3f974aa3a124f474ffc2d04fbcdec423d7a66374db9f84c461ba140ed4305be383a3bd153bad0304b8e4ea1a48ccd7d4555b3050fe13a05400394868a1cb894dac860611d44e3b4fff9d821ba98eeb7872d5b36479a8e28ed7f5c34fc89ca59b67f060dfc65c834f1b2a8e8a7b740894708d1c3fbf80ea6290b4f25fe8b437a3ea735ea44324a649e0ff0d88c8d2a897e52d075258e0f73df222534a86a2dcfd81cbd9c7dd9c94b5d09df90f80811cbbe082e0052483cf584214203cb8defddc719de9e34908b106d86301e748448dd057c7161e22234208a0e29c1062f851616fe347e5b7cc1fa57f67b7c03804381d59faaecfb728d9b71e16e943fc3c5771b00625135b609408df0b88b33afd46bb62fd03afa0181065acb8cbf9c9ddda549bab3810c70a99d8420ab13aa8c16c4352a605a87e51ecbfb92fa2d9168f4d57f792f6ab786e4c85e5a7ef365c0147c9a11845ed91d0646bf1218ed26aecf1eec42eb4cfe49153d9fca1dbc2e826b566981a5abe098e60dea78158ce38aaf3256a5a0b1a3107bcbd54ace341973d51e87a074b7fadd0f797cc4b1e8aea790cb84d89b581c0c723fd307a73f17480dd808047a9f3c1cdfde2039af8775ddd85833aa52aba4e026fbb823df6ec6cdea06a5dc80e864e64d44524e3dd9f73b15c5558e4779100aa5e9e10c551231560cfccd7f704f3fa28562d125c3c64c463ab5a3ce4bc51d458248cf9857a379bc877d530a547b31ffa38ca01ab16a50ac73942e6dbe653787524be77ccadf2a800a8c6b09191cee9da6e4956ce4c5c776f7b584a2cf920c7fdd8ad6002c944c9b60a5bfe10335f9dcb3078efbd01ac3261196e4c501f6cc2d89d07a847f3e45fc9e174a71c1dbfb712558bbf4e1de762d65856311a3fa584b81caabca2e46b1769331db9ea424e61e1f721d401d493a3653df95a1330e0dc9e73df7d0a3da52a648592b5a558a15dd124dbbd360914969ebb4a827229d9a0f5684da2e2e0baebec7090b0481f8192508b1a281e0e8f86762739d54ed536d24d9c9e1d6b030c562d490ad9ce4f29f318cb6f2244b830375bbffc2fa5c188a2bb72689f50e1c6d5c7aa148ff1c30376afb00d3ea00c321acbb9a9c86c09a551708cc6d07cb841e40b6caf7a138c81bcba1757557b7f5a5caab37e89ebfe4dc134365a997fd781808769826208bc9ea78d1b13f98de12dc0acc91f5128c5d18efb4ca47bf89f58a76ea238f738aa92bd4ebd097158b67ae198c6813b972bf98bfa7b9ad973311b163649405ef2b82fd8b3885d3cb1891093264408e6268c400c7e9b428b14ec2cbbdcd1607c2192aaba56aa3b0b11e51bc35ea8118ca0215d16c46d871422264343f76f2aadc0a066eb9a07db946721cc021bf30a4fe95fd545c611308d0719d3930ff3fdcc35762108bd0385607fa5ff915535e054174236c4e73baf00001f8dfd19c849215d2a3ceceb1e63b2a3a3515b162ee41e2aefe47a7a7665b69b0a5ea687aad7a916d6712ba80fbb7a87df5ab6c3073efe9f33fcee61c3597a315ce7c4b599df493fba5d6d61042b83b8a39469fee85986b886c7fe1a2e2fcb0453c7cd09c718f65b45a88bca5aa6f6e676883b22b2d703fbded2d901b7775db09995c002f9b4f254f22bd55aaf4f65fa297f2d08a8b6001ba94a28b83bcbc2db45a380489721d018174720f3e21fe285af61af945bb4daf17ba13db75a34ec6ef3ffda4eb8c494bb952c54c3b51e0da41981745c55f8c5ed598b646633b3afb1e8a1a47a30fd2e83376c0d6f1c0c4889fa3decb481cbe6e382d3b47b249e7d3eaa96de3702e472788a3fdc97d98626109ff531502a354942a55545438f47c9c8c5ce93e6c110db536c1a27cadff68fdf3bb9dc4dc06c92f8a21b47f3a4be12d24017e1ac51e63fcb38b8f85f1330b87ef62c54a3d3582e05d6bc9219258c8f607f19ba087d3e4cdad0334ad9b9139614c8e18bd6d319100b4460b1957f2ab9fd9918e8e4dbeea53ab1c13e0e64a53b865cbc47e849a7cd405d7a55d9d56d618f3363f7a14d6549317ddeb45fc883971fd2129b05a001f2584be5e7e7fbef1b19093ff1cd6003db81b47f41f3ef9b4c1799af19b5787f6aed0bd62ddf875f08130b2e25622fd593b2145add65adc78ce8b5aeb5efc6ee9d4a917976c3de9cb07d24113386dddf8c23d484f53a6bdcd683a33db50da39b1cd3e096d4b682f344caf83ea9f538669fd1bf4a7b8b75ec4aa451c4b961f4fc9d6b36bcfdf81481d98c145acd4d5d0c2f5ef04fbef8d1d46551971c80de5e140abdcdf1875b08253763451f265b6fd25c5e01244d2171bad8ca99fc4bebe5b09990ecc1d5a2e4f5b12ef30db78bca6438537432889899d084cda632042134109b8be7cfb91157323d057975c9f4a9b6a0ffbe2aec31b358c88c8632c938d5561ea2094836d7545bae5fc30d262638f133f79ef42082ef4542485d9442354a8ee81ec03e3e9a2ceeceaeed33deeb4db4fa5bfdcfbe1955afe45e3c33593f45e0903639d500a3f9014c16abefbc26ff6a287cf380faa387b34cc2e037c8d6a7458fce9bb76d7a1951299891f573a591542c4' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('cf8b53ec957edd0f4cc547460b75e80820d9db25cfe28f691516e376bc94bfcdf624e1a7bb693fa2b2b513b32ba36c7dc2324caf79b7d1e3ec29a757a4a040ceda471d34fc1bbd9ef52b535f1d6568c72039c6eea16d495d8d42e15009cdf0fb2a688b8a07b6b86e13cdb36711f91274457743d8ec701653750cd2b9bdd739e00a96f0b66d0dd1e40a8fe1a64a4e51c40063b08bff66d3cf3e9ca13e9ea018dbb31b8e9f923de1f96a9879708a2476efba8542992bbebe067a78e0e01cef573b49455996f41673')), S: new Uint8Array(index_browser_mod.hexToBuf('9149d9aee88a27660c929457dab1491b')), c: 188, dkLen: 3072, hash: 'SHA-384' }, output: '51a594ce4ff44547f9fcac91f2a9f7208ed191d9446e2c4c545f23ffa9e70267d19a05274e54a45ecec0fa46f59110cdccca57968723ce9bff1400756b0e350b2bf663e38dddd4e2664a2155d42a03eea8aa8aa0adade98b1ed403c301d48aa1c648697a5c6ea55fa91d5fef955252ebda73c27f1588b09c02393f680a6c0f250992b68779f18a3284376e0958c4b8f69fa099f6752d9ac00d4fd426431a7f91d0e9a4506d3a6ba30270651327abb14a663405122c7c88d708a5c9d01c1ad35eaa42ce5755f564598c3adc6375829be391c2f4d3c73ab7a9ed3ba91dce9cc441a02710f7dce9d37910e54d70ef86146cd6a2b73ee65fd0887b8017df6b006c9cdcbf5a799983961f8b4ffad6100396297311e880a7dd1d048ed852c9c458f7ebc502568de7b5d5d9d3640a20710e4c149be21a5d0e23819f0a6625fc4e7619ca6753e7721226238fe9358098bc5c79ae2e5b7556cab0492289f219ad9f51bbd34e5f4b38fd807a817cf17f5e088807d2ad0b365e1fe87ae30c6fe765c62b324cedb43f4ae532c1751451851d9e34bffa05df55d7d84f609eb0785086bd77a21863f69042fab840cdeb2c079a362d331d1a4143377cba523915006dcaa1efe3c7c8b87e524e8be049b13fba66472ed08eff35263ca7cd56934932b90cead3427a5b94c5e7c865ba2664ec504a9af996412ac9210b2fad41ca0326256209b33ae954daae6390921b8fa2df30f419b6f837564ce76cf27bc8d3a7fa240b34c1be35d75b2de0b2e1b74f7ad22a1f3219f9d385641482aad9c0323344101cc5fae48b2f5a6c24f832ffc3859757cd4b94a87cd1b62517f96e26e5abf3e7a81cccbbe761947042b5e9f450b3c341ccb094655ce6277f719ee372b16dfb9b0a85e82895c6561271cb70795ca986516627cdb2d2e5971272b2c105754404e2736d67d1986a092f0147217336a665979e8af939d9033c671bdaba39c884aeb6229143c695b584a1489be364234b2299fbc37d8b51e6da56ed3f8349765d8dbc9a12fb7293f39c71fd39a1ac81050313b77e63e96b3368c99f09971fa939b71f9182808192636f279ac06275e80afb9f9cd7a1ed4cb99a12055c75c16116e24216de30413c2f4a0030e310d2b4da2d800e021d0e5c928efbf67724a6879287058ae8a863d0021d989d10df99a12b312457c9b34f60e06cca4b218e6edae87a7b66e9a4aa2e88be27e2122a2e845aa563091eb4f039ba929e1861a4c0f00d2837fddb4ff28e042b665b336499c6a2144f75d79b2bd68ab0a95e6c6dcf58a686fed83d61cd16a7bb7c8e18f8d66282917aac013a659065396bcdf86eb788923633cf791af7abfe63573567668a340fe3ddae5ea5ec7f63ae5bfe28be043a3978dbe71c9f27bdea7794c5ec1fe3a90879f5af0830de818dfa3a9e1f849713d4da49040729fe49a0a0e98c51a8dc4ab0a53a49fa35081208fd75509aa9ba7d2b3f459c08f7083d06f1d79129b52c7710b17a20f0c8504c835191b52b57e4059e8dddb9ecbb06b7aafd0b81a5099dc89bda78b67010515e2bbd0dc58358619210ea45d6510693506e8d5fd0ac698c7481fba55fcbcea084510605d4b11509dd168f6c75635d1e872d7d3bfb7a31fc927f36988b6abbdd2eb4a3988818b4b14328ba93ba867f94f093278c7c28bd99508d8144909493cd7ab6164b734d734d61b13cbcac722f7d46ead983679f94396488f96cdac0c7a159314d1a461ee7cd484f6bbd1c1e4187c10a51bd77149a991207107b7f48a17cb21a58700dc4e21111b42602302b9388cec374cff99461e3d083190110941016fe3052c800207b7ca2bba2ab5c72339954bcaa67abea138846ef6cdfff747bfc6aa634615d51bb87e6e3a77e67e422c95f2ddd02696ecaac848bb0fdb215438a3b5bd776f479b89d00ffeaf949ca9400a4a7326e9e0bd4652c6e0efde0c03623b2fc7eebba7ab75c765ccb37534d51d92598e460c9bb0dd851bcc7fc9c24be8b90012f2b59fe48e6af75beacf2d2bb92fb7322cc249619855b1f2f25cfa2249e251482c84065b1bd62be64346171e7a6cc0a58c179d5eed82f5ac6b61e81ca4e180e89bbc32f82ec76b15bb93032c36e2f2e214ebf260c5b45bd0e7cfcdd898c860b71e40dd8e12c233f77659abadd708895f5473eb0fc3cd85878c57d98eb40608272040fa641a31b1d097af395dc1d9888f80195672b188c38ffd3e941316c9aea221cac13eaa3283b751b774ec4e50f527609da2582ae587c6323d1d16e7bafb7d5dc5008a5c18bbe1289000b8e03e8b2654e763dcb5eaef98ff22bd0e3cd5af8d70ab516fd9830d48db9f559469e987851bfefeae27dfa723015dd55fe754c1dc4ca3fcf67136db3c9232661d180cd281fb33f73875f7bc19167b92e4a93fd70f1d180bf7f442d0513bdd3e91f425aca88a69d38f36c006bed247536ff58d23723f36d49c0db817b2557c82acbc4e5315b03be5a15a93503c6e7118bff88e6cfa2d0f392b17e05ae4a7f2ecda32f9b5c79660e3014b928f1abef48547958b53a55e1dd5062cf454ae2578a1a0ea77001b568ad2a09dc1ce683475f1bedcc784c523f09c70cc9662c3275d0f42e7c2ecccdbc82a3d1cf7cc0e34d37c0696251f0f034c3dcd0eb0036ddc7d5415dfbde1e1241e6f72f4002f3e1c905cea7bd4cfbe75291a8b1a4f9a28df3e47fc26d342e483ccbf59dd0f241faabf9eee7ee459e1c7f1cc16d428a6b3dc47a87d891a55cb81c3beea417d4c7a60a1d4c22189d95796e1cc30d4c710b43632cef2a291e979ec711e32f43dbf20c43405cf74a0191872daf00c3d20c538d5980dc10ae3e243a4088ddd0084f07bb11cf93a9a572893b4c681c4ad83a4b356ef246e84f81532ae1f60a306f52fb1b43caa5b18c0ae708e3353979febfc2e4e709f02c53d0c7163335a5d644bafa3a42c8200b97df8715f10647b7da89c2f1435bbcb69cf6bb2e01115b6733abc461234c2451f59ef962da21a37e5ee9ace0221c7113c961d7957666e294085ae0dfdad6510e302053e1b630187c28a093efe94146edb3d302ff7477d2e1596e1f0bab07a25fe0358b985ea3fa4ca100354e121342018119761ad4ff33d52b296a922b8214218ad7a73abd508ce28779927bfc9b4f5b2386615c15a17e53bf674a694a9ca91218607f6ad54e55b1667c5e8d1568b59714387d8c38b21d8e1e6568b180dd1dd13eaf4661f7a1abe1b3ab11e40f22d51f273da4940b707cf402a3f61a6301590e39df53bbf2d8e6892185701cefe3f751fa9e6774782328f7415c7fc50903524198a132c80447eeaff99c999d8f30e723f61e7e178839804c901e322a8d79e3684c79db1664b1d090bf57fbd336a40b213fc080c3cac125e3e0c2f143c75eaceffddbf2776d6735d502816eee6c3501596bff3237b686c15aeec91b357ada427da2259f3c9c9345a2383fcef90a85c2abc77d6fe1f5cef86b44cd2ba175f6debe62571e68ad8542c3775ba4a42eab7f95c00213289abc1f10cbaf644702a4aa616f914bd4a92ba844da9c0008a74aae0336a6f5939d1aa9d5acfa555fa940c1b468f7ea261e71652093ba31d822db3521c7d0d105bd89802b37129dfef960a34d33a3d42b35a69e25c7e684ecb741a40f6f17226325bc15a554daa6d7a7144ee4c2229772dc37ea4b5ec57a77fa73c647b3b8a8278af6efe3929b4ea8c1eb1698ee6b52a13e6dbd2e4adb5eed744086c12760b62e612e727f3d94dd92690c305cb2b59e19344c9d1685ddc4dd43fb3f66ed159e9328866962ed3c992347bf2d8e2464b27605f43b5526fea2e3432ead1ab2f89f957ab626786a82635c5ada5aaae1ab6dc564b6493009c7a774ae0f72f3c899f8b1bf426241cb520941cb0df98108f2a2c828c666c287cf185d5eea23b023c1375621732c1bf6c2c882d5a011ea60ca81881b95728abecaafe32c2c5764d311c9d7facf3d06a452bba89ccdcaf5763465fc5f352b98d7cc452ecc550557fc33f88dcb658cd590fa4463ab1225212e6fee40fc92b54b534d4a38c587128ede5c2e0e930c53fd78de7dc4048962ce264fa46f2f2d51b1e7fa7a3920ce2133cf705023b88e579c6c876cd1fd37cb80421655dde2b767cff889f441a67eee8103aa3a40049304a8acbdb067fbc45508f955a9c8b4c5598cf8a286e6ff0d3820430a122b40b8a7e2e5899028868061d02ec55a59b6a2cebcf4892b52fdd31162ffce90e5ee5d98114fd97045cf4a9aead31ca3d49a5399197decbee1f982a1f020e11af8aaa4d73960c7100f5531008075649ad1105c3dae2ffb141b187117c6cb5a' }, { input: { P: new Uint8Array(index_browser_mod.hexToBuf('cf8b53ec957edd0f4cc547460b75e80820d9db25cfe28f691516e376bc94bfcdf624e1a7bb693fa2b2b513b32ba36c7dc2324caf79b7d1e3ec29a757a4a040ceda471d34fc1bbd9ef52b535f1d6568c72039c6eea16d495d8d42e15009cdf0fb2a688b8a07b6b86e13cdb36711f91274457743d8ec701653750cd2b9bdd739e00a96f0b66d0dd1e40a8fe1a64a4e51c40063b08bff66d3cf3e9ca13e9ea018dbb31b8e9f923de1f96a9879708a2476efba8542992bbebe067a78e0e01cef573b49455996f41673')), S: new Uint8Array(index_browser_mod.hexToBuf('9149d9aee88a27660c929457dab1491b')), c: 188, dkLen: 3072, hash: 'SHA-512' }, output: '157548b773151bf60836d9ca927e022b4df315ed4f40c618f00e1ae503613ee25f58b08c2d1cf7562de80c72d5880dd379d58b072c2b8499d171690ea81331dab3e88106d26962e7e49938554eec0a48b1796f0f9d5f7e29ba591c6e85efad6b35f06b40c58bff5c0ddfbe73f8cb7d7d51dad422fd027219b9490a27284325fde58c6a1ac8f0798f393a7dd483297a58ef76da67a6cd1b7eaaf66a842abceeaa5665d4227174786508f80d848b633d23efd310db499b88fdb5801d0d9dd0f446347947adcbde195caf912ed3c17260c5eeaf3a909db926768384584a9608aa5776d03a0e18031e3d1975a5c01d3bfb8f2d75b240a8098597ab88db9f0bf525f73f97b34ec89837ec53f1159f891f5d248d5c7d6cbbb9c5a13534b48b1cdd875b4cbd7ebb0e8969421c2d8c162e314c954f749aa514283a735bf274b845ce117c73f30a2d25665f727bd35397391155b105ae1ca8761bebaa624681825c23cf883fc36011b7f0dfd8d0f9373c9ae35dbd5df892690f6cfe059886d4a01dd0717692df30ae47ccdffcf9fe9cd2b39e8909fceea591b19ff1869006fffdc0e8342e8cab26cc98522bcd231de86d1aa9b814ed9c989d08c6014134c3fdab1946f94bf205da6f2d3ef328ae13cc65baeb843385a446ea80dca458496455e15292f3981944c215f924b463945ba2ed15ca2e563289400ea2fe16b801bfb810ed7253b265e23fa092305994505db3e98760942fb134f995045cd6c39900b962b07214390192a1bde99b99b44d9c1e168a42f3cf5e119ee96721226e147e05474ff5a64f76ac1b27bfae6cd96ca4b15df5eb76c528664fc7e9f181d38b0d3070d0978bfb572fafa8232ffd0ae7322fe73c904b7ddb37896f9eae80a8ad5ef9fbeed101f315cbd7c9429407b01ed5f7978261c4eecc8a5e9d9432df5e74a7ad72a934a8efc4fdb716bb57f3e3ffd1c70ceb692dccaac58e7fd16ea34d481ae43992a68fef2266bca80cbea75f6d8838b95d7c52a5af5c97a1233413b05244f1fd70c3a9bf2f67e3029f5112968439da6177d8d44ae22a31bfe49beeb7d9479f247e4750f114c3ad392716b0d1436452218bd79639e1d8c5e431d866b4d37f32d89197e9e623f02c4d1c702ecf3d40975a71b31a11fb1721a7a7ba2a628a35bab3dcf001b65629d1e4def0486c1fe1585e7601a8a1228056206fa41cb8badfe8fac4e93d67d8fdefeb811ce040ea7f9aca8ad4d937a9a2f842083fc37a496bd180bbeeb2af0eeb0befc89c2ef2a3bff9fb80f7a108331dffc25896b6997844f55ad8a545e2c6c3dd8ad50afaf7731c7c05c3f5c06e475f6fd7c41ea8bee135efca16b6ef320fb6770437034fb386f6d1cbf70405756e36050e3992e6acfd766eef5748b77d42983de7e3161949584321d56aad308c1af05c87b2e15703d9bcab4ab15a78368fa769ccd9d921106e3436be5e23aa635a4617c3a245de4f1c4a0497ff9af3a9a9da738e1a6b5adc12dd1ac678104b29cfe76cf4d91170734e6a5fbc3f63fd3bee68f48f1718537b8f8a6d0dc7af2a4a8ba451ca07980c81f9ae6e142c66234977efb630f6244230a02c4c8f4046e383861e5609554342e1634cf0baa04339988119dded7dde70f733af2a0dba376cafce99359b502272fdb426692baa3bbb5d20d342aeb0f25b5ba539515c9c286a1f0ecc48e0b6d8b05390d9bcd74545f6bf808ccdd085ccdfdc8b0f91f6d9197f4edb27fa674474b1fed64c2af3b0cdbd90a006be99268be750781c8fb31a6f1c567cfd4fa6c25e42d2f87f37b7dae4d02661276673ea5f392ecf0098681259baa603ae3313c70ba63ad4feaf7dbd6377466e2701cd70071501721a1ef3340822bac497533c7e46e376e1b6b83a39d5e1e094d92ea6b9a61565589ddb45de9150f8b9cb8b3ba9e44ef4c5170b8bc0ada06128e410ef169e0810bc228e78cf4b055e5c182230e1ba87d3439a3074360b2ada7b465a103b8800f3cafad79dc624d53d492feacfac8b49876ad4ceee4ac72ea22e590254790a1f4d4572f5ecb81a020bb36e7d7296b5d2330f41999d0ceae28a398b841a39a58c1ed0d8fc5f207f3efb8989ae229aae0880ccf48138966461a90ec2a94a443b90a09af3be705a212585b62fd920aa4272356c3bda74c29e4aa04c058790eeb364d4ffffa00d17d43062cbc97eee7025b27e416207e3ba2e2e302f9f53f5e2fe12835fc396623af28cbbb8f1a092af3d552940674808a12101037ab302427aa461f9ce0570b094338c4cef36b36731c3bc538570a1e594f5d82b900659e65f3e74e36ed60129d56c7ff3edbe3efe93584242c9552c8b83b547a34253b1bffad0d36c9af39d8a4c502b42c0bb66b1377bfbbef741a948160928613f8e260d6c8698964f548e911eddee90b8efcf9ddf928d7c9cb6dc59887dcae3cd83c74d40681984b19a266cc9cd2138619607e417c99e2fcd5fe94f35dd3d73f2f8dc0d28ac622f56c2b7d13c55014ef780c68d9ebeb6fd068ec8ddb8c50ac35cac3a2e88bb93e897d5d69499d7482bc910a9d45dbad970c092bd8cf8e067fe41ff2f27452ff495e024eb6aca5648b02dc1aee82d09a6df3b2b83a772b4f071f54f075738ddae524f638b8da26a511fb9ca7869e59e00a0bf6037475a6eb4ad97c242d12f158d287b3af3c37879878102273c78c10e7c8ddd5c1288df054adc0c905b6a39cd20570d639d3d717cf26abb26820c59ff217c72018adcf61bf53ad1435a6813c209b228c728dbc47862f669c05ca2db4da11cbed6da2d438254378f9678400f6d10a1c255d47574fab5938d93e8850003a23994843c7ca19201654c45ea51b2090c0cdc92b414244a5a0b63b2655a26668a4169ef2154312e51e7411cfd0a26d0d55bd225e9ccf253f9466a525e23aa4c0e5cf3f37559e94ccc8ffda9530c0990ef4416b617d4ba9d505d03aa000551882278cb5461a6cc7d30cdcfc68f6483f0017387e521b3467c31844498879bb493c3b19b4171abe41323b772f1a19c2e38fd2b842c255addd28d6eca4a8905e96d4c639f3cc7013dded20df1b9a02525981a06b377e896fdd6ddfb5d896055934ba6d3121c4a88ce99c685fb391893f61e08afb7509f25fe3041e69bd9983762e4321ae068b22a8d56d02fbe2ecf17d0b1e731bbc423a70a21937162baff6eb2efbc433049333f9019fd684653a1d9d834fae4896261f8d07f7aaab4309696e4a33f80dea6a21390039ec962785d1195b8640dbebe0e40ccad662576a3628eba51183f9b8b61acac74c42006f88cb353d5648ae2b6211d75ff27d3765fa790c4841ece2240796adf544a7978878299731918275ff7aad7488e7d2f9cb9605c85a09d602983c36ca4570f0acf85af051f7588efc4b69e9535840df05cf7666832a532d53ecdb334e8ed486d9890d83d60ad668da4fa4208f12c83fa5ab2dbd7907c475ce7b5be02af1e86e26dc6f1b9e0f734807ed70e57ab26e6d8d2d358de59689e8ef33f763c437e1fe5fcb68e6d5ae1424f2fafac345dfb5d2df38b80bfd39fe8258aa9578e9a2f921e2463961ea7e96f9bc3ae31fdfa9cac82a5f501c110562ea7d5800cb674e67f0416d4ecd3251719caf720f61e4b4237a34bd34eed2569e1bcc9611d9802531efeb95a1bef9535c0e1b75b52cf9d9f0897a6246b44368aa8a384e9a14e14b600cfe9b3245845aae0ff8923c7fac38a4d946303608d86d5a0a66d3ae6e223842802b27e2ce89bb2ea53cadd270defdcea02562bcc29d24de561d8eded7a0967b9d785373868d81ab6f6ea5632428c099a86e7bd4e7870c10f19586682b25c7dd456331e0f85bc2e6fb8daf107d95578b3481c575a533ac0f2f6a9c63d036a8cad1a507c54ab36ae6b172f832613e31431623aa0184e2629657cf1dac607bd91f9c570a012deb5ba681db1f534b07a7ee5812cb011075482444a310eb24442189a3e182c0177264be7261e0466bc85bef436d7cb2e718e45d3d4a5ba4dd4ea695f4e94b9ad214946e93392e9f57d10f3df9164435e0fa469a564364efbdc02c65fe98f6674fb9d23844a65133776e924b57f2870d9cb2718a43dcc5c614b613f88df3cd0193e57f62ab6099af97da58b9624721da40902bc13361bda321685ce6f2d1b41427cedfb248dd0337b59cf7c59055cd09e3c56776d88df2e2ee0d25f809f3e054badee21a948eb57c09927bb310852cef5b6dec4076ec97fa12ada7bb1a816d504153b2a31fd8cce1cdcabd1c066e5bf5bbd8bc6380b6aa8e3073a4845cd7e2a2171ddec1473eeef1c7a9c42367c364ce597037451bcbccb2130c0ace771' }
];

const vectors = pbkdf2.filter(val => !('error' in val));

const suite = new Benchmark.Suite('PBKDF2');
for (const vector of vectors) {
  // add tests
  suite.add(`${vector.comment}: ${JSON.stringify(vector.input)} `, {
    defer: true,
    fn: function (deferred) {
      pbkdf2Hmac(vector.input.P, vector.input.S, vector.input.c, vector.input.dkLen).then(ret => deferred.resolve());
    }
  });
}
// add listeners
suite.on('cycle', function (event) {
  console.log(String(event.target));
})
  .on('start', function () {
    console.log('Starting benchmarks for PBKDF2... (keep calm)');
  })
  .on('complete', function () {
    console.log('Benchmark completed');
  })
// run
  .run();
