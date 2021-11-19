/**
 * PBKDF2 following RFC 2898 using HMAC (with SHA-1, SHA-256, SHA-384, SHA-512) as the PRF
 *
 * @packageDocumentation
 */
const HASHALGS = {
    'SHA-1': { outputLength: 20, blockSize: 64 },
    'SHA-256': { outputLength: 32, blockSize: 64 },
    'SHA-384': { outputLength: 48, blockSize: 128 },
    'SHA-512': { outputLength: 64, blockSize: 128 }
};
/**
  * The PBKDF2-HMAC function used below denotes the PBKDF2 algorithm (RFC2898)
  * used with one of the SHA algorithms as the hash function for the HMAC
  *
  * @param P - a unicode string with a password
  * @param S - a salt. This should be a random or pseudo-random value of at least 16 bytes. You can easily get one with crypto.getRandomValues(new Uint8Array(16))
  * @param c - iteration count, a positive integer
  * @param dkLen - intended length in octets of the derived key
  * @param hash - hash function to use for the HMAC. One of 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'
  *
  * @returns an ArrayBuffer with the derived key
  */
function pbkdf2Hmac(P, S, c, dkLen, hash = 'SHA-256') {
    return new Promise((resolve, reject) => {
        if (!(hash in HASHALGS)) {
            reject(new RangeError(`Valid hash algorithm values are any of ${Object.keys(HASHALGS).toString()}`));
        }
        if (typeof P === 'string')
            P = new TextEncoder().encode(P); // encode S as UTF-8
        else if (P instanceof ArrayBuffer)
            P = new Uint8Array(P);
        else if (!ArrayBuffer.isView(P))
            reject(RangeError('P should be string, ArrayBuffer, TypedArray, DataView'));
        if (typeof S === 'string')
            S = new TextEncoder().encode(S); // encode S as UTF-8
        else if (S instanceof ArrayBuffer)
            S = new Uint8Array(S);
        else if (ArrayBuffer.isView(S))
            S = new Uint8Array(S.buffer, S.byteOffset, S.byteLength);
        else
            reject(RangeError('S should be string, ArrayBuffer, TypedArray, DataView'));
        {
            crypto.subtle.importKey('raw', P, 'PBKDF2', false, ['deriveBits']).then((PKey) => {
                const params = { name: 'PBKDF2', hash: hash, salt: S, iterations: c }; // pbkdf2 params
                crypto.subtle.deriveBits(params, PKey, dkLen * 8).then(derivedKey => resolve(derivedKey), 
                // eslint-disable-next-line node/handle-callback-err
                err => {
                    // Try our native implementation if browser's native one fails (firefox one fails when dkLen > 256)
                    _pbkdf2(P, S, c, dkLen, hash).then(derivedKey => resolve(derivedKey), error => reject(error));
                });
            }, err => reject(err));
        }
    });
}
async function _pbkdf2(P, S, c, dkLen, hash) {
    if (!(hash in HASHALGS)) {
        throw new RangeError(`Valid hash algorithm values are any of ${Object.keys(HASHALGS).toString()}`);
    }
    if (!Number.isInteger(c) || c <= 0)
        throw new RangeError('c must be a positive integer');
    /*
     1.  If dkLen > (2^32 - 1) * hLen, output "derived key too long"
             and stop.
     */
    const hLen = HASHALGS[hash].outputLength;
    if (!Number.isInteger(dkLen) || dkLen <= 0 || dkLen >= (2 ** 32 - 1) * hLen)
        throw new RangeError('dkLen must be a positive integer < (2 ** 32 - 1) * hLen');
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
    if (P.byteLength === 0)
        P = new Uint8Array(HASHALGS[hash].blockSize); // HMAC does not accept an empty ArrayVector
    const Pkey = await crypto.subtle.importKey('raw', P, {
        name: 'HMAC',
        hash: { name: hash }
    }, true, ['sign']);
    const HMAC = async function (key, arr) {
        const hmac = await crypto.subtle.sign('HMAC', key, arr);
        return new Uint8Array(hmac);
    };
    for (let i = 0; i < l; i++) {
        T[i] = await F(Pkey, S, c, i + 1);
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
      * @param P - password
      * @param S - salt
      * @param c - iterations
      * @param i - block index
      */
    async function F(P, S, c, i) {
        function INT(i) {
            const buf = new ArrayBuffer(4);
            const view = new DataView(buf);
            view.setUint32(0, i, false);
            return new Uint8Array(buf);
        }
        const Uacc = await HMAC(P, concat(S, INT(i)));
        let UjMinus1 = Uacc;
        for (let j = 1; j < c; j++) {
            UjMinus1 = await HMAC(P, UjMinus1);
            xorMe(Uacc, UjMinus1);
        }
        return Uacc;
    }
    /*
     4.  Concatenate the blocks and extract the first dkLen octets to
         produce a derived key DK:
                   DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
  
     5.  Output the derived key DK.
     */
    T[l - 1] = T[l - 1].slice(0, r);
    return concat(...T).buffer;
}
function concat(...arrs) {
    // sum of individual array lengths
    const totalLength = arrs.reduce((acc, value) => acc + value.length, 0);
    if (arrs.length === 0)
        throw new RangeError('Cannot concat no arrays');
    const result = new Uint8Array(totalLength);
    // for each array - copy it over result
    // next array is copied right after the previous one
    let length = 0;
    for (const array of arrs) {
        result.set(array, length);
        length += array.length;
    }
    return result;
}
function xorMe(arr1, arr2) {
    for (let i = 0; i < arr1.length; i++) {
        arr1[i] ^= arr2[i];
    }
}

export { pbkdf2Hmac as default };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7QUFvQkEsTUFBTSxRQUFRLEdBQWE7SUFDekIsT0FBTyxFQUFFLEVBQUUsWUFBWSxFQUFFLEVBQUUsRUFBRSxTQUFTLEVBQUUsRUFBRSxFQUFFO0lBQzVDLFNBQVMsRUFBRSxFQUFFLFlBQVksRUFBRSxFQUFFLEVBQUUsU0FBUyxFQUFFLEVBQUUsRUFBRTtJQUM5QyxTQUFTLEVBQUUsRUFBRSxZQUFZLEVBQUUsRUFBRSxFQUFFLFNBQVMsRUFBRSxHQUFHLEVBQUU7SUFDL0MsU0FBUyxFQUFFLEVBQUUsWUFBWSxFQUFFLEVBQUUsRUFBRSxTQUFTLEVBQUUsR0FBRyxFQUFFO0NBQ2hELENBQUE7QUFFRDs7Ozs7Ozs7Ozs7O1NBWXdCLFVBQVUsQ0FBRSxDQUErQyxFQUFFLENBQStDLEVBQUUsQ0FBUyxFQUFFLEtBQWEsRUFBRSxPQUFnQixTQUFTO0lBQ3ZMLE9BQU8sSUFBSSxPQUFPLENBQUMsQ0FBQyxPQUFPLEVBQUUsTUFBTTtRQUNqQyxJQUFJLEVBQUUsSUFBSSxJQUFJLFFBQVEsQ0FBQyxFQUFFO1lBQ3ZCLE1BQU0sQ0FBQyxJQUFJLFVBQVUsQ0FBQywwQ0FBMEMsTUFBTSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQyxRQUFRLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQTtTQUNyRztRQUVELElBQUksT0FBTyxDQUFDLEtBQUssUUFBUTtZQUFFLENBQUMsR0FBRyxJQUFJLFdBQVcsRUFBRSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQTthQUNyRCxJQUFJLENBQUMsWUFBWSxXQUFXO1lBQUUsQ0FBQyxHQUFHLElBQUksVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFBO2FBQ25ELElBQUksQ0FBQyxXQUFXLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQztZQUFFLE1B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
