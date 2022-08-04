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
  * Derives a key using using PBKDF2-HMAC algorithm
  * PBKDF2 (RFC 2898) using HMAC (with SHA-1, SHA-256, SHA-384, SHA-512) as
  * the PRF (RFC2898)
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7OztBQUlHO0FBZ0JILE1BQU0sUUFBUSxHQUFhO0lBQ3pCLE9BQU8sRUFBRSxFQUFFLFlBQVksRUFBRSxFQUFFLEVBQUUsU0FBUyxFQUFFLEVBQUUsRUFBRTtJQUM1QyxTQUFTLEVBQUUsRUFBRSxZQUFZLEVBQUUsRUFBRSxFQUFFLFNBQVMsRUFBRSxFQUFFLEVBQUU7SUFDOUMsU0FBUyxFQUFFLEVBQUUsWUFBWSxFQUFFLEVBQUUsRUFBRSxTQUFTLEVBQUUsR0FBRyxFQUFFO0lBQy9DLFNBQVMsRUFBRSxFQUFFLFlBQVksRUFBRSxFQUFFLEVBQUUsU0FBUyxFQUFFLEdBQUcsRUFBRTtDQUNoRCxDQUFBO0FBRUQ7Ozs7Ozs7Ozs7OztBQVlJO0FBQ29CLFNBQUEsVUFBVSxDQUFFLENBQStDLEVBQUUsQ0FBK0MsRUFBRSxDQUFTLEVBQUUsS0FBYSxFQUFFLE9BQWdCLFNBQVMsRUFBQTtJQUN2TCxPQUFPLElBQUksT0FBTyxDQUFDLENBQUMsT0FBTyxFQUFFLE1BQU0sS0FBSTtBQUNyQyxRQUFBLElBQUksRUFBRSxJQUFJLElBQUksUUFBUSxDQUFDLEVBQUU7QUFDdkIsWUFBQSxNQUFNLENBQUMsSUFBSSxVQUFVLENBQUMsQ0FBQSx1Q0FBQSxFQUEwQyxNQUFNLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDLFFBQVEsRUFBRSxDQUFFLENBQUEsQ0FBQyxDQUFDLENBQUE7QUFDckcsU0FBQTtRQUVELElBQUksT0FBTyxDQUFDLEtBQUssUUFBUTtZQUFFLENBQUMsR0FBRyxJQUFJLFdBQVcsRUFBRSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQTthQUNyRCxJQUFJLENBQUMsWUFBWSxXQUFXO0FBQUUsWUFBQSxDQUFDLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxDQUFD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
