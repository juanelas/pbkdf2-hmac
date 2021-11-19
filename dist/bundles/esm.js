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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXNtLmpzIiwic291cmNlcyI6WyIuLi8uLi9zcmMvdHMvaW5kZXgudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7OztBQW9CQSxNQUFNLFFBQVEsR0FBYTtJQUN6QixPQUFPLEVBQUUsRUFBRSxZQUFZLEVBQUUsRUFBRSxFQUFFLFNBQVMsRUFBRSxFQUFFLEVBQUU7SUFDNUMsU0FBUyxFQUFFLEVBQUUsWUFBWSxFQUFFLEVBQUUsRUFBRSxTQUFTLEVBQUUsRUFBRSxFQUFFO0lBQzlDLFNBQVMsRUFBRSxFQUFFLFlBQVksRUFBRSxFQUFFLEVBQUUsU0FBUyxFQUFFLEdBQUcsRUFBRTtJQUMvQyxTQUFTLEVBQUUsRUFBRSxZQUFZLEVBQUUsRUFBRSxFQUFFLFNBQVMsRUFBRSxHQUFHLEVBQUU7Q0FDaEQsQ0FBQTtBQUVEOzs7Ozs7Ozs7Ozs7U0FZd0IsVUFBVSxDQUFFLENBQStDLEVBQUUsQ0FBK0MsRUFBRSxDQUFTLEVBQUUsS0FBYSxFQUFFLE9BQWdCLFNBQVM7SUFDdkwsT0FBTyxJQUFJLE9BQU8sQ0FBQyxDQUFDLE9BQU8sRUFBRSxNQUFNO1FBQ2pDLElBQUksRUFBRSxJQUFJLElBQUksUUFBUSxDQUFDLEVBQUU7WUFDdkIsTUFBTSxDQUFDLElBQUksVUFBVSxDQUFDLDBDQUEwQyxNQUFNLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDLFFBQVEsRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFBO1NBQ3JHO1FBRUQsSUFBSSxPQUFPLENBQUMsS0FBSyxRQUFRO1lBQUUsQ0FBQyxHQUFHLElBQUksV0FBVyxFQUFFLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFBO2FBQ3JELElBQUksQ0FBQyxZQUFZLFdBQVc7WUFBRSxDQUFDLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxDQUFDLENBQUE7YUFDbkQsSUFBSSxDQUFDLFdBQVcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDO1lBQUUsTUFBTSxDQUFDLFVB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
