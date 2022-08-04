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
            const nodeAlg = hash.toLowerCase().replace('-', '');
            import('crypto').then(crypto => {
                crypto.pbkdf2(P, S, c, dkLen, nodeAlg, (err, derivedKey) => {
                    if (err != null)
                        reject(err);
                    else
                        resolve(derivedKey.buffer);
                });
            }).catch(reject);
        }
    });
}

export { pbkdf2Hmac as default };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7OztBQUlHO0FBZ0JILE1BQU0sUUFBUSxHQUFhO0lBQ3pCLE9BQU8sRUFBRSxFQUFFLFlBQVksRUFBRSxFQUFFLEVBQUUsU0FBUyxFQUFFLEVBQUUsRUFBRTtJQUM1QyxTQUFTLEVBQUUsRUFBRSxZQUFZLEVBQUUsRUFBRSxFQUFFLFNBQVMsRUFBRSxFQUFFLEVBQUU7SUFDOUMsU0FBUyxFQUFFLEVBQUUsWUFBWSxFQUFFLEVBQUUsRUFBRSxTQUFTLEVBQUUsR0FBRyxFQUFFO0lBQy9DLFNBQVMsRUFBRSxFQUFFLFlBQVksRUFBRSxFQUFFLEVBQUUsU0FBUyxFQUFFLEdBQUcsRUFBRTtDQUNoRCxDQUFBO0FBRUQ7Ozs7Ozs7Ozs7OztBQVlJO0FBQ29CLFNBQUEsVUFBVSxDQUFFLENBQStDLEVBQUUsQ0FBK0MsRUFBRSxDQUFTLEVBQUUsS0FBYSxFQUFFLE9BQWdCLFNBQVMsRUFBQTtJQUN2TCxPQUFPLElBQUksT0FBTyxDQUFDLENBQUMsT0FBTyxFQUFFLE1BQU0sS0FBSTtBQUNyQyxRQUFBLElBQUksRUFBRSxJQUFJLElBQUksUUFBUSxDQUFDLEVBQUU7QUFDdkIsWUFBQSxNQUFNLENBQUMsSUFBSSxVQUFVLENBQUMsQ0FBQSx1Q0FBQSxFQUEwQyxNQUFNLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDLFFBQVEsRUFBRSxDQUFFLENBQUEsQ0FBQyxDQUFDLENBQUE7QUFDckcsU0FBQTtRQUVELElBQUksT0FBTyxDQUFDLEtBQUssUUFBUTtZQUFFLENBQUMsR0FBRyxJQUFJLFdBQVcsRUFBRSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQTthQUNyRCxJQUFJLENBQUMsWUFBWSxXQUFXO0FBQUUsWUFBQSxDQUFDLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFDbkQsYUFBQSxJQUFJLENBQUMsV0FBVyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7QUFBRSxZQUFBLE1BQU0sQ0FBQyxVQUFVLENBQUMsdURBQXVELENBQUMsQ0FBQyxDQUFBO1FBRTVHLElBQUksT0FBTyxDQUFDLEtBQUssUUFBUTtZQUFFLENBQUMsR0FBRyxJQUFJLFdBQVcsRUFBRSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQTthQUNyRCxJQUFJLENBQUMsWUFBWSxXQUFXO0FBQUUsWUFBQSxDQUFDLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFDbkQsYUFBQSxJQUFJLFdBQVcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDO0FBQUUsWUFBQSxDQUFDLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxDQUFDLE1BQU0sRUFBRSxDQUFDLENBQUMsVUFBVSxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsQ0FBQTs7QUFDbkYsWUFBQSxNQUFNLENBQUMsVUFBVSxDQUFDLHVEQUF1RCxDQUFDLENBQUMsQ0FBQTtBQUVoRixRQWtCTztBQUNMLFlBQUEsTUFBTSxPQUFPLEdBQUcsSUFBSSxDQUFDLFdBQVcsRUFBRSxDQUFDLE9BQU8sQ0FBQyxHQUFHLEVBQUUsRUFBRSxDQUFDLENBQUE7WUFDbkQsT0FBUSxRQUFRLENBQUMsQ0FBQyxJQUFJLENBQUMsTUFBTSxJQUFHO0FBQzlCLGdCQUFBLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBMEIsRUFBRSxDQUFlLEVBQUUsQ0FBQyxFQUFFLEtBQUssRUFBRSxPQUFPLEVBQUUsQ0FBQyxHQUFpQixFQUFFLFVBQWtCLEtBQUk7b0JBQ3RILElBQUksR0FBRyxJQUFJLElBQUk7d0JBQUUsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBOztBQUN2Qix3QkFBQSxPQUFPLENBQUMsVUFBVSxDQUFDLE1BQU0sQ0FBQyxDQUFBO0FBQ2pDLGlCQUFDLENBQUMsQ0FBQTtBQUNKLGFBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsQ0FBQTtBQUNqQixTQUFBO0FBQ0gsS0FBQyxDQUFDLENBQUE7QUFDSjs7OzsifQ==
