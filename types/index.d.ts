export default pbkdf2Hmac;
/**
 * A TypedArray object describes an array-like view of an underlying binary data buffer.
 */
export type TypedArray = Int8Array | Uint8Array | Uint8ClampedArray | Int16Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Float64Array | BigInt64Array | BigUint64Array;
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
declare function pbkdf2Hmac(P: string | ArrayBuffer | TypedArray | DataView, S: string | ArrayBuffer | TypedArray | DataView, c: number, dkLen: number, hash?: string): Promise<ArrayBuffer>;
