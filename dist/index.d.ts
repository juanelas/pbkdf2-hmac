type TypedArray = Int8Array | Uint8Array | Uint8ClampedArray | Int16Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Float64Array | BigInt64Array | BigUint64Array;
type HashAlg = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
declare function pbkdf2Hmac(P: string | ArrayBuffer | TypedArray | DataView, S: string | ArrayBuffer | TypedArray | DataView, c: number, dkLen: number, hash?: HashAlg): Promise<ArrayBuffer>;

export { HashAlg, pbkdf2Hmac as default };
