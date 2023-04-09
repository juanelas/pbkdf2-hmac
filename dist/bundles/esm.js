const HASHALGS = {
    'SHA-1': { outputLength: 20, blockSize: 64 },
    'SHA-256': { outputLength: 32, blockSize: 64 },
    'SHA-384': { outputLength: 48, blockSize: 128 },
    'SHA-512': { outputLength: 64, blockSize: 128 }
};
function pbkdf2Hmac(P, S, c, dkLen, hash = 'SHA-256') {
    return new Promise((resolve, reject) => {
        if (!(hash in HASHALGS)) {
            reject(new RangeError(`Valid hash algorithm values are any of ${Object.keys(HASHALGS).toString()}`));
        }
        if (typeof P === 'string')
            P = new TextEncoder().encode(P);
        else if (P instanceof ArrayBuffer)
            P = new Uint8Array(P);
        else if (!ArrayBuffer.isView(P))
            reject(RangeError('P should be string, ArrayBuffer, TypedArray, DataView'));
        if (typeof S === 'string')
            S = new TextEncoder().encode(S);
        else if (S instanceof ArrayBuffer)
            S = new Uint8Array(S);
        else if (ArrayBuffer.isView(S))
            S = new Uint8Array(S.buffer, S.byteOffset, S.byteLength);
        else
            reject(RangeError('S should be string, ArrayBuffer, TypedArray, DataView'));
        {
            crypto.subtle.importKey('raw', P, 'PBKDF2', false, ['deriveBits']).then((PKey) => {
                const params = { name: 'PBKDF2', hash, salt: S, iterations: c };
                crypto.subtle.deriveBits(params, PKey, dkLen * 8).then(derivedKey => resolve(derivedKey), err => {
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
    const hLen = HASHALGS[hash].outputLength;
    if (!Number.isInteger(dkLen) || dkLen <= 0 || dkLen >= (2 ** 32 - 1) * hLen)
        throw new RangeError('dkLen must be a positive integer < (2 ** 32 - 1) * hLen');
    const l = Math.ceil(dkLen / hLen);
    const r = dkLen - (l - 1) * hLen;
    const T = new Array(l);
    if (P.byteLength === 0)
        P = new Uint8Array(HASHALGS[hash].blockSize);
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
    T[l - 1] = T[l - 1].slice(0, r);
    return concat(...T).buffer;
}
function concat(...arrs) {
    const totalLength = arrs.reduce((acc, value) => acc + value.length, 0);
    if (arrs.length === 0)
        throw new RangeError('Cannot concat no arrays');
    const result = new Uint8Array(totalLength);
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
