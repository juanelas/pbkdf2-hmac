# pbkdf2-hmac - v1.0.2

PBKDF2 following RFC 2898 using HMAC (with SHA-1, SHA-256, SHA-384, SHA-512) as the PRF

## Table of contents

### Type aliases

- [HashAlg](API.md#hashalg)

### Functions

- [default](API.md#default)

## Type aliases

### HashAlg

Ƭ **HashAlg**: ``"SHA-1"`` \| ``"SHA-256"`` \| ``"SHA-384"`` \| ``"SHA-512"``

#### Defined in

[index.ts:12](https://github.com/juanelas/pbkdf2-hmac/blob/f409af3/src/ts/index.ts#L12)

## Functions

### default

▸ **default**(`P`, `S`, `c`, `dkLen`, `hash?`): `Promise`<`ArrayBuffer`\>

The PBKDF2-HMAC function used below denotes the PBKDF2 algorithm (RFC2898)
used with one of the SHA algorithms as the hash function for the HMAC

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `P` | `string` \| `ArrayBuffer` \| `TypedArray` \| `DataView` | `undefined` | a unicode string with a password |
| `S` | `string` \| `ArrayBuffer` \| `TypedArray` \| `DataView` | `undefined` | a salt. This should be a random or pseudo-random value of at least 16 bytes. You can easily get one with crypto.getRandomValues(new Uint8Array(16)) |
| `c` | `number` | `undefined` | iteration count, a positive integer |
| `dkLen` | `number` | `undefined` | intended length in octets of the derived key |
| `hash` | [`HashAlg`](API.md#hashalg) | `'SHA-256'` | hash function to use for the HMAC. One of 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512' |

#### Returns

`Promise`<`ArrayBuffer`\>

an ArrayBuffer with the derived key

#### Defined in

[index.ts:40](https://github.com/juanelas/pbkdf2-hmac/blob/f409af3/src/ts/index.ts#L40)
