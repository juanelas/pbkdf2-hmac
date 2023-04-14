# pbkdf2-hmac - v1.2.1

PBKDF2 following RFC 2898 using HMAC (with SHA-1, SHA-256, SHA-384, SHA-512) as the PRF

## Table of contents

### Type Aliases

- [HashAlg](API.md#hashalg)

### Functions

- [default](API.md#default)

## Type Aliases

### HashAlg

Ƭ **HashAlg**: ``"SHA-1"`` \| ``"SHA-256"`` \| ``"SHA-384"`` \| ``"SHA-512"``

#### Defined in

[index.ts:12](https://github.com/juanelas/pbkdf2-hmac/blob/0a82e88/src/ts/index.ts#L12)

## Functions

### default

▸ **default**(`P`, `S`, `c`, `dkLen`, `hash?`): `Promise`<`ArrayBuffer`\>

Derives a key using using PBKDF2-HMAC algorithm
PBKDF2 (RFC 2898) using HMAC (with SHA-1, SHA-256, SHA-384, SHA-512) as
the PRF (RFC2898)

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `P` | `string` \| `TypedArray` \| `ArrayBuffer` \| `DataView` | `undefined` | a unicode string with a password |
| `S` | `string` \| `TypedArray` \| `ArrayBuffer` \| `DataView` | `undefined` | a salt. This should be a random or pseudo-random value of at least 16 bytes. You can easily get one with crypto.getRandomValues(new Uint8Array(16)) |
| `c` | `number` | `undefined` | iteration count, a positive integer |
| `dkLen` | `number` | `undefined` | intended length in octets of the derived key |
| `hash` | [`HashAlg`](API.md#hashalg) | `'SHA-256'` | hash function to use for the HMAC. One of 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512' |

#### Returns

`Promise`<`ArrayBuffer`\>

an ArrayBuffer with the derived key

#### Defined in

[index.ts:41](https://github.com/juanelas/pbkdf2-hmac/blob/0a82e88/src/ts/index.ts#L41)
