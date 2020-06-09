[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
[![Node CI](https://github.com/juanelas/pbkdf2-hmac/workflows/Node%20CI/badge.svg)](https://github.com/juanelas/pbkdf2-hmac/actions?query=workflow%3A%22Node+CI%22)
[![Coverage Status](https://coveralls.io/repos/github/juanelas/pbkdf2-hmac/badge.svg?branch=master)](https://coveralls.io/github/juanelas/pbkdf2-hmac?branch=master)

# pbkdf2-hmac

PBKDF2 with HMAC (with SHA-1, SHA-256, SHA-384 or SHA-512) as the PRF function for Node.js and browsers.

Node version internally uses Node's `crypto.pbkdf2()`, the browser version defaults to the subtle crypto native implementation, although a custom implementation is provided just in case the native one fails. This is nowadays (Jun, 2020) the case of Firefox, whose [PBKDF2 implementation can't derive more than 2048 bits](https://github.com/mdn/sprints/issues/3278).

## Installation

`pbkdf2-hmac` can be imported to your project with `npm`:

```bash
npm install pbkdf2-hmac
```

NPM installation defaults to the ES6 module for browsers and the CJS one for Node.js. For web browsers, you can also directly download the [IIFE bundle](https://raw.githubusercontent.com/juanelas/pbkdf2-hmac/master/lib/index.browser.bundle.iife.js) or the [ESM bundle](https://raw.githubusercontent.com/juanelas/pbkdf2-hmac/master/lib/index.browser.bundle.mod.js) from the repository.

## Usage examples

Import your module as :

 - Node.js
   ```javascript
   const pbkdf2Hmac = require('pbkdf2-hmac')
   ... // your code here
   ```
 - JavaScript native or TypeScript project (including React and Angular)
   ```javascript
   import * as pbkdf2Hmac from 'pbkdf2-hmac'
   ... // your code here
   ```
 - JavaScript native browser ES module
   ```html
   <script type="module">
      import * as pbkdf2Hmac from 'lib/index.browser.bundle.mod.js'  // Use you actual path to the broser mod bundle
      ... // your code here
    </script>
   ```
 - JavaScript native browser IIFE
   ```html
   <head>
     ...
     <script src="../../lib/index.browser.bundle.iife.js"></script> <!-- Use you actual path to the browser bundle -->
   </head>
   <body>
     ...
     <script>
       ... // your code here
     </script>
   </body>
   ```

An example of usage could be (from an async function):

```javascript
const derivedKey = await pbkdf2Hmac('password', 'salt', 1000, 32)
```
See the `test` for more examples

## API reference documentation

<a name="module_pbkdf2-hmac"></a>

### pbkdf2-hmac
PBKDF2 following RFC 2898 using HMAC (with SHA-1, SHA-256, SHA-384, SHA-512) as the PRF


* [pbkdf2-hmac](#module_pbkdf2-hmac)
    * [~TypedArray](#module_pbkdf2-hmac..TypedArray) : <code>Int8Array</code> \| <code>Uint8Array</code> \| <code>Uint8ClampedArray</code> \| <code>Int16Array</code> \| <code>Uint16Array</code> \| <code>Int32Array</code> \| <code>Uint32Array</code> \| <code>Float32Array</code> \| <code>Float64Array</code> \| <code>BigInt64Array</code> \| <code>BigUint64Array</code>
    * [~pbkdf2Hmac(P, S, c, dkLen, hash)](#module_pbkdf2-hmac..pbkdf2Hmac) ⇒ <code>Promise.&lt;ArrayBuffer&gt;</code>

<a name="module_pbkdf2-hmac..TypedArray"></a>

#### pbkdf2-hmac~TypedArray : <code>Int8Array</code> \| <code>Uint8Array</code> \| <code>Uint8ClampedArray</code> \| <code>Int16Array</code> \| <code>Uint16Array</code> \| <code>Int32Array</code> \| <code>Uint32Array</code> \| <code>Float32Array</code> \| <code>Float64Array</code> \| <code>BigInt64Array</code> \| <code>BigUint64Array</code>
A TypedArray object describes an array-like view of an underlying binary data buffer.

**Kind**: inner typedef of [<code>pbkdf2-hmac</code>](#module_pbkdf2-hmac)  
<a name="module_pbkdf2-hmac..pbkdf2Hmac"></a>

#### pbkdf2-hmac~pbkdf2Hmac(P, S, c, dkLen, hash) ⇒ <code>Promise.&lt;ArrayBuffer&gt;</code>
The PBKDF2-HMAC function used below denotes the PBKDF2 algorithm (RFC2898)
used with one of the SHA algorithms as the hash function for the HMAC

**Kind**: inner method of [<code>pbkdf2-hmac</code>](#module_pbkdf2-hmac)  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| P | <code>string</code> \| <code>ArrayBuffer</code> \| <code>TypedArray</code> \| <code>DataView</code> |  | A unicode string with a password |
| S | <code>string</code> \| <code>ArrayBuffer</code> \| <code>TypedArray</code> \| <code>DataView</code> |  | A salt. This should be a random or pseudo-random value of at least 16 bytes. You can easily get one with crypto.getRandomValues(new Uint8Array(16)) |
| c | <code>number</code> |  | iteration count, a positive integer |
| dkLen | <code>number</code> |  | intended length in octets of the derived key |
| hash | <code>string</code> | <code>&quot;SHA-256&quot;</code> | hash function to use for the HMAC. One of 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512' |

