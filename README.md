[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
[![Node.js CI](https://github.com/juanelas/pbkdf2-hmac/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/juanelas/pbkdf2-hmac/actions/workflows/build-and-test.yml)
[![Coverage Status](https://coveralls.io/repos/github/juanelas/pbkdf2-hmac/badge.svg?branch=main)](https://coveralls.io/github/juanelas/pbkdf2-hmac?branch=main)

# pbkdf2-hmac

PBKDF2 with HMAC (with SHA-1, SHA-256, SHA-384 or SHA-512) as the PRF function for Node.js and browsers.

Node version internally uses Node's `crypto.pbkdf2()`, the browser version defaults to the subtle crypto native implementation, although a custom implementation is provided just in case the native one fails. This is nowadays (Jun, 2020) the case of Firefox, whose [PBKDF2 implementation can't derive more than 2048 bits](https://github.com/mdn/sprints/issues/3278).

## Usage

`pbkdf2-hmac` can be imported to your project with `npm`:

```console
npm install pbkdf2-hmac
```

Then either require (Node.js CJS):

```javascript
const pbkdf2Hmac = require('pbkdf2-hmac')
```

or import (JavaScript ES module):

```javascript
import pbkdf2Hmac from 'pbkdf2-hmac'
```

The appropriate version for browser or node is automatically exported.

You can also download the [IIFE bundle](https://raw.githubusercontent.com/juanelas/pbkdf2-hmac/main/dist/bundle.iife.js), the [ESM bundle](https://raw.githubusercontent.com/juanelas/pbkdf2-hmac/main/dist/bundle.esm.min.js) or the [UMD bundle](https://raw.githubusercontent.com/juanelas/pbkdf2-hmac/main/dist/bundle.umd.js) and manually add it to your project, or, if you have already installed `pbkdf2-hmac` in your project, just get the bundles from `node_modules/pbkdf2-hmac/dist/bundles/`.

An example of usage could be:

```typescript
const derivedKey = await pbkdf2Hmac('password', 'salt', 1000, 32)
```

See the `test` for more examples.

## API reference documentation

[Check the API](./docs/API.md)
