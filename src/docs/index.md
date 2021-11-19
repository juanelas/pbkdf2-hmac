[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
{{GITHUB_ACTIONS_BADGES}}

# {{PKG_NAME}}

PBKDF2 with HMAC (with SHA-1, SHA-256, SHA-384 or SHA-512) as the PRF function for Node.js and browsers.

Node version internally uses Node's `crypto.pbkdf2()`, the browser version defaults to the subtle crypto native implementation, although a custom implementation is provided just in case the native one fails. This is nowadays (Jun, 2020) the case of Firefox, whose [PBKDF2 implementation can't derive more than 2048 bits](https://github.com/mdn/sprints/issues/3278).

## Usage

`{{PKG_NAME}}` can be imported to your project with `npm`:

```console
npm install {{PKG_NAME}}
```

Then either require (Node.js CJS):

```javascript
const {{PKG_CAMELCASE}} = require('{{PKG_NAME}}')
```

or import (JavaScript ES module):

```javascript
import {{PKG_CAMELCASE}} from '{{PKG_NAME}}'
```

The appropriate version for browser or node is automatically exported.

You can also download the {{IIFE_BUNDLE}}, the {{ESM_BUNDLE}} or the {{UMD_BUNDLE}} and manually add it to your project, or, if you have already installed `{{PKG_NAME}}` in your project, just get the bundles from `node_modules/{{PKG_NAME}}/dist/bundles/`.

An example of usage could be:

```typescript
const derivedKey = await {{PKG_CAMELCASE}}('password', 'salt', 1000, 32)
```

See the `test` for more examples.

## API reference documentation

[Check the API](./docs/API.md)
