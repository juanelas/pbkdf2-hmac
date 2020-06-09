[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
{{GITHUB_ACTIONS_BADGES}}

# {{PKG_NAME}}

PBKDF2 with HMAC (with SHA-1, SHA-256, SHA-384 or SHA-512) as the PRF function for Node.js and browsers.

Node version internally uses Node's `crypto.pbkdf2()`, the browser version defaults to the subtle crypto native implementation, although a custom implementation is provided just in case the native one fails. This is nowadays (Jun, 2020) the case of Firefox, whose [PBKDF2 implementation can't derive more than 2048 bits](https://github.com/mdn/sprints/issues/3278).

## Installation

`{{PKG_NAME}}` can be imported to your project with `npm`:

```bash
npm install {{PKG_NAME}}
```

NPM installation defaults to the ES6 module for browsers and the CJS one for Node.js. For web browsers, you can also directly download the {{IIFE_BUNDLE}} or the {{ESM_BUNDLE}} from the repository.

## Usage examples

Import your module as :

 - Node.js
   ```javascript
   const {{PKG_CAMELCASE}} = require('{{PKG_NAME}}')
   ... // your code here
   ```
 - JavaScript native or TypeScript project (including React and Angular)
   ```javascript
   import {{PKG_CAMELCASE}} from '{{PKG_NAME}}'
   ... // your code here
   ```
 - JavaScript native browser ES module
   ```html
   <script type="module">
      import {{PKG_CAMELCASE}} from 'lib/index.browser.bundle.mod.js'  // Use your actual path to the broser mod bundle
      ... // your code here
    </script>
   ```
 - JavaScript native browser IIFE
   ```html
   <head>
     ...
     <script src="../../lib/index.browser.bundle.iife.js"></script> <!-- Use your actual path to the browser bundle -->
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
const derivedKey = await {{PKG_CAMELCASE}}('password', 'salt', 1000, 32)
```
See the `test` for more examples

## API reference documentation

{{>main}}
