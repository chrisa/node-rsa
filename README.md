# node-rsa

This module provides access to RSA public-key routines from OpenSSL.

Support is limited to RSAES-OAEP and encryption with a public key,
decryption with a private key.

## Building

This module may be installed using npm:

$ npm install rsa

or may be built manually:

$ node-waf configure build

The tests may be run in a checkout directly, once the module is built:

$ node test/test.js

## Usage

See test/test.js.

## Licence

BSD, see LICENCE.
