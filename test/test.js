var
  fs = require('fs'),
  assert = require('assert');

var rsa = require('../rsa');

var plaintext = "The Plaintext";

// Test RSA routines - keypair:
var rsaPublic = fs.readFileSync("rsa.public", 'ascii');
var rsaPrivate = fs.readFileSync("rsa.private", 'ascii');
var passphrase = "foobar";

var params = { publicKey: rsaPublic, privateKey: rsaPrivate, passphrase: passphrase };
var keypair = rsa.createRsaKeypair(params);

// roundtrip via hex encoding
var ciphertext = keypair.encrypt(plaintext, 'utf8', 'hex');
var plaintext_again = keypair.decrypt(ciphertext, 'hex', 'utf8');
assert.equal(plaintext, plaintext_again);

// roundtrip via base64 encoding
var ciphertext = keypair.encrypt(plaintext, 'ascii', 'base64');
var plaintext_again = keypair.decrypt(ciphertext, 'base64', 'ascii');
assert.equal(plaintext, plaintext_again);

// roundtrip via binary
var ciphertext = keypair.encrypt(plaintext, 'utf8', 'binary');
var plaintext_again = keypair.decrypt(ciphertext, 'binary', 'utf8');
assert.equal(plaintext, plaintext_again);

// roundtrip via binary, encryption output encoding unspecified
var ciphertext = keypair.encrypt(plaintext, 'utf8');
var plaintext_again = keypair.decrypt(ciphertext, 'binary', 'utf8');
assert.equal(plaintext, plaintext_again);

// Check getters.
require("./getters").test(rsaPublic, rsaPrivate, passphrase);

console.log("done");
