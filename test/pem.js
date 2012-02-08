/*
 * Tests for the PEM-format getters of RsaKeyPair.
 */

var assert = require('assert');
var rsa = require('../rsa');

var thePlaintext = "Muffins are tasty!";

/**
 * Main test function, which takes two key file arguments, each of which is a
 * text file containing a key file, public and private (in that order);
 * and a third passphrase argument, which is the private key's passphrase.
 */
function test(rsaPublic, rsaPrivate, passphrase) {
    var publicKey = rsa.createRsaKeypair({ publicKey: rsaPublic });
    var privateKey = rsa.createRsaKeypair(
        { privateKey: rsaPrivate, passphrase: passphrase });

    testPublic(publicKey, privateKey, "public");
    testPublic(privateKey, privateKey, "private");
    testPrivate(publicKey, privateKey);
}

/**
 * Test that a round trip through PEM doesn't affect the use of the
 * public key.
 */
function testPublic(key1, privateKey, kind) {
    try {
	var pem = key1.getPublicKeyPem();
	var key2 = rsa.createRsaKeypair({ publicKey: pem });
	var enc2 = key2.encrypt(thePlaintext, "utf8", "hex");
	var dec2 = privateKey.decrypt(enc2, "hex", "utf8");
	
	assert.equal(thePlaintext, dec2);
    } catch (ex) {
	console.log("trouble with public PEM for %s key", kind);
	throw ex;
    }
}

/**
 * Test that a round trip through PEM doesn't affect the use of the
 * private key.
 */
function testPrivate(publicKey, key1) {
    var encrypted = publicKey.encrypt(thePlaintext, "utf8", "hex");
    var pem = key1.getPrivateKeyPem();
    var key2 = rsa.createRsaKeypair({ privateKey: pem });
    var dec1 = key1.decrypt(encrypted, "hex", "utf8");
    var dec2 = key2.decrypt(encrypted, "hex", "utf8");

    assert.equal(thePlaintext, dec1);
    assert.equal(thePlaintext, dec2);
}

module.exports = {
    test: test
};
