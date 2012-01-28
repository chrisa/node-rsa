/*
 * Tests for the getters of RsaKeyPair.
 */

var assert = require('assert');
var rsa = require('../rsa');

/** the expected modulus, as a hex string */
var expectedModulus =
    "d77271ebada824af8294e5c227e51911a98b3936a788e885f308776acc787baa" +
    "ec218e03cb93f3f058f38d31015842e1a1c647604c6218ff7b8d04041e1bd177" +
    "529d38cf30784b9efded16877887429eb222c02ceb2de2822912e894ae0e7b82" +
    "92dc2371773a2af0ebe60a012823effc9e7aea7c4bcfeae2d3c0cabb43ff71cc" +
    "019f5ecabb6cb5e0b5941810f522dd82b8b84b1180e3965606a3f86ebb705f6a" +
    "892897d960380a3bfc1da8d669d60b06691634d359f2fdb30373391c828e55d4" +
    "83b853e293a8f6b4341fff6478ad90ac4b8f94032c728aa6c47498171d87e4cf" +
    "daa3c7f7a1e43f8a57bfc2f8cf2a9259dd02fdf2e538575c8362b7018e1c0ef7";

/** the expected exponent, as a hex string */
var expectedExponent = "010001";

/**
 * Main test function, which takes two key file arguments, each of which is a
 * text file containing a key file, public and private (in that order);
 * and a third passphrase argument, which is the private key's passphrase.
 */
function test(rsaPublic, rsaPrivate, passphrase) {
    var publicKey = rsa.createRsaKeypair({ publicKey: rsaPublic });
    testGetters(publicKey, "public");

    var privateKey = rsa.createRsaKeypair(
        { privateKey: rsaPrivate, passphrase: passphrase });
    testGetters(privateKey, "private");
}

/**
 * Test getting the components of a key.
 */
function testGetters(key, kind) {
    try {
	testCombo(key, kind, "modulus",  "binary", expectedModulus);
	testCombo(key, kind, "exponent", "binary", expectedExponent);
	testCombo(key, kind, "modulus",  "base64", expectedModulus);
	testCombo(key, kind, "exponent", "base64", expectedExponent);
	testCombo(key, kind, "modulus",  "hex",    expectedModulus);
	testCombo(key, kind, "exponent", "hex",    expectedExponent);
    } catch (ex) {
	console.log("trouble with %s key getter", kind);
	throw ex;
    }
}

function testCombo(key, kind, which, encoding, expected) {
    var raw = doGet(key, kind, which, encoding);
    var hex = new Buffer(raw, encoding).toString("hex");

    try {
	assert.equal(hex, expected);
    } catch (ex) {
	console.log("while checking %s of %s key, in %s encoding",
		    which, kind, encoding);
	throw ex;
    }
}

/**
 * Get the given field of the given key in the given encoding.
 */
function doGet(key, kind, which, encoding) {
    try {
	if (which === "modulus") {
	    return key.getModulus(encoding);
	} else {
	    return key.getExponent(encoding);
	}
    } catch (ex) {
	console.log("trouble getting %s of %s key, in %s encoding",
                    which, kind, encoding);
	throw ex;
    }
}

/**
 * Test getting the components of a private key.
 */
function testPrivate(key) {
}

module.exports = {
    test: test
};
