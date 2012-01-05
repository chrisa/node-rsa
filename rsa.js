// load core crypto to get OpenSSL initialized
var crypto = require('crypto');

try {
    var binding = require('./rsaBinding');
    var RsaKeypair = binding.RsaKeypair;
    var rsa = true;
} catch (e) {
    var rsa = false;
}

exports.RsaKeypair = RsaKeypair;
exports.createRsaKeypair = function(keys) {
    var k = new RsaKeypair();

    if (keys.publicKey) {
	k.setPublicKey(keys.publicKey);
    }
    
    if (keys.privateKey) {
	if (keys.passphrase) {
	    k.setPrivateKey(keys.privateKey, keys.passphrase);
	}
	else {
	    k.setPrivateKey(keys.privateKey);
	}
    }

    return k;
}
