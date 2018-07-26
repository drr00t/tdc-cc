const nacl = require("tweetnacl");
const seedLength = 32;;
exports = module.exports = {};
 
exports.generateKeys = function() {
    let keys = nacl.box.keyPair();
    return {
            privateKey: Buffer.from(keys.secretKey),
            publicKey: Buffer.from(keys.publicKey)
        }
}