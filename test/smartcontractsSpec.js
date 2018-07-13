const expect = require("chai").expect;
const sc = require("../lib/smartcontracts");
const cc = require('five-bells-condition');

describe("SmartContracts", function(){
    describe("#generateKeys()", function(){
        it("should generate Pub/Priv keys", function(){

            let keyPair = sc.generateKeys();
            // console.log("Keys: %s \n%s", keyPair.publicKey.toString("hex"), 
            //     keyPair.privateKey.toString("hex"));
            expect(keyPair).to.have.a.property("publicKey");
            expect(keyPair).to.have.a.property("privateKey");
        });

        it("Ed25519Sha256 condition", function(){
            let msg = Buffer.from('dados enviados');

            let keyPair = sc.generateKeys();
            const ed25519_ff = new cc.Ed25519Sha256();
            ed25519_ff.sign(msg, keyPair.privateKey);
            console.log("condition: %s",ed25519_ff.getConditionUri());
            console.log("fulfillment: %s",ed25519_ff.serializeUri());

            expect(keyPair).to.have.a.property("publicKey");
            expect(keyPair).to.have.a.property("privateKey");
        });
    }); 
});