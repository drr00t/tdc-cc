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
            const msg = Buffer.from('dados enviados');
            const msg2 = Buffer.from('dados enviados diferentes');

            let keyPair = sc.generateKeys();
            const ed25519_ff = new cc.Ed25519Sha256();
            ed25519_ff.sign(msg, keyPair.privateKey);
            const valid = ed25519_ff.validate(msg);

            console.log("condition: %s",ed25519_ff.getConditionUri());
            console.log("fulfillment: %s",ed25519_ff.serializeUri());
            console.log("fulfillment validate the condition: %s", ed25519_ff.validate(msg));

            expect(keyPair).to.have.a.property("publicKey");
            expect(keyPair).to.have.a.property("privateKey");
            expect(ed25519_ff.validate(msg)).to.be.true;
            expect(()=> {return ed25519_ff.validate(msg2)}).to.throw();
           
        });

        it("THRESHOLD-SHA-256", function(){
            const msg1 = Buffer.from('dados enviados');
            const msg2 = Buffer.from('dados enviados diferentes');

            let keyPair1 = sc.generateKeys();
            let keyPair2 = sc.generateKeys();

            const ed25519_ff_1 = new cc.Ed25519Sha256();
            const ed25519_ff_2 = new cc.Ed25519Sha256();

            ed25519_ff_1.sign(msg1, keyPair1.privateKey);
            ed25519_ff_2.sign(msg1, keyPair2.privateKey);

            const ok_threshold_ff_t1 = new cc.ThresholdSha256();
            ok_threshold_ff_t1.addSubfulfillmentUri(ed25519_ff_1.serializeUri());
            ok_threshold_ff_t1.setThreshold(1);

            console.log("condition: %s",ok_threshold_ff_t1.getConditionUri());
            console.log("fulfillment: %s",ok_threshold_ff_t1.serializeUri());

            expect(ok_threshold_ff_t1.validate(msg1)).to.be.true;
            expect(()=> {return ok_threshold_ff_t1.validate(msg2);}).to.throw();

            // ====================================================================

            const ok_threshold_ff_t2 = new cc.ThresholdSha256();
            ok_threshold_ff_t2.addSubfulfillmentUri(ed25519_ff_1.serializeUri());
            ok_threshold_ff_t2.addSubfulfillmentUri(ed25519_ff_2.serializeUri());
            ok_threshold_ff_t2.setThreshold(2);

            console.log("condition: %s",ok_threshold_ff_t2.getConditionUri());
            console.log("fulfillment: %s",ok_threshold_ff_t2.serializeUri());

            expect(ok_threshold_ff_t2.validate(msg1)).to.be.true;
            expect(()=> {return ok_threshold_ff_t2.validate(msg2);}).to.throw();
        });
    }); 
});