const expect = require("chai").expect;
const nacl = require("tweetnacl");
const sc = require("../lib/smartcontracts");
const cc = require('five-bells-condition');

describe("SmartContracts ::", ()=>{
    describe("Conditions Types ::", ()=>{
        it("Must have publicKey and signature properties", ()=>{
            const keySize = 32;
            let privKey = Buffer.from(nacl.randomBytes(keySize));
            const ed25519_ff = new cc.Ed25519Sha256();
            const msg = Buffer.from('');
            ed25519_ff.sign(msg,privKey);
            // console.log("Keys: %s \n%s", keyPair.publicKey.toString("hex"), 
            //     keyPair.privateKey.toString("hex"));
            expect(ed25519_ff).to.have.a.property("publicKey");
            expect(ed25519_ff).to.have.a.property("signature");
        });

        it("Ed25519Sha256 condition", () => {
            const msg = Buffer.from('dados enviados');
            const msg2 = Buffer.from('dados enviados diferentes');

            const keySize = 32;
            let privKey = Buffer.from(nacl.randomBytes(keySize));

            const ed25519_ff = new cc.Ed25519Sha256();
            ed25519_ff.sign(msg, privKey);
            const valid = ed25519_ff.validate(msg);

            // console.log("condition: %s",ed25519_ff.getConditionUri());
            // console.log("fulfillment: %s",ed25519_ff.serializeUri());
            // console.log("fulfillment validate the condition: %s", valid);

            expect(ed25519_ff.validate(msg)).to.be.true;
            expect(()=> {return ed25519_ff.validate(msg2)}).to.throw();
           
        });

        it("THRESHOLD-SHA-256 - Multiassinaturas", ()=>{
            const msg1 = Buffer.from('dados enviados');
            const msg2 = Buffer.from('dados enviados diferentes');

            const keySize = 32;
            let privKey1 = Buffer.from(nacl.randomBytes(keySize));
            let privKey2 = Buffer.from(nacl.randomBytes(keySize));

            const ed25519_ff_1 = new cc.Ed25519Sha256();
            const ed25519_ff_2 = new cc.Ed25519Sha256();

            ed25519_ff_1.sign(msg1, privKey1);
            ed25519_ff_2.sign(msg1, privKey2);

            const ok_threshold_ff_t1 = new cc.ThresholdSha256();
            ok_threshold_ff_t1.addSubfulfillmentUri(ed25519_ff_1.serializeUri());
            ok_threshold_ff_t1.addSubfulfillmentUri(ed25519_ff_2.serializeUri());
            ok_threshold_ff_t1.setThreshold(1);

            const ok_threshold_ff_t2 = new cc.ThresholdSha256();
            ok_threshold_ff_t2.addSubfulfillmentUri(ed25519_ff_1.serializeUri());
            ok_threshold_ff_t2.addSubfulfillmentUri(ed25519_ff_2.serializeUri());
            ok_threshold_ff_t2.setThreshold(2);

            // console.log("condition: %s",ok_threshold_ff_t1.getConditionUri());
            // console.log("fulfillment: %s",ok_threshold_ff_t1.serializeUri());

            // console.log("condition: %s",ok_threshold_ff_t2.getConditionUri());
            // console.log("fulfillment: %s",ok_threshold_ff_t2.serializeUri());

            expect(ok_threshold_ff_t2.validate(msg1)).to.be.true;
            expect(()=> {return ok_threshold_ff_t1.validate(msg1);}).to.throw();
            expect(()=> {return ok_threshold_ff_t1.validate(msg2);}).to.throw();
            expect(()=> {return ok_threshold_ff_t2.validate(msg2);}).to.throw();

        });

        it("THRESHOLD-SHA-256 - Multiassinaturas multi-nível", ()=>{
            const msg1 = Buffer.from('dados enviados');
            const msg2 = Buffer.from('dados enviados diferentes');

            const keySize = 32;
            let privKey1 = Buffer.from(nacl.randomBytes(keySize));
            let privKey2 = Buffer.from(nacl.randomBytes(keySize));

            const ed25519_ff_1 = new cc.Ed25519Sha256();
            const ed25519_ff_2 = new cc.Ed25519Sha256();
            const ed25519_ff_3 = new cc.Ed25519Sha256();
            
            const sub_threshold_ff = new cc.ThresholdSha256();
            ed25519_ff_3.sign(msg1, privKey1);

            sub_threshold_ff.addSubfulfillmentUri(ed25519_ff_3.serializeUri());
            sub_threshold_ff.setThreshold(1);


            ed25519_ff_1.sign(msg1, privKey1);
            ed25519_ff_2.sign(msg1, privKey2);

            const ok_threshold_ff_t1 = new cc.ThresholdSha256();
            ok_threshold_ff_t1.addSubfulfillmentUri(ed25519_ff_1.serializeUri());
            ok_threshold_ff_t1.addSubfulfillmentUri(sub_threshold_ff.serializeUri());
            ok_threshold_ff_t1.setThreshold(2);

            // console.log("condition: %s",ok_threshold_ff_t1.getConditionUri());
            // console.log("fulfillment: %s",ok_threshold_ff_t1.serializeUri());

            expect(ok_threshold_ff_t1.validate(msg1)).to.be.true;
            expect(()=> {return ok_threshold_ff_t1.validate(msg2);}).to.throw();

            // ====================================================================

            const ok_threshold_ff_t2 = new cc.ThresholdSha256();
            ok_threshold_ff_t2.addSubfulfillmentUri(ed25519_ff_1.serializeUri());
            ok_threshold_ff_t2.addSubfulfillmentUri(ed25519_ff_2.serializeUri());
            ok_threshold_ff_t2.setThreshold(2);

            // console.log("condition: %s",ok_threshold_ff_t2.getConditionUri());
            // console.log("fulfillment: %s",ok_threshold_ff_t2.serializeUri());

            expect(ok_threshold_ff_t2.validate(msg1)).to.be.true;
            expect(()=> {return ok_threshold_ff_t2.validate(msg2);}).to.throw();
        });

        it("PREFIX-SHA-256 - assinatura com escopo", ()=>{
            const msg1 = Buffer.from('dados enviados');
            const msg2 = Buffer.from('dados enviados diferentes');

            const keySize = 32;
            let privKey1 = Buffer.from(nacl.randomBytes(keySize));

            const ed25519_ff_1 = new cc.Ed25519Sha256();

            ed25519_ff_1.sign(Buffer.concat([Buffer.from('PASSO UM:'), msg1]), privKey1);

            const prefix_ff_t1 = new cc.PrefixSha256();
            prefix_ff_t1.setPrefix(Buffer.from('PASSO UM:'))
            prefix_ff_t1.setSubfulfillmentUri(ed25519_ff_1.serializeUri());
            prefix_ff_t1.setMaxMessageLength(900);

            const prefix_ff_t2 = new cc.PrefixSha256();
            prefix_ff_t2.setPrefix(Buffer.from('PASSO DOIS:'))
            prefix_ff_t2.setSubfulfillmentUri(ed25519_ff_1.serializeUri());
            prefix_ff_t2.setMaxMessageLength(1000);
            
            // ====================================================================

            // console.log("condition: %s",ok_threshold_ff_t2.getConditionUri());
            // console.log("fulfillment: %s",ok_threshold_ff_t2.serializeUri());
            
            expect(prefix_ff_t1.validate(msg1)).to.be.true;
            expect(()=> {return prefix_ff_t2.validate(msg1);}).to.throw();
        });

        it("PREFIX-SHA-256 - Multiassinaturas com escopo", ()=>{
            const msg1 = Buffer.from('dados enviados');
            const msg2 = Buffer.from('dados enviados diferentes');
            const prefix1 = Buffer.from('PASSO UM:');
            const prefix2 = Buffer.from('PASSO DOIS:');

            const keySize = 32;
            let privKey1 = Buffer.from(nacl.randomBytes(keySize));

            const ed25519_ff_1 = new cc.Ed25519Sha256();
            const ed25519_ff_2 = new cc.Ed25519Sha256();

            ed25519_ff_1.sign(Buffer.concat([ prefix1, msg1]), privKey1);
            ed25519_ff_2.sign(Buffer.concat([ prefix2, msg2]), privKey1);

            const prefix_ff_t1 = new cc.PrefixSha256();
            prefix_ff_t1.setPrefix( prefix1);
            prefix_ff_t1.setSubfulfillmentUri(ed25519_ff_1.serializeUri());
            prefix_ff_t1.setMaxMessageLength(100);

            const prefix_ff_t2 = new cc.PrefixSha256();
            prefix_ff_t2.setPrefix( prefix2);
            prefix_ff_t2.setSubfulfillmentUri(ed25519_ff_2.serializeUri());
            prefix_ff_t2.setMaxMessageLength(100);
            
            // ====================================================================

            const threshold_ff_t1 = new cc.ThresholdSha256();
            threshold_ff_t1.addSubfulfillmentUri(prefix_ff_t1.serializeUri());
            threshold_ff_t1.setThreshold(1);

            const threshold_ff_t2 = new cc.ThresholdSha256();
            threshold_ff_t2.addSubfulfillmentUri(prefix_ff_t2.serializeUri());
            threshold_ff_t2.setThreshold(1);
            
            const threshold_ff = new cc.ThresholdSha256();
            threshold_ff.addSubfulfillmentUri(threshold_ff_t1.serializeUri());
            // threshold_ff.addSubfulfillmentUri(threshold_ff_t2.serializeUri());
            threshold_ff.setThreshold(1);

            // console.log("condition: %s",ok_threshold_ff_t2.getConditionUri());
            // console.log("fulfillment: %s",ok_threshold_ff_t2.serializeUri());
            
            expect(threshold_ff.validate(msg1)).to.be.true;
            // expect(threshold_ff.validate(msg2)).to.be.true;
            expect(()=> {return threshold_ff.validate(msg2);}).to.throw();

            // expect(ok_threshold_ff_t2.validate(msg1)).to.be.true;
            // expect(ok_threshold_ff_t2.validate(msg2)).to.be.true;

        });
    }); 
});