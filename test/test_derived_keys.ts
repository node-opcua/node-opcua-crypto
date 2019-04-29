import * as should from "should";
import * as crypto_utils from "..";
import {ComputeDerivedKeysOptions} from "..";

import * as loremIpsum1 from "lorem-ipsum";
const loremIpsum = (loremIpsum1 as any).loremIpsum({count: 100});

// tslint:disable-next-line:unused-constant
const should_ = should;

const makePseudoRandomBuffer = crypto_utils.makePseudoRandomBuffer;

loremIpsum.length.should.be.greaterThan(100);

function make_lorem_ipsum_buffer(): Buffer {
    return Buffer.from(loremIpsum);
}

describe("test derived key making", function () {

    const secret = Buffer.from("my secret");
    const seed = Buffer.from("my seed");

    const options_AES_128_CBC: ComputeDerivedKeysOptions = {
        signingKeyLength: 128,
        encryptingKeyLength: 16,
        encryptingBlockSize: 16,
        signatureLength: 20,
        algorithm: "aes-128-cbc",
        sha1or256: "SHA1"
    };
    const options_AES_256_CBC: ComputeDerivedKeysOptions = {
        signingKeyLength: 256,
        encryptingKeyLength: 32,
        encryptingBlockSize: 16,
        signatureLength: 20,
        algorithm: "aes-256-cbc",
        sha1or256: "SHA1"
    };
    const options_AES_256_CBC_SHA256: ComputeDerivedKeysOptions = {
        signingKeyLength: 256,
        encryptingKeyLength: 32,
        encryptingBlockSize: 16,
        signatureLength: 32,
        algorithm: "aes-256-cbc",
        sha1or256: "SHA256"
    };

    it("should create a large enough p_HASH buffer (makePseudoRandomBuffer) - SHA1", function () {

        const min_length = 256;
        const buf = makePseudoRandomBuffer(secret, seed, min_length, "SHA1");
        buf.length.should.be.equal(min_length);
        //xx console.log(hexDump(buf));
    });

    it("should create a large enough p_HASH buffer (makePseudoRandomBuffer) - SHA256", function () {

        const min_length = 256;
        const buf = makePseudoRandomBuffer(secret, seed, min_length, "SHA256");
        buf.length.should.be.equal(min_length);
        //xx console.log(hexDump(buf));
    });

    function perform_symmetric_encryption_test(options: any, done: (err?: Error | null) => void) {

        const derivedKeys = crypto_utils.computeDerivedKeys(secret, seed, options);

        derivedKeys.should.have.ownProperty("sha1or256");
        derivedKeys.sha1or256.should.eql(options.sha1or256);

        const clear_message = make_lorem_ipsum_buffer();
        //xx Buffer.concat([make_lorem_ipsum_buffer(),make_lorem_ipsum_buffer(),make_lorem_ipsum_buffer()]);
        //xx clear_message = Buffer.concat([clear_message,clear_message,clear_message,clear_message,clear_message]);

        // append padding
        const footer = crypto_utils.computePaddingFooter(clear_message, derivedKeys);
        const clear_message_with_padding = Buffer.concat([clear_message, footer]);

        const msg = "clear_message length " + clear_message_with_padding.length + " shall be a multiple of block size=" + options.encryptingBlockSize;
        (clear_message_with_padding.length % options.encryptingBlockSize).should.equal(0, msg);

        const encrypted_message = crypto_utils.encryptBufferWithDerivedKeys(clear_message_with_padding, derivedKeys);

        clear_message_with_padding.length.should.equal(encrypted_message.length);

        let reconstructed_message = crypto_utils.decryptBufferWithDerivedKeys(encrypted_message, derivedKeys);

        reconstructed_message = crypto_utils.removePadding(reconstructed_message);

        reconstructed_message.toString("ascii").should.eql(clear_message.toString("ascii"));

        done();

    }

    it("demonstrating how to use derived keys for symmetric encryption (aes-128-cbc)", (done) => {
        perform_symmetric_encryption_test(options_AES_128_CBC, done);
    });

    it("demonstrating how to use derived keys for symmetric encryption (aes-256-cbc) - SHA1", (done) => {
        perform_symmetric_encryption_test(options_AES_256_CBC, done);
    });

    it("demonstrating how to use derived keys for symmetric encryption (aes-256-cbc) - SHA256", (done) => {
        perform_symmetric_encryption_test(options_AES_256_CBC_SHA256, done);
    });

    it("should produce a smaller buffer (reduceLength)", function () {

        const buffer = Buffer.from("Hello World", "ascii");
        const reduced = crypto_utils.reduceLength(buffer, 6);
        reduced.toString("ascii").should.equal("Hello");

    });

    function test_verifyChunkSignatureWithDerivedKeys(options: any) {
        const derivedKeys = crypto_utils.computeDerivedKeys(secret, seed, options);

        const clear_message = make_lorem_ipsum_buffer();
        //xx console.log(clear_message.toString());

        const signature = crypto_utils.makeMessageChunkSignatureWithDerivedKeys(clear_message, derivedKeys);

        signature.length.should.eql(derivedKeys.signatureLength);

        const signed_message = Buffer.concat([clear_message, signature]);

        crypto_utils.verifyChunkSignatureWithDerivedKeys(signed_message, derivedKeys).should.equal(true);

        // let's corrupt the message ...
        signed_message.write("HELLO", 0x50);

        // ... and verify that signature verification returns a failure
        crypto_utils.verifyChunkSignatureWithDerivedKeys(signed_message, derivedKeys).should.equal(false);
    }

    it("demonstrating how to use derived keys for signature - AES_128_CBC", function () {
        test_verifyChunkSignatureWithDerivedKeys(options_AES_128_CBC);
    });
    it("demonstrating how to use derived keys for signature - AES_256_CBC", function () {
        test_verifyChunkSignatureWithDerivedKeys(options_AES_256_CBC);
    });
    it("demonstrating how to use derived keys for signature - AES_256_CBC_SHA256", function () {
        test_verifyChunkSignatureWithDerivedKeys(options_AES_256_CBC_SHA256);
    });

    it("should compute key using keysize, client and server keys.", function (done) {
        // see https://github.com/leandrob/node-psha1/blob/master/test/lib.index.js#L4
        const secret1 = Buffer.from("GS5olVevYMI4vW1Df/7FUpHcJJopTszp6sodlK4/rP8=", "base64");
        const seed1 = Buffer.from("LmF9Mjf9lYMa9YkxZDjaRFe6iMAfReKjzhLHDx376jA=", "base64");
        const key = crypto_utils.makePseudoRandomBuffer(secret1, seed1, 256 / 8, "SHA1");
        key.toString("base64").should.eql("ZMOP1NFa5VKTQ8I2awGXDjzKP+686eujiangAgf5N+Q=");
        done();
    });

    it("should create derived keys (computeDerivedKeys)", function () {

        const options: ComputeDerivedKeysOptions = options_AES_128_CBC;
        const derivedKeys = crypto_utils.computeDerivedKeys(secret, seed, options);

        derivedKeys.signingKey.length.should.eql(options.signingKeyLength);
        derivedKeys.encryptingKey.length.should.eql(options.encryptingKeyLength);
        derivedKeys.initializationVector.length.should.eql(options.encryptingBlockSize);

    });

});
