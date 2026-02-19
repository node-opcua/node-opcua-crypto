// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so,  subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ---------------------------------------------------------------------------------------------------------------------

import assert from "node:assert";
import {
    createCipheriv,
    createDecipheriv,
    createHmac,
    createSign,
    createVerify,
    getDiffieHellman,
    type KeyObject,
    publicEncrypt as publicEncrypt_fromCrypto,
    randomBytes,
} from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as loremIpsum1 from "lorem-ipsum";
import {
    convertPEMtoDER,
    extractPublicKeyFromCertificate,
    makeMessageChunkSignature,
    type PublicKeyPEM,
    privateDecrypt_long,
    publicEncrypt,
    publicEncrypt_long,
    RSA_PKCS1_OAEP_PADDING,
    RSA_PKCS1_PADDING,
    readCertificate,
    readPrivateKey,
    readPrivateRsaKey,
    readPublicKey,
    readPublicRsaKey,
    rsaLengthRsaPublicKey,
    setCertificateStore,
    toPem,
    verifyMessageChunkSignature,
} from "node-opcua-crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const loremIpsum: string = loremIpsum1.loremIpsum({ count: 100 });

// see https://github.com/nodejs/node/issues/22815

let old_store: string | null = null;

function switch_to_test_certificate_store() {
    assert(old_store === null);
    old_store = setCertificateStore(path.join(__dirname, "../test-fixtures/certs/"));
}

function restore_default_certificate_store() {
    if (old_store === null) {
        throw new Error("cannot restore certificate store");
    }

    setCertificateStore(old_store);
    old_store = null;
}

const alice_private_key_filename = path.join(__dirname, "../test-fixtures/alice_bob/alice_key_1024.pem");
const alice_public_key_filename = path.join(__dirname, "../test-fixtures/alice_bob/alice_public_key_1024.pub");
const alice_certificate_filename = path.join(__dirname, "../test-fixtures/alice_bob/alice_cert_1024.pem");
const alice_out_of_date_certificate_filename = path.join(__dirname, "../test-fixtures/alice_bob/alice_cert_1024_outofdate.pem");

const bob_private_key_filename = path.join(__dirname, "../test-fixtures/alice_bob/bob_key_1024.pem");
const bob_public_key_filename = path.join(__dirname, "../test-fixtures/alice_bob/bob_public_key_1024.pub");
const bob_certificate_filename = path.join(__dirname, "../test-fixtures/alice_bob/bob_cert_1024.pem");
const bob_certificate_out_of_date_filename = path.join(__dirname, "../test-fixtures/alice_bob/bob_cert_1024_outofdate.pem");

const doDebug = false;

//Xx doDebug = true;
function debugLog(...args: [unknown?, ...unknown[]]) {
    if (doDebug) {
        console.log(console, ...args);
    }
}

// symmetric encryption and decryption
function encrypt_buffer(buffer: Buffer, algorithm: string, key: Buffer): Buffer {
    const iv = Buffer.alloc(16, 0); // Initialization vector.
    const cipher = createCipheriv(algorithm, key, iv);
    const encrypted_chunks: Buffer[] = [];
    encrypted_chunks.push(cipher.update(buffer));
    encrypted_chunks.push(cipher.final());
    return Buffer.concat(encrypted_chunks);
}

function decrypt_buffer(buffer: Buffer, algorithm: string, key: Buffer): Buffer {
    const iv = Buffer.alloc(16, 0); // Initialization vector.
    const decipher = createDecipheriv(algorithm, key, iv);
    const decrypted_chunks: Buffer[] = [];
    decrypted_chunks.push(decipher.update(buffer));
    decrypted_chunks.push(decipher.final());
    return Buffer.concat(decrypted_chunks);
}

describe("testing and exploring the NodeJS crypto api", () => {
    beforeEach(() => {
        switch_to_test_certificate_store();
    });
    afterEach(() => {
        restore_default_certificate_store();
    });

    it("should be possible to sign a message and verify the signature of a message", () => {
        // ------------------- this is Alice
        //
        // alice want to send a message to Bob
        const message = "HelloWorld";

        // alice will sign her message to bob with her private key.
        const alice_private_key_pem = fs.readFileSync(alice_private_key_filename);
        const alice_private_key = alice_private_key_pem.toString("ascii");
        debugLog(alice_private_key);

        const signature = createSign("RSA-SHA256").update(message).sign(alice_private_key);

        debugLog("message   = ", message);
        debugLog("signature = ", signature.toString("hex"));

        // ------------------- this is Bob
        // Bob has received a message from Alice,
        // He wants to verify that the message is really from by Alice.
        // Alice has given Bob her public_key.
        // Bob uses Alice's public key to verify that the message is correct

        const message_from_alice = "HelloWorld";

        const alice_public_key = fs.readFileSync(alice_public_key_filename, "ascii");

        expect(createVerify("RSA-SHA256").update(message_from_alice).verify(alice_public_key, signature)).toBe(true);

        // -------------------------
        expect(createVerify("RSA-SHA256").update("Hello**HACK**World").verify(alice_public_key, signature)).toBe(false);

        // The keys are asymmetrical, this means that Bob cannot sign
        // a message using alice public key.
        expect(() => {
            const bob_sign = createSign("RSA-SHA256");
            bob_sign.update("HelloWorld");
            const signature1 = bob_sign.sign(alice_public_key);

            expect(signature1.length).toBeGreaterThan(0);
        }).toThrow();
    });

    if (publicEncrypt_fromCrypto !== null) {
        it("should check that bob rsa key is 2048bit long (256 bytes)", () => {
            const key = readPublicRsaKey("bob_id_rsa.pub");
            expect(rsaLengthRsaPublicKey(key)).toBe(256);
        });

        it("should check that john rsa key is 1024bit long (128 bytes)", () => {
            const key = readPublicRsaKey("john_id_rsa.pub");
            expect(rsaLengthRsaPublicKey(key)).toBe(128);
        });
        it("RSA_PKCS1_OAEP_PADDING 1024 verifying that RSA publicEncrypt cannot encrypt buffer bigger than 215 bytes due to the effect of padding", () => {
            const john_public_key = readPublicRsaKey("john_id_rsa.pub") as KeyObject; // 1024 bit RSA
            debugLog("john_public_key", john_public_key);

            let encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(1), john_public_key as KeyObject);
            debugLog(" A encryptedBuffer length = ", encryptedBuffer.length);
            expect(encryptedBuffer.length).toEqual(128);

            encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(128 - 42), john_public_key as KeyObject);
            debugLog(" B encryptedBuffer length = ", encryptedBuffer.length);
            expect(encryptedBuffer.length).toEqual(128);

            expect(() => {
                encryptedBuffer = publicEncrypt(
                    Buffer.allocUnsafe(128 - 42 + 1),
                    john_public_key as KeyObject,
                    RSA_PKCS1_OAEP_PADDING,
                );
                debugLog(" C encryptedBuffer length = ", encryptedBuffer.length);
            }).toThrow();

            expect(() => {
                encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(128), john_public_key, RSA_PKCS1_OAEP_PADDING);
                console.log(" D encryptedBuffer length = ", encryptedBuffer.length);
            }).toThrow();
        });

        it("RSA_PKCS1_PADDING 2048 verifying that RSA publicEncrypt cannot encrypt buffer bigger than 215 bytes due to the effect of padding", () => {
            //
            const bob_public_key = readPublicRsaKey("bob_id_rsa.pub");
            debugLog("bob_public_key", bob_public_key);

            let encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(1), bob_public_key as KeyObject, RSA_PKCS1_PADDING);
            debugLog(" A encryptedBuffer length = ", encryptedBuffer.length);
            expect(encryptedBuffer.length).toEqual(256);

            encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(245), bob_public_key as KeyObject, RSA_PKCS1_PADDING);
            debugLog(" B encryptedBuffer length = ", encryptedBuffer.length);
            expect(encryptedBuffer.length).toEqual(256);

            expect(() => {
                encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(246), bob_public_key as KeyObject, RSA_PKCS1_PADDING);
                debugLog(" C encryptedBuffer length = ", encryptedBuffer.length);
            }).toThrow();

            expect(() => {
                encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(259), bob_public_key as KeyObject, RSA_PKCS1_PADDING);
                console.log(" D encryptedBuffer length = ", encryptedBuffer.length);
            }).toThrow();
        });

        it("RSA_PKCS1_OAEP_PADDING 2048 verifying that RSA publicEncrypt cannot encrypt buffer bigger than 215 bytes due to the effect of padding", () => {
            //
            const bob_public_key = readPublicRsaKey("bob_id_rsa.pub") as KeyObject;
            debugLog("bob_public_key", bob_public_key);

            let _encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(1), bob_public_key, RSA_PKCS1_OAEP_PADDING);
            debugLog(" A encryptedBuffer length = ", _encryptedBuffer.length);
            expect(_encryptedBuffer.length).toEqual(256);

            _encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(214), bob_public_key, RSA_PKCS1_OAEP_PADDING);
            debugLog(" B encryptedBuffer length = ", _encryptedBuffer.length);
            expect(_encryptedBuffer.length).toEqual(256);

            expect(() => {
                _encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(215), bob_public_key, RSA_PKCS1_OAEP_PADDING);
                debugLog(" C encryptedBuffer length = ", _encryptedBuffer.length);
            }).toThrow();

            expect(() => {
                _encryptedBuffer = publicEncrypt(Buffer.allocUnsafe(259), bob_public_key, RSA_PKCS1_OAEP_PADDING);
                console.log(" D encryptedBuffer length = ", _encryptedBuffer.length);
            }).toThrow();
        });

        it("publicEncrypt  shall produce  different encrypted string if call many times with the same input", () => {
            const bob_public_key = readPublicRsaKey("bob_id_rsa.pub") as KeyObject; // 2048bit long key
            const bob_private_key = readPrivateRsaKey("bob_id_rsa");

            const initialBuffer = Buffer.from(loremIpsum.substring(0, 25));
            const encryptedBuffer1 = publicEncrypt_long(initialBuffer, bob_public_key, 256);
            const encryptedBuffer2 = publicEncrypt_long(initialBuffer, bob_public_key, 256);

            expect(encryptedBuffer1.toString("hex")).not.toBe(encryptedBuffer2.toString("hex"));

            const decryptedBuffer1 = privateDecrypt_long(encryptedBuffer1, bob_private_key, 256);
            const decryptedBuffer2 = privateDecrypt_long(encryptedBuffer2, bob_private_key, 256);

            expect(decryptedBuffer1.toString("hex")).toBe(decryptedBuffer2.toString("hex"));
        });

        it("publicEncrypt_long should encrypt a 256 bytes buffer and return a encrypted buffer of 512 bytes", () => {
            const bob_public_key = readPublicRsaKey("bob_id_rsa.pub") as KeyObject; // 2048bit long key

            const initialBuffer = Buffer.from(loremIpsum.substring(0, 256));
            const encryptedBuffer = publicEncrypt_long(initialBuffer, bob_public_key, 256);
            expect(encryptedBuffer.length).toEqual(256 * 2);

            const bob_private_key = readPrivateRsaKey("bob_id_rsa");
            const decryptedBuffer = privateDecrypt_long(encryptedBuffer, bob_private_key, 256);
            expect(decryptedBuffer.toString("ascii")).toEqual(initialBuffer.toString("ascii"));
        });

        it("publicEncrypt_long should encrypt a 1024 bytes buffer and return a encrypted buffer of 1280 bytes", () => {
            const bob_public_key = readPublicRsaKey("bob_id_rsa.pub") as KeyObject;

            const initialBuffer = Buffer.from(loremIpsum.substring(0, 1024));
            const encryptedBuffer = publicEncrypt_long(initialBuffer, bob_public_key, 256);
            expect(encryptedBuffer.length).toEqual(256 * 5);

            const bob_private_key = readPrivateRsaKey("bob_id_rsa");
            const decryptedBuffer = privateDecrypt_long(encryptedBuffer, bob_private_key, 256);
            expect(decryptedBuffer.length).toBe(initialBuffer.length);
            expect(decryptedBuffer.toString("ascii")).toEqual(initialBuffer.toString("ascii"));
        });

        it("Alice should be able to encrypt a message with bob's public key and Bob shall be able to decrypt it with his Private Key", () => {
            const message = `My dear Bob, ${loremIpsum}... Alice`;
            debugLog("length of original  message = ", message.length);

            const alice_private_key = readPrivateRsaKey("alice_id_rsa");
            const bob_public_key = readPublicRsaKey("bob_id_rsa.pub") as KeyObject;

            const signature = createSign("RSA-SHA256")
                .update(message)
                .sign(alice_private_key.hidden as KeyObject);
            debugLog("signature = ", signature.toString("hex"));
            debugLog("signature length = ", signature.length);

            debugLog(bob_public_key);

            const encryptedMessage = publicEncrypt_long(Buffer.from(message), bob_public_key, 256);

            debugLog("encrypted message=", encryptedMessage.toString("hex"));

            debugLog("length of encrypted message = ", encryptedMessage.length);

            // ------------------- this is Bob
            const bob_private_key = readPrivateRsaKey("bob_id_rsa");
            const alice_public_key = readPublicRsaKey("alice_id_rsa.pub") as KeyObject;

            const decryptedMessage = privateDecrypt_long(encryptedMessage, bob_private_key, 256).toString();
            debugLog("decrypted message=", decryptedMessage.toString());

            expect(createVerify("RSA-SHA256").update(decryptedMessage).verify(alice_public_key, signature)).toBe(true);
        });
    }

    it("explore DiffieHellman encryption (generating keys)", () => {
        const alice = getDiffieHellman("modp5");
        const bob = getDiffieHellman("modp5");

        alice.generateKeys();
        bob.generateKeys();

        const alice_secret = alice.computeSecret(bob.getPublicKey());
        const bob_secret = bob.computeSecret(alice.getPublicKey());

        /* alice_secret and bob_secret should be the same */
        expect(alice_secret).toEqual(bob_secret);
    });

    // encrypt_buffer(buffer,"aes-256-cbc",key);
    it("should encrypt a message", () => {
        const key = randomBytes(32);

        const bufferToEncrypt = Buffer.alloc(32);
        bufferToEncrypt.writeDoubleLE(3.14, 0);
        bufferToEncrypt.writeDoubleLE(3.14, 8);

        const encryptedBuf = encrypt_buffer(bufferToEncrypt, "aes-256-cbc", key);

        if (!fs.existsSync("tmp")) {
            fs.mkdirSync("tmp");
        }
        const s = fs.createWriteStream("tmp/output2.bin", "ascii");
        s.write(encryptedBuf.toString("hex"));
        s.end();
    });

    it("exploring crypto api with symmetrical encryption/decryption", () => {
        const key = randomBytes(32);

        const bufferToEncrypt = Buffer.from(`This is a top , very top secret message !! ah ah${loremIpsum}`);

        const encryptedBuffer = encrypt_buffer(bufferToEncrypt, "aes-256-cbc", key);
        const decryptedBuffer = decrypt_buffer(encryptedBuffer, "aes-256-cbc", key);

        expect(bufferToEncrypt.toString("hex")).toBe(decryptedBuffer.toString("hex"));
    });
});

describe("exploring symmetric signing", () => {
    it("should sign and verify", () => {
        const text = "I love cupcakes",
            key = randomBytes(32);

        const hash = createHmac("sha1", key).update(text).digest();

        assert(Buffer.isBuffer(hash));

        expect(hash.length).toEqual(20);
        // TO DO : to be completed.
    });
});

/// -------------------------------------------------------------

describe("Testing AsymmetricSignatureAlgorithm", () => {
    const chunk = Buffer.from(loremIpsum);

    function make_suite(algorithm: string, signatureLength: number) {
        it(`should sign with a private key and verify with the public key - ${algorithm}`, () => {
            const alice_private_key = readPrivateKey(alice_private_key_filename);
            const options1 = {
                algorithm,
                signatureLength,
                privateKey: alice_private_key,
            };
            const signature = makeMessageChunkSignature(chunk, options1);

            expect(signature).toBeInstanceOf(Buffer);
            expect(signature.length).toEqual(options1.signatureLength);

            const alice_public_key = fs.readFileSync(alice_public_key_filename, "ascii");

            const options2 = {
                algorithm,
                signatureLength,
                publicKey: alice_public_key,
            };
            const signVerif = verifyMessageChunkSignature(chunk, signature, options2);
            expect(signVerif).toEqual(true);
        });

        it(`should sign with a private key and verify with the certificate (ASCII) - ${algorithm}`, () => {
            const alice_private_key = readPrivateKey(alice_private_key_filename);
            const options1 = {
                algorithm,
                signatureLength,
                privateKey: alice_private_key,
            };

            const signature = makeMessageChunkSignature(chunk, options1);

            expect(signature).toBeInstanceOf(Buffer);
            expect(signature.length).toEqual(options1.signatureLength);

            const alice_certificate = fs.readFileSync(alice_certificate_filename, "ascii");

            const options2 = {
                algorithm,
                signatureLength,
                publicKey: alice_certificate,
            };
            const signVerif = verifyMessageChunkSignature(chunk, signature, options2);
            expect(signVerif).toBe(true);
        });

        it(`should sign with a private key and verify with a OUT OF DATE certificate (ASCII) - ${algorithm}`, () => {
            const alice_private_key = readPrivateKey(alice_private_key_filename);
            const options1 = {
                algorithm,
                signatureLength,
                privateKey: alice_private_key,
            };
            const signature = makeMessageChunkSignature(chunk, options1);

            expect(signature).toBeInstanceOf(Buffer);
            expect(signature.length).toEqual(options1.signatureLength);

            const alice_certificate = fs.readFileSync(alice_out_of_date_certificate_filename).toString("ascii");

            const options2 = {
                algorithm,
                signatureLength,
                publicKey: alice_certificate,
            };
            const signVerif = verifyMessageChunkSignature(chunk, signature, options2);
            expect(signVerif).toBe(true);
        });

        it(`should sign with a private key and verify with the certificate (DER) - ${algorithm}`, () => {
            const alice_private_key = readPrivateKey(alice_private_key_filename);
            const options1 = {
                algorithm,
                signatureLength,
                privateKey: alice_private_key,
            };
            const signature = makeMessageChunkSignature(chunk, options1);

            expect(signature).toBeInstanceOf(Buffer);
            expect(signature.length).toEqual(options1.signatureLength);

            const alice_certificate = readCertificate(alice_certificate_filename);

            const options2 = {
                algorithm,
                signatureLength,
                publicKey: toPem(alice_certificate, "CERTIFICATE"),
            };
            const signVerif = verifyMessageChunkSignature(chunk, signature, options2);
            expect(signVerif).toEqual(true);
        });

        it(`should sign with a other private key and verify with a OUT OF DATE certificate (ASCII) - ${algorithm}`, () => {
            const privateKey = readPrivateKey(bob_private_key_filename);
            const options1 = {
                algorithm,
                signatureLength,
                privateKey,
            };

            const signature = makeMessageChunkSignature(chunk, options1);

            expect(signature).toBeInstanceOf(Buffer);
            expect(signature.length).toEqual(options1.signatureLength);

            const certificate = readCertificate(bob_certificate_out_of_date_filename);

            const options2 = {
                algorithm,
                signatureLength,
                publicKey: toPem(certificate, "CERTIFICATE"),
            };

            const signVerif = verifyMessageChunkSignature(chunk, signature, options2);

            expect(signVerif).toEqual(true);
        });
    }

    make_suite("RSA-SHA384", 128);
    make_suite("RSA-SHA512", 128);
    make_suite("RSA-SHA256", 128);
    make_suite("RSA-SHA1", 128);
    // Obsolete  make_suite("RSA-MD4", 128);
    make_suite("sha224WithRSAEncryption", 128);
    make_suite("sha1WithRSAEncryption", 128);
    make_suite("sha256WithRSAEncryption", 128);
});

describe("extractPublicKeyFromCertificate", () => {
    it("should extract a public key from a certificate", async () => {
        const certificate2 = readCertificate(bob_certificate_filename);

        const publickey2 = readPublicKey(bob_public_key_filename);
        const publickey2Der = publickey2.export({ format: "der", type: "spki" });

        const publicKey = await new Promise<PublicKeyPEM>((resolve, reject) => {
            extractPublicKeyFromCertificate(certificate2, (err: Error | null, pk?: PublicKeyPEM) => {
                if (err || !pk) {
                    return reject(err || new Error("Error"));
                }
                resolve(pk);
            });
        });

        const raw_public_key = convertPEMtoDER(publicKey);
        expect(raw_public_key.toString("base64")).toEqual(publickey2Der.toString("base64"));
    });
});
