// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
// ---------------------------------------------------------------------------------------------------------------------

// The symmetric functions keep a Cipher, a Decipher and a keyed HMAC per derived key between chunks. Whatever the
// order of the chunks, each must give exactly what a Cipher, Decipher or Hmac made for that chunk alone gives.
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import {
    type ComputeDerivedKeysOptions,
    computeDerivedKeys,
    type DerivedKeys,
    decryptBufferWithDerivedKeys,
    encryptBufferWithDerivedKeys,
    makeMessageChunkSignatureWithDerivedKeys,
    verifyChunkSignatureWithDerivedKeys,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

const policies: Record<string, ComputeDerivedKeysOptions> = {
    // Basic256Sha256 and Aes256_Sha256_RsaPss
    "aes-256-cbc / SHA256": {
        signingKeyLength: 32,
        encryptingKeyLength: 32,
        encryptingBlockSize: 16,
        signatureLength: 32,
        algorithm: "aes-256-cbc",
        sha1or256: "SHA256",
    },
    // Aes128_Sha256_RsaOaep
    "aes-128-cbc / SHA256": {
        signingKeyLength: 32,
        encryptingKeyLength: 16,
        encryptingBlockSize: 16,
        signatureLength: 32,
        algorithm: "aes-128-cbc",
        sha1or256: "SHA256",
    },
    // Basic128Rsa15
    "aes-128-cbc / SHA1": {
        signingKeyLength: 16,
        encryptingKeyLength: 16,
        encryptingBlockSize: 16,
        signatureLength: 20,
        algorithm: "aes-128-cbc",
        sha1or256: "SHA1",
    },
};

function referenceEncrypt(buffer: Buffer, keys: DerivedKeys): Buffer {
    const cipher = createCipheriv(keys.algorithm, keys.encryptingKey, keys.initializationVector);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(buffer), cipher.final()]);
}
function referenceDecrypt(buffer: Buffer, keys: DerivedKeys): Buffer {
    const decipher = createDecipheriv(keys.algorithm, keys.encryptingKey, keys.initializationVector);
    decipher.setAutoPadding(false);
    return Buffer.concat([decipher.update(buffer), decipher.final()]);
}
const referenceHmac = (message: Buffer, keys: DerivedKeys) => createHmac(keys.sha1or256, keys.signingKey).update(message).digest();

const chunkSizes = [16, 32, 48, 112, 128, 144, 1024, 8192, 65536];
// around the SHA-256 padding boundaries (55/56 bytes in a block), the 256-byte switch to the native Hmac, and beyond
const messageSizes = [0, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 255, 256, 257, 300, 1000, 8192];

describe("symmetric crypto with kept state per derived key", () => {
    for (const [name, options] of Object.entries(policies)) {
        describe(name, () => {
            it("encrypts and decrypts any sequence of chunks as one Cipher per chunk would", () => {
                const keys = computeDerivedKeys(randomBytes(32), randomBytes(32), options);
                for (let round = 0; round < 3; round++) {
                    for (const size of chunkSizes) {
                        const clear = randomBytes(size);
                        const encrypted = encryptBufferWithDerivedKeys(clear, keys);
                        expect(encrypted.equals(referenceEncrypt(clear, keys))).toBe(true);
                        expect(decryptBufferWithDerivedKeys(encrypted, keys).equals(clear)).toBe(true);
                        // the same chunk twice in a row: the chaining state must come back to the IV both times
                        expect(encryptBufferWithDerivedKeys(clear, keys).equals(encrypted)).toBe(true);
                        expect(decryptBufferWithDerivedKeys(encrypted, keys).equals(referenceDecrypt(encrypted, keys))).toBe(true);
                    }
                }
            });

            it("keeps the chunks of two channels apart", () => {
                const keysA = computeDerivedKeys(randomBytes(32), randomBytes(32), options);
                const keysB = computeDerivedKeys(randomBytes(32), randomBytes(32), options);
                for (const size of chunkSizes) {
                    const clearA = randomBytes(size);
                    const clearB = randomBytes(size);
                    const encryptedA = encryptBufferWithDerivedKeys(clearA, keysA);
                    const encryptedB = encryptBufferWithDerivedKeys(clearB, keysB);
                    expect(encryptedA.equals(referenceEncrypt(clearA, keysA))).toBe(true);
                    expect(encryptedB.equals(referenceEncrypt(clearB, keysB))).toBe(true);
                    expect(decryptBufferWithDerivedKeys(encryptedB, keysB).equals(clearB)).toBe(true);
                    expect(decryptBufferWithDerivedKeys(encryptedA, keysA).equals(clearA)).toBe(true);
                }
            });

            it("returns a chunk the next call does not overwrite", () => {
                const keys = computeDerivedKeys(randomBytes(32), randomBytes(32), options);
                const clear1 = randomBytes(128);
                const encrypted1 = encryptBufferWithDerivedKeys(clear1, keys);
                const copy1 = Buffer.from(encrypted1);
                const decrypted1 = decryptBufferWithDerivedKeys(encrypted1, keys);
                encryptBufferWithDerivedKeys(randomBytes(128), keys);
                decryptBufferWithDerivedKeys(randomBytes(128), keys);
                expect(encrypted1.equals(copy1)).toBe(true);
                expect(decrypted1.equals(clear1)).toBe(true);
            });

            it("still refuses a buffer that is not made of whole blocks", () => {
                const keys = computeDerivedKeys(randomBytes(32), randomBytes(32), options);
                expect(() => encryptBufferWithDerivedKeys(randomBytes(17), keys)).toThrow();
                expect(() => decryptBufferWithDerivedKeys(randomBytes(17), keys)).toThrow();
                // and the kept cipher is not disturbed by it
                const clear = randomBytes(64);
                expect(encryptBufferWithDerivedKeys(clear, keys).equals(referenceEncrypt(clear, keys))).toBe(true);
            });

            it("signs as a node:crypto Hmac and verifies the signature", () => {
                const keys = computeDerivedKeys(randomBytes(32), randomBytes(32), options);
                for (const size of messageSizes) {
                    const message = randomBytes(size);
                    const signature = makeMessageChunkSignatureWithDerivedKeys(message, keys);
                    expect(signature.equals(referenceHmac(message, keys))).toBe(true);

                    const chunk = Buffer.concat([message, signature]);
                    expect(verifyChunkSignatureWithDerivedKeys(chunk, keys)).toBe(true);
                    for (const position of [0, chunk.length - 1, size]) {
                        if (position >= chunk.length) continue;
                        const tampered = Buffer.from(chunk);
                        tampered[position] ^= 0x01;
                        expect(verifyChunkSignatureWithDerivedKeys(tampered, keys)).toBe(false);
                    }
                }
            });
        });
    }

    it("starts from the new IV when a token brings new keys", () => {
        const options = policies["aes-256-cbc / SHA256"];
        const clear = randomBytes(256);
        for (let token = 0; token < 3; token++) {
            const keys = computeDerivedKeys(randomBytes(32), randomBytes(32), options);
            expect(encryptBufferWithDerivedKeys(clear, keys).equals(referenceEncrypt(clear, keys))).toBe(true);
        }
    });
});
