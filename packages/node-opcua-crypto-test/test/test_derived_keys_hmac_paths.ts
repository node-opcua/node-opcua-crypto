// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
// ---------------------------------------------------------------------------------------------------------------------

// makeMessageChunkSignatureWithDerivedKeys signs with WasmHmacSha256 (SHA256 up to 512 bytes, Node build) or
// KeyedHmacSha256 (up to 256 bytes where WebAssembly is missing), with two one-shot
// hashes (larger chunks, SHA1) or with createHmac (keys longer than a block). Whatever the path, the signature must be
// the HMAC node:crypto computes, and verifyChunkSignatureWithDerivedKeys must accept it and refuse a changed byte.
import { createHmac, randomBytes } from "node:crypto";
import {
    type ComputeDerivedKeysOptions,
    computeDerivedKeys,
    makeMessageChunkSignatureWithDerivedKeys,
    verifyChunkSignatureWithDerivedKeys,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

const cases: [string, ComputeDerivedKeysOptions][] = [];
for (const signingKeyLength of [1, 16, 24, 32, 63, 64, 80]) {
    cases.push([
        `SHA256, ${signingKeyLength}-byte key`,
        {
            signingKeyLength,
            encryptingKeyLength: 32,
            encryptingBlockSize: 16,
            signatureLength: 32,
            algorithm: "aes-256-cbc",
            sha1or256: "SHA256",
        },
    ]);
}
for (const signingKeyLength of [16, 24, 80]) {
    cases.push([
        `SHA1, ${signingKeyLength}-byte key`,
        {
            signingKeyLength,
            encryptingKeyLength: 16,
            encryptingBlockSize: 16,
            signatureLength: 20,
            algorithm: "aes-128-cbc",
            sha1or256: "SHA1",
        },
    ]);
}

// every length around the block and threshold boundaries, then larger chunks
const lengths: number[] = [];
for (let length = 0; length <= 700; length++) lengths.push(length);
lengths.push(1000, 1024, 4096, 8192 - 32, 65535);

describe("derived keys: HMAC of a chunk, every signing path", () => {
    for (const [name, options] of cases) {
        it(`${name}: the HMAC of node:crypto, verified, a changed byte refused`, () => {
            const derivedKeys = computeDerivedKeys(randomBytes(32), randomBytes(32), options);
            const algorithm = options.sha1or256 === "SHA1" ? "sha1" : "sha256";
            for (const length of lengths) {
                const message = randomBytes(length);
                const signature = makeMessageChunkSignatureWithDerivedKeys(message, derivedKeys);
                const expected = createHmac(algorithm, derivedKeys.signingKey).update(message).digest();
                expect(signature.toString("hex"), `length ${length}`).toBe(expected.toString("hex"));

                const chunk = Buffer.concat([message, signature]);
                expect(verifyChunkSignatureWithDerivedKeys(chunk, derivedKeys)).toBe(true);
                chunk[length > 0 ? length - 1 : 0] ^= 0x01;
                expect(verifyChunkSignatureWithDerivedKeys(chunk, derivedKeys)).toBe(false);
            }
        });
    }

    it("signatures of interleaved keys and sizes do not leak into each other (shared scratch buffers)", () => {
        const options = cases[2][1];
        const keys = [
            computeDerivedKeys(randomBytes(32), randomBytes(32), options),
            computeDerivedKeys(randomBytes(32), randomBytes(32), options),
        ];
        for (let i = 0; i < 200; i++) {
            const derivedKeys = keys[i % 2];
            const message = randomBytes((i * 97) % 3000);
            const expected = createHmac("sha256", derivedKeys.signingKey).update(message).digest();
            expect(makeMessageChunkSignatureWithDerivedKeys(message, derivedKeys).toString("hex")).toBe(expected.toString("hex"));
        }
    });
});
