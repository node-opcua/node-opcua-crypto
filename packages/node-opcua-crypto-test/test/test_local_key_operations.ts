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

import nodeCrypto from "node:crypto";
import {
    type AsymmetricDecryptParams,
    decryptLong,
    decryptLongSync,
    hasSyncKeyOperations,
    type IKeyOperations,
    isKeyOperations,
    keyOperationsFromPrivateKey,
    LocalKeyOperations,
    type PrivateKey,
    rsaLengthPrivateKey,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

function makeRsaKey(modulusLength = 2048): { keyObject: nodeCrypto.KeyObject; pem: string; privateKey: PrivateKey } {
    const { privateKey } = nodeCrypto.generateKeyPairSync("rsa", { modulusLength });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    return { keyObject: privateKey, pem, privateKey: { hidden: pem } };
}

const key2048 = makeRsaKey(2048);
const ops2048 = new LocalKeyOperations(key2048.privateKey);
const data = Buffer.from("The quick brown fox jumps over the lazy dog");

/** True when this Node still allows RSA PKCS#1 v1.5 private decryption (CVE-2023-46809 gate). */
function pkcs1v15DecryptSupported(): boolean {
    const encrypted = nodeCrypto.publicEncrypt(
        { key: nodeCrypto.createPublicKey(key2048.keyObject), padding: nodeCrypto.constants.RSA_PKCS1_PADDING },
        Buffer.from("probe"),
    );
    try {
        nodeCrypto.privateDecrypt({ key: key2048.keyObject, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, encrypted);
        return true;
    } catch {
        return false;
    }
}

describe("LocalKeyOperations - construction and metadata", () => {
    it("accepts both envelope forms: PEM string and KeyObject", async () => {
        const fromPem = new LocalKeyOperations({ hidden: key2048.pem });
        const fromKeyObject = new LocalKeyOperations({ hidden: key2048.keyObject });
        expect(fromPem.getKeyMetadataSync()).toEqual({ keyType: "RSA", modulusLength: 256 });
        expect(fromKeyObject.getKeyMetadataSync()).toEqual({ keyType: "RSA", modulusLength: 256 });
        expect(await fromPem.getKeyMetadata()).toEqual(fromKeyObject.getKeyMetadataSync());
    });

    it("metadata matches rsaLengthPrivateKey for RSA 2048/3072/4096", { timeout: 120_000 }, () => {
        for (const modulusLength of [2048, 3072, 4096]) {
            const { privateKey } = makeRsaKey(modulusLength);
            const ops = keyOperationsFromPrivateKey(privateKey);
            expect(ops.getKeyMetadataSync().modulusLength).toBe(rsaLengthPrivateKey(privateKey));
            expect(ops.getKeyMetadataSync().modulusLength).toBe(modulusLength / 8);
        }
    });

    it("rejects a non-RSA key with a clear error", () => {
        const { privateKey } = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
        const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
        expect(() => new LocalKeyOperations({ hidden: pem })).toThrow(/RSA keys only/);
    });

    it("is recognized by the guards, sync fast path included", () => {
        expect(isKeyOperations(ops2048)).toBe(true);
        expect(hasSyncKeyOperations(ops2048)).toBe(true);
    });

    it("exposes the public half as SPKI DER", async () => {
        const spki = Buffer.from(await ops2048.getPublicKey());
        const expected = nodeCrypto.createPublicKey(key2048.keyObject).export({ type: "spki", format: "der" });
        expect(spki.equals(expected)).toBe(true);
    });
});

describe("LocalKeyOperations - sign", () => {
    it("PKCS#1 v1.5 signatures byte-match node:crypto for SHA-1 and SHA-256", async () => {
        for (const [hash, nodeAlgorithm] of [
            ["SHA-1", "RSA-SHA1"],
            ["SHA-256", "RSA-SHA256"],
        ] as const) {
            const expected = nodeCrypto.createSign(nodeAlgorithm).update(data).sign(key2048.keyObject);
            expect(ops2048.signSync(data, { padding: "RSA-PKCS1-v1_5", hash }).equals(expected)).toBe(true);
            expect((await ops2048.sign(data, { padding: "RSA-PKCS1-v1_5", hash })).equals(expected)).toBe(true);
        }
    });

    it("PSS/SHA-256 signatures verify with salt length = digest length", async () => {
        const signature = await ops2048.sign(data, { padding: "RSA-PSS", hash: "SHA-256" });
        expect(signature.length).toBe(256);
        const verifiesWithDigestSalt = nodeCrypto
            .createVerify("RSA-SHA256")
            .update(data)
            .verify(
                {
                    key: nodeCrypto.createPublicKey(key2048.keyObject),
                    padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: 32,
                },
                signature,
            );
        expect(verifiesWithDigestSalt).toBe(true);
        const verifiesWithWrongSalt = nodeCrypto
            .createVerify("RSA-SHA256")
            .update(data)
            .verify(
                {
                    key: nodeCrypto.createPublicKey(key2048.keyObject),
                    padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: 20,
                },
                signature,
            );
        expect(verifiesWithWrongSalt).toBe(false);
    });
});

describe("LocalKeyOperations - decryptBlock", () => {
    const publicKey = nodeCrypto.createPublicKey(key2048.keyObject);

    function encryptOneBlock(plain: Buffer, params: AsymmetricDecryptParams): Buffer {
        if (params.padding === "RSA-OAEP") {
            return nodeCrypto.publicEncrypt(
                {
                    key: publicKey,
                    padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: params.oaepHash === "SHA-256" ? "sha256" : "sha1",
                },
                plain,
            );
        }
        return nodeCrypto.publicEncrypt({ key: publicKey, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, plain);
    }

    it("round-trips OAEP-SHA1 and OAEP-SHA256", async () => {
        for (const oaepHash of ["SHA-1", "SHA-256"] as const) {
            const params: AsymmetricDecryptParams = { padding: "RSA-OAEP", oaepHash };
            const block = encryptOneBlock(data, params);
            expect(ops2048.decryptBlockSync(block, params).equals(data)).toBe(true);
            expect((await ops2048.decryptBlock(block, params)).equals(data)).toBe(true);
        }
    });

    it("round-trips PKCS#1 v1.5 when this Node supports it", async () => {
        if (!pkcs1v15DecryptSupported()) {
            console.log("skipping: PKCS#1 v1.5 private decryption is disabled on this Node (CVE-2023-46809)");
            return;
        }
        const params: AsymmetricDecryptParams = { padding: "RSA-PKCS1-v1_5" };
        const block = encryptOneBlock(data, params);
        expect((await ops2048.decryptBlock(block, params)).equals(data)).toBe(true);
    });

    it("rejects a block that is not exactly one modulus long", () => {
        expect(() => ops2048.decryptBlockSync(Buffer.alloc(255), { padding: "RSA-OAEP", oaepHash: "SHA-256" })).toThrow(
            /exactly one cipher block of 256 bytes/,
        );
    });

    it("rejects RSA-OAEP without an oaepHash", () => {
        expect(() => ops2048.decryptBlockSync(Buffer.alloc(256), { padding: "RSA-OAEP" })).toThrow(/requires an oaepHash/);
    });

    it("throws on an undecryptable block instead of returning garbage", () => {
        expect(() => ops2048.decryptBlockSync(Buffer.alloc(256, 0xab), { padding: "RSA-OAEP", oaepHash: "SHA-256" })).toThrow();
    });
});

describe("decryptLong / decryptLongSync", () => {
    const params: AsymmetricDecryptParams = { padding: "RSA-OAEP", oaepHash: "SHA-256" };
    const publicKey = nodeCrypto.createPublicKey(key2048.keyObject);
    const plainBlocks = [Buffer.from("first block"), Buffer.from("second block"), Buffer.from("third block")];
    const encrypted = Buffer.concat(
        plainBlocks.map((plain) =>
            nodeCrypto.publicEncrypt(
                { key: publicKey, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
                plain,
            ),
        ),
    );
    const expected = Buffer.concat(plainBlocks);

    it("decrypts a multi-block buffer, async and sync, with identical results", async () => {
        expect((await decryptLong(ops2048, encrypted, params, 256)).equals(expected)).toBe(true);
        expect(decryptLongSync(ops2048, encrypted, params, 256).equals(expected)).toBe(true);
    });

    it("reassembles blocks in order even when they resolve out of order", async () => {
        let callIndex = 0;
        const outOfOrderOps: IKeyOperations = {
            sign: ops2048.sign.bind(ops2048),
            getKeyMetadata: ops2048.getKeyMetadata.bind(ops2048),
            async decryptBlock(block, blockParams) {
                // first block resolves last: ordered output proves reassembly is by position, not completion
                const delay = callIndex++ === 0 ? 50 : 0;
                await new Promise((resolve) => setTimeout(resolve, delay));
                return ops2048.decryptBlockSync(block, blockParams);
            },
        };
        expect((await decryptLong(outOfOrderOps, encrypted, params, 256)).equals(expected)).toBe(true);
    });

    it("rejects a misaligned buffer and a bogus block size", async () => {
        await expect(decryptLong(ops2048, encrypted.subarray(0, 300), params, 256)).rejects.toThrow(/whole number of 256-byte/);
        await expect(decryptLong(ops2048, Buffer.alloc(0), params, 256)).rejects.toThrow(/whole number/);
        await expect(decryptLong(ops2048, encrypted, params, 0)).rejects.toThrow(/invalid cipher block size/);
    });

    it("decryptLongSync refuses an async-only provider", () => {
        const asyncOnly: IKeyOperations = {
            sign: ops2048.sign.bind(ops2048),
            decryptBlock: ops2048.decryptBlock.bind(ops2048),
            getKeyMetadata: ops2048.getKeyMetadata.bind(ops2048),
        };
        expect(() => decryptLongSync(asyncOnly, encrypted, params, 256)).toThrow(/synchronous fast path/);
    });
});
