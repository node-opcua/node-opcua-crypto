import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
    coercePEMorDerToPrivateKey,
    generatePrivateKeyFile,
    PrivateKeyPassphraseRequiredError,
    pemToPrivateKey,
    readPrivateKey,
    readPrivateKeyAsync,
    writePrivateKeyFile,
} from "node-opcua-crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// Under NO_CREATE_PRIVATEKEY=1, node:crypto.createPrivateKey is treated as
// unavailable everywhere in this process, so decrypting an encrypted key is
// fundamentally impossible — myCreatePrivateKey's fallback path fails closed
// (see the "NO_CREATE_PRIVATEKEY fallback path" tests below), it cannot
// succeed. Tests that assert successful decryption are skipped in that mode.
const canDecryptEncryptedKeys = !process.env.NO_CREATE_PRIVATEKEY;

describe("private key passphrase support", () => {
    let tmpDir: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "node-opcua-crypto-passphrase-"));
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("generatePrivateKeyFile with a passphrase should write an ENCRYPTED PRIVATE KEY PEM", async () => {
        const filename = path.join(tmpDir, "key.pem");
        await generatePrivateKeyFile(filename, 2048, { passphrase: "correct horse battery staple" });

        const pem = fs.readFileSync(filename, "utf-8");
        expect(pem).toContain("-----BEGIN ENCRYPTED PRIVATE KEY-----");
    });

    it.skipIf(!canDecryptEncryptedKeys)("readPrivateKey should decrypt an encrypted key given the correct passphrase", async () => {
        const filename = path.join(tmpDir, "key.pem");
        const passphrase = "correct horse battery staple";
        await generatePrivateKeyFile(filename, 2048, { passphrase });

        const key = readPrivateKey(filename, passphrase);
        expect(key.hidden).toBeTruthy();
    });

    it.skipIf(!canDecryptEncryptedKeys)(
        "readPrivateKeyAsync should decrypt an encrypted key given the correct passphrase",
        async () => {
            const filename = path.join(tmpDir, "key.pem");
            const passphrase = "correct horse battery staple";
            await generatePrivateKeyFile(filename, 2048, { passphrase });

            const key = await readPrivateKeyAsync(filename, passphrase);
            expect(key.hidden).toBeTruthy();
        },
    );

    it("readPrivateKey should fail closed (throw PrivateKeyPassphraseRequiredError) when no passphrase is supplied", async () => {
        const filename = path.join(tmpDir, "key.pem");
        await generatePrivateKeyFile(filename, 2048, { passphrase: "some passphrase" });

        expect(() => readPrivateKey(filename)).toThrow(PrivateKeyPassphraseRequiredError);
    });

    it("readPrivateKeyAsync should fail closed (throw PrivateKeyPassphraseRequiredError) when no passphrase is supplied", async () => {
        const filename = path.join(tmpDir, "key.pem");
        await generatePrivateKeyFile(filename, 2048, { passphrase: "some passphrase" });

        await expect(readPrivateKeyAsync(filename)).rejects.toThrow(PrivateKeyPassphraseRequiredError);
    });

    it("readPrivateKey should throw (not silently succeed) when given the wrong passphrase", async () => {
        const filename = path.join(tmpDir, "key.pem");
        await generatePrivateKeyFile(filename, 2048, { passphrase: "correct passphrase" });

        expect(() => readPrivateKey(filename, "wrong passphrase")).toThrow();
    });

    it("readPrivateKey should read a passphrase-configured key with no passphrase supplied at generation time (unencrypted, backward compatible)", async () => {
        const filename = path.join(tmpDir, "key.pem");
        await generatePrivateKeyFile(filename, 2048);

        const pem = fs.readFileSync(filename, "utf-8");
        expect(pem).toContain("-----BEGIN PRIVATE KEY-----");
        expect(pem).not.toContain("ENCRYPTED");

        const key = readPrivateKey(filename);
        expect(key.hidden).toBeTruthy();
    });

    it.skipIf(!canDecryptEncryptedKeys)(
        "writePrivateKeyFile should round-trip an in-memory PrivateKey through encryption and back",
        async () => {
            const plainFilename = path.join(tmpDir, "plain.pem");
            await generatePrivateKeyFile(plainFilename, 2048);
            const privateKey = readPrivateKey(plainFilename);

            const encryptedFilename = path.join(tmpDir, "encrypted.pem");
            const passphrase = "round-trip passphrase";
            await writePrivateKeyFile(encryptedFilename, privateKey, { passphrase });

            const pem = fs.readFileSync(encryptedFilename, "utf-8");
            expect(pem).toContain("-----BEGIN ENCRYPTED PRIVATE KEY-----");

            const decrypted = readPrivateKey(encryptedFilename, passphrase);
            expect(decrypted.hidden).toBeTruthy();
        },
    );

    it("writePrivateKeyFile without a passphrase should write an unencrypted PKCS#8 PEM", async () => {
        const plainFilename = path.join(tmpDir, "plain.pem");
        await generatePrivateKeyFile(plainFilename, 2048);
        const privateKey = readPrivateKey(plainFilename);

        const outFilename = path.join(tmpDir, "out.pem");
        await writePrivateKeyFile(outFilename, privateKey);

        const pem = fs.readFileSync(outFilename, "utf-8");
        expect(pem).toContain("-----BEGIN PRIVATE KEY-----");
        expect(pem).not.toContain("ENCRYPTED");
    });

    describe("coercePEMorDerToPrivateKey (Node path)", () => {
        it("should fail closed when the PEM is encrypted and no passphrase is supplied", async () => {
            const filename = path.join(tmpDir, "key.pem");
            await generatePrivateKeyFile(filename, 2048, { passphrase: "some passphrase" });
            const pem = fs.readFileSync(filename, "utf-8");

            expect(() => coercePEMorDerToPrivateKey(pem)).toThrow(PrivateKeyPassphraseRequiredError);
        });

        it("should decrypt when the correct passphrase is supplied", async () => {
            const filename = path.join(tmpDir, "key.pem");
            const passphrase = "some passphrase";
            await generatePrivateKeyFile(filename, 2048, { passphrase });
            const pem = fs.readFileSync(filename, "utf-8");

            const key = coercePEMorDerToPrivateKey(pem, passphrase);
            expect(key.hidden).toBeTruthy();
        });

        it("should be unaffected by the passphrase parameter for unencrypted input", async () => {
            const filename = path.join(tmpDir, "key.pem");
            await generatePrivateKeyFile(filename, 2048);
            const pem = fs.readFileSync(filename, "utf-8");

            const key = coercePEMorDerToPrivateKey(pem);
            expect(key.hidden).toBeTruthy();
        });
    });

    describe("NO_CREATE_PRIVATEKEY fallback path", () => {
        const originalEnv = process.env.NO_CREATE_PRIVATEKEY;

        afterEach(() => {
            if (originalEnv === undefined) {
                delete process.env.NO_CREATE_PRIVATEKEY;
            } else {
                process.env.NO_CREATE_PRIVATEKEY = originalEnv;
            }
        });

        it("should fail closed rather than silently returning the still-encrypted PEM", async () => {
            const filename = path.join(tmpDir, "key.pem");
            await generatePrivateKeyFile(filename, 2048, { passphrase: "some passphrase" });

            process.env.NO_CREATE_PRIVATEKEY = "1";
            expect(() => readPrivateKey(filename)).toThrow(PrivateKeyPassphraseRequiredError);
            expect(() => readPrivateKey(filename, "some passphrase")).toThrow(PrivateKeyPassphraseRequiredError);
        });

        it("should still return unencrypted key PEM text unchanged (pre-existing fallback behavior)", async () => {
            const filename = path.join(tmpDir, "key.pem");
            await generatePrivateKeyFile(filename, 2048);

            process.env.NO_CREATE_PRIVATEKEY = "1";
            const key = readPrivateKey(filename);
            expect(typeof key.hidden).toBe("string");
        });
    });

    describe("pemToPrivateKey (WebCrypto / browser path)", () => {
        it("should throw a clear, browser-specific error for an encrypted PEM rather than attempting decryption", async () => {
            const filename = path.join(tmpDir, "key.pem");
            await generatePrivateKeyFile(filename, 2048, { passphrase: "some passphrase" });
            const pem = fs.readFileSync(filename, "utf-8");

            await expect(pemToPrivateKey(pem)).rejects.toThrow(/not supported/i);
        });

        it("should still work for unencrypted input", async () => {
            const filename = path.join(tmpDir, "key.pem");
            await generatePrivateKeyFile(filename, 2048);
            const pem = fs.readFileSync(filename, "utf-8");

            const cryptoKey = await pemToPrivateKey(pem);
            expect(cryptoKey).toBeTruthy();
        });
    });
});
