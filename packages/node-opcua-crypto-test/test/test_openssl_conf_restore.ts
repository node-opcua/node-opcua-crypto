import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generatePrivateKeyFile, readPrivateKey } from "node-opcua-crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// readPrivateKey points OPENSSL_CONF at /dev/null while node:crypto parses the
// key, then puts the previous value back. process.env stores every value as a
// string, so putting back an unset variable used to store the text
// "undefined": any openssl command started afterwards by the same process
// then failed with `Can't open "undefined" for reading`. A key that failed to
// parse left /dev/null behind instead.

const canDecryptEncryptedKeys = !process.env.NO_CREATE_PRIVATEKEY;

describe("readPrivateKey leaves OPENSSL_CONF as it found it", () => {
    let tmpDir: string;
    let saved: string | undefined;
    let keyFile: string;

    beforeEach(async () => {
        saved = process.env.OPENSSL_CONF;
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "node-opcua-crypto-openssl-conf-"));
        keyFile = path.join(tmpDir, "key.pem");
        await generatePrivateKeyFile(keyFile, 2048);
    });

    afterEach(() => {
        if (saved === undefined) {
            delete process.env.OPENSSL_CONF;
        } else {
            process.env.OPENSSL_CONF = saved;
        }
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('keeps an unset OPENSSL_CONF unset, not the string "undefined"', () => {
        delete process.env.OPENSSL_CONF;

        readPrivateKey(keyFile);

        expect("OPENSSL_CONF" in process.env).toBe(false);
        expect(process.env.OPENSSL_CONF).toBeUndefined();
    });

    it("puts back the value that was set", () => {
        process.env.OPENSSL_CONF = path.join(tmpDir, "openssl.cnf");

        readPrivateKey(keyFile);

        expect(process.env.OPENSSL_CONF).toBe(path.join(tmpDir, "openssl.cnf"));
    });

    it.skipIf(!canDecryptEncryptedKeys)("puts it back when the key cannot be read", async () => {
        const encrypted = path.join(tmpDir, "encrypted.pem");
        await generatePrivateKeyFile(encrypted, 2048, { passphrase: "right" });
        process.env.OPENSSL_CONF = path.join(tmpDir, "openssl.cnf");

        expect(() => readPrivateKey(encrypted, "wrong")).toThrow();

        expect(process.env.OPENSSL_CONF).toBe(path.join(tmpDir, "openssl.cnf"));
    });
});
