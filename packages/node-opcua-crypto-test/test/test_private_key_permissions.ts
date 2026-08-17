import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generatePrivateKeyFile, generatePrivateKeyFileAlternate } from "node-opcua-crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const isWin32 = process.platform === "win32";
const modeBits = (filename: string) => fs.statSync(filename).mode & 0o777;

describe("private key file permissions", () => {
    let tmpDir: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "node-opcua-crypto-perms-"));
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    describe.skipIf(isWin32)("on POSIX", () => {
        it("generatePrivateKeyFile should create the key with mode 0600", async () => {
            const filename = path.join(tmpDir, "key1.pem");
            await generatePrivateKeyFile(filename, 2048);
            expect(modeBits(filename)).toBe(0o600);
        });

        it("generatePrivateKeyFile should repair a pre-existing loosely-permissioned file", async () => {
            const filename = path.join(tmpDir, "key2.pem");
            fs.writeFileSync(filename, "placeholder", { mode: 0o644 });
            expect(modeBits(filename)).toBe(0o644);

            await generatePrivateKeyFile(filename, 2048);
            expect(modeBits(filename)).toBe(0o600);
        });

        it("generatePrivateKeyFileAlternate should create the key with mode 0600", async () => {
            const filename = path.join(tmpDir, "key3.pem");
            await generatePrivateKeyFileAlternate(filename, 2048);
            expect(modeBits(filename)).toBe(0o600);
        });

        it("generatePrivateKeyFileAlternate should repair a pre-existing loosely-permissioned file", async () => {
            const filename = path.join(tmpDir, "key4.pem");
            fs.writeFileSync(filename, "placeholder", { mode: 0o644 });
            expect(modeBits(filename)).toBe(0o644);

            await generatePrivateKeyFileAlternate(filename, 2048);
            expect(modeBits(filename)).toBe(0o600);
        });
    });

    describe.skipIf(!isWin32)("on Windows", () => {
        it("generatePrivateKeyFile should not throw even though permission hardening is a no-op", async () => {
            const filename = path.join(tmpDir, "key1.pem");
            await generatePrivateKeyFile(filename, 2048);
            expect(fs.existsSync(filename)).toBe(true);
        });

        it("generatePrivateKeyFileAlternate should not throw even though permission hardening is a no-op", async () => {
            const filename = path.join(tmpDir, "key2.pem");
            await generatePrivateKeyFileAlternate(filename, 2048);
            expect(fs.existsSync(filename)).toBe(true);
        });
    });
});
