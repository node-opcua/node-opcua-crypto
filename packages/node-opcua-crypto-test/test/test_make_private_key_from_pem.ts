import path from "node:path";
import {
    coercePEMorDerToPrivateKey,
    coercePrivateKeyPem,
    generatePrivateKey,
    generatePrivateKeyFile,
    makePrivateKeyFromPem,
    privateKeyToPEM,
    readPrivateKey,
    rsaLengthPrivateKey,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

describe("makePrivateKeyFromPem", () => {
    it("should make a private key from pem", async () => {
        const privateKeySubtle = await generatePrivateKey(2048);

        const privateKeyPem = await privateKeyToPEM(privateKeySubtle);
        const privateKey = coercePEMorDerToPrivateKey(privateKeyPem.privPem);
        //  console.log(privateKeyPem.privPem);

        const pem = coercePrivateKeyPem(privateKey);

        const privateKey2 = makePrivateKeyFromPem(pem);
        const pem2 = coercePrivateKeyPem(privateKey2);
        expect(pem2.trimEnd()).toEqual(pem.trimEnd());

        expect(rsaLengthPrivateKey(privateKey)).toEqual(2048 / 8);
    });

    it("should make a private key from pem", async () => {
        const filename = path.join(__dirname, "tmp_private_key.pem");
        await generatePrivateKeyFile(filename, 2048);

        const privateKey = readPrivateKey(filename);
        const pem = coercePrivateKeyPem(privateKey);

        const privateKey2 = makePrivateKeyFromPem(pem);
        const pem2 = coercePrivateKeyPem(privateKey2);
        expect(pem2).toEqual(pem);

        expect(rsaLengthPrivateKey(privateKey)).toEqual(2048 / 8);
    });
});
