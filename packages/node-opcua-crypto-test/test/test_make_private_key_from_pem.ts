import path from "path";
import "should";
import {
    makePrivateKeyFromPem,
    generatePrivateKey,
    coercePrivateKeyPem,
    privateKeyToPEM,
    generatePrivateKeyFile,
    readPrivateKey,
    coercePEMorDerToPrivateKey,
    rsaLengthPrivateKey,
} from "node-opcua-crypto";

describe("makePrivateKeyFromPem", () => {
    it("should make a private key from pem", async () => {
        const privateKeySubtle = await generatePrivateKey(2048);

        const privateKeyPem = await privateKeyToPEM(privateKeySubtle);
        const privateKey = coercePEMorDerToPrivateKey(privateKeyPem.privPem);
        //  console.log(privateKeyPem.privPem);

        const pem = coercePrivateKeyPem(privateKey);

        const privateKey2 = makePrivateKeyFromPem(pem);
        const pem2 = coercePrivateKeyPem(privateKey2);
        pem2.trimEnd().should.eql(pem.trimEnd());

        rsaLengthPrivateKey(privateKey).should.eql(2048 / 8);
    });

    it("should make a private key from pem", async () => {
        const filename = path.join(__dirname, "tmp_private_key.pem");
        await generatePrivateKeyFile(filename, 2048);

        const privateKey = readPrivateKey(filename);
        const pem = coercePrivateKeyPem(privateKey);

        const privateKey2 = makePrivateKeyFromPem(pem);
        const pem2 = coercePrivateKeyPem(privateKey2);
        pem2.should.eql(pem);

        rsaLengthPrivateKey(privateKey).should.eql(2048 / 8);
    });
});
