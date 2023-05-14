import * as fs from "fs";
// import * as crypto from "crypto";

import { readPrivateKey } from "../source_nodejs";
import { explorePrivateKey } from "../source";
import {
    derToPrivateKey,
    generateKeyPair,
    generatePrivateKey,
    privateKeyToPEM,
} from "../source/x509/create_key_pair";

// https://kjur.github.io/jsrsasign/wikistatic/Tutorial-for-generating-X.509-certificate.html
describe("creating X509 key pair", function () {
    this.timeout(100000);

    it("should create a key pair", async () => {
        const { privateKey, publicKey } = await generateKeyPair();

        const { privPem, privDer } = await privateKeyToPEM(privateKey);

        //  const privPem = x509.PemConverter.encode(data);
        //  keys.publicKeys
        console.log(privPem);
        const tmpPrivateKey = "_tmp_privatekey.pem";
        await fs.promises.writeFile(tmpPrivateKey, privPem);

        const tmpPrivateKeyDER = "_tmp_privatekey.der";
        await fs.promises.writeFile(tmpPrivateKeyDER, Buffer.from(privDer));

        const p = readPrivateKey(tmpPrivateKey);
        const j = explorePrivateKey(p);
        console.log(j);

        // openssl asn1parse -in _tmp_privatekey.pem -inform pem -i
        // openssl asn1parse -in _tmp_privatekey.der -inform=der -strparse 22
    });
    it("derToPrivateKey", async () => {
        const privateKey = await generatePrivateKey();

        const { privPem, privDer } = await privateKeyToPEM(privateKey);
        const privateKey2 = await derToPrivateKey(privDer);
        const { privPem: privPem2 } = await privateKeyToPEM(privateKey2);
        console.log(privPem2);
        privPem2.should.eql(privPem);
    });

});
