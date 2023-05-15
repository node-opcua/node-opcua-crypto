// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2023 - Sterfive.com
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

import * as fs from "fs";
// import * as crypto from "crypto";

import { readPrivateKey } from "../source_nodejs";
import { explorePrivateKey } from "../source";
import { derToPrivateKey, generateKeyPair, generatePrivateKey, privateKeyToPEM } from "../source/x509/create_key_pair";

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
