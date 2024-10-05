// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2024 - Sterfive.com
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

import path from "node:path";
import { exploreCertificate, explorePrivateKey } from "node-opcua-crypto";
import { publicKeyAndPrivateKeyMatches, certificateMatchesPrivateKey } from "node-opcua-crypto";
import { readCertificate, readPrivateKey } from "node-opcua-crypto";

const useCases = [1024, 2048];
describe("Checking that public key (from certificate) and private key matches", function () {
    useCases.forEach((keyLength) => {
        const certificateFile = path.join(__dirname, `../test-fixtures/certs/server_cert_${keyLength}.pem`);
        const privateKeyFile = path.join(__dirname, `../test-fixtures/certs/server_key_${keyLength}.pem`);
        const certificate = readCertificate(certificateFile);
        const privateKey = readPrivateKey(privateKeyFile);
        it("publicKeyAndPrivateKeyMatches: should explore a RSA private key " + keyLength, () => {
            const i = exploreCertificate(certificate);
            const j = explorePrivateKey(privateKey);

            //  const ii = readSubjectPublicKey(i.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey);

            const modulus1 = i.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.modulus;
            const modulus2 = j.modulus;

            modulus1.length.should.eql(keyLength / 8);
            modulus1.toString("hex").should.eql(modulus2.toString("hex"));

            publicKeyAndPrivateKeyMatches(certificate, privateKey).should.eql(true);
        });
        it("certificateMatchesPrivateKey: " + keyLength, () => {
            certificateMatchesPrivateKey(certificate, privateKey).should.eql(true);
        });
    });
});
