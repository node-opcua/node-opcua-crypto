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

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import "should";

import {
    CertificatePurpose,
    createCertificateSigningRequest,
    exploreCertificateSigningRequest,
    generateKeyPair,
    readCertificate,
} from "node-opcua-crypto";

const tmpTestFolder = os.tmpdir();

describe("creating X509 certificate signing requests", function () {
    this.timeout(100000);

    it("should create a certificate", async () => {
        const { privateKey } = await generateKeyPair();
        const { csr } = await createCertificateSigningRequest({
            privateKey,
            notAfter: new Date(2020, 1, 1),
            notBefore: new Date(2019, 1, 1),
            subject: "CN=Test",
            dns: ["DNS1", "DNS2"],
            ip: ["192.168.1.1"],
            applicationUri: "urn:HOSTNAME:ServerDescription",
            purpose: CertificatePurpose.ForApplication,
        });

        console.log(csr); // Certificate in PEM format}
        const tmpCSRPemFile = path.join(tmpTestFolder, "_tmp_csr.pem");
        await fs.promises.writeFile(tmpCSRPemFile, csr);

        // openssl asn1parse -in _tmp_certificate.pem -inform pem -i
        // openssl x509 -in _tmp_certificate.pem -inform pem -out --text --noout
        //        const csr1 = readCertificateSigningRequest(tmpCSRPemFile);
        const csr1 = readCertificate(tmpCSRPemFile);

        const csrInfo = exploreCertificateSigningRequest(csr1);

        csrInfo.extensionRequest.subjectAltName.should.eql({
            uniformResourceIdentifier: ["urn:HOSTNAME:ServerDescription"],
            dNSName: ["DNS1", "DNS2"],
            iPAddress: ["c0a80101"],
        });
        csrInfo.extensionRequest.basicConstraints.cA.should.eql(false);
    });
});
