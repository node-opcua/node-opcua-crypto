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

import fs from "fs";
import util from "util";

import x509 from "@peculiar/x509";
import { readCertificate, readPrivateKey , CertificatePurpose, convertPEMtoDER, exploreCertificate, explorePrivateKey, generateKeyPair, pemToPrivateKey, privateKeyToPEM ,  createSelfSignedCertificate } from "..";

// https://kjur.github.io/jsrsasign/wikistatic/Tutorial-for-generating-X.509-certificate.html
describe("creating X509 self-signed certificates", function () {
    this.timeout(100000);

    it("should create a certificate", async () => {
        const { privateKey } = await generateKeyPair();
        const { cert } = await createSelfSignedCertificate({
            privateKey,
            purpose: CertificatePurpose.ForApplication,
        });

        console.log(cert); // Certificate in PEM format}
        const tmpCertificatePemFile = "_tmp_certificate.pem";
        await fs.promises.writeFile(tmpCertificatePemFile, cert);

        // openssl asn1parse -in _tmp_certificate.pem -inform pem -i
        // openssl x509 -in _tmp_certificate.pem -inform pem -out --text --noout

        const certificate = readCertificate(tmpCertificatePemFile);
        const info = exploreCertificate(Buffer.from(x509.PemConverter.decode(cert)[0]));

        console.log(util.inspect(info, { depth: 4 }));

        info.tbsCertificate.extensions!.keyUsage!.dataEncipherment.should.eql(true);
        info.tbsCertificate.extensions!.keyUsage!.digitalSignature.should.eql(true);
        info.tbsCertificate.extensions!.keyUsage!.cRLSign.should.eql(false);
    });
    it("should create a certificate with alternative names", async () => {
        const { privateKey } = await generateKeyPair();
        await createSelfSignedCertificate({
            privateKey,
            notAfter: new Date(2020, 1, 1),
            notBefore: new Date(2019, 1, 1),
            subject: "CN=Test",
            dns: ["DNS1", "DNS2"],
            ip: ["192.168.1.1"],
            applicationUri: "urn:HOSTNAME:ServerDescription",
            purpose: CertificatePurpose.ForApplication,
        });
    });
    it("should create a certificate with alternative names - (reloading private key) ", async () => {
        const tmpPrivateKeyFilename = "_tmp_privatekey.pem";
        {
            const { privateKey } = await generateKeyPair();
            const { privPem } = await privateKeyToPEM(privateKey);
            await fs.promises.writeFile(tmpPrivateKeyFilename, privPem);
        }

        const privateKeyPem = await fs.promises.readFile(tmpPrivateKeyFilename, "utf-8");
        const privateKey = await pemToPrivateKey(privateKeyPem);

        const { cert } = await createSelfSignedCertificate({
            privateKey,
            notAfter: new Date(2020, 1, 1),
            notBefore: new Date(2019, 1, 1),
            subject: "CN=Test",
            dns: ["DNS1", "DNS2"],
            ip: ["192.168.1.1"],
            applicationUri: "urn:HOSTNAME:ServerDescription",
            purpose: CertificatePurpose.ForApplication,
        });

        const info = exploreCertificate(convertPEMtoDER(cert));
        info.tbsCertificate.extensions?.subjectAltName.should.eql({
            dNSName: ["DNS1", "DNS2"],
            iPAddress: ["c0a80101"],
            uniformResourceIdentifier: ["urn:HOSTNAME:ServerDescription"],
        });
    });
});
