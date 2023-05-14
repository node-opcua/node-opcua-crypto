import * as fs from "fs";
import "should";

import { readCertificate } from "../source_nodejs";
import { generateKeyPair } from "../source/x509/create_key_pair";
import { createCertificateSigningRequest } from "../source/x509/create_certificate_signing_request";
import { exploreCertificateSigningRequest } from "..";
import { CertificatePurpose } from "../source/common";

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
            purpose: CertificatePurpose.ForApplication
        });

        console.log(csr); // Certificate in PEM format}
        const tmpCSRPemFile = "_tmp_csr.pem";
        await fs.promises.writeFile(tmpCSRPemFile, csr);

        // openssl asn1parse -in _tmp_certificate.pem -inform pem -i
        // openssl x509 -in _tmp_certificate.pem -inform pem -out --text --noout
//        const csr1 = readCertificateSigningRequest(tmpCSRPemFile);
        const csr1 = readCertificate(tmpCSRPemFile);

        const csrInfo = exploreCertificateSigningRequest(csr1);
        
        csrInfo.extensionRequest.subjectAltName.should.eql({
            uniformResourceIdentifier: ["urn:HOSTNAME:ServerDescription"],
            dNSName: ["DNS1", "DNS2"],
            iPAddress: ["c0a80101"]
        });
        csrInfo.extensionRequest.basicConstraints.cA.should.eql(false);
    });
});
