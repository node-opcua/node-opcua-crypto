import * as fs from "fs";
import * as util from "util";
// import * as crypto from "crypto";

import * as x509 from "@peculiar/x509";
import { readCertificate, readPrivateKey } from "../source_nodejs";
import { CertificatePurpose, convertPEMtoDER, exploreCertificate, explorePrivateKey } from "../source";
import { generateKeyPair, pemToPrivateKey, privateKeyToPEM } from "../source/x509/create_key_pair";
import { createSelfSignedCertificate } from "../source/x509/create_self_signed_certificate";

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
