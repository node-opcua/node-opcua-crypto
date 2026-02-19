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
import path from "node:path";
import {
    CertificatePurpose,
    combine_der,
    convertPEMtoDER,
    createSelfSignedCertificate,
    exploreAsn1,
    exploreCertificate,
    generatePrivateKeyFile,
    pemToPrivateKey,
    readCertificate,
    readCertificatePEM,
    split_der,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

describe(" exploring Certificates", { timeout: 200000 }, () => {
    it("should extract the information out of a 1024-bits certificate", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/certs/server_cert_1024.pem"));

        const certificate_info = exploreCertificate(certificate);

        console.log(" Version                   : ", certificate_info.tbsCertificate.version);
        console.log(" issuer.commonName         : ", certificate_info.tbsCertificate.issuer.commonName);
        console.log(
            " uniformResourceIdentifier : ",
            certificate_info.tbsCertificate.extensions?.subjectAltName?.uniformResourceIdentifier,
        );
        console.log(" dNSName                   : ", certificate_info.tbsCertificate.extensions?.subjectAltName?.dNSName);

        expect(certificate_info.tbsCertificate.version).toEqual(3);
        expect(certificate_info.tbsCertificate.subjectPublicKeyInfo.keyLength).toEqual(128);
        expect(certificate_info.tbsCertificate.extensions?.subjectAltName?.uniformResourceIdentifier?.length).toEqual(1);
    });

    it("should extract the information out of a 2048-bits certificate ", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/certs/server_cert_2048.pem"));

        const certificate_info = exploreCertificate(certificate);

        expect(certificate_info.tbsCertificate.version).toEqual(3);
        expect(certificate_info.tbsCertificate.subjectPublicKeyInfo.keyLength).toEqual(256);
        expect(certificate_info.tbsCertificate.extensions?.subjectAltName?.uniformResourceIdentifier).toBeDefined();
        expect(certificate_info.tbsCertificate.extensions?.subjectAltName?.uniformResourceIdentifier?.length).toEqual(1);
    });

    it("should extract the information out of a 4096-bits certificate - 1", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/certs/demo_certificate_4096.pem"));

        const certificate_info = exploreCertificate(certificate);

        expect(certificate_info.tbsCertificate.version).toEqual(3);
        expect(certificate_info.tbsCertificate.subjectPublicKeyInfo.keyLength).toEqual(512);
    });

    it("should read a V3 X509 self-certificate (with extensions)", () => {
        const filename = path.join(__dirname, "../test-fixtures/certs/demo_certificate.pem");
        expect(fs.existsSync(filename)).toBe(true);

        const certificate = readCertificate(filename);

        const certificate_info = exploreCertificate(certificate);

        expect(certificate_info.tbsCertificate.version).toEqual(3);

        expect(certificate_info.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuer).toBeDefined();
        expect(certificate_info.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuer?.countryName).toEqual("FR");
        expect(certificate_info.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuer?.localityName).toBeDefined();
        expect(certificate_info.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuer?.localityName).toEqual(
            "Paris",
        );

        expect(certificate_info.tbsCertificate.extensions?.subjectKeyIdentifier).toBeDefined();
        expect(certificate_info.tbsCertificate.extensions?.subjectKeyIdentifier).toEqual(
            "74:38:FD:90:B1:F1:90:51:0E:9C:65:D6:AA:AC:63:9E:BC:DC:58:2F",
        );

        if (certificate_info.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier) {
            expect(certificate_info.tbsCertificate.extensions.authorityKeyIdentifier.serial).toBeDefined();
            expect(certificate_info.tbsCertificate.extensions.authorityKeyIdentifier.keyIdentifier).toBeDefined();
        }
    });
    it("should read a V3 X509 certificate  signed by ta CA (with extensions)", () => {
        const filename = path.join(__dirname, "../test-fixtures/certsChain/1000.pem");
        expect(fs.existsSync(filename)).toBe(true);

        const certificate = readCertificate(filename);

        const certificate_info = exploreCertificate(certificate);

        expect(certificate_info.tbsCertificate.version).toEqual(3);

        expect(certificate_info.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuer?.countryName).toEqual("FR");
        expect(certificate_info.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuer?.localityName).toEqual(
            "Paris",
        );

        expect(certificate_info.tbsCertificate.extensions?.subjectKeyIdentifier).toBeDefined();
        expect(certificate_info.tbsCertificate.extensions?.subjectKeyIdentifier).toEqual(
            "B2:75:61:AF:63:66:27:96:94:52:3F:BD:03:DB:87:01:71:DD:94:19",
        );

        if (certificate_info.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier) {
            expect(certificate_info.tbsCertificate.extensions?.authorityKeyIdentifier?.serial).toBeDefined();
            expect(certificate_info.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier).toBeDefined();
        }
    });

    it("should read a V1 X509 certificate", () => {
        const filename = path.join(__dirname, "../test-fixtures/certs/demo_certificate_x509_V1.pem");
        expect(fs.existsSync(filename)).toBe(true);

        const certificate = readCertificate(filename);
        const certificate_info = exploreCertificate(certificate);

        expect(certificate_info.tbsCertificate.version).toEqual(1);
        expect(certificate_info.tbsCertificate.extensions).toEqual(null);
    });

    it("investigate certificate with block problem 1", () => {
        const filename = path.join(__dirname, "../test-fixtures/certs/certificate_with_block_issue.pem");
        expect(fs.existsSync(filename)).toBe(true);

        const certificate = readCertificate(filename);
        const certificate_info = exploreCertificate(certificate);

        expect(certificate_info.tbsCertificate.version).toEqual(3);
        expect(certificate_info.tbsCertificate.extensions).toEqual(null);
    });
    it("investigate certificate with block problem 2", () => {
        const filename = path.join(__dirname, "../test-fixtures/certs/certificate_with_block_issue2.pem");
        expect(fs.existsSync(filename)).toBe(true);

        const certificate = readCertificate(filename);
        const certificate_info = exploreCertificate(certificate);

        expect(certificate_info.tbsCertificate.version).toEqual(3);
        expect(certificate_info.tbsCertificate.extensions).not.toEqual(null);
    });

    it("AFS-01 investigate certificate with block problem 3", () => {
        const filename = path.join(__dirname, "../test-fixtures/certs/strange-certificate.pem");
        const certificatePem = readCertificatePEM(filename);
        const certificate = convertPEMtoDER(certificatePem);
        exploreAsn1(certificate);
        console.log(certificate.toString("base64"));
        const _certificate_info = exploreCertificate(certificate);
    });

    it("PEC-1: investigate certificate generated by @peculiar/webcrypto", () => {
        const content = fs.readFileSync(path.join(__dirname, "../test-fixtures/peculiar_cert_in_base64.txt"), "utf-8");
        const certificate = Buffer.from(content, "base64");
        const _info = exploreCertificate(certificate);
    });

    it("PEC-2 create a certificate with subtle and explore it with @peculiar/x509", async () => {
        // generate private key , not using SSL
        if (!fs.existsSync(path.join(__dirname, "../tmp"))) {
            fs.mkdirSync(path.join(__dirname, "../tmp"));
        }
        const privateKeyFilename = path.join(__dirname, "../tmp/pec2-privatekey.pem");

        await generatePrivateKeyFile(privateKeyFilename, 2048);

        const privateKeyPem = await fs.promises.readFile(privateKeyFilename, "utf-8");
        const privateKey = await pemToPrivateKey(privateKeyPem);

        const startDate = new Date(2020, 1, 20);
        const endDate = new Date(2021, 1, 2);
        const validity = 365;
        const dns: string[] = [];
        const ip: string[] = [];
        const subject = "CN=TOTO";
        const applicationUri = "uri:application";
        const purpose = CertificatePurpose.ForApplication;
        const { cert } = await createSelfSignedCertificate({
            privateKey,
            notBefore: startDate,
            notAfter: endDate,
            validity: validity,
            dns,
            ip,
            subject,
            applicationUri: applicationUri,
            purpose,
        });

        const certificateDer = convertPEMtoDER(cert);
        const _info = exploreCertificate(certificateDer);
    });
});

describe("exploring certificate chains", () => {
    it("should combine 2 certificates in a single block", () => {
        const cert1_name = path.join(__dirname, "../test-fixtures/certs/client_cert_1024.pem");
        const cert2_name = path.join(__dirname, "../test-fixtures/certs/server_cert_1024.pem");

        expect(fs.existsSync(cert1_name)).toEqual(true);
        expect(fs.existsSync(cert2_name)).toEqual(true);

        const cert1 = readCertificate(cert1_name);
        const cert2 = readCertificate(cert2_name);

        const combined = combine_der([cert1, cert2]);
        expect(combined.toString("hex")).toBe(cert1.toString("hex") + cert2.toString("hex"));

        expect(combined.length).toEqual(cert1.length + cert2.length);

        const chain = split_der(combined);

        expect(chain.length).toEqual(2);

        // biome-ignore lint/correctness/noConstantCondition: this is for debugging purpose
        if (false) {
            console.log(chain[0].toString("hex"));
            console.log(cert1.toString("hex"));
            console.log("-------");
            console.log(chain[1].toString("hex"));
            console.log(cert2.toString("hex"));
        }
        expect(chain[0].length).toEqual(cert1.length);
        expect(chain[1].length).toEqual(cert2.length);

        expect(chain[0].toString("hex")).toEqual(cert1.toString("hex"));
        expect(chain[1].toString("hex")).toEqual(cert2.toString("hex"));
    });

    it("should combine 3 certificates in a single block", () => {
        const cert1_name = path.join(__dirname, "../test-fixtures/certs/client_cert_1024.pem");
        const cert2_name = path.join(__dirname, "../test-fixtures/certs/server_cert_1024.pem");
        const cert3_name = path.join(__dirname, "../test-fixtures/certs/client_cert_1024.pem");

        expect(fs.existsSync(cert1_name)).toEqual(true);
        expect(fs.existsSync(cert2_name)).toEqual(true);
        expect(fs.existsSync(cert3_name)).toEqual(true);

        const cert1 = readCertificate(cert1_name);
        const cert2 = readCertificate(cert2_name);
        const cert3 = readCertificate(cert3_name);

        const combined = combine_der([cert1, cert2, cert3]);
        expect(combined.toString("hex")).toBe(cert1.toString("hex") + cert2.toString("hex") + cert3.toString("hex"));

        expect(combined.length).toEqual(cert1.length + cert2.length + cert3.length);

        const chain = split_der(combined);

        expect(chain.length).toEqual(3);

        // biome-ignore lint/correctness/noConstantCondition: this is for debugging purpose
        if (false) {
            console.log(chain[0].toString("hex"));
            console.log(cert1.toString("hex"));
            console.log("-------");
            console.log(chain[1].toString("hex"));
            console.log(cert2.toString("hex"));
            console.log("-------");
            console.log(chain[2].toString("hex"));
            console.log(cert3.toString("hex"));
        }
        expect(chain[0].length).toEqual(cert1.length);
        expect(chain[1].length).toEqual(cert2.length);
        expect(chain[2].length).toEqual(cert3.length);

        expect(chain[0].toString("hex")).toEqual(cert1.toString("hex"));
        expect(chain[1].toString("hex")).toEqual(cert2.toString("hex"));
        expect(chain[2].toString("hex")).toEqual(cert3.toString("hex"));
    });
});

describe("explore ECC certificates", () => {
    it("should extract information from a prime256v1 ECC certificate", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/ecc_certificates/prime256_certif.pem"));
        const certificate_info = exploreCertificate(certificate);
        console.log(" Version                   : ", certificate_info.tbsCertificate.version);
        console.log(" issuer.countryName        : ", certificate_info.tbsCertificate.issuer.countryName);

        expect(certificate_info.tbsCertificate.version).toEqual(3);
        expect(certificate_info.tbsCertificate.subjectPublicKeyInfo.keyLength).toEqual(64);
    });
    it("should do the same but with a brainpool256r1 certificate", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/ecc_certificates/brainpool256_certif.pem"));

        const certificate_info = exploreCertificate(certificate);
        expect(certificate_info.tbsCertificate.subjectPublicKeyInfo.algorithm).toEqual("brainpoolP256r1");
        expect(certificate_info.tbsCertificate.subjectPublicKeyInfo.keyLength).toEqual(64);
    });
    it("should do the same but with a brainpoolP384r1 certificate", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/ecc_certificates/brainpoolP384r1_certif.pem"));

        const certificate_info = exploreCertificate(certificate);
        expect(certificate_info.tbsCertificate.subjectPublicKeyInfo.algorithm).toEqual("brainpoolP384r1");
        expect(certificate_info.tbsCertificate.subject.organizationName).toEqual("Sterfive");
        expect(certificate_info.tbsCertificate.subjectPublicKeyInfo.keyLength).toEqual(96);
    });
});
