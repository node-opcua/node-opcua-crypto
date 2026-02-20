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

import path from "node:path";
import {
    exploreCertificate,
    exploreCertificateRevocationList,
    isCrlIssuedByCertificate,
    readCertificate,
    readCertificateRevocationList,
    toPem,
    verifyCertificateRevocationListSignature,
    verifyCertificateSignature,
    verifyCrlIssuedByCertificate,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

describe("Explore Certificate Revocation List", () => {
    it("should read and explore a PEM revocation list", async () => {
        const crlFilename = path.join(__dirname, "../test-fixtures/crl/certificate_revocation_list3.pem");
        const crl = await readCertificateRevocationList(crlFilename);

        const crlInfo = exploreCertificateRevocationList(crl);
        expect(crlInfo.tbsCertList.issuerFingerprint).toEqual("67:EB:EB:D2:54:93:17:8B:5F:D7:63:7A:6D:A7:CD:DD:B9:D2:C6:CD");
        expect(crlInfo.tbsCertList.revokedCertificates.length).toEqual(0);
    });
    it("should explore crl1 ", async () => {
        const crlFilename = path.join(__dirname, "../test-fixtures/crl/certificate_revocation_list1.crl");
        const crl = await readCertificateRevocationList(crlFilename);

        const crlInfo = exploreCertificateRevocationList(crl);

        expect(crlInfo.tbsCertList.issuerFingerprint).toEqual("AF:FE:C7:57:6C:85:65:59:2F:35:C5:21:10:38:8A:2C:62:0C:D5:DD");
        expect(crlInfo.tbsCertList.revokedCertificates.length).toEqual(4);

        expect(crlInfo.tbsCertList.revokedCertificates[0].userCertificate).toEqual("03");
        expect(crlInfo.tbsCertList.revokedCertificates[0].revocationDate.toISOString()).toEqual("2019-11-15T09:04:16.000Z");

        expect(crlInfo.tbsCertList.revokedCertificates[1].userCertificate).toEqual("04");
        expect(crlInfo.tbsCertList.revokedCertificates[1].revocationDate.toISOString()).toEqual("2019-11-15T09:04:19.000Z");

        expect(crlInfo.tbsCertList.revokedCertificates[2].userCertificate).toEqual("07");
        expect(crlInfo.tbsCertList.revokedCertificates[2].revocationDate.toISOString()).toEqual("2019-11-15T09:04:27.000Z");

        expect(crlInfo.tbsCertList.revokedCertificates[3].userCertificate).toEqual("08");
        expect(crlInfo.tbsCertList.revokedCertificates[3].revocationDate.toISOString()).toEqual("2019-11-15T09:04:30.000Z");

        expect(crlInfo.signatureAlgorithm.identifier).toEqual("sha256WithRSAEncryption");
        expect(crlInfo.tbsCertList.signature.identifier).toEqual("sha256WithRSAEncryption");
    });
    it("should verify a CRL signature", async () => {
        const crlFilename = path.join(__dirname, "../test-fixtures/crl/certificate_revocation_list1.crl");

        const crl = await readCertificateRevocationList(crlFilename);
        const crlInfo = exploreCertificateRevocationList(crl);

        const issuerCertifcateFile = path.join(__dirname, "../test-fixtures/crl/ctt_ca1I.der");

        const certificateOfIssuer = await readCertificate(issuerCertifcateFile);
        const certificateOfIssuerInfo = await exploreCertificate(certificateOfIssuer);

        expect(crlInfo.tbsCertList.issuerFingerprint).toEqual("AF:FE:C7:57:6C:85:65:59:2F:35:C5:21:10:38:8A:2C:62:0C:D5:DD");
        expect(certificateOfIssuerInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.authorityCertIssuerFingerPrint).toEqual(
            "AF:FE:C7:57:6C:85:65:59:2F:35:C5:21:10:38:8A:2C:62:0C:D5:DD",
        );
        expect(certificateOfIssuerInfo.tbsCertificate.subjectFingerPrint).toEqual(
            "AF:FE:C7:57:6C:85:65:59:2F:35:C5:21:10:38:8A:2C:62:0C:D5:DD",
        );

        verifyCertificateSignature(certificateOfIssuer, certificateOfIssuer);

        expect(verifyCertificateRevocationListSignature(crl, certificateOfIssuer)).toEqual(true);
    });
    it("should load a crl PEM", async () => {
        const crlFilename = path.join(__dirname, "../test-fixtures/crl/certificate_revocation_list4.pem");
        const crl = await readCertificateRevocationList(crlFilename);
        const crlInfo = await exploreCertificateRevocationList(crl);
        console.log(crlInfo);
    });

    it("should convert a DER CRL to PEM", async () => {
        const crlFilename = path.join(__dirname, "../test-fixtures/crl/certificate_revocation_list1.crl");
        const crl = await readCertificateRevocationList(crlFilename);

        const crlPem = toPem(crl, "X509 CRL");
        expect(crlPem).toMatch(/BEGIN X509 CRL/);
    });

    it("CRLBAD - should read and explore a PEM revocation list - node-opcua#1127", async () => {
        const crlFilename = path.join(__dirname, "../test-fixtures/crl/crl_version_1.pem");
        const crl = await readCertificateRevocationList(crlFilename);
        const crlInfo = exploreCertificateRevocationList(crl);
        expect(crlInfo.tbsCertList.revokedCertificates.length).toEqual(0);
    });
});

describe("CRL-to-Issuer Matching", () => {
    const crl1Filename = path.join(__dirname, "../test-fixtures/crl/certificate_revocation_list1.crl");
    const crl3Filename = path.join(__dirname, "../test-fixtures/crl/certificate_revocation_list3.pem");
    const issuerCertFilename = path.join(__dirname, "../test-fixtures/crl/ctt_ca1I.der");
    const unrelatedCertFilename = path.join(__dirname, "../test-fixtures/certs/demo_certificate.pem");

    it("isCrlIssuedByCertificate should return true for matching CRL and issuer", async () => {
        const crl = await readCertificateRevocationList(crl1Filename);
        const issuerCert = await readCertificate(issuerCertFilename);
        expect(isCrlIssuedByCertificate(crl, issuerCert)).toBe(true);
    });

    it("isCrlIssuedByCertificate should return false for non-matching certificate", async () => {
        const crl = await readCertificateRevocationList(crl1Filename);
        const unrelatedCert = await readCertificate(unrelatedCertFilename);
        expect(isCrlIssuedByCertificate(crl, unrelatedCert)).toBe(false);
    });

    it("isCrlIssuedByCertificate should return false when CRL has different issuer", async () => {
        const crl = await readCertificateRevocationList(crl3Filename);
        const issuerCert = await readCertificate(issuerCertFilename);
        // crl3 has issuerFingerprint 67:EB:... while ctt_ca1I has AF:FE:...
        expect(isCrlIssuedByCertificate(crl, issuerCert)).toBe(false);
    });

    it("verifyCrlIssuedByCertificate should return true for matching CRL with valid signature", async () => {
        const crl = await readCertificateRevocationList(crl1Filename);
        const issuerCert = await readCertificate(issuerCertFilename);
        expect(verifyCrlIssuedByCertificate(crl, issuerCert)).toBe(true);
    });

    it("verifyCrlIssuedByCertificate should return false for non-matching certificate", async () => {
        const crl = await readCertificateRevocationList(crl1Filename);
        const unrelatedCert = await readCertificate(unrelatedCertFilename);
        // Fingerprint mismatch: short-circuits before signature check
        expect(verifyCrlIssuedByCertificate(crl, unrelatedCert)).toBe(false);
    });

    it("verifyCrlIssuedByCertificate should return false when CRL has different issuer", async () => {
        const crl = await readCertificateRevocationList(crl3Filename);
        const issuerCert = await readCertificate(issuerCertFilename);
        expect(verifyCrlIssuedByCertificate(crl, issuerCert)).toBe(false);
    });
});
