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

import {
    type CaSignAlgorithm,
    CertificatePurpose,
    createCertificateFromCsr,
    createCertificateSigningRequest,
    createCrl,
    createSelfSignedCertificate,
    generateKeyPair,
    LocalPrivateKeySigner,
    x509,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

const rsaAlgorithm: CaSignAlgorithm = { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } };

async function makeCa() {
    const { privateKey, publicKey } = await generateKeyPair();
    const signer = new LocalPrivateKeySigner({ privateKey, publicKey }, rsaAlgorithm);
    const { cert: caCertPem } = await createSelfSignedCertificate({
        privateKey,
        subject: "CN=TestCA",
        purpose: CertificatePurpose.ForCertificateAuthority,
    });
    return { signer, publicKey, caCertPem };
}

describe("createCertificateFromCsr / createCrl", { timeout: 60000 }, () => {
    it("signs a CSR into an end-entity certificate that chains to the issuing CA", async () => {
        const { signer, publicKey: issuerPublicKey, caCertPem } = await makeCa();

        const { privateKey: leafPrivateKey } = await generateKeyPair();
        const { csr } = await createCertificateSigningRequest({
            privateKey: leafPrivateKey,
            subject: "CN=Leaf",
            dns: ["localhost"],
            applicationUri: "urn:test:leaf",
            purpose: CertificatePurpose.ForApplication,
        });

        const { cert: leafCertPem } = await createCertificateFromCsr({
            csr,
            issuerName: "CN=TestCA",
            issuerPublicKey,
            signingKey: signer,
            signingAlgorithm: rsaAlgorithm,
            purpose: CertificatePurpose.ForApplication,
            dns: ["localhost"],
            applicationUri: "urn:test:leaf",
        });

        const leafCert = new x509.X509Certificate(leafCertPem);
        const caCert = new x509.X509Certificate(caCertPem);

        expect(leafCert.subject).toEqual("CN=Leaf");
        expect(leafCert.issuer).toEqual("CN=TestCA");

        const chainIsValid = await leafCert.verify({ publicKey: caCert.publicKey });
        expect(chainIsValid).toEqual(true);

        // wrong issuer key must NOT verify
        const { publicKey: unrelatedPublicKey } = await generateKeyPair();
        const chainIsValidAgainstWrongKey = await leafCert.verify({ publicKey: unrelatedPublicKey });
        expect(chainIsValidAgainstWrongKey).toEqual(false);
    });

    it("refuses to sign a CSR whose signature does not verify", async () => {
        const { signer, publicKey: issuerPublicKey } = await makeCa();

        const { privateKey: leafPrivateKey } = await generateKeyPair();
        const { der: csrDer } = await createCertificateSigningRequest({
            privateKey: leafPrivateKey,
            subject: "CN=Leaf",
            purpose: CertificatePurpose.ForApplication,
        });

        // corrupt one byte inside the signature to break verification
        const tampered = new Uint8Array(csrDer.rawData ?? csrDer);
        tampered[tampered.length - 5] ^= 0xff;

        await expect(
            createCertificateFromCsr({
                csr: tampered,
                issuerName: "CN=TestCA",
                issuerPublicKey,
                signingKey: signer,
                signingAlgorithm: rsaAlgorithm,
                purpose: CertificatePurpose.ForApplication,
            }),
        ).rejects.toThrow(/signature does not verify/);
    });

    it("builds a signed CRL listing the revoked serial, with a CRL number and Authority Key Identifier", async () => {
        const { signer, publicKey: issuerPublicKey, caCertPem } = await makeCa();
        const caCert = new x509.X509Certificate(caCertPem);

        const { crl: crlPem } = await createCrl({
            issuerName: "CN=TestCA",
            issuerPublicKey,
            signingKey: signer,
            signingAlgorithm: rsaAlgorithm,
            crlNumber: 1,
            entries: [{ serialNumber: "0102030405", reason: x509.X509CrlReason.keyCompromise }],
        });

        const crl = new x509.X509Crl(crlPem);
        expect(crl.issuer).toEqual("CN=TestCA");

        const crlIsValid = await crl.verify({ publicKey: caCert.publicKey });
        expect(crlIsValid).toEqual(true);

        const entry = crl.findRevoked("0102030405");
        expect(entry).not.toBeNull();
        expect(entry?.reason).toEqual(x509.X509CrlReason.keyCompromise);

        expect(crl.getExtension("2.5.29.20")).not.toBeNull();
        expect(crl.getExtension("2.5.29.35")).not.toBeNull(); // authorityKeyIdentifier

        // @peculiar/x509's own X509Crl.toString("pem") emits the
        // non-standard "-----BEGIN CRL-----" label; openssl's `crl` command
        // only recognizes RFC 7468's "X509 CRL" label and rejects the
        // other one outright ("Could not find CRL from ..."). This pins
        // createCrl's output to the label openssl actually accepts.
        expect(crlPem.startsWith("-----BEGIN X509 CRL-----")).toEqual(true);
        expect(crlPem.trim().endsWith("-----END X509 CRL-----")).toEqual(true);
    });

    it("createCertificateFromCsr and createCrl accept a raw CryptoKey signingKey, not just a CaSigner", async () => {
        const { privateKey: caPrivateKey, publicKey: caPublicKey } = await generateKeyPair();
        const { cert: caCertPem } = await createSelfSignedCertificate({
            privateKey: caPrivateKey,
            subject: "CN=RawKeyCA",
            purpose: CertificatePurpose.ForCertificateAuthority,
        });
        const caCert = new x509.X509Certificate(caCertPem);

        const { privateKey: leafPrivateKey } = await generateKeyPair();
        const { csr } = await createCertificateSigningRequest({
            privateKey: leafPrivateKey,
            subject: "CN=Leaf2",
            purpose: CertificatePurpose.ForApplication,
        });

        const { cert: leafCertPem } = await createCertificateFromCsr({
            csr,
            issuerName: "CN=RawKeyCA",
            issuerPublicKey: caPublicKey,
            signingKey: caPrivateKey,
            signingAlgorithm: rsaAlgorithm,
            purpose: CertificatePurpose.ForApplication,
        });
        const leafCert = new x509.X509Certificate(leafCertPem);
        expect(await leafCert.verify({ publicKey: caCert.publicKey })).toEqual(true);

        const { crl: crlPem } = await createCrl({
            issuerName: "CN=RawKeyCA",
            issuerPublicKey: caPublicKey,
            signingKey: caPrivateKey,
            signingAlgorithm: rsaAlgorithm,
            crlNumber: 1,
            entries: [],
        });
        const crl = new x509.X509Crl(crlPem);
        expect(await crl.verify({ publicKey: caCert.publicKey })).toEqual(true);
    });
});
