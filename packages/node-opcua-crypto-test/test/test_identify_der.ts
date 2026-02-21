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
    combine_der,
    convertPEMtoDER,
    identifyDERContent,
    readCertificate,
    readCertificateRevocationList,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

const fixturesDir = path.join(__dirname, "../test-fixtures");

describe("identifyDERContent", () => {
    // ── X.509 Certificates ────────────────────────────────────────

    describe("X.509 certificates", () => {
        it("should identify a DER-encoded X.509 v3 certificate", () => {
            const cert = readCertificate(
                path.join(fixturesDir, "certs/server_cert_1024.pem"),
            );
            expect(identifyDERContent(cert)).toBe("X509Certificate");
        });

        it("should identify a 2048-bit certificate chain (2 certs)", () => {
            const cert = readCertificate(
                path.join(fixturesDir, "certs/server_cert_2048.pem"),
            );
            // This PEM file contains 2 concatenated DER certificates
            expect(identifyDERContent(cert)).toBe("X509CertificateChain");
        });

        it("should identify a 4096-bit X.509 v3 certificate", () => {
            const cert = readCertificate(
                path.join(fixturesDir, "certs/demo_certificate_4096.pem"),
            );
            expect(identifyDERContent(cert)).toBe("X509Certificate");
        });

        it("should identify a self-signed X.509 v3 certificate", () => {
            const cert = readCertificate(
                path.join(fixturesDir, "certs/demo_certificate.pem"),
            );
            expect(identifyDERContent(cert)).toBe("X509Certificate");
        });

        it("should identify a X.509 v1 certificate", () => {
            const cert = readCertificate(
                path.join(
                    fixturesDir,
                    "certs/demo_certificate_x509_V1.pem",
                ),
            );
            expect(identifyDERContent(cert)).toBe("X509Certificate");
        });

        it("should identify a CA-signed X.509 v3 certificate", () => {
            const cert = readCertificate(
                path.join(fixturesDir, "certsChain/1000.pem"),
            );
            expect(identifyDERContent(cert)).toBe("X509Certificate");
        });

        it("should identify an ECC (prime256v1) certificate", () => {
            const cert = readCertificate(
                path.join(
                    fixturesDir,
                    "ecc_certificates/prime256_certif.pem",
                ),
            );
            expect(identifyDERContent(cert)).toBe("X509Certificate");
        });
    });

    // ── Certificate Chain ─────────────────────────────────────────

    describe("certificate chains", () => {
        it("should identify a chain of 2 concatenated certificates", () => {
            const cert1 = readCertificate(
                path.join(fixturesDir, "certs/client_cert_1024.pem"),
            );
            const cert2 = readCertificate(
                path.join(fixturesDir, "certs/server_cert_1024.pem"),
            );
            const chain = combine_der([cert1, cert2]);
            expect(identifyDERContent(chain)).toBe("X509CertificateChain");
        });

        it("should identify a chain of 3 concatenated certificates", () => {
            const cert1 = readCertificate(
                path.join(fixturesDir, "certs/client_cert_1024.pem"),
            );
            const cert2 = readCertificate(
                path.join(fixturesDir, "certs/server_cert_1024.pem"),
            );
            const cert3 = readCertificate(
                path.join(fixturesDir, "certs/demo_certificate_4096.pem"),
            );
            const chain = combine_der([cert1, cert2, cert3]);
            expect(identifyDERContent(chain)).toBe("X509CertificateChain");
        });

        it("should identify a CA certificate concatenated with its CRL", () => {
            const filename = path.join(
                fixturesDir,
                "certsChain/cacertificate_with_crl.pem",
            );
            const pem = fs.readFileSync(filename, "utf-8");
            const der = convertPEMtoDER(pem);
            // The first DER block is a certificate, and the
            // remaining data makes this look like a chain.
            const result = identifyDERContent(der);
            expect(
                result === "X509CertificateChain" ||
                result === "X509Certificate",
            ).toBe(true);
        });
    });

    // ── CRLs ──────────────────────────────────────────────────────

    describe("Certificate Revocation Lists", () => {
        it("should identify a v2 DER CRL", async () => {
            const crl = await readCertificateRevocationList(
                path.join(fixturesDir, "crl/certificate_revocation_list1.crl"),
            );
            expect(identifyDERContent(crl)).toBe(
                "CertificateRevocationList",
            );
        });

        it("should identify another v2 DER CRL", async () => {
            const crl = await readCertificateRevocationList(
                path.join(fixturesDir, "crl/certificate_revocation_list2.crl"),
            );
            expect(identifyDERContent(crl)).toBe(
                "CertificateRevocationList",
            );
        });

        it("should identify a PEM-encoded CRL", async () => {
            const crl = await readCertificateRevocationList(
                path.join(fixturesDir, "crl/certificate_revocation_list3.pem"),
            );
            expect(identifyDERContent(crl)).toBe(
                "CertificateRevocationList",
            );
        });

        it("should identify a v1 CRL (no version field)", async () => {
            const crl = await readCertificateRevocationList(
                path.join(fixturesDir, "crl/crl_version_1.pem"),
            );
            expect(identifyDERContent(crl)).toBe(
                "CertificateRevocationList",
            );
        });
    });

    // ── CSRs ──────────────────────────────────────────────────────

    describe("Certificate Signing Requests", () => {
        it("should identify a CSR (csr1.pem)", () => {
            const pem = fs.readFileSync(
                path.join(fixturesDir, "csr/csr1.pem"),
                "utf-8",
            );
            const der = convertPEMtoDER(pem);
            expect(identifyDERContent(der)).toBe(
                "CertificateSigningRequest",
            );
        });

        it("should identify a CSR (csr2.pem)", () => {
            const pem = fs.readFileSync(
                path.join(fixturesDir, "csr/csr2.pem"),
                "utf-8",
            );
            const der = convertPEMtoDER(pem);
            expect(identifyDERContent(der)).toBe(
                "CertificateSigningRequest",
            );
        });
    });

    // ── Private Keys ──────────────────────────────────────────────

    describe("Private Keys", () => {
        it("should identify a PEM-encoded RSA private key", () => {
            const pem = fs.readFileSync(
                path.join(fixturesDir, "certs/server_key_1024.pem"),
                "utf-8",
            );
            const der = convertPEMtoDER(pem);
            expect(identifyDERContent(der)).toBe("PrivateKey");
        });

        it("should identify a 2048-bit RSA private key", () => {
            const pem = fs.readFileSync(
                path.join(fixturesDir, "certs/server_key_2048.pem"),
                "utf-8",
            );
            const der = convertPEMtoDER(pem);
            expect(identifyDERContent(der)).toBe("PrivateKey");
        });
    });

    // ── PKCS#12 / PFX ─────────────────────────────────────────────

    describe("PKCS#12 / PFX files", () => {
        it("should identify a simple PFX (no password)", () => {
            const buf = fs.readFileSync(
                path.join(fixturesDir, "pfx/simple_no_password.pfx"),
            );
            expect(identifyDERContent(buf)).toBe("PKCS12");
        });

        it("should identify a password-protected PFX", () => {
            const buf = fs.readFileSync(
                path.join(fixturesDir, "pfx/with_password.pfx"),
            );
            expect(identifyDERContent(buf)).toBe("PKCS12");
        });

        it("should identify a PFX with CA chain", () => {
            const buf = fs.readFileSync(
                path.join(fixturesDir, "pfx/with_ca_chain.pfx"),
            );
            expect(identifyDERContent(buf)).toBe("PKCS12");
        });

        it("should identify a PFX with CA chain and password", () => {
            const buf = fs.readFileSync(
                path.join(
                    fixturesDir,
                    "pfx/with_ca_chain_password.pfx",
                ),
            );
            expect(identifyDERContent(buf)).toBe("PKCS12");
        });

        it("should identify an ECC PFX", () => {
            const buf = fs.readFileSync(
                path.join(fixturesDir, "pfx/ecc.pfx"),
            );
            expect(identifyDERContent(buf)).toBe("PKCS12");
        });

        it("should identify a PFX with friendly name", () => {
            const buf = fs.readFileSync(
                path.join(fixturesDir, "pfx/with_friendly_name.pfx"),
            );
            expect(identifyDERContent(buf)).toBe("PKCS12");
        });
    });

    // ── Edge Cases ────────────────────────────────────────────────

    describe("edge cases", () => {
        it("should return Unknown for an empty buffer", () => {
            expect(identifyDERContent(Buffer.alloc(0))).toBe("Unknown");
        });

        it("should return Unknown for a 1-byte buffer", () => {
            expect(identifyDERContent(Buffer.from([0x30]))).toBe("Unknown");
        });

        it("should return Unknown for random data", () => {
            const buf = Buffer.from("this is not a DER buffer");
            expect(identifyDERContent(buf)).toBe("Unknown");
        });

        it("should return Unknown for a buffer starting with a non-SEQUENCE tag", () => {
            const buf = Buffer.from([0x02, 0x01, 0x00]); // INTEGER
            expect(identifyDERContent(buf)).toBe("Unknown");
        });
    });
});
