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
import {
    type CaSignAlgorithm,
    createCrl,
    exploreCertificateRevocationList,
    exploreCertificateSigningRequest,
    readCertificateRevocationList,
    readCertificateSigningRequest,
    x509,
} from "node-opcua-crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// A DER object is a SEQUENCE (0x30) followed by its length, which is
// short form (one byte, < 128) or long form (0x81 = one length byte,
// 0x82 = two, 0x83 = three...). The readers used to accept a file as DER
// only on "30 82", so a small CRL or CSR (an EC P-256 CA with few
// entries is under 256 bytes: "30 81") and a CRL over 64 KiB ("30 83")
// went down the PEM path and came back as an empty buffer.

const ecAlgorithm: CaSignAlgorithm = { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } };

async function generateEcKeyPair(): Promise<CryptoKeyPair> {
    return (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
}

async function makeEcCrl(entryCount: number) {
    const { privateKey, publicKey } = await generateEcKeyPair();
    const entries = [];
    for (let i = 0; i < entryCount; i++) {
        // 20-byte serials (the RFC 5280 maximum) make each entry about 40
        // bytes, so 2000 entries pass 64 KiB while staying under the 10000
        // node limit asn1js puts on what @peculiar/x509 parses back.
        const serialNumber = `01${i.toString(16).padStart(38, "0")}`;
        entries.push({ serialNumber, revocationDate: new Date("2026-01-01T00:00:00Z") });
    }
    const { crl, der } = await createCrl({
        issuerName: "CN=EcCA",
        issuerPublicKey: publicKey,
        signingKey: privateKey,
        signingAlgorithm: ecAlgorithm,
        crlNumber: 1,
        entries,
    });
    return { pem: crl, der: Buffer.from(der) };
}

async function makeEcCsr() {
    const keys = await generateEcKeyPair();
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: "CN=a",
        keys,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        // exploreCertificateSigningRequest expects an extensionRequest, which
        // an OPC UA CSR always has: the subjectAltName carries the
        // application URI.
        extensions: [new x509.SubjectAlternativeNameExtension([{ type: "url", value: "urn:a" }])],
    });
    return { pem: csr.toString("pem"), der: Buffer.from(csr.rawData) };
}

describe("reading a DER or PEM file whatever the DER length form", { timeout: 120000 }, () => {
    let tmpDir: string;
    beforeAll(async () => {
        tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "der-or-pem-"));
    });
    afterAll(async () => {
        await fs.promises.rm(tmpDir, { recursive: true, force: true });
    });
    async function writeFile(name: string, content: Buffer | string): Promise<string> {
        const filename = path.join(tmpDir, name);
        await fs.promises.writeFile(filename, content);
        return filename;
    }

    describe("readCertificateRevocationList", () => {
        it("reads a DER CRL under 256 bytes (short length form, 30 81)", async () => {
            const { der } = await makeEcCrl(1);
            expect(der.length).toBeLessThan(256);
            expect(der[1]).not.toEqual(0x82);

            const crl = await readCertificateRevocationList(await writeFile("small.crl", der));
            expect(crl.toString("hex")).toEqual(der.toString("hex"));
            expect(exploreCertificateRevocationList(crl).tbsCertList.revokedCertificates.length).toEqual(1);
        });

        it("reads a DER CRL followed by a trailing newline", async () => {
            const { der } = await makeEcCrl(0);
            const crl = await readCertificateRevocationList(
                await writeFile("trailing.crl", Buffer.concat([der, Buffer.from("\r\n")])),
            );
            expect(crl.toString("hex")).toEqual(der.toString("hex"));
        });

        it("reads a DER CRL over 64 KiB (three-byte length, 30 83)", async () => {
            const { der } = await makeEcCrl(2000);
            expect(der.length).toBeGreaterThan(65536);
            expect(der[1]).toEqual(0x83);

            const crl = await readCertificateRevocationList(await writeFile("large.crl", der));
            expect(crl.toString("hex")).toEqual(der.toString("hex"));
            expect(exploreCertificateRevocationList(crl).tbsCertList.revokedCertificates.length).toEqual(2000);
        });

        it("still reads a PEM CRL, whatever its file extension", async () => {
            const { pem, der } = await makeEcCrl(1);
            const crl1 = await readCertificateRevocationList(await writeFile("small_pem.pem", pem));
            expect(crl1.toString("hex")).toEqual(der.toString("hex"));
            const crl2 = await readCertificateRevocationList(await writeFile("small_pem.crl", pem));
            expect(crl2.toString("hex")).toEqual(der.toString("hex"));
        });

        it("keeps the PEM fallback for a file that starts like DER but whose length does not match", async () => {
            const { der } = await makeEcCrl(0);
            const crl = await readCertificateRevocationList(await writeFile("truncated.crl", der.subarray(0, der.length - 1)));
            expect(crl.length).toEqual(0);
        });
    });

    describe("readCertificateSigningRequest", () => {
        it("reads a DER CSR under 256 bytes (short length form, 30 81)", async () => {
            const { der } = await makeEcCsr();
            expect(der.length).toBeLessThan(256);
            expect(der[1]).not.toEqual(0x82);

            const csr = await readCertificateSigningRequest(await writeFile("small.csr", der));
            expect(csr.toString("hex")).toEqual(der.toString("hex"));
            expect(exploreCertificateSigningRequest(csr).extensionRequest.subjectAltName.uniformResourceIdentifier).toEqual([
                "urn:a",
            ]);
        });

        it("still reads a PEM CSR", async () => {
            const { pem, der } = await makeEcCsr();
            const csr = await readCertificateSigningRequest(await writeFile("small_pem.csr", pem));
            expect(csr.toString("hex")).toEqual(der.toString("hex"));
        });
    });
});
