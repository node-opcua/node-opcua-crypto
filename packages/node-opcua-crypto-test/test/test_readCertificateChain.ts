import fs from "node:fs";
import path from "node:path";
import {
    certificatesToDer,
    certificatesToPem,
    exploreCertificate,
    readCertificate,
    readCertificateChain,
    readCertificateChainAsync,
    split_der,
    verifyCertificateChain,
    writeCertificateChain,
    writeCertificateChainAsync,
    writeCertificateChainDer,
} from "node-opcua-crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { toPemBuggy } from "./helpers/toPemBuggy";

const fixturesDir = path.join(__dirname, "../test-fixtures");
const certsChainDir = path.join(fixturesDir, "certsChain");
const derCertFile = path.join(fixturesDir, "NodeOPCUA [40BA2E8A5BEEC90067A7E554C5F3F2ECDD5BCDDF].der");

// Multi-cert PEM fixture — created once before all tests
const multiCertPemFile = path.join(__dirname, "../tmp/multi_cert_chain.pem");

describe("readCertificateChain", () => {
    beforeAll(() => {
        // Create a multi-cert PEM fixture by concatenating leaf + CA
        const leafPem = fs.readFileSync(path.join(certsChainDir, "1000.pem"), "utf-8");
        const caPem = fs.readFileSync(path.join(certsChainDir, "cacert.pem"), "utf-8");
        const combined = `${leafPem.trimEnd()}\n${caPem.trimEnd()}\n`;
        fs.mkdirSync(path.dirname(multiCertPemFile), { recursive: true });
        fs.writeFileSync(multiCertPemFile, combined, "utf-8");
    });

    it("should return a single certificate for a single-cert PEM file", () => {
        const certs = readCertificateChain(path.join(certsChainDir, "1000.pem"));
        expect(certs).toHaveLength(1);
        expect(Buffer.isBuffer(certs[0])).toBe(true);
        expect(certs[0].length).toBeGreaterThan(0);
        // DER starts with SEQUENCE tag (0x30)
        expect(certs[0][0]).toBe(0x30);
    });

    it("should return a single certificate for a DER file", () => {
        const certs = readCertificateChain(derCertFile);
        expect(certs).toHaveLength(1);
        expect(certs[0][0]).toBe(0x30);
    });

    it("should return multiple certificates for a multi-cert PEM file", () => {
        const certs = readCertificateChain(multiCertPemFile);
        expect(certs).toHaveLength(2);

        // Both should be valid DER
        for (const cert of certs) {
            expect(Buffer.isBuffer(cert)).toBe(true);
            expect(cert[0]).toBe(0x30);
        }

        // First cert should be the leaf (1000.pem)
        const leafDer = readCertificate(path.join(certsChainDir, "1000.pem"));
        expect(Buffer.compare(certs[0], leafDer)).toBe(0);

        // Second cert should be the CA (cacert.pem)
        const caDer = readCertificate(path.join(certsChainDir, "cacert.pem"));
        expect(Buffer.compare(certs[1], caDer)).toBe(0);
    });

    it("should extract multiple certificates from a single unified PEM block (auto-healing)", () => {
        // Create an artificially mangled PEM with a single Base64 block containing two concatenated DERs
        const certs = readCertificateChain(multiCertPemFile);
        expect(certs).toHaveLength(2);

        const concatenatedBuffer = Buffer.concat(certs);
        const unifiedPem = toPemBuggy(concatenatedBuffer, "CERTIFICATE");

        const mangledFile = path.join(__dirname, "../tmp/mangled_chain.pem");
        fs.writeFileSync(mangledFile, unifiedPem, "utf-8");

        // Assert that readCertificateChain effectively unwraps it using split_der internally
        const extractedCerts = readCertificateChain(mangledFile);
        expect(extractedCerts).toHaveLength(2);
        expect(Buffer.compare(certs[0], extractedCerts[0])).toBe(0);
        expect(Buffer.compare(certs[1], extractedCerts[1])).toBe(0);
    });

    it("should produce certificates verifiable by verifyCertificateChain", async () => {
        const certs = readCertificateChain(multiCertPemFile);
        expect(certs).toHaveLength(2);

        const result = await verifyCertificateChain(certs);
        expect(result.status).toBe("Good");
    });

    it("should allow inspection of individual certs via exploreCertificate", () => {
        const certs = readCertificateChain(multiCertPemFile);
        expect(certs).toHaveLength(2);

        const leafInfo = exploreCertificate(certs[0]);
        const caInfo = exploreCertificate(certs[1]);

        // Leaf's authorityKeyIdentifier should match CA's subjectKeyIdentifier
        const leafAKI = leafInfo.tbsCertificate.extensions?.authorityKeyIdentifier?.keyIdentifier;
        const caSKI = caInfo.tbsCertificate.extensions?.subjectKeyIdentifier;

        expect(leafAKI).toBeDefined();
        expect(caSKI).toBeDefined();
        expect(leafAKI).toBe(caSKI);
    });

    it("async version should match sync version", async () => {
        const sync = readCertificateChain(multiCertPemFile);
        const async_ = await readCertificateChainAsync(multiCertPemFile);

        expect(async_).toHaveLength(sync.length);
        for (let i = 0; i < sync.length; i++) {
            expect(Buffer.compare(sync[i], async_[i])).toBe(0);
        }
    });

    it("async version should work with DER files", async () => {
        const sync = readCertificateChain(derCertFile);
        const async_ = await readCertificateChainAsync(derCertFile);

        expect(async_).toHaveLength(1);
        expect(Buffer.compare(sync[0], async_[0])).toBe(0);
    });
});

describe("certificatesToPem / writeCertificateChain", () => {

    const leafDerFile = path.join(certsChainDir, "1000.pem");
    const caDerFile = path.join(certsChainDir, "cacert.pem");
    const tmpDir = path.join(__dirname, "../tmp");
    const tmpFile = path.join(tmpDir, "write_chain_test.pem");
    const tmpFileAsync = path.join(tmpDir, "write_chain_async_test.pem");

    beforeAll(() => {
        fs.mkdirSync(tmpDir, { recursive: true });
    });

    it("certificatesToPem should convert a single DER cert to PEM", () => {
        const certs = readCertificateChain(leafDerFile);
        const pem = certificatesToPem(certs[0]);

        expect(typeof pem).toBe("string");
        expect(pem).toContain("-----BEGIN CERTIFICATE-----");
        expect(pem).toContain("-----END CERTIFICATE-----");
        // Single cert → exactly 1 block
        const blocks = pem.match(/-----BEGIN CERTIFICATE-----/g) ?? [];
        expect(blocks).toHaveLength(1);
    });

    it("certificatesToPem should convert multiple DER certs to multi-block PEM", () => {
        const leaf = readCertificateChain(leafDerFile);
        const ca = readCertificateChain(caDerFile);
        const pem = certificatesToPem([...leaf, ...ca]);

        const blocks = pem.match(/-----BEGIN CERTIFICATE-----/g) ?? [];
        expect(blocks).toHaveLength(2);
    });

    it("writeCertificateChain should write and be readable with readCertificateChain", () => {
        const origCerts = readCertificateChain(path.join(__dirname, "../tmp/multi_cert_chain.pem"));
        expect(origCerts).toHaveLength(2);

        writeCertificateChain(tmpFile, origCerts);

        // Read back and verify roundtrip
        const readBack = readCertificateChain(tmpFile);
        expect(readBack).toHaveLength(2);
        for (let i = 0; i < origCerts.length; i++) {
            expect(Buffer.compare(origCerts[i], readBack[i])).toBe(0);
        }
    });

    it("writeCertificateChain roundtrip should produce a valid chain", async () => {
        const certs = readCertificateChain(tmpFile);
        const result = await verifyCertificateChain(certs);
        expect(result.status).toBe("Good");
    });

    it("writeCertificateChainAsync should match sync version", async () => {
        const certs = readCertificateChain(path.join(__dirname, "../tmp/multi_cert_chain.pem"));
        await writeCertificateChainAsync(tmpFileAsync, certs);

        const readBack = readCertificateChain(tmpFileAsync);
        expect(readBack).toHaveLength(certs.length);
        for (let i = 0; i < certs.length; i++) {
            expect(Buffer.compare(certs[i], readBack[i])).toBe(0);
        }
    });
});

describe("certificatesToDer / writeCertificateChainDer", () => {
    const tmpDir = path.join(__dirname, "../tmp");
    const tmpDerFile = path.join(tmpDir, "write_chain_test.der");

    beforeAll(() => {
        fs.mkdirSync(tmpDir, { recursive: true });
    });

    it("certificatesToDer should concatenate multiple DER certs", () => {
        const certs = readCertificateChain(path.join(__dirname, "../tmp/multi_cert_chain.pem"));
        expect(certs).toHaveLength(2);

        const combined = certificatesToDer(certs);
        expect(Buffer.isBuffer(combined)).toBe(true);
        expect(combined.length).toBe(certs[0].length + certs[1].length);

        // split_der should recover both certs
        const split = split_der(combined);
        expect(split).toHaveLength(2);
        expect(Buffer.compare(split[0], certs[0])).toBe(0);
        expect(Buffer.compare(split[1], certs[1])).toBe(0);
    });

    it("certificatesToDer should handle a single cert", () => {
        const certs = readCertificateChain(path.join(certsChainDir, "1000.pem"));
        const combined = certificatesToDer(certs[0]);
        expect(Buffer.compare(combined, certs[0])).toBe(0);
    });

    it("writeCertificateChainDer roundtrip should preserve chain", async () => {
        const certs = readCertificateChain(path.join(__dirname, "../tmp/multi_cert_chain.pem"));
        writeCertificateChainDer(tmpDerFile, certs);

        // Read back as DER and split
        const readBack = readCertificateChain(tmpDerFile);
        expect(readBack).toHaveLength(2);
        for (let i = 0; i < certs.length; i++) {
            expect(Buffer.compare(certs[i], readBack[i])).toBe(0);
        }

        // Chain should still be valid
        const result = await verifyCertificateChain(readBack);
        expect(result.status).toBe("Good");
    });
});
