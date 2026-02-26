import path from "node:path";
import {
    readCertificate,
    readCertificateAsync,
    readCertificatePEM,
    readCertificatePEMAsync,
    readCertificateRevocationList,
    readPrivateKey,
    readPrivateKeyAsync,
    readPublicKey,
    readPublicKeyAsync,
    readPublicKeyPEM,
    readPublicKeyPEMAsync,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

const fixturesDir = path.join(__dirname, "../test-fixtures");

const pemCertFile = path.join(fixturesDir, "alice_bob/alice_cert_1024.pem");
const pemPrivKeyFile = path.join(fixturesDir, "alice_bob/alice_key_1024.pem");
const pemPubKeyFile = path.join(fixturesDir, "alice_bob/alice_public_key_1024.pub");
const derCertFile = path.join(fixturesDir, "NodeOPCUA [40BA2E8A5BEEC90067A7E554C5F3F2ECDD5BCDDF].der");
const crlFile = path.join(fixturesDir, "crl/certificate_revocation_list1_issuer_certificate.der");

describe("Async read functions should produce identical results to sync versions", () => {

    it("readCertificateAsync should match readCertificate (PEM)", async () => {
        const sync = readCertificate(pemCertFile);
        const async_ = await readCertificateAsync(pemCertFile);
        expect(Buffer.compare(sync, async_)).toBe(0);
    });

    it("readCertificateAsync should match readCertificate (DER)", async () => {
        const sync = readCertificate(derCertFile);
        const async_ = await readCertificateAsync(derCertFile);
        expect(Buffer.compare(sync, async_)).toBe(0);
    });

    it("readPublicKeyAsync should match readPublicKey (PEM)", async () => {
        const sync = readPublicKey(pemPubKeyFile);
        const async_ = await readPublicKeyAsync(pemPubKeyFile);
        // Compare exported DER to check key equality
        const syncDer = sync.export({ format: "der", type: "spki" });
        const asyncDer = async_.export({ format: "der", type: "spki" });
        expect(Buffer.compare(syncDer, asyncDer)).toBe(0);
    });

    it("readPrivateKeyAsync should match readPrivateKey (PEM)", async () => {
        const sync = readPrivateKey(pemPrivKeyFile);
        const async_ = await readPrivateKeyAsync(pemPrivKeyFile);
        // Both return { hidden: KeyObject | string }
        // Compare the hidden values
        if (typeof sync.hidden === "object" && typeof async_.hidden === "object") {
            const syncDer = (sync.hidden as import("node:crypto").KeyObject).export({ format: "der", type: "pkcs8" });
            const asyncDer = (async_.hidden as import("node:crypto").KeyObject).export({ format: "der", type: "pkcs8" });
            expect(Buffer.compare(syncDer, asyncDer)).toBe(0);
        } else {
            expect(sync.hidden).toEqual(async_.hidden);
        }
    });

    it("readCertificatePEMAsync should match readCertificatePEM", async () => {
        const sync = readCertificatePEM(pemCertFile);
        const async_ = await readCertificatePEMAsync(pemCertFile);
        expect(sync).toBe(async_);
    });

    it("readPublicKeyPEMAsync should match readPublicKeyPEM", async () => {
        const sync = readPublicKeyPEM(pemPubKeyFile);
        const async_ = await readPublicKeyPEMAsync(pemPubKeyFile);
        expect(sync).toBe(async_);
    });

    it("readCertificateRevocationList should be async and return valid CRL", async () => {
        const crl = await readCertificateRevocationList(crlFile);
        expect(Buffer.isBuffer(crl)).toBe(true);
        expect(crl.length).toBeGreaterThan(0);
        // DER-encoded CRL starts with SEQUENCE tag (0x30)
        expect(crl[0]).toBe(0x30);
    });
});
