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

import nodeCrypto from "node:crypto";
import {
    type CaSignAlgorithm,
    type CaSigner,
    CertificatePurpose,
    createCertificateSigningRequest,
    ecdsaSignatureDerToP1363,
    generateKeyPair,
    LocalPrivateKeySigner,
    webCryptoFromSigner,
    x509,
} from "node-opcua-crypto";
import { describe, expect, it, vi } from "vitest";

const rsaAlgorithm: CaSignAlgorithm = { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } };

describe("CaSigner / LocalPrivateKeySigner / webCryptoFromSigner", { timeout: 60000 }, () => {
    it("LocalPrivateKeySigner signs and its public key matches the key pair's public key", async () => {
        const { privateKey, publicKey } = await generateKeyPair();
        const signer = new LocalPrivateKeySigner({ privateKey, publicKey }, rsaAlgorithm);

        const spkiFromSigner = await signer.getPublicKey();
        const spkiFromKeyPair = await crypto.subtle.exportKey("spki", publicKey);
        expect(Buffer.from(spkiFromSigner)).toEqual(Buffer.from(spkiFromKeyPair));

        const tbs = new Uint8Array([1, 2, 3, 4, 5]);
        const signature = await signer.sign(tbs);
        const valid = await crypto.subtle.verify(rsaAlgorithm, publicKey, signature, tbs);
        expect(valid).toEqual(true);
    });

    it("webCryptoFromSigner routes crypto.subtle.sign(privateKeyHandle, ...) to the signer, not to any real key", async () => {
        const { privateKey, publicKey } = await generateKeyPair();
        const signer = new LocalPrivateKeySigner({ privateKey, publicKey }, rsaAlgorithm);
        const signSpy = vi.spyOn(signer, "sign");

        const { crypto: adaptedCrypto, privateKeyHandle, publicKey: importedPublicKey } = await webCryptoFromSigner(signer);

        const tbs = new Uint8Array([9, 9, 9]);
        const signature = await adaptedCrypto.subtle.sign(rsaAlgorithm, privateKeyHandle, tbs);
        expect(signSpy).toHaveBeenCalledTimes(1);

        const valid = await crypto.subtle.verify(rsaAlgorithm, importedPublicKey, signature, tbs);
        expect(valid).toEqual(true);

        // digest/importKey/etc. are delegated to the real provider, not the signer
        const digest = await adaptedCrypto.subtle.digest("SHA-256", tbs);
        expect(digest.byteLength).toEqual(32);
    });

    it("a self-signed certificate generated through webCryptoFromSigner verifies, and never touches the real private key", async () => {
        const { privateKey, publicKey } = await generateKeyPair();

        // A signer that throws if anything ever calls back into the real
        // private key directly — only signer.sign() may be used.
        const guardedSigner: CaSigner = {
            algorithm: rsaAlgorithm,
            async getPublicKey() {
                return crypto.subtle.exportKey("spki", publicKey);
            },
            async sign(tbs: Uint8Array) {
                return crypto.subtle.sign(rsaAlgorithm, privateKey, tbs as BufferSource);
            },
        };
        const signSpy = vi.spyOn(guardedSigner, "sign");

        const { crypto: adaptedCrypto, privateKeyHandle, publicKey: importedPublicKey } = await webCryptoFromSigner(guardedSigner);

        const cert = await x509.X509CertificateGenerator.createSelfSigned(
            {
                name: "CN=CaSignerTest",
                notBefore: new Date(),
                notAfter: new Date(Date.now() + 24 * 60 * 60 * 1000),
                signingAlgorithm: rsaAlgorithm,
                keys: { privateKey: privateKeyHandle, publicKey: importedPublicKey },
                extensions: [new x509.BasicConstraintsExtension(false, undefined, true)],
            },
            adaptedCrypto,
        );

        expect(signSpy).toHaveBeenCalledTimes(1);
        const valid = await cert.verify();
        expect(valid).toEqual(true);
    });

    it("createCertificateSigningRequest signs a CSR with a CaSigner, embedding the signer's own public key", async () => {
        // A CA whose key is in an HSM still has to produce a CSR for its own
        // key - to be signed by a parent, or self-signed into a root - and
        // the proof-of-possession signature on it can only come from the
        // signer. The public key must come from getPublicKey(), since the
        // private half cannot be exported to derive it.
        const { privateKey, publicKey } = await generateKeyPair();
        const signer = new LocalPrivateKeySigner({ privateKey, publicKey }, rsaAlgorithm);
        const signSpy = vi.spyOn(signer, "sign");

        const { csr } = await createCertificateSigningRequest({
            privateKey: signer,
            subject: "CN=HsmCa",
            purpose: CertificatePurpose.ForCertificateAuthority,
        });

        expect(signSpy).toHaveBeenCalledTimes(1);
        const request = new x509.Pkcs10CertificateRequest(csr);
        expect(request.subject).toEqual("CN=HsmCa");
        // the CSR verifies against itself, i.e. the embedded public key really
        // is the signer's and the signature really was made by its private half
        expect(await request.verify()).toEqual(true);

        const spki = await crypto.subtle.exportKey("spki", publicKey);
        expect(Buffer.from(request.publicKey.rawData)).toEqual(Buffer.from(spki));
    });
});

describe("CaSigner with an ECDSA key", { timeout: 60000 }, () => {
    const ecAlgorithm: CaSignAlgorithm = { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } };

    async function generateEcKeyPair(namedCurve: "P-256" | "P-384" | "P-521" = "P-256") {
        return (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve }, true, ["sign", "verify"])) as CryptoKeyPair;
    }

    it("adapts an ECDSA signer, which an RSA-only algorithm type could not describe", async () => {
        // `namedCurve` is what makes this possible: importing the signer's
        // public key needs the curve, and an SPKI import cannot guess it.
        const keys = await generateEcKeyPair();
        const signer = new LocalPrivateKeySigner(keys, ecAlgorithm);

        const { crypto: adaptedCrypto, privateKeyHandle, publicKey } = await webCryptoFromSigner(signer);
        expect((publicKey.algorithm as EcKeyAlgorithm).namedCurve).toEqual("P-256");

        const tbs = new Uint8Array([4, 2]);
        const signature = await adaptedCrypto.subtle.sign(ecAlgorithm, privateKeyHandle, tbs);
        expect(await crypto.subtle.verify(ecAlgorithm, publicKey, signature, tbs)).toEqual(true);
    });

    it("produces a certificate whose ECDSA signature verifies", async () => {
        // The signer returns WebCrypto's r||s; X.509 carries DER. The
        // generator does that re-encoding, and this is what proves it: a
        // certificate whose signature verifies against the public key.
        const keys = await generateEcKeyPair();
        const signer = new LocalPrivateKeySigner(keys, ecAlgorithm);
        const signSpy = vi.spyOn(signer, "sign");

        const { crypto: adaptedCrypto, privateKeyHandle, publicKey } = await webCryptoFromSigner(signer);
        const cert = await x509.X509CertificateGenerator.createSelfSigned(
            {
                name: "CN=EcCaSignerTest",
                notBefore: new Date(),
                notAfter: new Date(Date.now() + 24 * 60 * 60 * 1000),
                signingAlgorithm: ecAlgorithm,
                keys: { privateKey: privateKeyHandle, publicKey },
                extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
            },
            adaptedCrypto,
        );

        expect(signSpy).toHaveBeenCalledTimes(1);
        expect(await cert.verify()).toEqual(true);
        expect(cert.signatureAlgorithm.name).toEqual("ECDSA");
    });

    it("rejects a curve the key does not actually live on, instead of signing into the void", async () => {
        // A KMS signer declares its algorithm by hand, so it can be declared
        // wrong. The SPKI bytes carry the true curve, so the import is where
        // the lie is caught - loudly, and before any certificate exists.
        const keys = await generateEcKeyPair("P-256");
        const misdeclared = new LocalPrivateKeySigner(keys, {
            name: "ECDSA",
            namedCurve: "P-384",
            hash: { name: "SHA-384" },
        });

        await expect(webCryptoFromSigner(misdeclared)).rejects.toThrow();
    });
});

describe("ecdsaSignatureDerToP1363", () => {
    it("converts a real DER signature into something WebCrypto verifies", async () => {
        // node's webcrypto emits r||s, so a DER signature has to come from
        // somewhere else: node:crypto's sign() emits DER for EC keys, which
        // is exactly the shape a KMS hands back.
        const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
            "sign",
            "verify",
        ])) as CryptoKeyPair;
        const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
        const nodeKey = nodeCrypto.createPrivateKey({ key: Buffer.from(pkcs8), format: "der", type: "pkcs8" });

        const tbs = Buffer.from("to be signed");
        const derSignature = nodeCrypto.sign("sha256", tbs, nodeKey);
        expect(derSignature[0]).toEqual(0x30); // a DER SEQUENCE, not r||s

        const p1363 = ecdsaSignatureDerToP1363(derSignature, "P-256");
        expect(p1363.byteLength).toEqual(64);

        const valid = await crypto.subtle.verify(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            keys.publicKey,
            p1363,
            tbs as unknown as BufferSource,
        );
        expect(valid).toEqual(true);
    });

    it("left-pads coordinates that are shorter than the curve width", () => {
        // r = 1, s = 1: minimal DER encoding is one byte each, but P-256
        // needs both padded to 32 bytes or the halves shift into each other
        const der = Buffer.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        const p1363 = new Uint8Array(ecdsaSignatureDerToP1363(der, "P-256"));

        expect(p1363.length).toEqual(64);
        expect(p1363[31]).toEqual(1);
        expect(p1363[63]).toEqual(1);
        expect(p1363.filter((b) => b !== 0).length).toEqual(2);
    });

    it("strips the sign byte DER adds to a coordinate whose top bit is set", () => {
        // 0x00FF... is how DER keeps a high-bit value positive; the leading
        // zero is encoding, not magnitude, and must not occupy a byte of r
        const der = Buffer.from([0x30, 0x08, 0x02, 0x02, 0x00, 0xff, 0x02, 0x02, 0x00, 0x80]);
        const p1363 = new Uint8Array(ecdsaSignatureDerToP1363(der, "P-256"));

        expect(p1363[31]).toEqual(0xff);
        expect(p1363[63]).toEqual(0x80);
    });

    it("sizes the output from the curve, not from the input", () => {
        const der = Buffer.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        expect(ecdsaSignatureDerToP1363(der, "P-384").byteLength).toEqual(96);
        expect(ecdsaSignatureDerToP1363(der, "P-521").byteLength).toEqual(132);
    });

    it("refuses input that is not DER, rather than corrupting it further", () => {
        // the mistake this guards against is calling the converter twice
        expect(() => ecdsaSignatureDerToP1363(new Uint8Array(64), "P-256")).toThrow(/SEQUENCE/);
        expect(() => ecdsaSignatureDerToP1363(Buffer.from([0x30, 0x02, 0x02, 0x01, 0x01]), "P-256")).toThrow(/does not match/);
        expect(() => ecdsaSignatureDerToP1363(Buffer.from([0x30, 0x03, 0x04, 0x01, 0x01]), "P-256")).toThrow(/INTEGER/);
    });

    it("refuses a coordinate too wide for the curve it was told about", () => {
        // a P-384-width signature handed to the P-256 conversion: silently
        // truncating it would produce a signature that never verifies
        const coordinate = Buffer.concat([Buffer.from([0x02, 48]), Buffer.alloc(48, 0x11)]);
        const wide = Buffer.concat([Buffer.from([0x30, coordinate.length * 2]), coordinate, coordinate]);

        expect(() => ecdsaSignatureDerToP1363(wide, "P-256")).toThrow(/too long/);
        // and the same bytes convert cleanly for the curve they belong to
        expect(ecdsaSignatureDerToP1363(wide, "P-384").byteLength).toEqual(96);
    });
});
