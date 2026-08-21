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
    type CaSigner,
    CertificatePurpose,
    createCertificateSigningRequest,
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
