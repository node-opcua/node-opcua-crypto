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
    caSignerFromKeyOperations,
    CertificatePurpose,
    createCertificateFromCsr,
    createCertificateSigningRequest,
    generateKeyPair,
    type IKeyOperations,
    LocalKeyOperations,
    x509,
} from "node-opcua-crypto";
import { describe, expect, it, vi } from "vitest";

const rsaAlgorithm = { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } };

function makeCaOps(): LocalKeyOperations {
    const { privateKey } = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    return new LocalKeyOperations({ hidden: privateKey.export({ type: "pkcs8", format: "pem" }).toString() });
}

/** Strips an IKeyOperations down to what a remote KMS-style provider offers. */
function asAsyncOnly(ops: IKeyOperations, withPublicKey: boolean): IKeyOperations {
    const asyncOnly: IKeyOperations = {
        sign: ops.sign.bind(ops),
        decryptBlock: ops.decryptBlock.bind(ops),
        getKeyMetadata: ops.getKeyMetadata.bind(ops),
    };
    if (withPublicKey && ops.getPublicKey) {
        asyncOnly.getPublicKey = ops.getPublicKey.bind(ops);
    }
    return asyncOnly;
}

async function importCaPublicKey(ops: IKeyOperations): Promise<CryptoKey> {
    if (!ops.getPublicKey) {
        throw new Error("test setup: ops has no getPublicKey");
    }
    return crypto.subtle.importKey("spki", await ops.getPublicKey(), rsaAlgorithm, true, ["verify"]);
}

describe("caSignerFromKeyOperations", { timeout: 60000 }, () => {
    it("refuses a provider without getPublicKey, naming the missing capability", () => {
        const asyncOnlyWithoutPublicKey = asAsyncOnly(makeCaOps(), false);
        expect(() => caSignerFromKeyOperations(asyncOnlyWithoutPublicKey)).toThrow(/getPublicKey/);
    });

    it("passes the provider's public key through unchanged", async () => {
        const ops = makeCaOps();
        const signer = caSignerFromKeyOperations(ops);
        expect(signer.algorithm).toEqual(rsaAlgorithm);
        expect(Buffer.from(await signer.getPublicKey())).toEqual(Buffer.from(await ops.getPublicKey()));
    });

    it("drives createCertificateFromCsr: the issued certificate verifies against the CA key's public half", async () => {
        const caOps = makeCaOps();
        const signer = caSignerFromKeyOperations(caOps);
        const caPublicKey = await importCaPublicKey(caOps);

        const { privateKey: leafPrivateKey } = await generateKeyPair();
        const { csr } = await createCertificateSigningRequest({
            privateKey: leafPrivateKey,
            subject: "CN=Leaf",
            purpose: CertificatePurpose.ForApplication,
            applicationUri: "urn:test:leaf",
        });

        const { cert } = await createCertificateFromCsr({
            csr,
            issuerName: "CN=OpaqueCA",
            issuerPublicKey: caPublicKey,
            signingKey: signer,
            signingAlgorithm: signer.algorithm,
            purpose: CertificatePurpose.ForApplication,
            applicationUri: "urn:test:leaf",
        });

        const leafCert = new x509.X509Certificate(cert);
        expect(leafCert.subject).toEqual("CN=Leaf");
        expect(leafCert.issuer).toEqual("CN=OpaqueCA");
        expect(await leafCert.verify({ publicKey: caPublicKey })).toEqual(true);

        // and NOT against an unrelated key
        const { publicKey: unrelatedPublicKey } = await generateKeyPair();
        expect(await leafCert.verify({ publicKey: unrelatedPublicKey })).toEqual(false);
    });

    it("works with an async-only provider, signing only through IKeyOperations.sign", async () => {
        const caOps = makeCaOps();
        const asyncOnly = asAsyncOnly(caOps, true);
        const signSpy = vi.spyOn(asyncOnly, "sign");
        const signer = caSignerFromKeyOperations(asyncOnly);

        // the CSR-over-the-opaque-key-itself case: proof-of-possession
        // signature and embedded public key both have to come from the provider
        const { csr } = await createCertificateSigningRequest({
            privateKey: signer,
            subject: "CN=OpaqueRenewal",
            purpose: CertificatePurpose.ForApplication,
            applicationUri: "urn:test:renewal",
        });

        expect(signSpy).toHaveBeenCalledTimes(1);
        expect(signSpy).toHaveBeenCalledWith(expect.any(Uint8Array), { padding: "RSA-PKCS1-v1_5", hash: "SHA-256" });

        const request = new x509.Pkcs10CertificateRequest(csr);
        expect(request.subject).toEqual("CN=OpaqueRenewal");
        expect(await request.verify()).toEqual(true);
        expect(Buffer.from(request.publicKey.rawData)).toEqual(Buffer.from(await caOps.getPublicKey()));
    });
});
