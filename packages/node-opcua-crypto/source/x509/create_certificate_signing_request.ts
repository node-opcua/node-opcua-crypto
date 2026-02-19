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
import { Subject } from "../subject.js";
import { CertificatePurpose } from "../common.js";
import { getAttributes } from "./_get_attributes.js";
import { getCrypto, x509 } from "./_crypto.js";
import { buildPublicKey } from "./_build_public_key.js";

interface CreateCertificateSigningRequestOptions {
    privateKey: CryptoKey;
    notBefore?: Date;
    notAfter?: Date;
    validity?: number;
    subject?: string;
    dns?: string[];
    ip?: string[];
    applicationUri?: string;
    purpose: CertificatePurpose;
}
export async function createCertificateSigningRequest({
    privateKey,
    subject,
    dns,
    ip,
    applicationUri,
    purpose,
}: CreateCertificateSigningRequestOptions) {
    const crypto = getCrypto();

    const modulusLength = 2048;

    const alg = {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength,
    };

    const publicKey = await buildPublicKey(privateKey);

    const keys = {
        privateKey,
        publicKey,
    };

    const alternativeNameExtensions: x509.JsonGeneralName[] = [];
    dns && dns.forEach((d) => alternativeNameExtensions.push({ type: "dns", value: d }));
    ip && ip.forEach((d) => alternativeNameExtensions.push({ type: "ip", value: d }));
    applicationUri && alternativeNameExtensions.push({ type: "url", value: applicationUri });

    const { basicConstraints, usages } = getAttributes(purpose);

    const s = new Subject(subject || "");
    const s1 = s.toStringInternal(", ");
    const name = s1;

    const csr = await x509.Pkcs10CertificateRequestGenerator.create(
        {
            name,
            keys,
            signingAlgorithm: alg,
            extensions: [
                basicConstraints,
                new x509.KeyUsagesExtension(usages, true),
                new x509.SubjectAlternativeNameExtension(alternativeNameExtensions),
            ],
        },
        crypto
    );
    return { csr: csr.toString("pem"), der: csr };
}
