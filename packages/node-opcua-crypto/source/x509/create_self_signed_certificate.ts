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

import { AsnConvert, AsnUtf8StringConverter } from "@peculiar/asn1-schema";
import type { CertificatePurpose } from "../common.js";
import { Subject } from "../subject.js";
import { type CaSigner, resolveCaKeyPair } from "./ca_signer.js";
import { ensurePemTrailingNewline, x509 } from "./_crypto.js";
import { getAttributes } from "./_get_attributes.js";

export interface CreateSelfSignCertificateOptions {
    /** The key that signs the certificate and whose public half it carries — a raw key, or an HSM/KMS-backed {@link CaSigner}. */
    privateKey: CryptoKey | CaSigner;
    notBefore?: Date;
    notAfter?: Date;
    validity?: number;
    // CN=common/O=Org/C=US/ST=State/L=City
    subject?: string;
    dns?: string[];
    ip?: string[];
    applicationUri?: string;
    purpose: CertificatePurpose;
}

/**
 *
 * construct a self-signed certificate
 */
export async function createSelfSignedCertificate({
    privateKey,
    notAfter,
    notBefore,
    validity,
    subject,
    dns,
    ip,
    applicationUri,
    purpose,
}: CreateSelfSignCertificateOptions) {
    // resolves either kind of key to what the generator needs: for a raw
    // CryptoKey this derives the public half and keeps the ambient crypto;
    // for a CaSigner the public key comes from getPublicKey() and signing
    // is routed through the signer (the key never exists in-process).
    const { crypto, keys, signingAlgorithm } = await resolveCaKeyPair(privateKey);

    const { nsComment, basicConstraints, keyUsageExtension, usages } = getAttributes(purpose);

    notBefore = notBefore || new Date();
    validity = validity || 0;
    if (!notAfter) {
        validity = validity || 365;
    }
    notAfter = notAfter || new Date(notBefore.getTime() + validity * 24 * 60 * 60 * 1000);

    const alternativeNameExtensions: x509.JsonGeneralName[] = [];
    if (dns) {
        for (const d of dns) {
            alternativeNameExtensions.push({ type: "dns", value: d });
        }
    }
    if (ip) {
        for (const d of ip) {
            alternativeNameExtensions.push({ type: "ip", value: d });
        }
    }
    if (applicationUri) {
        alternativeNameExtensions.push({ type: "url", value: applicationUri });
    }

    // https://opensource.apple.com/source/OpenSSH/OpenSSH-186/osslshim/heimdal-asn1/rfc2459.asn1.auto.html
    const ID_NETSCAPE_COMMENT = "2.16.840.1.113730.1.13";

    const s = new Subject(subject || "");
    const s1 = s.toStringInternal(", ");
    const name = s1;

    const cert = await x509.X509CertificateGenerator.createSelfSigned(
        {
            // no serialNumber: @peculiar/x509 generates a cryptographically
            // random 16-byte serial when it is omitted. Date.now().toString()
            // was read back as a HEX string by the generator, not decimal, so
            // it produced a predictable, easily-colliding serial (two certs
            // created in the same millisecond got the same value).
            name,
            notBefore,
            notAfter,

            // for a raw key resolveCaKeyPair yields exactly the historical
            // RSASSA-PKCS1-v1_5/SHA-256; for a CaSigner, the signer's declared algorithm
            signingAlgorithm,

            keys,

            extensions: [
                new x509.Extension(ID_NETSCAPE_COMMENT, false, AsnConvert.serialize(AsnUtf8StringConverter.toASN(nsComment))),
                // new x509.BasicConstraintsExtension(true, 2, true),
                basicConstraints,
                // see RFC 5280 4.2.1.12 - an empty critical EKU is invalid
                ...(keyUsageExtension.length > 0 ? [new x509.ExtendedKeyUsageExtension(keyUsageExtension, true)] : []),
                new x509.KeyUsagesExtension(usages, true),
                await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
                await x509.AuthorityKeyIdentifierExtension.create(keys.publicKey),
                new x509.SubjectAlternativeNameExtension(alternativeNameExtensions),
            ],
        },
        crypto as Crypto,
    );

    return { cert: ensurePemTrailingNewline(cert.toString("pem")), der: cert };
}
