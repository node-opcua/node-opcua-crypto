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
import type { PublicKeyType } from "@peculiar/x509";
import type { CertificatePurpose } from "../common.js";
import { ensurePemTrailingNewline, getCrypto, x509 } from "./_crypto.js";
import { getAttributes } from "./_get_attributes.js";
import {
    buildAuthorityKeyIdentifierFromIssuer,
    buildRevocationExtensions,
    type RevocationExtensionsParams,
} from "./build_ca_extensions.js";
import type { CaSignAlgorithm } from "./ca_signer.js";
import { type CaSigner, resolveCaSigningKey } from "./ca_signer.js";

export interface CreateCertificateFromCsrOptions {
    /** The CSR to sign, PEM or DER encoded. */
    csr: string | BufferSource;
    /**
     * The issuing CA's subject. Prefer passing the issuer's parsed
     * `subjectName` (`X509Certificate.subjectName`, or the CSR's own for a
     * self-signed root) over a string: re-parsing a string form can change
     * the DER encoding, and an issuer that is not byte-identical to the
     * issuer certificate's subject breaks chain building.
     */
    issuerName: x509.X509CertificateCreateParamsName;
    /** The issuing CA's public key, used to derive the Authority Key Identifier extension. */
    issuerPublicKey: PublicKeyType;
    /** The issuing CA's signing key — a raw key, or an HSM/KMS-backed {@link CaSigner}. */
    signingKey: CryptoKey | CaSigner;
    signingAlgorithm: CaSignAlgorithm;
    /** Hexadecimal serial number. If omitted, a random one is generated. */
    serialNumber?: string;
    notBefore?: Date;
    notAfter?: Date;
    /** Validity in days from `notBefore`, used when `notAfter` is not given. Default 365. */
    validity?: number;
    purpose: CertificatePurpose;
    dns?: string[];
    ip?: string[];
    applicationUri?: string;
    revocation?: RevocationExtensionsParams;
}

/**
 * Signs a certificate signing request with a CA key, producing an
 * end-entity or subordinate-CA certificate — the primitive a native
 * (non-openssl) `CaBackend` needs for `signCertificateRequest` and
 * `signSubordinateCsr`.
 *
 * The CSR's own signature is always verified first: a CA must never sign a
 * public key without proof the requester holds the matching private key.
 */
export async function createCertificateFromCsr(
    options: CreateCertificateFromCsrOptions,
): Promise<{ cert: string; der: ArrayBuffer }> {
    const crypto = getCrypto() as unknown as Crypto;

    const csr = new x509.Pkcs10CertificateRequest(options.csr);
    const csrIsValid = await csr.verify(crypto);
    if (!csrIsValid) {
        throw new Error("createCertificateFromCsr: the CSR signature does not verify — refusing to sign an unproven key");
    }

    const { basicConstraints, keyUsageExtension, usages } = getAttributes(options.purpose);

    const alternativeNameExtensions: x509.JsonGeneralName[] = [];
    for (const d of options.dns ?? []) {
        alternativeNameExtensions.push({ type: "dns", value: d });
    }
    for (const d of options.ip ?? []) {
        alternativeNameExtensions.push({ type: "ip", value: d });
    }
    if (options.applicationUri) {
        alternativeNameExtensions.push({ type: "url", value: options.applicationUri });
    }

    const extensions: x509.Extension[] = [
        basicConstraints,
        // RFC 5280 4.2.1.12: extendedKeyUsage SHALL contain at least one
        // KeyPurposeId. getAttributes yields an empty list for a CA
        // certificate, so emitting it unconditionally would produce an
        // empty critical extension that a strict validator must reject.
        ...(keyUsageExtension.length > 0 ? [new x509.ExtendedKeyUsageExtension(keyUsageExtension, true)] : []),
        new x509.KeyUsagesExtension(usages, true),
        await x509.SubjectKeyIdentifierExtension.create(csr.publicKey),
        await buildAuthorityKeyIdentifierFromIssuer(options.issuerPublicKey, crypto),
        // an empty SubjectAlternativeName is an empty GeneralNames sequence,
        // which RFC 5280 4.2.1.6 does not permit - omit the extension instead
        ...(alternativeNameExtensions.length > 0 ? [new x509.SubjectAlternativeNameExtension(alternativeNameExtensions)] : []),
        ...(options.revocation ? buildRevocationExtensions(options.revocation) : []),
    ];

    const notBefore = options.notBefore ?? new Date();
    const validity = options.validity ?? 365;
    const notAfter = options.notAfter ?? new Date(notBefore.getTime() + validity * 24 * 60 * 60 * 1000);

    const { crypto: signingCrypto, signingKey } = await resolveCaSigningKey(options.signingKey, crypto);

    const cert = await x509.X509CertificateGenerator.create(
        {
            serialNumber: options.serialNumber,
            subject: csr.subjectName,
            issuer: options.issuerName,
            notBefore,
            notAfter,
            signingAlgorithm: options.signingAlgorithm,
            publicKey: csr.publicKey,
            signingKey,
            extensions,
        },
        signingCrypto,
    );

    return { cert: ensurePemTrailingNewline(cert.toString("pem")), der: cert.rawData };
}
