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
import type { PublicKeyType, X509CrlReason } from "@peculiar/x509";
import { getCrypto, x509 } from "./_crypto.js";
import { buildAuthorityKeyIdentifierFromIssuer, buildCrlNumberExtension } from "./build_ca_extensions.js";
import type { CaSignAlgorithm } from "./ca_signer.js";
import { type CaSigner, resolveCaSigningKey } from "./ca_signer.js";

export interface CreateCrlEntryOptions {
    /** Hexadecimal serial number of the revoked certificate. */
    serialNumber: string;
    revocationDate?: Date;
    reason?: X509CrlReason;
    invalidity?: Date;
}

export interface CreateCrlOptions {
    /** The issuing CA's subject, e.g. `"CN=MyCA"`. */
    issuerName: string;
    /** The issuing CA's public key, used to derive the Authority Key Identifier extension. */
    issuerPublicKey: PublicKeyType;
    /** The issuing CA's signing key — a raw key, or an HSM/KMS-backed {@link CaSigner}. */
    signingKey: CryptoKey | CaSigner;
    signingAlgorithm: CaSignAlgorithm;
    /** Monotonically increasing CRL number (RFC 5280 §5.2.3). */
    crlNumber: number | bigint;
    thisUpdate?: Date;
    /** Default: 30 days after `thisUpdate`. */
    nextUpdate?: Date;
    entries: CreateCrlEntryOptions[];
}

/**
 * Builds and signs a Certificate Revocation List — the primitive a native
 * (non-openssl) `CaBackend` needs for `revoke`/`regenerateCrl`.
 */
export async function createCrl(options: CreateCrlOptions): Promise<{ crl: string; der: ArrayBuffer }> {
    const crypto = getCrypto() as unknown as Crypto;

    const thisUpdate = options.thisUpdate ?? new Date();
    const nextUpdate = options.nextUpdate ?? new Date(thisUpdate.getTime() + 30 * 24 * 60 * 60 * 1000);

    const extensions: x509.Extension[] = [
        await buildAuthorityKeyIdentifierFromIssuer(options.issuerPublicKey, crypto),
        buildCrlNumberExtension(options.crlNumber),
    ];

    const { crypto: signingCrypto, signingKey } = await resolveCaSigningKey(options.signingKey, crypto);

    const crl = await x509.X509CrlGenerator.create(
        {
            issuer: options.issuerName,
            thisUpdate,
            nextUpdate,
            signingAlgorithm: options.signingAlgorithm,
            signingKey,
            extensions,
            entries: options.entries.map((entry) => ({
                serialNumber: entry.serialNumber,
                revocationDate: entry.revocationDate ?? new Date(),
                reason: entry.reason,
                invalidity: entry.invalidity,
            })),
        },
        signingCrypto,
    );

    return { crl: crl.toString("pem"), der: crl.rawData };
}
