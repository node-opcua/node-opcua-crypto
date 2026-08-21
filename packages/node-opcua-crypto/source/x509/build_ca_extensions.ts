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
import { AsnConvert, AsnIntegerBigIntConverter } from "@peculiar/asn1-schema";
import type { PublicKeyType } from "@peculiar/x509";
import { getCrypto, x509 } from "./_crypto.js";

/**
 * Authority Key Identifier extension identifying the issuer by its public
 * key (`keyid`), matching what {@link createSelfSignedCertificate} already
 * does for the self-signed case, and what openssl's
 * `authorityKeyIdentifier = keyid:always` produces for the issued case.
 */
export async function buildAuthorityKeyIdentifierFromIssuer(
    issuerPublicKey: PublicKeyType,
    crypto: Crypto = getCrypto() as unknown as Crypto,
): Promise<x509.AuthorityKeyIdentifierExtension> {
    return x509.AuthorityKeyIdentifierExtension.create(issuerPublicKey, false, crypto);
}

/** Opt-in CRL Distribution Point / Authority Info Access URLs for a certificate. */
export interface RevocationExtensionsParams {
    crlDistributionUrl?: string;
    ocspResponderUrl?: string;
    caIssuersUrl?: string;
}

/**
 * Builds the CDP (`crlDistributionUrl`) and AIA (`ocspResponderUrl` /
 * `caIssuersUrl`) extensions for a certificate, mirroring the
 * `$ENV::CDP_URL` / `$ENV::AIA_VALUE` opt-in extensions the openssl-backed
 * CA templates emit. Each extension is included only when at least one of
 * its values is set.
 */
export function buildRevocationExtensions(params: RevocationExtensionsParams): x509.Extension[] {
    const extensions: x509.Extension[] = [];
    if (params.crlDistributionUrl) {
        extensions.push(new x509.CRLDistributionPointsExtension([params.crlDistributionUrl], false));
    }
    if (params.ocspResponderUrl || params.caIssuersUrl) {
        extensions.push(
            new x509.AuthorityInfoAccessExtension(
                {
                    ocsp: params.ocspResponderUrl,
                    caIssuers: params.caIssuersUrl,
                },
                false,
            ),
        );
    }
    return extensions;
}

const ID_CE_CRL_NUMBER = "2.5.29.20";

/** The CRL Number extension (RFC 5280 §5.2.3), a plain monotonically-increasing counter. */
export function buildCrlNumberExtension(crlNumber: number | bigint): x509.Extension {
    const value = typeof crlNumber === "bigint" ? crlNumber : BigInt(crlNumber);
    return new x509.Extension(ID_CE_CRL_NUMBER, false, AsnConvert.serialize(AsnIntegerBigIntConverter.toASN(value)));
}
