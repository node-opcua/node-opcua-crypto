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

import type { Certificate, CertificateRevocationList } from "./common.js";
import { exploreCertificate } from "./crypto_explore_certificate.js";
import { exploreCertificateRevocationList } from "./explore_certificate_revocation_list.js";
import { verifyCertificateRevocationListSignature } from "./verify_certificate_signature.js";

/**
 * Determine if a Certificate Revocation List (CRL) was issued by
 * the given certificate, by comparing the CRL's issuer name
 * fingerprint with the certificate's subject name fingerprint.
 *
 * This is a lightweight check (no cryptographic signature
 * verification). Use {@link verifyCrlIssuedByCertificate} for
 * full verification.
 *
 * @param crl  - the CRL to check (DER-encoded)
 * @param certificate - the candidate issuer certificate (DER-encoded)
 * @returns `true` if the CRL's issuer fingerprint matches the
 *          certificate's subject fingerprint
 */
export function isCrlIssuedByCertificate(
    crl: CertificateRevocationList,
    certificate: Certificate,
): boolean {
    const crlInfo = exploreCertificateRevocationList(crl);
    const certInfo = exploreCertificate(certificate);
    return (
        crlInfo.tbsCertList.issuerFingerprint ===
        certInfo.tbsCertificate.subjectFingerPrint
    );
}

/**
 * Verify that a Certificate Revocation List (CRL) was issued by
 * the given certificate. This performs both a fingerprint match
 * **and** a cryptographic signature verification.
 *
 * @param crl  - the CRL to verify (DER-encoded)
 * @param certificate - the candidate issuer certificate (DER-encoded)
 * @returns `true` if the CRL's issuer matches the certificate
 *          **and** the CRL's signature is valid against the
 *          certificate's public key
 */
export function verifyCrlIssuedByCertificate(
    crl: CertificateRevocationList,
    certificate: Certificate,
): boolean {
    if (!isCrlIssuedByCertificate(crl, certificate)) {
        return false;
    }
    return verifyCertificateRevocationListSignature(crl, certificate);
}
