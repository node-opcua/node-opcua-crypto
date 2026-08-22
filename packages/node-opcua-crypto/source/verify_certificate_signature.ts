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

// Now that we got a hash of the original certificate,
// we need to verify if we can obtain the same hash by using the same hashing function
// (in this case SHA-384). In order to do that, we need to extract just the body of
// the signed certificate. Which, in our case, is everything but the signature.
// The start of the body is always the first digit of the second line of the following command:
import { createVerify } from "node:crypto";
import { readAlgorithmIdentifier, readSignatureValueBin, readStruct, readTag } from "./asn1.js";
import type { Certificate } from "./common.js";
import { exploreCertificate, split_der } from "./crypto_explore_certificate.js";
import { toPem } from "./crypto_utils.js";

/**
 * ECDSA signature algorithms, which `readAlgorithmIdentifier` reports as bare
 * OIDs rather than names.
 */
const ECDSA_SIGNATURE_DIGESTS: Record<string, string> = {
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
};

/**
 * The digest to verify a signature under, given its algorithm.
 *
 * `createVerify` wants a digest, and happens to accept `sha256WithRSAEncryption`
 * because OpenSSL resolves that name to one. Nothing resolves
 * `1.2.840.10045.4.3.2`, so an ECDSA-signed certificate used to fail with
 * "Invalid digest" - the digest is named inside the algorithm either way, and
 * naming it directly works for both key types.
 *
 * Anything unrecognized is passed through as before, so an algorithm whose
 * digest is not in its identifier (RSASSA-PSS carries it in the parameters)
 * behaves exactly as it did.
 */
function digestForSignatureAlgorithm(identifier: string): string {
    const ecdsaDigest = ECDSA_SIGNATURE_DIGESTS[identifier];
    if (ecdsaDigest) {
        return ecdsaDigest;
    }
    const named = /sha-?(1|224|256|384|512)/i.exec(identifier);
    return named ? `sha${named[1]}` : identifier;
}

export function verifyCertificateOrClrSignature(certificateOrCrl: Buffer, parentCertificate: Certificate): boolean {
    const block_info = readTag(certificateOrCrl, 0);
    const blocks = readStruct(certificateOrCrl, block_info);
    const bufferToBeSigned = certificateOrCrl.subarray(block_info.position, blocks[1].position - 2);

    //xx console.log("bufferToBeSigned  = ", bufferToBeSigned.length, bufferToBeSigned.toString("hex").substr(0, 50), bufferToBeSigned.toString("hex").substr(-10));
    const signatureAlgorithm = readAlgorithmIdentifier(certificateOrCrl, blocks[1]);
    const signatureValue = readSignatureValueBin(certificateOrCrl, blocks[2]);

    const p = split_der(parentCertificate)[0];
    //xx    const publicKey = extractPublicKeyFromCertificateSync(p);
    const certPem = toPem(p, "CERTIFICATE");
    const verify = createVerify(digestForSignatureAlgorithm(signatureAlgorithm.identifier));
    verify.update(bufferToBeSigned);
    verify.end();
    return verify.verify(certPem, signatureValue);
}

export function verifyCertificateSignature(certificate: Certificate, parentCertificate: Certificate): boolean {
    return verifyCertificateOrClrSignature(certificate, parentCertificate);
}
export function verifyCertificateRevocationListSignature(
    certificateRevocationList: Certificate,
    parentCertificate: Certificate,
): boolean {
    return verifyCertificateOrClrSignature(certificateRevocationList, parentCertificate);
}

export type _VerifyStatus = "BadCertificateIssuerUseNotAllowed" | "BadCertificateInvalid" | "Good";
export async function verifyCertificateChain(certificateChain: Certificate[]): Promise<{ status: _VerifyStatus; reason: string }> {
    // verify that all the certificate
    // second certificate must be used for CertificateSign

    for (let index = 1; index < certificateChain.length; index++) {
        const cert = certificateChain[index - 1];
        const certParent = certificateChain[index];

        // parent child must have keyCertSign
        const certParentInfo = exploreCertificate(certParent);
        const keyUsage = certParentInfo.tbsCertificate.extensions?.keyUsage;

        // istanbul ignore next
        if (!keyUsage?.keyCertSign) {
            return {
                status: "BadCertificateIssuerUseNotAllowed",
                reason: "One of the certificate in the chain has not keyUsage set for Certificate Signing",
            };
        }

        const parentSignChild = verifyCertificateSignature(cert, certParent);
        if (!parentSignChild) {
            return {
                status: "BadCertificateInvalid",
                reason: "One of the certificate in the chain is not signing the previous certificate",
            };
        }
        const certInfo = exploreCertificate(cert);

        // istanbul ignore next
        if (!certInfo.tbsCertificate.extensions) {
            return {
                status: "BadCertificateInvalid",
                reason: "Cannot find X509 Extension 3 in certificate",
            };
        }

        // istanbul ignore next
        if (!certParentInfo.tbsCertificate.extensions || !certInfo.tbsCertificate.extensions.authorityKeyIdentifier) {
            return {
                status: "BadCertificateInvalid",
                reason: "Cannot find X509 Extension 3 in certificate (parent)",
            };
        }

        // istanbul ignore next
        if (
            certParentInfo.tbsCertificate.extensions.subjectKeyIdentifier !==
            certInfo.tbsCertificate.extensions.authorityKeyIdentifier.keyIdentifier
        ) {
            return {
                status: "BadCertificateInvalid",
                reason: "subjectKeyIdentifier authorityKeyIdentifier in child certificate do not match subjectKeyIdentifier of parent certificate",
            };
        }
    }
    return {
        status: "Good",
        reason: `certificate chain is valid(length = ${certificateChain.length})`,
    };
}
