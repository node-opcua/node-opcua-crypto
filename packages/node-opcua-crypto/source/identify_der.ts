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

import { readStruct, readTag, TagType } from "./asn1.js";

/**
 * The type of content found in a DER-encoded buffer.
 */
export type DERContentType =
    | "X509Certificate"
    | "X509CertificateChain"
    | "CertificateRevocationList"
    | "CertificateSigningRequest"
    | "PKCS12"
    | "PrivateKey"
    | "Unknown";

/**
 * Identify the content type of a DER-encoded buffer by inspecting
 * its ASN.1 structure.
 *
 * This function does NOT fully parse the buffer — it only inspects
 * the outermost tags to determine the type. It can distinguish:
 *
 * - **X509Certificate** — a single X.509 certificate (v1 or v3)
 * - **X509CertificateChain** — multiple concatenated X.509 DER
 *   certificates
 * - **CertificateRevocationList** — an X.509 CRL (v1 or v2)
 * - **CertificateSigningRequest** — a PKCS#10 CSR
 * - **PKCS12** — a PKCS#12 / PFX container (version 3)
 * - **PrivateKey** — a PKCS#8 or raw RSA private key
 * - **Unknown** — could not identify the content
 *
 * @param buffer  A DER-encoded buffer to identify.
 * @returns       The detected {@link DERContentType}.
 */
export function identifyDERContent(buffer: Buffer): DERContentType {
    if (!Buffer.isBuffer(buffer) || buffer.length < 2) {
        return "Unknown";
    }

    try {
        const outer = readTag(buffer, 0);

        // Every type we care about starts with a SEQUENCE (0x30).
        if (outer.tag !== TagType.SEQUENCE) {
            return "Unknown";
        }

        const outerEnd = outer.position + outer.length;

        // --- Certificate chain detection ---
        // If the outer SEQUENCE does not cover the entire buffer,
        // there are additional DER structures concatenated — that
        // means it is a certificate chain.
        if (outerEnd < buffer.length) {
            // Verify the next blob starts with a SEQUENCE too.
            const next = readTag(buffer, outerEnd);
            if (next.tag === TagType.SEQUENCE) {
                return "X509CertificateChain";
            }
        }

        const blocks = readStruct(buffer, outer);
        if (blocks.length < 2) {
            return "Unknown";
        }

        // --- PKCS#12 / PFX detection ---
        // PFX ::= SEQUENCE { version INTEGER (v3), ... }
        // The first element is an INTEGER with value 3.
        if (blocks[0].tag === TagType.INTEGER) {
            const versionByte = buffer[blocks[0].position];
            if (blocks[0].length === 1 && versionByte === 3) {
                return "PKCS12";
            }
            // A bare INTEGER at the top of a SEQUENCE could also
            // be a PKCS#8 or RSA private key (version 0).
            if (blocks[0].length === 1 && versionByte === 0) {
                return "PrivateKey";
            }
        }

        // Both X.509 certs and CRLs and CSRs have the first
        // inner element as a SEQUENCE (TBS block).
        if (blocks[0].tag !== TagType.SEQUENCE) {
            return "Unknown";
        }

        // Drill into the TBS (first inner SEQUENCE)
        const tbsBlocks = readStruct(buffer, blocks[0]);
        if (tbsBlocks.length === 0) {
            return "Unknown";
        }

        // --- X.509 v3 Certificate ---
        // TBSCertificate starts with [0] EXPLICIT Version
        // (tag 0xa0 = CONTEXT_SPECIFIC0).
        if (tbsBlocks[0].tag === TagType.CONTEXT_SPECIFIC0) {
            return "X509Certificate";
        }

        // From here, the TBS starts with an INTEGER.
        // This covers:
        //   - X.509 v1 cert  (serial number — typically large)
        //   - CRL with version (INTEGER value 1)
        //   - CSR (INTEGER value 0)
        //
        // Without version, a CRL starts with a SEQUENCE
        // (signature algorithm) directly.

        if (tbsBlocks[0].tag === TagType.INTEGER) {
            const intLen = tbsBlocks[0].length;
            const intVal = intLen === 1 ? buffer[tbsBlocks[0].position] : -1;

            // --- CSR detection ---
            // CertificationRequestInfo ::= SEQUENCE {
            //   version       INTEGER { v1(0) },
            //   subject       Name,                 -- SEQUENCE
            //   subjectPKInfo SubjectPublicKeyInfo,  -- SEQUENCE
            //   attributes    [0] Attributes         -- 0xa0
            // }
            // version is always 0, and the 4th element is [0] (0xa0).
            if (intVal === 0 && tbsBlocks.length >= 4) {
                if (tbsBlocks[3].tag === TagType.CONTEXT_SPECIFIC0) {
                    return "CertificateSigningRequest";
                }
            }

            // --- CRL v2 detection ---
            // TBSCertList with version:
            //   version         INTEGER (1 for v2)
            //   signature       AlgorithmIdentifier (SEQUENCE)
            //   issuer          Name (SEQUENCE)
            //   thisUpdate      Time (UTCTime or GeneralizedTime)
            if (intVal === 1 && tbsBlocks.length >= 4) {
                const tag3 = tbsBlocks[3].tag;
                if (tag3 === TagType.UTCTime || tag3 === TagType.GeneralizedTime) {
                    return "CertificateRevocationList";
                }
            }

            // --- X.509 v1 certificate ---
            // TBSCertificate (v1) structure:
            //   serialNumber    INTEGER
            //   signature       AlgorithmIdentifier  (SEQUENCE)
            //   issuer          Name                 (SEQUENCE)
            //   validity        Validity             (SEQUENCE wrapping two Time values)
            //   subject         Name                 (SEQUENCE)
            //   subjectPKInfo   SubjectPublicKeyInfo (SEQUENCE)
            // Element [3] is a SEQUENCE (validity), not a bare Time.
            if (tbsBlocks.length >= 6) {
                if (tbsBlocks[3].tag === TagType.SEQUENCE) {
                    return "X509Certificate";
                }
            }
        }

        // --- CRL v1 (no version field) ---
        // TBSCertList without version:
        //   signature   AlgorithmIdentifier (SEQUENCE)
        //   issuer      Name                (SEQUENCE)
        //   thisUpdate  Time                (UTCTime or GeneralizedTime)
        if (tbsBlocks[0].tag === TagType.SEQUENCE && tbsBlocks.length >= 3) {
            const tag2 = tbsBlocks[2].tag;
            if (tag2 === TagType.UTCTime || tag2 === TagType.GeneralizedTime) {
                return "CertificateRevocationList";
            }
        }

        return "Unknown";
    } catch {
        return "Unknown";
    }
}
