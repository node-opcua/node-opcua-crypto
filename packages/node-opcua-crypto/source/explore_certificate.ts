// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2024 - Sterfive.com
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
/**
 * @module node_opcua_crypto
 */
import assert from "assert";

import { Certificate, CertificatePEM } from "./common.js";
import { exploreCertificate, SubjectPublicKey } from "./crypto_explore_certificate.js";
import { DirectoryName } from "./directory_name.js";
import { convertPEMtoDER } from "./crypto_utils.js";

export type PublicKeyLength = 64 | 96 | 128 | 256 | 384 | 512;

/**
 * A structure exposing useful information about a certificate
 */
export interface CertificateInfo {
    /** the public key length in bits */
    publicKeyLength: PublicKeyLength;
    /** the date at which the certificate starts to be valid */
    notBefore: Date;
    /** the date after which the certificate is not valid any more */
    notAfter: Date;
    /** info about certificate owner */
    subject: DirectoryName;
    /** public key */
    publicKey: SubjectPublicKey;
}

export function coerceCertificate(certificate: Certificate | CertificatePEM): Certificate {
    if (typeof certificate === "string") {
        certificate = convertPEMtoDER(certificate);
    }
    assert(Buffer.isBuffer(certificate));
    return certificate;
}

/**
 * @method exploreCertificateInfo
 * returns useful information about the certificate such as public key length, start date and end of validity date,
 * and CN
 * @param certificate the certificate to explore
 */
export function exploreCertificateInfo(certificate: Certificate | CertificatePEM): CertificateInfo {
    certificate = coerceCertificate(certificate);

    const certInfo = exploreCertificate(certificate);
    const data: CertificateInfo = {
        publicKeyLength: certInfo.tbsCertificate.subjectPublicKeyInfo.keyLength,
        notBefore: certInfo.tbsCertificate.validity.notBefore,
        notAfter: certInfo.tbsCertificate.validity.notAfter,
        publicKey: certInfo.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
        subject: certInfo.tbsCertificate.subject,
    };
    // istanbul ignore next
    if (
        !(
            data.publicKeyLength === 512 ||
            data.publicKeyLength === 384 ||
            data.publicKeyLength === 256 ||
            data.publicKeyLength === 128
        )
    ) {
        throw new Error("Invalid public key length (expecting 128,256,384 or 512)" + data.publicKeyLength);
    }
    return data;
}
