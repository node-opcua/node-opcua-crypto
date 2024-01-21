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

import { explorePrivateKey } from "./explore_private_key.js";
import { Certificate, CertificatePEM, PrivateKey } from "./common.js";
import { privateDecrypt_long, publicEncrypt_long, toPem } from "./crypto_utils.js";
import { exploreCertificate } from "./crypto_explore_certificate.js";

export function publicKeyAndPrivateKeyMatches(certificate: Certificate, privateKey: PrivateKey): boolean {
    const i = exploreCertificate(certificate);
    const j = explorePrivateKey(privateKey);

    const modulus1 = i.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.modulus;
    const modulus2 = j.modulus;

    if (modulus1.length != modulus2.length) {
        return false;
    }
    return modulus1.toString("hex") === modulus2.toString("hex");
}

/**
 * check that the given certificate matches the given private key
 * @param certificate
 * @param privateKey
 */
function certificateMatchesPrivateKeyPEM(certificate: CertificatePEM, privateKey: PrivateKey, blockSize: number): boolean {
    const initialBuffer = Buffer.from("Lorem Ipsum");
    const encryptedBuffer = publicEncrypt_long(initialBuffer, certificate, blockSize, 11);
    const decryptedBuffer = privateDecrypt_long(encryptedBuffer, privateKey, blockSize);
    const finalString = decryptedBuffer.toString("utf-8");
    return initialBuffer.toString("utf-8") === finalString;
}

export function certificateMatchesPrivateKey(certificate: Certificate, privateKey: PrivateKey): boolean {
    const e = explorePrivateKey(privateKey);
    const blockSize = e.modulus.length;
    const certificatePEM = toPem(certificate, "CERTIFICATE");
    return certificateMatchesPrivateKeyPEM(certificatePEM, privateKey, blockSize);
}
