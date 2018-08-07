
import {  exploreCertificate } from "./crypto_explore_certificate";
import { readPEM } from "./crypto_utils";

const  assert = require("better-assert");

/**
 * @method exploreCertificate
 * @param certificate
 * @return object.publicKeyLength
 * @return object.notBefore
 * @return object.notAfter
 */
const a = 1;
interface CertificateInfo {
    publicKeyLength: number;
    notBefore: Date;
    notAfter: Date;
}

export function exploreCertificateInfo(certificate: Buffer | string): CertificateInfo {

    if (typeof certificate === "string") {
        certificate = readPEM(certificate);
    }
    assert(certificate instanceof Buffer);

    const certInfo = exploreCertificate(certificate);

    const data : CertificateInfo= {
        publicKeyLength: certInfo.tbsCertificate.subjectPublicKeyInfo.keyLength,
        notBefore:       certInfo.tbsCertificate.validity.notBefore,
        notAfter:        certInfo.tbsCertificate.validity.notAfter
    };
    if (!(data.publicKeyLength  === 512 || data.publicKeyLength === 384 || data.publicKeyLength === 256 || data.publicKeyLength === 128)) {
        throw new Error("Invalid public key length (expecting 128,256,384 or 512)" + data.publicKeyLength);
    }
    return data;
}

