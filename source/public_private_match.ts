import { explorePrivateKey } from "./explore_private_key";
import { Certificate, CertificatePEM, PrivateKey, PrivateKeyPEM } from "./common";
import { privateDecrypt_long, publicEncrypt_long, toPem } from "./crypto_utils";
import { exploreCertificate } from "./crypto_explore_certificate";

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
