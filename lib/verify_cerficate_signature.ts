// tslint:disable: no-console


// Now that we got a hash of the orginal certificate,
// we need to verify if we can obtain the same hash by using the same hashing function 
// (in this case SHA-384). In order to do that, we need to extract just the body of 
// the signed certificate. Which, in our case, is everything but the signature. 
// The start of the body is always the first digit of the second line of the following command:

import { Certificate } from "./common";
import * as crypto from "crypto";
import { readTag, readStruct, read_AlgorithmIdentifier, read_SignatureValue, read_SignatureValueBin, TagType } from "./crypto_explore_certificate";
import { split_der, exploreCertificate, toPem, PrivateKey, PaddingAlgorithm } from "../dist";
import { extractPublicKeyFromCertificateSync, convertPEMtoDER } from ".";
import { kMaxLength } from "buffer";


function getHash(algo: string): crypto.Hash {
    return crypto.createHash(algo);
    switch (algo) {
        case "md2WithRSAEncryption":
            return crypto.createHash("md2");
        case "md4WithRSAEncryption":
            return crypto.createHash("md4");
        case "md5WithRSAEncryption":
            return crypto.createHash("md5");
        case "sha1WithRSAEncryption":
            return crypto.createHash("sha1");
        case "sha256WithRSAEncryption":
            return crypto.createHash("sha256");
        case "sha384WithRSAEncryption":
            return crypto.createHash("sha384");
        case "sha512WithRSAEncryption":
            return crypto.createHash("sha512");
        case "sha224WithRSAEncryption":
            return crypto.createHash("sh224");
    }
    throw new Error("Unsupport algo " + algo);

}
function convertToDEROctetString(buffer: Buffer): Buffer {
    /**
     * 2.11 Encoding of a length prefix
     * The length prefix that is part of the encoding of certain ASN.1 types (see the sections referencing this section)
     * specifies the length of an encoding in terms of number of octets. A length prefix consists of one or more octets,
     * as follows:
     * 1) If the length is less than 128, it is encoded in the lowest-order 7 bit positions of the first and only octet,
     *    and the highest-order bit of the octet is set to zero.
     * 2) If the length is greater than 127, it is encoded in one or more subsequent octets, in big-endian order.
     *    The number of those octets is indicated in the lowest-order 7 bit positions of the first octet, and the
     *    highest-order bit of that octet is set to 1.
     */

    const l = buffer.length;
    const b = Buffer.alloc(l + 10, 0);
    let c = 0;
    b[0] = TagType.OCTET_STRING;

    if (l <= 127) {
        b[1] = l;
        c = 2;
    } else if (l < 256) {
        b[1] = 0x81;
        b[2] = l;
        c = 3;
    } else if (l < 65535) {
        b[1] = 0x82;
        b[2] = (l - l % 256) / 256;
        b[3] = l % 256;
        c = 4;
    } else {
        throw new Error("Not supported yet");
    }
    // count the number of octect
    for (let i = 0; i < buffer.length; i++) {
        b[c++] = buffer[i];
    }
    return b.slice(0, c);
}
function convertToDERBitString(buffer: Buffer): Buffer {
    const l = buffer.length;
    const b = Buffer.alloc(l + 10, 0);
    let c = 0;
    b[0] = TagType.BIT_STRING;
    if (l <= 127) {
        b[1] = l;
        c = 2;
    } else if (l < 256) {
        b[1] = 0x81;
        b[2] = l;
        c = 3;
    } else if (l < 65535) {
        b[1] = 0x82;
        b[2] = (l - l % 256) / 256;
        b[3] = l % 256;
        c = 4;
    } else {
        throw new Error("Not supported yet");
    }
    b[c++] = 0; // unused bits
    // count the number of octect
    for (let i = 0; i < buffer.length; i++) {
        b[c++] = buffer[i];
    }

    return b.slice(0, c);

}


export function verifyCertificateSignature(
    certificate: Certificate,
    parentCerticate: Certificate,
    caPrivateKey?: PrivateKey
): boolean {

    // console.log(certificate.toString("hex"));

    const block_info = readTag(certificate, 0);
    const blocks = readStruct(certificate, block_info);

    //  console.log(block_info, blocks[0], blocks[1], blocks[2]);
    const bufferTbsCertificate = certificate.slice(block_info.position, block_info.position + 4 + blocks[0].length);

    //xx console.log("bufferTbsCertificate = ", bufferTbsCertificate.length);
    const signatureAlgorithm = read_AlgorithmIdentifier(certificate, blocks[1]);
    const signatureValue = read_SignatureValueBin(certificate, blocks[2]);

    const p = split_der(parentCerticate)[0];
    //xx    const publicKey = extractPublicKeyFromCertificateSync(p);
    const certPem = toPem(p, "CERTIFICATE")
    const verify = crypto.createVerify(signatureAlgorithm.identifier);
    verify.update(bufferTbsCertificate);
    verify.end();
    return verify.verify(certPem, signatureValue);
}