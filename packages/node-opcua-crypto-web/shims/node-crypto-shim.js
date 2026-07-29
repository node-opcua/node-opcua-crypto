/**
 * node-crypto-shim.js
 *
 * Re-exports everything from crypto-browserify, then adds
 * minimal browser implementations of createPublicKey / createPrivateKey
 * that crypto-browserify doesn't provide.
 *
 * This file is ONLY used at esbuild bundle time (via alias in build-web.mjs).
 * Node.js users always get native node:crypto.
 */
import cryptoBrowserify from "crypto-browserify";

// Re-export everything crypto-browserify provides
export const createHash = cryptoBrowserify.createHash;
export const createHmac = cryptoBrowserify.createHmac;
export const createSign = cryptoBrowserify.createSign;
export const createVerify = cryptoBrowserify.createVerify;
export const createCipheriv = cryptoBrowserify.createCipheriv;
export const createDecipheriv = cryptoBrowserify.createDecipheriv;
export const publicEncrypt = cryptoBrowserify.publicEncrypt;
export const privateDecrypt = cryptoBrowserify.privateDecrypt;
export const randomBytes = cryptoBrowserify.randomBytes;
export const pseudoRandomBytes = cryptoBrowserify.pseudoRandomBytes;
export const getCiphers = cryptoBrowserify.getCiphers;
export const getHashes = cryptoBrowserify.getHashes;
export const pbkdf2 = cryptoBrowserify.pbkdf2;
export const pbkdf2Sync = cryptoBrowserify.pbkdf2Sync;
export const getDiffieHellman = cryptoBrowserify.getDiffieHellman;
export const createDiffieHellman = cryptoBrowserify.createDiffieHellman;
export const createECDH = cryptoBrowserify.createECDH;
export const randomFillSync = cryptoBrowserify.randomFillSync;
export const randomFill = cryptoBrowserify.randomFill;

// ---------- Minimal DER/ASN1 helpers ----------

function readLength(buf, offset) {
    let length = buf[offset];
    offset++;
    if ((length & 0x80) !== 0) {
        const numBytes = length & 0x7f;
        length = 0;
        for (let i = 0; i < numBytes; i++) {
            length = (length << 8) | buf[offset];
            offset++;
        }
    }
    return { length, offset };
}

/** Read one TLV (tag-length-value) from the buffer at the given offset. */
function readTLV(buf, offset) {
    const tag = buf[offset];
    const startOffset = offset;
    offset++;
    const { length, offset: dataOffset } = readLength(buf, offset);
    return { tag, length, dataOffset, endOffset: dataOffset + length, startOffset };
}

/** Skip N children inside a SEQUENCE starting at `offset`. */
function skipChildren(buf, offset, count) {
    for (let i = 0; i < count; i++) {
        const tlv = readTLV(buf, offset);
        offset = tlv.endOffset;
    }
    return offset;
}

function pemToDer(pem) {
    const base64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    return Buffer.from(base64, "base64");
}

function derToPem(der, label) {
    const base64 = (Buffer.isBuffer(der) ? der : Buffer.from(der)).toString("base64");
    let pem = `-----BEGIN ${label}-----\n`;
    for (let i = 0; i < base64.length; i += 64) {
        pem += base64.substring(i, i + 64) + "\n";
    }
    pem += `-----END ${label}-----`;
    return pem;
}

// ---------- Extract SPKI from X.509 certificate DER ----------

function extractSPKIFromCertDER(der) {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, sig }
    let tlv = readTLV(der, 0);       // outer SEQUENCE
    let offset = tlv.dataOffset;

    // TBSCertificate ::= SEQUENCE { ... }
    tlv = readTLV(der, offset);
    offset = tlv.dataOffset;

    // version [0] EXPLICIT (optional)
    tlv = readTLV(der, offset);
    if (tlv.tag === 0xa0) {
        offset = tlv.endOffset;
    }
    // serialNumber, signature, issuer, validity, subject → skip 5 children
    offset = skipChildren(der, offset, 5);

    // subjectPublicKeyInfo SEQUENCE — capture the whole TLV
    tlv = readTLV(der, offset);
    return der.subarray(tlv.startOffset, tlv.endOffset);
}

// ---------- Extract modulus bit-length from SPKI DER ----------

function modulusLengthFromSPKI(spki) {
    let offset = 0;
    let tlv = readTLV(spki, offset);   // SEQUENCE (SubjectPublicKeyInfo)
    offset = tlv.dataOffset;

    // algorithm SEQUENCE — skip
    tlv = readTLV(spki, offset);
    offset = tlv.endOffset;

    // BIT STRING
    tlv = readTLV(spki, offset);
    offset = tlv.dataOffset;
    offset++; // skip "unused bits" byte

    // RSAPublicKey SEQUENCE
    tlv = readTLV(spki, offset);
    offset = tlv.dataOffset;

    // modulus INTEGER
    tlv = readTLV(spki, offset);
    let len = tlv.length;
    // leading zero byte for unsigned representation
    if (spki[tlv.dataOffset] === 0) len--;
    return len * 8;
}

// ---------- Extract modulus bit-length from PKCS#1 / PKCS#8 private key DER --

function modulusLengthFromPrivateKeyDER(der, isPKCS8) {
    let offset = 0;
    let tlv;

    if (isPKCS8) {
        // PrivateKeyInfo ::= SEQUENCE { version, algorithm, OCTET STRING }
        tlv = readTLV(der, offset);   // outer SEQUENCE
        offset = tlv.dataOffset;

        // version INTEGER — skip
        tlv = readTLV(der, offset);
        offset = tlv.endOffset;

        // algorithm SEQUENCE — skip
        tlv = readTLV(der, offset);
        offset = tlv.endOffset;

        // OCTET STRING containing PKCS#1 RSAPrivateKey
        tlv = readTLV(der, offset);
        offset = tlv.dataOffset;
    }

    // RSAPrivateKey ::= SEQUENCE { version, modulus, ... }
    tlv = readTLV(der, offset);
    offset = tlv.dataOffset;

    // version INTEGER — skip
    tlv = readTLV(der, offset);
    offset = tlv.endOffset;

    // modulus INTEGER
    tlv = readTLV(der, offset);
    let len = tlv.length;
    if (der[tlv.dataOffset] === 0) len--;
    return len * 8;
}

// ---------- createPublicKey / createPrivateKey ----------

export function createPublicKey(input) {
    const pem = typeof input === "string"
        ? input
        : (input && input.key) ? input.key.toString() : input.toString();

    const isCert = pem.includes("BEGIN CERTIFICATE");
    const der = pemToDer(pem);

    let spkiDer;
    if (isCert) {
        spkiDer = extractSPKIFromCertDER(der);
    } else {
        spkiDer = der; // already SPKI
    }

    const modulusLength = modulusLengthFromSPKI(spkiDer);

    return {
        type: "public",
        asymmetricKeyType: "rsa",
        asymmetricKeyDetails: { modulusLength },
        export(options) {
            if (!options || options.format === "pem") {
                return derToPem(spkiDer, "PUBLIC KEY");
            }
            return spkiDer;
        },
    };
}

export function createPrivateKey(input) {
    const pem = typeof input === "string" ? input : input.toString();
    const der = pemToDer(pem);
    const isPKCS8 = pem.includes("BEGIN PRIVATE KEY");

    const modulusLength = modulusLengthFromPrivateKeyDER(der, isPKCS8);

    return {
        type: "private",
        asymmetricKeyType: "rsa",
        asymmetricKeyDetails: { modulusLength },
        export(options) {
            const fmt = options?.format || "pem";
            const tp = options?.type || "pkcs8";
            if (fmt === "pem") {
                if (tp === "pkcs1") {
                    if (pem.includes("BEGIN RSA PRIVATE KEY")) return pem;
                    throw new Error("PKCS8→PKCS1 conversion not supported in browser shim");
                }
                return pem;
            }
            return der;
        },
    };
}

export default {
    ...cryptoBrowserify,
    createPublicKey,
    createPrivateKey,
};
