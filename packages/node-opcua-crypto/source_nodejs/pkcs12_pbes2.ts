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

// RFC 8018 PBES2 (PBKDF2 + a block cipher) encrypt/decrypt via WebCrypto.
//
// This is used ONLY for the CMS `EncryptedData` that protects the
// certificate SafeContents. It is deliberately NOT used for the
// pkcs8ShroudedKeyBag: that bag is a plain PKCS#8 EncryptedPrivateKeyInfo,
// which Node's `crypto.createPrivateKey({ passphrase })` decrypts natively
// (PBES2 *and* the legacy PBE-SHA1-3DES scheme) — so pkcs12.ts hands the
// key bag straight to Node instead of routing it through here. Keeping
// this path off the key bag halves the hand-rolled-crypto surface and gains
// legacy 3DES key support for free.
//
// Legacy PBE (RC2-40/3DES) for the CERT bag is a separate, Node-only
// concern not implemented here — see the PKCS#12 plan for why.

import { randomBytes } from "node:crypto";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { Pkcs12UnsupportedAlgorithmError } from "../source/common.js";
import { OID_AES256_CBC, OID_HMAC_SHA1, OID_HMAC_SHA256, OID_PBES2, OID_PBKDF2, Pbes2Params, Pbkdf2Params } from "./pkcs12_asn1.js";

function prfHashName(oid: string | undefined): "SHA-1" | "SHA-256" {
    if (oid === undefined || oid === OID_HMAC_SHA1) {
        return "SHA-1"; // RFC 8018 default
    }
    if (oid === OID_HMAC_SHA256) {
        return "SHA-256";
    }
    throw new Pkcs12UnsupportedAlgorithmError(`Unsupported PBKDF2 PRF: ${oid}`);
}

async function derivePbes2Key(
    subtle: SubtleCrypto,
    algId: AlgorithmIdentifier,
    password: string,
    keyUsages: KeyUsage[],
): Promise<{ key: CryptoKey; iv: Uint8Array }> {
    if (algId.algorithm !== OID_PBES2) {
        throw new Pkcs12UnsupportedAlgorithmError(`Expected PBES2, got ${algId.algorithm}`);
    }
    if (!algId.parameters) {
        throw new Pkcs12UnsupportedAlgorithmError("PBES2 AlgorithmIdentifier is missing its parameters");
    }
    const pbes2 = AsnConvert.parse(algId.parameters, Pbes2Params);
    if (pbes2.keyDerivationFunc.algorithm !== OID_PBKDF2) {
        throw new Pkcs12UnsupportedAlgorithmError(
            `Unsupported PBES2 key derivation function: ${pbes2.keyDerivationFunc.algorithm}`,
        );
    }
    if (!pbes2.keyDerivationFunc.parameters) {
        throw new Pkcs12UnsupportedAlgorithmError("PBKDF2 AlgorithmIdentifier is missing its parameters");
    }
    const pbkdf2 = AsnConvert.parse(pbes2.keyDerivationFunc.parameters, Pbkdf2Params);
    const hash = prfHashName(pbkdf2.prf?.algorithm);
    const keyLength = pbkdf2.keyLength ?? 32; // AES-256

    if (pbes2.encryptionScheme.algorithm !== OID_AES256_CBC) {
        throw new Pkcs12UnsupportedAlgorithmError(`Unsupported PBES2 encryption scheme: ${pbes2.encryptionScheme.algorithm}`);
    }
    if (!pbes2.encryptionScheme.parameters) {
        throw new Pkcs12UnsupportedAlgorithmError("AES-CBC AlgorithmIdentifier is missing its IV parameter");
    }
    // AES-CBC parameters ::= OCTET STRING (the IV)
    const iv = new Uint8Array(AsnConvert.parse(pbes2.encryptionScheme.parameters, OctetString).buffer);

    const baseKey = await subtle.importKey("raw", Buffer.from(password, "utf-8"), "PBKDF2", false, ["deriveKey"]);
    const key = await subtle.deriveKey(
        { name: "PBKDF2", salt: pbkdf2.salt, iterations: pbkdf2.iterationCount, hash },
        baseKey,
        { name: "AES-CBC", length: keyLength * 8 },
        false,
        keyUsages,
    );
    return { key, iv };
}

export async function decryptPbes2(
    subtle: SubtleCrypto,
    encryptedContent: ArrayBuffer,
    algId: AlgorithmIdentifier,
    password: string,
): Promise<ArrayBuffer> {
    const { key, iv } = await derivePbes2Key(subtle, algId, password, ["decrypt"]);
    return subtle.decrypt({ name: "AES-CBC", iv: new Uint8Array(iv) }, key, encryptedContent);
}

/**
 * Encrypt via PBES2/PBKDF2(HMAC-SHA256)/AES-256-CBC and return both the
 * ciphertext and the `AlgorithmIdentifier` describing how to reverse it —
 * generates a fresh random salt and IV, matching the shape OpenSSL 3.x
 * itself produces (PBKDF2 with an explicit `hmacWithSHA256` PRF, not the
 * RFC-default SHA-1).
 */
export async function encryptPbes2(
    subtle: SubtleCrypto,
    plaintext: ArrayBuffer,
    password: string,
    iterations: number,
): Promise<{ encryptedContent: ArrayBuffer; algorithmIdentifier: AlgorithmIdentifier }> {
    // node:crypto randomBytes rather than the WebCrypto `crypto` global: the
    // global is only present on Node >= 19 without a flag, and this package
    // declares Node >= 18. Every other primitive here comes in via `subtle`.
    const salt = new Uint8Array(randomBytes(16));
    const iv = new Uint8Array(randomBytes(16));

    const baseKey = await subtle.importKey("raw", Buffer.from(password, "utf-8"), "PBKDF2", false, ["deriveKey"]);
    const key = await subtle.deriveKey(
        { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
        baseKey,
        { name: "AES-CBC", length: 256 },
        false,
        ["encrypt"],
    );
    const encryptedContent = await subtle.encrypt({ name: "AES-CBC", iv }, key, plaintext);

    const pbkdf2Params = new Pbkdf2Params({
        salt: salt.buffer as ArrayBuffer,
        iterationCount: iterations,
        prf: new AlgorithmIdentifier({ algorithm: OID_HMAC_SHA256 }),
    });
    const pbes2Params = new Pbes2Params({
        keyDerivationFunc: new AlgorithmIdentifier({ algorithm: OID_PBKDF2, parameters: AsnConvert.serialize(pbkdf2Params) }),
        encryptionScheme: new AlgorithmIdentifier({
            algorithm: OID_AES256_CBC,
            parameters: AsnConvert.serialize(new OctetString(iv)),
        }),
    });
    const algorithmIdentifier = new AlgorithmIdentifier({ algorithm: OID_PBES2, parameters: AsnConvert.serialize(pbes2Params) });

    return { encryptedContent, algorithmIdentifier };
}
