// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2023 - Sterfive.com
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
import { x509 } from "./_crypto.js";
import { getCrypto } from "./_crypto";

export async function generateKeyPair(modulusLength: 1024 | 2048 | 3072 | 4096 = 2048): Promise<CryptoKeyPair> {
    const crypto = getCrypto();

    const alg: RsaHashedKeyGenParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength,
    };
    const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

    return keys;
}

export async function generatePrivateKey(modulusLength: 1024 | 2048 | 3072 | 4096 = 2048): Promise<CryptoKey> {
    return (await generateKeyPair(modulusLength)).privateKey;
}

export async function privateKeyToPEM(privateKey: CryptoKey) {
    const crypto = getCrypto();

    const privDer = await crypto.subtle.exportKey("pkcs8", privateKey);
    const privPem = x509.PemConverter.encode(privDer, "PRIVATE KEY");
    return { privPem, privDer };
}

export async function derToPrivateKey(privDer: ArrayBuffer): Promise<CryptoKey> {
    const crypto = getCrypto();

    return await crypto.subtle.importKey(
        "pkcs8",
        privDer,
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: { name: "SHA-256" },
        },
        true,
        [
            "sign",
            // "encrypt",
            // "decrypt",
            // "verify",
            //    "wrapKey",
            //    "unwrapKey",
            //    "deriveKey",
            //    "deriveBits"
        ]
    );
}

export async function pemToPrivateKey(pem: string): Promise<CryptoKey> {
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
    const privDer = x509.PemConverter.decode(pem);
    return derToPrivateKey(privDer[0]);
}
