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

// tslint:disabled:no-var-requires
/**
 * @module node_opcua_crypto
 */
import assert from "assert";

// be careful: createPrivateKey is not polyfilled in crypto-browserify
import { createPrivateKey as createPrivateKeyFromNodeJSCrypto, KeyObject } from "crypto";

import { PublicKey, PublicKeyPEM, PrivateKeyPEM, PrivateKey } from "./common.js";
import { toPem } from "./crypto_utils.js";
import { type } from "os";

const jsrsasign = require("jsrsasign");

/***
 * @method rsaLengthPrivateKey
 * A very expensive way to determine the rsa key length ( i.e 2048bits or 1024bits)
 * @param key  a PEM public key or a PEM rsa private key
 * @return the key length in bytes.
 */
export function rsaLengthPrivateKey(key: PrivateKey): number {
    const keyPem = typeof key.hidden === "string" ? key.hidden : key.hidden.export({ type: "pkcs1", format: "pem" }).toString();
    // in node 16 and above :
    // return o.asymmetricKeyDetails.modulusLength/8
    // in node <16 :
    const a = jsrsasign.KEYUTIL.getKey(keyPem);
    return a.n.toString(16).length / 2;
}

/**
 * @method toPem2
 * @param raw_key
 * @param pem
 *
 *
 * @return a PEM string containing the Private Key
 *
 * Note:  a Pem key can be converted back to a private key object using coercePrivateKey
 *
 */
export function toPem2(raw_key: Buffer | string | KeyObject | PrivateKey, pem: string): string {
    if ((raw_key as PrivateKey).hidden) {
        return toPem2((raw_key as PrivateKey).hidden, pem);
    }
    assert(raw_key, "expecting a key");
    assert(typeof pem === "string");

    if (raw_key instanceof KeyObject) {
        if (pem === "RSA PRIVATE KEY") {
            return raw_key.export({ format: "pem", type: "pkcs1" }).toString();
        } else if (pem === "PRIVATE KEY") {
            return raw_key.export({ format: "pem", type: "pkcs8" }).toString();
        } else {
            throw new Error("Unsupported case!");
        }
    }
    return toPem(raw_key as (Buffer | string), pem);
}

export function coercePrivateKeyPem(privateKey: PrivateKey): PrivateKeyPEM {
    return toPem2(privateKey, "PRIVATE KEY");
    /*
    if (privateKey.hidden instanceof Buffer) {
        const o = createPrivateKeyFromNodeJSCrypto({ key: privateKey.hidden, format: "der", type: "pkcs1" });
        const e = o.export({ format: "der", type: "pkcs1" });
        return toPem(e, "RSA PRIVATE KEY");
    } else if (privateKey.hidden instanceof KeyObject) {
        const o = privateKey.hidden.export({ format: "pem", type: "pkcs1" });
        return o.toString();
    } else if (typeof privateKey.hidden === "string") {
        return privateKey.hidden;
    }
    throw new Error("Invalid privateKey");
    */
}

export function coercePublicKeyPem(publicKey: PublicKey | PublicKeyPEM): PublicKeyPEM {
    if (publicKey instanceof KeyObject) {
        return publicKey.export({ format: "pem", type: "spki" }).toString();
    }
    assert(typeof publicKey === "string");
    return publicKey;
}
export function coerceRsaPublicKeyPem(publicKey: PublicKey | PublicKeyPEM): PublicKeyPEM {
    if (publicKey instanceof KeyObject) {
        return publicKey.export({ format: "pem", type: "spki" }).toString();
    }
    assert(typeof publicKey === "string");
    return publicKey;
}

export function rsaLengthPublicKey(key: PublicKeyPEM | PublicKey): number {
    key = coercePublicKeyPem(key);
    assert(typeof key === "string");
    const a = jsrsasign.KEYUTIL.getKey(key);
    return a.n.toString(16).length / 2;
}
export function rsaLengthRsaPublicKey(key: PublicKeyPEM | PublicKey): number {
    key = coerceRsaPublicKeyPem(key);
    assert(typeof key === "string");
    const a = jsrsasign.KEYUTIL.getKey(key);
    return a.n.toString(16).length / 2;
}
