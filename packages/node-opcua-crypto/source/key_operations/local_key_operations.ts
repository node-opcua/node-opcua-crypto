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
// the legacy constants module rather than crypto.constants: it is what the
// browser shim of node-opcua-crypto-web knows how to satisfy (same choice as crypto_utils.ts).
import constants from "node:constants";
import { createPrivateKey, createPublicKey, createSign, type KeyObject, privateDecrypt } from "node:crypto";
import type { PrivateKey } from "../common.js";
import type { AsymmetricDecryptParams, AsymmetricSignParams, IKeyOperations, KeyMetadata } from "./key_operations.js";

function toNodeHash(hash: "SHA-1" | "SHA-256"): "RSA-SHA1" | "RSA-SHA256" {
    return hash === "SHA-1" ? "RSA-SHA1" : "RSA-SHA256";
}

/**
 * Adapts an in-process private key — the {@link PrivateKey} envelope — to
 * {@link IKeyOperations}, sync fast path included, so callers only ever deal
 * with one key shape whether the key lives in memory or in an HSM.
 *
 * This class is intended to be the ONE place that dereferences
 * `privateKey.hidden`; everything above it should hold an
 * {@link IKeyOperations} and stay ignorant of key material.
 *
 * Failure behavior differs deliberately from `privateDecrypt_native`, which
 * swallows errors into a 1-byte buffer: {@link decryptBlock} throws, like any
 * remote provider would. A caller that needs the swallow-and-return-garbage
 * anti-oracle behavior implements it above this interface, uniformly for
 * local and remote keys.
 */
export class LocalKeyOperations implements IKeyOperations {
    readonly #key: KeyObject;
    readonly #metadata: KeyMetadata;

    constructor(privateKey: PrivateKey) {
        const hidden = privateKey.hidden;
        // re-imported through pkcs8 DER rather than cast, so a malformed
        // envelope fails here, loudly, not at first use.
        this.#key =
            typeof hidden === "string"
                ? createPrivateKey(hidden)
                : createPrivateKey({ key: hidden.export({ type: "pkcs8", format: "der" }), format: "der", type: "pkcs8" });
        if (this.#key.asymmetricKeyType !== "rsa") {
            throw new Error(`LocalKeyOperations supports RSA keys only for now, got a "${this.#key.asymmetricKeyType}" key`);
        }
        const modulusLength = this.#key.asymmetricKeyDetails?.modulusLength;
        if (!modulusLength) {
            throw new Error("cannot determine the modulus length of the private key");
        }
        this.#metadata = { keyType: "RSA", modulusLength: modulusLength / 8 };
    }

    getKeyMetadataSync(): KeyMetadata {
        return this.#metadata;
    }

    async getKeyMetadata(): Promise<KeyMetadata> {
        return this.#metadata;
    }

    async getPublicKey(): Promise<ArrayBuffer> {
        const spki = createPublicKey(this.#key).export({ type: "spki", format: "der" });
        return spki.buffer.slice(spki.byteOffset, spki.byteOffset + spki.byteLength);
    }

    signSync(data: Uint8Array, params: AsymmetricSignParams): Buffer {
        const signer = createSign(toNodeHash(params.hash));
        signer.update(data);
        if (params.padding === "RSA-PSS") {
            // salt length pinned to the digest length: the convention the
            // OPC UA Aes256_Sha256_RsaPss profile and WebCrypto verifiers expect.
            return signer.sign({
                key: this.#key,
                padding: constants.RSA_PKCS1_PSS_PADDING,
                saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
            });
        }
        return signer.sign(this.#key);
    }

    async sign(data: Uint8Array, params: AsymmetricSignParams): Promise<Buffer> {
        return this.signSync(data, params);
    }

    decryptBlockSync(block: Uint8Array, params: AsymmetricDecryptParams): Buffer {
        if (block.length !== this.#metadata.modulusLength) {
            throw new Error(
                `decryptBlock expects exactly one cipher block of ${this.#metadata.modulusLength} bytes, got ${block.length}`,
            );
        }
        if (params.padding === "RSA-OAEP") {
            if (!params.oaepHash) {
                throw new Error("RSA-OAEP decryption requires an oaepHash");
            }
            return privateDecrypt(
                {
                    key: this.#key,
                    padding: constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: params.oaepHash === "SHA-256" ? "sha256" : "sha1",
                },
                block,
            );
        }
        return privateDecrypt({ key: this.#key, padding: constants.RSA_PKCS1_PADDING }, block);
    }

    async decryptBlock(block: Uint8Array, params: AsymmetricDecryptParams): Promise<Buffer> {
        return this.decryptBlockSync(block, params);
    }
}

/** Wraps a {@link PrivateKey} envelope as {@link IKeyOperations}. */
export function keyOperationsFromPrivateKey(privateKey: PrivateKey): LocalKeyOperations {
    return new LocalKeyOperations(privateKey);
}
