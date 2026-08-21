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
import { getCrypto } from "./_crypto.js";

/**
 * The signing algorithm a {@link CaSigner} operates under. This travels with
 * the signer rather than being inferred from a key, because an HSM/KMS-backed
 * signer (e.g. Google Cloud KMS) exposes no key material to inspect — only a
 * public key and a `sign` operation whose algorithm the caller must already
 * know.
 */
export type CaSignAlgorithm =
    | { name: "RSASSA-PKCS1-v1_5"; hash: { name: "SHA-256" | "SHA-384" | "SHA-512" } }
    | { name: "ECDSA"; hash: { name: "SHA-256" | "SHA-384" | "SHA-512" } };

/**
 * Abstraction over "something that can produce a certificate/CRL signature",
 * without ever exposing private key material.
 *
 * This is deliberately shaped after Google Cloud KMS (and similar HSM APIs):
 * the caller builds the to-be-signed bytes locally and hands them to
 * {@link sign}; the signer never returns, and this interface never asks for,
 * the private key itself. A local PEM/DER key is adapted to this interface
 * via {@link LocalPrivateKeySigner}; a KMS key is adapted by wrapping its
 * `getPublicKey` / `asymmetricSign` calls the same way.
 */
export interface CaSigner {
    /** The algorithm this signer signs with — declared, not inferred. */
    readonly algorithm: CaSignAlgorithm;

    /** The public key, SPKI-encoded DER. */
    getPublicKey(): Promise<ArrayBuffer>;

    /**
     * Sign `tbs` (the to-be-signed bytes, e.g. a certificate or CRL's TBS
     * DER encoding) and return the raw signature bytes.
     */
    sign(tbs: Uint8Array): Promise<ArrayBuffer>;
}

/**
 * Adapts an in-process key pair (e.g. one produced by {@link generateKeyPair}
 * or read from disk via {@link pemToPrivateKey}) to the {@link CaSigner}
 * interface, so CA-signing code only ever has to know about one signer
 * shape regardless of whether the key lives on disk or in an HSM.
 */
export class LocalPrivateKeySigner implements CaSigner {
    readonly algorithm: CaSignAlgorithm;
    readonly #privateKey: CryptoKey;
    readonly #publicKey: CryptoKey;
    readonly #crypto: Pick<Crypto, "subtle">;

    constructor(
        keys: { privateKey: CryptoKey; publicKey: CryptoKey },
        algorithm: CaSignAlgorithm,
        crypto: Pick<Crypto, "subtle"> = getCrypto() as unknown as Pick<Crypto, "subtle">,
    ) {
        this.#privateKey = keys.privateKey;
        this.#publicKey = keys.publicKey;
        this.algorithm = algorithm;
        this.#crypto = crypto;
    }

    async getPublicKey(): Promise<ArrayBuffer> {
        return this.#crypto.subtle.exportKey("spki", this.#publicKey);
    }

    async sign(tbs: Uint8Array): Promise<ArrayBuffer> {
        return this.#crypto.subtle.sign(this.algorithm, this.#privateKey, tbs as BufferSource);
    }
}

/**
 * A `Crypto`-shaped object plus the key handles needed to drive
 * `@peculiar/x509`'s certificate/CSR/CRL generators against a {@link CaSigner}
 * instead of a real in-process private key.
 */
export interface WebCryptoFromSigner {
    /**
     * Pass this as the generator's per-call `crypto` argument (every
     * `@peculiar/x509` generator accepts one). Every member other than
     * `subtle.sign` is delegated to the underlying crypto provider
     * unchanged; `subtle.sign`, when called with {@link privateKeyHandle},
     * is routed to `signer.sign(...)` instead of touching any private key
     * material.
     */
    crypto: Crypto;
    /**
     * An opaque placeholder to pass as `keys.privateKey` to a generator.
     * It carries no key material — it exists only so `crypto.subtle.sign`
     * has something to recognize and route to the signer. Never pass it to
     * anything other than the paired {@link crypto} object.
     */
    privateKeyHandle: CryptoKey;
    /** The signer's public key, imported as a real, usable `CryptoKey`. */
    publicKey: CryptoKey;
}

/**
 * Build a `Crypto`-shaped adapter that routes signing through `signer`
 * while delegating everything else (hashing, key import/export, random
 * bytes) to `baseCrypto`. This lets `@peculiar/x509`'s certificate, CSR and
 * CRL generators — which all accept crypto as a per-call argument rather
 * than only a process-global one — sign with an HSM/KMS-backed key without
 * that key ever existing as an in-process `CryptoKey`.
 */
export async function webCryptoFromSigner(
    signer: CaSigner,
    baseCrypto: Pick<Crypto, "subtle" | "getRandomValues"> = getCrypto() as unknown as Crypto,
): Promise<WebCryptoFromSigner> {
    const publicKeyDer = await signer.getPublicKey();
    const publicKey = await baseCrypto.subtle.importKey("spki", publicKeyDer, signer.algorithm, true, ["verify"]);

    // Never dereferenced for key material — subtle.sign below recognizes it
    // by identity and routes to signer.sign() instead of using it as a key.
    const privateKeyHandle = {
        type: "private",
        extractable: false,
        algorithm: signer.algorithm,
        usages: ["sign"],
    } as CryptoKey;

    const subtle = new Proxy(baseCrypto.subtle, {
        get(target, prop, receiver) {
            if (prop === "sign") {
                return async (algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource) => {
                    if (key !== privateKeyHandle) {
                        return target.sign(algorithm, key, data);
                    }
                    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data as ArrayBuffer);
                    return signer.sign(bytes);
                };
            }
            const value = Reflect.get(target, prop, receiver);
            return typeof value === "function" ? value.bind(target) : value;
        },
    });

    const crypto = new Proxy(baseCrypto as unknown as Crypto, {
        get(target, prop, receiver) {
            if (prop === "subtle") {
                return subtle;
            }
            const value = Reflect.get(target, prop, receiver);
            return typeof value === "function" ? value.bind(target) : value;
        },
    });

    return { crypto, privateKeyHandle, publicKey };
}

/** True when `value` implements {@link CaSigner} rather than being a raw `CryptoKey`. */
function isCaSigner(value: CryptoKey | CaSigner): value is CaSigner {
    // a CryptoKey never carries methods — only `type`/`extractable`/`algorithm`/`usages`.
    return typeof (value as CaSigner).sign === "function" && typeof (value as CaSigner).getPublicKey === "function";
}

/** The `crypto`/`signingKey` pair a `@peculiar/x509` generator needs, resolved from either a raw key or a {@link CaSigner}. */
export interface ResolvedCaSigningKey {
    crypto: Crypto;
    signingKey: CryptoKey;
}

/**
 * Resolves a `CryptoKey | CaSigner` union into the `{ crypto, signingKey }`
 * pair a `@peculiar/x509` generator's `signingKey`/per-call `crypto`
 * arguments need — a raw `CryptoKey` is passed through unchanged against
 * `baseCrypto`; a {@link CaSigner} is adapted via {@link webCryptoFromSigner}.
 * This is the single place CA-signing primitives (certificate, CSR, CRL
 * generation) need to branch on which kind of signing key they were given.
 */
export async function resolveCaSigningKey(
    signingKey: CryptoKey | CaSigner,
    baseCrypto: Pick<Crypto, "subtle" | "getRandomValues"> = getCrypto() as unknown as Crypto,
): Promise<ResolvedCaSigningKey> {
    if (isCaSigner(signingKey)) {
        const adapted = await webCryptoFromSigner(signingKey, baseCrypto);
        return { crypto: adapted.crypto, signingKey: adapted.privateKeyHandle };
    }
    return { crypto: baseCrypto as Crypto, signingKey };
}
