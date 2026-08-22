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
import { buildPublicKey } from "./_build_public_key.js";
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
    | {
          name: "ECDSA";
          /**
           * The curve the key lives on. Required, unlike in most WebCrypto
           * signing parameters, because {@link webCryptoFromSigner} has to
           * *import* the signer's public key, and `importKey` cannot infer a
           * curve it was not given. Declaring it wrong is safe: the SPKI
           * bytes returned by {@link CaSigner.getPublicKey} state the real
           * curve, so the import fails rather than producing a key that
           * signs into the void.
           */
          namedCurve: "P-256" | "P-384" | "P-521";
          hash: { name: "SHA-256" | "SHA-384" | "SHA-512" };
      };

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
     * DER encoding) and return the signature.
     *
     * The signature must be encoded the way `SubtleCrypto.sign` encodes it,
     * because that is what the certificate generators are given and what
     * they know how to re-encode:
     *
     * - **RSA** - the signature bytes, with nothing to decide.
     * - **ECDSA** - the fixed-width `r || s` pair of IEEE P1363, *not* the
     *   `SEQUENCE { r, s }` of DER. Certificates carry the DER form, but the
     *   conversion is done downstream; a signer that returns DER here
     *   produces a certificate whose signature will not verify.
     *
     * That distinction matters for KMS-backed signers: Google Cloud KMS,
     * AWS KMS and most PKCS#11 tokens return ECDSA signatures already in
     * DER, so their adapters have to convert to `r || s` before returning.
     * {@link ecdsaSignatureDerToP1363} does that conversion.
     */
    sign(tbs: Uint8Array): Promise<ArrayBuffer>;
}

/** Bytes per coordinate for each curve a {@link CaSignAlgorithm} can name. */
const ECDSA_COORDINATE_BYTES: Record<"P-256" | "P-384" | "P-521", number> = {
    "P-256": 32,
    "P-384": 48,
    // 521 bits is not a byte multiple, so each coordinate occupies 66 bytes
    "P-521": 66,
};

/** Views any `BufferSource` as bytes, without copying where possible. */
function asBytes(source: BufferSource): Uint8Array {
    if (source instanceof Uint8Array) {
        return source;
    }
    if (ArrayBuffer.isView(source)) {
        return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    }
    return new Uint8Array(source);
}

/** Reads a DER length, short or long form, advancing `cursor`. */
function readDerLength(bytes: Uint8Array, cursor: { offset: number }): number {
    const first = bytes[cursor.offset++];
    if (first === undefined) {
        throw new Error("malformed ECDSA signature: truncated length");
    }
    if (first < 0x80) {
        return first;
    }
    const byteCount = first & 0x7f;
    if (byteCount === 0 || byteCount > 4) {
        throw new Error(`malformed ECDSA signature: unsupported length encoding (0x${first.toString(16)})`);
    }
    let length = 0;
    for (let index = 0; index < byteCount; index++) {
        const byte = bytes[cursor.offset++];
        if (byte === undefined) {
            throw new Error("malformed ECDSA signature: truncated length");
        }
        length = length * 256 + byte;
    }
    return length;
}

/** Reads one DER INTEGER, advancing `cursor`. */
function readDerInteger(bytes: Uint8Array, cursor: { offset: number }): Uint8Array {
    if (bytes[cursor.offset++] !== 0x02) {
        throw new Error("malformed ECDSA signature: expected an INTEGER");
    }
    const length = readDerLength(bytes, cursor);
    const end = cursor.offset + length;
    if (length === 0 || end > bytes.length) {
        throw new Error("malformed ECDSA signature: INTEGER runs past the end");
    }
    const value = bytes.subarray(cursor.offset, end);
    cursor.offset = end;
    return value;
}

/**
 * Left-pads a DER INTEGER's magnitude to exactly `size` bytes. DER integers
 * are signed and minimally encoded, so a coordinate arrives with a leading
 * `0x00` when its top bit is set, and shorter than `size` when its leading
 * bytes are zero.
 */
function toFixedWidth(value: Uint8Array, size: number, label: string): Uint8Array {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) {
        start++;
    }
    const magnitude = value.subarray(start);
    if (magnitude.length > size) {
        throw new Error(`malformed ECDSA signature: ${label} is ${magnitude.length} bytes, too long for a ${size * 8}-bit curve`);
    }
    const padded = new Uint8Array(size);
    padded.set(magnitude, size - magnitude.length);
    return padded;
}

/**
 * Convert a DER-encoded ECDSA signature, `SEQUENCE { INTEGER r, INTEGER s }`,
 * into the fixed-width `r || s` form that WebCrypto - and therefore
 * {@link CaSigner.sign} - is defined to return.
 *
 * Use it when adapting a signer that hands back DER, which is what Google
 * Cloud KMS, AWS KMS and most PKCS#11 tokens do:
 *
 * ```ts
 * async sign(tbs: Uint8Array): Promise<ArrayBuffer> {
 *     const { signature } = await kms.asymmetricSign({ name: keyName, digest: { sha256: await sha256(tbs) } });
 *     return ecdsaSignatureDerToP1363(signature, "P-256");
 * }
 * ```
 *
 * Passing an already-converted signature is not silently tolerated: `r || s`
 * is not valid DER, so it is rejected rather than corrupted further.
 *
 * @param derSignature the signature as `SEQUENCE { r, s }`
 * @param namedCurve   the curve the signing key lives on, which fixes the
 *                     width each coordinate is padded to
 */
export function ecdsaSignatureDerToP1363(derSignature: BufferSource, namedCurve: "P-256" | "P-384" | "P-521"): ArrayBuffer {
    const size = ECDSA_COORDINATE_BYTES[namedCurve];
    if (size === undefined) {
        throw new Error(`unsupported curve ${namedCurve}`);
    }
    const bytes = asBytes(derSignature);
    const cursor = { offset: 0 };
    if (bytes[cursor.offset++] !== 0x30) {
        throw new Error("malformed ECDSA signature: expected a SEQUENCE (is it already in r||s form?)");
    }
    const sequenceLength = readDerLength(bytes, cursor);
    if (cursor.offset + sequenceLength !== bytes.length) {
        throw new Error("malformed ECDSA signature: SEQUENCE length does not match the data");
    }

    const r = toFixedWidth(readDerInteger(bytes, cursor), size, "r");
    const s = toFixedWidth(readDerInteger(bytes, cursor), size, "s");
    if (cursor.offset !== bytes.length) {
        throw new Error("malformed ECDSA signature: trailing data after s");
    }

    const p1363 = new Uint8Array(size * 2);
    p1363.set(r, 0);
    p1363.set(s, size);
    return p1363.buffer;
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
export function isCaSigner(value: CryptoKey | CaSigner): value is CaSigner {
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

/**
 * What a `@peculiar/x509` generator needs when it must sign with a key AND
 * embed that same key's public half — a CSR, or a self-signed certificate.
 * {@link resolveCaSigningKey} is not enough there: it yields no public key.
 */
export interface ResolvedCaKeyPair {
    crypto: Crypto;
    keys: { privateKey: CryptoKey; publicKey: CryptoKey };
    signingAlgorithm: CaSignAlgorithm;
}

/**
 * Resolves a `CryptoKey | CaSigner` into the key pair and per-call `crypto`
 * a CSR or self-signed-certificate generator needs.
 *
 * For a raw `CryptoKey` the public half is derived from the private one.
 * For a {@link CaSigner} it comes from `getPublicKey()` — the only way to
 * obtain it when the private key lives in an HSM and cannot be exported.
 */
export async function resolveCaKeyPair(
    key: CryptoKey | CaSigner,
    baseCrypto: Pick<Crypto, "subtle" | "getRandomValues"> = getCrypto() as unknown as Crypto,
): Promise<ResolvedCaKeyPair> {
    if (isCaSigner(key)) {
        const adapted = await webCryptoFromSigner(key, baseCrypto);
        return {
            crypto: adapted.crypto,
            keys: { privateKey: adapted.privateKeyHandle, publicKey: adapted.publicKey },
            signingAlgorithm: key.algorithm,
        };
    }
    return {
        crypto: baseCrypto as Crypto,
        keys: { privateKey: key, publicKey: await buildPublicKey(key) },
        signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
    };
}
