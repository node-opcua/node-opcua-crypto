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

/**
 * The signature scheme an {@link IKeyOperations.sign} call operates under.
 *
 * These are the schemes the OPC UA security policies need — PKCS#1 v1.5 for
 * Basic128Rsa15 through Aes128_Sha256_RsaOaep, PSS for Aes256_Sha256_RsaPss —
 * expressed as parameters rather than OPC UA algorithm URIs so this layer
 * stays policy-agnostic. The mapping from a security policy to its parameters
 * belongs to the caller.
 *
 * For `"RSA-PSS"` the salt length is fixed to the digest length
 * (`RSA_PSS_SALTLEN_DIGEST`), which is what the OPC UA Aes256_Sha256_RsaPss
 * profile — and WebCrypto's `saltLength: 32` convention for SHA-256 —
 * expects. A remote signer whose backend salts differently (e.g. maximum
 * salt) produces signatures peers cannot verify.
 */
export interface AsymmetricSignParams {
    padding: "RSA-PKCS1-v1_5" | "RSA-PSS";
    hash: "SHA-1" | "SHA-256";
}

/**
 * The decryption scheme an {@link IKeyOperations.decryptBlock} call operates
 * under. `oaepHash` is required when `padding` is `"RSA-OAEP"` and names the
 * hash used for both the OAEP digest and MGF1.
 */
export interface AsymmetricDecryptParams {
    padding: "RSA-PKCS1-v1_5" | "RSA-OAEP";
    oaepHash?: "SHA-1" | "SHA-256";
}

/**
 * The facts about a key that callers need before performing any operation
 * with it — declared by the implementation, never inferred, because an
 * HSM/KMS-held key exposes no material to inspect (the same reason
 * {@link CaSignAlgorithm} travels with a {@link CaSigner}).
 *
 * Only RSA today. When EC security policies arrive, `keyType: "EC"` gains a
 * `namedCurve` here and an ECDSA variant in {@link AsymmetricSignParams} —
 * additive changes, not a second interface.
 */
export interface KeyMetadata {
    keyType: "RSA";
    /**
     * The RSA modulus size in **bytes** (256 for a 2048-bit key). For RSA
     * this single number is also the signature length under both paddings
     * and the cipher block size for {@link IKeyOperations.decryptBlock}.
     */
    modulusLength: number;
}

/**
 * Opaque private-key operations: an object that can use a private key —
 * sign, decrypt — without the key ever being obtainable through it.
 *
 * This is the secure-channel/session-side sibling of {@link CaSigner}
 * (which covers X509 issuance and is sign-only): shaped after cloud
 * KMS/HSM APIs, so the OPC UA application instance key can live in a TPM,
 * HSM, KMS or OS keystore, non-exportable, while node-opcua drives it
 * through this interface. Implementations wrap a local in-process key, a
 * PKCS#11 token, a cloud KMS client — the caller cannot tell the
 * difference, and this interface never asks for the key itself.
 *
 * The three required methods are asynchronous, because a remote key is.
 * The optional `*Sync` trio is the fast path a local-key implementation
 * provides so that code paths which are synchronous by contract (OPC UA
 * chunk assembly) keep working unchanged with local keys; remote
 * implementations simply omit them, and callers choose a path via
 * {@link hasSyncKeyOperations}.
 */
export interface IKeyOperations {
    /** Sign `data` and return the signature (`modulusLength` bytes for RSA). */
    sign(data: Uint8Array, params: AsymmetricSignParams): Promise<Buffer>;

    /**
     * Decrypt exactly ONE cipher block — `block.length` must equal
     * {@link KeyMetadata.modulusLength} — and return the plaintext.
     *
     * One call is one HSM/KMS operation by design: callers own the
     * multi-block loop (and may issue blocks concurrently), so a provider
     * never has to reimplement it and round trips stay visible.
     */
    decryptBlock(block: Uint8Array, params: AsymmetricDecryptParams): Promise<Buffer>;

    /** The declared key facts. Stable for the lifetime of the object. */
    getKeyMetadata(): Promise<KeyMetadata>;

    /**
     * The public half of the key, SPKI-encoded DER.
     *
     * Optional, but strongly recommended: certificate/key match checks and
     * CSR generation over an opaque key both need it, and are unavailable
     * (with a clear error) without it.
     */
    getPublicKey?(): Promise<ArrayBuffer>;

    /** Synchronous {@link sign}. Local keys only; remote providers omit it. */
    signSync?(data: Uint8Array, params: AsymmetricSignParams): Buffer;
    /** Synchronous {@link decryptBlock}. Local keys only. */
    decryptBlockSync?(block: Uint8Array, params: AsymmetricDecryptParams): Buffer;
    /** Synchronous {@link getKeyMetadata}. Local keys only. */
    getKeyMetadataSync?(): KeyMetadata;
}

/**
 * True when `value` implements {@link IKeyOperations} — the three required
 * methods are present — as opposed to being raw key material (a `PrivateKey`
 * envelope, a `CryptoKey`, a PEM string), none of which carry methods.
 */
export function isKeyOperations(value: unknown): value is IKeyOperations {
    if (value === null || typeof value !== "object") {
        return false;
    }
    const candidate = value as IKeyOperations;
    return (
        typeof candidate.sign === "function" &&
        typeof candidate.decryptBlock === "function" &&
        typeof candidate.getKeyMetadata === "function"
    );
}

/**
 * True when `ops` provides the complete synchronous fast path, so a caller
 * on a synchronous code path can use it without ever awaiting. All three
 * methods are required together — a partial sync surface would force
 * callers to mix paths mid-operation.
 */
export function hasSyncKeyOperations(ops: IKeyOperations): boolean {
    return (
        typeof ops.signSync === "function" &&
        typeof ops.decryptBlockSync === "function" &&
        typeof ops.getKeyMetadataSync === "function"
    );
}

/**
 * Thrown by `getPrivateKey()`-style accessors when the key is opaque —
 * held by an {@link IKeyOperations} implementation (HSM/KMS) and therefore
 * deliberately not obtainable as material. Catching this specific error is
 * how callers distinguish "the key exists but cannot be read" from "no key
 * is configured".
 */
export class PrivateKeyUnavailableError extends Error {
    constructor(message = "the private key is opaque: it is held by a key-operations provider and cannot be read") {
        super(message);
        this.name = "PrivateKeyUnavailableError";
    }
}
