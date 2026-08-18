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
 * RFC 7292 Appendix B key-derivation function.
 *
 * This is *not* PBKDF2 — it's PKCS#12's own, older, password-based KDF,
 * still used today for the integrity `MacData` key regardless of which
 * cipher (legacy RC2/3DES or modern PBES2/AES) protects the bags
 * themselves. Modern OpenSSL (3.x) parameterizes it with SHA-256 instead
 * of the originally-specified SHA-1; both are supported here.
 *
 * `id` selects the derived material's purpose per the RFC: 1 = encryption
 * key, 2 = IV, 3 = MAC key. This module only ever needs `id = 3` (the
 * bags' own encryption uses PBES2/PBKDF2 or Node's native PKCS#8 decrypt).
 *
 * Implemented with the synchronous `node:crypto.createHash` rather than
 * `subtle.digest`: the KDF hashes `iterations` (2048 by default) times in a
 * strict chain, and one awaited WebCrypto round-trip per iteration costs
 * ~50-80 ms of pure scheduling per PFX read/write — more than the actual
 * cryptography. This module lives in `source_nodejs/` and is Node-only, so
 * the synchronous hash is both available and appropriate.
 */

import { createHash } from "node:crypto";

const BLOCK_BYTES = 64; // v: both SHA-1 and SHA-256 have a 64-byte block size

export type Pkcs12KdfHash = "SHA-1" | "SHA-256";

/** Digest length in bytes for a supported PKCS#12 KDF/MAC hash. */
export function hashOutputBytes(hash: Pkcs12KdfHash): number {
    return hash === "SHA-256" ? 32 : 20;
}

function nodeHashName(hash: Pkcs12KdfHash): "sha1" | "sha256" {
    return hash === "SHA-256" ? "sha256" : "sha1";
}

/** Repeat `buf` to fill a whole multiple of BLOCK_BYTES; empty input stays empty. */
function fillToBlockMultiple(buf: Uint8Array): Uint8Array {
    if (buf.length === 0) {
        return new Uint8Array(0);
    }
    const len = BLOCK_BYTES * Math.ceil(buf.length / BLOCK_BYTES);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        out[i] = buf[i % buf.length];
    }
    return out;
}

/**
 * Reject a string that is not well-formed UTF-16 (contains a lone
 * surrogate). Such a value has no single canonical byte encoding: the
 * BMPString (UTF-16BE) form used by the PKCS#12 MAC KDF would carry the
 * lone surrogate verbatim, while the UTF-8 form used by PBKDF2 (see
 * pkcs12_pbes2.ts) replaces it with U+FFFD — so the MAC key and the bag
 * key would silently derive from *different* password bytes, and a bundle
 * `createPfx` produced could never be verified again, by us or by anyone.
 * Failing loudly up front is the only correct behavior.
 */
export function assertWellFormedUtf16(value: string, what: string): void {
    // `String.prototype.isWellFormed` exists on Node >= 20; do it by hand so
    // the check also holds on the Node 18 floor this package declares.
    for (let i = 0; i < value.length; i++) {
        const c = value.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
            const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
            if (next >= 0xdc00 && next <= 0xdfff) {
                i++; // valid surrogate pair
                continue;
            }
            throw new TypeError(`${what} contains a lone high surrogate at index ${i}; it is not well-formed UTF-16`);
        }
        if (c >= 0xdc00 && c <= 0xdfff) {
            throw new TypeError(`${what} contains a lone low surrogate at index ${i}; it is not well-formed UTF-16`);
        }
    }
}

/**
 * Encode a string as PKCS#12's `BMPString`: UTF-16BE, and — for a
 * *password* — always null-terminated, including the empty-password case
 * whose encoded form is the 2-byte terminator alone, *not* a zero-length
 * string. (An earlier draft got that case wrong; verified against real
 * OpenSSL-generated PFX files with an empty password.)
 *
 * The single shared UTF-16BE encoder for the whole PKCS#12 module: the KDF
 * uses it with `nullTerminate: true`, the friendlyName attribute with
 * `nullTerminate: false`. Callers are expected to have run
 * {@link assertWellFormedUtf16} first; a surrogate pair is emitted as its two
 * code units, exactly as OpenSSL's `OPENSSL_utf82uni` does.
 */
export function encodeBmpString(value: string, nullTerminate: boolean): Uint8Array {
    const out = new Uint8Array(value.length * 2 + (nullTerminate ? 2 : 0));
    const view = new DataView(out.buffer);
    for (let i = 0; i < value.length; i++) {
        view.setUint16(i * 2, value.charCodeAt(i), false);
    }
    // trailing 2 bytes (when present) stay zero: the null terminator
    return out;
}

/**
 * Derive `outputBytes` bytes of key material for purpose `id` per RFC 7292
 * Appendix B. `outputBytes` defaults to the hash length, which is what the
 * MAC key (id = 3) always needs.
 */
export function pkcs12Kdf(
    hash: Pkcs12KdfHash,
    password: string,
    salt: Uint8Array,
    iterations: number,
    id: 1 | 2 | 3,
    outputBytes: number = hashOutputBytes(hash),
): Uint8Array {
    const u = hashOutputBytes(hash);
    const algorithm = nodeHashName(hash);

    const D = new Uint8Array(BLOCK_BYTES).fill(id);
    const S = fillToBlockMultiple(salt);
    const P = fillToBlockMultiple(encodeBmpString(password, true));
    const I = new Uint8Array(S.length + P.length);
    I.set(S, 0);
    I.set(P, S.length);

    const c = Math.ceil(outputBytes / u);
    const result = new Uint8Array(c * u);

    for (let i = 0; i < c; i++) {
        let A: Uint8Array = new Uint8Array(D.length + I.length);
        A.set(D, 0);
        A.set(I, D.length);
        for (let r = 0; r < iterations; r++) {
            A = new Uint8Array(createHash(algorithm).update(A).digest());
        }
        result.set(A, i * u);

        if (i < c - 1) {
            const B = new Uint8Array(BLOCK_BYTES);
            for (let k = 0; k < BLOCK_BYTES; k++) {
                B[k] = A[k % A.length];
            }
            // For each v-byte block I_j of I: I_j = (I_j + B + 1) mod 2^v (big-endian integer addition)
            const numBlocks = I.length / BLOCK_BYTES;
            for (let j = 0; j < numBlocks; j++) {
                const block = I.subarray(j * BLOCK_BYTES, (j + 1) * BLOCK_BYTES);
                let carry = 1;
                for (let k = BLOCK_BYTES - 1; k >= 0; k--) {
                    const sum = block[k] + B[k] + carry;
                    block[k] = sum & 0xff;
                    carry = sum >> 8;
                }
            }
        }
    }

    return result.subarray(0, outputBytes);
}
