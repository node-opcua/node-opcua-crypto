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
import type { CaSigner } from "../x509/ca_signer.js";
import type { IKeyOperations } from "./key_operations.js";

/**
 * Expose an {@link IKeyOperations} as a {@link CaSigner}, so ONE HSM/KMS
 * integration serves both worlds: the secure-channel/session operations
 * (native shape) and X509 issuance — CSR, self-signed certificate, CRL —
 * through the existing `CaSigner`-accepting primitives. The concrete use
 * case is an OPC UA application whose instance key is opaque and that must
 * still renew its certificate: a CSR over the existing key, signed through
 * this adapter.
 *
 * RSASSA-PKCS1-v1_5 only — the signature scheme X509 issuance uses here —
 * and SHA-256 only, {@link AsymmetricSignParams} not going higher today;
 * the `hash` parameter exists so a future widening is additive.
 *
 * Requires {@link IKeyOperations.getPublicKey}: a `CaSigner` must produce
 * its public half (a CSR embeds it, an issued certificate's AKI derives
 * from it), and with an opaque key there is nowhere else it can come from.
 */
export function caSignerFromKeyOperations(ops: IKeyOperations, hash: "SHA-256" = "SHA-256"): CaSigner {
    const getPublicKey = ops.getPublicKey;
    if (typeof getPublicKey !== "function") {
        throw new Error(
            "caSignerFromKeyOperations requires a key-operations provider that implements getPublicKey():" +
                " a CaSigner must be able to produce its public key (SPKI DER), and an opaque key has no other source for it",
        );
    }
    return {
        algorithm: { name: "RSASSA-PKCS1-v1_5", hash: { name: hash } },
        getPublicKey: () => getPublicKey.call(ops),
        async sign(tbs: Uint8Array): Promise<ArrayBuffer> {
            const signature = await ops.sign(tbs, { padding: "RSA-PKCS1-v1_5", hash });
            // copied so the result is a plain ArrayBuffer, not a view into Buffer pool memory
            const copy = new Uint8Array(signature.byteLength);
            copy.set(signature);
            return copy.buffer;
        },
    };
}
