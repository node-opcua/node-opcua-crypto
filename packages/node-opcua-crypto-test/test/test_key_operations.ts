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

import nodeCrypto from "node:crypto";
import {
    type AsymmetricDecryptParams,
    type AsymmetricSignParams,
    hasSyncKeyOperations,
    type IKeyOperations,
    isKeyOperations,
    type KeyMetadata,
    PrivateKeyUnavailableError,
} from "node-opcua-crypto";
import { isKeyOperations as isKeyOperationsWeb } from "node-opcua-crypto/web";
import { describe, expect, it } from "vitest";

const metadata: KeyMetadata = { keyType: "RSA", modulusLength: 256 };

/** A remote-style implementation: required methods only, no sync fast path. */
function makeAsyncOnlyOps(): IKeyOperations {
    return {
        async sign(_data: Uint8Array, _params: AsymmetricSignParams) {
            return Buffer.alloc(metadata.modulusLength);
        },
        async decryptBlock(block: Uint8Array, _params: AsymmetricDecryptParams) {
            return Buffer.from(block);
        },
        async getKeyMetadata() {
            return metadata;
        },
    };
}

/** A local-style implementation: full surface, sync fast path included. */
function makeFullOps(): IKeyOperations {
    const ops = makeAsyncOnlyOps();
    return {
        ...ops,
        async getPublicKey() {
            return new ArrayBuffer(0);
        },
        signSync: (_data, _params) => Buffer.alloc(metadata.modulusLength),
        decryptBlockSync: (block, _params) => Buffer.from(block),
        getKeyMetadataSync: () => metadata,
    };
}

describe("isKeyOperations", () => {
    it("accepts an async-only implementation", () => {
        expect(isKeyOperations(makeAsyncOnlyOps())).toBe(true);
    });

    it("accepts a full implementation", () => {
        expect(isKeyOperations(makeFullOps())).toBe(true);
    });

    it("rejects raw key material of every shape the union types carry", () => {
        // the PrivateKey envelope
        expect(isKeyOperations({ hidden: "-----BEGIN PRIVATE KEY-----" })).toBe(false);
        // a real KeyObject inside the envelope
        const { privateKey } = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
        expect(isKeyOperations({ hidden: privateKey })).toBe(false);
        expect(isKeyOperations(privateKey)).toBe(false);
        // a PEM string, null, undefined
        expect(isKeyOperations("-----BEGIN PRIVATE KEY-----")).toBe(false);
        expect(isKeyOperations(null)).toBe(false);
        expect(isKeyOperations(undefined)).toBe(false);
    });

    it("rejects a partial implementation missing a required method", () => {
        const { getKeyMetadata: _dropped, ...missingMetadata } = makeAsyncOnlyOps();
        expect(isKeyOperations(missingMetadata)).toBe(false);
        const { decryptBlock: _dropped2, ...missingDecrypt } = makeAsyncOnlyOps();
        expect(isKeyOperations(missingDecrypt)).toBe(false);
    });

    it("does not mistake a CaSigner-shaped object for key operations", () => {
        const caSignerLike = {
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
            getPublicKey: async () => new ArrayBuffer(0),
            sign: async () => new ArrayBuffer(0),
        };
        expect(isKeyOperations(caSignerLike)).toBe(false);
    });
});

describe("hasSyncKeyOperations", () => {
    it("is false for an async-only implementation", () => {
        expect(hasSyncKeyOperations(makeAsyncOnlyOps())).toBe(false);
    });

    it("is true only when the whole sync trio is present", () => {
        expect(hasSyncKeyOperations(makeFullOps())).toBe(true);
        const { decryptBlockSync: _dropped, ...partial } = makeFullOps();
        expect(hasSyncKeyOperations(partial as IKeyOperations)).toBe(false);
    });
});

describe("PrivateKeyUnavailableError", () => {
    it("is an Error with a stable name and a default message naming the cause", () => {
        const error = new PrivateKeyUnavailableError();
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe("PrivateKeyUnavailableError");
        expect(error.message).toMatch(/opaque/);
    });

    it("accepts a custom message", () => {
        expect(new PrivateKeyUnavailableError("held in the HSM").message).toBe("held in the HSM");
    });
});

it("is exported from the web entry point too", () => {
    expect(isKeyOperationsWeb(makeAsyncOnlyOps())).toBe(true);
    expect(isKeyOperationsWeb(null)).toBe(false);
});
