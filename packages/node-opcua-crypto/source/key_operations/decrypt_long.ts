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
import type { AsymmetricDecryptParams, IKeyOperations } from "./key_operations.js";

function splitBlocks(buffer: Uint8Array, blockSize: number): Uint8Array[] {
    if (!Number.isInteger(blockSize) || blockSize <= 0) {
        throw new Error(`invalid cipher block size ${blockSize}`);
    }
    if (buffer.length === 0 || buffer.length % blockSize !== 0) {
        throw new Error(`encrypted buffer length ${buffer.length} is not a whole number of ${blockSize}-byte cipher blocks`);
    }
    const blocks: Uint8Array[] = [];
    for (let offset = 0; offset < buffer.length; offset += blockSize) {
        blocks.push(buffer.subarray(offset, offset + blockSize));
    }
    return blocks;
}

/**
 * Decrypt a multi-block ciphertext through an {@link IKeyOperations}.
 *
 * This is THE multi-block loop, shipped once so providers never reimplement
 * it and only ever see one block per call — one call, one HSM/KMS operation.
 * Blocks are decrypted concurrently (a remote provider's round trips
 * overlap) and reassembled in order. `blockSize` is the cipher block size,
 * i.e. {@link KeyMetadata.modulusLength}; the buffer must be a whole number
 * of blocks — a partial trailing block is a framing error upstream and is
 * rejected rather than papered over.
 *
 * A block that fails to decrypt rejects the whole call; the caller decides
 * whether that surfaces or degrades (see {@link LocalKeyOperations} on
 * anti-oracle behavior).
 */
export async function decryptLong(
    ops: IKeyOperations,
    buffer: Uint8Array,
    params: AsymmetricDecryptParams,
    blockSize: number,
): Promise<Buffer> {
    const blocks = splitBlocks(buffer, blockSize);
    const decrypted = await Promise.all(blocks.map((block) => ops.decryptBlock(block, params)));
    return Buffer.concat(decrypted);
}

/**
 * Synchronous {@link decryptLong}, for callers that are synchronous by
 * contract. Requires the sync fast path — check {@link hasSyncKeyOperations}
 * first; an async-only provider is rejected with a clear error.
 */
export function decryptLongSync(
    ops: IKeyOperations,
    buffer: Uint8Array,
    params: AsymmetricDecryptParams,
    blockSize: number,
): Buffer {
    const decryptBlockSync = ops.decryptBlockSync;
    if (typeof decryptBlockSync !== "function") {
        throw new Error("decryptLongSync requires a key-operations provider with a synchronous fast path (decryptBlockSync)");
    }
    const blocks = splitBlocks(buffer, blockSize);
    return Buffer.concat(blocks.map((block) => decryptBlockSync.call(ops, block, params)));
}
