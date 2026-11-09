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

import type { DER } from "../source/common.js";
import { convertPEMtoDER } from "../source/crypto_utils.js";

const SEQUENCE_TAG = 0x30;

function isWhitespace(byte: number): boolean {
    return byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d;
}

/**
 * Size of the DER SEQUENCE that `buf` starts with (tag, length and content),
 * or `undefined` when `buf` does not start with a SEQUENCE whose encoded
 * length, in short or long form, covers the whole buffer (trailing
 * whitespace allowed).
 */
function derSequenceSize(buf: Buffer): number | undefined {
    if (buf.length < 2 || buf[0] !== SEQUENCE_TAG) {
        return undefined;
    }
    let headerSize = 2;
    let contentLength = buf[1];
    if (contentLength & 0x80) {
        const lengthBytes = contentLength & 0x7f;
        // 0x80 is the indefinite form, which DER forbids; more than 4
        // length bytes would describe a file of several gigabytes.
        if (lengthBytes === 0 || lengthBytes > 4 || buf.length < 2 + lengthBytes) {
            return undefined;
        }
        contentLength = 0;
        for (let i = 0; i < lengthBytes; i++) {
            contentLength = contentLength * 256 + buf[2 + i];
        }
        headerSize += lengthBytes;
    }
    const size = headerSize + contentLength;
    if (size > buf.length) {
        return undefined;
    }
    for (let i = size; i < buf.length; i++) {
        if (!isWhitespace(buf[i])) {
            return undefined;
        }
    }
    return size;
}

/**
 * Decode the content of a file holding one DER object or PEM block(s).
 *
 * The decision is made on the content, not on one length form: checking
 * for `30 82` alone misses DER whose length is short form (`30 81` /
 * `30 7x`, e.g. a CRL of an EC CA with few entries) or takes three bytes
 * (`30 83`, over 64 KiB).
 */
export function derOrPemToDer(buf: Buffer): DER {
    if (!buf.includes("-----BEGIN")) {
        const size = derSequenceSize(buf);
        if (size !== undefined) {
            return size === buf.length ? buf : buf.subarray(0, size);
        }
    }
    return convertPEMtoDER(buf.toString());
}
