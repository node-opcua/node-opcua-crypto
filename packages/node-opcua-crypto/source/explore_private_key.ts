// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2024 - Sterfive.com
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

import { BlockInfo, readTag, TagType, _readIntegerAsByteString, _readStruct } from "./asn1.js";
import { PrivateKey } from "./common.js";
import { convertPEMtoDER } from "./crypto_utils.js";

// tslint:disable:no-empty-interface
export interface PrivateKeyInternals {
    /***/
    version: Buffer;
    modulus: Buffer;
    publicExponent: Buffer;
    privateExponent: Buffer;
    prime1: Buffer;
    prime2: Buffer;
    exponent1: Buffer;
    exponent2: Buffer;
}

function f(buffer: Buffer, b: BlockInfo) {
    return buffer.subarray(b.position + 1, b.position + b.length);
}
const doDebug = !!process.env.DEBUG;
/**
 * 
 * @param privateKey RSAPrivateKey ::= SEQUENCE {
 *  version           Version,
 *  modulus           INTEGER,  -- n
 *  publicExponent    INTEGER,  -- e
 *  privateExponent   INTEGER,  -- d
 *  prime1            INTEGER,  -- p
 *  prime2            INTEGER,  -- q
 *  exponent1         INTEGER,  -- d mod (p-1)
 *  exponent2         INTEGER,  -- d mod (q-1)
 *  coefficient       INTEGER,  -- (inverse of q) mod p
 *  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
 */
export function explorePrivateKey(privateKey2: PrivateKey): PrivateKeyInternals {
    const privateKey1 = privateKey2.hidden;
    const privateKey =
        typeof privateKey1 === "string" ? convertPEMtoDER(privateKey1) : privateKey1.export({ format: "der", type: "pkcs1" });

    const block_info = readTag(privateKey, 0);
    const blocks = _readStruct(privateKey, block_info);

    if (blocks.length === 9) {
        // alice_rsa
        const version = f(privateKey, blocks[0]); // _readIntegerAsByteString(privateKey, blocks1[0]);
        const modulus = f(privateKey, blocks[1]);
        const publicExponent = f(privateKey, blocks[2]);
        const privateExponent = f(privateKey, blocks[3]);
        const prime1 = f(privateKey, blocks[4]);
        const prime2 = f(privateKey, blocks[5]);
        const exponent1 = f(privateKey, blocks[6]);
        const exponent2 = f(privateKey, blocks[7]);

        return {
            version,
            modulus,
            publicExponent,
            privateExponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
        };
    }
    /* istanbul ignore next */
    if (doDebug) {
        // tslint:disable:no-console
        console.log("-------------------- private key:");
        console.log(block_info);

        // tslint:disable:no-console
        console.log(
            blocks.map((b) => ({
                tag: TagType[b.tag] + " 0x" + b.tag.toString(16),
                l: b.length,
                p: b.position,
                buff: privateKey.subarray(b.position, b.position + b.length).toString("hex"),
            }))
        );
    }

    const b = blocks[2];
    const bb = privateKey.subarray(b.position, b.position + b.length);
    const block_info1 = readTag(bb, 0);
    const blocks1 = _readStruct(bb, block_info1);

    /* istanbul ignore next */
    if (doDebug) {
        // tslint:disable:no-console
        console.log(
            blocks1.map((b) => ({
                tag: TagType[b.tag] + " 0x" + b.tag.toString(16),
                l: b.length,
                p: b.position,
                buff: bb.subarray(b.position, b.position + b.length).toString("hex"),
            }))
        );
    }

    const version = f(bb, blocks1[0]);
    const modulus = f(bb, blocks1[1]);
    const publicExponent = f(bb, blocks1[2]);
    const privateExponent = f(bb, blocks1[3]);
    const prime1 = f(bb, blocks1[4]);
    const prime2 = f(bb, blocks1[5]);
    const exponent1 = f(bb, blocks1[6]);
    const exponent2 = f(bb, blocks1[7]);

    return {
        version,
        modulus,
        publicExponent,
        privateExponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
    };
}
