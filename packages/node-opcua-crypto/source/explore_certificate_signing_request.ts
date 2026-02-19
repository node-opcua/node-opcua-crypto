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

import { type BlockInfo, findBlockAtIndex, getBlock, readObjectIdentifier, readStruct, readTag } from "./asn1.js";

import { type BasicConstraints, readExtension, type X509KeyUsage } from "./crypto_explore_certificate.js";


export interface SubjectAltName {
    uniformResourceIdentifier: string[];
    dNSName: string[];
    iPAddress: string[];
    [key: string]: unknown;
}
export interface ExtensionRequest {
    basicConstraints: BasicConstraints;
    keyUsage: X509KeyUsage;
    subjectAltName: SubjectAltName;
}
export interface CertificateSigningRequestInfo {
    extensionRequest: ExtensionRequest;
}

function _readExtensionRequest(buffer: Buffer): ExtensionRequest {
    const block = readTag(buffer, 0);

    const inner_blocks = readStruct(buffer, block);
    const extensions = inner_blocks.map((block1) => readExtension(buffer, block1));

    const result: ExtensionRequest = {} as ExtensionRequest;
    for (const e of extensions) {
        switch (e.identifier.name) {
            case "basicConstraints":
                result.basicConstraints = e.value as BasicConstraints;
                break;
            case "keyUsage":
                result.keyUsage = e.value as X509KeyUsage;
                break;
            case "subjectAltName":
                result.subjectAltName = e.value as SubjectAltName;
                break;
            default:
                // ignore unknown extensions
                break;
        }
    }
    return result;
}

export function readCertificationRequestInfo(buffer: Buffer, block: BlockInfo): CertificateSigningRequestInfo {
    const blocks = readStruct(buffer, block);
    if (blocks.length === 4) {
        const extensionRequestBlock = findBlockAtIndex(blocks, 0);
        if (!extensionRequestBlock) {
            throw new Error("cannot find extensionRequest block");
        }
        const blocks1 = readStruct(buffer, extensionRequestBlock);
        const blocks2 = readStruct(buffer, blocks1[0]);
        const identifier = readObjectIdentifier(buffer, blocks2[0]);
        if (identifier.name !== "extensionRequest") {
            throw new Error(" Cannot find extension Request in ASN1 block");
        }
        const buf = getBlock(buffer, blocks2[1]);

        const extensionRequest = _readExtensionRequest(buf);

        return { extensionRequest };
    }
    throw new Error("Invalid CSR or ");
}

// see https://tools.ietf.org/html/rfc2986 : Certification Request Syntax Specification Version 1.7

export function exploreCertificateSigningRequest(crl: Buffer): CertificateSigningRequestInfo {
    const blockInfo = readTag(crl, 0);
    const blocks = readStruct(crl, blockInfo);
    const csrInfo = readCertificationRequestInfo(crl, blocks[0]);
    return csrInfo;
}
