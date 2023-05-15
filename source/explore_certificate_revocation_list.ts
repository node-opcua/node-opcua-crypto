// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2023 - Sterfive.com
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

import {
    _readStruct,
    readTag,
    _readBitString,
    AlgorithmIdentifier,
    _readAlgorithmIdentifier,
    _readSignatureValue,
    _readSignatureValueBin,
    BlockInfo,
    _readObjectIdentifier,
    DirectoryName,
    _readValue,
    _readTime,
    _readLongIntegerValue,
    formatBuffer2DigitHexWithColum,
    _getBlock,
    _readDirectoryName,
    _findBlockAtIndex,
    _readIntegerValue,
    TagType,
} from "./asn1";
import { CertificateRevocationList } from "./common";
import { makeSHA1Thumbprint, convertPEMtoDER } from "./crypto_utils";

export type Version = string;
export type Name = string;
export type CertificateSerialNumber = string;
export type Extensions = Record<string, unknown>;
export interface RevokedCertificate {
    userCertificate: CertificateSerialNumber;
    revocationDate: Date;
    crlEntryExtensions?: Extensions;
}
export interface TBSCertList {
    version?: Version; //OPTIONAL; // must be 2
    signature: AlgorithmIdentifier;
    issuer: Name;
    issuerFingerprint: string; // 00:AA:BB:etc ...
    thisUpdate: Date;
    nextUpdate?: Date; //             Time OPTIONAL,
    revokedCertificates: RevokedCertificate[];
    //    crlExtensions[0]  EXPLICIT Extensions OPTIONAL
}
export interface CertificateRevocationListInfo {
    tbsCertList: TBSCertList;
    signatureAlgorithm: AlgorithmIdentifier;
    signatureValue: Buffer;
}

export function readNameForCrl(buffer: Buffer, block: BlockInfo): DirectoryName {
    return _readDirectoryName(buffer, block);
}

function _readTbsCertList(buffer: Buffer, blockInfo: BlockInfo): TBSCertList {
    const blocks = _readStruct(buffer, blockInfo);

    const hasOptionalVersion = blocks[0].tag === TagType.INTEGER;

    if (hasOptionalVersion) {
        const version = _readIntegerValue(buffer, blocks[0]);
        const signature = _readAlgorithmIdentifier(buffer, blocks[1]);
        const issuer = readNameForCrl(buffer, blocks[2]);
        const issuerFingerprint = formatBuffer2DigitHexWithColum(makeSHA1Thumbprint(_getBlock(buffer, blocks[2])));

        const thisUpdate = _readTime(buffer, blocks[3]);
        const nextUpdate = _readTime(buffer, blocks[4]);

        const revokedCertificates: RevokedCertificate[] = [];

        if (blocks[5] && blocks[5].tag < 0x80) {
            const list = _readStruct(buffer, blocks[5]);
            for (const r of list) {
                // sometime blocks[5] doesn't exits .. in this case
                const rr = _readStruct(buffer, r);
                const userCertificate = formatBuffer2DigitHexWithColum(_readLongIntegerValue(buffer, rr[0]));
                const revocationDate = _readTime(buffer, rr[1]);
                revokedCertificates.push({
                    revocationDate,
                    userCertificate,
                });
            }
        }

        const ext0 = _findBlockAtIndex(blocks, 0);
        return { issuer, issuerFingerprint, thisUpdate, nextUpdate, signature, revokedCertificates } as TBSCertList;
    } else {
        const signature = _readAlgorithmIdentifier(buffer, blocks[0]);
        const issuer = readNameForCrl(buffer, blocks[1]);
        const issuerFingerprint = formatBuffer2DigitHexWithColum(makeSHA1Thumbprint(_getBlock(buffer, blocks[1])));

        const thisUpdate = _readTime(buffer, blocks[2]);
        const nextUpdate = _readTime(buffer, blocks[3]);

        const revokedCertificates: RevokedCertificate[] = [];

        if (blocks[4] && blocks[4].tag < 0x80) {
            const list = _readStruct(buffer, blocks[4]);
            for (const r of list) {
                // sometime blocks[5] doesn't exits .. in this case
                const rr = _readStruct(buffer, r);
                const userCertificate = formatBuffer2DigitHexWithColum(_readLongIntegerValue(buffer, rr[0]));
                const revocationDate = _readTime(buffer, rr[1]);
                revokedCertificates.push({
                    revocationDate,
                    userCertificate,
                });
            }
        }
        return { issuer, issuerFingerprint, thisUpdate, nextUpdate, signature, revokedCertificates } as TBSCertList;
    }
}
// see https://tools.ietf.org/html/rfc5280

export function exploreCertificateRevocationList(crl: CertificateRevocationList): CertificateRevocationListInfo {
    const blockInfo = readTag(crl, 0);
    const blocks = _readStruct(crl, blockInfo);
    const tbsCertList = _readTbsCertList(crl, blocks[0]);
    const signatureAlgorithm = _readAlgorithmIdentifier(crl, blocks[1]);
    const signatureValue = _readSignatureValueBin(crl, blocks[2]);
    return { tbsCertList, signatureAlgorithm, signatureValue };
}
