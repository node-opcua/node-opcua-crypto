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

import {
    type AlgorithmIdentifier,
    type BlockInfo,
    formatBuffer2DigitHexWithColum,
    getBlock,
    readAlgorithmIdentifier,
    readIntegerValue,
    readLongIntegerValue,
    readObjectIdentifier,
    readSignatureValueBin,
    readStruct,
    readTag,
    readTime,
    TagType,
} from "./asn1.js";
import type { CertificateRevocationList } from "./common.js";
import { makeSHA1Thumbprint } from "./crypto_utils.js";
import { type DirectoryName, readDirectoryName } from "./directory_name.js";

export type Version = string;
/**
 * A Name is an RDNSequence, not a string.
 *
 * This was declared `string` while `readNameForCrl` has always returned a
 * {@link DirectoryName} object — the `as TBSCertList` casts below hid the
 * mismatch, so `tbsCertList.issuer` type-checked as a string while being an
 * object at runtime. Correcting the declaration is a breaking *type* change and
 * no behaviour change at all: callers reading `issuer` as a string were already
 * getting an object.
 */
export type Name = DirectoryName;
export type CertificateSerialNumber = string;
export type Extensions = Record<string, unknown>;

/**
 * CRLReason, RFC 5280 §5.3.1 (value 7 is unused).
 */
export type CRLReason =
    | "unspecified"
    | "keyCompromise"
    | "cACompromise"
    | "affiliationChanged"
    | "superseded"
    | "cessationOfOperation"
    | "certificateHold"
    | "removeFromCRL"
    | "privilegeWithdrawn"
    | "aACompromise";

const crlReasonNames: Record<number, CRLReason> = {
    0: "unspecified",
    1: "keyCompromise",
    2: "cACompromise",
    3: "affiliationChanged",
    4: "superseded",
    5: "cessationOfOperation",
    6: "certificateHold",
    8: "removeFromCRL",
    9: "privilegeWithdrawn",
    10: "aACompromise",
};

/**
 * Decoded crlEntryExtensions (RFC 5280 §5.3).
 * Known extensions get a named field; any other extension is kept under its
 * dotted OID as the raw extnValue bytes.
 */
export interface CrlEntryExtensions extends Extensions {
    /** reasonCode (2.5.29.21); a value outside RFC 5280 is reported as `unknown(<n>)` */
    reasonCode?: CRLReason | `unknown(${number})`;
    /** invalidityDate (2.5.29.24) */
    invalidityDate?: Date;
}

export interface RevokedCertificate {
    userCertificate: CertificateSerialNumber;
    revocationDate: Date;
    /** present only when the entry carries extensions */
    crlEntryExtensions?: CrlEntryExtensions;
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
    return readDirectoryName(buffer, block);
}

/*
 Extension  ::=  SEQUENCE  {
     extnID      OBJECT IDENTIFIER,
     critical    BOOLEAN DEFAULT FALSE,
     extnValue   OCTET STRING }
 */
function _readCrlEntryExtensions(buffer: Buffer, block: BlockInfo): CrlEntryExtensions {
    const result: CrlEntryExtensions = {};
    for (const extensionBlock of readStruct(buffer, block)) {
        const inner = readStruct(buffer, extensionBlock);
        const { oid } = readObjectIdentifier(buffer, inner[0]);
        const extnValue = inner[inner.length - 1];
        // extnValue is an OCTET STRING wrapping the DER of the actual value
        const value = readTag(buffer, extnValue.position);
        switch (oid) {
            case "2.5.29.21": {
                // CRLReason ::= ENUMERATED
                const code = readIntegerValue(buffer, { ...value, tag: TagType.INTEGER });
                result.reasonCode = crlReasonNames[code] ?? `unknown(${code})`;
                break;
            }
            case "2.5.29.24":
                // InvalidityDate ::= GeneralizedTime
                result.invalidityDate = readTime(buffer, value) as Date;
                break;
            default:
                result[oid] = getBlock(buffer, extnValue);
        }
    }
    return result;
}

/*
 revokedCertificates     SEQUENCE OF SEQUENCE  {
     userCertificate         CertificateSerialNumber,
     revocationDate          Time,
     crlEntryExtensions      Extensions OPTIONAL }
 */
function _readRevokedCertificates(buffer: Buffer, block: BlockInfo): RevokedCertificate[] {
    return readStruct(buffer, block).map((r) => {
        const rr = readStruct(buffer, r);
        const revokedCertificate: RevokedCertificate = {
            revocationDate: readTime(buffer, rr[1]) as Date,
            userCertificate: formatBuffer2DigitHexWithColum(readLongIntegerValue(buffer, rr[0])),
        };
        if (rr[2]) {
            revokedCertificate.crlEntryExtensions = _readCrlEntryExtensions(buffer, rr[2]);
        }
        return revokedCertificate;
    });
}

/*
 TBSCertList  ::=  SEQUENCE  {
     version                 Version OPTIONAL, -- if present, MUST be v2
     signature               AlgorithmIdentifier,
     issuer                  Name,
     thisUpdate              Time,
     nextUpdate              Time OPTIONAL,
     revokedCertificates     SEQUENCE OF SEQUENCE { ... } OPTIONAL,
     crlExtensions           [0] EXPLICIT Extensions OPTIONAL }
 */
function _isTime(block: BlockInfo | undefined): boolean {
    return block?.tag === TagType.UTCTime || block?.tag === TagType.GeneralizedTime;
}

function _readTbsCertList(buffer: Buffer, blockInfo: BlockInfo): TBSCertList {
    const blocks = readStruct(buffer, blockInfo);

    // optional fields are recognised by their tag, not by a fixed index
    let index = 0;
    if (blocks[index].tag === TagType.INTEGER) {
        index++; // version
    }
    const signature = readAlgorithmIdentifier(buffer, blocks[index++]);
    const issuerBlock = blocks[index++];
    const issuer = readNameForCrl(buffer, issuerBlock);
    const issuerFingerprint = formatBuffer2DigitHexWithColum(makeSHA1Thumbprint(getBlock(buffer, issuerBlock)));

    const thisUpdate = readTime(buffer, blocks[index++]) as Date;
    const nextUpdate = _isTime(blocks[index]) ? (readTime(buffer, blocks[index++]) as Date) : undefined;

    const revokedCertificates: RevokedCertificate[] = [];
    if (blocks[index]?.tag === TagType.SEQUENCE) {
        revokedCertificates.push(..._readRevokedCertificates(buffer, blocks[index++]));
    }
    // the remaining block, if any, is crlExtensions ([0], tag 0xa0): not decoded here
    return { issuer, issuerFingerprint, thisUpdate, nextUpdate, signature, revokedCertificates };
}
// see https://tools.ietf.org/html/rfc5280

export function exploreCertificateRevocationList(crl: CertificateRevocationList): CertificateRevocationListInfo {
    const blockInfo = readTag(crl, 0);
    const blocks = readStruct(crl, blockInfo);
    const tbsCertList = _readTbsCertList(crl, blocks[0]);
    const signatureAlgorithm = readAlgorithmIdentifier(crl, blocks[1]);
    const signatureValue = readSignatureValueBin(crl, blocks[2]);
    return { tbsCertList, signatureAlgorithm, signatureValue };
}
