import * as fs from "fs";
import * as assert from "assert";

import { promisify } from "util";
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
    formatBuffer2DigetHexWithColum,
    _getBlock,
    _readDirectoryName
} from "./asn1";
import { makeSHA1Thumbprint } from "./crypto_utils";
import { Certificate } from "crypto";

export type Version = string;
export type Name = string;
export type CertificateSerialNumber = string;
export interface Extensions {

}
export interface RevokedCertificate {
    userCertificate: CertificateSerialNumber;
    revocationDate: Date,
    crlEntryExtensions?: Extensions;
}
export interface TBSCertList {
    version?: Version //OPTIONAL; // must be 2
    signature: AlgorithmIdentifier;
    issuer: Name;
    issuerFingerprint: string; // 00:AA:BB:etc ...
    thisUpdate: Date;
    nextUpdate?: Date;//             Time OPTIONAL,
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
    const signature = _readAlgorithmIdentifier(buffer, blocks[1]);

    const issuer = readNameForCrl(buffer, blocks[2]);
    const issuerFingerprint = formatBuffer2DigetHexWithColum(makeSHA1Thumbprint(_getBlock(buffer, blocks[2])));

    const thisUpdate = _readTime(buffer, blocks[3]);
    const nextUpdate = _readTime(buffer, blocks[4]);

    const revokedCertificates: RevokedCertificate[] = [];
    const s1 = _readStruct(buffer, blocks[5]);
    for (const r of s1) {
        const rr = _readStruct(buffer, r);
        const userCertificate = formatBuffer2DigetHexWithColum(_readLongIntegerValue(buffer, rr[0]));
        const revocationDate = _readTime(buffer, rr[1]);
        revokedCertificates.push({
            revocationDate, userCertificate
        })
    }
    return { issuer, issuerFingerprint, thisUpdate, nextUpdate, signature, revokedCertificates } as TBSCertList;
}
// see https://tools.ietf.org/html/rfc5280

export type CertificateRevocationList = Buffer;
export async function readCertificateRevocationList(filename: string): Promise<CertificateRevocationList> {
    const crl = await promisify(fs.readFile)(filename);
    return crl as CertificateRevocationList;
}
export function exploreCertificateRevocationList(crl: CertificateRevocationList): CertificateRevocationListInfo {
    const blockInfo = readTag(crl, 0);
    const blocks = _readStruct(crl, blockInfo);
    const tbsCertList = _readTbsCertList(crl, blocks[0]);
    const signatureAlgorithm = _readAlgorithmIdentifier(crl, blocks[1])
    const signatureValue = _readSignatureValueBin(crl, blocks[2]);
    return { tbsCertList, signatureAlgorithm, signatureValue };
}