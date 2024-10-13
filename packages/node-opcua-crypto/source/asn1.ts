import assert from "assert";
import { oid_map } from "./oid_map.js";
import { DirectoryName } from "./directory_name.js";
// https://github.com/lapo-luchini/asn1js/blob/master/asn1.js
export enum TagType {
    BOOLEAN = 0x01,
    INTEGER = 0x02,
    BIT_STRING = 0x03,
    OCTET_STRING = 0x04,
    NULL = 0x05,
    OBJECT_IDENTIFIER = 0x06,
    UTF8String = 0x0c,
    NumericString = 0x12,
    PrintableString = 0x13,
    TeletexString = 0x14,
    IA5String = 0x16,
    UTCTime = 0x17,
    GeneralizedTime = 0x18,
    GraphicString = 0x19,
    VisibleString = 0x1a,
    GeneralString = 0x1b,
    UniversalString = 0x1c,
    BMPString = 0x1e,

    SEQUENCE = 0x30,

    SET = 0x31,

    CONTEXT_SPECIFIC0 = 0xa0,
    CONTEXT_SPECIFIC1 = 0xa1,
    CONTEXT_SPECIFIC2 = 0xa2,
    CONTEXT_SPECIFIC3 = 0xa3,
    A4 = 0xa4
}

export interface BlockInfo {
    tag: TagType | number;
    position: number;
    length: number;
    start: number;
}

export function readTag(buf: Buffer, pos: number): BlockInfo {


    const start = pos;
    // istanbul ignore next
    if (buf.length <= pos) {
        throw new Error("Invalid position : buf.length=" + buf.length + " pos =" + pos);
    }
    const tag = buf.readUInt8(pos);
    pos += 1;

    let length = buf.readUInt8(pos);
    pos += 1;

    // tslint:disable:no-bitwise
    if (length > 127) {
        const nbBytes = length & 0x7f;
        length = 0;
        for (let i = 0; i < nbBytes; i++) {
            length = length * 256 + buf.readUInt8(pos);
            pos += 1;
        }
    }
    return { start, tag, position: pos, length };
}

export function readStruct(buf: Buffer, blockInfo: BlockInfo): BlockInfo[] {
    const length = blockInfo.length;
    let cursor = blockInfo.position;
    const end = blockInfo.position + length;
    const blocks: BlockInfo[] = [];
    while (cursor < end) {
        const inner = readTag(buf, cursor);
        cursor = inner.position + inner.length;
        blocks.push(inner);
    }
    return blocks;
}

export function parseBitString(buffer: Buffer, start: number, end: number, maxLength: number): string {
    const unusedBit = buffer.readUInt8(start),
        lenBit = ((end - start - 1) << 3) - unusedBit,
        intro = "(" + lenBit + " bit)\n";

    let s = "",
        skip = unusedBit;

    for (let i = end - 1; i > start; --i) {
        const b = buffer.readUInt8(i);

        for (let j = skip; j < 8; ++j) {
            // noinspection JSBitwiseOperatorUsage
            s += (b >> j) & 1 ? "1" : "0";
        }
        skip = 0;
        assert(s.length <= maxLength);
    }
    return intro + s;
}

export interface BitString {
    lengthInBits: number;
    lengthInBytes: number;
    data: Buffer;
    debug?: any;
}

export function readBitString(buffer: Buffer, block: BlockInfo): BitString {
    assert(block.tag === TagType.BIT_STRING);
    const data = getBlock(buffer, block);
    // number of skipped bits
    const ignore_bits = data.readUInt8(0);

    return {
        lengthInBits: data.length * 8 - ignore_bits,
        lengthInBytes: data.length - 1,
        data: data.subarray(1),
        debug: parseBitString(buffer, block.position, block.length + block.position, 4 * 16 * 1024),
    };
}

export function formatBuffer2DigitHexWithColum(buffer: Buffer): string {
    const value: string[] = [];
    for (let i = 0; i < buffer.length; i++) {
        value.push(("00" + buffer.readUInt8(i).toString(16)).substr(-2, 2));
    }
    // remove leading 00
    return value
        .join(":")
        .toUpperCase()
        .replace(/^(00:)*/, "");
}

export function readOctetString(buffer: Buffer, block: BlockInfo): Buffer {
    assert(block.tag === TagType.OCTET_STRING);
    const tag = readTag(buffer, block.position);
    assert(tag.tag === TagType.OCTET_STRING);

    const nbBytes = tag.length;
    const pos = tag.position;
    const b = buffer.subarray(pos, pos + nbBytes);
    return b;
}

export function getBlock(buffer: Buffer, block: BlockInfo): Buffer {
    const start = block.position;
    const end = block.position + block.length;
    return buffer.subarray(start, end);
}

export interface AlgorithmIdentifier {
    identifier: string;
}

export function readIntegerAsByteString(buffer: Buffer, block: BlockInfo): Buffer {
    return getBlock(buffer, block);
}

export function readListOfInteger(buffer: Buffer): Buffer[] {
    const block = readTag(buffer, 0);
    const inner_blocks = readStruct(buffer, block);
    return inner_blocks.map((innerBlock: BlockInfo) => {
        return readIntegerAsByteString(buffer, innerBlock);
    });
}

function parseOID(buffer: Buffer, start: number, end: number): string {
    // ASN.1 JavaScript decoder
    // Copyright (c) 2008-2014 Lapo Luchini <lapo@lapo.it>
    let s = "",
        n = 0,
        bits = 0;
    for (let i = start; i < end; ++i) {
        const v = buffer.readUInt8(i);

        // tslint:disable-next-line: no-bitwise
        n = n * 128 + (v & 0x7f);
        bits += 7;

        // noinspection JSBitwiseOperatorUsage
        // tslint:disable-next-line: no-bitwise
        if (!(v & 0x80)) {
            // finished
            if (s === "") {
                const m = n < 80 ? (n < 40 ? 0 : 1) : 2;
                s = m + "." + (n - m * 40);
            } else {
                s += "." + n.toString();
            }
            n = 0;
            bits = 0;
        }
    }
    assert(bits === 0); // if (bits > 0) { s += ".incomplete"; }
    return s;
}

export function readObjectIdentifier(buffer: Buffer, block: BlockInfo): { oid: string; name: string } {
    assert(block.tag === TagType.OBJECT_IDENTIFIER);
    const b = buffer.subarray(block.position, block.position + block.length);
    const oid = parseOID(b, 0, block.length);
    return {
        oid,
        name: oid_map[oid] ? oid_map[oid].d : oid,
    };
}

export function readAlgorithmIdentifier(buffer: Buffer, block: BlockInfo): AlgorithmIdentifier {
    const inner_blocks = readStruct(buffer, block);
    return {
        identifier: readObjectIdentifier(buffer, inner_blocks[0]).name,
    };
}

export function readECCAlgorithmIdentifier(buffer: Buffer, block: BlockInfo): AlgorithmIdentifier {
    const inner_blocks = readStruct(buffer, block);
    return {
        identifier: readObjectIdentifier(buffer, inner_blocks[1]).name, // difference with RSA as algorithm is second element of nested block
    };
}

export type SignatureValue = string;

export function readSignatureValueBin(buffer: Buffer, block: BlockInfo): Buffer {
    return readBitString(buffer, block).data;
}

export function readSignatureValue(buffer: Buffer, block: BlockInfo): SignatureValue {
    return readSignatureValueBin(buffer, block).toString("hex");
}

export function readLongIntegerValue(buffer: Buffer, block: BlockInfo): Buffer {
    assert(block.tag === TagType.INTEGER, "expecting a INTEGER tag");
    const pos = block.position;
    const nbBytes = block.length;
    const buf = buffer.subarray(pos, pos + nbBytes);
    return buf;
}

export function readIntegerValue(buffer: Buffer, block: BlockInfo): number {
    assert(block.tag === TagType.INTEGER, "expecting a INTEGER tag");
    let pos = block.position;
    const nbBytes = block.length;
    assert(nbBytes < 4);
    let value = 0;
    for (let i = 0; i < nbBytes; i++) {
        value = value * 256 + buffer.readUInt8(pos);
        pos += 1;
    }
    return value;
}

export function readBooleanValue(buffer: Buffer, block: BlockInfo): boolean {
    assert(block.tag === TagType.BOOLEAN, "expecting a BOOLEAN tag. got " + TagType[block.tag]);
    const pos = block.position;
    const nbBytes = block.length;
    assert(nbBytes < 4);
    const value = buffer.readUInt8(pos) ? true : false;
    return value as boolean;
}

export function readVersionValue(buffer: Buffer, block: BlockInfo): number {
    block = readTag(buffer, block.position);
    return readIntegerValue(buffer, block);
}

/*
 4.1.2.5.2  GeneralizedTime

 The generalized time type, GeneralizedTime, is a standard ASN.1 type
 for variable precision representation of time.  Optionally, the
 GeneralizedTime field can include a representation of the time
 differential between local and Greenwich Mean Time.

 For the purposes of this profile, GeneralizedTime values MUST be
 expressed Greenwich Mean Time (Zulu) and MUST include seconds (i.e.,
 times are YYYYMMDDHHMMSSZ), even where the number of seconds is zero.
 GeneralizedTime values MUST NOT include fractional seconds.

 */
function convertGeneralizedTime(str: string): Date {
    const year = parseInt(str.substr(0, 4), 10);
    const month = parseInt(str.substr(4, 2), 10) - 1;
    const day = parseInt(str.substr(6, 2), 10);
    const hours = parseInt(str.substr(8, 2), 10);
    const mins = parseInt(str.substr(10, 2), 10);
    const secs = parseInt(str.substr(12, 2), 10);

    return new Date(Date.UTC(year, month, day, hours, mins, secs));
}

function _readBMPString(buffer: Buffer, block: BlockInfo): string {
    const strBuff = getBlock(buffer, block);
    let str = "";
    for (let i = 0; i < strBuff.length; i += 2) {
        const word = strBuff.readUInt16BE(i);
        str += String.fromCharCode(word);
    }
    return str;
}

/*
 http://tools.ietf.org/html/rfc5280

 4.1.2.5. Validity
 [...]
 As conforming to this profile MUST always encode certificate
 validity dates through the year 2049 as UTCTime; certificate validity
 dates in 2050 or later MUST be encoded as GeneralizedTime.
 Conforming applications MUST be able to process validity dates that
 are encoded in either UTCTime or GeneralizedTime.
 [...]

 4.1.2.5.1  UTCTime

 The universal time type, UTCTime, is a standard ASN.1 type intended
 for representation of dates and time.  UTCTime specifies the year
 through the two low order digits and time is specified to the
 precision of one minute or one second.  UTCTime includes either Z
 (for Zulu, or Greenwich Mean Time) or a time differential.

 For the purposes of this profile, UTCTime values MUST be expressed
 Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
 YYMMDDHHMMSSZ), even where the number of seconds is zero.  Conforming
 systems MUST interpret the year field (YY) as follows:

 Where YY is greater than or equal to 50, the year SHALL be
 interpreted as 19YY; and

 Where YY is less than 50, the year SHALL be interpreted as 20YY.
 */
function convertUTCTime(str: string): Date {
    let year = parseInt(str.substr(0, 2), 10);
    const month = parseInt(str.substr(2, 2), 10) - 1;
    const day = parseInt(str.substr(4, 2), 10);
    const hours = parseInt(str.substr(6, 2), 10);
    const mins = parseInt(str.substr(8, 2), 10);
    const secs = parseInt(str.substr(10, 2), 10);

    year += year >= 50 ? 1900 : 2000;
    return new Date(Date.UTC(year, month, day, hours, mins, secs));
}

export function readValue(buffer: Buffer, block: BlockInfo): any {
    switch (block.tag) {
        case TagType.BOOLEAN:
            return readBooleanValue(buffer, block);
        case TagType.BMPString:
            return _readBMPString(buffer, block);
        case TagType.PrintableString:
        case TagType.TeletexString:
        case TagType.UTF8String:
        case TagType.NumericString:
        case TagType.IA5String:
            return getBlock(buffer, block).toString("ascii");
        case TagType.UTCTime:
            return convertUTCTime(getBlock(buffer, block).toString("ascii"));
        case TagType.GeneralizedTime:
            return convertGeneralizedTime(getBlock(buffer, block).toString("ascii"));
        default:
            throw new Error("Invalid tag 0x" + block.tag.toString(16) + "");
        //xx return " ??? <" + block.tag + ">";
    }
}


export function compactDirectoryName(d: DirectoryName): string {
    return JSON.stringify(d);
}


export function findBlockAtIndex(blocks: BlockInfo[], index: number): BlockInfo | null {
    const tmp = blocks.filter((b: BlockInfo) => b.tag === 0xa0 + index || b.tag === 0x80 + index);
    if (tmp.length === 0) {
        return null;
    }
    return tmp[0];
}

export function readTime(buffer: Buffer, block: BlockInfo): any {
    return readValue(buffer, block);
}
