/**
 * @module node_opcua_crypto
 */
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

// portion of this code has been ported from :
//
// ASN.1 JavaScript decoder Copyright (c) 2008-2014 Lapo Luchini lapo@lapo.it
// Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby
// granted, provided that the above copyright notice and this permission notice appear in all copies.
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
// INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
// AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.
// ---------------------------------------------------------------------------------------------------------------------
/*jslint bitwise: true */

// references:
//  - http://tools.ietf.org/html/rfc5280
//  - http://www-lor.int-evry.fr/~michel/Supports/presentation.pdf
//  - ftp://ftp.rsa.com/pub/pkcs/ascii/layman.asc
//  - pubs.opengroup.org/onlinepubs/009609799/7a_nch02.htm#tagcjh_49_03
//  - https://github.com/lapo-luchini/asn1js/blob/master/asn1.js
//  - http://lapo.it/asn1js
//  - https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
//  - http://pubs.opengroup.org/onlinepubs/009609799/7a_nch02.htm
//  - http://stackoverflow.com/questions/5929050/how-does-asn-1-encode-an-object-identifier
//  - http://luca.ntop.org/Teaching/Appunti/asn1.html

// note:
//  - http://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art030
//  openssl can be also used to discover the content of a DER file
//  $ openssl asn1parse -in cert.pem
import assert from "node:assert";

import {
    type AlgorithmIdentifier,
    type BlockInfo,
    findBlockAtIndex,
    formatBuffer2DigitHexWithColum,
    getBlock,
    readAlgorithmIdentifier,
    readBitString,
    readBooleanValue,
    readECCAlgorithmIdentifier,
    readIntegerValue,
    readListOfInteger,
    readLongIntegerValue,
    readObjectIdentifier,
    readOctetString,
    readSignatureValue,
    readStruct,
    readTag,
    readTime,
    readValue,
    readVersionValue,
    type SignatureValue,
    TagType,
} from "./asn1.js";
import type { Certificate } from "./common.js";
import { makeSHA1Thumbprint } from "./crypto_utils.js";
import { type DirectoryName, readDirectoryName } from "./directory_name.js";
import type { PublicKeyLength } from "./explore_certificate.js";

// Converted from: https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
// which is made by Peter Gutmann and whose license states:
// You can use this code in whatever way you want,
// as long as you don't try to claim you wrote it.

const doDebug = false;

export interface AttributeTypeAndValue {
    [key: string]: unknown;
}

function _readAttributeTypeAndValue(buffer: Buffer, block: BlockInfo): AttributeTypeAndValue {
    let inner_blocks = readStruct(buffer, block);
    inner_blocks = readStruct(buffer, inner_blocks[0]);

    const data = {
        identifier: readObjectIdentifier(buffer, inner_blocks[0]).name,
        value: readValue(buffer, inner_blocks[1]),
    };

    const result: AttributeTypeAndValue = {};

    for (const [key, value] of Object.entries(data)) {
        result[key] = value;
    }
    return result;
}

interface RelativeDistinguishedName {
    [prop: string]: unknown;
}

function _readRelativeDistinguishedName(buffer: Buffer, block: BlockInfo): RelativeDistinguishedName {
    const inner_blocks = readStruct(buffer, block);
    const data = inner_blocks.map((block) => _readAttributeTypeAndValue(buffer, block));
    const result: RelativeDistinguishedName = {};
    for (const e of data) {
        result[e.identifier as string] = e.value;
    }
    return result;
}

function _readName(buffer: Buffer, block: BlockInfo): RelativeDistinguishedName {
    return _readRelativeDistinguishedName(buffer, block);
}

export interface Validity {
    notBefore: Date;
    notAfter: Date;
}

function _readValidity(buffer: Buffer, block: BlockInfo): Validity {
    const inner_blocks = readStruct(buffer, block);
    return {
        notBefore: readTime(buffer, inner_blocks[0]) as Date,
        notAfter: readTime(buffer, inner_blocks[1]) as Date,
    };
}

function _readAuthorityKeyIdentifier(buffer: Buffer): AuthorityKeyIdentifier {
    /**
     *  where a CA distributes its public key in the form of a "self-signed"
     *  certificate, the authority key identifier MAY be omitted.  Th
     *  signature on a self-signed certificate is generated with the private
     * key associated with the certificate's subject public key.  (This
     * proves that the issuer possesses both the public and private keys.)
     * In this case, the subject and authority key identifiers would be
     * identical, but only the subject key identifier is needed for
     * certification path building.
     */
    // see: https://www.ietf.org/rfc/rfc3280.txt page 25
    // AuthorityKeyIdentifier ::= SEQUENCE {
    //      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
    //      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
    //      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
    // KeyIdentifier ::= OCTET STRING

    const block_info = readTag(buffer, 0);
    const blocks = readStruct(buffer, block_info);

    const keyIdentifier_block = findBlockAtIndex(blocks, 0);
    const authorityCertIssuer_block = findBlockAtIndex(blocks, 1);
    const authorityCertSerialNumber_block = findBlockAtIndex(blocks, 2);

    function _readAuthorityCertIssuer(block: BlockInfo): DirectoryName {
        const inner_blocks = readStruct(buffer, block);
        const directoryName_block = findBlockAtIndex(inner_blocks, 4);
        if (directoryName_block) {
            const a = readStruct(buffer, directoryName_block);
            return readDirectoryName(buffer, a[0]);
        } else {
            throw new Error("Invalid _readAuthorityCertIssuer");
        }
    }
    function _readAuthorityCertIssuerFingerPrint(block: BlockInfo): string {
        const inner_blocks = readStruct(buffer, block);
        const directoryName_block = findBlockAtIndex(inner_blocks, 4);
        if (!directoryName_block) {
            return "";
        }
        const a = readStruct(buffer, directoryName_block);
        if (a.length < 1) {
            return "";
        }
        return directoryName_block ? formatBuffer2DigitHexWithColum(makeSHA1Thumbprint(getBlock(buffer, a[0]))) : "";
    }

    const authorityCertIssuer = authorityCertIssuer_block ? _readAuthorityCertIssuer(authorityCertIssuer_block) : null;
    const authorityCertIssuerFingerPrint = authorityCertIssuer_block
        ? _readAuthorityCertIssuerFingerPrint(authorityCertIssuer_block)
        : "";

    return {
        authorityCertIssuer,
        authorityCertIssuerFingerPrint,
        serial: authorityCertSerialNumber_block
            ? formatBuffer2DigitHexWithColum(getBlock(buffer, authorityCertSerialNumber_block))
            : null, // can be null for self-signed cert
        keyIdentifier: keyIdentifier_block ? formatBuffer2DigitHexWithColum(getBlock(buffer, keyIdentifier_block)) : null, // can be null for self-signed certf
    };
}

/*
 Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }

      id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }

      KeyUsage ::= BIT STRING {
           digitalSignature        (0),
           nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) }

extKeyUsage
*/

function readBasicConstraint2_5_29_19(buffer: Buffer, _block: BlockInfo): BasicConstraints {
    const block_info = readTag(buffer, 0);
    const inner_blocks = readStruct(buffer, block_info).slice(0, 2);
    let cA = false;
    let pathLengthConstraint = 0;
    let breakControl = 0;

    for (const inner_block of inner_blocks) {
        switch (inner_block.tag) {
            case TagType.BOOLEAN:
                cA = readBooleanValue(buffer, inner_block);
                break;
            case TagType.INTEGER:
                pathLengthConstraint = readIntegerValue(buffer, inner_block);
                breakControl = 1;
                break;
        }

        if (breakControl) {
            break;
        }
    }

    return { critical: true, cA, pathLengthConstraint };
}

// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
// GeneralName ::= CHOICE {
//        otherName                 [0]  AnotherName,
//        rfc822Name                [1]  IA5String,
//        dNSName                   [2]  IA5String,
//        x400Address               [3]  ORAddress,
//        directoryName             [4]  Name,
//        ediPartyName              [5]  EDIPartyName,
//        uniformResourceIdentifier [6]  IA5String,
//        iPAddress                 [7]  OCTET STRING,
//        registeredID              [8]  OBJECT IDENTIFIER }
function _readGeneralNames(buffer: Buffer, block: BlockInfo) {
    const _data: { [key: number]: { name: string; type: string } } = {
        1: { name: "rfc822Name", type: "IA5String" },
        2: { name: "dNSName", type: "IA5String" },
        3: { name: "x400Address", type: "ORAddress" },
        4: { name: "directoryName", type: "Name" },
        5: { name: "ediPartyName", type: "EDIPartyName" },
        6: { name: "uniformResourceIdentifier", type: "IA5String" },
        7: { name: "iPAddress", type: "OCTET_STRING" },
        8: { name: "registeredID", type: "OBJECT_IDENTIFIER" },
        32: { name: "otherName", type: "AnotherName" },
    };
    const blocks = readStruct(buffer, block);

    function _readFromType(buffer: Buffer, block: BlockInfo, type: string) {
        switch (type) {
            case "IA5String":
                return buffer.subarray(block.position, block.position + block.length).toString("ascii");
            default:
                return buffer.subarray(block.position, block.position + block.length).toString("hex");
        }
    }

    const n: { [key: string]: string[] } = {};
    for (const block of blocks) {
        assert((block.tag & 0x80) === 0x80);
        const t = block.tag & 0x7f;
        const type = _data[t] as { name: string; type: string } | undefined;
        // istanbul ignore next
        if (!type) {
            console.log(`_readGeneralNames: INVALID TYPE => ${t} 0x${t.toString(16)}`);
            continue;
        }

        if (t === 32) {
            // console.log(buffer.subarray(block.start, block.position+ block.length).toString("hex"));
            n[type.name] = n[type.name] || [];

            const blocks2 = readStruct(buffer, block);
            const name = readObjectIdentifier(buffer, blocks2[0]).name;
            const buf = getBlock(buffer, blocks2[1]);
            const b = readTag(buf, 0);
            const nn = readValue(buf, b);
            // console.log(buf.toString("hex"), buf.toString("ascii"));
            // console.log("name = ", name, nn);
            const data = {
                identifier: name,
                value: nn,
            };
            n[type.name].push(data.value as string);
        } else {
            n[type.name] = n[type.name] || [];
            n[type.name].push(_readFromType(buffer, block, type.type));
        }
    }
    return n;
}

function _readSubjectAltNames(buffer: Buffer) {
    const block_info = readTag(buffer, 0);
    return _readGeneralNames(buffer, block_info);
}

// ---------------------------------------------------------------------------
//  CRL Distribution Points  -- RFC 5280 4.2.1.13, OID 2.5.29.31
// ---------------------------------------------------------------------------
//
//   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
//   DistributionPoint ::= SEQUENCE {
//        distributionPoint       [0] DistributionPointName OPTIONAL,
//        reasons                 [1] ReasonFlags OPTIONAL,
//        cRLIssuer               [2] GeneralNames OPTIONAL }
//   DistributionPointName ::= CHOICE {
//        fullName                [0] GeneralNames,
//        nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
//
// Only the fullName form is decoded; it is the one certificate authorities
// emit. The result has the same shape as subjectAltName, so a caller reads a
// URI from `uniformResourceIdentifier` in both places.
function _readCrlDistributionPoints(buffer: Buffer): { [key: string]: string[] } {
    const result: { [key: string]: string[] } = {};
    const outer = readTag(buffer, 0);
    for (const distributionPoint of readStruct(buffer, outer)) {
        for (const member of readStruct(buffer, distributionPoint)) {
            // [0] distributionPoint; skip reasons and cRLIssuer
            if ((member.tag & 0x1f) !== 0) continue;
            for (const choice of readStruct(buffer, member)) {
                // [0] fullName; nameRelativeToCRLIssuer is not decoded
                if ((choice.tag & 0x1f) !== 0) continue;
                const names = _readGeneralNames(buffer, choice);
                for (const key of Object.keys(names)) {
                    result[key] = (result[key] || []).concat(names[key]);
                }
            }
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
//  Authority Information Access  -- RFC 5280 4.2.2.1, OID 1.3.6.1.5.5.7.1.1
// ---------------------------------------------------------------------------

/** id-ad-ocsp, RFC 5280 4.2.2.1 */
const OID_AD_OCSP = "1.3.6.1.5.5.7.48.1";
/** id-ad-caIssuers, RFC 5280 4.2.2.1 */
const OID_AD_CA_ISSUERS = "1.3.6.1.5.5.7.48.2";

export interface AuthorityInformationAccess {
    /** Where to ask for revocation status online (RFC 6960). */
    ocsp?: string[];
    /** Where to fetch the issuer certificate, for chain repair. */
    caIssuers?: string[];
}

//   AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
//   AccessDescription ::= SEQUENCE {
//        accessMethod          OBJECT IDENTIFIER,
//        accessLocation        GeneralName }
//
// Each leg is identified by the OID that precedes it, never by its position:
// the order of the legs is not fixed, and reading them positionally points
// chain repair at the OCSP responder.
function _readAuthorityInformationAccess(buffer: Buffer): AuthorityInformationAccess {
    const result: AuthorityInformationAccess = {};
    const outer = readTag(buffer, 0);
    for (const accessDescription of readStruct(buffer, outer)) {
        const parts = readStruct(buffer, accessDescription);
        if (parts.length < 2 || parts[0].tag !== TagType.OBJECT_IDENTIFIER) continue;
        const accessMethod = readObjectIdentifier(buffer, parts[0]);
        const accessLocation = parts[1];
        // uniformResourceIdentifier [6]; other GeneralName forms carry no URL.
        if ((accessLocation.tag & 0x1f) !== 6) continue;
        const uri = buffer.subarray(accessLocation.position, accessLocation.position + accessLocation.length).toString("ascii");
        if (accessMethod.oid === OID_AD_OCSP) {
            result.ocsp = (result.ocsp || []).concat(uri);
        } else if (accessMethod.oid === OID_AD_CA_ISSUERS) {
            result.caIssuers = (result.caIssuers || []).concat(uri);
        }
    }
    return result;
}

// named X509KeyUsage not to confuse with DOM KeyUsage
export interface X509KeyUsage {
    digitalSignature: boolean;
    nonRepudiation: boolean;
    keyEncipherment: boolean;
    dataEncipherment: boolean;
    keyAgreement: boolean;
    keyCertSign: boolean;
    cRLSign: boolean;
    encipherOnly: boolean;
    decipherOnly: boolean;
}
export interface X509ExtKeyUsage {
    clientAuth: boolean;
    serverAuth: boolean;
    codeSigning: boolean;
    emailProtection: boolean;
    timeStamping: boolean;
    ocspSigning: boolean;
    ipsecEndSystem: boolean;
    ipsecTunnel: boolean;
    ipsecUser: boolean;
    // etc ... to be completed
}

function readKeyUsage(_oid: string, buffer: Buffer): X509KeyUsage {
    const block_info = readTag(buffer, 0);

    // get value as BIT STRING
    let b2 = 0x00;
    let b3 = 0x00;
    if (block_info.length > 1) {
        // skip first byte, just indicates unused bits which
        // will be padded with 0s anyway
        // get bytes with flag bits
        b2 = buffer[block_info.position + 1];
        b3 = block_info.length > 2 ? buffer[block_info.position + 2] : 0;
    }

    // set flags
    return {
        digitalSignature: (b2 & 0x80) === 0x80,
        nonRepudiation: (b2 & 0x40) === 0x40,
        keyEncipherment: (b2 & 0x20) === 0x20,
        dataEncipherment: (b2 & 0x10) === 0x10,
        keyAgreement: (b2 & 0x08) === 0x08,
        keyCertSign: (b2 & 0x04) === 0x04,
        cRLSign: (b2 & 0x02) === 0x02,
        encipherOnly: (b2 & 0x01) === 0x01,
        decipherOnly: (b3 & 0x80) === 0x80,
    };
}

function readExtKeyUsage(oid: string, buffer: Buffer): X509ExtKeyUsage {
    assert(oid === "2.5.29.37");
    // see https://tools.ietf.org/html/rfc5280#section-4.2.1.12
    const block_info = readTag(buffer, 0);

    const inner_blocks = readStruct(buffer, block_info);

    const extKeyUsage: X509ExtKeyUsage = {
        serverAuth: false,
        clientAuth: false,
        codeSigning: false,
        emailProtection: false,
        timeStamping: false,
        ipsecEndSystem: false,
        ipsecTunnel: false,
        ipsecUser: false,
        ocspSigning: false,
    };
    for (const block of inner_blocks) {
        const identifier = readObjectIdentifier(buffer, block);
        // verify that identifier is one of the expected ones
        // to do

        // set flag
        extKeyUsage[identifier.name as keyof X509ExtKeyUsage] = true;
    }
    /*
    
   id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }

   id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
   -- TLS WWW server authentication
   -- Key usage bits that may be consistent: digitalSignature,
   -- keyEncipherment or keyAgreement

   id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
   -- TLS WWW client authentication
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or keyAgreement

   id-kp-codeSigning             OBJECT IDENTIFIER ::= { id-kp 3 }
   -- Signing of downloadable executable code
   -- Key usage bits that may be consistent: digitalSignature

   id-kp-emailProtection         OBJECT IDENTIFIER ::= { id-kp 4 }
   -- Email protection
   -- Key usage bits that may be consistent: digitalSignature,
   -- nonRepudiation, and/or (keyEncipherment or keyAgreement)

   id-kp-timeStamping            OBJECT IDENTIFIER ::= { id-kp 8 }
   -- Binding the hash of an object to a time
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation

   id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
   -- Signing OCSP responses
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation

   */
    // set flags
    return extKeyUsage;
}

export interface SubjectPublicKey {
    modulus: Buffer;
}
function _readSubjectPublicKey(buffer: Buffer): SubjectPublicKey {
    const block_info = readTag(buffer, 0);
    const blocks = readStruct(buffer, block_info);

    return {
        modulus: buffer.subarray(blocks[0].position + 1, blocks[0].position + blocks[0].length),
    };
}
/*
 Extension  ::=  SEQUENCE  {
 extnID      OBJECT IDENTIFIER,
 critical    BOOLEAN DEFAULT FALSE,
 extnValue   OCTET STRING
 -- contains the DER encoding of an ASN.1 value
 -- corresponding to the extension type identified
 -- by extnID
 }
 */
export function readExtension(
    buffer: Buffer,
    block: BlockInfo,
): {
    identifier: { oid: string; name: string };
    value:
        | string
        | X509KeyUsage
        | X509ExtKeyUsage
        | AuthorityKeyIdentifier
        | BasicConstraints
        | AuthorityInformationAccess
        | { [key: string]: string[] };
} {
    const inner_blocks = readStruct(buffer, block);

    if (inner_blocks.length === 3) {
        assert(inner_blocks[1].tag === TagType.BOOLEAN);
        inner_blocks[1] = inner_blocks[2];
    }

    const identifier = readObjectIdentifier(buffer, inner_blocks[0]);
    const buf = getBlock(buffer, inner_blocks[1]);
    let value:
        | string
        | X509KeyUsage
        | X509ExtKeyUsage
        | AuthorityKeyIdentifier
        | BasicConstraints
        | AuthorityInformationAccess
        | { [key: string]: string[] }
        | null = null;
    switch (identifier.name) {
        case "subjectKeyIdentifier":
            /* from https://tools.ietf.org/html/rfc3280#section-4.1 :
               For CA certificates, subject key identifiers SHOULD be derived from
               the public key or a method that generates unique values.  Two common
               methods for generating key identifiers from the public key are:

                  (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
                  value of the BIT STRING subjectPublicKey (excluding the tag,
                  length, and number of unused bits).

                  (2) The keyIdentifier is composed of a four bit type field with
                  the value 0100 followed by the least significant 60 bits of the
                  SHA-1 hash of the value of the BIT STRING subjectPublicKey
                  (excluding the tag, length, and number of unused bit string bits).
            */
            value = formatBuffer2DigitHexWithColum(readOctetString(buffer, inner_blocks[1]));
            break;
        case "subjectAltName":
            value = _readSubjectAltNames(buf);
            break;
        case "authorityKeyIdentifier":
            value = _readAuthorityKeyIdentifier(buf);
            break;
        case "basicConstraints":
            value = readBasicConstraint2_5_29_19(buf, inner_blocks[1]); //  "2.5.29.19":
            // "basicConstraints ( not implemented yet) " + buf.toString("hex");
            break;
        case "certExtension": // Netscape
            value = `basicConstraints ( not implemented yet) ${buf.toString("hex")}`;
            break;
        case "extKeyUsage":
            value = readExtKeyUsage(identifier.oid, buf);
            break;
        case "cRLDistributionPoints":
            value = _readCrlDistributionPoints(buf);
            break;
        case "authorityInfoAccess":
            value = _readAuthorityInformationAccess(buf);
            break;
        case "keyUsage":
            value = readKeyUsage(identifier.oid, buf);
            break;
        default:
            value = `Unknown ${identifier.name}${buf.toString("hex")}`;
    }
    return {
        identifier,
        value,
    };
}

// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
function _readExtensions(buffer: Buffer, block: BlockInfo): CertificateExtension {
    assert(block.tag === 0xa3);
    let inner_blocks = readStruct(buffer, block);
    inner_blocks = readStruct(buffer, inner_blocks[0]);

    const extensions = inner_blocks.map((block) => readExtension(buffer, block));

    const result: Record<
        string,
        | string
        | AuthorityKeyIdentifier
        | BasicConstraints
        | AuthorityInformationAccess
        | X509KeyUsage
        | X509ExtKeyUsage
        | { [key: string]: string[] }
    > = {};
    for (const e of extensions) {
        result[e.identifier.name] = e.value;
    }
    return result as unknown as CertificateExtension;
}

/*
 SEQUENCE {
 204   13:       SEQUENCE {
 206    9:         OBJECT IDENTIFIER
 :           rsaEncryption (1 2 840 113549 1 1 1)
 217    0:         NULL
 :         }
 219  141:       BIT STRING, encapsulates {
 223  137:         SEQUENCE {
 226  129:           INTEGER
 :             00 C2 D7 97 6D 28 70 AA 5B CF 23 2E 80 70 39 EE
 :             DB 6F D5 2D D5 6A 4F 7A 34 2D F9 22 72 47 70 1D
 :             EF 80 E9 CA 30 8C 00 C4 9A 6E 5B 45 B4 6E A5 E6
 :             6C 94 0D FA 91 E9 40 FC 25 9D C7 B7 68 19 56 8F
 :             11 70 6A D7 F1 C9 11 4F 3A 7E 3F 99 8D 6E 76 A5
 :             74 5F 5E A4 55 53 E5 C7 68 36 53 C7 1D 3B 12 A6
 :             85 FE BD 6E A1 CA DF 35 50 AC 08 D7 B9 B4 7E 5C
 :             FE E2 A3 2C D1 23 84 AA 98 C0 9B 66 18 9A 68 47
 :             E9
 358    3:           INTEGER 65537
 :           }
 :         }
 :       }
 */

function _readSubjectPublicKeyInfo(buffer: Buffer, block: BlockInfo): SubjectPublicKeyInfo {
    const inner_blocks = readStruct(buffer, block);

    // algorithm identifier
    const algorithm = readAlgorithmIdentifier(buffer, inner_blocks[0]);
    //const parameters         = _readBitString(buffer,inner_blocks[1]);
    const subjectPublicKey = readBitString(buffer, inner_blocks[1]);

    // read the 2 big integers of the key
    const data = subjectPublicKey.data;
    const values = readListOfInteger(data);
    // xx const value = _readListOfInteger(data);
    return {
        algorithm: algorithm.identifier,
        keyLength: (values[0].length - 1) as PublicKeyLength,
        subjectPublicKey: _readSubjectPublicKey(subjectPublicKey.data),
        //xx values: values,
        //xx values_length : values.map(function (a){ return a.length; })
    };
}

function _readSubjectECCPublicKeyInfo(buffer: Buffer, block: BlockInfo): SubjectPublicKeyInfo {
    const inner_blocks = readStruct(buffer, block);

    // first parameter is the second element of the first block, which is why we have another algorithm
    const algorithm = readECCAlgorithmIdentifier(buffer, inner_blocks[0]);

    // the public key is already in bit format, we just need to read it
    const subjectPublicKey = readBitString(buffer, inner_blocks[1]);

    // take out the data which is the entirity of our public key
    const data = subjectPublicKey.data;
    return {
        algorithm: algorithm.identifier,
        keyLength: (data.length - 1) as PublicKeyLength,
        subjectPublicKey: {
            modulus: data,
        },
    };
}

export interface SubjectPublicKeyInfo {
    algorithm: string;
    keyLength: PublicKeyLength;
    subjectPublicKey: SubjectPublicKey;
}

export interface BasicConstraints {
    critical: boolean;
    cA: boolean;
    pathLengthConstraint?: number; // 0 Unlimited
}

export interface AuthorityKeyIdentifier {
    keyIdentifier: string | null;
    authorityCertIssuer: DirectoryName | null;
    authorityCertIssuerFingerPrint: string;
    serial: string | null;
}

export interface CertificateExtension {
    basicConstraints: BasicConstraints;
    subjectKeyIdentifier?: string;
    authorityKeyIdentifier?: AuthorityKeyIdentifier;
    keyUsage?: X509KeyUsage;
    extKeyUsage?: X509ExtKeyUsage;
    subjectAltName?: { [key: string]: string[] };
    /** RFC 5280 4.2.1.13 -- where the CRL for this certificate is published. */
    cRLDistributionPoints?: { [key: string]: string[] };
    /** RFC 5280 4.2.2.1 -- OCSP responder and issuer-certificate locations. */
    authorityInfoAccess?: AuthorityInformationAccess;
}

export interface TbsCertificate {
    version: number;
    serialNumber: string;
    issuer: DirectoryName;
    signature: AlgorithmIdentifier;
    validity: Validity;
    subject: DirectoryName;
    subjectFingerPrint: string;
    subjectPublicKeyInfo: SubjectPublicKeyInfo;
    extensions: CertificateExtension | null;
}

export function readTbsCertificate(buffer: Buffer, block: BlockInfo): TbsCertificate {
    const blocks = readStruct(buffer, block);

    let _version: number;
    let serialNumber: string | undefined;
    let signature: AlgorithmIdentifier;
    let issuer: DirectoryName;
    let validity: Validity;
    let subject: DirectoryName;
    let subjectFingerPrint: string;
    let extensions: CertificateExtension | null;
    let subjectPublicKeyInfo: SubjectPublicKeyInfo;

    if (blocks.length === 6) {
        // X509 Version 1:
        _version = 1;

        serialNumber = formatBuffer2DigitHexWithColum(readLongIntegerValue(buffer, blocks[0]));
        signature = readAlgorithmIdentifier(buffer, blocks[1]);
        issuer = _readName(buffer, blocks[2]);
        validity = _readValidity(buffer, blocks[3]);
        subject = _readName(buffer, blocks[4]);
        subjectFingerPrint = formatBuffer2DigitHexWithColum(makeSHA1Thumbprint(getBlock(buffer, blocks[4])));
        subjectPublicKeyInfo = _readSubjectPublicKeyInfo(buffer, blocks[5]);

        extensions = null;
    } else {
        // X509 Version 3:
        const version_block = findBlockAtIndex(blocks, 0);
        if (!version_block) {
            throw new Error("cannot find version block");
        }
        _version = readVersionValue(buffer, version_block) + 1;
        serialNumber = formatBuffer2DigitHexWithColum(readLongIntegerValue(buffer, blocks[1]));
        signature = readAlgorithmIdentifier(buffer, blocks[2]);
        issuer = _readName(buffer, blocks[3]);
        validity = _readValidity(buffer, blocks[4]);
        subject = _readName(buffer, blocks[5]);
        subjectFingerPrint = formatBuffer2DigitHexWithColum(makeSHA1Thumbprint(getBlock(buffer, blocks[5])));

        const inner_block = readStruct(buffer, blocks[6]);
        const what_type = readAlgorithmIdentifier(buffer, inner_block[0]).identifier;

        switch (what_type) {
            case "rsaEncryption": {
                subjectPublicKeyInfo = _readSubjectPublicKeyInfo(buffer, blocks[6]);
                break;
            }
            default: {
                assert(what_type === "ecPublicKey");
                subjectPublicKeyInfo = _readSubjectECCPublicKeyInfo(buffer, blocks[6]);
                break;
            }
        }

        const extensionBlock = findBlockAtIndex(blocks, 3);
        if (!extensionBlock) {
            doDebug && console.log(`X509 certificate is invalid : cannot find extension block version = ${version_block}`);
            extensions = null;
        } else {
            extensions = _readExtensions(buffer, extensionBlock);
        }
    }

    return {
        version: _version,
        serialNumber,
        signature,
        issuer,
        validity,
        subject,
        subjectFingerPrint,
        subjectPublicKeyInfo,
        extensions,
    };
}
export interface CertificateInternals {
    tbsCertificate: TbsCertificate;
    signatureAlgorithm: AlgorithmIdentifier;
    signatureValue: SignatureValue;
}

class LRUCache<K, V> {
    private map = new Map<K, V>();
    constructor(private maxSize: number) {}

    public get(key: K): V | undefined {
        if (!this.map.has(key)) {
            return undefined;
        }
        const val = this.map.get(key);
        if (val !== undefined) {
            this.map.delete(key);
            this.map.set(key, val);
            return val;
        }
        return undefined;
    }

    public set(key: K, value: V): void {
        if (this.map.has(key)) {
            this.map.delete(key);
        } else if (this.map.size >= this.maxSize) {
            const oldestKey = this.map.keys().next().value;
            if (oldestKey !== undefined) {
                this.map.delete(oldestKey);
            }
        }
        this.map.set(key, value);
    }

    public clear(): void {
        this.map.clear();
    }
}

const exploreCertificateCache = new LRUCache<string, CertificateInternals>(1000);

export function clearExploreCertificateCache(): void {
    exploreCertificateCache.clear();
}

/**
 * explore a certificate structure
 * @param certificate
 * @returns a json object that exhibits the internal data of the certificate
 */
export function exploreCertificate(certificate: Certificate): CertificateInternals {
    assert(Buffer.isBuffer(certificate));

    const key = certificate.toString("base64");
    let cached = exploreCertificateCache.get(key);

    if (!cached) {
        verify_certificate_der_structure(certificate);
        const block_info = readTag(certificate, 0);
        const blocks = readStruct(certificate, block_info);
        cached = {
            tbsCertificate: readTbsCertificate(certificate, blocks[0]),
            signatureAlgorithm: readAlgorithmIdentifier(certificate, blocks[1]),
            signatureValue: readSignatureValue(certificate, blocks[2]),
        };
        exploreCertificateCache.set(key, cached);
    }

    return cached;
}

/**
 * @method split_der
 * split a multi chain certificates
 * @param certificateChain  the certificate chain in der (binary) format}
 * @returns an array of Der , each element of the array is one certificate of the chain
 */
export function split_der(certificateChain: Certificate): Certificate[] {
    const certificate_chain: Buffer[] = [];

    do {
        const block_info = readTag(certificateChain, 0);
        const length = block_info.position + block_info.length;
        if (length > certificateChain.length) {
            throw new Error("Invalid certificate chain: block length exceeds buffer length");
        }
        const der_certificate = certificateChain.subarray(0, length);
        certificate_chain.push(der_certificate);
        certificateChain = certificateChain.subarray(length);
    } while (certificateChain.length > 0);
    return certificate_chain;
}

/**
 * @method verify_certificate_der_structure
 * Verify that a certificate or certificate chain is structurally well-formed DER.
 * Ensures the blocks parse correctly and the length exactly matches the buffer length.
 * @param cert the DER certificate or chain to verify
 * @throws {Error} if the structure is invalid or truncated
 */
export function verify_certificate_der_structure(cert: Certificate): void {
    const blocks = split_der(cert);
    let sum = 0;
    for (const block of blocks) {
        const block_info = readTag(block, 0);
        if (block_info.position + block_info.length !== block.length) {
            throw new Error("Invalid certificate buffer: block length doesn't match");
        }
        sum += block.length;
    }
    if (sum !== cert.length) {
        throw new Error("Invalid certificate buffer: total block length doesn't match buffer length");
    }
}

/**
 * @method combine_der
 * combine an array of certificates into a single blob
 * @param certificates a array with the individual DER certificates of the chain
 * @return a concatenated buffer containing the certificates
 */
export function combine_der(certificates: Certificate[]): Certificate {
    // perform some sanity check
    for (const cert of certificates) {
        verify_certificate_der_structure(cert);
    }
    return Buffer.concat(certificates);
}
