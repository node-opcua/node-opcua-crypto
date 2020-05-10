/**
 * @module node_opcua_crypto
 */
// ---------------------------------------------------------------------------------------------------------------------
// crypto_explore_certificate
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2020 - Etienne Rossignon
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
//
//
// ---------------------------------------------------------------------------------------------------------------------
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
// tslint:disable:no-shadowed-variable

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
import * as _ from "underscore";
import { Certificate, PrivateKey } from "./common";
import { PublicKeyLength } from "./explore_certificate";
import * as assert from "assert";
// Converted from: https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
// which is made by Peter Gutmann and whose license states:
// You can use this code in whatever way you want,
// as long as you don't try to claim you wrote it.

const doDebug = false;

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
}

// https://github.com/lapo-luchini/asn1js/blob/master/oids.js
const oid_map: any = {
    "0.9.2342.19200300.100.1.1": { d: "userID", c: "Some oddball X.500 attribute collection" },
    "0.9.2342.19200300.100.1.3": { d: "rfc822Mailbox", c: "Some oddball X.500 attribute collection" },
    "0.9.2342.19200300.100.1.25": { d: "domainComponent", c: "Men are from Mars, this OID is from Pluto" },

    "1.2.840.113549.1.1": { d: "pkcs-1", c: "", w: false },
    "1.2.840.113549.1.1.1": { d: "rsaEncryption", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.2": { d: "md2WithRSAEncryption", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.3": { d: "md4WithRSAEncryption", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.4": { d: "md5WithRSAEncryption", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.5": { d: "sha1WithRSAEncryption", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.7": { d: "rsaOAEP", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.8": { d: "pkcs1-MGF", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.9": { d: "rsaOAEP-pSpecified", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.10": { d: "rsaPSS", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.11": { d: "sha256WithRSAEncryption", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.12": { d: "sha384WithRSAEncryption", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.13": { d: "sha512WithRSAEncryption", c: "PKCS #1", w: false },
    "1.2.840.113549.1.1.14": { d: "sha224WithRSAEncryption", c: "PKCS #1", w: false },

    "1.2.840.113549.1.9.1": {
        d: "emailAddress",
        c: "PKCS #9. Deprecated, use an altName extension instead",
        w: false,
    },
    "1.2.840.113549.1.9.2": { d: "unstructuredName", c: "PKCS #9", w: false },
    "1.2.840.113549.1.9.3": { d: "contentType", c: "PKCS #9", w: false },
    "1.2.840.113549.1.9.4": { d: "messageDigest", c: "PKCS #9", w: false },
    "1.2.840.113549.1.9.5": { d: "signingTime", c: "PKCS #9", w: false },
    "1.2.840.113549.1.9.6": { d: "countersignature", c: "PKCS #9", w: false },
    "1.2.840.113549.1.9.7": { d: "challengePassword", c: "PKCS #9", w: false },
    "1.2.840.113549.1.9.8": { d: "unstructuredAddress", c: "PKCS #9", w: false },
    "1.2.840.113549.1.9.9": { d: "extendedCertificateAttributes", c: "PKCS #9", w: false },
    "1.2.840.113549.1.9.10": { d: "issuerAndSerialNumber", c: "PKCS #9 experimental", w: true },
    "1.2.840.113549.1.9.11": { d: "passwordCheck", c: "PKCS #9 experimental", w: true },
    "1.2.840.113549.1.9.12": { d: "publicKey", c: "PKCS #9 experimental", w: true },
    "1.2.840.113549.1.9.13": { d: "signingDescription", c: "PKCS #9", w: false },
    "1.2.840.113549.1.9.14": { d: "extensionRequest", c: "PKCS #9 via CRMF", w: false },

    "1.3.6.1.5.5.7.3.1": { d: "serverAuth", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.2": { d: "clientAuth", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.3": { d: "codeSigning", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.4": { d: "emailProtection", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.5": { d: "ipsecEndSystem", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.6": { d: "ipsecTunnel", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.7": { d: "ipsecUser", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.8": { d: "timeStamping", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.9": { d: "ocspSigning", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.10": { d: "dvcs", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.11": { d: "sbgpCertAAServerAuth", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.13": { d: "eapOverPPP", c: "PKIX key purpose" },
    "1.3.6.1.5.5.7.3.14": { d: "eapOverLAN", c: "PKIX key purpose" },

    "2.5.4.0": { d: "objectClass", c: "X.520 DN component", w: false },
    "2.5.4.1": { d: "aliasedEntryName", c: "X.520 DN component", w: false },
    "2.5.4.2": { d: "knowledgeInformation", c: "X.520 DN component", w: false },
    "2.5.4.3": { d: "commonName", c: "X.520 DN component", w: false },
    "2.5.4.4": { d: "surname", c: "X.520 DN component", w: false },
    "2.5.4.5": { d: "serialNumber", c: "X.520 DN component", w: false },
    "2.5.4.6": { d: "countryName", c: "X.520 DN component", w: false },
    "2.5.4.7": { d: "localityName", c: "X.520 DN component", w: false },
    "2.5.4.7.1": { d: "collectiveLocalityName", c: "X.520 DN component", w: false },
    "2.5.4.8": { d: "stateOrProvinceName", c: "X.520 DN component", w: false },
    "2.5.4.8.1": { d: "collectiveStateOrProvinceName", c: "X.520 DN component", w: false },
    "2.5.4.9": { d: "streetAddress", c: "X.520 DN component", w: false },
    "2.5.4.9.1": { d: "collectiveStreetAddress", c: "X.520 DN component", w: false },
    "2.5.4.10": { d: "organizationName", c: "X.520 DN component", w: false },
    "2.5.4.10.1": { d: "collectiveOrganizationName", c: "X.520 DN component", w: false },
    "2.5.4.11": { d: "organizationalUnitName", c: "X.520 DN component", w: false },
    "2.5.4.11.1": { d: "collectiveOrganizationalUnitName", c: "X.520 DN component", w: false },
    "2.5.4.12": { d: "title", c: "X.520 DN component", w: false },
    "2.5.4.13": { d: "description", c: "X.520 DN component", w: false },
    "2.5.4.14": { d: "searchGuide", c: "X.520 DN component", w: false },
    "2.5.4.15": { d: "businessCategory", c: "X.520 DN component", w: false },
    "2.5.4.16": { d: "postalAddress", c: "X.520 DN component", w: false },
    "2.5.4.16.1": { d: "collectivePostalAddress", c: "X.520 DN component", w: false },
    "2.5.4.17": { d: "postalCode", c: "X.520 DN component", w: false },
    "2.5.4.17.1": { d: "collectivePostalCode", c: "X.520 DN component", w: false },
    "2.5.4.18": { d: "postOfficeBox", c: "X.520 DN component", w: false },
    "2.5.4.18.1": { d: "collectivePostOfficeBox", c: "X.520 DN component", w: false },
    "2.5.4.19": { d: "physicalDeliveryOfficeName", c: "X.520 DN component", w: false },
    "2.5.4.19.1": { d: "collectivePhysicalDeliveryOfficeName", c: "X.520 DN component", w: false },
    "2.5.4.20": { d: "telephoneNumber", c: "X.520 DN component", w: false },
    "2.5.4.20.1": { d: "collectiveTelephoneNumber", c: "X.520 DN component", w: false },
    "2.5.4.21": { d: "telexNumber", c: "X.520 DN component", w: false },
    "2.5.4.21.1": { d: "collectiveTelexNumber", c: "X.520 DN component", w: false },
    "2.5.4.22": { d: "teletexTerminalIdentifier", c: "X.520 DN component", w: false },
    "2.5.4.22.1": { d: "collectiveTeletexTerminalIdentifier", c: "X.520 DN component", w: false },
    "2.5.4.23": { d: "facsimileTelephoneNumber", c: "X.520 DN component", w: false },
    "2.5.4.23.1": { d: "collectiveFacsimileTelephoneNumber", c: "X.520 DN component", w: false },
    "2.5.4.24": { d: "x121Address", c: "X.520 DN component", w: false },
    "2.5.4.25": { d: "internationalISDNNumber", c: "X.520 DN component", w: false },
    "2.5.4.25.1": { d: "collectiveInternationalISDNNumber", c: "X.520 DN component", w: false },
    "2.5.4.26": { d: "registeredAddress", c: "X.520 DN component", w: false },
    "2.5.4.27": { d: "destinationIndicator", c: "X.520 DN component", w: false },
    "2.5.4.28": { d: "preferredDeliveryMehtod", c: "X.520 DN component", w: false },
    "2.5.4.29": { d: "presentationAddress", c: "X.520 DN component", w: false },
    "2.5.4.30": { d: "supportedApplicationContext", c: "X.520 DN component", w: false },
    "2.5.4.31": { d: "member", c: "X.520 DN component", w: false },
    "2.5.4.32": { d: "owner", c: "X.520 DN component", w: false },
    "2.5.4.33": { d: "roleOccupant", c: "X.520 DN component", w: false },
    "2.5.4.34": { d: "seeAlso", c: "X.520 DN component", w: false },
    "2.5.4.35": { d: "userPassword", c: "X.520 DN component", w: false },
    "2.5.4.36": { d: "userCertificate", c: "X.520 DN component", w: false },
    "2.5.4.37": { d: "caCertificate", c: "X.520 DN component", w: false },
    "2.5.4.38": { d: "authorityRevocationList", c: "X.520 DN component", w: false },
    "2.5.4.39": { d: "certificateRevocationList", c: "X.520 DN component", w: false },
    "2.5.4.40": { d: "crossCertificatePair", c: "X.520 DN component", w: false },
    "2.5.4.41": { d: "name", c: "X.520 DN component", w: false },
    "2.5.4.42": { d: "givenName", c: "X.520 DN component", w: false },
    "2.5.4.43": { d: "initials", c: "X.520 DN component", w: false },
    "2.5.4.44": { d: "generationQualifier", c: "X.520 DN component", w: false },
    "2.5.4.45": { d: "uniqueIdentifier", c: "X.520 DN component", w: false },
    "2.5.4.46": { d: "dnQualifier", c: "X.520 DN component", w: false },
    "2.5.4.47": { d: "enhancedSearchGuide", c: "X.520 DN component", w: false },
    "2.5.4.48": { d: "protocolInformation", c: "X.520 DN component", w: false },
    "2.5.4.49": { d: "distinguishedName", c: "X.520 DN component", w: false },
    "2.5.4.50": { d: "uniqueMember", c: "X.520 DN component", w: false },
    "2.5.4.51": { d: "houseIdentifier", c: "X.520 DN component", w: false },
    "2.5.4.52": { d: "supportedAlgorithms", c: "X.520 DN component", w: false },
    "2.5.4.53": { d: "deltaRevocationList", c: "X.520 DN component", w: false },
    "2.5.4.54": { d: "dmdName", c: "X.520 DN component", w: false },
    "2.5.4.55": { d: "clearance", c: "X.520 DN component", w: false },
    "2.5.4.56": { d: "defaultDirQop", c: "X.520 DN component", w: false },
    "2.5.4.57": { d: "attributeIntegrityInfo", c: "X.520 DN component", w: false },
    "2.5.4.58": { d: "attributeCertificate", c: "X.520 DN component", w: false },
    "2.5.4.59": { d: "attributeCertificateRevocationList", c: "X.520 DN component", w: false },
    "2.5.4.60": { d: "confKeyInfo", c: "X.520 DN component", w: false },
    "2.5.4.61": { d: "aACertificate", c: "X.520 DN component", w: false },
    "2.5.4.62": { d: "attributeDescriptorCertificate", c: "X.520 DN component", w: false },
    "2.5.4.63": { d: "attributeAuthorityRevocationList", c: "X.520 DN component", w: false },
    "2.5.4.64": { d: "familyInformation", c: "X.520 DN component", w: false },
    "2.5.4.65": { d: "pseudonym", c: "X.520 DN component", w: false },
    "2.5.4.66": { d: "communicationsService", c: "X.520 DN component", w: false },
    "2.5.4.67": { d: "communicationsNetwork", c: "X.520 DN component", w: false },
    "2.5.4.68": { d: "certificationPracticeStmt", c: "X.520 DN component", w: false },
    "2.5.4.69": { d: "certificatePolicy", c: "X.520 DN component", w: false },
    "2.5.4.70": { d: "pkiPath", c: "X.520 DN component", w: false },
    "2.5.4.71": { d: "privPolicy", c: "X.520 DN component", w: false },
    "2.5.4.72": { d: "role", c: "X.520 DN component", w: false },
    "2.5.4.73": { d: "delegationPath", c: "X.520 DN component", w: false },
    "2.5.4.74": { d: "protPrivPolicy", c: "X.520 DN component", w: false },
    "2.5.4.75": { d: "xMLPrivilegeInfo", c: "X.520 DN component", w: false },
    "2.5.4.76": { d: "xmlPrivPolicy", c: "X.520 DN component", w: false },
    "2.5.4.82": { d: "permission", c: "X.520 DN component", w: false },
    "2.5.6.0": { d: "top", c: "X.520 objectClass", w: false },
    "2.5.6.1": { d: "alias", c: "X.520 objectClass", w: false },
    "2.5.6.2": { d: "country", c: "X.520 objectClass", w: false },
    "2.5.6.3": { d: "locality", c: "X.520 objectClass", w: false },
    "2.5.6.4": { d: "organization", c: "X.520 objectClass", w: false },
    "2.5.6.5": { d: "organizationalUnit", c: "X.520 objectClass", w: false },
    "2.5.6.6": { d: "person", c: "X.520 objectClass", w: false },
    "2.5.6.7": { d: "organizationalPerson", c: "X.520 objectClass", w: false },
    "2.5.6.8": { d: "organizationalRole", c: "X.520 objectClass", w: false },
    "2.5.6.9": { d: "groupOfNames", c: "X.520 objectClass", w: false },
    "2.5.6.10": { d: "residentialPerson", c: "X.520 objectClass", w: false },
    "2.5.6.11": { d: "applicationProcess", c: "X.520 objectClass", w: false },
    "2.5.6.12": { d: "applicationEntity", c: "X.520 objectClass", w: false },
    "2.5.6.13": { d: "dSA", c: "X.520 objectClass", w: false },
    "2.5.6.14": { d: "device", c: "X.520 objectClass", w: false },
    "2.5.6.15": { d: "strongAuthenticationUser", c: "X.520 objectClass", w: false },
    "2.5.6.16": { d: "certificateAuthority", c: "X.520 objectClass", w: false },
    "2.5.6.17": { d: "groupOfUniqueNames", c: "X.520 objectClass", w: false },
    "2.5.6.21": { d: "pkiUser", c: "X.520 objectClass", w: false },
    "2.5.6.22": { d: "pkiCA", c: "X.520 objectClass", w: false },

    "2.5.29.1": { d: "authorityKeyIdentifier", c: "X.509 extension. Deprecated, use 2 5 29 35 instead", w: true },
    "2.5.29.2": { d: "keyAttributes", c: "X.509 extension. Obsolete, use keyUsage/extKeyUsage instead", w: true },
    "2.5.29.3": { d: "certificatePolicies", c: "X.509 extension. Deprecated, use 2 5 29 32 instead", w: true },
    "2.5.29.4": {
        d: "keyUsageRestriction",
        c: "X.509 extension. Obsolete, use keyUsage/extKeyUsage instead",
        w: true,
    },
    "2.5.29.5": { d: "policyMapping", c: "X.509 extension. Deprecated, use 2 5 29 33 instead", w: true },
    "2.5.29.6": { d: "subtreesConstraint", c: "X.509 extension. Obsolete, use nameConstraints instead", w: true },
    "2.5.29.7": { d: "subjectAltName", c: "X.509 extension. Deprecated, use 2 5 29 17 instead", w: true },
    "2.5.29.8": { d: "issuerAltName", c: "X.509 extension. Deprecated, use 2 5 29 18 instead", w: true },
    "2.5.29.9": { d: "subjectDirectoryAttributes", c: "X.509 extension", w: false },
    "2.5.29.10": { d: "basicConstraints", c: "X.509 extension. Deprecated, use 2 5 29 19 instead", w: true },
    "2.5.29.11": { d: "nameConstraints", c: "X.509 extension. Deprecated, use 2 5 29 30 instead", w: true },
    "2.5.29.12": { d: "policyConstraints", c: "X.509 extension. Deprecated, use 2 5 29 36 instead", w: true },
    "2.5.29.13": { d: "basicConstraints", c: "X.509 extension. Deprecated, use 2 5 29 19 instead", w: true },
    "2.5.29.14": { d: "subjectKeyIdentifier", c: "X.509 extension", w: false },
    "2.5.29.15": { d: "keyUsage", c: "X.509 extension", w: false },
    "2.5.29.16": { d: "privateKeyUsagePeriod", c: "X.509 extension", w: false },
    "2.5.29.17": { d: "subjectAltName", c: "X.509 extension", w: false },
    "2.5.29.18": { d: "issuerAltName", c: "X.509 extension", w: false },
    "2.5.29.19": { d: "basicConstraints", c: "X.509 extension", w: false },
    "2.5.29.20": { d: "cRLNumber", c: "X.509 extension", w: false },
    "2.5.29.21": { d: "cRLReason", c: "X.509 extension", w: false },
    "2.5.29.22": { d: "expirationDate", c: "X.509 extension. Deprecated, alternative OID uncertain", w: true },
    "2.5.29.23": { d: "instructionCode", c: "X.509 extension", w: false },
    "2.5.29.24": { d: "invalidityDate", c: "X.509 extension", w: false },
    "2.5.29.25": { d: "cRLDistributionPoints", c: "X.509 extension. Deprecated, use 2 5 29 31 instead", w: true },
    "2.5.29.26": {
        d: "issuingDistributionPoint",
        c: "X.509 extension. Deprecated, use 2 5 29 28 instead",
        w: true,
    },
    "2.5.29.27": { d: "deltaCRLIndicator", c: "X.509 extension", w: false },
    "2.5.29.28": { d: "issuingDistributionPoint", c: "X.509 extension", w: false },
    "2.5.29.29": { d: "certificateIssuer", c: "X.509 extension", w: false },
    "2.5.29.30": { d: "nameConstraints", c: "X.509 extension", w: false },
    "2.5.29.31": { d: "cRLDistributionPoints", c: "X.509 extension", w: false },
    "2.5.29.32": { d: "certificatePolicies", c: "X.509 extension", w: false },
    "2.5.29.32.0": { d: "anyPolicy", c: "X.509 certificate policy", w: false },
    "2.5.29.33": { d: "policyMappings", c: "X.509 extension", w: false },
    "2.5.29.34": { d: "policyConstraints", c: "X.509 extension. Deprecated, use 2 5 29 36 instead", w: true },
    "2.5.29.35": { d: "authorityKeyIdentifier", c: "X.509 extension", w: false },
    "2.5.29.36": { d: "policyConstraints", c: "X.509 extension", w: false },
    "2.5.29.37": { d: "extKeyUsage", c: "X.509 extension", w: false },
    "2.5.29.37.0": { d: "anyExtendedKeyUsage", c: "X.509 extended key usage", w: false },
    "2.5.29.38": { d: "authorityAttributeIdentifier", c: "X.509 extension", w: false },
    "2.5.29.39": { d: "roleSpecCertIdentifier", c: "X.509 extension", w: false },
    "2.5.29.40": { d: "cRLStreamIdentifier", c: "X.509 extension", w: false },
    "2.5.29.41": { d: "basicAttConstraints", c: "X.509 extension", w: false },
    "2.5.29.42": { d: "delegatedNameConstraints", c: "X.509 extension", w: false },
    "2.5.29.43": { d: "timeSpecification", c: "X.509 extension", w: false },
    "2.5.29.44": { d: "cRLScope", c: "X.509 extension", w: false },
    "2.5.29.45": { d: "statusReferrals", c: "X.509 extension", w: false },
    "2.5.29.46": { d: "freshestCRL", c: "X.509 extension", w: false },
    "2.5.29.47": { d: "orderedList", c: "X.509 extension", w: false },
    "2.5.29.48": { d: "attributeDescriptor", c: "X.509 extension", w: false },
    "2.5.29.49": { d: "userNotice", c: "X.509 extension", w: false },
    "2.5.29.50": { d: "sOAIdentifier", c: "X.509 extension", w: false },
    "2.5.29.51": { d: "baseUpdateTime", c: "X.509 extension", w: false },
    "2.5.29.52": { d: "acceptableCertPolicies", c: "X.509 extension", w: false },
    "2.5.29.53": { d: "deltaInfo", c: "X.509 extension", w: false },
    "2.5.29.54": { d: "inhibitAnyPolicy", c: "X.509 extension", w: false },
    "2.5.29.55": { d: "targetInformation", c: "X.509 extension", w: false },
    "2.5.29.56": { d: "noRevAvail", c: "X.509 extension", w: false },
    "2.5.29.57": { d: "acceptablePrivilegePolicies", c: "X.509 extension", w: false },
    "2.5.29.58": { d: "toBeRevoked", c: "X.509 extension", w: false },
    "2.5.29.59": { d: "revokedGroups", c: "X.509 extension", w: false },
    "2.5.29.60": { d: "expiredCertsOnCRL", c: "X.509 extension", w: false },
    "2.5.29.61": { d: "indirectIssuer", c: "X.509 extension", w: false },
    "2.5.29.62": { d: "noAssertion", c: "X.509 extension", w: false },
    "2.5.29.63": { d: "aAissuingDistributionPoint", c: "X.509 extension", w: false },
    "2.5.29.64": { d: "issuedOnBehalfOf", c: "X.509 extension", w: false },
    "2.5.29.65": { d: "singleUse", c: "X.509 extension", w: false },
    "2.5.29.66": { d: "groupAC", c: "X.509 extension", w: false },
    "2.5.29.67": { d: "allowedAttAss", c: "X.509 extension", w: false },
    "2.5.29.68": { d: "attributeMappings", c: "X.509 extension", w: false },
    "2.5.29.69": { d: "holderNameConstraints", c: "X.509 extension", w: false },

    // Netscape certificate type
    // An X.509 v3 certificate extension used to identify whether
    // the certificate subject is an SSL client, …
    "2.16.840.1.113730.1": { d: "certExtension", c: "Netscape" },
    "2.16.840.1.113730.1.1": { d: "netscapeCertType", c: "Netscape certificate extension" },
    "2.16.840.1.113730.1.2": { d: "netscapeBaseUrl", c: "Netscape certificate extension" },
    "2.16.840.1.113730.1.3": { d: "netscapeRevocationUrl", c: "Netscape certificate extension" },
    "2.16.840.1.113730.1.4": { d: "netscapeCaRevocationUrl", c: "Netscape certificate extension" },
    "2.16.840.1.113730.1.7": { d: "netscapeCertRenewalUrl", c: "Netscape certificate extension" },
    "2.16.840.1.113730.1.8": { d: "netscapeCaPolicyUrl", c: "Netscape certificate extension" },
    "2.16.840.1.113730.1.9": { d: "HomePageUrl", c: "Netscape certificate extension" },
    "2.16.840.1.113730.1.10": { d: "EntityLogo", c: "Netscape certificate extension" },
    "2.16.840.1.113730.1.11": { d: "UserPicture", c: "Netscape certificate extension" },
    "2.16.840.1.113730.1.12": { d: "netscapeSslServerName", c: "Netscape certificate extension" },
    "2.16.840.1.113730.1.13": { d: "netscapeComment", c: "Netscape certificate extension" },

    done: {},
};

export interface BlockInfo {
    tag: TagType;
    position: number;
    length: number;
}

export function readTag(buf: Buffer, pos: number): BlockInfo {
    assert(buf instanceof Buffer);
    assert(_.isNumber(pos) && pos >= 0);
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
    return { tag, position: pos, length };
}

export function _readStruct(buf: Buffer, block_info: BlockInfo): BlockInfo[] {
    const length = block_info.length;
    let cursor = block_info.position;
    const end = block_info.position + length;
    const blocks: BlockInfo[] = [];
    while (cursor < end) {
        const inner = readTag(buf, cursor);
        cursor = inner.position + inner.length;
        blocks.push(inner);
    }
    return blocks;
}

function _getBlock(buffer: Buffer, block: BlockInfo): Buffer {
    const start = block.position;
    const end = block.position + block.length;
    return buffer.slice(start, end);
}

function parseBitString(buffer: Buffer, start: number, end: number, maxLength: number): string {
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

interface BitString {
    lengthInBits: number;
    lengthInBytes: number;
    data: Buffer;
    debug?: any;
}

function _readBitString(buffer: Buffer, block: BlockInfo): BitString {
    assert(block.tag === TagType.BIT_STRING);
    const data = _getBlock(buffer, block);

    // number of skipped bits
    const ignore_bits = data.readUInt8(0);

    return {
        lengthInBits: data.length * 8 - ignore_bits,
        lengthInBytes: data.length - 1,
        data: data.slice(1),
        debug: parseBitString(buffer, block.position, block.length + block.position, 5000),
    };
}

function formatBuffer2DigetHexWithColum(buffer: Buffer): string {
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
function _readOctetString(buffer: Buffer, block: BlockInfo): Buffer {
    assert(block.tag === TagType.OCTET_STRING);
    const tag = readTag(buffer, block.position);
    assert(tag.tag === TagType.OCTET_STRING);

    const nbBytes = tag.length;
    const pos = tag.position;
    const b = buffer.slice(pos, pos + nbBytes);
    return b;
}

export type SignatureValue = string;

export function _readSignatureValueBin(buffer: Buffer, block: BlockInfo): Buffer {
    return _readBitString(buffer, block).data;
}

export function _readSignatureValue(buffer: Buffer, block: BlockInfo): SignatureValue {
    return _readSignatureValueBin(buffer, block).toString("hex");
}

function _readLongIntegerValue(buffer: Buffer, block: BlockInfo): Buffer {
    assert(block.tag === TagType.INTEGER, "expecting a INTEGER tag");
    const pos = block.position;
    const nbBytes = block.length;
    const buf = buffer.slice(pos, pos + nbBytes);
    return buf;
}

function _readIntegerValue(buffer: Buffer, block: BlockInfo): number {
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
function _readBooleanValue(buffer: Buffer, block: BlockInfo): boolean {
    assert(block.tag === TagType.BOOLEAN, "expecting a BOOLEAN tag. got " + TagType[block.tag]);
    const pos = block.position;
    const nbBytes = block.length;
    assert(nbBytes < 4);
    const value = buffer.readUInt8(pos) ? true : false;
    return value as boolean;
}

function _readVersionValue(buffer: Buffer, block: BlockInfo): number {
    block = readTag(buffer, block.position);
    return _readIntegerValue(buffer, block);
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
    const strBuff = _getBlock(buffer, block);
    let str = "";
    for (let i = 0; i < strBuff.length; i += 2) {
        const word = strBuff.readUInt16BE(i);
        str += String.fromCharCode(word);
    }
    return str;
}

function _readValue(buffer: Buffer, block: BlockInfo): any {
    switch (block.tag) {
        case TagType.BOOLEAN:
            return _readBooleanValue(buffer, block);
        case TagType.BMPString:
            return _readBMPString(buffer, block);
        case TagType.PrintableString:
        case TagType.TeletexString:
        case TagType.UTF8String:
        case TagType.NumericString:
        case TagType.IA5String:
            return _getBlock(buffer, block).toString("ascii");
        case TagType.UTCTime:
            return convertUTCTime(_getBlock(buffer, block).toString("ascii"));
        case TagType.GeneralizedTime:
            return convertGeneralizedTime(_getBlock(buffer, block).toString("ascii"));
        default:
            throw new Error("Invalid tag 0x" + block.tag.toString(16) + "");
        //xx return " ??? <" + block.tag + ">";
    }
}

export interface AttributeTypeAndValue {
    [key: string]: any;
}

function parseOID(buffer: Buffer, start: number, end: number) {
    // ASN.1 JavaScript decoder
    // Copyright (c) 2008-2014 Lapo Luchini <lapo@lapo.it>
    let s = "",
        n = 0,
        bits = 0;
    for (let i = start; i < end; ++i) {
        const v = buffer.readUInt8(i);

        n = n * 128 + (v & 0x7f);
        bits += 7;

        // noinspection JSBitwiseOperatorUsage
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

function _readObjectIdentifier(buffer: Buffer, block: BlockInfo) {
    assert(block.tag === TagType.OBJECT_IDENTIFIER);
    const b = buffer.slice(block.position, block.position + block.length);
    const oid = parseOID(b, 0, block.length);
    return {
        oid,
        name: oid_map[oid] ? oid_map[oid].d : oid,
    };
}

function _readAttributeTypeAndValue(buffer: Buffer, block: BlockInfo): AttributeTypeAndValue {
    let inner_blocks = _readStruct(buffer, block);
    inner_blocks = _readStruct(buffer, inner_blocks[0]);

    const data = {
        identifier: _readObjectIdentifier(buffer, inner_blocks[0]).name,
        value: _readValue(buffer, inner_blocks[1]),
    };

    const result: AttributeTypeAndValue = {};
    _.forEach(data, (value, key) => {
        result[key] = value;
    });
    return result;
}

interface RelativeDistinguishedName {
    [prop: string]: any;
}

function _readRelativeDistinguishedName(buffer: Buffer, block: BlockInfo): RelativeDistinguishedName {
    const inner_blocks = _readStruct(buffer, block);
    const data = inner_blocks.map((block) => _readAttributeTypeAndValue(buffer, block));
    const result: any = {};
    _.forEach(data, (e) => {
        result[e.identifier] = e.value;
    });
    return result;
}

function _readName(buffer: Buffer, block: BlockInfo): RelativeDistinguishedName {
    return _readRelativeDistinguishedName(buffer, block);
}

function _readTime(buffer: Buffer, block: BlockInfo) {
    return _readValue(buffer, block);
}

export interface Validity {
    notBefore: Date;
    notAfter: Date;
}

function _readValidity(buffer: Buffer, block: BlockInfo): Validity {
    const inner_blocks = _readStruct(buffer, block);
    return {
        notBefore: _readTime(buffer, inner_blocks[0]),
        notAfter: _readTime(buffer, inner_blocks[1]),
    };
}

function _findBlockAtIndex(blocks: BlockInfo[], index: number): BlockInfo | null {
    const tmp = blocks.filter((b: BlockInfo) => b.tag === 0xa0 + index || b.tag === 0x80 + index);
    if (tmp.length === 0) {
        return null;
    }
    return tmp[0];
}

function _readAuthorityKeyIdentifier(buffer: Buffer): AuthorithyKeyIdentifier {
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
    const blocks = _readStruct(buffer, block_info);

    const keyIdentifier_block = _findBlockAtIndex(blocks, 0);
    const authorityCertIssuer_block = _findBlockAtIndex(blocks, 1);
    const authorityCertSerialNumber_block = _findBlockAtIndex(blocks, 2);
    function readNames(buffer: Buffer, block: BlockInfo): DirectoryName {
        // AttributeTypeAndValue ::= SEQUENCE {
        //    type   ATTRIBUTE.&id({SupportedAttributes}),
        //    value  ATTRIBUTE.&Type({SupportedAttributes}{@type}),
        const inner_blocks = _readStruct(buffer, block);
        const names: DirectoryName = {};
        inner_blocks.forEach((sequence_block) => {
            assert(sequence_block.tag === 0x30);
            const set_blocks = _readStruct(buffer, sequence_block);
            set_blocks.forEach((set_block) => {
                assert(set_block.tag === 0x31);
                const blocks = _readStruct(buffer, set_block);
                assert(blocks.length === 1);
                assert(blocks[0].tag === 0x30);

                const _blocks = _readStruct(buffer, blocks[0]);
                assert(_blocks.length === 2);

                const type = _readObjectIdentifier(buffer, _blocks[0]);

                (names as any)[type.name] = _readValue(buffer, _blocks[1]);
            });
        });
        return names;
    }

    function _readAuthorithyCertIssuer(block: BlockInfo): DirectoryName {
        const inner_blocks = _readStruct(buffer, block);

        const directoryName_block = _findBlockAtIndex(inner_blocks, 4);
        if (directoryName_block) {
            return readNames(buffer, directoryName_block);
        } else {
            throw new Error("Invalid _readAuthorithyCertIssuer");
        }
    }

    return {
        authorityCertIssuer: authorityCertIssuer_block ? _readAuthorithyCertIssuer(authorityCertIssuer_block) : null,
        serial: authorityCertSerialNumber_block
            ? formatBuffer2DigetHexWithColum(_getBlock(buffer, authorityCertSerialNumber_block!))
            : null, // can be null for self-signed certf
        keyIdentifier: keyIdentifier_block ? formatBuffer2DigetHexWithColum(_getBlock(buffer, keyIdentifier_block!)) : null, // can be null for self-signed certf
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

function readBasicConstraint2_5_29_19(buffer: Buffer, block: BlockInfo): BasicConstraints {
    const block_info = readTag(buffer, 0);
    const inner_blocks = _readStruct(buffer, block_info);
    const cA = inner_blocks.length > 0 ? _readBooleanValue(buffer, inner_blocks[0]) : false;

    //    console.log("buffer[block_info.position] = ", buffer[block_info.position]);
    // const cA = buffer[block_info.position] ? true : false;

    let pathLengthConstraint = 0;
    if (inner_blocks.length > 1) {
        pathLengthConstraint = _readIntegerValue(buffer, inner_blocks[1]);
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
    };
    const blocks = _readStruct(buffer, block);

    function _readFromType(buffer: Buffer, block: BlockInfo, type: string) {
        switch (type) {
            case "IA5String":
                return buffer.slice(block.position, block.position + block.length).toString("ascii");
            default:
                return buffer.slice(block.position, block.position + block.length).toString("hex");
        }
    }

    const n: { [key: string]: string[] } = {};
    for (const block of blocks) {
        assert((block.tag & 0x80) === 0x80);
        const t = block.tag & 0x7f;
        const type = _data[t] as { name: string; type: string } | undefined;

        // istanbul ignore next
        if (!type) {
            throw new Error(" INVALID TYPE => " + t + "0x" + t.toString(16));
        }
        n[type.name] = n[type.name] || [];
        n[type.name].push(_readFromType(buffer, block, type.type));
    }
    return n;
}

function _readSubjectAltNames(buffer: Buffer) {
    const block_info = readTag(buffer, 0);
    return _readGeneralNames(buffer, block_info);
}

export interface KeyUsage {
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
export interface ExtKeyUsage {
    clientAuth: boolean;
    serverAuth: boolean;
    codeSigning: boolean;
    emailProtection: boolean;
    timeStamping: boolean;
    // etc ... to be completed
}

function readKeyUsage(oid: string, buffer: Buffer): KeyUsage {
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

function readExtKeyUsage(oid: string, buffer: Buffer): string {
    return "readExtKeyUsage " + oid + "  " + buffer.toString("hex");
    /*    // handle extKeyUsage
        // value is a SEQUENCE of OIDs
        var ev = asn1.fromDer(e.value);
        for (var vi = 0; vi < ev.value.length; ++vi) {
            var oid = asn1.derToOid(ev.value[vi].value);
            if (oid in oids) {
                e[oids[oid]] = true;
            } else {
                e[oid] = true;
            }
        }
        */
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
function _readExtension(buffer: Buffer, block: BlockInfo) {
    const inner_blocks = _readStruct(buffer, block);

    if (inner_blocks.length === 3) {
        assert(inner_blocks[1].tag === TagType.BOOLEAN);
        inner_blocks[1] = inner_blocks[2];
    }

    const identifier = _readObjectIdentifier(buffer, inner_blocks[0]);
    const buf = _getBlock(buffer, inner_blocks[1]);
    let value = null;
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
            value = formatBuffer2DigetHexWithColum(_readOctetString(buffer, inner_blocks[1]));
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
            value = "basicConstraints ( not implemented yet) " + buf.toString("hex");
            break;
        case "extKeyUsage":
            value = readExtKeyUsage(identifier.oid, buf);
            break;
        case "keyUsage":
            value = readKeyUsage(identifier.oid, buf);
            break;
        default:
            value = "Unknown " + identifier.name + buf.toString("hex");
    }
    return {
        identifier,
        value,
    };
}

// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
function _readExtensions(buffer: Buffer, block: BlockInfo): CertificateExtension {
    assert(block.tag === 0xa3);

    let inner_blocks = _readStruct(buffer, block);
    inner_blocks = _readStruct(buffer, inner_blocks[0]);

    const exts = inner_blocks.map((block) => _readExtension(buffer, block));

    const result: any = {};
    _.forEach(exts, (e) => (result[e.identifier.name] = e.value));
    return result as CertificateExtension;
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
function _readIntegerAsByteString(buffer: Buffer, block: BlockInfo) {
    return _getBlock(buffer, block);
}

function _readListOfInteger(buffer: Buffer) {
    const block = readTag(buffer, 0);
    const inner_blocks = _readStruct(buffer, block);

    return inner_blocks.map((block) => {
        return _readIntegerAsByteString(buffer, block);
    });
}

export interface AlgorithmIdentifier {
    identifier: string;
}

export function _readAlgorithmIdentifier(buffer: Buffer, block: BlockInfo): AlgorithmIdentifier {
    const inner_blocks = _readStruct(buffer, block);
    return {
        identifier: _readObjectIdentifier(buffer, inner_blocks[0]).name,
    };
}

function _readSubjectPublicKeyInfo(buffer: Buffer, block: BlockInfo): SubjectPublicKeyInfo {
    const inner_blocks = _readStruct(buffer, block);

    // algorithm identifier
    const algorithm = _readAlgorithmIdentifier(buffer, inner_blocks[0]);
    //const parameters         = _readBitString(buffer,inner_blocks[1]);
    const subjectPublicKey = _readBitString(buffer, inner_blocks[1]);

    // read the 2 big integers of the key
    const data = subjectPublicKey.data;
    const values = _readListOfInteger(data);
    // xx const value = _readListOfInteger(data);
    return {
        algorithm: algorithm.identifier,
        keyLength: (values[0].length - 1) as PublicKeyLength,
        subjectPublicKey: subjectPublicKey.data,
        //xx values: values,
        //xx values_length : values.map(function (a){ return a.length; })
    };
}

export interface SubjectPublicKeyInfo {
    algorithm: string;
    keyLength: PublicKeyLength;
    subjectPublicKey: Buffer;
}

export interface DirectoryName {
    stateOrProvinceName?: string;
    localityName?: string;
    organizationName?: string;
    organizationUnitName?: string;
    commonName?: string;
    countryName?: string;
}
export interface BasicConstraints {
    critical: boolean;
    cA: boolean;
    pathLengthConstraint?: number; // 0 Unlimited
}

export interface AuthorithyKeyIdentifier {
    keyIdentifier: string | null;
    authorityCertIssuer: DirectoryName | null;
    serial: string | null;
}

export interface CertificateExtension {
    basicConstraints: BasicConstraints;
    subjectKeyIdentifier?: string;
    authorityKeyIdentifier?: AuthorithyKeyIdentifier;
    keyUsage?: KeyUsage;
    extKeyUsage?: KeyUsage;
    subjectAltName?: any;
}

export interface TbsCertificate {
    version: number;
    serialNumber: string;
    issuer: any;
    signature: AlgorithmIdentifier;
    validity: Validity;
    subject: DirectoryName;
    subjectPublicKeyInfo: SubjectPublicKeyInfo;
    extensions: CertificateExtension | null;
}

function readTbsCertificate(buffer: Buffer, block: BlockInfo): TbsCertificate {
    const blocks = _readStruct(buffer, block);

    let version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, extensions;

    if (blocks.length === 6) {
        // X509 Version 1:
        version = 1;

        serialNumber = formatBuffer2DigetHexWithColum(_readLongIntegerValue(buffer, blocks[0]));
        signature = _readAlgorithmIdentifier(buffer, blocks[1]);
        issuer = _readName(buffer, blocks[2]);
        validity = _readValidity(buffer, blocks[3]);
        subject = _readName(buffer, blocks[4]);
        subjectPublicKeyInfo = _readSubjectPublicKeyInfo(buffer, blocks[5]);

        extensions = null;
    } else {
        // X509 Version 3:

        const version_block = _findBlockAtIndex(blocks, 0);
        if (!version_block) {
            throw new Error("cannot find version block");
        }
        version = _readVersionValue(buffer, version_block) + 1;
        serialNumber = formatBuffer2DigetHexWithColum(_readLongIntegerValue(buffer, blocks[1]));
        signature = _readAlgorithmIdentifier(buffer, blocks[2]);
        issuer = _readName(buffer, blocks[3]);
        validity = _readValidity(buffer, blocks[4]);
        subject = _readName(buffer, blocks[5]);
        subjectPublicKeyInfo = _readSubjectPublicKeyInfo(buffer, blocks[6]);

        const extensionBlock = _findBlockAtIndex(blocks, 3);
        if (!extensionBlock) {
            throw new Error("cannot find extention block");
        }
        extensions = _readExtensions(buffer, extensionBlock);
    }

    return {
        version,
        serialNumber,
        signature,
        issuer,
        validity,
        subject,
        subjectPublicKeyInfo,
        extensions,
    };
}
export interface CertificateInternals {
    tbsCertificate: TbsCertificate;
    signatureAlgorithm: AlgorithmIdentifier;
    signatureValue: SignatureValue;
}

/**
 * explore a certificate structure
 * @param certificate
 * @returns a json object that exhibits the internal data of the certificate
 */
export function exploreCertificate(certificate: Certificate): CertificateInternals {
    assert(certificate instanceof Buffer);
    if (!(certificate as any)._exploreCertificate_cache) {
        const block_info = readTag(certificate, 0);
        const blocks = _readStruct(certificate, block_info);
        (certificate as any)._exploreCertificate_cache = {
            tbsCertificate: readTbsCertificate(certificate, blocks[0]),
            signatureAlgorithm: _readAlgorithmIdentifier(certificate, blocks[1]),
            signatureValue: _readSignatureValue(certificate, blocks[2]),
        };
    }
    return (certificate as any)._exploreCertificate_cache;
}

// tslint:disable:no-empty-interface
export interface PrivateKeyInternals {
    /**/
}

export function explorePrivateKey(privateKey: PrivateKey): PrivateKeyInternals {
    assert(privateKey instanceof Buffer);
    const block_info = readTag(privateKey, 0);
    const blocks = _readStruct(privateKey, block_info);

    /* istanbul ignore next */
    if (doDebug) {
        // tslint:disable:no-console
        console.log(block_info);

        // tslint:disable:no-console
        console.log(
            blocks.map((b) => ({
                tag: TagType[b.tag] + " 0x" + b.tag.toString(16),
                l: b.length,
                p: b.position,
                buff: privateKey.slice(b.position, b.position + b.length).toString("hex"),
            }))
        );
    }

    const b = blocks[2];
    const bb = privateKey.slice(b.position, b.position + b.length);
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
                buff: privateKey.slice(b.position, b.position + b.length).toString("hex"),
            }))
        );
    }

    return {};
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
        const der_certificate = certificateChain.slice(0, length);
        certificate_chain.push(der_certificate);
        certificateChain = certificateChain.slice(length);
    } while (certificateChain.length > 0);
    return certificate_chain;
}

/**
 * @method combine_der
 * combine an array of certificates into a single blob
 * @param certificates a array with the individual DER certificates of the chain
 * @return a concatenated buffer containing the certificates
 */
export function combine_der(certificates: Certificate[]): Certificate {
    assert(_.isArray(certificates));

    // perform some sanity check
    for (const cert of certificates) {
        const b = split_der(cert);
        let sum = 0;
        b.forEach((block) => {
            const block_info = readTag(block, 0);
            //xx console.log("xxxx" ,cert.length,block_info);
            //xx console.log(cert.toString("base64"));
            assert(block_info.position + block_info.length === block.length);
            sum += block.length;
        });
        assert(sum === cert.length);
    }
    return Buffer.concat(certificates);
}
