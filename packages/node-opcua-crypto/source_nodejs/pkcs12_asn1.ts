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

// ASN.1 schema pieces RFC 7292 (PKCS#12) needs that aren't provided by the
// installed @peculiar/asn1-* packages: the CMS `EncryptedData` SEQUENCE (only
// its narrower, unrelated OCTET-STRING-typed namesake inside
// EncryptedPrivateKeyInfo exists upstream), the RFC 8018 PBES2/PBKDF2
// AlgorithmIdentifier parameter structures, and the PKCS#12 `CertBag`.
//
// Note on style: `AsnProp` is applied as a plain function call after each
// class, not `@AsnProp(...)` decorator syntax. It's a legacy-style
// (experimentalDecorators) decorator factory, and this project compiles
// with TypeScript's standard (TC39) decorators instead — the two have
// incompatible call signatures. Calling the factory directly sidesteps
// that without touching the project's shared compiler options; every
// @peculiar/asn1-* schema class works this way under the hood too, just
// pre-compiled.
//
// Verified by round-tripping real OpenSSL-generated .pfx fixtures through
// this exact schema set — see the "PKCS#12" tests in
// packages/node-opcua-crypto-test/test/test_pkcs12.ts.

import { EncryptedContentInfo } from "@peculiar/asn1-cms";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";

/**
 * CMS `EncryptedData ::= SEQUENCE { version CMSVersion, encryptedContentInfo
 * EncryptedContentInfo, unprotectedAttrs ... OPTIONAL }` (RFC 5652 §8).
 *
 * `unprotectedAttrs` is omitted: OpenSSL-generated PFX files don't set it,
 * and this codebase never writes one either.
 */
export class CmsEncryptedData {
    public version = 0;
    public encryptedContentInfo!: EncryptedContentInfo;

    constructor(params?: Partial<CmsEncryptedData>) {
        Object.assign(this, params);
    }
}
AsnProp({ type: AsnPropTypes.Integer })(CmsEncryptedData.prototype, "version");
AsnProp({ type: EncryptedContentInfo })(CmsEncryptedData.prototype, "encryptedContentInfo");

/**
 * RFC 8018 `PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount
 * INTEGER, keyLength INTEGER OPTIONAL, prf AlgorithmIdentifier DEFAULT
 * hmacWithSHA1 }`.
 *
 * The `salt` field is technically a CHOICE of `OCTET STRING` or an
 * `AlgorithmIdentifier` (for a non-standard salt source) — only the
 * `OCTET STRING` form is modeled, since that's the only one any real-world
 * PKCS#12 tooling (OpenSSL, Windows, Java) actually produces.
 */
export class Pbkdf2Params {
    public salt!: ArrayBuffer;
    public iterationCount!: number;
    public keyLength?: number;
    public prf?: AlgorithmIdentifier;

    constructor(params?: Partial<Pbkdf2Params>) {
        Object.assign(this, params);
    }
}
AsnProp({ type: AsnPropTypes.OctetString })(Pbkdf2Params.prototype, "salt");
AsnProp({ type: AsnPropTypes.Integer })(Pbkdf2Params.prototype, "iterationCount");
AsnProp({ type: AsnPropTypes.Integer, optional: true })(Pbkdf2Params.prototype, "keyLength");
AsnProp({ type: AlgorithmIdentifier, optional: true })(Pbkdf2Params.prototype, "prf");

/**
 * RFC 8018 `PBES2-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier,
 * encryptionScheme AlgorithmIdentifier }`.
 */
export class Pbes2Params {
    public keyDerivationFunc!: AlgorithmIdentifier;
    public encryptionScheme!: AlgorithmIdentifier;

    constructor(params?: Partial<Pbes2Params>) {
        Object.assign(this, params);
    }
}
AsnProp({ type: AlgorithmIdentifier })(Pbes2Params.prototype, "keyDerivationFunc");
AsnProp({ type: AlgorithmIdentifier })(Pbes2Params.prototype, "encryptionScheme");

/**
 * RFC 7292 §4.2.3 `CertBag ::= SEQUENCE { certId BAG-TYPE.&id, certValue [0]
 * EXPLICIT BAG-TYPE.&Type }`. Only the `x509Certificate` bag type
 * (`certId = 1.2.840.113549.1.9.22.1`, `certValue` = DER-encoded X.509
 * certificate wrapped in an `OCTET STRING`) is modeled — that's the only
 * one this codebase reads or writes.
 */
export class CertBag {
    public certId!: string;
    public certValue!: ArrayBuffer;

    constructor(params?: Partial<CertBag>) {
        Object.assign(this, params);
    }
}
AsnProp({ type: AsnPropTypes.ObjectIdentifier })(CertBag.prototype, "certId");
AsnProp({ type: AsnPropTypes.OctetString, context: 0 })(CertBag.prototype, "certValue");

export const OID_PKCS7_DATA = "1.2.840.113549.1.7.1";
export const OID_PKCS7_ENCRYPTED_DATA = "1.2.840.113549.1.7.6";

export const OID_PBES2 = "1.2.840.113549.1.5.13";
export const OID_PBKDF2 = "1.2.840.113549.1.5.12";
export const OID_AES256_CBC = "2.16.840.1.101.3.4.1.42";

export const OID_HMAC_SHA1 = "1.2.840.113549.2.7";
export const OID_HMAC_SHA256 = "1.2.840.113549.2.9";

export const OID_SHA1 = "1.3.14.3.2.26";
export const OID_SHA256 = "2.16.840.1.101.3.4.2.1";

// SafeBag.bagId values (RFC 7292 §4.2, the `bagtypes` arc {pkcs-12 10 1}):
// these identify what kind of bag a SafeBag *is*.
export const OID_KEY_BAG = "1.2.840.113549.1.12.10.1.1";
export const OID_PKCS8_SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2";
export const OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3";

// CertBag.certId value (RFC 7292 §4.2.3, the `certTypes` arc {pkcs-9 22}):
// this identifies what kind of certificate a CertBag's certValue *is*, one
// level deeper than bagId — not to be confused with OID_CERT_BAG above.
export const OID_X509_CERTIFICATE = "1.2.840.113549.1.9.22.1";

export const OID_FRIENDLY_NAME = "1.2.840.113549.1.9.20";
export const OID_LOCAL_KEY_ID = "1.2.840.113549.1.9.21";
