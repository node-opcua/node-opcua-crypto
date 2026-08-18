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

// Native PKCS#12 (PFX, RFC 7292) support — create and parse a certificate +
// private key bundle without shelling out to the openssl CLI.
//
// Reading: any bag type is accepted from any SafeContents envelope (RFC
// 7292 does not tie bag types to envelopes), both DER and BER (constructed
// OCTET STRING) encodings are handled, and the leaf certificate is paired
// to the key through the `localKeyId` attribute rather than by bag order.
// The key bag is handed straight to Node's `crypto.createPrivateKey`, which
// natively decrypts a PKCS#8 EncryptedPrivateKeyInfo under both the modern
// PBES2/AES scheme and the legacy PBE-SHA1-3DES scheme. Only the CMS
// `EncryptedData` around the *certificate* SafeContents needs the hand-rolled
// PBES2 path (Node has no PKCS#7 EncryptedData decryptor); a legacy RC2-40
// certificate safe surfaces as Pkcs12UnsupportedAlgorithmError, never as a
// silent wrong answer.
//
// Writing: the profile OpenSSL 3.x itself defaults to — PBES2 +
// PBKDF2(HMAC-SHA256) + AES-256-CBC for both bags, and the RFC 7292
// Appendix B MAC-key KDF parameterized with SHA-256.
//
// Verified against real OpenSSL-3.5.4-generated .pfx fixtures — see
// packages/node-opcua-crypto-test/test/test_pkcs12.ts.

import { randomBytes, timingSafeEqual } from "node:crypto";
import { ContentInfo, EncryptedContent, EncryptedContentInfo } from "@peculiar/asn1-cms";
import { AuthenticatedSafe, MacData, PFX, PKCS12Attribute, SafeBag, SafeContents } from "@peculiar/asn1-pfx";
import { EncryptedPrivateKeyInfo } from "@peculiar/asn1-pkcs8";
import { FriendlyName, id_pkcs9_at_friendlyName, id_pkcs9_at_localKeyId, LocalKeyId } from "@peculiar/asn1-pkcs9";
import { DigestInfo } from "@peculiar/asn1-rsa";
import { AsnConvert, AsnNullConverter, OctetString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import * as asn1js from "asn1js";

import type { Certificate, PrivateKey } from "../source/common.js";
import {
    createPrivateKeyFromNodeJSCrypto,
    PfxIntegrityError,
    PfxMalformedError,
    Pkcs12UnsupportedAlgorithmError,
} from "../source/common.js";
import { getCrypto } from "../source/x509/_crypto.js";
import {
    CertBag,
    CmsEncryptedData,
    OID_CERT_BAG,
    OID_KEY_BAG,
    OID_PKCS7_DATA,
    OID_PKCS7_ENCRYPTED_DATA,
    OID_PKCS8_SHROUDED_KEY_BAG,
    OID_SHA1,
    OID_SHA256,
    OID_X509_CERTIFICATE,
} from "./pkcs12_asn1.js";
import { assertWellFormedUtf16, hashOutputBytes, type Pkcs12KdfHash, pkcs12Kdf } from "./pkcs12_kdf.js";
import { decryptPbes2, encryptPbes2 } from "./pkcs12_pbes2.js";
import { _toExportableKeyObject } from "./write.js";

const DEFAULT_ITERATIONS = 2048; // matches OpenSSL's own default

export interface CreatePfxOptions {
    certificate: Certificate;
    /** Issuer/CA chain to embed alongside the certificate, if any. */
    certificateChain?: Certificate[];
    privateKey: PrivateKey;
    /** Pass "" explicitly for an unprotected bundle — never silently default to unprotected. */
    password: string;
    /**
     * Cosmetic label attached to both the leaf certificate bag and the key
     * bag (as OpenSSL's `-name` does), so tools that display it — the
     * Windows certificate store reads it from the *certificate* bag,
     * keytool from the key bag — all see it.
     */
    friendlyName?: string;
}

/**
 * `@peculiar/asn1-pfx`'s `PKCS12Attribute` constructor has a bug that is
 * still present in 2.9.0 (`constructor(params = {}) { Object.assign(params); }`
 * — missing `this` as the assignment target), so passing `{ attrId,
 * attrValues }` to `new PKCS12Attribute(...)` silently no-ops. Work around it
 * by constructing with no arguments and assigning the (correctly
 * `@AsnProp`-decorated) fields directly. This form keeps working if/when
 * upstream fixes the constructor.
 */
function makePkcs12Attribute(attrId: string, ...attrValues: ArrayBuffer[]): PKCS12Attribute {
    const attr = new PKCS12Attribute();
    attr.attrId = attrId;
    attr.attrValues = attrValues;
    return attr;
}

/**
 * Unwrap the DER of an OCTET STRING, correctly for BOTH encodings: the
 * DER-primitive form OpenSSL emits *and* the BER-constructed (chunked,
 * indefinite-length) form that BouncyCastle Java/.NET `Pkcs12Store.Save`
 * emits by default. `asn1js` only fills `valueBlock.valueHex` for the
 * primitive form; `getValue()` concatenates the chunks in the constructed
 * form and is identical to `valueHex` for the primitive one, so it is the
 * one correct accessor for both. (`AsnConvert.parse(..., OctetString)`
 * reads `valueHex` and therefore returns an EMPTY buffer for constructed
 * input — the origin of a false "wrong password" on valid BER files.)
 */
function unwrapOctetString(der: ArrayBuffer): ArrayBuffer {
    const { result, offset } = asn1js.fromBER(der);
    if (offset === -1 || !(result instanceof asn1js.OctetString)) {
        throw new PfxMalformedError("Expected an OCTET STRING");
    }
    return result.getValue();
}

/** The `EncryptedContent` CHOICE: primitive `value`, or BER-constructed `constructedValue` chunks. */
function encryptedContentBytes(content: EncryptedContent | undefined): ArrayBuffer | undefined {
    if (!content) {
        return undefined;
    }
    if (content.value) {
        return content.value.buffer;
    }
    if (content.constructedValue && content.constructedValue.length > 0) {
        const total = content.constructedValue.reduce((n, chunk) => n + chunk.byteLength, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const chunk of content.constructedValue) {
            out.set(new Uint8Array(chunk.buffer), offset);
            offset += chunk.byteLength;
        }
        return out.buffer;
    }
    return undefined;
}

function toArrayBuffer(buf: Buffer): ArrayBuffer {
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/**
 * Create a PFX (PKCS#12) bundle containing a certificate (+ optional issuer
 * chain) and its matching private key, encrypted with `password`.
 */
export async function createPfx(options: CreatePfxOptions): Promise<Buffer> {
    assertWellFormedUtf16(options.password, "password");
    if (options.friendlyName !== undefined) {
        assertWellFormedUtf16(options.friendlyName, "friendlyName");
    }
    const subtle = getCrypto().subtle as unknown as SubtleCrypto;

    // localKeyId pairs the leaf certificate with its key; friendlyName goes
    // on BOTH the leaf cert bag and the key bag, matching OpenSSL `-name`.
    const localKeyId = AsnConvert.serialize(new LocalKeyId(new Uint8Array(randomBytes(20))));
    const localKeyIdAttr = makePkcs12Attribute(id_pkcs9_at_localKeyId, localKeyId);
    const friendlyNameAttr =
        options.friendlyName !== undefined
            ? makePkcs12Attribute(id_pkcs9_at_friendlyName, AsnConvert.serialize(new FriendlyName(options.friendlyName)))
            : undefined;
    const leafAttributes = friendlyNameAttr ? [localKeyIdAttr, friendlyNameAttr] : [localKeyIdAttr];

    // ── cert bag(s): leaf first, then chain ──
    const certificates = [options.certificate, ...(options.certificateChain ?? [])];
    const certSafeBags = certificates.map(
        (der, index) =>
            new SafeBag({
                bagId: OID_CERT_BAG,
                bagValue: AsnConvert.serialize(new CertBag({ certId: OID_X509_CERTIFICATE, certValue: toArrayBuffer(der) })),
                bagAttributes: index === 0 ? leafAttributes : undefined,
            }),
    );
    const certSafeContentsDer = AsnConvert.serialize(new SafeContents(certSafeBags));
    const { encryptedContent: certEncryptedContent, algorithmIdentifier: certAlgId } = await encryptPbes2(
        subtle,
        certSafeContentsDer,
        options.password,
        DEFAULT_ITERATIONS,
    );
    const certContentInfo = new ContentInfo({
        contentType: OID_PKCS7_ENCRYPTED_DATA,
        content: AsnConvert.serialize(
            new CmsEncryptedData({
                version: 0,
                encryptedContentInfo: new EncryptedContentInfo({
                    contentType: OID_PKCS7_DATA,
                    contentEncryptionAlgorithm: certAlgId,
                    encryptedContent: new EncryptedContent({ value: new OctetString(certEncryptedContent) }),
                }),
            }),
        ),
    });

    // ── key bag: a PKCS#8 EncryptedPrivateKeyInfo, produced by Node itself ──
    // Node's KeyObject.export({cipher, passphrase}) emits exactly the PBES2 /
    // PBKDF2 / AES-256-CBC EncryptedPrivateKeyInfo a shrouded key bag holds
    // (the same call shape write.ts uses for PEM), so there is nothing to
    // hand-roll here — and it is what createPrivateKey reads back natively.
    const keyObject = _toExportableKeyObject(options.privateKey);
    const shroudedKeyDer = keyObject.export({
        type: "pkcs8",
        format: "der",
        cipher: "aes-256-cbc",
        passphrase: options.password,
    }) as Buffer;
    // Sanity: it must parse as an EncryptedPrivateKeyInfo, i.e. what a shrouded bag holds.
    AsnConvert.parse(toArrayBuffer(shroudedKeyDer), EncryptedPrivateKeyInfo);
    const keySafeBag = new SafeBag({
        bagId: OID_PKCS8_SHROUDED_KEY_BAG,
        bagValue: toArrayBuffer(shroudedKeyDer),
        bagAttributes: leafAttributes,
    });
    const keySafeContentsDer = AsnConvert.serialize(new SafeContents([keySafeBag]));
    const keyContentInfo = new ContentInfo({
        contentType: OID_PKCS7_DATA,
        content: AsnConvert.serialize(new OctetString(keySafeContentsDer)),
    });

    // ── authSafe ──
    const authenticatedSafeDer = AsnConvert.serialize(new AuthenticatedSafe([certContentInfo, keyContentInfo]));
    const authSafeContentInfo = new ContentInfo({
        contentType: OID_PKCS7_DATA,
        content: AsnConvert.serialize(new OctetString(authenticatedSafeDer)),
    });

    // ── MacData (integrity) ──
    const macSalt = new Uint8Array(randomBytes(20));
    const macKey = pkcs12Kdf("SHA-256", options.password, macSalt, DEFAULT_ITERATIONS, 3);
    const hmacKey = await subtle.importKey("raw", macKey as unknown as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, [
        "sign",
    ]);
    const macDigest = new Uint8Array(await subtle.sign("HMAC", hmacKey, authenticatedSafeDer));
    const macData = new MacData({
        mac: new DigestInfo({
            digestAlgorithm: new AlgorithmIdentifier({ algorithm: OID_SHA256, parameters: AsnNullConverter.toASN(null).toBER() }),
            digest: new OctetString(macDigest),
        }),
        macSalt: new OctetString(macSalt),
        iterations: DEFAULT_ITERATIONS,
    });

    const pfx = new PFX({ version: 3, authSafe: authSafeContentInfo, macData });
    return Buffer.from(AsnConvert.serialize(pfx));
}

export interface ParsedPfx {
    certificate: Certificate;
    certificateChain: Certificate[];
    privateKey: PrivateKey;
    /**
     * The `friendlyName` attribute carried by the leaf certificate bag, if
     * any — the label the Windows certificate store and similar tools show
     * for this identity. `undefined` when the file has none.
     */
    friendlyName?: string;
}

interface CollectedCert {
    der: Certificate;
    localKeyId?: string; // hex, when the bag carries one
    friendlyName?: string;
}
interface CollectedKey {
    key: PrivateKey;
    localKeyId?: string;
}

/** Return the hex of a bag's `localKeyId` attribute, if it has one. */
function bagLocalKeyId(bag: SafeBag): string | undefined {
    const attr = bag.bagAttributes?.find((a) => a.attrId === id_pkcs9_at_localKeyId);
    const value = attr?.attrValues[0];
    if (!value) {
        return undefined;
    }
    try {
        return Buffer.from(AsnConvert.parse(value, LocalKeyId).buffer).toString("hex");
    } catch {
        return undefined; // malformed attribute: treat as absent rather than failing the whole parse
    }
}

/** Return a bag's `friendlyName` attribute, if it has one. */
function bagFriendlyName(bag: SafeBag): string | undefined {
    const attr = bag.bagAttributes?.find((a) => a.attrId === id_pkcs9_at_friendlyName);
    const value = attr?.attrValues[0];
    if (!value) {
        return undefined;
    }
    try {
        return AsnConvert.parse(value, FriendlyName).value;
    } catch {
        return undefined;
    }
}

function macHash(digestOid: string): Pkcs12KdfHash {
    if (digestOid === OID_SHA256) {
        return "SHA-256";
    }
    if (digestOid === OID_SHA1) {
        return "SHA-1";
    }
    throw new Pkcs12UnsupportedAlgorithmError(`Unsupported MacData digest algorithm: ${digestOid}`);
}

/**
 * Decrypt a shrouded key bag with Node's own PKCS#8 decryptor. Handles the
 * modern PBES2/AES scheme and the legacy PBE-SHA1-3DES scheme natively.
 * `passphrase` must be `""` (not `undefined`) for an empty password — Node
 * treats `undefined` as "no passphrase supplied" and raises
 * ERR_MISSING_PASSPHRASE even on an empty-password bag.
 */
function decryptShroudedKeyBag(bagValue: ArrayBuffer, password: string): PrivateKey {
    try {
        const hidden = createPrivateKeyFromNodeJSCrypto({
            key: Buffer.from(bagValue),
            format: "der",
            type: "pkcs8",
            passphrase: password,
        });
        return { hidden } as unknown as PrivateKey;
    } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === "ERR_OSSL_BAD_DECRYPT" || code === "ERR_MISSING_PASSPHRASE") {
            throw new PfxIntegrityError();
        }
        // e.g. an EncryptedPrivateKeyInfo under a PBE scheme this OpenSSL build
        // does not provide (RC2 needs the legacy provider), or a truly malformed key
        throw new Pkcs12UnsupportedAlgorithmError(`Cannot decrypt shrouded key bag: ${(err as Error).message}`);
    }
}

/**
 * Parse and decrypt a PFX (PKCS#12) bundle. Verifies the bundle's
 * `MacData` integrity check before returning (skipped, with no error, if
 * the file has no `MacData` at all — rare, but valid per RFC 7292).
 *
 * The leaf certificate is the one whose `localKeyId` attribute matches the
 * private key's; when the file carries no `localKeyId`s (some producers
 * omit them) it falls back to the first certificate encountered. Every
 * other certificate is returned in `certificateChain`, in file order.
 *
 * Throws {@link PfxIntegrityError} on a wrong password or a
 * corrupted/tampered file, {@link PfxMalformedError} if the (correctly
 * decrypted) bundle holds no private key or no certificate, and
 * {@link Pkcs12UnsupportedAlgorithmError} if the file uses an algorithm this
 * build cannot handle (e.g. a legacy RC2-40 certificate safe).
 */
export async function parsePfx(pfx: Buffer, password: string): Promise<ParsedPfx> {
    assertWellFormedUtf16(password, "password");
    const subtle = getCrypto().subtle as unknown as SubtleCrypto;

    const parsed = AsnConvert.parse(pfx, PFX);
    const authenticatedSafeDer = unwrapOctetString(parsed.authSafe.content);

    // `@peculiar/asn1-pfx` models `macData` as a required field with a default
    // `new MacData()`, so a PFX that genuinely carries no MacData (rare, but
    // RFC-valid) can surface here as an all-empty MacData rather than
    // `undefined`. Treat that degenerate form as absent — it is "no integrity
    // check", not an unsupported algorithm.
    const macData = parsed.macData;
    const hasMacData = macData !== undefined && macData.mac.digestAlgorithm.algorithm !== "";
    if (hasMacData) {
        const hash = macHash(macData.mac.digestAlgorithm.algorithm);
        const macSalt = new Uint8Array(macData.macSalt.buffer);
        const macKey = pkcs12Kdf(hash, password, macSalt, macData.iterations, 3, hashOutputBytes(hash));
        const hmacKey = await subtle.importKey("raw", macKey as unknown as BufferSource, { name: "HMAC", hash }, false, ["sign"]);
        const computedMac = new Uint8Array(await subtle.sign("HMAC", hmacKey, authenticatedSafeDer));
        const expectedMac = new Uint8Array(macData.mac.digest.buffer);
        if (computedMac.length !== expectedMac.length || !timingSafeEqual(computedMac, expectedMac)) {
            throw new PfxIntegrityError();
        }
    }

    const authenticatedSafe = AsnConvert.parse(authenticatedSafeDer, AuthenticatedSafe);

    // Gather every SafeContents first — whichever envelope it came in — then
    // dispatch on bag type uniformly. RFC 7292 does not restrict which bag
    // types may live under which envelope, so a cert bag in a plain Data
    // safe (`openssl -certpbe NONE`) or a key bag inside the encrypted safe
    // (BouncyCastle-style) must be collected all the same.
    const safeContentsList: SafeContents[] = [];
    for (const contentInfo of authenticatedSafe) {
        if (contentInfo.contentType === OID_PKCS7_ENCRYPTED_DATA) {
            const encryptedData = AsnConvert.parse(contentInfo.content, CmsEncryptedData);
            const ciphertext = encryptedContentBytes(encryptedData.encryptedContentInfo.encryptedContent);
            if (!ciphertext) {
                continue;
            }
            let plainDer: ArrayBuffer;
            try {
                plainDer = await decryptPbes2(
                    subtle,
                    ciphertext,
                    encryptedData.encryptedContentInfo.contentEncryptionAlgorithm,
                    password,
                );
            } catch (err) {
                if (err instanceof Pkcs12UnsupportedAlgorithmError) {
                    throw err;
                }
                throw new PfxIntegrityError();
            }
            safeContentsList.push(AsnConvert.parse(plainDer, SafeContents));
        } else if (contentInfo.contentType === OID_PKCS7_DATA) {
            safeContentsList.push(AsnConvert.parse(unwrapOctetString(contentInfo.content), SafeContents));
        }
        // Any other envelope (e.g. public-key EnvelopedData) is not password-based; ignore.
    }

    const certs: CollectedCert[] = [];
    const keys: CollectedKey[] = [];
    for (const safeContents of safeContentsList) {
        for (const bag of safeContents) {
            switch (bag.bagId) {
                case OID_CERT_BAG: {
                    const certBag = AsnConvert.parse(bag.bagValue, CertBag);
                    if (certBag.certId === OID_X509_CERTIFICATE) {
                        certs.push({
                            der: Buffer.from(certBag.certValue),
                            localKeyId: bagLocalKeyId(bag),
                            friendlyName: bagFriendlyName(bag),
                        });
                    }
                    break;
                }
                case OID_PKCS8_SHROUDED_KEY_BAG:
                    keys.push({ key: decryptShroudedKeyBag(bag.bagValue, password), localKeyId: bagLocalKeyId(bag) });
                    break;
                case OID_KEY_BAG: {
                    // KeyBag ::= PrivateKeyInfo, unencrypted — spec-valid but rarely produced by real tooling
                    const hidden = createPrivateKeyFromNodeJSCrypto({
                        key: Buffer.from(bag.bagValue),
                        format: "der",
                        type: "pkcs8",
                    });
                    keys.push({ key: { hidden } as unknown as PrivateKey, localKeyId: bagLocalKeyId(bag) });
                    break;
                }
                default:
                    break; // secretBag, safeContentsBag, crlBag, ...: not something this API returns
            }
        }
    }

    if (keys.length === 0) {
        throw new PfxMalformedError("PFX contains no private key");
    }
    if (certs.length === 0) {
        throw new PfxMalformedError("PFX contains no certificate");
    }

    // Pair the key with its certificate via localKeyId; prefer a key that
    // actually has a matching cert (a multi-identity PFX), else the first key.
    let leafIndex = -1;
    let chosenKey = keys[0];
    for (const candidate of keys) {
        if (candidate.localKeyId === undefined) {
            continue;
        }
        const idx = certs.findIndex((c) => c.localKeyId === candidate.localKeyId);
        if (idx !== -1) {
            leafIndex = idx;
            chosenKey = candidate;
            break;
        }
    }
    if (leafIndex === -1) {
        leafIndex = 0; // no localKeyId pairing available in this file: fall back to file order
    }

    const leaf = certs[leafIndex];
    const certificateChain = certs.filter((_, i) => i !== leafIndex).map((c) => c.der);
    return { certificate: leaf.der, certificateChain, privateKey: chosenKey.key, friendlyName: leaf.friendlyName };
}
