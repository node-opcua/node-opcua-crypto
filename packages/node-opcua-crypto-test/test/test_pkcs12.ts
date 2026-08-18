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

import type { KeyObject } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { AuthenticatedSafe, PFX, SafeContents } from "@peculiar/asn1-pfx";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import * as asn1js from "asn1js";
import {
    createPfx,
    exploreCertificate,
    makePrivateKeyFromPem,
    PfxIntegrityError,
    PfxMalformedError,
    Pkcs12UnsupportedAlgorithmError,
    PrivateKeyPassphraseRequiredError,
    parsePfx,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

const fixturesDir = path.join(__dirname, "../test-fixtures/pfx");

function loadFixture(name: string): Buffer {
    return fs.readFileSync(path.join(fixturesDir, name));
}

/**
 * `PrivateKey.hidden` is typed as the package's own structural `KeyObject`
 * interface (deliberately decoupled from Node's class, and without an
 * `asymmetricKeyType` member). At runtime, under Node, it IS a
 * `node:crypto` KeyObject, so read that property through an explicit cast
 * at this one boundary rather than pretending the two types are related.
 */
function asymmetricKeyType(hidden: unknown): string | undefined {
    return (hidden as KeyObject).asymmetricKeyType;
}

// The exact certs/keys/passwords baked into these fixtures by
// scripts/generate_pfx_fixtures.js — kept in sync with that script.
const FIXTURES = [
    { file: "simple_no_password.pfx", password: "", subject: "PFXTestLeaf", chainLength: 0, keyType: "rsa" },
    { file: "with_password.pfx", password: "secret", subject: "PFXTestLeaf", chainLength: 0, keyType: "rsa" },
    { file: "with_ca_chain.pfx", password: "", subject: "PFXTestSigned", chainLength: 1, keyType: "rsa" },
    { file: "with_ca_chain_password.pfx", password: "capass", subject: "PFXTestSigned", chainLength: 1, keyType: "rsa" },
    { file: "with_friendly_name.pfx", password: "", subject: "PFXTestLeaf", chainLength: 0, keyType: "rsa" },
    { file: "ecc.pfx", password: "", subject: "PFXTestECC", chainLength: 0, keyType: "ec" },
] as const;

describe("PKCS#12 (PFX)", () => {
    describe("parsePfx — real OpenSSL 3.x-generated fixtures", () => {
        for (const { file, password, subject, chainLength, keyType } of FIXTURES) {
            it(`should parse ${file}`, async () => {
                const buf = loadFixture(file);
                const result = await parsePfx(buf, password);

                expect(result.certificate.length).toBeGreaterThan(0);
                expect(result.certificateChain.length).toBe(chainLength);
                expect(result.privateKey.hidden).toBeTruthy();
                expect(asymmetricKeyType(result.privateKey.hidden)).toBe(keyType);

                expect(exploreCertificate(result.certificate).tbsCertificate.subject.commonName).toBe(subject);
            });
        }

        it("should fail closed (PfxIntegrityError) with the wrong password", async () => {
            const buf = loadFixture("with_password.pfx");
            await expect(parsePfx(buf, "WRONG")).rejects.toThrow(PfxIntegrityError);
        });

        it("should fail closed (PfxIntegrityError) with an empty password when one was actually set", async () => {
            const buf = loadFixture("with_password.pfx");
            await expect(parsePfx(buf, "")).rejects.toThrow(PfxIntegrityError);
        });
    });

    describe("createPfx / parsePfx round-trip", () => {
        it("should round-trip a certificate + RSA key with a password", async () => {
            const source = await parsePfx(loadFixture("with_password.pfx"), "secret");

            const created = await createPfx({
                certificate: source.certificate,
                privateKey: source.privateKey,
                password: "round-trip-password",
            });
            const reparsed = await parsePfx(created, "round-trip-password");

            expect(reparsed.certificate.equals(source.certificate)).toBe(true);
            expect(reparsed.certificateChain).toEqual([]);
            expect(asymmetricKeyType(reparsed.privateKey.hidden)).toBe("rsa");
        });

        it("should round-trip with an empty password", async () => {
            const source = await parsePfx(loadFixture("simple_no_password.pfx"), "");
            const created = await createPfx({ certificate: source.certificate, privateKey: source.privateKey, password: "" });
            const reparsed = await parsePfx(created, "");
            expect(reparsed.certificate.equals(source.certificate)).toBe(true);
        });

        it("should round-trip a certificate chain", async () => {
            const source = await parsePfx(loadFixture("with_ca_chain.pfx"), "");
            const created = await createPfx({
                certificate: source.certificate,
                certificateChain: source.certificateChain,
                privateKey: source.privateKey,
                password: "chain-pw",
            });
            const reparsed = await parsePfx(created, "chain-pw");

            expect(reparsed.certificate.equals(source.certificate)).toBe(true);
            expect(reparsed.certificateChain.length).toBe(source.certificateChain.length);
            expect(reparsed.certificateChain[0].equals(source.certificateChain[0])).toBe(true);
        });

        it("should round-trip an EC key", async () => {
            const source = await parsePfx(loadFixture("ecc.pfx"), "");
            const created = await createPfx({ certificate: source.certificate, privateKey: source.privateKey, password: "ecpass" });
            const reparsed = await parsePfx(created, "ecpass");

            expect(reparsed.certificate.equals(source.certificate)).toBe(true);
            expect(asymmetricKeyType(reparsed.privateKey.hidden)).toBe("ec");
        });

        it("should embed a friendlyName without corrupting the bundle", async () => {
            const source = await parsePfx(loadFixture("with_password.pfx"), "secret");
            const created = await createPfx({
                certificate: source.certificate,
                privateKey: source.privateKey,
                password: "pw",
                friendlyName: "My Test Certificate",
            });
            const reparsed = await parsePfx(created, "pw");
            expect(reparsed.certificate.equals(source.certificate)).toBe(true);
        });

        it("should fail closed on a bundle it just created, given the wrong password", async () => {
            const source = await parsePfx(loadFixture("with_password.pfx"), "secret");
            const created = await createPfx({
                certificate: source.certificate,
                privateKey: source.privateKey,
                password: "correct",
            });
            await expect(parsePfx(created, "incorrect")).rejects.toThrow(PfxIntegrityError);
        });
    });

    // ── Interop / regression coverage ────────────────────────────────────
    // Every case here targets a layout the OpenSSL-default fixtures above
    // cannot exercise. They exist because parsePfx once mishandled each of
    // them silently (a wrong answer or a misleading error, no crash).

    const cn = (der: Buffer) => exploreCertificate(der).tbsCertificate.subject.commonName;

    /**
     * Rebuild a PFX with a NEW AuthenticatedSafe and NO MacData at all — a
     * genuinely 2-element `PFX ::= SEQUENCE { version, authSafe }`, which is
     * RFC-valid ("no integrity check"). Done with raw asn1js because
     * `@peculiar/asn1-pfx` models macData as a required field with a default
     * value, so setting it to `undefined` still serializes an (empty) MacData.
     * Dropping MacData is what lets a test alter the authSafe without having
     * to re-derive and re-sign the HMAC.
     */
    function rebuildPfxWithoutMacData(authSafeDer: ArrayBuffer): Buffer {
        const authSafeContentInfo = new asn1js.Sequence({
            value: [
                new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.7.1" }), // pkcs7-data
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 },
                    value: [new asn1js.OctetString({ valueHex: authSafeDer })],
                }),
            ],
        });
        const pfxSeq = new asn1js.Sequence({ value: [new asn1js.Integer({ value: 3 }), authSafeContentInfo] });
        return Buffer.from(pfxSeq.toBER());
    }

    describe("interop: layouts beyond the OpenSSL default", () => {
        it("reads a certificate safe left UNENCRYPTED (openssl -certpbe NONE)", async () => {
            // Cert bags live in a plain Data envelope here, not EncryptedData.
            // RFC 7292 does not tie bag types to envelopes; a parser that only
            // looks for cert bags inside EncryptedData reports 'no certificate'.
            const result = await parsePfx(loadFixture("certpbe_none.pfx"), "secret");
            expect(cn(result.certificate)).toBe("PFXTestLeaf");
            expect(result.certificateChain).toEqual([]);
            expect(asymmetricKeyType(result.privateKey.hidden)).toBe("rsa");
        });

        it("fails LOUDLY (Pkcs12UnsupportedAlgorithmError), never silently, on a legacy RC2-40 certificate safe", async () => {
            // openssl -legacy: 3DES key bag (which Node decrypts natively) but an
            // RC2-40 cert safe this build cannot decrypt (RC2 needs OpenSSL's
            // legacy provider). The contract is a typed, honest error — not a
            // wrong answer and not a bogus 'wrong password'.
            await expect(parsePfx(loadFixture("legacy.pfx"), "secret")).rejects.toThrow(Pkcs12UnsupportedAlgorithmError);
        });

        it("reads a BER-encoded file (constructed OCTET STRING), as BouncyCastle emits", async () => {
            // Re-encode a valid DER PFX so its authSafe content is a BER
            // CONSTRUCTED OCTET STRING split into chunks. The MAC is computed
            // over the *inner* bytes, which are unchanged, so it must still
            // verify. asn1js only fills valueHex for the primitive form; a
            // parser reading valueHex sees an EMPTY authSafe here -> false
            // PfxIntegrityError ("wrong password") on a perfectly valid file.
            const der = loadFixture("with_password.pfx");
            const pfx = AsnConvert.parse(der, PFX);
            const inner = new Uint8Array(AsnConvert.parse(pfx.authSafe.content, OctetString).buffer);
            const mid = Math.floor(inner.length / 2);
            const constructed = new asn1js.OctetString({
                isConstructed: true,
                value: [
                    new asn1js.OctetString({ valueHex: inner.slice(0, mid).buffer }),
                    new asn1js.OctetString({ valueHex: inner.slice(mid).buffer }),
                ],
            });
            pfx.authSafe.content = constructed.toBER();
            const berPfx = Buffer.from(AsnConvert.serialize(pfx));
            expect(berPfx.equals(der)).toBe(false); // sanity: we really did re-encode it

            const result = await parsePfx(berPfx, "secret");
            expect(cn(result.certificate)).toBe("PFXTestLeaf");
            expect(asymmetricKeyType(result.privateKey.hidden)).toBe("rsa");
        });

        it("pairs the leaf to its key via localKeyId, not by cert-bag position (CA bag first)", async () => {
            // openssl always emits the cert matching -inkey first, and createPfx
            // stamps localKeyId on cert bag #0, so neither can produce the
            // Windows/keytool-style file where the LEAF is NOT bag #0. Build it
            // by hand from an openssl fixture whose cert safe is plain Data
            // (certpbe_none.pfx, no re-encryption needed): move the leaf bag —
            // the one carrying localKeyId — to the END of the SafeContents,
            // behind a CA cert bag with no localKeyId. A parser that pairs via
            // localKeyId still returns the leaf; one that takes bag #0 returns
            // the CA, silently.
            const der = loadFixture("certpbe_none.pfx");
            const pfx = AsnConvert.parse(der, PFX);
            const authSafeDer = AsnConvert.parse(pfx.authSafe.content, OctetString).buffer;
            const authSafe = AsnConvert.parse(authSafeDer, AuthenticatedSafe);
            const certEnvelopeIndex = authSafe.findIndex((ci) => ci.contentType === "1.2.840.113549.1.7.1");
            const certSafe = AsnConvert.parse(
                AsnConvert.parse(authSafe[certEnvelopeIndex].content, OctetString).buffer,
                SafeContents,
            );
            expect(certSafe.length).toBe(1); // the leaf, carrying localKeyId
            const leafBag = certSafe[0];
            expect(leafBag.bagAttributes?.some((a) => a.attrId === "1.2.840.113549.1.9.21")).toBe(true);
            // A CA cert bag with NO attributes, placed BEFORE the leaf:
            const caDer = (await parsePfx(loadFixture("with_ca_chain.pfx"), "")).certificateChain[0];
            const { SafeBag } = await import("@peculiar/asn1-pfx");
            const caBag = new SafeBag({
                bagId: "1.2.840.113549.1.12.10.1.3",
                bagValue: (() => {
                    // CertBag ::= SEQUENCE { certId x509Certificate, certValue [0] EXPLICIT OCTET STRING }
                    // Uint8Array.from copies exactly the cert bytes into a fresh, correctly-typed
                    // BufferSource (Buffer#buffer.slice is typed ArrayBuffer | SharedArrayBuffer,
                    // which asn1js rejects, and it also depends on getting byteOffset right).
                    const octet = new asn1js.OctetString({ valueHex: Uint8Array.from(caDer) });
                    const seq = new asn1js.Sequence({
                        value: [
                            new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.9.22.1" }),
                            new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [octet] }),
                        ],
                    });
                    return seq.toBER();
                })(),
            });
            const reordered = new SafeContents([caBag, leafBag]);
            authSafe[certEnvelopeIndex].content = AsnConvert.serialize(new OctetString(AsnConvert.serialize(reordered)));
            // authSafe changed, so the original MAC no longer applies: rebuild without MacData (RFC-valid).
            const caFirst = rebuildPfxWithoutMacData(AsnConvert.serialize(authSafe));

            const result = await parsePfx(caFirst, "secret");
            expect(cn(result.certificate)).toBe("PFXTestLeaf"); // the leaf, even though it is bag #1
            expect(result.certificateChain.map(cn)).toEqual(["TestCA"]); // the CA, even though it was bag #0
            expect(asymmetricKeyType(result.privateKey.hidden)).toBe("rsa");
        });
    });

    describe("createPfx: attributes and input validation", () => {
        it("stamps friendlyName on the leaf CERTIFICATE bag (what Windows displays), not only the key bag", async () => {
            const source = await parsePfx(loadFixture("with_password.pfx"), "secret");
            const built = await createPfx({
                certificate: source.certificate,
                privateKey: source.privateKey,
                password: "pw",
                friendlyName: "Attribute Check",
            });
            // parsePfx surfaces the leaf CERT bag's friendlyName specifically, so
            // this asserts the attribute is on the cert bag — the Windows
            // certificate store reads it from there. (The key bag carries it too,
            // as OpenSSL -name does; a key-bag-only stamp would fail this test.)
            const reparsed = await parsePfx(built, "pw");
            expect(reparsed.friendlyName).toBe("Attribute Check");
            expect(reparsed.certificate.equals(source.certificate)).toBe(true);
            // Structural cross-check on the plain Data key safe (readable without a password):
            const pfx = AsnConvert.parse(built, PFX);
            const authSafe = AsnConvert.parse(AsnConvert.parse(pfx.authSafe.content, OctetString).buffer, AuthenticatedSafe);
            const plainDataEnvelope = authSafe.find((ci) => ci.contentType === "1.2.840.113549.1.7.1");
            const keySafe = AsnConvert.parse(
                AsnConvert.parse(plainDataEnvelope?.content as ArrayBuffer, OctetString).buffer,
                SafeContents,
            );
            expect(keySafe[0].bagAttributes?.some((a) => a.attrId === "1.2.840.113549.1.9.20")).toBe(true);
        });

        it("reads back the friendlyName OpenSSL wrote (-name) from a real fixture", async () => {
            const result = await parsePfx(loadFixture("with_friendly_name.pfx"), "");
            expect(result.friendlyName).toBe("MyFriendlyName");
        });

        it("reports no friendlyName for a bundle that has none", async () => {
            const result = await parsePfx(loadFixture("with_password.pfx"), "secret");
            expect(result.friendlyName).toBeUndefined();
        });

        it("rejects a password containing a lone surrogate up front, instead of emitting an unverifiable file", async () => {
            // A lone surrogate has no single byte encoding: BMPString (used by the
            // MAC KDF) keeps it verbatim, UTF-8 (used by PBKDF2) turns it into
            // U+FFFD, so MAC and bag keys would derive from DIFFERENT bytes and
            // the file could never be verified by anyone, ourselves included.
            const source = await parsePfx(loadFixture("with_password.pfx"), "secret");
            const loneSurrogate = "pass\uD800word";
            await expect(
                createPfx({ certificate: source.certificate, privateKey: source.privateKey, password: loneSurrogate }),
            ).rejects.toThrow(/lone high surrogate/);
            await expect(parsePfx(loadFixture("with_password.pfx"), loneSurrogate)).rejects.toThrow(/lone high surrogate/);
        });

        it("round-trips a password containing a valid non-BMP character (surrogate PAIR)", async () => {
            // Pairs are fine and must interoperate: OpenSSL encodes them the same way.
            const source = await parsePfx(loadFixture("with_password.pfx"), "secret");
            const emojiPassword = "p\u{1F511}w"; // 🔑
            const built = await createPfx({
                certificate: source.certificate,
                privateKey: source.privateKey,
                password: emojiPassword,
            });
            const reparsed = await parsePfx(built, emojiPassword);
            expect(reparsed.certificate.equals(source.certificate)).toBe(true);
        });

        it("throws the typed PrivateKeyPassphraseRequiredError (not a raw OpenSSL error) for an encrypted-PEM key", async () => {
            const encryptedPem = [
                "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                "MIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIAAAAAAAAAAACAggA",
                "-----END ENCRYPTED PRIVATE KEY-----",
            ].join("\n");
            const source = await parsePfx(loadFixture("with_password.pfx"), "secret");
            await expect(
                createPfx({ certificate: source.certificate, privateKey: makePrivateKeyFromPem(encryptedPem), password: "pw" }),
            ).rejects.toThrow(PrivateKeyPassphraseRequiredError);
        });
    });

    describe("typed errors", () => {
        it("PfxMalformedError for a structurally-valid bundle with no private key (distinct from wrong password)", async () => {
            // Take a real PFX and drop the key SafeContents from the AuthenticatedSafe,
            // rebuilding without MacData (RFC-valid) so the altered authSafe needs no
            // re-signing. The result decrypts fine — the password is right — it just
            // has nothing to return: that must be PfxMalformedError, NOT PfxIntegrityError.
            const der = loadFixture("simple_no_password.pfx");
            const pfx = AsnConvert.parse(der, PFX);
            const authSafeDer = AsnConvert.parse(pfx.authSafe.content, OctetString).buffer;
            const authSafe = AsnConvert.parse(authSafeDer, AuthenticatedSafe);
            const certOnly = new AuthenticatedSafe(authSafe.filter((ci) => ci.contentType === "1.2.840.113549.1.7.6"));
            expect(certOnly.length).toBe(1);
            const noKey = rebuildPfxWithoutMacData(AsnConvert.serialize(certOnly));
            await expect(parsePfx(noKey, "")).rejects.toThrow(PfxMalformedError);
        });

        it("accepts a bundle with no MacData at all (RFC-valid: 'no integrity check')", async () => {
            // Same rebuild, but with the FULL authSafe kept — a legitimate no-MacData
            // file must parse, not be rejected as 'unsupported algorithm'.
            const der = loadFixture("simple_no_password.pfx");
            const pfx = AsnConvert.parse(der, PFX);
            const authSafeDer = AsnConvert.parse(pfx.authSafe.content, OctetString).buffer;
            const noMac = rebuildPfxWithoutMacData(authSafeDer);
            const result = await parsePfx(noMac, "");
            expect(cn(result.certificate)).toBe("PFXTestLeaf");
            expect(asymmetricKeyType(result.privateKey.hidden)).toBe("rsa");
        });

        it("keeps PfxIntegrityError and PfxMalformedError distinguishable by class, not message text", () => {
            expect(new PfxIntegrityError()).toBeInstanceOf(Error);
            expect(new PfxMalformedError("x")).toBeInstanceOf(Error);
            expect(new PfxIntegrityError()).not.toBeInstanceOf(PfxMalformedError);
            expect(new PfxMalformedError("x")).not.toBeInstanceOf(PfxIntegrityError);
            expect(new Pkcs12UnsupportedAlgorithmError("x").name).toBe("Pkcs12UnsupportedAlgorithmError");
        });
    });
});
