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
import __crypto from "node:crypto";

const KeyObjectOrig = __crypto.KeyObject;

export const { createPrivateKey: createPrivateKeyFromNodeJSCrypto } = __crypto;

type KeyFormat = "pem" | "der" | "jwk";
type KeyObjectType = "secret" | "public" | "private";
export interface KeyExportOptions<T extends KeyFormat> {
    type: "pkcs1" | "spki" | "pkcs8" | "sec1";
    format: T;
    cipher?: string | undefined;
    passphrase?: string | Buffer | undefined;
}
interface JwkKeyExportOptions {
    format: "jwk";
}
export interface KeyObject {
    export(options: KeyExportOptions<"pem">): string | Buffer;
    export(options: KeyExportOptions<"der">): Buffer;
    export(options: JwkKeyExportOptions): JsonWebKey;

    type: KeyObjectType;
}
export function isKeyObject(mayBeKeyObject: unknown): boolean {
    if (KeyObjectOrig) {
        return mayBeKeyObject instanceof KeyObjectOrig;
    }
    return typeof mayBeKeyObject === "object" && typeof (mayBeKeyObject as { type?: unknown }).type === "string"; /// .constructor?.name === "KeyObject";
}
export type PrivateKey = { hidden: string } | { hidden: KeyObject };
export type PublicKey = KeyObject;

/**
 * Thrown when a private key is encrypted (PKCS#8 `ENCRYPTED PRIVATE KEY`)
 * and the caller did not supply a passphrase to decrypt it. Reading an
 * encrypted key without a passphrase always fails closed — it never falls
 * back to treating the key as unencrypted or skipping it.
 */
export class PrivateKeyPassphraseRequiredError extends Error {
    constructor(message = "This private key is encrypted and requires a passphrase to be read") {
        super(message);
        this.name = "PrivateKeyPassphraseRequiredError";
    }
}

// ── PKCS#12 (PFX) errors ────────────────────────────────────────────────
// Defined here, alongside PrivateKeyPassphraseRequiredError, so every
// PKCS#12 module and every consumer imports them from one place. They are
// deliberately distinct classes so a caller can tell "wrong password" from
// "structurally invalid file" from "algorithm this build cannot handle"
// without matching on message text.

/**
 * PKCS#12 integrity check failed: the password is wrong, or the file has
 * been corrupted or tampered with. Raised on a `MacData` HMAC mismatch and
 * on a bag-decryption failure (both are the observable symptom of a wrong
 * password; PKCS#12 does not let the two be distinguished reliably).
 */
export class PfxIntegrityError extends Error {
    constructor(message = "PFX integrity check failed: wrong password, or the file is corrupted or has been tampered with") {
        super(message);
        this.name = "PfxIntegrityError";
    }
}

/**
 * The PKCS#12 file parsed and (where applicable) decrypted correctly, but
 * is not a bundle this API can represent — for example it carries no
 * private key, or no certificate. Distinct from {@link PfxIntegrityError}:
 * the password was fine; the content is what is missing or malformed.
 */
export class PfxMalformedError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "PfxMalformedError";
    }
}

/**
 * The PKCS#12 file uses an encryption or digest algorithm this build does
 * not implement (for example the legacy RC2-40 PBE scheme, which neither
 * WebCrypto nor a default Node build exposes). Not a data error — the file
 * may be perfectly valid; it just needs a capability this code lacks.
 */
export class Pkcs12UnsupportedAlgorithmError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "Pkcs12UnsupportedAlgorithmError";
    }
}

export type Nonce = Buffer;
export type PEM = string;
export type DER = Buffer;
export type Certificate = DER;
export type CertificatePEM = PEM; // certificate as a PEM string
export type PrivateKeyPEM = PEM;
export type PublicKeyPEM = PEM;

export type Signature = Buffer;
export type CertificateRevocationList = Buffer;

export enum CertificatePurpose {
    NotSpecified = 0,
    ForCertificateAuthority = 1,
    ForApplication = 2,
    ForUserAuthentication = 3, // X509
}
