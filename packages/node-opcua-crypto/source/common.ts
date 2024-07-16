// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2024 - Sterfive.com
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
import __crypto from "crypto";
const KeyObjectOrig = __crypto.KeyObject;

export const { createPrivateKey: createPrivateKeyFromNodeJSCrypto } = __crypto;

type KeyFormat = "pem" | "der" | "jwk";
type KeyObjectType = "secret" | "public" | "private";
interface KeyExportOptions<T extends KeyFormat> {
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
export function isKeyObject(mayBeKeyObject: any): boolean {
    if (KeyObjectOrig) {
        return mayBeKeyObject instanceof KeyObjectOrig;
    }
    return typeof mayBeKeyObject === "object" && typeof (mayBeKeyObject as any).type === "string"; /// .constructor?.name === "KeyObject";
}
export type PrivateKey = { hidden: string } | { hidden: KeyObject };
export type PublicKey = KeyObject;

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
