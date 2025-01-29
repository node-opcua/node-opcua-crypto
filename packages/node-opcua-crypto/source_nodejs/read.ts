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

import assert from "assert";
import fs from "node:fs";
import path from "node:path";
import { createPrivateKey, createPublicKey } from "crypto";
import { Certificate, CertificatePEM, DER, PEM, PublicKey, PublicKeyPEM, PrivateKeyPEM, PrivateKey } from "../source/common.js";
import { convertPEMtoDER, identifyPemType, removeTrailingLF, toPem } from "../source/crypto_utils.js";
import sshpk from "sshpk";

function _readPemFile(filename: string): PEM {
    assert(typeof filename === "string");
    return removeTrailingLF(fs.readFileSync(filename, "utf-8"));
}

function _readPemOrDerFileAsDER(filename: string): DER {
    if (filename.match(/.*\.der/)) {
        return fs.readFileSync(filename) as Buffer;
    }
    const raw_key: string = _readPemFile(filename);
    return convertPEMtoDER(raw_key);
}

/**
 * read a DER or PEM certificate from file
 */
export function readCertificate(filename: string): Certificate {
    return _readPemOrDerFileAsDER(filename) as Certificate;
}

/**
 * read a DER or PEM certificate from file
 */
export function readPublicKey(filename: string): PublicKey {
    if (filename.match(/.*\.der/)) {
        const der = fs.readFileSync(filename) as Buffer;
        return createPublicKey(der);
    } else {
        const raw_key: string = _readPemFile(filename);
        return createPublicKey(raw_key);
    }
}

// console.log("createPrivateKey", (crypto as any).createPrivateKey, process.env.NO_CREATE_PRIVATEKEY);

function myCreatePrivateKey(rawKey: string | Buffer): PrivateKey {
    if (!createPrivateKey || process.env.NO_CREATE_PRIVATEKEY) {
        // we are not running nodejs or createPrivateKey is not supported in the environment
        if (Buffer.isBuffer(rawKey)) {
            const pemKey = toPem(rawKey, "PRIVATE KEY");
            assert(["RSA PRIVATE KEY", "PRIVATE KEY"].indexOf(identifyPemType(pemKey) as string) >= 0);
            return { hidden: pemKey };
        }
        return { hidden: ensureTrailingLF(rawKey as string) };
    }
    // see https://askubuntu.com/questions/1409458/openssl-config-cuases-error-in-node-js-crypto-how-should-the-config-be-updated
    const backup = process.env.OPENSSL_CONF;
    process.env.OPENSSL_CONF = "/dev/null";
    const retValue = createPrivateKey(rawKey);
    process.env.OPENSSL_CONF = backup;
    return { hidden: retValue };
}

function ensureTrailingLF(str: string): string {
    return str.match(/\n$/) ? str : str + "\n";
}
/**
 * read a DER or PEM certificate from file
 */
export function readPrivateKey(filename: string): PrivateKey {
    if (filename.match(/.*\.der/)) {
        const der: Buffer = fs.readFileSync(filename);
        return myCreatePrivateKey(der);
    } else {
        const raw_key: string = _readPemFile(filename);
        return myCreatePrivateKey(raw_key);
    }
}

export function readCertificatePEM(filename: string): CertificatePEM {
    return _readPemFile(filename);
}

export function readPublicKeyPEM(filename: string): PublicKeyPEM {
    return _readPemFile(filename);
}
/**
 *
 * @deprecated
 */
export function readPrivateKeyPEM(filename: string): PrivateKeyPEM {
    return _readPemFile(filename);
}

let _g_certificate_store: string = "";

export function setCertificateStore(store: string): string {
    const old_store = _g_certificate_store;
    _g_certificate_store = store;
    return old_store;
}
export function getCertificateStore(): string {
    if (!_g_certificate_store) {
        _g_certificate_store = path.join(__dirname, "../../certificates/");
    }
    return _g_certificate_store;
}
/**
 *
 * @param filename
 */
export function readPrivateRsaKey(filename: string): PrivateKey {
    if (!createPrivateKey) {
        throw new Error("createPrivateKey is not supported in this environment");
    }
    if (filename.substring(0, 1) !== "." && !fs.existsSync(filename)) {
        filename = path.join(getCertificateStore(), filename);
    }
    const content = fs.readFileSync(filename, "utf8");
    const sshKey = sshpk.parsePrivateKey(content, "auto");
    const key = sshKey.toString("pkcs1") as PEM;
    const hidden = createPrivateKey({ format: "pem", type: "pkcs1", key });
    return { hidden };
}

export function readPublicRsaKey(filename: string): PublicKey {
    if (filename.substring(0, 1) !== "." && !fs.existsSync(filename)) {
        filename = path.join(getCertificateStore(), filename);
    }
    const content = fs.readFileSync(filename, "utf-8");
    const sshKey = sshpk.parseKey(content, "ssh");
    const key = sshKey.toString("pkcs1") as PEM;
    return createPublicKey({ format: "pem", type: "pkcs1", key });
}
