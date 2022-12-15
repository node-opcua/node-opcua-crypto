import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { createPrivateKey, createPublicKey } from "crypto";
import { Certificate, CertificatePEM, DER, PEM, PrivateKey, PrivateKeyPEM, PublicKey, PublicKeyPEM } from "../source/common";
import { convertPEMtoDER, identifyPemType } from "../source/crypto_utils";

const sshpk = require("sshpk");

function _readPemFile(filename: string): PEM {
    assert(typeof filename === "string");
    return fs.readFileSync(filename, "ascii");
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

function myCreatePrivateKey(rawKey: string | Buffer) {
    // see https://askubuntu.com/questions/1409458/openssl-config-cuases-error-in-node-js-crypto-how-should-the-config-be-updated
    const backup = process.env.OPENSSL_CONF;
    process.env.OPENSSL_CONF = "/dev/null";
    const retValue = createPrivateKey(rawKey);
    process.env.OPENSSL_CONF = backup;
    return retValue;
}
/**
 * read a DER or PEM certificate from file
 */
export function readPrivateKey(filename: string): PrivateKey {
    if (filename.match(/.*\.der/)) {
        const der = fs.readFileSync(filename) as Buffer;
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

export function readPrivateKeyPEM(filename: string): PrivateKeyPEM {
    return _readPemFile(filename);
}
let __certificate_store = path.join(__dirname, "../../certificates/");

export function setCertificateStore(store: string): string {
    const old_store = __certificate_store;
    __certificate_store = store;
    return old_store;
}

/**
 *
 * @param filename
 */
export function readPrivateRsaKey(filename: string): PrivateKey {
    if (filename.substring(0, 1) !== "." && !fs.existsSync(filename)) {
        filename = __certificate_store + filename;
    }
    const content = fs.readFileSync(filename, "ascii");
    const sshKey = sshpk.parsePrivateKey(content, "auto");
    const key = sshKey.toString("pkcs1") as PEM;
    return createPrivateKey({ format: "pem", type: "pkcs1", key });
}

export function readPublicRsaKey(filename: string): PublicKey {
    if (filename.substring(0, 1) !== "." && !fs.existsSync(filename)) {
        filename = __certificate_store + filename;
    }
    const content = fs.readFileSync(filename, "ascii");
    const sshKey = sshpk.parseKey(content, "ssh");
    const key = sshKey.toString("pkcs1") as PEM;
    return createPublicKey({ format: "pem", type: "pkcs1", key });
}
