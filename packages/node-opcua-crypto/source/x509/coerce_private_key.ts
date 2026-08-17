import {
    createPrivateKeyFromNodeJSCrypto,
    isKeyObject,
    type KeyObject,
    type PrivateKey,
    PrivateKeyPassphraseRequiredError,
} from "../common.js";
import { getCrypto } from "./_crypto.js";
import { derToPrivateKey, pemToPrivateKey } from "./create_key_pair.js";

const crypto = getCrypto();

const doDebug = false;

const ENCRYPTED_PEM_HEADER = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

/**
 * @param privateKeyInDerOrPem
 * @param passphrase — required if the PEM is an encrypted PKCS#8 key
 *   (`-----BEGIN ENCRYPTED PRIVATE KEY-----`). Throws
 *   {@link PrivateKeyPassphraseRequiredError} if the key is encrypted and
 *   no passphrase is supplied. Unencrypted input is unaffected by this
 *   parameter.
 */
export function coercePEMorDerToPrivateKey(privateKeyInDerOrPem: string | Buffer, passphrase?: string | Buffer): PrivateKey {
    if (typeof privateKeyInDerOrPem === "string") {
        if (privateKeyInDerOrPem.includes(ENCRYPTED_PEM_HEADER) && passphrase === undefined) {
            throw new PrivateKeyPassphraseRequiredError();
        }
        const hidden =
            passphrase !== undefined
                ? createPrivateKeyFromNodeJSCrypto({ key: privateKeyInDerOrPem, format: "pem", passphrase })
                : createPrivateKeyFromNodeJSCrypto(privateKeyInDerOrPem);
        return { hidden: hidden as unknown as KeyObject };
    }
    //istanbul ignore next
    throw new Error("not implemented");
    // return privateKey.hidden;
}

/**
 *
 * @private
 */
export async function _coercePrivateKey(privateKey: unknown): Promise<KeyObject> {
    const KeyObject = (crypto as unknown as { KeyObject: { from(key: unknown): KeyObject } }).KeyObject;
    if (Buffer.isBuffer(privateKey)) {
        const privateKey1 = await derToPrivateKey(privateKey as unknown as ArrayBuffer); //
        return KeyObject.from(privateKey1);
    } else if (typeof privateKey === "string") {
        try {
            // privateKey = privateKey.replace(/RSA PRIVATE KEY-----\n.*/mg, "RSA PRIVATE KEY-----");
            const privateKey1 = await pemToPrivateKey(privateKey);
            return KeyObject.from(privateKey1);
        } catch (err) {
            doDebug && console.log(privateKey);
            throw err;
        }
    } else if (isKeyObject(privateKey)) {
        return privateKey as KeyObject;
    }
    throw new Error("Invalid privateKey");
}
