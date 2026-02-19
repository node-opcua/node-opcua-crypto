import { createPrivateKeyFromNodeJSCrypto, isKeyObject, type KeyObject, type PrivateKey } from "../common.js";
import { getCrypto } from "./_crypto.js";
import { derToPrivateKey, pemToPrivateKey } from "./create_key_pair.js";

const crypto = getCrypto();

const doDebug = false;

export function coercePEMorDerToPrivateKey(privateKeyInDerOrPem: string | Buffer): PrivateKey {
    if (typeof privateKeyInDerOrPem === "string") {
        const hidden = createPrivateKeyFromNodeJSCrypto(privateKeyInDerOrPem);
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
