

import { PrivateKey, KeyObject, createPrivateKeyFromNodeJSCrypto } from "../common.js";
import { getCrypto } from "./_crypto.js";
import { derToPrivateKey, pemToPrivateKey } from "./create_key_pair.js";


const crypto = getCrypto();

const doDebug = false;

export function coercePEMorDerToPrivateKey(privateKeyInDerOrPem: string| Buffer ): PrivateKey {
    if (typeof privateKeyInDerOrPem === "string") {
        const hidden = createPrivateKeyFromNodeJSCrypto(privateKeyInDerOrPem);
        return { hidden};
    }
    //istanbul ignore next
    throw new Error("not implemented");
    // return privateKey.hidden;
}

export async function _coercePrivateKey(privateKey: any): Promise<KeyObject> {
    const KeyObject = (crypto as any).KeyObject;
    if (privateKey instanceof Buffer) {
        const privateKey1 = await derToPrivateKey(privateKey); //
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
    } else if (privateKey instanceof KeyObject) {
        return privateKey;
    }
    throw new Error("Invalid privateKey");
}
