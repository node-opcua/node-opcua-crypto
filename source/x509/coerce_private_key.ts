import { PrivateKeyPEM } from "../common";
import { getCrypto } from "./_crypto";
import { derToPrivateKey, pemToPrivateKey } from "./create_key_pair";
import { PrivateKey } from "../common";
import { createPrivateKey as createPrivateKeyFromNode } from "crypto";
const crypto = getCrypto();

const doDebug = false;

export function coercePrivateKey(privateKey: PrivateKey | PrivateKeyPEM): PrivateKey {
    if (typeof privateKey === "string") {
        return createPrivateKeyFromNode(privateKey);
    }
    return privateKey;
}

export async function _coercePrivateKey(privateKey: any): Promise<PrivateKey> {
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
