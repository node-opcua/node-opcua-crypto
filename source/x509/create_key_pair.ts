import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";
const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

// ---------------------------------------------------------

interface KeyAlgorithm {
    name: string;
}
type KeyType = "private" | "public" | "secret";
type KeyUsage = "decrypt" | "deriveBits" | "deriveKey" | "encrypt" | "sign" | "unwrapKey" | "verify" | "wrapKey";

/**
 * The CryptoKey dictionary of the Web Crypto API represents a cryptographic key.
 * Available only in secure contexts.
 */
interface CryptoKey {
    readonly algorithm: KeyAlgorithm;
    readonly extractable: boolean;
    readonly type: KeyType;
    readonly usages: KeyUsage[];
}
interface CryptoKeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

// ---------------------------------------------------------

export async function generateKeyPair(modulusLength: 1024 | 2048 | 3072 | 4096 = 2048): Promise<CryptoKeyPair> {
    const alg: RsaHashedKeyGenParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength,
    };
    const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

    return keys;
}

export async function generatePrivateKey(modulusLength: 1024 | 2048 | 3072 | 4096 = 2048): Promise<CryptoKey> {
    return (await generateKeyPair(modulusLength)).privateKey;
}

export async function privateKeyToPEM(privateKey: CryptoKey) {
    const privDer = await crypto.subtle.exportKey("pkcs8", privateKey);
    const privPem = x509.PemConverter.encode(privDer, "PRIVATE KEY");
    return { privPem, privDer };
}

export async function derToPrivateKey(privDer: ArrayBuffer): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
        "pkcs8",
        privDer,
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: { name: "SHA-256" },
        },
        true,
        ["sign", "encrypt", "decrypt", "verify", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
    );
}

export async function pemToPrivateKey(pem: string): Promise<CryptoKey> {
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
    const privDer = x509.PemConverter.decode(pem);
    return derToPrivateKey(privDer[0]);
}
