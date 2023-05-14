import { cryptoProvider } from "@peculiar/x509";

// https://stackoverflow.com/questions/56807959/generate-public-key-from-private-key-using-webcrypto-api
export async function buildPublicKey(privateKey: CryptoKey): Promise<CryptoKey> {
    const crypto = cryptoProvider.get();

    // export private key to JWK
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);

    // remove private data from JWK
    delete jwk.d;
    delete jwk.dp;
    delete jwk.dq;
    delete jwk.q;
    delete jwk.qi;
    jwk.key_ops = ["encrypt", "wrapKey"];

    // import public key
    const publicKey = await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-512" }, true, [
        "encrypt",
        "wrapKey",
    ]);

    return publicKey;
}
