import nativeCrypto from "node:crypto";
import { Crypto as PeculiarWebCrypto } from "@peculiar/webcrypto";
import * as x509 from "@peculiar/x509";

const doDebug = false;

let _crypto: PeculiarWebCrypto | typeof nativeCrypto | undefined;

declare const crypto: typeof nativeCrypto;
declare const window: unknown;

const ignoreCrypto = process.env.IGNORE_SUBTLE_FROM_CRYPTO;

if (typeof window === "undefined") {
    _crypto = nativeCrypto;

    if (!_crypto?.subtle || ignoreCrypto) {
        _crypto = new PeculiarWebCrypto();
        doDebug && console.warn("using @peculiar/webcrypto");
    } else {
        doDebug && console.warn("using nodejs crypto (native)");
    }
    x509.cryptoProvider.set(_crypto as Crypto);
} else {
    // using browser crypto
    doDebug && console.warn("using browser crypto (native)");
    _crypto = crypto;
    x509.cryptoProvider.set(crypto as Crypto);
}

export function getCrypto(): PeculiarWebCrypto | typeof nativeCrypto {
    return _crypto || crypto || nativeCrypto;
}
export * as x509 from "@peculiar/x509";
