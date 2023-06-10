const x509 = require("@peculiar/x509");
import { Crypto } from "@peculiar/webcrypto";

let _crypto: Crypto | undefined;

declare const crypto: any;
declare const window: any;

if (typeof window === "undefined") {
    _crypto = require("crypto");
    if (!_crypto?.subtle) {
        _crypto = new Crypto();
        //xx  console.warn("using @peculiar/webcrypto");
    } else {
        //xx console.warn("using nodejs crypto (native)");
    }
    x509.cryptoProvider.set(_crypto);
} else {
    // using browser crypto
    _crypto = crypto;
    x509.cryptoProvider.set(crypto);
}

interface CryptoInterface {}
export function getCrypto(): Crypto {
    return _crypto || crypto || require("crypto");
}
export * as x509 from "@peculiar/x509";
