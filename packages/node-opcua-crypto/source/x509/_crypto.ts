import * as x509 from "@peculiar/x509";

import { Crypto as PeculiarWebCrypto } from "@peculiar/webcrypto";
import nativeCrypto from "crypto";

let _crypto: PeculiarWebCrypto | undefined;

declare const crypto: any;
declare const window: any;

const ignoreCrypto = process.env.IGNORE_SUBTLE_FROM_CRYPTO;

if (typeof window === "undefined") {
    _crypto = nativeCrypto as any;
    
    if (!_crypto?.subtle || ignoreCrypto) {
        _crypto = new PeculiarWebCrypto();
        console.warn("using @peculiar/webcrypto");
    } else {
        console.warn("using nodejs crypto (native)");
    }
    x509.cryptoProvider.set(_crypto);
} else {
    // using browser crypto
    console.warn("using browser crypto (native)");
    _crypto = crypto;
    x509.cryptoProvider.set(crypto);
}

interface CryptoInterface {}
export function getCrypto(): PeculiarWebCrypto {
    return _crypto || crypto || require("crypto");
}
export * as x509 from "@peculiar/x509";
