import nativeCrypto from "node:crypto";
import { Crypto as PeculiarWebCrypto } from "@peculiar/webcrypto";
// @peculiar/x509 v2+ uses tsyringe which requires this polyfill
import "reflect-metadata";
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

/**
 * `@peculiar/x509`'s `toString("pem")` (and `PemConverter.encode`) never
 * terminate their output with a trailing newline, unlike openssl CLI's PEM
 * output, which always does. Code that concatenates PEM blocks by simple
 * string concatenation — exactly what a certificate-chain file is — relies
 * on each block already ending in "\n"; without it, two blocks glue
 * together at the `-----END ... ----------BEGIN ... -----` boundary with
 * no separator, corrupting the file. Every PEM string this package returns
 * goes through this so that never happens regardless of the caller.
 */
export function ensurePemTrailingNewline(pem: string): string {
    return pem.endsWith("\n") ? pem : `${pem}\n`;
}
