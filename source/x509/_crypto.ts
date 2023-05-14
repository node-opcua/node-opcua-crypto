import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";
export const crypto = new Crypto();
x509.cryptoProvider.set(crypto);
export * as x509 from "@peculiar/x509";
