import type { PrivateKey } from "./common.js";
export function makePrivateKeyThumbPrint(_privateKey: PrivateKey): Buffer {
    //   // .export({ format: "der", type: "pkcs1" });
    //   if (typeof privateKey === "string") {
    //
    //   } else {
    //    return makeSHA1Thumbprint(privateKey.hidden);
    //   }
    // to do
    return Buffer.alloc(0);
}
