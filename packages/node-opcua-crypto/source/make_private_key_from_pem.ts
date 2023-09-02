

import { PrivateKey } from "./common.js";
export function makePrivateKeyFromPem(privateKeyInPem: string): PrivateKey {
    return { hidden: privateKeyInPem };
}

