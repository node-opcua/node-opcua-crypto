

import { PrivateKey } from "./common";
export function makePrivateKeyFromPem(privateKeyInPem: string): PrivateKey {
    return { hidden: privateKeyInPem };
}

