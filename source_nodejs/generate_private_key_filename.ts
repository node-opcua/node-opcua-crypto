import * as fs from "fs";
import { generateKeyPair, privateKeyToPEM } from "../source";

export async function generatePrivateKeyFile(privateKeyFilename: string, modulusLength: 1024 |2048| 3072| 4096) {
    const keys = await generateKeyPair(modulusLength);
    const privateKeyPem = await privateKeyToPEM(keys.privateKey);
    await fs.promises.writeFile(privateKeyFilename, privateKeyPem.privPem);
    privateKeyPem.privPem = "";
    privateKeyPem.privDer = new Uint8Array(0);
}
