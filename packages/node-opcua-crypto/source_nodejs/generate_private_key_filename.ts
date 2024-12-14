// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2024 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so,  subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ---------------------------------------------------------------------------------------------------------------------

import fs from "node:fs";
import { generateKeyPair, privateKeyToPEM } from "../source/index.js";
import jsrsasign from "jsrsasign";
export async function generatePrivateKeyFile(privateKeyFilename: string, modulusLength: 1024 | 2048 | 3072 | 4096) {
    const keys = await generateKeyPair(modulusLength);
    const privateKeyPem = await privateKeyToPEM(keys.privateKey);
    await fs.promises.writeFile(privateKeyFilename, privateKeyPem.privPem, "utf-8");
    privateKeyPem.privPem = "";
    privateKeyPem.privDer = Buffer.alloc(0) as any; // new Uint8Array(0);
}

/**
 * alternate function to generate PrivateKeyFile, using jsrsasign.
 *
 * This function is slower than generatePrivateKeyFile
 */
export async function generatePrivateKeyFileAlternate(privateKeyFilename: string, modulusLength: 2048 | 3072 | 4096) {
    const kp = jsrsasign.KEYUTIL.generateKeypair("RSA", modulusLength);
    const prv = kp.prvKeyObj;
    const pub = kp.pubKeyObj;
    const prvpem = jsrsasign.KEYUTIL.getPEM(prv, "PKCS8PRV");
    // const pubpem = jsrsasign.KEYUTIL.getPEM(pub, "PKCS8PUB");
    await fs.promises.writeFile(privateKeyFilename, prvpem, "utf-8");
}
