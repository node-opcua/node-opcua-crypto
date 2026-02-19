// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
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

import { createPublicKey } from "node:crypto";
import path from "node:path";
import { readCertificatePEM, rsaLengthPublicKey } from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

describe("rsaLengthPublicKey", () => {
    it("rsaLengthPublicKey - 1024", () => {
        const key = readCertificatePEM(path.join(__dirname, "../test-fixtures/certs/client_cert_1024.pem"));
        const p = createPublicKey(key);
        expect(rsaLengthPublicKey(p)).toEqual(128);
    });
    it("rsaLengthPublicKey - 2048", () => {
        const key = readCertificatePEM(path.join(__dirname, "../test-fixtures/certs/server_cert_2048.pem"));
        const p = createPublicKey(key);
        expect(rsaLengthPublicKey(p)).toEqual(256);
    });
});
