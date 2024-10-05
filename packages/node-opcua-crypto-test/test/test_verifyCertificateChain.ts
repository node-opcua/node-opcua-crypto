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

import path from "node:path";
import { verifyCertificateChain, readCertificate } from "node-opcua-crypto";

describe("Test Certificate Chain", () => {
    it("DX should verify a certificate chain", async () => {
        const certificate1 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/1000.pem"));
        const certificate2 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/cacert.pem"));
        const certificate3 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/wrongcacert.pem"));
        (await verifyCertificateChain([certificate1, certificate2])).status.should.eql("Good");
        (await verifyCertificateChain([certificate2, certificate1])).status.should.eql("BadCertificateInvalid");
        (await verifyCertificateChain([certificate1, certificate3])).should.eql({
            status: "BadCertificateInvalid",
            reason: "One of the certificate in the chain is not signing the previous certificate",
        });
    });
});
