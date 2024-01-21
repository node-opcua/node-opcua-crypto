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

import path from "path";
import { exploreCertificate, readCertificate } from "node-opcua-crypto";
import should from "should";

describe("X509ExtKeyUsage", () => {
    it("should parse extKeyUsage 1", () => {
        const certificateFile = path.join(__dirname, "../test-fixtures/certificate_with_extKeyUsage1.pem");
        const certificate = readCertificate(certificateFile);

        const info = exploreCertificate(certificate);
        should.exists(info.tbsCertificate.extensions);
        should.exists(info.tbsCertificate.extensions!.extKeyUsage);

        info.tbsCertificate.extensions!.extKeyUsage!.serverAuth.should.eql(true);
        info.tbsCertificate.extensions!.extKeyUsage!.clientAuth.should.eql(true);
    });
    it("should parse extKeyUsage 2", () => {
        const certificateFile = path.join(__dirname, "../test-fixtures/certificate_with_extKeyUsage2.pem");
        const certificate = readCertificate(certificateFile);

        const info = exploreCertificate(certificate);
        should.exists(info.tbsCertificate.extensions);
        should.exists(info.tbsCertificate.extensions!.extKeyUsage);

        info.tbsCertificate.extensions!.extKeyUsage!.serverAuth.should.eql(true);
        info.tbsCertificate.extensions!.extKeyUsage!.clientAuth.should.eql(true);

        console.log(info.tbsCertificate.extensions!.extKeyUsage!);
    });
});
