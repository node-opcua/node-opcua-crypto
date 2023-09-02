// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2023 - Sterfive.com
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

import fs from "fs";
import os from "os";
import path from "path";

import  * as loremIpsum from "lorem-ipsum";
import "should";

import { exploreCertificateInfo, makeSHA1Thumbprint, readCertificatePEM, removeTrailingLF, split_der, toPem } from "node-opcua-crypto";
import { readCertificate } from "node-opcua-crypto";


// tslint:disable:no-var-requires
const loremIpsumTxt = (loremIpsum as any).loremIpsum({ units: "words", count: 100 });
loremIpsumTxt.length.should.be.greaterThan(100);

function make_lorem_ipsum_buffer() {
    return Buffer.from(loremIpsumTxt);
}

describe("Crypto utils", function () {
    it("should read a PEM file", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/certs/demo_certificate.pem"));

        certificate
            .toString("base64")
            .should.equal(
                "MIIEVTCCAz2gAwIBAgICEJEwDQYJKoZIhvcNAQELBQAwgY4xCzAJBgNVBAYTAkZS" +
                    "MQwwCgYDVQQIDANJREYxDjAMBgNVBAcMBVBhcmlzMUIwQAYDVQQKDDlGYWtlIE5v" +
                    "ZGVPUENVQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAoZm9yIHRlc3Rpbmcgb25s" +
                    "eSkxHTAbBgNVBAMMFG5vZGUtb3BjdWEuZ2l0aHViLmlvMB4XDTEzMDIxNDE0Mjgx" +
                    "NVoXDTEzMDIyNDE0MjgxNVowMzESMBAGA1UEChMJTm9kZU9QQ1VBMR0wGwYDVQQD" +
                    "ExR1cm46Tm9kZU9QQ1VBLVNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC" +
                    "AQoCggEBAJVeDuZfyHyqJYN9mIfl1TqvaepCSPf4cyU9dRpx+hxciLNzmK7paObL" +
                    "/QC8EvY41FIUJOtGMBJeAaZ7loBWNdX2kPA53ImxfJS7GfPqF2wQczdLzC+ToVFR" +
                    "fc5X5415pX2Hnjl4ecWs3yOP99QFjiz4FoK0dL80VJed1BgdLIIHcK59g3AWekcF" +
                    "nm6xBvkdOlO7w5iGjYzP0F/xxf//32OicQnDCjSTe+D1nZtGZzEGv3GD5MD7p8kc" +
                    "p8I5NRI8C+kLCKJRMO3xsZ0ve9hhpskg+PpeF+C3IsdTAyp0mCf3SpIBcuu1zhNI" +
                    "+B5ZGpmTmqqeesZE69GZWwnCLiYbzq8CAwEAAaOCARUwggERMAkGA1UdEwQCMAAw" +
                    "HQYDVR0OBBYEFHQ4/ZCx8ZBRDpxl1qqsY5683FgvMIGtBgNVHSMEgaUwgaKhgZSk" +
                    "gZEwgY4xCzAJBgNVBAYTAkZSMQwwCgYDVQQIDANJREYxDjAMBgNVBAcMBVBhcmlz" +
                    "MUIwQAYDVQQKDDlGYWtlIE5vZGVPUENVQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0" +
                    "eSAoZm9yIHRlc3Rpbmcgb25seSkxHTAbBgNVBAMMFG5vZGUtb3BjdWEuZ2l0aHVi" +
                    "LmlvggkA3if7nVaKKTUwKgYDVR0RBCMwIYYUdXJuOk5vZGVPUENVQS1TZXJ2ZXKC" +
                    "CWxvY2FsaG9zdDAJBgNVHRIEAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCIJU3XnCT9" +
                    "2MBGtWZYeGQtK4kBRIDQiEI0uiT+CDvtIkv/KbqSHBNq04jA9FcwKWwhoI+DCQvj" +
                    "yhkdfAb7i4qkd0lq8p/GI9MWpL50k9Rg0Ak/eAjwTSuDNRB1KzMlZtn/+D6fGZbR" +
                    "hupROculSJ749son0sP1rBvdJEyKN9v9jQf2nv6jo9wytJKM+VslEMCeBzGhi1n6" +
                    "FYHX/e3jaMAQAdkyq9aIQYaHyVQxOBy98B5usZclZ7ry6xf/Rb9bOOP8c61tBQ9k" +
                    "SXDGOBbNHWyWf+DqquMvwN0+Ud/n6hhDexyiShstLhKK1gMNpO6ftMZO80HdI/sm" +
                    "ynbBVHaSnuA9"
            );
    });

    it("should read a certificate chain", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/certs/demo_certificate_chain.pem"));

        const arrayCertificate = split_der(certificate);

        arrayCertificate.length.should.eql(3);
    });

    it("ZZ should read a certificate chain - write and read it again", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/certs/demo_certificate_chain.pem"));

        const t = toPem(certificate, "CERTIFICATE");

        const certificate_one_blob = path.join(os.tmpdir(), "./tmp.pem");
        fs.writeFileSync(certificate_one_blob, t, "ascii");
        const certificate2 = readCertificate(certificate_one_blob);

        certificate.toString("base64").should.eql(certificate2.toString("base64"));
    });

    it("makeSHA1Thumbprint should produce a 20-byte thumbprint ", () => {
        const buf = make_lorem_ipsum_buffer();

        const digest = makeSHA1Thumbprint(buf);

        digest.should.be.instanceOf(Buffer);

        digest.length.should.eql(20); // SHA1 should condensed to 160 bits
    });

    it("toPem should return a string if provided certificate is a buffer containing a PEM string", () => {
        const certificate = fs.readFileSync(path.join(__dirname, "../test-fixtures/certs/cert1.pem"), "binary");
        const pemCertificate = toPem(certificate, "CERTIFICATE");
        pemCertificate.should.be.type('string');
    });

    it("toPem should return a certificate directly if provided certificate is PEM string", () => {
        const certificate = readCertificatePEM(path.join(__dirname, "../test-fixtures/certs/cert1.pem"));
        const pemCertificate = toPem(certificate, "CERTIFICATE");
        pemCertificate.should.eql(removeTrailingLF(certificate));
    });
});

describe("exploreCertificate", () => {
    it("should explore a 1024 bits RSA certificate", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/certs/server_cert_1024.pem"));
        const data = exploreCertificateInfo(certificate);
        data.publicKeyLength.should.eql(128);
        data.notAfter.should.be.instanceOf(Date);
        data.notBefore.should.be.instanceOf(Date);
    });
    it("should explore a 2048 bits RSA certificate", () => {
        const certificate = readCertificate(path.join(__dirname, "../test-fixtures/certs/server_cert_2048.pem"));
        const data = exploreCertificateInfo(certificate);
        data.publicKeyLength.should.eql(256);
        data.notAfter.should.be.instanceOf(Date);
        data.notBefore.should.be.instanceOf(Date);
    });
});
