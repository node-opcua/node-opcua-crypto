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

import path from "path";
import crypto from "crypto";
import { verifyCertificateSignature, Certificate, PrivateKey, toPem } from "..";
import { readTag, _readStruct, _readAlgorithmIdentifier, _readSignatureValueBin } from "..";
import { readCertificate, readPrivateKey } from "..";

function ellipsis(str: string): string {
    return str.substr(0, 16) + "[...]" + str.substr(-16);
}
export function investigateCertificateSignature(certificate: Certificate, caPrivateKey?: PrivateKey): void {
    const block_info = readTag(certificate, 0);
    const blocks = _readStruct(certificate, block_info);

    //  console.log(block_info, blocks[0], blocks[1], blocks[2]);
    const bufferTbsCertificate = certificate.slice(block_info.position, block_info.position + 4 + blocks[0].length);

    // console.log("bufferTbsCertificate = ", bufferTbsCertificate.length);
    const signatureAlgorithm = _readAlgorithmIdentifier(certificate, blocks[1]);

    const signatureValue = _readSignatureValueBin(certificate, blocks[2]);
    // console.log("SIGV", ellipsis(signatureValue.toString("hex")), signatureValue.length);

    function testPadding(padding: number, saltLength?: number): boolean {
        const sign = crypto.createSign(signatureAlgorithm.identifier);
        sign.update(bufferTbsCertificate);
        // verify.update(bufferSignatureAlgo);
        sign.end();

        const signOption: crypto.SignPrivateKeyInput = {
            key: toPem(caPrivateKey!, "RSA PRIVATE KEY"),
            padding,
        };
        // the following circumvolution is needed to make it work with node< 12
        if (saltLength) {
            signOption.saltLength = saltLength;
        }
        const sign1 = sign.sign(signOption);
        // console.log("RRR=", padding, saltLength, ellipsis(sign1.toString("hex")), sign1.length);
        if (sign1.toString("hex") === signatureValue.toString("hex")) {
            //  console.log("Found !!!!! => see below");
            return true;
        }
        return false;
    }
    testPadding(crypto.constants.RSA_PKCS1_PADDING).should.eql(true);
    if (false) {
        testPadding(crypto.constants.RSA_PKCS1_PADDING, crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN);
        testPadding(crypto.constants.RSA_PKCS1_PSS_PADDING, crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN);
        testPadding(crypto.constants.RSA_X931_PADDING, crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN);

        testPadding(crypto.constants.RSA_PKCS1_PADDING, crypto.constants.RSA_PSS_SALTLEN_DIGEST);
        testPadding(crypto.constants.RSA_PKCS1_PSS_PADDING, crypto.constants.RSA_PSS_SALTLEN_DIGEST);
        testPadding(crypto.constants.RSA_X931_PADDING, crypto.constants.RSA_PSS_SALTLEN_DIGEST);

        testPadding(crypto.constants.RSA_PKCS1_PADDING, crypto.constants.RSA_PSS_SALTLEN_AUTO);
        testPadding(crypto.constants.RSA_PKCS1_PSS_PADDING, crypto.constants.RSA_PSS_SALTLEN_AUTO);
        testPadding(crypto.constants.RSA_X931_PADDING, crypto.constants.RSA_PSS_SALTLEN_AUTO);
        // testPadding(crypto.constants.RSA_NO_PADDING);
    }
}

describe("Verify Certificate Signature", () => {
    it("WW investigate how certificate signature is build", () => {
        const certificate1 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/1000.pem"));
        const caPrivateKey = readPrivateKey(path.join(__dirname, "../test-fixtures/certsChain/cakey.pem"));
        investigateCertificateSignature(certificate1, caPrivateKey);
    });

    it("WW should verify the signature of certificate signed by a CA", () => {
        const certificate1 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/1000.pem"));
        const certificate2 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/cacert.pem"));
        verifyCertificateSignature(certificate1, certificate2).should.eql(true);
    });
    it("WW should verify the signature of a self-signed certificate", () => {
        const certificate2 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/cacert.pem"));
        verifyCertificateSignature(certificate2, certificate2).should.eql(true);
    });
    it("WW should fail when verifying a signature with the wrong parent certificate ", () => {
        const certificate1 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/1000.pem"));
        const certificate2 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/wrongcacert.pem"));
        verifyCertificateSignature(certificate1, certificate2).should.eql(false);
    });
});
