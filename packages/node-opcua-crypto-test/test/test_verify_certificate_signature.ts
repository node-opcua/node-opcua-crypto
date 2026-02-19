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

import { constants, createSign, type SignPrivateKeyInput } from "node:crypto";
import path from "node:path";
import {
    asn1,
    type Certificate,
    type PrivateKey,
    readCertificate,
    readPrivateKey,
    toPem2,
    verifyCertificateSignature,
} from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

function investigateCertificateSignature(certificate: Certificate, caPrivateKey?: PrivateKey): void {
    const block_info = asn1.readTag(certificate, 0);
    const blocks = asn1.readStruct(certificate, block_info);

    const bufferTbsCertificate = certificate.subarray(block_info.position, block_info.position + 4 + blocks[0].length);

    const signatureAlgorithm = asn1.readAlgorithmIdentifier(certificate, blocks[1]);

    const signatureValue = asn1.readSignatureValueBin(certificate, blocks[2]);

    function testPadding(padding: number, saltLength?: number): boolean {
        const sign = createSign(signatureAlgorithm.identifier);
        sign.update(bufferTbsCertificate);
        sign.end();

        const signOption: SignPrivateKeyInput = {
            key: toPem2(caPrivateKey?.hidden || "", "RSA PRIVATE KEY"),
            padding,
        };
        if (saltLength) {
            signOption.saltLength = saltLength;
        }
        const sign1 = sign.sign(signOption);
        if (sign1.toString("hex") === signatureValue.toString("hex")) {
            return true;
        }
        return false;
    }
    expect(testPadding(constants.RSA_PKCS1_PADDING)).toEqual(true);

    // biome-ignore lint/correctness/noConstantCondition: this is for debugging purpose
    if (false) {
        testPadding(constants.RSA_PKCS1_PADDING, constants.RSA_PSS_SALTLEN_MAX_SIGN);
        testPadding(constants.RSA_PKCS1_PSS_PADDING, constants.RSA_PSS_SALTLEN_MAX_SIGN);
        testPadding(constants.RSA_X931_PADDING, constants.RSA_PSS_SALTLEN_MAX_SIGN);

        testPadding(constants.RSA_PKCS1_PADDING, constants.RSA_PSS_SALTLEN_DIGEST);
        testPadding(constants.RSA_PKCS1_PSS_PADDING, constants.RSA_PSS_SALTLEN_DIGEST);
        testPadding(constants.RSA_X931_PADDING, constants.RSA_PSS_SALTLEN_DIGEST);

        testPadding(constants.RSA_PKCS1_PADDING, constants.RSA_PSS_SALTLEN_AUTO);
        testPadding(constants.RSA_PKCS1_PSS_PADDING, constants.RSA_PSS_SALTLEN_AUTO);
        testPadding(constants.RSA_X931_PADDING, constants.RSA_PSS_SALTLEN_AUTO);
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
        expect(verifyCertificateSignature(certificate1, certificate2)).toEqual(true);
    });
    it("WW should verify the signature of a self-signed certificate", () => {
        const certificate2 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/cacert.pem"));
        expect(verifyCertificateSignature(certificate2, certificate2)).toEqual(true);
    });
    it("WW should fail when verifying a signature with the wrong parent certificate ", () => {
        const certificate1 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/1000.pem"));
        const certificate2 = readCertificate(path.join(__dirname, "../test-fixtures/certsChain/wrongcacert.pem"));
        expect(verifyCertificateSignature(certificate1, certificate2)).toEqual(false);
    });
});
