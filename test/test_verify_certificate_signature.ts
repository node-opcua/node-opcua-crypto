
import * as path from "path";
import { readCertificate, Certificate, PrivateKey, readTag, readStruct, read_AlgorithmIdentifier, read_SignatureValueBin, toPem } from "../lib";
import * as crypto from "crypto";
import { verifyCertificateSignature } from "../lib/verify_cerficate_signature";
import { readPrivateKey } from "../dist";

function ellipsys(str: string): string {
    return str.substr(0, 16) + "[...]" + str.substr(-16);
}
export function investigateCertificateSignature(
    certificate: Certificate,
    caPrivateKey?: PrivateKey
) {

    const block_info = readTag(certificate, 0);
    const blocks = readStruct(certificate, block_info);

    //  console.log(block_info, blocks[0], blocks[1], blocks[2]);
    const bufferTbsCertificate = certificate.slice(block_info.position, block_info.position + 4 + blocks[0].length);

    console.log("bufferTbsCertificate = ", bufferTbsCertificate.length);
    const signatureAlgorithm = read_AlgorithmIdentifier(certificate, blocks[1]);

    const signatureValue = read_SignatureValueBin(certificate, blocks[2]);
    console.log("SIGV", ellipsys(signatureValue.toString("hex")), signatureValue.length);

    function testPadding(padding: number, saltLength?: number): boolean {
        const sign = crypto.createSign(signatureAlgorithm.identifier);
        sign.update(bufferTbsCertificate);
        // verify.update(bufferSignatureAlgo);
        sign.end();
        const sign1 = sign.sign({
            key: toPem(caPrivateKey!, "RSA PRIVATE KEY"),
            padding,
            //            saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
            // saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            saltLength
        });
        console.log("RRR=", padding, saltLength, ellipsys(sign1.toString("hex")), sign1.length);
        if (sign1.toString("hex") === signatureValue.toString("hex")) {
            console.log("Found !!!!! => see below");
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

describe("Verify Certifcate Signature", () => {

    it("WW investiagate how certificate signature is build", () => {
        const certificate1 = readCertificate(path.join(__dirname, "./fixtures/certsChain/1000.pem"));
        const caPrivateKey = readPrivateKey(path.join(__dirname, "./fixtures/certsChain/cakey.pem"));
        investigateCertificateSignature(certificate1, caPrivateKey);
    });

    it("WW should verify the signature of certificate signed by a CA", () => {
        const certificate1 = readCertificate(path.join(__dirname, "./fixtures/certsChain/1000.pem"));
        const certificate2 = readCertificate(path.join(__dirname, "./fixtures/certsChain/cacert.pem"));
        verifyCertificateSignature(certificate1, certificate2).should.eql(true);
    });
    it("WW should verify the signature of a self-signed certificate", () => {
        const certificate2 = readCertificate(path.join(__dirname, "./fixtures/certsChain/cacert.pem"));
        verifyCertificateSignature(certificate2, certificate2).should.eql(true);
    });
    it("WW should fail when verifying a signature with the wrong parent certificate ", () => {
        const certificate1 = readCertificate(path.join(__dirname, "./fixtures/certsChain/1000.pem"));
        const certificate2 = readCertificate(path.join(__dirname, "./fixtures/certsChain/wrongcacert.pem"));
        verifyCertificateSignature(certificate1, certificate2).should.eql(false);
    });

});