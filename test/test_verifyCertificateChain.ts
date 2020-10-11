import * as path from "path";
import { verifyCertificateChain } from "../source";
import { readCertificate } from "../source_nodejs";

describe("Test Certificate Chain", () => {
    it("DX should verify a certificate chain", async () => {
        const certificate1 = readCertificate(path.join(__dirname, "./fixtures/certsChain/1000.pem"));
        const certificate2 = readCertificate(path.join(__dirname, "./fixtures/certsChain/cacert.pem"));
        const certificate3 = readCertificate(path.join(__dirname, "./fixtures/certsChain/wrongcacert.pem"));
        (await verifyCertificateChain([certificate1, certificate2])).status.should.eql("Good");
        (await verifyCertificateChain([certificate2, certificate1])).status.should.eql("BadCertificateInvalid");
        (await verifyCertificateChain([certificate1, certificate3])).should.eql({
            status: "BadCertificateInvalid",
            reason: "One of the certificate in the chain is not signing the previous certificate",
        });
    });
});
