import * as path from "path";
import {
    verifyCertificateRevocationListSignature,
    exploreCertificateRevocationList,
    verifyCertificateSignature,
    exploreCertificate,
    toPem,
    exploreCertificateInfo,
} from "../source";
import { readCertificateRevocationList, readCertificate } from "../source_nodejs";
import * as should from "should";

describe("ExtKeyUsage", () => {
    it("should parse extKeyUsage 1", () => {
        const certificateFile = path.join(__dirname, "./fixtures/certificate_with_extKeyUsage1.pem");
        const certificate = readCertificate(certificateFile);

        const info = exploreCertificate(certificate);
        should.exists(info.tbsCertificate.extensions);
        should.exists(info.tbsCertificate.extensions!.extKeyUsage);

        info.tbsCertificate.extensions!.extKeyUsage!.serverAuth.should.eql(true);
        info.tbsCertificate.extensions!.extKeyUsage!.clientAuth.should.eql(true);
    });
    it("should parse extKeyUsage 2", () => {
        const certificateFile = path.join(__dirname, "./fixtures/certificate_with_extKeyUsage2.pem");
        const certificate = readCertificate(certificateFile);

        const info = exploreCertificate(certificate);
        should.exists(info.tbsCertificate.extensions);
        should.exists(info.tbsCertificate.extensions!.extKeyUsage);

        info.tbsCertificate.extensions!.extKeyUsage!.serverAuth.should.eql(true);
        info.tbsCertificate.extensions!.extKeyUsage!.clientAuth.should.eql(true);

        console.log(info.tbsCertificate.extensions!.extKeyUsage!);
    });
});
