import * as path from "path";
import {
    verifyCertificateRevocationListSignature,
    exploreCertificateRevocationList,
    verifyCertificateSignature,
    exploreCertificate,
    toPem,
} from "../source";
import { readCertificateRevocationList, readCertificate } from "../source_nodejs";

describe("Explore Certificate Revocation List", () => {
    it("should read and explore a PEM revocation list", async () => {
        const crlFilename = path.join(__dirname, "fixtures/crl/certificate_revocation_list3.pem");
        const crl = await readCertificateRevocationList(crlFilename);

        // xx console.log(crl.toString("hex"));
        const crlInfo = exploreCertificateRevocationList(crl);
        crlInfo.tbsCertList.issuerFingerprint.should.eql("67:EB:EB:D2:54:93:17:8B:5F:D7:63:7A:6D:A7:CD:DD:B9:D2:C6:CD");
        crlInfo.tbsCertList.revokedCertificates.length.should.eql(0);
    });
    it("should explore crl1 ", async () => {
        const crlFilename = path.join(__dirname, "fixtures/crl/certificate_revocation_list1.crl");
        const crl = await readCertificateRevocationList(crlFilename);
        // xx console.log(crl.toString("hex"));

        const crlInfo = exploreCertificateRevocationList(crl);
        // console.log(util.inspect(crlInfo, { colors: true, depth: 100 }));

        crlInfo.tbsCertList.issuerFingerprint.should.eql("AF:FE:C7:57:6C:85:65:59:2F:35:C5:21:10:38:8A:2C:62:0C:D5:DD");
        crlInfo.tbsCertList.revokedCertificates.length.should.eql(4);

        crlInfo.tbsCertList.revokedCertificates[0].userCertificate.should.eql("03");
        crlInfo.tbsCertList.revokedCertificates[0].revocationDate.toISOString().should.eql("2019-11-15T09:04:16.000Z");

        crlInfo.tbsCertList.revokedCertificates[1].userCertificate.should.eql("04");
        crlInfo.tbsCertList.revokedCertificates[1].revocationDate.toISOString().should.eql("2019-11-15T09:04:19.000Z");

        crlInfo.tbsCertList.revokedCertificates[2].userCertificate.should.eql("07");
        crlInfo.tbsCertList.revokedCertificates[2].revocationDate.toISOString().should.eql("2019-11-15T09:04:27.000Z");

        crlInfo.tbsCertList.revokedCertificates[3].userCertificate.should.eql("08");
        crlInfo.tbsCertList.revokedCertificates[3].revocationDate.toISOString().should.eql("2019-11-15T09:04:30.000Z");

        crlInfo.signatureAlgorithm.identifier.should.eql("sha256WithRSAEncryption");
        crlInfo.tbsCertList.signature.identifier.should.eql("sha256WithRSAEncryption");
    });
    it("should verify a CRL signature", async () => {
        const crlFilename = path.join(__dirname, "fixtures/crl/certificate_revocation_list1.crl");

        const crl = await readCertificateRevocationList(crlFilename);
        const crlInfo = exploreCertificateRevocationList(crl);

        // console.log(util.inspect(crlInfo, { colors: true, depth: 100 }));

        const issuerCertifcateFile = path.join(__dirname, "fixtures/crl/ctt_ca1I.der");

        const certificateOfIssuer = await readCertificate(issuerCertifcateFile);
        const certificateOfIssuerInfo = await exploreCertificate(certificateOfIssuer);

        // console.log(certificateOfIssuerInfo.tbsCertificate.extensions!.authorityKeyIdentifier?.authorityCertIssuerFingerPrint);
        // console.log(crlInfo.tbsCertList.issuerFingerprint);
        //  console.log(certificateOfIssuerInfo.tbsCertificate.extensions!.authorityKeyIdentifier?.authorityCertIssuer);
        // console.log(crlInfo.tbsCertList.issuer);
        crlInfo.tbsCertList.issuerFingerprint.should.eql("AF:FE:C7:57:6C:85:65:59:2F:35:C5:21:10:38:8A:2C:62:0C:D5:DD");
        certificateOfIssuerInfo.tbsCertificate.extensions!.authorityKeyIdentifier?.authorityCertIssuerFingerPrint.should.eql(
            "AF:FE:C7:57:6C:85:65:59:2F:35:C5:21:10:38:8A:2C:62:0C:D5:DD"
        );
        certificateOfIssuerInfo.tbsCertificate.subjectFingerPrint.should.eql(
            "AF:FE:C7:57:6C:85:65:59:2F:35:C5:21:10:38:8A:2C:62:0C:D5:DD"
        );

        verifyCertificateSignature(certificateOfIssuer, certificateOfIssuer);

        verifyCertificateRevocationListSignature(crl, certificateOfIssuer).should.eql(true);
    });
    it("should load a crl PEM", async () => {
        const crlFilename = path.join(__dirname, "fixtures/crl/certificate_revocation_list4.pem");
        const crl = await readCertificateRevocationList(crlFilename);
        const crlInfo = await exploreCertificateRevocationList(crl);
        console.log(crlInfo);
    });

    it("should convert a DER CRL to PEM", async () => {
        const crlFilename = path.join(__dirname, "fixtures/crl/certificate_revocation_list1.crl");
        const crl = await readCertificateRevocationList(crlFilename);

        const crlPem = toPem(crl, "X509 CRL");
        crlPem.should.match(/BEGIN X509 CRL/);
    });
});
