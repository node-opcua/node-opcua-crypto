import * as should from "should";
import * as path from "path";
import * as fs from "fs";
import * as util from "util";

import { readCertificate, exploreCertificate, exploreCertificateInfo, combine_der, split_der } from "../lib";

describe(" exploring Certificates", function (this: Mocha.Suite) {
    this.timeout(200000);
    it("should extract the information out of a 1024-bits certificate", () => {
        const certificate = readCertificate(path.join(__dirname, "./fixtures/certs/server_cert_1024.pem"));

        //xx console.log(hexDump(certificate));
        const certificate_info = exploreCertificate(certificate);

        //xx console.log(certificate_info.tbsCertificate);
        console.log(" Version                   : ", certificate_info.tbsCertificate.version);
        console.log(" issuer.commonName         : ", certificate_info.tbsCertificate.issuer.commonName);
        console.log(
            " uniformResourceIdentifier : ",
            certificate_info.tbsCertificate.extensions!.subjectAltName.uniformResourceIdentifier
        );
        console.log(" dNSName                   : ", certificate_info.tbsCertificate.extensions!.subjectAltName.dNSName);

        certificate_info.tbsCertificate.version.should.eql(3);
        certificate_info.tbsCertificate.subjectPublicKeyInfo.keyLength.should.eql(128);
        certificate_info.tbsCertificate.extensions!.subjectAltName.uniformResourceIdentifier.length.should.eql(1);
    });

    it("should extract the information out of a 2048-bits certificate ", () => {
        const certificate = readCertificate(path.join(__dirname, "./fixtures/certs/server_cert_2048.pem"));

        // console.log(hexDump(certificate))
        const certificate_info = exploreCertificate(certificate);

        certificate_info.tbsCertificate.version.should.eql(3);
        certificate_info.tbsCertificate.subjectPublicKeyInfo.keyLength.should.eql(256);
        certificate_info.tbsCertificate.extensions!.subjectAltName.uniformResourceIdentifier.length.should.eql(1);
    });

    it("should extract the information out of a 4096-bits certificate - 1", () => {
        //  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -config toto.cnf -nodes -subj '/CN=localhost' -sha256
        const certificate = readCertificate(path.join(__dirname, "./fixtures/certs/demo_certificate_4096.pem"));

        const certificate_info = exploreCertificate(certificate);

        certificate_info.tbsCertificate.version.should.eql(3);
        certificate_info.tbsCertificate.subjectPublicKeyInfo.keyLength.should.eql(512);
        //xx certificate_info.tbsCertificate.extensions!.subjectAltName.uniformResourceIdentifier.length.should.eql(1);
        const data = exploreCertificate(certificate);
    });

    it("should read a V3 X509 self-certificate (with extensions)", () => {
        const filename = path.join(__dirname, "./fixtures/certs/demo_certificate.pem");
        fs.existsSync(filename).should.equal(true);

        const certificate = readCertificate(filename);
        //xx console.log(certificate.toString("base64"));

        const certificate_info = exploreCertificate(certificate);

        certificate_info.tbsCertificate.version.should.eql(3);

        // console.log(util.inspect(certificate_info,{colors:true,depth:10}));
        //xx console.log("x => ",util.inspect(certificate_info.tbsCertificate.extensions!.authorityCertIssuer,{colors:true,depth:10}));
        certificate_info.tbsCertificate.extensions!.authorityKeyIdentifier!.authorityCertIssuer!.countryName!.should.eql("FR");
        certificate_info.tbsCertificate.extensions!.authorityKeyIdentifier!.authorityCertIssuer!.localityName!.should.eql("Paris");

        console.log(util.inspect(certificate_info, { colors: true, depth: 100 }));

        certificate_info.tbsCertificate.extensions!.subjectKeyIdentifier!.should.eql(
            "74:38:FD:90:B1:F1:90:51:0E:9C:65:D6:AA:AC:63:9E:BC:DC:58:2F"
        );

        if (certificate_info.tbsCertificate.extensions!.authorityKeyIdentifier!.keyIdentifier) {
            // when serial and keyIdentifier are providef the certificate is not self-signed
            should.exist(certificate_info.tbsCertificate.extensions!.authorityKeyIdentifier!.serial);
            should.exist(certificate_info.tbsCertificate.extensions!.authorityKeyIdentifier!.keyIdentifier);
        }
    });
    it("should read a V3 X509 certificate  signed by ta CA (with extensions)", () => {
        const filename = path.join(__dirname, "./fixtures/certsChain/1000.pem");
        fs.existsSync(filename).should.equal(true);

        const certificate = readCertificate(filename);
        //xx console.log(certificate.toString("base64"));

        const certificate_info = exploreCertificate(certificate);

        certificate_info.tbsCertificate.version.should.eql(3);

        // console.log(util.inspect(certificate_info,{colors:true,depth:10}));
        //xx console.log("x => ",util.inspect(certificate_info.tbsCertificate.extensions!.authorityCertIssuer,{colors:true,depth:10}));
        certificate_info.tbsCertificate.extensions!.authorityKeyIdentifier!.authorityCertIssuer!.countryName!.should.eql("FR");
        certificate_info.tbsCertificate.extensions!.authorityKeyIdentifier!.authorityCertIssuer!.localityName!.should.eql("Paris");

        console.log(util.inspect(certificate_info, { colors: true, depth: 100 }));

        certificate_info.tbsCertificate.extensions!.subjectKeyIdentifier!.should.eql(
            "B2:75:61:AF:63:66:27:96:94:52:3F:BD:03:DB:87:01:71:DD:94:19"
        );

        if (certificate_info.tbsCertificate.extensions!.authorityKeyIdentifier!.keyIdentifier) {
            // when serial and keyIdentifier are providef the certificate is not self-signed
            should.exist(certificate_info.tbsCertificate.extensions!.authorityKeyIdentifier!.serial);
            should.exist(certificate_info.tbsCertificate.extensions!.authorityKeyIdentifier!.keyIdentifier);
        }
    });

    it("should read a V1 X509 certificate", () => {
        // note : http://stackoverflow.com/questions/26788244/how-to-create-a-legacy-v1-or-v2-x-509-cert-for-testing

        const filename = path.join(__dirname, "./fixtures/certs/demo_certificate_x509_V1.pem");
        fs.existsSync(filename).should.equal(true, "certificate file must exist");

        const certificate = readCertificate(filename);
        //xx console.log(certificate.toString("base64"));
        const certificate_info = exploreCertificate(certificate);

        certificate_info.tbsCertificate.version.should.eql(1);
        should(certificate_info.tbsCertificate.extensions).eql(null);

        // console.log(util.inspect(certificate_info,{colors:true,depth:10}));
    });
});

describe("exploring certificate chains", () => {
    it("should combine 2 certificates in a single block", () => {
        const cert1_name = path.join(__dirname, "./fixtures/certs/client_cert_1024.pem");
        const cert2_name = path.join(__dirname, "./fixtures/certs/server_cert_1024.pem");

        fs.existsSync(cert1_name).should.eql(true);
        fs.existsSync(cert2_name).should.eql(true);

        const cert1 = readCertificate(cert1_name);
        const cert2 = readCertificate(cert2_name);
        //xx console.log("cert1 = ",cert1.toString("base64"));
        //xx console.log("cert2 = ",cert2.toString("base64"));

        const combined = combine_der([cert1, cert2]);
        combined.toString("hex").should.equal(cert1.toString("hex") + cert2.toString("hex"));

        combined.length.should.eql(cert1.length + cert2.length);

        const chain = split_der(combined);

        chain.length.should.eql(2);

        if (false) {
            console.log(chain[0].toString("hex"));
            console.log(cert1.toString("hex"));
            console.log("-------");
            console.log(chain[1].toString("hex"));
            console.log(cert2.toString("hex"));
        }
        chain[0].length.should.eql(cert1.length);
        chain[1].length.should.eql(cert2.length);

        chain[0].toString("hex").should.eql(cert1.toString("hex"));
        chain[1].toString("hex").should.eql(cert2.toString("hex"));
    });

    it("should combine 3 certificates in a single block", () => {
        const cert1_name = path.join(__dirname, "./fixtures/certs/client_cert_1024.pem");
        const cert2_name = path.join(__dirname, "./fixtures/certs/server_cert_1024.pem");
        const cert3_name = path.join(__dirname, "./fixtures/certs/client_cert_1024.pem");

        fs.existsSync(cert1_name).should.eql(true);
        fs.existsSync(cert2_name).should.eql(true);
        fs.existsSync(cert3_name).should.eql(true);

        const cert1 = readCertificate(cert1_name);
        const cert2 = readCertificate(cert2_name);
        const cert3 = readCertificate(cert3_name);

        const combined = combine_der([cert1, cert2, cert3]);
        combined.toString("hex").should.equal(cert1.toString("hex") + cert2.toString("hex") + cert3.toString("hex"));

        combined.length.should.eql(cert1.length + cert2.length + cert3.length);

        const chain = split_der(combined);

        chain.length.should.eql(3);

        if (false) {
            console.log(chain[0].toString("hex"));
            console.log(cert1.toString("hex"));
            console.log("-------");
            console.log(chain[1].toString("hex"));
            console.log(cert2.toString("hex"));
            console.log("-------");
            console.log(chain[2].toString("hex"));
            console.log(cert3.toString("hex"));
        }
        chain[0].length.should.eql(cert1.length);
        chain[1].length.should.eql(cert2.length);
        chain[2].length.should.eql(cert3.length);

        chain[0].toString("hex").should.eql(cert1.toString("hex"));
        chain[1].toString("hex").should.eql(cert2.toString("hex"));
        chain[2].toString("hex").should.eql(cert3.toString("hex"));
    });
});
