import * as path from "path";
import { convertPEMtoDER, exploreCertificate, explorePrivateKey } from "../source";
import { publicKeyAndPrivateKeyMatches } from "../source/public_private_match";
import { readPrivateRsaKey, readPrivateKeyPEM, readCertificate } from "../source_nodejs";

describe("Checking that public key (from certificate) and private key matches", function () {

    const certificateFile = path.join(__dirname,"fixtures/certs/server_cert_1024.pem");
    const certificate = readCertificate(certificateFile);
    const privateKeyFile = path.join(__dirname, "fixtures/certs/server_key_1024.pem");
    const privateKeyPEM = readPrivateKeyPEM(privateKeyFile);
    const privateKey = convertPEMtoDER(privateKeyPEM);
    
    it("should explore a RSA private key", () => {
    
        const i = exploreCertificate(certificate);
        const j = explorePrivateKey(privateKey);

      //  const ii = readSubjectPublicKey(i.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey);

        const modulus1 = i.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.modulus;
        const modulus2 = j.modulus;
        
        modulus1.length.should.eql(1024/8);
        modulus1.toString("hex").should.eql(modulus2.toString("hex"));

        publicKeyAndPrivateKeyMatches(certificate, privateKey).should.eql(true);
    });

});
