import * as path from "path";
import { convertPEMtoDER, exploreCertificate, explorePrivateKey } from "../source";
import { publicKeyAndPrivateKeyMatches, certificateMatchesPrivateKey } from "../source/public_private_match";
import { readPrivateRsaKey, readPrivateKeyPEM, readCertificate, readPrivateKey } from "../source_nodejs";

const useCases = [1024, 2048];
describe("Checking that public key (from certificate) and private key matches", function () {
    useCases.forEach((keyLength) => {
        const certificateFile = path.join(__dirname, `fixtures/certs/server_cert_${keyLength}.pem`);
        const privateKeyFile = path.join(__dirname, `fixtures/certs/server_key_${keyLength}.pem`);
        const certificate = readCertificate(certificateFile);
        const privateKey = readPrivateKey(privateKeyFile);
        it("publicKeyAndPrivateKeyMatches: should explore a RSA private key " + keyLength, () => {
            const i = exploreCertificate(certificate);
            const j = explorePrivateKey(privateKey);

            //  const ii = readSubjectPublicKey(i.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey);

            const modulus1 = i.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.modulus;
            const modulus2 = j.modulus;

            modulus1.length.should.eql(keyLength / 8);
            modulus1.toString("hex").should.eql(modulus2.toString("hex"));

            publicKeyAndPrivateKeyMatches(certificate, privateKey).should.eql(true);
        });
        it("certificateMatchesPrivateKey: " + keyLength, () => {
            certificateMatchesPrivateKey(certificate, privateKey).should.eql(true);
        });
    });
});
