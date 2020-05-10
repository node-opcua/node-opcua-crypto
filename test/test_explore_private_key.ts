import * as path from "path";
import { convertPEMtoDER, explorePrivateKey, readPrivateRsaKey, readPrivateKeyPEM } from "../lib";

describe(" exploring Private Key", function () {
    it("should explore a RSA private key", () => {
        const privateKeyRSA = readPrivateRsaKey(path.join(__dirname, "./fixtures/certs/alice_id_rsa"));

        //  const a = explorePrivateKey(privateKeyRSA);
    });

    it("should explore a private key", () => {
        const privateKeyPEM = readPrivateKeyPEM(path.join(__dirname, "./fixtures/certs/demo_key_4096.pem"));
        const privateKey = convertPEMtoDER(privateKeyPEM);
        const a = explorePrivateKey(privateKey);
    });
});
