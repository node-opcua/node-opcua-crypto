import * as path from "path";
import { exploreCertificateSigningRequest } from "../source/explore_certificate_signing_request";

import { readCertificateSigningRequest } from "../source_nodejs";

const doDebug = !!process.env.DEBUG;


describe("Explore Certificate Signing Request", () => {
    it("ECSR1- should read and explore a Certificate Signing Request", async () => {
        const csr1Filename = path.join(__dirname, "fixtures/csr/csr1.pem");
        const csr1 = await readCertificateSigningRequest(csr1Filename);

        const csrInfo = exploreCertificateSigningRequest(csr1);
        
        csrInfo.extensionRequest.subjectAltName.should.eql({
            uniformResourceIdentifier: [
                "urn:Some-Fake-Server-1"
            ],
            dNSName: [
                "DESKTOP-6P074LR"
            ]
        });

        if (doDebug) {
            console.log(JSON.stringify(csrInfo,null, " "));
        }
    });

});
