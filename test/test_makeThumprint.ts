import * as path from "path";
import { makeSHA1Thumbprint } from "../source";
import { readCertificate } from "../source_nodejs";

describe("makeSHA1Thumbprint", () => {
    it("should calculate a certificate SHA1-thumbprint", () => {
        const cert = readCertificate(path.join(__dirname, "fixtures/NodeOPCUA [40BA2E8A5BEEC90067A7E554C5F3F2ECDD5BCDDF].der"));
        const thumbprint = makeSHA1Thumbprint(cert);
        thumbprint.toString("hex").toUpperCase().should.eql("40BA2E8A5BEEC90067A7E554C5F3F2ECDD5BCDDF");
    });
});
