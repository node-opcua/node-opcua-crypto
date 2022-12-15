import { createPublicKey } from "crypto";
import * as path from "path";
import { rsaLengthPublicKey } from "../source";
import { readCertificate, readCertificatePEM } from "../source_nodejs";

describe("rsaLengthPublicKey", () => {
    it("rsaLengthPublicKey - 1024", () => {
        const key = readCertificatePEM(path.join(__dirname,"./fixtures/certs/client_cert_1024.pem"));
        const p = createPublicKey(key);
        rsaLengthPublicKey(p).should.eql(128);
    });
    it("rsaLengthPublicKey - 2048", () => {
        const key = readCertificatePEM(path.join(__dirname,"./fixtures/certs/server_cert_2048.pem"));
        const p = createPublicKey(key);
        rsaLengthPublicKey(p).should.eql(256);
    });
});
