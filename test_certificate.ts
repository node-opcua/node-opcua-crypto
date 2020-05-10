// tslint:disable: no-console
import * as fs from "fs";
import { exploreCertificate, readCertificate } from ".";

async function test_certificate(filename: string): Promise<void> {
    const cert1 = await readCertificate(filename);
    try {
        const info = exploreCertificate(cert1);
        //        console.log(info);
    } catch (err) {
        console.log(filename, "err = ", err.message);
    }
}
async function test_certificate1(filename: string): Promise<void> {
    const cert1 = fs.readFileSync(filename);
    try {
        const info = exploreCertificate(cert1 as any as Buffer);
        //        console.log(info);
    } catch (err) {
        console.log(filename, "err = ", err.message);
        console.log(err);
        throw err;
    }
}

(async () => {

    try {
        test_certificate1("./read.cer");
        test_certificate1("./unsol.cer");
        test_certificate1("./write.cer");
    } catch (err) {
        console.log("???? ERR !!!! ", err.message);
    }
})();
