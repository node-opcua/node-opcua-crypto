import { exploreCertificateInfo } from "node-opcua-crypto/web";


try {
    exploreCertificateInfo(Buffer.from("123"));
} catch (err) {
    console.log(err.message);
}
console.log("OK");
process.exit(0);
