import { exploreCertificateInfo } from "node-opcua-crypto/web";
// eslint-disable-next-line no-undef

try {
    exploreCertificateInfo(Buffer.from("123"));
} catch (err) {
    console.log(err.message);
}
console.log("OK");
process.exit(0);
