const { exploreCertificateInfo } = require("node-opcua-crypto");

try {
    exploreCertificateInfo(Buffer.from("123"));
} catch (err) {
    console.log(err.message);
}
console.log("OK");
process.exit(0);
