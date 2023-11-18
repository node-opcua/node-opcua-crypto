const { exploreCertificateInfo } = require("../../node-opcua-crypto");
// eslint-disable-next-line no-undef


try {
    exploreCertificateInfo(Buffer.from("123"));
} catch (err) {
    console.log(err.message);
}
console.log("OK");
