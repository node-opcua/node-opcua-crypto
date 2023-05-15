/* eslint-disable no-undef */
var global = global || window;

import { generatePrivateKey, privateKeyToPEM, CertificatePurpose, createSelfSignedCertificate } from "../dist-esm/source/index.js";

export async function demonstratePrivateKeyAndSelfSignedCertificateCreation() {

    // create the Private Key
    const privateKey = await generatePrivateKey();
    const { privPem } = await privateKeyToPEM(privateKey);
    console.log(privPem);

    // create a self-sign certificate
    const { cert } = await createSelfSignedCertificate({
        privateKey,
        notAfter: new Date(2020, 1, 1),
        notBefore: new Date(2019, 1, 1),
        subject: "CN=Test",
        dns: ["DNS1", "DNS2"],
        ip: ["192.168.1.1"],
        applicationUri: "urn:HOSTNAME:ServerDescription",
        purpose: CertificatePurpose.ForApplication,
    });
    console.log(cert);
}

console.log("Hello World! we are going to create a RSA Private key in PKCS8 PEM Format and a X509 OPCUA Self-Signed Certificate! ");
demonstratePrivateKeyAndSelfSignedCertificateCreation();
