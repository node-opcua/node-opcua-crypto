/* eslint-disable no-undef */
// declare const global: any;

import {
    generatePrivateKey,
    privateKeyToPEM,
    CertificatePurpose,
    createSelfSignedCertificate,
    exploreCertificateInfo,
    convertPEMtoDER,
    exploreCertificate,
    makePrivateKeyFromPem,
    rsaLengthPrivateKey,
    makeMessageChunkSignature,
    PrivateKey,
    toPem,
    Signature,
    Certificate,
    verifyMessageChunkSignature,
    publicEncrypt_native,
    privateDecrypt_native,
    extractPublicKeyFromCertificateSync,
} from "node-opcua-crypto/web";

let privateKey: CryptoKey | undefined;
export async function makeSelfSignedCertificate({
    subject,
    applicationUri,
    dns,
    ip,
    privateKey,
}: {
    applicationUri: string;
    subject: string;
    dns: string[];
    ip: string[];
    privateKey: CryptoKey;
}) {
    // create a self-sign certificate
    const { cert } = await createSelfSignedCertificate({
        privateKey,
        notAfter: new Date(2020, 1, 1),
        notBefore: new Date(2019, 1, 1),
        subject,
        dns,
        ip,
        applicationUri,
        purpose: CertificatePurpose.ForApplication,
    });

    return { privateKey, selfSignedCertificate: cert };
}

console.log("Hello World! Let's  create a Private key in PKCS8 PEM Format and a X509 OPCUA Self-Signed Certificate! ");

declare const window: any;
declare const document: any;

window.addEventListener("load", (event) => {
    console.log("page is fully loaded");
    document.getElementById("generate").addEventListener("click", generate);
});

async function generate(event) {
    event.preventDefault();
    const keySize = document.getElementById("keySize").value;
    const applicationUri = document.getElementById("applicationUri").value;
    const subject = document.getElementById("subject").value;
    const dns = (document.getElementById("dns").value || "").split(";").filter((a: string) => !!a);
    const ip = (document.getElementById("ip").value || "").split(";").filter((a: string) => !!a);
    const validKeySizes = ["1024", "2048", "4096", "3072"];
    if (validKeySizes.indexOf(keySize) === -1) {
        alert(" Invalid key size " + keySize + "\n expected " + validKeySizes.join(" , "));
        return;
    }
    console.log("key size       =", keySize);
    console.log("applicationUri =", applicationUri);
    console.log("dnsNames       =", dns);
    console.log("ipAddresses    =", ip);

    if (!privateKey) {
        privateKey = await generatePrivateKey(keySize);
    }
    const { selfSignedCertificate } = await makeSelfSignedCertificate({
        subject,
        applicationUri,
        dns,
        ip,
        privateKey,
    });
    const { privPem } = await privateKeyToPEM(privateKey);

    document.getElementById("privateKey").innerHTML = `<pre>${privPem}</pre>`;
    document.getElementById("certificate").innerHTML = `<pre>${selfSignedCertificate}</pre>`;

    const info = exploreCertificate(convertPEMtoDER(selfSignedCertificate));
    const subjectPublicKey = info.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey;
    (subjectPublicKey as any).modulus = subjectPublicKey.modulus.toString("hex");

    document.getElementById("info").innerHTML = `<pre>${JSON.stringify(info, null, " ")}</pre>`;

    const logTest = testEncryptionDecryption(privPem, selfSignedCertificate);

    document.getElementById("info2").innerHTML = `<pre>${logTest}</pre>`;
}

if (!crypto.subtle) {
    alert("Your browser does not support crypto.subtle : are you running in an unsecure context ? use http://localhost:3000");
}

const algorithm = "RSA-SHA1";
function sign(buffer: Buffer, privateKey: PrivateKey): Buffer {
    const params = {
        algorithm,
        privateKey,
        signatureLength: rsaLengthPrivateKey(privateKey),
    };
    return makeMessageChunkSignature(buffer, params);
}

function verify(buffer: Buffer, signature: Signature, certificate: Certificate): boolean {
    const publicKey = toPem(certificate, "CERTIFICATE");
    const options = {
        algorithm,
        publicKey,
        signatureLength: 0,
    };
    return verifyMessageChunkSignature(buffer, signature, options);
}

// test encryption decryption in the browse
function testEncryptionDecryption(privPem: string, certificate: string) {
    try {
        const privateKey = makePrivateKeyFromPem(privPem);
        const publicKey = extractPublicKeyFromCertificateSync(certificate);

        const data = Buffer.from("Hello World");
        console.log("originalData = ", data.toString("hex"));
        const encryptedData = publicEncrypt_native(data, publicKey);
        console.log("encryptedData = ", encryptedData.toString("hex"));

        const decryptedData = privateDecrypt_native(encryptedData, privateKey);
        console.log("decrypted = ", decryptedData.toString("hex"));

        const signature = sign(data, privateKey);
        const isSignatureValid = verify(data, signature, convertPEMtoDER(certificate));
        return isSignatureValid ? "OK" : "Bad";
    } catch (err) {
        console.log(err);
        return err.message;
    }
}
