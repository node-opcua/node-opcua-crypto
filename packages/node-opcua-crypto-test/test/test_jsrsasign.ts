// based on
// https://github.com/kjur/jsrsasign/wiki/Tutorial-for-generating-X.509-certificate

import jsrsasign from "jsrsasign";

describe("testing X509 certificate creating with jsrsasign", () => {
    it("should create an X509 certificate using jsrsasign", () => {
        // STEP1. generate a key pair
        const kp = jsrsasign.KEYUTIL.generateKeypair("RSA", 2048);
        const prv = kp.prvKeyObj;
        const pub = kp.pubKeyObj;
        const prvpem = jsrsasign.KEYUTIL.getPEM(prv, "PKCS8PRV");
        //  const pubpem = jsrsasign.KEYUTIL.getPEM(pub, "PKCS8PUB");

        // STEP2. specify certificate parameters
        const x = new jsrsasign.KJUR.asn1.x509.Certificate({
            version: 3,
            serial: { int: 4 },
            issuer: { str: "/CN=UserCA" },
            notbefore: "201231235959Z",
            notafter: "221231235959Z",
            subject: { str: "/CN=User1" },
            sbjpubkey: pub, // can specify public key object or PEM string
            ext: [
                { extname: "basicConstraints", cA: false },
                { extname: "keyUsage", critical: true, names: ["digitalSignature"] },
                { extname: "cRLDistributionPoints", array: [{ fulluri: "http://example.com/a.crl" }] },
            ],
            sigalg: "SHA256withRSA",
            cakey: prv, // can specify private key object or PEM string
        });

        // you can modify any fields until the certificate is signed.
        // ????? w     x.params!.subject = { str: "/CN=User2" };

        // STEP3. show PEM strings of keys and a certificate
        console.log(prvpem);
        //    console.log(pubpem);
        console.log(x.getPEM()); // certificate object is signed automatically with "cakey" value
    });
});
