import path from "node:path";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { Crypto as PeculiarWebCrypto } from "@peculiar/webcrypto";
import * as x509 from "@peculiar/x509";
import { AsnConvert, AsnUtf8StringConverter } from "@peculiar/asn1-schema";
import jsrsasign from "jsrsasign";

const privateKeyFilename = path.join(tmpdir(), "_private_key.pem");
console.log(privateKeyFilename);

// problematic key generated by crypto.subtle
const privateKey1 = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCWZladPrpQPac0
oHvBzcWBDqZ/nixuRm42SAuYXRw4txneooLfBT1v4TkUWzopgGTeA0B0IkiysAaJ
InrcKT3Tytjl3VOm+l2Ezqk42XiKN7zkjaKYnMfEpB3snbWul+uEOPqE7IZ5x85D
8UQute1CAP7ZycR8mnTA8Tcp6rvrAP8TGLUM/Tvgl2oRGYSvnDNzQuS09AwZir+X
AtFXqsOoANDnVQRfhcG1P5hkZA9DZRleo6p4nUCdk/JClrXr88QvRhWtweUq2DNj
zIRzNA7Kvuh+YmMY6xbznOQw2KelupB3x/agWvSArfFUYnq80HSwoiTJHAmR6JN0
iizlylPHAgMBAAECggEACNuYIesa2ZteW9jqN2mhRmhdezCoPz2b3UvBWxGvL58h
DlEV67Q8TRJZStvTzhpT8BUGJV2lJT9jjMB6HSAhfKkt791o9HGhMy9hg6Ns2DJP
yEoxl4YytPmErA94LtAFvL2gvryYPIqwmQtkz53cjls1Dao2p0jVgLONyZGbzBhY
zYtwsTOuyJzkJwadRjD0iSLJ+7Mx2J9Ynm1uJiw8vsRttjRpQTGgIDhXitUTtYTW
275fON209g6fHb29JuQQo6d7SHhs8UFzIFL0sSa5ZYCVcMWVpC4sfH0ghq67cp+c
/cQ25MnnyziUvgf5jgzg1QVz0j6FP1ns5iFEp2WFuQKBgQDKkWPWTxVODynbf+cc
UN9ybkCg6uezmbc0M8eqDtM71MEXpxIp4Cm9916DIwxTQQLrcWK0DSPwasvUlCZ6
X6iedACObIOJ/sS8AtTVmimwYCkXg06Qxu/Zgn3XwJ9LqUjYdl8KMCR1iVFO9sri
6Ka95E18ljBcvfU2yH5GeC3D9QKBgQC+Ej0IPrkyk8EaDbDGrvLM2IlY1bWmT2+1
t8CB5akwNcGOOwo1UnqVFSUOGAjP2pr7OrSpX+KRmM2wYXwgBXRQKHywJ2INHau8
WEzQ+K0iDyNX/oZPc2Gq3DVOYLNBZJHmBd3Sz227ePZCBYS7NGXaECKsA0bdjvzv
mqUjQcJfSwKBgHoHS9V2nqb/i3+ndVohffo5YMWPvTT8jNjtuIJBnA6XBBtzkgWX
/I1rz4vAOVSN/WxISeWdZOEX9OKCvQtLRRDvYMZrqHIg//Mi4YQr8qFFzHtVpqag
sSye56BpcYzq1e9Qn8BLcCs+JbUkBuTaslgCiItdDpVP+cCe1zMsgqVhAoGAfyAB
tBcHlP1f5QYNGwX+HOYjDsh5Iw/0Pkz1M6wgeb8qgu+YB0vv8vBehUur8SFcEPYV
yUb5aboSsIqzE1OylL5Pjx34JZ+XsnQ4hHgejC4lzH/O4yrfwwBfotloay9RqdB4
qbvUv9PKmSPJv8/u42dxWS0j46H0KGl9U9RypXsCgYBTXe6iz0iSF0wIsjlg86su
LDIeWVwx67nM2VQ0cI9dHRAtAY/lTa3DC/dJWHSmiD2ngPPIsgHntWLN0PL1PkHN
ceVSxCWfoBmyvdEAdzdryB6gP/4bK4+DnpyTadEpxxDaBKPGtVQvvKiysrr2eVEI
TU1WcJPHPFOWVmsq4mlY7Q==
-----END PRIVATE KEY-----
`;

// valid private key generated by jsrsasign
const ok_privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCeksos8uYyXxXQ
a7XsdORlZofL1Vk4g7D6vF4Gs7BadJduTU27RTlgo77nUB6z+IsfdeLdrWbpcmZC
baWVrp/kCnFbZpFm+mpasRRRQ8FUFygAFcSInjtxBi7xhHtUwbvT+HI1HUUd5gbf
zCA6gTMKHF6NdQB4JkNdK/w41E4MeeGegBsvjS+732jYQl9PTQA/6dPWYam+n3h2
ww7tJJEPCvr+CT6WC73yHhKJQd9aE3mdsXKwO5E1N5CpMWVIr7Qrv8XfjYpS64tC
rudfDtouJ4Xgz0DtHaAAjsT4M7/p/Hf7+XnBwXmZunfjIIQpJqjoaQm45ujnMEwc
dhlS2rbXAgMBAAECggEAXmfT18jQhYKYcRn/GARLiZbuF8svr/avIceNTv4haujo
0rFRKsG+tCsoV3wam1jIMvWzF/jJQQhrmva+UwvAgzo4XIsG28EQGmg8SVlGOvMC
THKpLBDQIKzmu8D8z+v7D+pky/xeDrvIsepL8ajDoyxammri2aUmC81I/uhegwwF
Z343g+d4UHq/CBJbxVIKAqWbLrDNmPM0R/eeDixug+ELkYKsI9bBzBs2uJwIYUwo
wCWYUbnC/oXkhQFPXCuEPk21Labj5KkrWAzDWbH/akFBbSLm2aSsJZAfxrCHLfxQ
LTWJVrPcDvKNT9H/6cb5bgL+4n8zrhcjkyHItetWsQKBgQDvg97EoNUL7hxjmicH
q1/JFZj8pfQKdvg5a/eVh/wi3wyxr+6GWprr3uxJEsCBZnDUlEGIIPJzMJq57zOR
aPKUEuLpwov6IVcTS0TYtQcdfMi77KH+W+DO66jTpDed/PT4nHI78qS3So93AOi+
X1UT1fSlis1aQie/DgG7CtkUPwKBgQCpfMTrcBdtZsu6/yzlCzVY/ZVwgqWxUy7G
FaQnC96NiPkjr5Oc41z+suosEQEpDzIRChqpuCsONBw37OoYd/eLQarcKCjmoLvK
RO2YLaIisTi1ozwzN44ZSVwxmL6l4dotkGyvO05RUcFzd32bDMU02f+5/3ZChOrU
rV2RqhBXaQKBgHfn05kqTx3G2Y1/ebScNbqsRkeNKQwoHQJaK7s/NZmbgnZd9hJq
v43/rtiyO49MYoX5pojovZevKHaW6oEMQgyhG9oc3AifskDleJToo6Q+eRujTkHR
a00Lqxww5OsB3P2tDH84bP+ZoxLXcK0FeskQXoaVY1KhNdauw20I9D3vAoGAGs18
Zq8nRUnIVh4cf2wyV4xioZRHl69L6k9p0jLyUveiTp5pfZoHDtBEcAuQX2njxQYQ
CV7ykCB1hfKVYqE2KH import rs = from "jsrsasign";
   OODZrcPPyWNfqIiFRPG6VjDnZuArt6YU1UoxNAswLwedwp
E90RGZMQQK5Y0rhGR4FiC4v2q7ZRXKi971cxlmECgYEAl/9+CYcPue/DheB10aFj
8g33g7Jr2EU9yuN547IPQ/eSE27GtclR9HHXQO4bdD+8+PLwO0rZ5w0b5/ijkOKx
3+VqqjrjVDyuWs0K02egpAOpFzhd1ZBvTRJBxJF1g1EtEo9wsvvoHAHRDRu+5zK9
mK3gTv2HExCJojJSXLe/A0s=
-----END PRIVATE KEY-----`;

/**
 * 
 * // dump of the valid key
  Certificate SEQUENCE (3 elem)
  tbsCertificate TBSCertificate INTEGER 0
  signatureAlgorithm AlgorithmIdentifier SEQUENCE (2 elem)
    algorithm OBJECT IDENTIFIER 1.2.840.113549.1.1.1 rsaEncryption (PKCS #1)
    parameters ANY NULL
  signature BIT STRING OCTET STRING (1191 byte) 308204A302010002820101009E92CA2CF2E6325F15D06BB5EC74E4656687CBD55938…
    SEQUENCE (9 elem)
      INTEGER 0
      INTEGER (2048 bit) 200180369073714278831739278449003774074597054048214887574056452546509…
      INTEGER 65537
      INTEGER (2047 bit) 119175999208830279341104588663575999100791205850118257907395221157623…
      INTEGER (1024 bit) 168193235618184182434131608698373145194108940032957500147962911293855…
      INTEGER (1024 bit) 119018085559721411901982988389191088594078705579204164333890645439912…
      INTEGER (1023 bit) 842005564398279573596811564426953403523737768518745536468638350342571…
      INTEGER (1021 bit) 188214815865992143819850113930386871872229687752395129340134984716916…
      INTEGER (1024 bit) 106736637320045350647169232509502844342836430219909303120677032102485…

      // dump of the problematic key
Certificate SEQUENCE (3 elem)
  tbsCertificate TBSCertificate INTEGER 0
  signatureAlgorithm AlgorithmIdentifier SEQUENCE (2 elem)
    algorithm OBJECT IDENTIFIER 1.2.840.113549.1.1.1 rsaEncryption (PKCS #1)
    parameters ANY NULL
  signature BIT STRING OCTET STRING (1190 byte) 308204A202010002820101009666569D3EBA503DA734A07BC1CDC5810EA67F9E2C6E…
    SEQUENCE (9 elem)
      INTEGER 0
      INTEGER (2048 bit) 189862106596719048129752073156943138642968958120308513743641089887432…
      INTEGER 65537
      INTEGER (2044 bit) 111819240893238351156021339391667169161562412767256176106276741191618…
      INTEGER (1024 bit) 142248037681310581229645699628768184951961139839271120785531410694391…
      INTEGER (1024 bit) 133472566435033708035703101049362867736421698786549054494358095666029…
      INTEGER (1023 bit) 856913274586591047339123277132576703526775073752906579277778978930155…
      INTEGER (1023 bit) 892702291003071932546343901658104976042628182997513573348062683267325…
      INTEGER (1023 bit) 585422438810792541886454800476608824191572635894667134864663963894195…
 */
let _crypto: Crypto | undefined;

declare const crypto: any;
declare const window: any;

const ignoreCrypto = process.env.IGNORE_SUBTLE_FROM_CRYPTO;

import nativeCrypto from "node:crypto";

if (typeof window === "undefined") {
    _crypto = nativeCrypto as any;
    if (!_crypto?.subtle || ignoreCrypto) {
        _crypto = new PeculiarWebCrypto();
        console.warn("using @peculiar/webcrypto");
    } else {
        console.warn("using nodejs crypto (native)");
    }
    x509.cryptoProvider.set(_crypto);
} else {
    // using browser crypto
    console.warn("using browser crypto (native)");
    _crypto = crypto;
    x509.cryptoProvider.set(crypto);
}

export function getCrypto(): Crypto {
    return _crypto || crypto;
}

async function generateKeyPair(modulusLength: 1024 | 2048 | 3072 | 4096 = 2048): Promise<CryptoKeyPair> {
    const crypto = getCrypto();
    const alg: RsaHashedKeyGenParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength,
    };
    const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    return keys;
}
async function generatePrivateKey(modulusLength: 1024 | 2048 | 3072 | 4096 = 2048): Promise<CryptoKey> {
    return (await generateKeyPair(modulusLength)).privateKey;
}

async function generatePrivateKeyFile(privateKeyFilename: string, modulusLength: 1024 | 2048 | 3072 | 4096) {
    const keys = await generateKeyPair(modulusLength);
    const privateKeyPem = await privateKeyToPEM(keys.privateKey);
    await fs.promises.writeFile(privateKeyFilename, privateKeyPem.privPem, "utf-8");
    privateKeyPem.privPem = "";
    privateKeyPem.privDer = new ArrayBuffer(0);
}

async function generatePrivateKeyFileJSRSA(privateKeyFilename: string, modulusLength: 2048 | 3072 | 4096) {
    const kp = jsrsasign.KEYUTIL.generateKeypair("RSA", modulusLength);
    const prv = kp.prvKeyObj;
    const pub = kp.pubKeyObj;
    const prvpem = jsrsasign.KEYUTIL.getPEM(prv, "PKCS8PRV");
    // const pubpem = jsrsasign.KEYUTIL.getPEM(pub, "PKCS8PUB");
    await fs.promises.writeFile(privateKeyFilename, prvpem, "utf-8");
}

async function privateKeyToPEM(privateKey: CryptoKey) {
    const crypto = getCrypto();
    const privDer = await crypto.subtle.exportKey("pkcs8", privateKey);
    const privPem = x509.PemConverter.encode(privDer, "PRIVATE KEY");
    return { privPem, privDer };
}
async function generatePrivateKeyPem(modulusLength: 2048): Promise<string> {
    const cryptoKey = await generatePrivateKey(modulusLength);
    const { privPem, privDer } = await privateKeyToPEM(cryptoKey);
    return privPem;
}

async function derToPrivateKey(privDer: ArrayBuffer): Promise<CryptoKey> {
    const crypto = getCrypto();

    return await crypto.subtle.importKey(
        "pkcs8",
        privDer,
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: { name: "SHA-256" },
        },
        true,
        [
            "sign",
            // "encrypt",
            // "decrypt",
            // "verify",
            //    "wrapKey",
            //    "unwrapKey",
            //    "deriveKey",
            //    "deriveBits"
        ]
    );
}

async function pemToPrivateKey(pem: string): Promise<CryptoKey> {
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
    const privDer = x509.PemConverter.decode(pem);
    return derToPrivateKey(privDer[0]);
}

// async function generatePrivateKeyPEM(modulusLength: 1024 | 2048 | 3072 | 4096 = 2048): Promise<string> {
//     const privateKey = await generatePrivateKey(modulusLength);
//     return await privateKeyToPem(privateKey);
// }

// async function generatePrivateKeyDer1(modulusLength: 2048): Promise<Buffer> {
//     // generate private key , not using SSL
//     const privateKeyFilename = "/tmp/pec2-privatekey.pem";
//     await fs.promises.writeFile(privateKeyFilename, privateKey1, "utf-8");

//     await generatePrivateKeyFile(privateKeyFilename, 2048);
//     await generatePrivateKeyFile(privateKeyFilename, 2048);

//     const privateKeyPem = await fs.promises.readFile(privateKeyFilename, "utf-8");
//     const privateKey = await pemToPrivateKey(privateKeyPem);
//     return privateKey;
// }

enum CertificatePurpose {
    ForApplication = 1,
}

export interface CreateSelfSignCertificateOptions {
    privateKey: CryptoKey;
    notBefore?: Date;
    notAfter?: Date;
    validity?: number;
    // CN=common/O=Org/C=US/ST=State/L=City
    subject?: string;
    dns?: string[];
    ip?: string[];
    applicationUri?: string;
    purpose: CertificatePurpose;
}

async function createSelfSignedCertificate({
    privateKey,
    notAfter,
    notBefore,
    validity,
    subject,
    dns,
    ip,
    applicationUri,
    purpose,
}: CreateSelfSignCertificateOptions) {
    const crypto = getCrypto();

    const publicKey = await buildPublicKey(privateKey);

    const keys = {
        privateKey,
        publicKey,
    };

    const keyUsageApplication =
        x509.KeyUsageFlags.keyEncipherment |
        x509.KeyUsageFlags.nonRepudiation |
        x509.KeyUsageFlags.dataEncipherment |
        x509.KeyUsageFlags.keyCertSign |
        x509.KeyUsageFlags.digitalSignature;

    const { nsComment, basicConstraints, keyUsageExtension, usages } = {
        //                extension: "v3_selfsigned",
        basicConstraints: new x509.BasicConstraintsExtension(false, undefined, true),
        usages: keyUsageApplication,
        keyUsageExtension: [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
        nsComment: "Self-signed certificate generated by Node-OPCUA Certificate utility V2",
    };

    notBefore = notBefore || new Date();
    validity = validity || 0;
    if (!notAfter) {
        validity = validity || 365;
    }
    notAfter = notAfter || new Date(notBefore.getTime() + validity * 24 * 60 * 60 * 1000);

    const alternativeNameExtensions: x509.JsonGeneralName[] = [];
    dns && dns.forEach((d) => alternativeNameExtensions.push({ type: "dns", value: d }));
    ip && ip.forEach((d) => alternativeNameExtensions.push({ type: "ip", value: d }));
    applicationUri && alternativeNameExtensions.push({ type: "url", value: applicationUri });

    // https://opensource.apple.com/source/OpenSSH/OpenSSH-186/osslshim/heimdal-asn1/rfc2459.asn1.auto.html
    const ID_NETSCAPE_COMMENT = "2.16.840.1.113730.1.13";

    //  const s = new Subject(subject || "");
    //  const s1 = s.toStringInternal(", ");
    const name = subject;

    const cert = await x509.X509CertificateGenerator.createSelfSigned(
        {
            serialNumber: Date.now().toString(),
            name,
            notBefore,
            notAfter,

            signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },

            keys,

            extensions: [
                new x509.Extension(ID_NETSCAPE_COMMENT, false, AsnConvert.serialize(AsnUtf8StringConverter.toASN(nsComment))),
                // new x509.BasicConstraintsExtension(true, 2, true),
                basicConstraints,
                new x509.ExtendedKeyUsageExtension(keyUsageExtension, true),
                new x509.KeyUsagesExtension(usages, true),
                await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
                new x509.SubjectAlternativeNameExtension(alternativeNameExtensions),
            ],
        },
        crypto
    );

    return { cert: cert.toString("pem"), der: cert };
}
async function createSelfSignedCertificate2(privateKey: CryptoKey) {
    const startDate = new Date(2020, 1, 20);
    const endDate = new Date(2021, 1, 2);
    const validity = 365;
    const dns: string[] = [];
    const ip: string[] = [];
    const subject = "CN=TOTO";
    const applicationUri = "uri:application";
    const purpose = CertificatePurpose.ForApplication;
    const { cert } = await createSelfSignedCertificate({
        privateKey,
        notBefore: startDate,
        notAfter: endDate,
        validity: validity,
        dns,
        ip,
        subject,
        applicationUri: applicationUri,
        purpose,
    });
    return cert;
}

// https://stackoverflow.com/questions/56807959/generate-public-key-from-private-key-using-webcrypto-api
async function buildPublicKey(privateKey: CryptoKey): Promise<CryptoKey> {
    const crypto = getCrypto();
    // export private key to JWK
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    // remove private data from JWK
    delete jwk.d;
    delete jwk.dp;
    delete jwk.dq;
    delete jwk.q;
    delete jwk.qi;
    jwk.key_ops = [
        "encrypt",
        "sign",
        // "wrapKey"
    ];
    // import public key
    // const publicKey = await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: { name: "SHA-256" } }, true, [
    const publicKey = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } }, true, [
        //   "encrypt",
        //     "sign",
        // "wrapKey",
    ]);
    return publicKey;
}
async function testStuff() {
    console.log("generatePrivateKeyPem:");
    const privateKeyPem = await generatePrivateKeyPem(2048);
    console.log("pemToPrivateKey:");
    const privateKey = await pemToPrivateKey(privateKeyPem);
    console.log("buildPublicKey:");
    const publicKey = await buildPublicKey(privateKey);

    const cert = await createSelfSignedCertificate2(privateKey);
    console.log("cert = ", cert);
    /*
    const certificateDer = convertPEMtoDER(cert);
    const info = exploreCertificate(certificateDer);
    console.log(info);
    */
    console.log("IGNORE_SUBTLE_FROM_CRYPTO", process.env.IGNORE_SUBTLE_FROM_CRYPTO);
    console.log("nodejs version", process.version);
}

describe("Test @peculiar/x509 (investigate github node-opcua issue#1289 ", function (this) {
    this.timeout(1000000);

    it("T1 - should create a certificate with a pre-existing private key generated by subtle", async () => {
        await testStuff();
    });
    it("T2 - should convert a PEM private key and generate a certificate for it", async () => {
        //
        const pem = privateKey1;
        console.log("convert PEM Private key to DER");
        const privDer = x509.PemConverter.decode(pem);
        const privateKey = await derToPrivateKey(privDer[0]);

        await createSelfSignedCertificate2(privateKey);
    });
    it("T3 - should convert a PEM private key written in PEM and reloaded and generate a certificate for it", async () => {
        //
        await generatePrivateKeyFile(privateKeyFilename, 2048);
        const privateKeyPem = await fs.promises.readFile(privateKeyFilename, "utf-8");
        const privateKey = await pemToPrivateKey(privateKeyPem);
        await createSelfSignedCertificate2(privateKey);
    });

    xit("T4 - messing with Private Key", async () => {
        let success = 0;
        for (let i = 0; i < 100; i++) {
            //
            if (!(i % 10)) console.log("i=", i);
            await generatePrivateKeyFile(privateKeyFilename, 2048);
            const privateKeyPem = await fs.promises.readFile(privateKeyFilename, "utf-8");
            const privateKey = await pemToPrivateKey(privateKeyPem);

            // now back to PEM
            const privateKeyPem2 = (await privateKeyToPEM(privateKey)).privPem;

            // should be identical
            if (privateKeyPem2.replace(/\r|\n/gm, "") != privateKeyPem.replace(/\r|\n/gm, "")) {
                console.log(privateKeyPem);
                console.log(privateKeyPem2);
                throw new Error(" Found issue here with key ");
            }
            try {
                await createSelfSignedCertificate2(privateKey);
                success++;
            } catch (err) {
                console.log((err as any).message);
                // console.log(privateKeyPem2);
                console.log(" this private key didn't fit the createSelfSignedCertificate");
            }
        }
        console.log("success rate", success, "%");
        if (success != 100) {
            throw new Error(`success rate should be 100% (was ${success})`);
        }
    });
    xit("T5 - messing with Private Key directly", async () => {
        let success = 0;
        for (let i = 0; i < 100; i++) {
            //
            if (!(i % 10)) console.log("i=", i);
            const privateKey = await generatePrivateKey(2048);
            try {
                await createSelfSignedCertificate2(privateKey);
                success++;
            } catch (err) {
                //  console.log(privateKeyPem2);
                console.log((err as any).message);
                console.log(" this private key didn't fit the createSelfSignedCertificate");
            }
        }
        if (success != 100) {
            throw new Error(`success rate should be 100% (was ${success})`);
        }
        console.log("success rate", success, "%");
    });
});
