import { Subject } from "../subject";
    import { CertificatePurpose } from "../common";
import { x509 } from "./_crypto";
import { getAttributes } from "./_get_attributes";
import { buildPublicKey } from "./_build_public_key";

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
export async function createSelfSignedCertificate({
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
    
     const publicKey = await buildPublicKey(privateKey);
  
    const keys = {
        privateKey,
        publicKey,
    };

    const { nsComment, basicConstraints, keyUsageExtension, usages } = getAttributes(purpose);

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

    const s = new Subject(subject || "");
    const s1 = s.toStringInternal(", ");
    const name = s1;
    // const issuer = s1;
    /**
     *  name: "CN=Test, O=Дом",
     *  subject: "CN=Test, O=Дом",
     *  issuer: "CN=Test, O=Дом",

     */

    //  const gg = new x509.GeneralNames(gga);
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name,
        // subject: s1,
        // issuer,
        notBefore,
        notAfter,

        signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },

        keys,

        extensions: [
            new x509.Extension(ID_NETSCAPE_COMMENT, false, Buffer.from(nsComment, "ascii")),
            // new x509.BasicConstraintsExtension(true, 2, true),
            basicConstraints,
            new x509.ExtendedKeyUsageExtension(keyUsageExtension, true),
            new x509.KeyUsagesExtension(usages, true),
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
            new x509.SubjectAlternativeNameExtension(alternativeNameExtensions),
        ],
    });

    return { cert: cert.toString("pem"), der: cert };
}
