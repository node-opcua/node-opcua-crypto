import { Subject } from "../subject";
import { CertificatePurpose } from "../common";
import { getAttributes } from "./_get_attributes";
import { x509 } from "./_crypto";
import { buildPublicKey } from "./_build_public_key";

interface CreateCertificateSigningRequestOptions {
    privateKey: CryptoKey;
    notBefore?: Date;
    notAfter?: Date;
    validity?: number;
    subject?: string;
    dns?: string[];
    ip?: string[];
    applicationUri?: string;
    purpose: CertificatePurpose;
}
export async function createCertificateSigningRequest({
    privateKey,
    subject,
    dns,
    ip,
    applicationUri,
    purpose,
}: CreateCertificateSigningRequestOptions) {
    const modulusLength = 2048;

    const alg = {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength,
    };

    const publicKey  = await buildPublicKey(privateKey);
  
    const keys = {
        privateKey,
        publicKey,
    };

    const alternativeNameExtensions: x509.JsonGeneralName[] = [];
    dns && dns.forEach((d) => alternativeNameExtensions.push({ type: "dns", value: d }));
    ip && ip.forEach((d) => alternativeNameExtensions.push({ type: "ip", value: d }));
    applicationUri && alternativeNameExtensions.push({ type: "url", value: applicationUri });

    const { basicConstraints, usages } = getAttributes(purpose);

    const s = new Subject(subject || "");
    const s1 = s.toStringInternal(", ");
    const name = s1;

    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name,
        keys,
        signingAlgorithm: alg,
        extensions: [
            basicConstraints,
            new x509.KeyUsagesExtension(usages, true),
            new x509.SubjectAlternativeNameExtension(alternativeNameExtensions),
        ],
    });
    return { csr: csr.toString("pem"), der: csr };
}
