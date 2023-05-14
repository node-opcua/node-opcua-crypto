import { KeyObject } from "node:crypto";

export type PrivateKey = KeyObject;
export type PublicKey = KeyObject;

export type Nonce = Buffer;
export type PEM = string;
export type DER = Buffer;
export type Certificate = DER;
export type CertificatePEM = PEM; // certificate as a PEM string
export type PrivateKeyPEM = PEM;
export type PublicKeyPEM = PEM;

export type Signature = Buffer;
export type CertificateRevocationList = Buffer;

export enum CertificatePurpose {
    NotSpecified = 0,
    ForCertificateAuthority = 1,
    ForApplication = 2,
    ForUserAuthentication = 3, // X509
}
