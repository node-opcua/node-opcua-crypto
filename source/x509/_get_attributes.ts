// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2023 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so,  subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ---------------------------------------------------------------------------------------------------------------------
import { CertificatePurpose } from "../common.js";
import { x509 } from "./_crypto.js";

// key usage of OPCUA Server or OPCUA Client
const keyUsageApplication =
    x509.KeyUsageFlags.keyEncipherment | x509.KeyUsageFlags.dataEncipherment | x509.KeyUsageFlags.digitalSignature;

// key usage for CA certificate
const keyUsageCA = x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign;

export function getAttributes(purpose: CertificatePurpose): {
    nsComment: string;
    basicConstraints: x509.BasicConstraintsExtension;
    keyUsageExtension: x509.ExtendedKeyUsage[];
    usages: x509.KeyUsageFlags;
} {
    let basicConstraints: x509.BasicConstraintsExtension;
    let keyUsageExtension: x509.ExtendedKeyUsage[] = [];
    let usages: x509.KeyUsageFlags;
    let nsComment: string;
    let extension: string;
    switch (purpose) {
        case CertificatePurpose.ForCertificateAuthority:
            extension = "v3_ca";
            /**
                [ v3_ca ]
                subjectKeyIdentifier        = hash
                authorityKeyIdentifier      = keyid:always,issuer:always
                *  basicConstraints            = CA:TRUE
                * keyUsage                    = critical, cRLSign, keyCertSign
                * nsComment                   = "Self-signed Certificate for CA generated by Node-OPCUA Certificate utility"
                subjectAltName              = $ENV::ALTNAME
             */
            basicConstraints = new x509.BasicConstraintsExtension(true, undefined, false);
            usages = keyUsageCA;
            keyUsageExtension = [];
            nsComment = "Self-signed certificate for CA generated by Node-OPCUA Certificate utility V2";
            break;
        case CertificatePurpose.ForApplication:
        case CertificatePurpose.ForUserAuthentication:
        default:
            /**
               [ v3_selfsigned]
               subjectKeyIdentifier       = hash
                authorityKeyIdentifier    = keyid,issuer
                * basicConstraints          = critical, CA:FALSE
                * keyUsage                  = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyCertSign
                * extendedKeyUsage          = clientAuth,serverAuth
                * nsComment                 = "Self-signed certificate generated by Node-OPCUA Certificate utility"
                subjectAltName            = $ENV::ALTNAME
             */
            extension = "v3_selfsigned";
            basicConstraints = new x509.BasicConstraintsExtension(false, undefined, true);
            usages = keyUsageApplication;
            keyUsageExtension = [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth];
            nsComment = "Self-signed certificate generated by Node-OPCUA Certificate utility V2";
            break;
    }
    return { nsComment, basicConstraints, keyUsageExtension, usages };
}
