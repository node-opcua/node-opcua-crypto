// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
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

// ---------------------------------------------------------------------------------------------------------------------
// Browser-native exports — these work in the browser without any Node.js crypto shim.
// They use ASN1 parsing, @peculiar/x509, and pure JS only.
// ---------------------------------------------------------------------------------------------------------------------

//xx export * from "./asn1.js";
export * from "./common.js";
export * from "./crl_utils.js";
export * from "./crypto_explore_certificate.js";
export type { DirectoryName } from "./directory_name.js";
export * from "./explore_asn1.js";
export * from "./explore_certificate.js";
export * from "./explore_certificate.js";
export * from "./explore_certificate_revocation_list.js";
export * from "./explore_certificate_signing_request.js";
export * from "./explore_private_key.js";
export * from "./identify_der.js";
export * from "./subject.js";
export * from "./verify_certificate_signature.js";
export * from "./x509/coerce_private_key.js";
export * from "./x509/create_certificate_signing_request.js";
export * from "./x509/create_key_pair.js";
export * from "./x509/create_self_signed_certificate.js";

// ---------------------------------------------------------------------------------------------------------------------
// Exports that require a node:crypto shim in the browser.
// On Node.js these use native crypto. In the browser, the bundler must alias
// node:crypto → a shim providing createPublicKey, createPrivateKey,
// createSign, createVerify, publicEncrypt, privateDecrypt, etc.
// (see node-opcua-crypto-web/node-crypto-shim.js)
// ---------------------------------------------------------------------------------------------------------------------

export * from "./crypto_utils.js";
export * from "./crypto_utils2.js";
export * from "./derived_keys.js";
export * from "./make_private_key_from_pem.js";
export * from "./make_private_key_thumbprint.js";
/**
 * @module node_opcua_crypto
 */
export { certificateMatchesPrivateKey, publicKeyAndPrivateKeyMatches } from "./public_private_match.js";

import { readAlgorithmIdentifier, readSignatureValueBin, readStruct, readTag } from "./asn1.js";
import { readDirectoryName } from "./directory_name.js";
export const asn1 = { readDirectoryName, readTag, readStruct, readAlgorithmIdentifier, readSignatureValueBin };
