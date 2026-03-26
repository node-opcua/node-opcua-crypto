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

import fs from "node:fs";

import type { Certificate } from "../source/common.js";
import { combine_der } from "../source/crypto_explore_certificate.js";
import { toPem } from "../source/crypto_utils.js";

// ── PEM ──────────────────────────────────────────────────────

/**
 * Convert one or more DER certificates to a PEM string.
 *
 * Accepts a single `Certificate` (DER buffer) or an array.
 * Returns a multi-block PEM string with each certificate
 * separated by a newline.
 */
export function certificatesToPem(certificates: Certificate | Certificate[]): string {
    const certs = Array.isArray(certificates) ? certificates : [certificates];
    return `${certs.map((der) => toPem(der, "CERTIFICATE")).join("\n")}\n`;
}

/**
 * Write one or more DER certificates to a PEM file.
 *
 * Each certificate is written as a separate PEM block in the
 * order provided (typically leaf first, then issuer chain).
 */
export function writeCertificateChain(filename: string, certificates: Certificate | Certificate[]): void {
    fs.writeFileSync(filename, certificatesToPem(certificates), "utf-8");
}

/**
 * Async version of {@link writeCertificateChain}.
 */
export async function writeCertificateChainAsync(filename: string, certificates: Certificate | Certificate[]): Promise<void> {
    await fs.promises.writeFile(filename, certificatesToPem(certificates), "utf-8");
}

// ── DER ──────────────────────────────────────────────────────

/**
 * Convert one or more DER certificates to a single concatenated
 * DER buffer (OPC UA certificate chain format).
 *
 * Accepts a single `Certificate` (DER buffer) or an array.
 */
export function certificatesToDer(certificates: Certificate | Certificate[]): Certificate {
    const certs = Array.isArray(certificates) ? certificates : [certificates];
    return combine_der(certs);
}

/**
 * Write one or more DER certificates to a `.der` file as a
 * concatenated DER chain (OPC UA binary chain format).
 *
 * Order should be leaf first, then issuer chain.
 */
export function writeCertificateChainDer(filename: string, certificates: Certificate | Certificate[]): void {
    fs.writeFileSync(filename, certificatesToDer(certificates));
}

/**
 * Async version of {@link writeCertificateChainDer}.
 */
export async function writeCertificateChainDerAsync(filename: string, certificates: Certificate | Certificate[]): Promise<void> {
    await fs.promises.writeFile(filename, certificatesToDer(certificates));
}
