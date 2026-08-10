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

/**
 * `crlDistributionPoints` (RFC 5280 4.2.1.13) and `authorityInfoAccess`
 * (RFC 5280 4.2.2.1) are how a relying party finds where to check whether a
 * certificate has been revoked, and where to fetch a missing issuer.
 *
 * Both used to be reported as the string `"Unknown <name><hex>"`, so every
 * consumer wanting a CRL or OCSP URL had to decode the DER itself, even though
 * `oid_map` already knew the names.
 *
 * The fixture is a real certificate issued by OpenSSL. `openssl x509 -text`
 * reports exactly the three URLs asserted below.
 */

import path from "node:path";
import { exploreCertificate, readCertificate } from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

const certificate = readCertificate(path.join(__dirname, "../test-fixtures/certs/cert_with_revocation_urls.pem"));

describe("exploreCertificate: revocation and issuer URLs", () => {
    it("decodes crlDistributionPoints", () => {
        const extensions = exploreCertificate(certificate).tbsCertificate.extensions;
        // The same shape as subjectAltName, so a caller reads a URI from
        // `uniformResourceIdentifier` in both places.
        expect(extensions?.cRLDistributionPoints).toEqual({
            uniformResourceIdentifier: ["http://pki.example/crl.pem"],
        });
    });

    it("tells the two authorityInfoAccess legs apart by their access-method OID", () => {
        // Not by position. `AccessDescription` carries the OID precisely so
        // that order does not matter, and a reader keyed on order would point
        // chain repair at the OCSP responder.
        const extensions = exploreCertificate(certificate).tbsCertificate.extensions;
        expect(extensions?.authorityInfoAccess).toEqual({
            ocsp: ["http://pki.example/ocsp"],
            caIssuers: ["http://pki.example/ca.der"],
        });
    });

    it("no longer reports either extension as Unknown", () => {
        // The regression this guards: an extension whose OID is in oid_map but
        // has no reader falls through to `Unknown <name><hex>`, which is a
        // diagnostic and not something a consumer can use.
        const extensions = exploreCertificate(certificate).tbsCertificate.extensions;
        expect(JSON.stringify(extensions)).not.toMatch(/Unknown/);
    });

    it("leaves a certificate without them undisturbed", () => {
        // Absent is the ordinary case: RFC 5280 requires neither extension.
        const plain = readCertificate(path.join(__dirname, "../test-fixtures/certs/cert1.pem"));
        const extensions = exploreCertificate(plain).tbsCertificate.extensions;
        expect(extensions?.cRLDistributionPoints).toBeUndefined();
        expect(extensions?.authorityInfoAccess).toBeUndefined();
    });
});
