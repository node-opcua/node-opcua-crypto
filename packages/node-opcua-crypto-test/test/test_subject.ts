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

import { Subject } from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

describe("Subject", () => {
    it("should compose a subject with common name only", () => {
        const subject = new Subject({ commonName: "Hello" });
        expect(subject.toStringForOPCUA()).toEqual("CN=Hello");
        expect(subject.toString()).toEqual("/CN=Hello");
    });

    it("should compose a subject with a subject string - starting with a / (like in OpenSSL)", () => {
        const subject = new Subject("/CN=Hello");
        expect(subject.toStringForOPCUA()).toEqual("CN=Hello");
        expect(subject.toString()).toEqual("/CN=Hello");
    });

    it("should compose a subject with a subject string - correctly starting without a / (like in OPCUA-GDS)", () => {
        const subject = new Subject("CN=Hello");
        expect(subject.toStringForOPCUA()).toEqual("CN=Hello");
        expect(subject.toString()).toEqual("/CN=Hello");
    });

    it("should parse a SubjectLine ", () => {
        const str = "/C=FR/ST=IDF/L=Paris/O=Local NODE-OPCUA Certificate Authority/CN=Hello";
        const subject = Subject.parse(str);
        expect(subject.commonName).toEqual("Hello");
        expect(subject.country).toEqual("FR");
    });

    it("should parse a SubjectLine ", () => {
        const str = "/DC=MYDOMAIN/CN=Hello";

        const subject = Subject.parse(str);
        expect(subject.commonName).toEqual("Hello");
        expect(subject.domainComponent).toEqual("MYDOMAIN");
    });

    it("should parse a long CN with slashes SubjectLine ", () => {
        const str = "/CN=PC.DOMAIN.COM/path/scada/server@PC/DC=/O=Sterfive/L=Orleans/C=FR";
        const subject = Subject.parse(str);
        expect(subject.commonName).toEqual("PC.DOMAIN.COM/path/scada/server@PC");
        expect(subject.domainComponent).toEqual("");
    });

    it("should enclose data that contains special character  = with quote", () => {
        const subject = new Subject({ commonName: "Hello=Hallo" });
        expect(subject.toString()).toEqual('/CN="Hello=Hallo"');
    });
    it("should enclose data that contains special character / with quote", () => {
        const subject = new Subject({ commonName: "Hello/Hallo" });
        expect(subject.toString()).toEqual('/CN="Hello/Hallo"');
    });
    it("should replace unwanted quote character with a substitute character", () => {
        const subject = new Subject({ commonName: 'Hello"Hallo"' });
        expect(subject.commonName).toEqual('Hello"Hallo"');
        expect(subject.toString()).toEqual("/CN=Hello\u201dHallo\u201d");
    });
    it("should parse a quoted string ", () => {
        const subject = new Subject("CN=Hello'Hallo'");
        expect(subject.commonName).toEqual("Hello'Hallo'");
        expect(subject.toString()).toEqual("/CN=Hello'Hallo'");
    });
    it("should parse a quoted string ", () => {
        const subject = new Subject('CN="Hello/Hallo"');
        expect(subject.commonName).toEqual("Hello/Hallo");
        expect(subject.toString()).toEqual('/CN="Hello/Hallo"');
    });

    it("should produce a string with ', ' as sep ", () => {
        const subject = new Subject('CN="Hello/Hallo"/O=Sterfive/L=Orleans/C=FR');
        expect(subject.commonName).toEqual("Hello/Hallo");
        expect(subject.toStringInternal(", ")).toEqual('C=FR, L=Orleans, O=Sterfive, CN="Hello/Hallo"');
    });
});
