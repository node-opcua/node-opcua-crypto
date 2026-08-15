import { asn1 } from "node-opcua-crypto";
import { describe, expect, it } from "vitest";

/**
 * Distinguished Name parsing.
 *
 * A DN is a *sequence*, not a record: an attribute may repeat, and both the
 * repetition and the order carry meaning. Two things used to be lost —
 * a repeated attribute overwrote the previous one, and only the first attribute
 * of a multi-valued RDN was read — which is invisible to a caller reading
 * `subject.commonName` and fatal to one that must reproduce the DN faithfully,
 * such as an OPC UA Part 18 §4.4.3 `X509Subject` role criteria.
 *
 * The DER here is hand-built so the exact structure under test is explicit.
 */

/** Minimal DER TLV encoder — short-form lengths only, which is all these need. */
const tlv = (tag: number, ...payload: Buffer[]): Buffer => {
    const value = Buffer.concat(payload);
    if (value.length > 127) throw new Error("test helper only encodes short-form lengths");
    return Buffer.concat([Buffer.from([tag, value.length]), value]);
};

const SEQUENCE = 0x30;
const SET = 0x31;
const OID = 0x06;
const UTF8_STRING = 0x0c;

const oid = (...bytes: number[]) => tlv(OID, Buffer.from(bytes));
const text = (value: string) => tlv(UTF8_STRING, Buffer.from(value, "ascii"));

// 2.5.4.3 commonName / 2.5.4.11 organizationUnitName / 2.5.4.5 serialNumber
const CN = () => oid(0x55, 0x04, 0x03);
const OU = () => oid(0x55, 0x04, 0x0b);
const SERIAL_NUMBER = () => oid(0x55, 0x04, 0x05);
// 0.9.2342.19200300.100.1.25 domainComponent
const DC = () => oid(0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19);

/** One single-valued RDN: SET { SEQUENCE { type, value } }. */
const rdn = (type: Buffer, value: string) => tlv(SET, tlv(SEQUENCE, type, text(value)));

/** A multi-valued RDN: SET { SEQUENCE {..}, SEQUENCE {..} }. */
const multiRdn = (...pairs: Array<[Buffer, string]>) => tlv(SET, ...pairs.map(([type, value]) => tlv(SEQUENCE, type, text(value))));

const parse = (...rdns: Buffer[]) => {
    const der = tlv(SEQUENCE, ...rdns);
    return asn1.readDirectoryName(der, asn1.readTag(der, 0));
};

describe("readDirectoryName", () => {
    it("reads a simple name into the convenience properties", () => {
        const name = parse(rdn(CN(), "operator-1"), rdn(OU(), "Plant"));
        expect(name.commonName).toBe("operator-1");
        expect(name.organizationalUnitName).toBe("Plant");
    });

    it("keeps every repeated attribute, in certificate order", () => {
        // The map can only hold one, so this is what `entries` exists for.
        const name = parse(rdn(CN(), "x"), rdn(OU(), "Plant"), rdn(OU(), "Night"));
        expect(name.entries.map((e) => [e.name, e.value])).toEqual([
            ["commonName", "x"],
            ["organizationalUnitName", "Plant"],
            ["organizationalUnitName", "Night"],
        ]);
    });

    it("still exposes the last value of a repeated attribute on the map, as before", () => {
        const name = parse(rdn(OU(), "Plant"), rdn(OU(), "Night"));
        expect(name.organizationUnitName).toBe("Night");
    });

    it("preserves order even when the same attribute is interleaved", () => {
        const name = parse(rdn(OU(), "a"), rdn(CN(), "b"), rdn(OU(), "c"));
        expect(name.entries.map((e) => e.value)).toEqual(["a", "b", "c"]);
    });

    it("reads every attribute of a multi-valued RDN, not just the first", () => {
        // SET { CN=x + serialNumber=42 } is legal X.500 and does occur; the
        // previous implementation asserted a single attribute and lost the rest.
        const name = parse(multiRdn([CN(), "x"], [SERIAL_NUMBER(), "42"]));
        expect(name.entries.map((e) => [e.name, e.value])).toEqual([
            ["commonName", "x"],
            ["serialNumber", "42"],
        ]);
        expect(name.commonName).toBe("x");
        expect(name.serialNumber).toBe("42");
    });

    it("exposes domainComponent, dnQualifier and serialNumber, which the type used to hide", () => {
        // These were produced at runtime all along but missing from DirectoryName,
        // so TypeScript hid them from callers.
        const name = parse(rdn(DC(), "example"), rdn(SERIAL_NUMBER(), "7"));
        expect(name.domainComponent).toBe("example");
        expect(name.serialNumber).toBe("7");
    });

    it("records the OID alongside the resolved name", () => {
        const name = parse(rdn(CN(), "x"));
        expect(name.entries[0].oid).toBe("2.5.4.3");
        expect(name.entries[0].name).toBe("commonName");
    });

    it("returns an empty entry list for an empty name", () => {
        const name = parse();
        expect(name.entries).toEqual([]);
    });
});
