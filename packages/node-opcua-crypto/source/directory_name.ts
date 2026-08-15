import assert from "node:assert";
import { type BlockInfo, readObjectIdentifier, readStruct, readValue } from "./asn1";

/**
 * One attribute of a Distinguished Name, as it appears in the certificate.
 *
 * Kept as an ordered list alongside the convenience map because a DN is a
 * *sequence*, not a record: an attribute may legitimately repeat (two `OU`s,
 * several `DC`s), and both the repetition and the order carry meaning. Callers
 * that must reproduce a DN faithfully — OPC UA Part 18 §4.4.3 Table 10
 * `X509Subject` role criteria, for instance — cannot do so from the map alone,
 * because the map keeps only the last value for a repeated attribute.
 */
export interface DistinguishedNameAttribute {
    /** Dotted OID, e.g. `2.5.4.3`. */
    oid: string;
    /** Resolved attribute name, e.g. `commonName`; the OID when unknown. */
    name: string;
    value: string;
}

/**
 * A parsed Distinguished Name.
 *
 * The named properties are a convenience view and keep the **last** value when
 * an attribute repeats. {@link DirectoryName.entries} is the faithful one.
 */
export interface DirectoryName {
    stateOrProvinceName?: string;
    localityName?: string;
    organizationName?: string;
    /**
     * OU (2.5.4.11). Note the spelling: the OID table resolves this attribute to
     * `organizationalUnitName`, so this is the property that carries the value.
     */
    organizationalUnitName?: string;
    /**
     * @deprecated Misspelling of {@link DirectoryName.organizationalUnitName}.
     *
     * It was **never populated**. The parser keys properties by the name the OID
     * table returns — `organizationalUnitName` — so every caller reading this got
     * `undefined` and silently lost the OU. It is now filled with the same value,
     * so existing readers start working instead of continuing to miss it.
     */
    organizationUnitName?: string;
    commonName?: string;
    countryName?: string;
    /**
     * These three were always produced at runtime — the parser assigns whatever
     * name the OID resolves to — but were missing from this interface, so
     * TypeScript hid them from callers.
     */
    domainComponent?: string;
    dnQualifier?: string;
    /** The DN's own `serialNumber` attribute (2.5.4.5), not the certificate's. */
    serialNumber?: string;
    /** Every attribute in certificate order, repeats included. */
    entries: DistinguishedNameAttribute[];
}

export function readDirectoryName(buffer: Buffer, block: BlockInfo): DirectoryName {
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    // RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
    // AttributeTypeAndValue ::= SEQUENCE {
    //    type   ATTRIBUTE.&id({SupportedAttributes}),
    //    value  ATTRIBUTE.&Type({SupportedAttributes}{@type}),
    const set_blocks = readStruct(buffer, block);
    const entries: DistinguishedNameAttribute[] = [];

    for (const set_block of set_blocks) {
        assert(set_block.tag === 0x31);
        const blocks = readStruct(buffer, set_block);

        // A RelativeDistinguishedName is a SET of one *or more* attributes: a
        // multi-valued RDN such as `CN=x + serialNumber=1` is legal X.500 and
        // does occur. The previous implementation asserted exactly one and threw
        // on such a certificate rather than parsing it.
        for (const attribute_block of blocks) {
            assert(attribute_block.tag === 0x30);
            const sequenceBlock = readStruct(buffer, attribute_block);
            assert(sequenceBlock.length === 2);

            const type = readObjectIdentifier(buffer, sequenceBlock[0]);
            const value = readValue(buffer, sequenceBlock[1]) as string;
            entries.push({ oid: type.oid, name: type.name, value });
        }
    }

    const names: DirectoryName = { entries };
    // Last-wins for the convenience view, which is the historical behaviour and
    // what existing callers already rely on.
    const asRecord = names as unknown as Record<string, unknown>;
    for (const entry of entries) {
        asRecord[entry.name] = entry.value;
        // Fill the long-standing misspelling too, so callers written against it
        // stop silently receiving undefined.
        if (entry.name === "organizationalUnitName") {
            asRecord.organizationUnitName = entry.value;
        }
    }
    return names;
}
