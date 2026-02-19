import assert from "node:assert";
import { type BlockInfo, readObjectIdentifier, readStruct, readValue } from "./asn1";

export interface DirectoryName {
    stateOrProvinceName?: string;
    localityName?: string;
    organizationName?: string;
    organizationUnitName?: string;
    commonName?: string;
    countryName?: string;
}

export function readDirectoryName(buffer: Buffer, block: BlockInfo): DirectoryName {
    // AttributeTypeAndValue ::= SEQUENCE {
    //    type   ATTRIBUTE.&id({SupportedAttributes}),
    //    value  ATTRIBUTE.&Type({SupportedAttributes}{@type}),
    const set_blocks = readStruct(buffer, block);
    const names: DirectoryName = {};
    for (const set_block of set_blocks) {
        assert(set_block.tag === 0x31);
        const blocks = readStruct(buffer, set_block);
        assert(blocks.length === 1);
        assert(blocks[0].tag === 0x30);

        const sequenceBlock = readStruct(buffer, blocks[0]);
        assert(sequenceBlock.length === 2);

        const type = readObjectIdentifier(buffer, sequenceBlock[0]);
        names[type.name as keyof DirectoryName] = readValue(buffer, sequenceBlock[1]) as string;
    }
    return names;
}
