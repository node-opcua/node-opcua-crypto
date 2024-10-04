import { BlockInfo, readTag, readStruct, TagType } from "./asn1";
import { hexDump } from "./crypto_utils";

function t(tag: number) {
    // convert Asn1 tag to string
    return TagType[tag];
}
function bi(blockInfo: BlockInfo, depth: number) {
    const indent = "  ".repeat(depth);
    const hl = blockInfo.position - blockInfo.start; // header length
    return `${blockInfo.start.toString().padStart(5, " ")}:d=${depth} hl=${hl.toString().padEnd(3, " ")}  l=${blockInfo.length
        .toString()
        .padStart(6, " ")} ${blockInfo.tag.toString(16).padEnd(2, " ")} ${indent} ${t(blockInfo.tag)}`;
}

export function exploreAsn1(buffer: Buffer) {
    console.log(hexDump(buffer));

    function dump(offset: number, depth: number) {
        const blockInfo = readTag(buffer, offset);
        dumpBlock(blockInfo, depth);

        function dumpBlock(blockInfo: BlockInfo, depth: number) {
            console.log(bi(blockInfo, depth));
            if (blockInfo.tag === TagType.SEQUENCE || blockInfo.tag === TagType.SET || blockInfo.tag >= TagType.CONTEXT_SPECIFIC0) {
                const blocks = readStruct(buffer, blockInfo);
                for (const block of blocks) {
                    dumpBlock(block, depth +1);
                }
            }
        }
    }
    dump(0, 0);
}
