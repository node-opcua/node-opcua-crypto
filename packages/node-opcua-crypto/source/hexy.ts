
// good enough replacement of hexy package for our needs
export function hexy(buffer: Buffer, { width, format }: { width?: number; format?: "twos" } = {}): string {
    // output in hex of 80 car
    width = width || 80;

 
    if (format === "twos") {
        width = 26*3;
    }
    const regex = new RegExp(`.{1,${width}}`, "g");
    const regexTwos = new RegExp(`.{1,${2}}`, "g");

    let  fullHex = buffer.toString("hex");
    if (format === "twos") {
        fullHex= fullHex.match(regexTwos)?.join(" ") || "";
    }
    return fullHex.match(regex)?.join("\n") || "";
}