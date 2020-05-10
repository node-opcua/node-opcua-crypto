// tslint:disable-next-line:ban-types
export function inlineText(f: Function): string {
    let k = f
        .toString()
        .replace(/^[^\/]+\/\*!?/, "")
        .replace(/\*\/[^\/]+$/, "");
    k = k
        .split("\n")
        .map((t) => t.trim())
        .join("\n");
    return k;
}

/**
 * @method makeBuffer
 * turn a string make of hexadecimal bytes into a buffer
 *
 * @example
 *     const buffer = makeBuffer("BE EF");
 *
 * @param listOfBytes
 * @return
 */
export function makeBuffer(listOfBytes: string): Buffer {
    const l = listOfBytes.split(" ");
    const b = Buffer.allocUnsafe(l.length);
    let i = 0;
    l.forEach((value) => {
        b.writeUInt8(parseInt(value, 16), i);
        i += 1;
    });
    return b;
}

export function hexString(str: string): string {
    let hexline = "";
    const lines = str.split("\n");
    lines.forEach(function (line) {
        line = line.trim();
        if (line.length > 80) {
            line = line.substr(10, 98).trim();
            hexline = hexline ? hexline + " " + line : line;
        } else if (line.length > 60) {
            line = line.substr(7, 48).trim();
            hexline = hexline ? hexline + " " + line : line;
        }
    });
    return hexline;
}

// tslint:disable-next-line:ban-types
export function makebuffer_from_trace(func: Function): Buffer {
    return makeBuffer(hexString(inlineText(func)));
}
