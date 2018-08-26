
export function inlineText(f: Function): string {
    var k = f.toString().
        replace(/^[^\/]+\/\*!?/, '').
        replace(/\*\/[^\/]+$/, '');
    k = k.split("\n").map(function(t){  t = t.trim(); return t; }).join("\n");
    return k;
}


/**
 * @method makeBuffer
 * turn a string make of hexadecimal bytes into a buffer
 *
 * @example
 *     var buffer = makeBuffer("BE EF");
 *
 * @param listOfBytes
 * @return {Buffer}
 */
export function makeBuffer(listOfBytes: string): Buffer {
    var l = listOfBytes.split(" ");
    var b = new Buffer(l.length);
    var i = 0;
    l.forEach(function (value) {
        b.writeUInt8(parseInt(value, 16), i);
        i += 1;
    });
    return b;
}

export  function hexString(str: string): string {
    var hexline = "";
    var lines = str.split("\n");
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

export function makebuffer_from_trace(func: Function) {
    return makeBuffer(hexString(inlineText(func)));
}
