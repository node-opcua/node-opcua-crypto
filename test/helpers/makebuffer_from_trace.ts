// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2023 - Sterfive.com
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

// tslint:disable-next-line:ban-types
export function inlineText(f: (() => void) | string): string {
    let k = typeof f === "function" ?  f
        .toString()
        .replace(/^[^/]+\/\*!?/, "")
        .replace(/\*\/[^/]+$/, "") : f as string;
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
export function makebuffer_from_trace(func: (() => void )| string): Buffer {
    return makeBuffer(hexString(inlineText(func)));
}
