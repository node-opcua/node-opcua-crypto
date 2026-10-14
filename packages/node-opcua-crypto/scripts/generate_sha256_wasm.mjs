// Writes a WebAssembly module computing SHA-256 compressions and keyed HMAC-SHA256, byte by byte, without a toolchain.
//   compress(statePtr, blockPtr): one SHA-256 block into the 8-word state at statePtr (native-endian words)
//   hmac(keyPtr, msgPtr, nBlocks, outPtr): the inner state from keyPtr (8 words), nBlocks already padded blocks at
//     msgPtr, then the outer hash from keyPtr + 32 over the 64-byte outer block at OUTER (bytes 32..63 prefilled by
//     the caller), the digest written big-endian at outPtr.
//
// The module is committed as base64 in source/sha256_wasm_module.ts; regenerate it with
//   node scripts/generate_sha256_wasm.mjs
// (test_sha256_wasm.ts checks that the committed module is what this script produces).
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const STATE = 0;
const OUTER = 64;

// biome-ignore format: the table of FIPS 180-4
const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/** unsigned LEB128 */
function uleb(n) {
    const out = [];
    do {
        let b = n & 0x7f;
        n >>>= 7;
        if (n) b |= 0x80;
        out.push(b);
    } while (n);
    return out;
}

/** signed LEB128 of a 32-bit value */
function sleb(v) {
    let n = v | 0;
    const out = [];
    for (;;) {
        const b = n & 0x7f;
        n >>= 7;
        if ((n === 0 && !(b & 0x40)) || (n === -1 && b & 0x40)) {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

const OP = { add: 0x6a, sub: 0x6b, and: 0x71, or: 0x72, xor: 0x73, shr_u: 0x76, rotl: 0x77, rotr: 0x78, eqz: 0x45 };

class Code {
    b = [];
    get(i) {
        this.b.push(0x20, ...uleb(i));
    }
    set(i) {
        this.b.push(0x21, ...uleb(i));
    }
    const(v) {
        this.b.push(0x41, ...sleb(v));
    }
    load(offset) {
        this.b.push(0x28, 0x02, ...uleb(offset));
    }
    store(offset) {
        this.b.push(0x36, 0x02, ...uleb(offset));
    }
    op(name) {
        this.b.push(OP[name]);
    }
    call(index) {
        this.b.push(0x10, ...uleb(index));
    }
    rotr(local, n) {
        this.get(local);
        this.const(n);
        this.op("rotr");
    }
    /** the local, byte-swapped: (rotl(x, 8) & 0x00ff00ff) | (rotr(x, 8) & 0xff00ff00) */
    bswap(local) {
        this.get(local);
        this.const(8);
        this.op("rotl");
        this.const(0x00ff00ff);
        this.op("and");
        this.get(local);
        this.const(8);
        this.op("rotr");
        this.const(0xff00ff00);
        this.op("and");
        this.op("or");
    }
}

/** a function body: one group of `localCount` i32 locals, then the code */
function body(localCount, code) {
    const bytes = [...uleb(1), ...uleb(localCount), 0x7f, ...code.b, 0x0b];
    return [...uleb(bytes.length), ...bytes];
}

function compressBody() {
    // params: 0 statePtr, 1 blockPtr; locals: W0..W63 = 2..65, a..h = 66..73, t1 = 74
    const c = new Code();
    const W = (i) => 2 + i;
    const names = [66, 67, 68, 69, 70, 71, 72, 73];
    const T1 = 74;
    for (let i = 0; i < 16; i++) {
        c.get(1);
        c.load(4 * i);
        c.set(W(i));
        c.bswap(W(i));
        c.set(W(i));
    }
    for (let i = 16; i < 64; i++) {
        c.get(W(i - 16));
        // s0 = rotr 7 ^ rotr 18 ^ shr 3
        c.rotr(W(i - 15), 7);
        c.rotr(W(i - 15), 18);
        c.op("xor");
        c.get(W(i - 15));
        c.const(3);
        c.op("shr_u");
        c.op("xor");
        c.op("add");
        c.get(W(i - 7));
        c.op("add");
        // s1 = rotr 17 ^ rotr 19 ^ shr 10
        c.rotr(W(i - 2), 17);
        c.rotr(W(i - 2), 19);
        c.op("xor");
        c.get(W(i - 2));
        c.const(10);
        c.op("shr_u");
        c.op("xor");
        c.op("add");
        c.set(W(i));
    }
    for (let k = 0; k < 8; k++) {
        c.get(0);
        c.load(4 * k);
        c.set(names[k]);
    }
    // the working variables are renamed from round to round instead of moved
    for (let i = 0; i < 64; i++) {
        const [a, b, cc, d, e, f, g, h] = [0, 1, 2, 3, 4, 5, 6, 7].map((k) => names[(((k - i) % 8) + 8) % 8]);
        // t1 = h + S1(e) + Ch(e, f, g) + K[i] + W[i], Ch = g ^ (e & (f ^ g))
        c.get(h);
        c.rotr(e, 6);
        c.rotr(e, 11);
        c.op("xor");
        c.rotr(e, 25);
        c.op("xor");
        c.op("add");
        c.get(g);
        c.get(e);
        c.get(f);
        c.get(g);
        c.op("xor");
        c.op("and");
        c.op("xor");
        c.op("add");
        c.const(K[i]);
        c.op("add");
        c.get(W(i));
        c.op("add");
        c.set(T1);
        // d += t1
        c.get(d);
        c.get(T1);
        c.op("add");
        c.set(d);
        // h = t1 + S0(a) + Maj(a, b, c), Maj = (a & b) | (c & (a | b))
        c.get(T1);
        c.rotr(a, 2);
        c.rotr(a, 13);
        c.op("xor");
        c.rotr(a, 22);
        c.op("xor");
        c.op("add");
        c.get(a);
        c.get(b);
        c.op("and");
        c.get(cc);
        c.get(a);
        c.get(b);
        c.op("or");
        c.op("and");
        c.op("or");
        c.op("add");
        c.set(h);
    }
    for (let k = 0; k < 8; k++) {
        c.get(0);
        c.get(0);
        c.load(4 * k);
        c.get(names[k]);
        c.op("add");
        c.store(4 * k);
    }
    return body(73, c);
}

function hmacBody() {
    // params: 0 keyPtr, 1 msgPtr, 2 nBlocks, 3 outPtr; local 4: temp
    const c = new Code();
    const X = 4;
    for (let k = 0; k < 8; k++) {
        // inner midstate -> STATE
        c.const(STATE);
        c.get(0);
        c.load(4 * k);
        c.store(4 * k);
    }
    c.b.push(0x02, 0x40, 0x03, 0x40); // block, loop
    c.get(2);
    c.op("eqz");
    c.b.push(0x0d, ...uleb(1)); // br_if out of the block
    c.const(STATE);
    c.get(1);
    c.call(0);
    c.get(1);
    c.const(64);
    c.op("add");
    c.set(1);
    c.get(2);
    c.const(1);
    c.op("sub");
    c.set(2);
    c.b.push(0x0c, ...uleb(0), 0x0b, 0x0b); // br loop, end loop, end block
    for (let k = 0; k < 8; k++) {
        // the inner digest, big-endian, into the outer block
        c.const(OUTER);
        c.const(STATE);
        c.load(4 * k);
        c.set(X);
        c.bswap(X);
        c.store(4 * k);
    }
    for (let k = 0; k < 8; k++) {
        // outer midstate -> STATE
        c.const(STATE);
        c.get(0);
        c.load(32 + 4 * k);
        c.store(4 * k);
    }
    c.const(STATE);
    c.const(OUTER);
    c.call(0);
    for (let k = 0; k < 8; k++) {
        // the digest, big-endian, at outPtr
        c.get(3);
        c.const(STATE);
        c.load(4 * k);
        c.set(X);
        c.bswap(X);
        c.store(4 * k);
    }
    return body(1, c);
}

const section = (id, payload) => [id, ...uleb(payload.length), ...payload];
const name = (s) => [...uleb(s.length), ...Buffer.from(s)];

/** the bytes of the module */
export function buildSha256WasmModule() {
    const I32 = 0x7f;
    const types = [...uleb(2), 0x60, ...uleb(2), I32, I32, ...uleb(0), 0x60, ...uleb(4), I32, I32, I32, I32, ...uleb(0)];
    const functions = [...uleb(2), ...uleb(0), ...uleb(1)];
    const memory = [...uleb(1), 0x00, ...uleb(2)]; // 2 pages, growable
    const exportsSection = [
        ...uleb(3),
        ...name("memory"),
        0x02,
        ...uleb(0),
        ...name("compress"),
        0x00,
        ...uleb(0),
        ...name("hmac"),
        0x00,
        ...uleb(1),
    ];
    const code = [...uleb(2), ...compressBody(), ...hmacBody()];
    return Buffer.from([
        0x00,
        0x61,
        0x73,
        0x6d,
        0x01,
        0x00,
        0x00,
        0x00,
        ...section(1, types),
        ...section(3, functions),
        ...section(5, memory),
        ...section(7, exportsSection),
        ...section(10, code),
    ]);
}

/** the TypeScript file that carries the module */
export function sha256WasmModuleSource() {
    const base64 = buildSha256WasmModule().toString("base64");
    const lines = (base64.match(/.{1,120}/g) ?? []).map((line, i, all) => `    "${line}"${i < all.length - 1 ? " +" : ";"}`);
    return `// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
// ---------------------------------------------------------------------------------------------------------------------

// GENERATED by scripts/generate_sha256_wasm.mjs: do not edit. The WebAssembly module of hmac_sha256_wasm.ts.
export const sha256WasmModuleBase64 =
${lines.join(String.fromCharCode(10))}
`;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    const target = fileURLToPath(new URL("../source/sha256_wasm_module.ts", import.meta.url));
    if (process.argv.includes("--check")) {
        // the committed module must be what this script writes
        if (readFileSync(target, "utf8").replaceAll("\r\n", "\n") !== sha256WasmModuleSource()) {
            console.error(`${target} is not what scripts/generate_sha256_wasm.mjs writes: run it`);
            process.exit(1);
        }
        console.log(`${target}: up to date`);
    } else {
        writeFileSync(target, sha256WasmModuleSource());
        console.log(`${target}: ${buildSha256WasmModule().length} bytes of WebAssembly`);
    }
}
