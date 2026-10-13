// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
// ---------------------------------------------------------------------------------------------------------------------

/**
 * @module node_opcua_crypto
 */

// HMAC-SHA256 in plain JavaScript, keyed once: the inner and outer pads of the key are compressed when the key is
// first seen, so signing a message costs the compressions of the message itself plus one for the outer hash.
// node:crypto cannot keep a keyed Hmac between messages, and for the small chunks of a secure channel (a Read
// response is ~130 bytes) creating one costs several times the hashing. SHA-256 has no secret-dependent branch or
// table lookup, so this runs in constant time like the native one.

// Int32Array, not Uint32Array: V8 reads a Uint32Array element above 2^31 as a heap number (a double), which takes
// every round of the compression off the integer fast path. The bits are the same.
const K = new Int32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const INITIAL_STATE = new Int32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
const BLOCK_SIZE = 64;

// shared scratch: every call runs to completion synchronously
const W = new Int32Array(64);
const H = new Int32Array(8);
const tail = new Uint8Array(2 * BLOCK_SIZE);
const innerDigest = new Uint8Array(32);

function compress(state: Int32Array, bytes: Uint8Array, offset: number): void {
    for (let i = 0; i < 16; i++, offset += 4) {
        W[i] = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    }
    for (let i = 16; i < 64; i++) {
        const w15 = W[i - 15];
        const w2 = W[i - 2];
        const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
        const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    let a = state[0];
    let b = state[1];
    let c = state[2];
    let d = state[3];
    let e = state[4];
    let f = state[5];
    let g = state[6];
    let h = state[7];
    let t1 = 0;
    // eight rounds per iteration: each round updates d and h, and the next one reads the names shifted by one
    for (let i = 0; i < 64; i += 8) {
        t1 =
            (h +
                (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) +
                ((e & f) ^ (~e & g)) +
                K[i + 0] +
                W[i + 0]) |
            0;
        d = (d + t1) | 0;
        h =
            (t1 + (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c))) |
            0;
        t1 =
            (g +
                (((d >>> 6) | (d << 26)) ^ ((d >>> 11) | (d << 21)) ^ ((d >>> 25) | (d << 7))) +
                ((d & e) ^ (~d & f)) +
                K[i + 1] +
                W[i + 1]) |
            0;
        c = (c + t1) | 0;
        g =
            (t1 + (((h >>> 2) | (h << 30)) ^ ((h >>> 13) | (h << 19)) ^ ((h >>> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b))) |
            0;
        t1 =
            (f +
                (((c >>> 6) | (c << 26)) ^ ((c >>> 11) | (c << 21)) ^ ((c >>> 25) | (c << 7))) +
                ((c & d) ^ (~c & e)) +
                K[i + 2] +
                W[i + 2]) |
            0;
        b = (b + t1) | 0;
        f =
            (t1 + (((g >>> 2) | (g << 30)) ^ ((g >>> 13) | (g << 19)) ^ ((g >>> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a))) |
            0;
        t1 =
            (e +
                (((b >>> 6) | (b << 26)) ^ ((b >>> 11) | (b << 21)) ^ ((b >>> 25) | (b << 7))) +
                ((b & c) ^ (~b & d)) +
                K[i + 3] +
                W[i + 3]) |
            0;
        a = (a + t1) | 0;
        e =
            (t1 + (((f >>> 2) | (f << 30)) ^ ((f >>> 13) | (f << 19)) ^ ((f >>> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h))) |
            0;
        t1 =
            (d +
                (((a >>> 6) | (a << 26)) ^ ((a >>> 11) | (a << 21)) ^ ((a >>> 25) | (a << 7))) +
                ((a & b) ^ (~a & c)) +
                K[i + 4] +
                W[i + 4]) |
            0;
        h = (h + t1) | 0;
        d =
            (t1 + (((e >>> 2) | (e << 30)) ^ ((e >>> 13) | (e << 19)) ^ ((e >>> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g))) |
            0;
        t1 =
            (c +
                (((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7))) +
                ((h & a) ^ (~h & b)) +
                K[i + 5] +
                W[i + 5]) |
            0;
        g = (g + t1) | 0;
        c =
            (t1 + (((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f))) |
            0;
        t1 =
            (b +
                (((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7))) +
                ((g & h) ^ (~g & a)) +
                K[i + 6] +
                W[i + 6]) |
            0;
        f = (f + t1) | 0;
        b =
            (t1 + (((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e))) |
            0;
        t1 =
            (a +
                (((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7))) +
                ((f & g) ^ (~f & h)) +
                K[i + 7] +
                W[i + 7]) |
            0;
        e = (e + t1) | 0;
        a =
            (t1 + (((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d))) |
            0;
    }
    state[0] = (state[0] + a) | 0;
    state[1] = (state[1] + b) | 0;
    state[2] = (state[2] + c) | 0;
    state[3] = (state[3] + d) | 0;
    state[4] = (state[4] + e) | 0;
    state[5] = (state[5] + f) | 0;
    state[6] = (state[6] + g) | 0;
    state[7] = (state[7] + h) | 0;
}

// absorbs data into a state that has already absorbed one block (the key pad), pads, and writes the digest
function finish(state: Int32Array, data: Uint8Array, out: Uint8Array): void {
    const length = data.length;
    let offset = 0;
    for (; offset + BLOCK_SIZE <= length; offset += BLOCK_SIZE) {
        compress(state, data, offset);
    }
    const rest = length - offset;
    // byte by byte rather than tail.set(data.subarray(offset)): no view object per message
    for (let i = 0; i < rest; i++) {
        tail[i] = data[offset + i];
    }
    tail.fill(0, rest);
    tail[rest] = 0x80;
    const end = rest + 9 > BLOCK_SIZE ? 2 * BLOCK_SIZE : BLOCK_SIZE;
    const bits = (BLOCK_SIZE + length) * 8;
    tail[end - 5] = Math.floor(bits / 0x100000000);
    tail[end - 4] = bits >>> 24;
    tail[end - 3] = bits >>> 16;
    tail[end - 2] = bits >>> 8;
    tail[end - 1] = bits;
    compress(state, tail, 0);
    if (end > BLOCK_SIZE) {
        compress(state, tail, BLOCK_SIZE);
    }
    for (let i = 0, o = 0; i < 8; i++) {
        const v = state[i];
        out[o++] = v >>> 24;
        out[o++] = v >>> 16;
        out[o++] = v >>> 8;
        out[o++] = v;
    }
}

/** an HMAC-SHA256 key, prepared once, that signs any number of messages */
export class KeyedHmacSha256 {
    readonly #inner = new Int32Array(8);
    readonly #outer = new Int32Array(8);

    /** @param key at most 64 bytes, as every derived signing key of the OPC UA security policies */
    constructor(key: Uint8Array) {
        if (key.length > BLOCK_SIZE) {
            throw new Error("KeyedHmacSha256: keys longer than 64 bytes are not supported");
        }
        const pad = new Uint8Array(BLOCK_SIZE);
        pad.fill(0x36);
        for (let i = 0; i < key.length; i++) pad[i] ^= key[i];
        this.#inner.set(INITIAL_STATE);
        compress(this.#inner, pad, 0);
        pad.fill(0x5c);
        for (let i = 0; i < key.length; i++) pad[i] ^= key[i];
        this.#outer.set(INITIAL_STATE);
        compress(this.#outer, pad, 0);
    }

    digest(message: Uint8Array): Buffer {
        const signature = Buffer.allocUnsafe(32);
        H.set(this.#inner);
        finish(H, message, innerDigest);
        H.set(this.#outer);
        finish(H, innerDigest, signature);
        return signature;
    }
}
