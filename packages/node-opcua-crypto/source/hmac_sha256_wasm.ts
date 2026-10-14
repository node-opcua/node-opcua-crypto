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

// HMAC-SHA256 in WebAssembly, keyed once like KeyedHmacSha256: about 1.4 times faster than the JavaScript one on a
// small chunk (Node 22 to 26), as the compression runs on registers without the JIT's checks. The module is written
// by scripts/generate_sha256_wasm.mjs (sha256_wasm_module.ts). It is compiled on first use, synchronously: Node
// allows it at any size, a browser main thread does not, so only the Node build uses it (see derived_keys.ts).

import { sha256WasmModuleBase64 } from "./sha256_wasm_module.js";

// the memory layout of the module (scripts/generate_sha256_wasm.mjs): STATE and OUTER are fixed by the module itself
const STATE = 0;
const OUTER = 64;
const OUT = 128;
const KEY = 256; // the inner and outer midstates of the key of the current call
const MESSAGE = 1024;
const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

interface Sha256Wasm {
    memory: WebAssembly.Memory;
    compress: (statePtr: number, blockPtr: number) => void;
    hmac: (keyPtr: number, msgPtr: number, nBlocks: number, outPtr: number) => void;
    bytes: Uint8Array;
    words: Int32Array;
}

let instance: Sha256Wasm | null | undefined;

function sha256Wasm(): Sha256Wasm | null {
    if (instance !== undefined) {
        return instance;
    }
    try {
        const module = new WebAssembly.Module(Buffer.from(sha256WasmModuleBase64, "base64"));
        const exports = new WebAssembly.Instance(module, {}).exports as unknown as Omit<Sha256Wasm, "bytes" | "words">;
        const memory = exports.memory;
        instance = { ...exports, bytes: new Uint8Array(memory.buffer), words: new Int32Array(memory.buffer) };
        // the outer block after the inner digest: 0x80, zeros, the bit length of a key block and a digest (768)
        instance.bytes.fill(0, OUTER + 32, OUTER + 64);
        instance.bytes[OUTER + 32] = 0x80;
        instance.bytes[OUTER + 62] = 0x03;
    } catch {
        instance = null; // no WebAssembly here: the caller keeps the JavaScript HMAC
    }
    return instance;
}

/** room for `size` bytes of message; growing the memory detaches the views, so they are made again */
function ensureCapacity(wasm: Sha256Wasm, size: number): void {
    const needed = MESSAGE + size;
    if (needed > wasm.memory.buffer.byteLength) {
        wasm.memory.grow(Math.ceil((needed - wasm.memory.buffer.byteLength) / 65536));
        wasm.bytes = new Uint8Array(wasm.memory.buffer);
        wasm.words = new Int32Array(wasm.memory.buffer);
    }
}

/** an HMAC-SHA256 key, prepared once, that signs any number of messages in WebAssembly */
export class WasmHmacSha256 {
    readonly #midstates = new Int32Array(16);

    /** whether WebAssembly compiles here (compiling the module on the first call) */
    public static available(): boolean {
        return sha256Wasm() !== null;
    }

    /** null when WebAssembly is not available: use KeyedHmacSha256 */
    public static create(key: Uint8Array): WasmHmacSha256 | null {
        const wasm = sha256Wasm();
        return wasm ? new WasmHmacSha256(wasm, key) : null;
    }

    private constructor(wasm: Sha256Wasm, key: Uint8Array) {
        if (key.length > 64) {
            throw new Error("WasmHmacSha256: keys longer than 64 bytes are not supported");
        }
        // the inner and outer pads of the key, compressed once
        for (const [pad, at] of [
            [0x36, 0],
            [0x5c, 8],
        ]) {
            for (let i = 0; i < 64; i++) {
                wasm.bytes[MESSAGE + i] = (i < key.length ? key[i] : 0) ^ pad;
            }
            wasm.words.set(IV, STATE >> 2);
            wasm.compress(STATE, MESSAGE);
            this.#midstates.set(wasm.words.subarray(STATE >> 2, (STATE >> 2) + 8), at);
        }
    }

    digest(message: Uint8Array): Buffer {
        const wasm = instance as Sha256Wasm;
        const length = message.length;
        const blocks = Math.floor((length + 9 + 63) / 64);
        ensureCapacity(wasm, blocks * 64);
        const bytes = wasm.bytes;
        wasm.words.set(this.#midstates, KEY >> 2);
        bytes.set(message, MESSAGE);
        // SHA-256 padding: 0x80, zeros, the bit length of the key block and the message, big-endian on 64 bits
        const end = MESSAGE + blocks * 64;
        bytes[MESSAGE + length] = 0x80;
        bytes.fill(0, MESSAGE + length + 1, end - 5);
        const bits = (64 + length) * 8;
        bytes[end - 5] = Math.floor(bits / 0x100000000);
        bytes[end - 4] = bits >>> 24;
        bytes[end - 3] = bits >>> 16;
        bytes[end - 2] = bits >>> 8;
        bytes[end - 1] = bits;
        wasm.hmac(KEY, MESSAGE, blocks, OUT);
        const signature = Buffer.allocUnsafe(32);
        signature.set(bytes.subarray(OUT, OUT + 32));
        return signature;
    }
}
