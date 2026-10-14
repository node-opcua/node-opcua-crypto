// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
// ---------------------------------------------------------------------------------------------------------------------

// The WebAssembly HMAC-SHA256 module is committed (source/sha256_wasm_module.ts): it must be what
// scripts/generate_sha256_wasm.mjs writes. Its signatures are checked against node:crypto, through
// makeMessageChunkSignatureWithDerivedKeys, by test_derived_keys_hmac_paths.ts.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { describe, expect, it } from "vitest";

describe("WebAssembly HMAC-SHA256 module", () => {
    it("the committed module is what scripts/generate_sha256_wasm.mjs writes", () => {
        const script = path.join(__dirname, "../../node-opcua-crypto/scripts/generate_sha256_wasm.mjs");
        const result = spawnSync(process.execPath, [script, "--check"], { encoding: "utf8" });
        expect(result.stderr).toBe("");
        expect(result.status).toBe(0);
    });
});
