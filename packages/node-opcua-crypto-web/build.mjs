// Builds the JS bundle with raw esbuild rather than tsup.
//
// tsup installs its own externalize plugin that resolves node: builtins to "external"
// BEFORE esbuild's alias map gets a chance to run, so the aliases below were silently
// ignored and the bundle shipped bare `import ... from "crypto"` - unresolvable in a
// browser. Driving esbuild directly is the same approach the demo package uses.
//
// tsup still owns the .d.ts rollup (see tsup.config.ts), where node: builtins must stay
// external for the opposite reason.
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const shim = (name) => path.join(__dirname, "shims", name);

await esbuild.build({
    entryPoints: [path.join(__dirname, "source", "index_web.ts")],
    outfile: path.join(__dirname, "dist", "index_web.js"),
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    sourcemap: true,
    minify: false,
    external: [],
    alias: {
        // node:crypto needs more than crypto-browserify offers
        // (createPublicKey / createPrivateKey), hence the local shim.
        crypto: shim("node-crypto-shim.js"),
        "node:crypto": shim("node-crypto-shim.js"),
        assert: "assert",
        "node:assert": "assert",
        buffer: "buffer",
        "node:buffer": "buffer",
        stream: "stream-browserify",
        "node:stream": "stream-browserify",
        util: "util",
        "node:util": "util",
        constants: "constants-browserify",
        "node:constants": "constants-browserify",
        events: "events",
        "node:events": "events",
        vm: "vm-browserify",
        "node:vm": "vm-browserify",
        path: "path-browserify",
        "node:path": "path-browserify",
        string_decoder: "string_decoder",
        "node:string_decoder": "string_decoder",
        // safe-buffer's Node implementation leaks Buffer internals.
        "safe-buffer": "buffer",
        // Prefer the browser's native WebCrypto; @peculiar/webcrypto is a Node shim and
        // would pull Node crypto back in.
        "@peculiar/webcrypto": shim("webcrypto-shim.js"),
    },
    define: {
        global: "globalThis",
        // Resolved at build time so _crypto.ts does not crash when the process polyfill
        // has no .env.
        "process.env.IGNORE_SUBTLE_FROM_CRYPTO": "undefined",
        "process.env.NODE_DEBUG": "undefined",
        "process.env.NODE_ENV": JSON.stringify("production"),
    },
    inject: [shim("inject-buffer.js")],
    logLevel: "info",
});

console.log("bundled -> dist/index_web.js");
