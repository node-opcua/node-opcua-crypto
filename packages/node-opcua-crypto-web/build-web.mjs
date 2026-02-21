import * as esbuild from "esbuild";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function build() {
    // Ensure output directories exist
    fs.mkdirSync(path.join(__dirname, "dist", "assets"), { recursive: true });

    // Copy index.html to dist/web/
    const webDir = path.join(__dirname, "dist", "web");
    fs.mkdirSync(webDir, { recursive: true });
    fs.copyFileSync(path.join(__dirname, "web", "index.html"), path.join(webDir, "index.html"));

    await esbuild.build({
        entryPoints: [path.join(__dirname, "web", "main.ts")],
        bundle: true,
        outfile: path.join(__dirname, "dist", "assets", "main.js"),
        format: "esm",
        platform: "browser",
        target: "es2022",
        minify: false,
        sourcemap: true,
        external: [],
        alias: {
            // Resolve node-opcua-crypto/web to its TypeScript source
            // so esbuild bundles it from scratch (the pre-built dist/ has Node-only imports)
            "node-opcua-crypto/web": path.resolve(__dirname, "..", "node-opcua-crypto", "source", "index_web.ts"),
            // Node built-in → browser polyfill (with createPublicKey/createPrivateKey shims)
            "crypto": path.resolve(__dirname, "node-crypto-shim.js"),
            "node:crypto": path.resolve(__dirname, "node-crypto-shim.js"),
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
            string_decoder: "string_decoder",
            "node:string_decoder": "string_decoder",
            // Redirect safe-buffer to buffer polyfill
            "safe-buffer": "buffer",
            // Use native browser crypto instead of @peculiar/webcrypto
            "@peculiar/webcrypto": path.resolve(__dirname, "webcrypto-shim.js"),
        },
        define: {
            "global": "globalThis",
            // Replace process.env references at compile time so _crypto.ts
            // doesn't crash when the process polyfill lacks .env
            "process.env.IGNORE_SUBTLE_FROM_CRYPTO": "undefined",
            "process.env.NODE_DEBUG": "undefined",
            "process.env.NODE_ENV": JSON.stringify("production"),
        },
        inject: [path.join(__dirname, "inject-buffer.js")],
        logLevel: "info",
    });

    console.log("Build complete: dist/assets/main.js");
}

build().catch((err) => {
    console.error(err);
    process.exit(1);
});
