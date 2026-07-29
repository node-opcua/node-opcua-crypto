#!/usr/bin/env node
/**
 * Proves the browser/Node split actually holds, end to end, through a real bundler.
 *
 * node-opcua-crypto is deliberately kept lean for Node: the pre-bundled browser build
 * (~347 KB gzip, larger than the entire Node tarball) lives in the separate
 * node-opcua-crypto-web package, and node-opcua-crypto's "browser" export condition
 * redirects to it via a ~60 byte stub (packages/node-opcua-crypto/browser/index.js).
 *
 * That arrangement is invisible to the type checker and to `npm test` - it only shows up
 * when a bundler resolves the package. Four things can silently break it:
 *
 *   - the "browser" condition being reordered after "import"/"require" (first match wins,
 *     so a browser bundler would quietly get the Node build)
 *   - the stub or the browser/ folder dropping out of the "files" globs
 *   - the web bundle regaining an unresolvable bare import (e.g. "crypto"), which no
 *     browser can load
 *   - the Node build accidentally picking up browser polyfills
 *
 * Run after `npm run build`.
 */
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const entry = path.join(repoRoot, "test", "browser-redirect", "app.ts");
const outDir = path.join(repoRoot, "test", "browser-redirect", "dist");

const failures = [];
const check = (ok, label, detail) => {
    console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}`);
    if (!ok) {
        failures.push(detail ? `${label} - ${detail}` : label);
    }
};

mkdirSync(outDir, { recursive: true });

async function bundle(platform) {
    const outfile = path.join(outDir, `out-${platform}.js`);
    await esbuild.build({
        entryPoints: [entry],
        outfile,
        bundle: true,
        format: "esm",
        platform,
        logLevel: "silent",
    });
    return readFileSync(outfile, "utf8");
}

// Markers unique to the pre-bundled browser package. crypto-browserify only ever gets
// inlined by node-opcua-crypto-web's build; the Node build never contains it.
const BROWSER_MARKERS = /crypto-browserify|createPublicKeyFromDer|browserify-sign/;

console.log("browser redirect (platform=browser)");
let browserBundle;
try {
    browserBundle = await bundle("browser");
    check(true, "bundles without unresolved imports");
} catch (err) {
    check(false, "bundles without unresolved imports", String(err.message ?? err).split("\n")[0]);
}

if (browserBundle) {
    check(
        BROWSER_MARKERS.test(browserBundle),
        "resolves through node-opcua-crypto-web",
        'the "browser" export condition did not win - check that it is declared FIRST in exports["."]',
    );
    // A bare `from"crypto"` surviving here would throw in every browser.
    const bare = [...browserBundle.matchAll(/\bfrom\s*"([^".][^"]*)"/g)]
        .map((m) => m[1])
        .filter((s) => !s.startsWith(".") && !s.startsWith("/"));
    check(bare.length === 0, "no unresolved bare imports remain", bare.join(", "));
}

console.log("node build (platform=node)");
let nodeBundle;
try {
    nodeBundle = await bundle("node");
    check(true, "bundles");
} catch (err) {
    check(false, "bundles", String(err.message ?? err).split("\n")[0]);
}

if (nodeBundle) {
    check(
        !BROWSER_MARKERS.test(nodeBundle),
        "does NOT pull in browser polyfills",
        "the Node build leaked the browser bundle - node-opcua-crypto got heavier for every Node consumer",
    );
    check(/from\s*"node:crypto"|require\("node:crypto"\)/.test(nodeBundle), "keeps native node:crypto");
}

// The browser bundle must not merely resolve - it must run. _crypto.ts branches on
// `typeof window`, so present a browser-shaped global before importing it.
console.log("browser bundle executes");
try {
    globalThis.window = globalThis;
    const webEntry = path.join(repoRoot, "packages", "node-opcua-crypto-web", "dist", "index_web.js");
    const web = await import(`file://${webEntry.split(path.sep).join("/")}`);
    const pem = readFileSync(
        path.join(repoRoot, "packages", "node-opcua-crypto-test", "test-fixtures", "certs", "server_cert_2048.pem"),
        "utf8",
    );
    const info = web.exploreCertificate(web.convertPEMtoDER(pem));
    check(info.tbsCertificate.subject.commonName === "NodeOPCUA", "parses a certificate", "unexpected common name");
} catch (err) {
    check(false, "parses a certificate", String(err.message ?? err).split("\n")[0]);
}

rmSync(outDir, { recursive: true, force: true });

if (failures.length > 0) {
    console.error(`\n${failures.length} check(s) failed:`);
    for (const f of failures) {
        console.error(`  - ${f}`);
    }
    process.exit(1);
}
console.log("\nall browser/node split checks passed");
