#!/usr/bin/env node
// ---------------------------------------------------------------------------------------------------------------------
// Script: generate_pfx_fixtures.js
//
// Generates PKCS#12 / PFX test fixture files of various
// compositions using OpenSSL CLI.
//
// Usage:
//   node scripts/generate_pfx_fixtures.js
//
// Output directory:
//   packages/node-opcua-crypto-test/test-fixtures/pfx/
// ---------------------------------------------------------------------------------------------------------------------

const { execSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const outDir = path.join(
    __dirname,
    "..",
    "packages",
    "node-opcua-crypto-test",
    "test-fixtures",
    "pfx",
);

const tmpDir = path.join(__dirname, "..", "_tmp_pfx_gen");

function ensureDir(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

function ssl(cmd) {
    console.log(`  > openssl ${cmd}`);
    return execSync(`openssl ${cmd}`, {
        cwd: tmpDir,
        stdio: ["pipe", "pipe", "pipe"],
    });
}

function cleanup() {
    if (fs.existsSync(tmpDir)) {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
}

try {
    ensureDir(outDir);
    ensureDir(tmpDir);

    // ── 1. Generate a leaf private key ──────────────────────────────
    console.log("1. Generating leaf private key...");
    ssl("genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out leaf_key.pem");

    // ── 2. Generate a self-signed leaf certificate ──────────────────
    console.log("2. Generating self-signed leaf certificate...");
    ssl(
        'req -new -x509 -key leaf_key.pem -out leaf_cert.pem -days 3650 -subj "/CN=PFXTestLeaf/O=TestOrg"',
    );

    // ── 3. Generate a CA private key + self-signed CA cert ──────────
    console.log("3. Generating CA key and certificate...");
    ssl("genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca_key.pem");
    ssl(
        'req -new -x509 -key ca_key.pem -out ca_cert.pem -days 3650 -subj "/CN=TestCA/O=TestOrg"',
    );

    // ── 4. Create a CSR for a CA-signed leaf certificate ────────────
    console.log("4. Creating CA-signed leaf certificate...");
    ssl(
        'req -new -key leaf_key.pem -out leaf_csr.pem -subj "/CN=PFXTestSigned/O=TestOrg"',
    );
    ssl(
        "x509 -req -in leaf_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out signed_cert.pem -days 3650",
    );

    // ── 5. Generate an ECC private key + cert ───────────────────────
    console.log("5. Generating ECC key and certificate...");
    ssl("ecparam -name prime256v1 -genkey -noout -out ecc_key.pem");
    ssl(
        'req -new -x509 -key ecc_key.pem -out ecc_cert.pem -days 3650 -subj "/CN=PFXTestECC/O=TestOrg"',
    );

    // ── PFX Generation ─────────────────────────────────────────────

    // A) Simple PFX — cert + key, no password
    console.log("A. Creating simple PFX (no password)...");
    ssl(
        "pkcs12 -export -in leaf_cert.pem -inkey leaf_key.pem -out simple_no_password.pfx -passout pass:",
    );
    fs.copyFileSync(
        path.join(tmpDir, "simple_no_password.pfx"),
        path.join(outDir, "simple_no_password.pfx"),
    );

    // B) PFX with password
    console.log("B. Creating PFX with password...");
    ssl(
        "pkcs12 -export -in leaf_cert.pem -inkey leaf_key.pem -out with_password.pfx -passout pass:secret",
    );
    fs.copyFileSync(
        path.join(tmpDir, "with_password.pfx"),
        path.join(outDir, "with_password.pfx"),
    );

    // C) PFX with CA chain
    console.log("C. Creating PFX with CA chain...");
    ssl(
        "pkcs12 -export -in signed_cert.pem -inkey leaf_key.pem -certfile ca_cert.pem -out with_ca_chain.pfx -passout pass:",
    );
    fs.copyFileSync(
        path.join(tmpDir, "with_ca_chain.pfx"),
        path.join(outDir, "with_ca_chain.pfx"),
    );

    // D) PFX with CA chain and password
    console.log("D. Creating PFX with CA chain and password...");
    ssl(
        "pkcs12 -export -in signed_cert.pem -inkey leaf_key.pem -certfile ca_cert.pem -out with_ca_chain_password.pfx -passout pass:capass",
    );
    fs.copyFileSync(
        path.join(tmpDir, "with_ca_chain_password.pfx"),
        path.join(outDir, "with_ca_chain_password.pfx"),
    );

    // E) PFX with ECC key
    console.log("E. Creating PFX with ECC certificate...");
    ssl(
        "pkcs12 -export -in ecc_cert.pem -inkey ecc_key.pem -out ecc.pfx -passout pass:",
    );
    fs.copyFileSync(
        path.join(tmpDir, "ecc.pfx"),
        path.join(outDir, "ecc.pfx"),
    );

    // F) PFX with friendly name
    console.log("F. Creating PFX with friendly name...");
    ssl(
        'pkcs12 -export -in leaf_cert.pem -inkey leaf_key.pem -name "MyFriendlyName" -out with_friendly_name.pfx -passout pass:',
    );
    fs.copyFileSync(
        path.join(tmpDir, "with_friendly_name.pfx"),
        path.join(outDir, "with_friendly_name.pfx"),
    );

    console.log("\n=== All PFX fixtures generated successfully ===");
    console.log(`Output directory: ${outDir}`);
    console.log("Files:");
    for (const f of fs.readdirSync(outDir)) {
        const stat = fs.statSync(path.join(outDir, f));
        console.log(`  ${f}  (${stat.size} bytes)`);
    }
} finally {
    cleanup();
}
