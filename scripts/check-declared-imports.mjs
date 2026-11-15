#!/usr/bin/env node
/**
 * Gates the issue-#99 class of bug: a publishable package importing a bare module
 * that its package.json does not declare. Such an import only resolves when the
 * package manager hoists the module in from a transitive dependency (asn1js used
 * to reach node-opcua-crypto only via @peculiar/*), and fails with
 * ERR_MODULE_NOT_FOUND under any non-hoisted layout (pnpm isolated store, hoist=false).
 *
 * The scan covers the files that actually ship - the directories listed in each
 * publishable package's "files" glob (dist/, browser/, ...) - so it sees exactly
 * what `npm pack` puts in the tarball, .js and .d.ts alike. tsc keeps comments, and
 * comments or ordinary strings can contain import-looking text, so those are
 * blanked out before matching (import specifiers themselves are kept).
 *
 * A bare specifier is allowed when it is a node builtin (with or without the
 * "node:" prefix, e.g. "crypto" in the ./web entry) or a key of the package's
 * dependencies, peerDependencies or optionalDependencies. Anything else fails.
 *
 * Run after `npm run build` (dist/ must exist).
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const packagesDir = path.join(repoRoot, "packages");

const SCANNED_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".d.ts", ".d.mts", ".d.cts"]);
const SKIP_DIRS = new Set(["node_modules", ".git"]);

const builtins = new Set(builtinModules.flatMap((m) => [m, m.replace(/^node:/, "")]));

// Blanks comments and every string literal EXCEPT import specifiers, so the import
// regexes below see real specifiers but never import-looking text inside a comment
// or an ordinary string. Newlines are preserved so offsets still map to line numbers.
function blankCommentsAndStrings(code) {
    let out = "";
    let tail = ""; // last few chars emitted, to recognise an import specifier without rescanning `out`
    const push = (s) => {
        out += s;
        tail = (tail + s).slice(-16);
    };
    let i = 0;
    let state = "code"; // code | line | block
    while (i < code.length) {
        const c = code[i];
        const next = code[i + 1];
        if (state === "code") {
            if (c === "/" && next === "/") {
                state = "line";
                push("  ");
                i += 2;
            } else if (c === "/" && next === "*") {
                state = "block";
                push("  ");
                i += 2;
            } else if (c === "'" || c === '"' || c === "`") {
                const quote = c;
                const isSpecifier = /(?:^|[^\w$])(?:from|import|require\(|import\()\s*$/.test(tail);
                let j = i + 1;
                let literal = quote;
                while (j < code.length) {
                    const d = code[j];
                    literal += d;
                    if (d === "\\") {
                        literal += code[j + 1] ?? "";
                        j += 2;
                        continue;
                    }
                    j += 1;
                    if (d === quote || (d === "\n" && quote !== "`")) {
                        break; // closing quote, or unterminated single-line string
                    }
                }
                push(isSpecifier ? literal : quote + quote);
                i = j;
            } else {
                push(c);
                i += 1;
            }
        } else if (state === "line") {
            if (c === "\n") {
                state = "code";
                push("\n");
            } else {
                push(" ");
            }
            i += 1;
        } else {
            if (c === "*" && next === "/") {
                state = "code";
                push("  ");
                i += 2;
            } else {
                push(c === "\n" ? "\n" : " ");
                i += 1;
            }
        }
    }
    return out;
}

const IMPORT_PATTERNS = [
    /\bimport\s+(?:[\w*{}\s,]+\s+from\s+)?["']([^"']+)["']/g,
    /\bexport\s+(?:\*(?:\s+as\s+\w+)?|\{[^}]*\})\s+from\s+["']([^"']+)["']/g,
    /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
];

function packageNameOf(specifier) {
    const parts = specifier.split("/");
    return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

// Relative/absolute specifiers and node builtins never need a package.json entry.
function isBuiltinOrRelative(specifier) {
    if (specifier.startsWith(".") || specifier.startsWith("/")) {
        return true;
    }
    if (specifier.startsWith("node:") || builtins.has(specifier)) {
        return true;
    }
    if (!specifier.startsWith("@") && builtins.has(specifier.split("/")[0])) {
        return true; // builtin subpath, e.g. "fs/promises"
    }
    return false;
}

function collectFiles(dir, out = []) {
    for (const entry of readdirSync(dir)) {
        if (SKIP_DIRS.has(entry) || entry.startsWith(".")) {
            continue;
        }
        const full = path.join(dir, entry);
        const stat = statSync(full);
        if (stat.isDirectory()) {
            collectFiles(full, out);
        } else if (SCANNED_EXTENSIONS.has(path.extname(entry))) {
            out.push(full);
        }
    }
    return out;
}

// Directories that end up in the published tarball: the non-negated directory
// entries of the package's "files" glob.
function shippedDirs(pkgDir, pkgJson) {
    const entries = Array.isArray(pkgJson.files) ? pkgJson.files : [];
    return entries
        .filter((e) => !e.startsWith("!") && !path.extname(e))
        .map((e) => path.join(pkgDir, e))
        .filter((p) => {
            try {
                return statSync(p).isDirectory();
            } catch {
                return false;
            }
        });
}

const failures = [];
let scannedFiles = 0;
let scannedImports = 0;

for (const entry of readdirSync(packagesDir)) {
    const pkgDir = path.join(packagesDir, entry);
    let pkgJson;
    try {
        pkgJson = JSON.parse(readFileSync(path.join(pkgDir, "package.json"), "utf8"));
    } catch {
        continue; // not a package
    }
    if (pkgJson.private) {
        continue; // only published packages can break consumers
    }
    const allowed = new Set([
        ...Object.keys(pkgJson.dependencies ?? {}),
        ...Object.keys(pkgJson.peerDependencies ?? {}),
        ...Object.keys(pkgJson.optionalDependencies ?? {}),
    ]);

    const dirs = shippedDirs(pkgDir, pkgJson);
    console.log(`${pkgJson.name}@${pkgJson.version}`);
    if (dirs.length === 0) {
        console.log("  FAIL  no shipped directories found - run `npm run build` first (dist/ missing?)");
        failures.push(`${pkgJson.name}: no shipped directories to scan`);
        continue;
    }

    const undeclared = new Map(); // "pkg|specifier" -> first location
    let pkgImports = 0;
    for (const dir of dirs) {
        for (const file of collectFiles(dir)) {
            scannedFiles += 1;
            const code = blankCommentsAndStrings(readFileSync(file, "utf8"));
            for (const pattern of IMPORT_PATTERNS) {
                pattern.lastIndex = 0;
                for (const match of code.matchAll(pattern)) {
                    const specifier = match[1];
                    if (!specifier || isBuiltinOrRelative(specifier)) {
                        continue;
                    }
                    scannedImports += 1;
                    pkgImports += 1;
                    if (allowed.has(packageNameOf(specifier))) {
                        continue;
                    }
                    // only computed for failures, so the 2 MB web bundle stays cheap to scan
                    const line = code.slice(0, match.index).split("\n").length;
                    const key = `${packageNameOf(specifier)}|${specifier}`;
                    if (!undeclared.has(key)) {
                        undeclared.set(key, `${path.relative(repoRoot, file)}:${line}`);
                    }
                }
            }
        }
    }

    if (undeclared.size === 0) {
        console.log(`  PASS  all ${pkgImports} bare imports are declared (${dirs.map((d) => path.relative(pkgDir, d)).join(", ")})`);
    } else {
        for (const [key, location] of [...undeclared.entries()].sort()) {
            const specifier = key.slice(key.indexOf("|") + 1);
            console.log(`  FAIL  "${specifier}" imported at ${location} but not in dependencies/peerDependencies/optionalDependencies`);
            failures.push(`${pkgJson.name}: undeclared import "${specifier}" at ${location}`);
        }
    }
}

console.log("");
if (failures.length > 0) {
    console.log(`check-declared-imports: ${failures.length} undeclared import(s) found. Add the package to the package.json "dependencies" of the listed package.`);
    process.exitCode = 1;
} else {
    console.log(`check-declared-imports: OK (${scannedFiles} files, ${scannedImports} bare imports checked)`);
}
