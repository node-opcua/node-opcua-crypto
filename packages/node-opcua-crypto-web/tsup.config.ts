import { defineConfig } from "tsup";

// Declarations ONLY. The JS bundle is built by build.mjs with raw esbuild - see the
// comment there for why tsup cannot do it (its externalize plugin preempts the alias map).
//
// node: builtins must stay external here for the opposite reason to the JS build:
// rollup-plugin-dts cannot resolve a default import from a builtin and fails with
// `"default" is not exported by "node:crypto"`.
export default defineConfig({
    entry: { index_web: "source/index_web.ts" },
    dts: { only: true },
    format: ["esm"],
    platform: "browser",
    target: "es2022",
    splitting: false,
    clean: false,
    external: [/^node:/],
});
