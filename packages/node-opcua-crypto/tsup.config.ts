import { defineConfig } from "tsup";

export default defineConfig({
    entry: {
        index: "index.ts",
        "source/index_web": "source/index_web.ts",
        "source_nodejs/index": "source_nodejs/index.ts",
    },
    format: ["esm", "cjs"],
    dts: true,
    splitting: true,
    sourcemap: true,
    clean: true,
    shims: true,
    target: "es2022",
    minify: false,
});
