import { defineConfig } from "tsup";

export default defineConfig({
    entry: ["web/main.ts"],
    splitting: false,
    sourcemap: true,
    format: ["esm"],
    bundle: true,
    clean: true,
});
