// vite.config.js
import { defineConfig } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";

export default defineConfig({
    plugins: [
        nodePolyfills({
            include: ["crypto", "constants", "url", "path", "buffer", "process"],
            globals: {
                Buffer: true,
                process: true,
            },
            // Active les polyfills pour les fonctions spécifiques de crypto
            crypto: true,
        }),
    ],
    build: {
        outDir: "./dist",
        emptyOutDir: true,
        minify: true,
        sourcemap: true,
        rollupOptions: {
            input: "./web/main.ts",
            output: {
                format: "esm",
                entryFileNames: "main.mjs",
            },
            plugins: [
                // Polyfills supplémentaires pour Rollup
                nodePolyfills(),
            ],
        },
    },
});
