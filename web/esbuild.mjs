// build with esbuild
import { build } from "esbuild";
import { polyfillNode } from "esbuild-plugin-polyfill-node";

build({
    entryPoints: ["web/main.ts"],
    bundle: true,
    outfile: "web/bundle.js",
    sourcemap: true,
    // minify: true,
    plugins: [
        polyfillNode({
            polyfills: {
                crypto: true, // 'rollup-plugin-node-polyfills/polyfills/crypto-browserify'
            // Options (optional)
            }
        }),
    ],
});
