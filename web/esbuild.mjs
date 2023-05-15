// build with esbuild
import { build } from "esbuild";
import { polyfillNode } from "esbuild-plugin-polyfill-node";

build({
    entryPoints: ["web/main.js"],
    bundle: true,
    outfile: "web/bundle.js",
    sourcemap: true,
    plugins: [
        polyfillNode({
            // Options (optional)
        }),
    ],
});
