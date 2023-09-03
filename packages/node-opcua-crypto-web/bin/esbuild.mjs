// build with esbuild
import { build } from "esbuild";
import { polyfillNode } from "esbuild-plugin-polyfill-node";

build({
    entryPoints: ["./web/main.ts"],
    bundle: true,
    outfile: "./web/bundle.js",
    sourcemap: true,
    format: "esm",
    minify: true,
    plugins: [
        polyfillNode({
            polyfills: {
                crypto: true
            }
        }),
    ],
});


console.log("done");
