// esbuild.config.mjs

import { NodeGlobalsPolyfillPlugin } from "@esbuild-plugins/node-globals-polyfill";
import { NodeModulesPolyfillPlugin } from "@esbuild-plugins/node-modules-polyfill";
import { build } from "esbuild";

build({
    entryPoints: ["./web/main.ts"],
    bundle: true,
    outfile: "./dist/main.mjs",
    sourcemap: true,
    format: "esm",
    minify: true,
    platform: "browser", // On cible le navigateur
    plugins: [
        // Polyfill les modules Node.js (crypto, constants, path, etc.)
        NodeModulesPolyfillPlugin(),
        // Polyfill les globals (Buffer, process, etc.)
        NodeGlobalsPolyfillPlugin({
            buffer: true,
            process: true,
        }),
    ],
})
    .then(() => {
        console.log("Build terminée avec succès !");
    })
    .catch((error) => {
        console.error("Erreur lors du build :", error);
        process.exit(1);
    });
