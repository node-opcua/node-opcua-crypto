// The bundle entry.
//
// It reaches into node-opcua-crypto's TypeScript SOURCE by relative path rather than
// importing the package by name, for two reasons:
//
//  1. Cycle. The bare "node-opcua-crypto" specifier carries a "browser" export
//     condition that redirects back to this very package; bundling with
//     platform:browser would follow it straight into a loop.
//  2. Self-contained types. tsup's dts rollup does not follow the "node-opcua-crypto/web"
//     subpath (dts.resolve has no effect on it) and emits a bare re-export, which would
//     make these published types require node-opcua-crypto to be installed alongside.
//     Pointing at the source lets the rollup inline the declarations.
//
// Building from source is also what we want at runtime: dist/source/index_web.js shares
// chunk-BGGEFTMF.js with the Node entry, which drags in Node-only imports.
export * from "../../node-opcua-crypto/source/index_web.js";
