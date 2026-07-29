// Resolved only via the "browser" export condition (webpack 5, Vite/Rollup, esbuild
// --platform=browser, Parcel). Node never sees this file.
//
// node-opcua-crypto-web is an OPTIONAL peer: it carries the pre-bundled, zero-config
// browser build (~344 KB gzip) that would otherwise be dead weight in every Node
// install. If it is not installed, the bundler fails here with an unresolved
// specifier - install it, or import "node-opcua-crypto/web" and supply your own
// polyfills for assert/constants/crypto/path/url.
export * from "node-opcua-crypto-web";
