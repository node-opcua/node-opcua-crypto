// Types for the "browser" export condition. TypeScript only follows this when the
// consumer opts in with "customConditions": ["browser"] (moduleResolution bundler or
// node16+); otherwise it keeps the Node types, which describe the same API surface
// minus the Node-only entry points.
export * from "node-opcua-crypto-web";
