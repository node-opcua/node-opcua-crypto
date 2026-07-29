# node-opcua-crypto-web

Pre-bundled, zero-config browser build of [`node-opcua-crypto`](https://www.npmjs.com/package/node-opcua-crypto).

## Why this package exists

`node-opcua-crypto` is kept lean for Node.js. A browser build has to inline its own
polyfills (`crypto-browserify`, `stream-browserify`, …), which weighs roughly **347 KB
gzip** — more than the entire `node-opcua-crypto` tarball. Shipping that inside the main
package would make every Node consumer download a browser bundle they never import.

So it lives here instead, and Node users never pay for it.

## Usage

### Automatic (recommended)

Install both packages and keep importing `node-opcua-crypto` as usual:

```bash
npm install node-opcua-crypto node-opcua-crypto-web
```

```ts
import { exploreCertificate, convertPEMtoDER } from "node-opcua-crypto";
```

`node-opcua-crypto` declares a `"browser"` export condition that redirects to this
package, so webpack 5, Vite/Rollup, esbuild (`--platform=browser`) and Parcel pick it up
automatically. Node ignores the condition and keeps the native build — the same source
file works in both targets.

If you bundle for the browser *without* installing this package, your bundler fails with
an unresolved `node-opcua-crypto-web`. That is deliberate: it tells you the browser build
is missing rather than silently bundling the Node one.

For TypeScript to follow the same condition, add:

```jsonc
{ "compilerOptions": { "customConditions": ["browser"] } }
```

Without it, TypeScript keeps the Node types, which describe the same API surface minus
the Node-only entry points.

### Direct

```ts
import { exploreCertificate } from "node-opcua-crypto-web";
```

### Bring your own polyfills

If you would rather bundle from source and control the polyfills yourself, skip this
package and import `node-opcua-crypto/web`. That entry costs the main package almost
nothing (it shares a chunk with the Node entry), but it still imports `assert`,
`constants`, `crypto`, `path` and `url`, so your bundler must supply them.

## What is inside

An ESM-only, fully self-contained bundle — no runtime dependencies, no bare imports.
`node:crypto` is served by a local shim over `crypto-browserify` that adds the
`createPublicKey` / `createPrivateKey` functions it lacks, and WebCrypto comes from the
browser's native `globalThis.crypto` rather than `@peculiar/webcrypto`.

There is no CommonJS build. A CJS consumer must use `await import(...)`.

## License

MIT — see [LICENSE](./LICENSE).
