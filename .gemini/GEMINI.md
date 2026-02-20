# node-opcua-crypto Project Notes

## Publishing

- Do NOT publish from the dev machine using `lerna publish` or `npm publish`.
- Publishing should be done via the GitHub Actions CI workflow (see `.github/workflows/`).
- Use `lerna version minor --yes` locally to bump versions and push tags, then let CI handle the publish.

## Building

- Use `npm run build` (runs `tsup` → outputs to `dist/`).
- Do NOT use `tsc -b` — it outputs `.js`/`.js.map` files alongside sources.
