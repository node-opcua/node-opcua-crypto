// Fixture for scripts/check-browser-redirect.mjs.
//
// It imports the BARE specifier on purpose - that is the whole point of the check.
// "node-opcua-crypto" carries a "browser" export condition, so a browser bundler must
// land on the pre-bundled node-opcua-crypto-web package while a Node bundler must keep
// the native Node build.
//
// It must live inside the repo: Node resolution walks up from the ENTRY file, so a
// fixture in the system temp dir would find some unrelated global install instead of
// this workspace (which is exactly what happened while developing this check).
import { convertPEMtoDER, exploreCertificate } from "node-opcua-crypto";

export { convertPEMtoDER, exploreCertificate };
