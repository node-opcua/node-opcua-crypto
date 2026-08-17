// ---------------------------------------------------------------------------------------------------------------------
// node-opcua-crypto
// ---------------------------------------------------------------------------------------------------------------------
// Copyright (c) 2014-2022 - Etienne Rossignon - etienne.rossignon (at) gadz.org
// Copyright (c) 2022-2026 - Sterfive.com
// ---------------------------------------------------------------------------------------------------------------------
//
// This  project is licensed under the terms of the MIT license.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so,  subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ---------------------------------------------------------------------------------------------------------------------

import fs from "node:fs";

/**
 * Restrict a private key file to owner-only access (mode 0600).
 *
 * `fs.chmod` only toggles the read-only attribute on Windows and cannot
 * express POSIX-style owner-only permissions, so this is a no-op there
 * rather than a false sense of protection. Errors are logged, not thrown:
 * a read-only mount or an unexpected ownership mismatch should not prevent
 * a caller from starting up.
 */
export async function restrictPrivateKeyFilePermissions(filename: string): Promise<void> {
    // istanbul ignore if
    if (process.platform === "win32") {
        return;
    }
    try {
        await fs.promises.chmod(filename, 0o600);
    } catch (err) {
        // istanbul ignore next
        console.warn(`could not restrict permissions on ${filename}: ${(err as Error).message}`);
    }
}
