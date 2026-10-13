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

/**
 * @module node_opcua_crypto
 */
import assert from "node:assert";
import {
    type Cipheriv,
    createCipheriv,
    createDecipheriv,
    createHmac,
    createSecretKey,
    type Decipheriv,
    type KeyObject,
} from "node:crypto";

import { createFastUninitializedBuffer } from "./buffer_utils.js";
import type { Nonce } from "./common.js";
import { type VerifyMessageChunkSignatureOptions, verifyMessageChunkSignature } from "./crypto_utils.js";
import { exploreCertificateInfo } from "./explore_certificate.js";
import { KeyedHmacSha256 } from "./hmac_sha256.js";

function HMAC_HASH(sha1or256: "SHA1" | "SHA256", secret: Buffer, message: Buffer) {
    return createHmac(sha1or256, secret).update(message).digest();
}

function plus(buf1: Buffer, buf2: Buffer): Buffer {
    return Buffer.concat([buf1, buf2]);
}

// OPC-UA Spec 1.02 part 6 - 6.7.5  Deriving Keys page 42
// Once the  SecureChannel  is established the  Messages  are signed and encrypted with keys derived
// from the  Nonces  exchanged in t he  OpenSecureChannel  call. These keys are derived by passing the
// Nonces  to a pseudo - random function which produces a sequence of bytes from a set of inputs.   A
// pseudo- random function  is represented by the following function declaration:
// Byte[] PRF(
//     Byte[] secret,
//     Byte[] seed,
//     Int32 length,
//     Int32 offset
// )
// Where length   is the number of bytes to return and  offset  is a number of bytes from the beginning of
// the sequence.
// The lengths of the keys that need to be generated depend on the  SecurityPolicy  used for the
//    channel. The following information is specified by the  SecurityPolicy:
//    a)  SigningKeyLength  (from the  DerivedSignatureKeyLength);
//    b)  EncryptingKeyLength  (implied by the  SymmetricEncryptionAlgorithm);
//    c)  EncryptingBlockSize  (implied by the  SymmetricEncryptionAlgorithm).
//  The parameters  passed to the pseudo random function are specified in  Table 36.
//  Table 36  - Cryptography Key Generation Parameters
//
// Key                         Secret       Seed         Length               Offset
// ClientSigningKey            ServerNonce  ClientNonce  SigningKeyLength     0
// ClientEncryptingKey         ServerNonce  ClientNonce  EncryptingKeyLength  SigningKeyLength
// ClientInitializationVector  ServerNonce  ClientNonce  EncryptingBlockSize  SigningKeyLength+ EncryptingKeyLength
// ServerSigningKey            ClientNonce  ServerNonce  SigningKeyLength     0
// ServerEncryptingKey         ClientNonce  ServerNonce  EncryptingKeyLength  SigningKeyLength
// ServerInitializationVector  ClientNonce  ServerNonce  EncryptingBlockSize  SigningKeyLength+ EncryptingKeyLength
//
// The  Client  keys are used to secure  Messages  sent by the  Client. The  Server  keys are used to
// secure Messages  sent by the  Server.
// The SSL/TLS  specification  defines a pseudo random function called P_HASH which is used for this purpose.
//
// The P_HASH  algorithm is defined as follows:
//
//    P_HASH(secret, seed) = HMAC_HASH(secret, A(1) + seed) +
//                            HMAC_HASH(secret, A(2) + seed) +
//                            HMAC_HASH(secret, A(3) + seed) + ...
// Where A(n) is defined as:
//       A(0) = seed
//       A(n) = HMAC_HASH(secret, A(n-1))
//            + indicates that the results are appended to previous results.
// Where HASH is a hash function such as SHA1 or SHA256. The hash function to use depends on the SecurityPolicyUri.
//
//
// see also http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/ws-secureconversation-1.3-os.html
//          http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
export function makePseudoRandomBuffer(secret: Nonce, seed: Nonce, minLength: number, sha1or256: "SHA1" | "SHA256"): Buffer {
    assert(Buffer.isBuffer(seed));
    assert(sha1or256 === "SHA1" || sha1or256 === "SHA256");

    const a: Buffer[] = [];
    a[0] = seed;
    let index = 1;
    let p_hash = createFastUninitializedBuffer(0);
    while (p_hash.length <= minLength) {
        a[index] = HMAC_HASH(sha1or256, secret, a[index - 1]);
        p_hash = plus(p_hash, HMAC_HASH(sha1or256, secret, plus(a[index], seed)));
        index += 1;
    }
    return p_hash.subarray(0, minLength);
}

export interface ComputeDerivedKeysOptions {
    signatureLength: number;
    signingKeyLength: number;
    encryptingKeyLength: number;

    encryptingBlockSize: number;
    algorithm: string;
    sha1or256?: "SHA1" | "SHA256";
}

export interface DerivedKeys extends ComputeDerivedKeysOptions {
    signatureLength: number;
    signingKeyLength: number;
    encryptingKeyLength: number;

    encryptingBlockSize: number;
    algorithm: string;
    sha1or256: "SHA1" | "SHA256";

    signingKey: Buffer;
    encryptingKey: Buffer;
    initializationVector: Buffer;
}

export function computeDerivedKeys(secret: Nonce, seed: Nonce, options: ComputeDerivedKeysOptions): DerivedKeys {
    assert(Number.isFinite(options.signatureLength));
    assert(Number.isFinite(options.encryptingKeyLength));
    assert(Number.isFinite(options.encryptingBlockSize));
    assert(typeof options.algorithm === "string");
    options.sha1or256 = options.sha1or256 || "SHA1";
    assert(typeof options.sha1or256 === "string");

    const offset1 = options.signingKeyLength;
    const offset2 = offset1 + options.encryptingKeyLength;
    const minLength = offset2 + options.encryptingBlockSize;

    const buf = makePseudoRandomBuffer(secret, seed, minLength, options.sha1or256);

    // +---------------+---------------------+-----------------------+
    // + signingKey    + encryptingKey       + initializationVector  +
    // +---------------+---------------------+-----------------------+
    return {
        signatureLength: options.signatureLength,
        signingKeyLength: options.signingKeyLength,
        encryptingKeyLength: options.encryptingKeyLength,

        encryptingBlockSize: options.encryptingBlockSize,
        algorithm: options.algorithm,
        sha1or256: options.sha1or256,

        signingKey: buf.subarray(0, offset1),
        encryptingKey: buf.subarray(offset1, offset2),
        initializationVector: buf.subarray(offset2, minLength),
    };
}

/**
 * @method reduceLength
 * @param buffer
 * @param byteToRemove
 * @return buffer
 */
export function reduceLength(buffer: Buffer, byteToRemove: number): Buffer {
    return buffer.subarray(0, buffer.length - byteToRemove);
}

/**
 * @method removePadding
 * @param buffer
 * @return buffer with padding removed
 */
export function removePadding(buffer: Buffer): Buffer {
    const nbPaddingBytes = buffer.readUInt8(buffer.length - 1) + 1;
    return reduceLength(buffer, nbPaddingBytes);
}

export type VerifyChunkSignatureOptions = VerifyMessageChunkSignatureOptions;

/**
 * @method verifyChunkSignature
 *
 *     const signer = {
 *           signatureLength : 128,
 *           algorithm : "RSA-SHA256",
 *           public_key: "qsdqsdqsd"
 *     };
 *
 * @param chunk  The message chunk to verify.
 * @param options
 * @param options.signatureLength
 * @param options.algorithm  the algorithm.
 * @param options.publicKey
 * @return {*}
 */
export function verifyChunkSignature(chunk: Buffer, options: VerifyChunkSignatureOptions): boolean {
    assert(Buffer.isBuffer(chunk));
    let signatureLength = options.signatureLength || 0;
    if (signatureLength === 0) {
        // let's get the signatureLength by checking the size
        // of the certificate's public key
        const cert = exploreCertificateInfo(options.publicKey);
        signatureLength = cert.publicKeyLength || 0; // 1024 bits = 128Bytes or 2048=256Bytes
    }
    const block_to_verify = chunk.subarray(0, chunk.length - signatureLength);
    const signature = chunk.subarray(chunk.length - signatureLength);
    return verifyMessageChunkSignature(block_to_verify, signature, options);
}

// /**
//  * extract the public key from a certificate - using the pem module
//  *
//  * @method extractPublicKeyFromCertificate_WithPem
//  * @async
//  * @param certificate
//  * @param callback {Function}
//  * @param callback.err
//  * @param callback.publicKey as pem
//  */
// exports.extractPublicKeyFromCertificate_WithPem = function (certificate, callback) {
//
//     const err1 = new Error();
//     const cert_pem = crypto_utils.toPem(certificate, "CERTIFICATE");
//     require("pem").getPublicKey(cert_pem, function (err, data) {
//         if (err) {
//             console.log(err1.stack);
//             console.log(" CANNOT EXTRAT PUBLIC KEY from Certificate".red, certificate);
//             return callback(err);
//         }
//         callback(err, data.publicKey);
//     });
// };
//

export function computePaddingFooter(buffer: Buffer, derivedKeys: DerivedKeys): Buffer {
    assert(Object.hasOwn(derivedKeys, "encryptingBlockSize"));
    const paddingSize = derivedKeys.encryptingBlockSize - ((buffer.length + 1) % derivedKeys.encryptingBlockSize);
    const padding = createFastUninitializedBuffer(paddingSize + 1);
    padding.fill(paddingSize);
    return padding;
}

// The KeyObject of each derived key, made once. Handing node:crypto a Buffer as key makes it check and wrap
// that key on every call, which costs more than signing or encrypting an 8 KiB chunk. A derived key is
// never modified once computed, so its Buffer stands for its KeyObject. (crypto-browserify, in the web
// build, has no createSecretKey: the Buffer is used as it is there.)
const keyObjects = new WeakMap<Buffer, KeyObject>();
function keyObjectOf(key: Buffer): KeyObject | Buffer {
    if (typeof createSecretKey !== "function") return key;
    let keyObject = keyObjects.get(key);
    if (!keyObject) {
        keyObject = createSecretKey(key);
        keyObjects.set(key, keyObject);
    }
    return keyObject;
}

function derivedKeys_algorithm(derivedKeys: DerivedKeys) {
    assert(Object.hasOwn(derivedKeys, "algorithm"));
    const algorithm = derivedKeys.algorithm || "aes-128-cbc";
    assert(algorithm === "aes-128-cbc" || algorithm === "aes-256-cbc");
    return algorithm;
}

// One long-lived Cipher and Decipher per encrypting key. node:crypto has no way to rewind a CBC cipher to its IV,
// and creating one per chunk (context allocation, key schedule, four calls into C++) costs several times the AES
// work on a small chunk. Every chunk of a token is encrypted from the same IV, so the cipher is never finalised:
// one extra block, fed before each chunk, brings its chaining state back to the IV.
//  - encrypting X = D_k(IV) xor C_prev gives E_k(X xor C_prev) = IV, which becomes the chaining state;
//  - decrypting IV as a ciphertext block makes IV the chaining state.
// The output of that extra block is dropped. Only for whole blocks (anything else is refused by final() anyway),
// and only with node:crypto: the web build keeps one cipher per chunk.
interface SymmetricCipherState {
    initializationVector: Buffer;
    encrypt?: { cipher: Cipheriv; decryptedIv: Buffer; lastBlock: Buffer };
    decrypt?: Decipheriv;
}
const cipherStates = new WeakMap<Buffer, SymmetricCipherState>();
const canKeepCiphers = typeof createSecretKey === "function";

function cipherStateOf(derivedKeys: DerivedKeys): SymmetricCipherState {
    let state = cipherStates.get(derivedKeys.encryptingKey);
    if (!state || state.initializationVector !== derivedKeys.initializationVector) {
        state = { initializationVector: derivedKeys.initializationVector };
        cipherStates.set(derivedKeys.encryptingKey, state);
    }
    return state;
}

// the reset block and the chunk side by side, for a single update() call (cheaper than two calls); one buffer for
// the whole process rather than one per channel, as every call completes synchronously
let scratch = Buffer.alloc(0);
function withLeadingBlock(block: Buffer, buffer: Buffer): Buffer {
    const length = block.length + buffer.length;
    if (scratch.length < length) {
        scratch = Buffer.alloc(Math.max(length, 2 * scratch.length));
    }
    block.copy(scratch, 0);
    buffer.copy(scratch, block.length);
    return scratch.subarray(0, length);
}

function isWholeBlocks(buffer: Buffer, derivedKeys: DerivedKeys): boolean {
    const blockSize = derivedKeys.initializationVector.length;
    return blockSize === 16 && buffer.length > 0 && buffer.length % blockSize === 0;
}

export function encryptBufferWithDerivedKeys(buffer: Buffer, derivedKeys: DerivedKeys): Buffer {
    const algorithm = derivedKeys_algorithm(derivedKeys);
    const key = derivedKeys.encryptingKey;
    const initVector = derivedKeys.initializationVector;
    if (canKeepCiphers && isWholeBlocks(buffer, derivedKeys)) {
        const state = cipherStateOf(derivedKeys);
        if (!state.encrypt) {
            const blockDecipher = createDecipheriv(algorithm.replace("-cbc", "-ecb"), keyObjectOf(key), null);
            blockDecipher.setAutoPadding(false);
            const decryptedIv = blockDecipher.update(initVector);
            const cipher = createCipheriv(algorithm, keyObjectOf(key), initVector);
            cipher.setAutoPadding(false);
            // a new cipher chains from the IV already: the reset block of the first chunk turns it into the IV again
            state.encrypt = { cipher, decryptedIv, lastBlock: initVector };
        }
        const encrypt = state.encrypt;
        const blockSize = initVector.length;
        const reset = Buffer.allocUnsafe(blockSize);
        for (let i = 0; i < blockSize; i++) {
            reset[i] = encrypt.decryptedIv[i] ^ encrypt.lastBlock[i];
        }
        const encrypted = encrypt.cipher.update(withLeadingBlock(reset, buffer));
        encrypt.lastBlock = encrypted.subarray(encrypted.length - blockSize);
        return encrypted.subarray(blockSize);
    }
    const cipher = createCipheriv(algorithm, keyObjectOf(key), initVector);

    cipher.setAutoPadding(false);
    const encrypted = cipher.update(buffer);
    // without padding, a buffer of whole blocks is all in the output of update()
    const tail = cipher.final();
    return tail.length === 0 ? encrypted : Buffer.concat([encrypted, tail]);
}

export function decryptBufferWithDerivedKeys(buffer: Buffer, derivedKeys: DerivedKeys): Buffer {
    const algorithm = derivedKeys_algorithm(derivedKeys);
    const key = derivedKeys.encryptingKey;
    const initVector = derivedKeys.initializationVector;
    if (canKeepCiphers && isWholeBlocks(buffer, derivedKeys)) {
        const state = cipherStateOf(derivedKeys);
        if (!state.decrypt) {
            state.decrypt = createDecipheriv(algorithm, keyObjectOf(key), initVector);
            state.decrypt.setAutoPadding(false);
        }
        // decrypting the IV as a block makes it the chaining state; its own output is dropped
        return state.decrypt.update(withLeadingBlock(initVector, buffer)).subarray(initVector.length);
    }
    const cipher = createDecipheriv(algorithm, keyObjectOf(key), initVector);

    cipher.setAutoPadding(false);
    const decrypted = cipher.update(buffer);
    const tail = cipher.final();
    return tail.length === 0 ? decrypted : Buffer.concat([decrypted, tail]);
}

// Up to this size a chunk is signed by KeyedHmacSha256 (key pads compressed once) rather than by a new node:crypto
// Hmac: on a small chunk creating the Hmac costs more than hashing. Above it the native SHA-256 is faster.
// Measured on a Celeron J4125, Node 24: 128 B 6.0 us against 10.3 us; 1 KiB 20.7 us against 11.4 us.
const KEYED_HMAC_MAX_MESSAGE = 256;
const keyedHmacs = new WeakMap<Buffer, KeyedHmacSha256>();
function keyedHmacOf(signingKey: Buffer): KeyedHmacSha256 {
    let hmac = keyedHmacs.get(signingKey);
    if (!hmac) {
        hmac = new KeyedHmacSha256(signingKey);
        keyedHmacs.set(signingKey, hmac);
    }
    return hmac;
}

/**
 * @method makeMessageChunkSignatureWithDerivedKeys
 * @param message
 * @param derivedKeys
 * @return
 */
export function makeMessageChunkSignatureWithDerivedKeys(message: Buffer, derivedKeys: DerivedKeys): Buffer {
    assert(Buffer.isBuffer(message));
    assert(Buffer.isBuffer(derivedKeys.signingKey));
    assert(typeof derivedKeys.sha1or256 === "string");
    assert(derivedKeys.sha1or256 === "SHA1" || derivedKeys.sha1or256 === "SHA256");
    const useKeyedHmac =
        derivedKeys.sha1or256 === "SHA256" && message.length <= KEYED_HMAC_MAX_MESSAGE && derivedKeys.signingKey.length <= 64;
    const signature = useKeyedHmac
        ? keyedHmacOf(derivedKeys.signingKey).digest(message)
        : createHmac(derivedKeys.sha1or256, keyObjectOf(derivedKeys.signingKey)).update(message).digest();
    assert(signature.length === derivedKeys.signatureLength);
    return signature;
}

/**
 * @method verifyChunkSignatureWithDerivedKeys
 * @param chunk
 * @param derivedKeys
 * @return
 */
export function verifyChunkSignatureWithDerivedKeys(chunk: Buffer, derivedKeys: DerivedKeys): boolean {
    const message = chunk.subarray(0, chunk.length - derivedKeys.signatureLength);
    const expectedSignature = chunk.subarray(chunk.length - derivedKeys.signatureLength);
    const computedSignature = makeMessageChunkSignatureWithDerivedKeys(message, derivedKeys);
    if (computedSignature.length !== expectedSignature.length) {
        return false;
    }
    // every byte is compared, whatever the first difference
    let difference = 0;
    for (let i = 0; i < computedSignature.length; i++) {
        difference |= computedSignature[i] ^ expectedSignature[i];
    }
    return difference === 0;
}
