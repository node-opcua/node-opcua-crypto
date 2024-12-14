import * as loremIpsum1 from "lorem-ipsum";
import fs from "fs";
import constants from "constants";
import sshpk from "sshpk";
import "should";

import { publicEncrypt, privateDecrypt, createPrivateKey, createPublicKey } from "crypto";
const PaddingAlgorithm = {
    RSA_PKCS1_OAEP_PADDING: 4,
    RSA_PKCS1_PADDING: 1,
};
const RSA_PKCS1_OAEP_PADDING = constants.RSA_PKCS1_OAEP_PADDING;
const RSA_PKCS1_PADDING = constants.RSA_PKCS1_PADDING;
const createFastUninitializedBuffer = (size) => Buffer.allocUnsafe(size);

export function publicEncrypt_native(buffer, publicKey, algorithm) {
    if (algorithm === undefined) {
        algorithm = PaddingAlgorithm.RSA_PKCS1_PADDING;
    }
    return publicEncrypt(
        {
            key: publicKey,
            padding: algorithm,
        },
        buffer
    );
}

export function privateDecrypt_native(buffer, privateKey, algorithm) {
    if (algorithm === undefined) {
        algorithm = PaddingAlgorithm.RSA_PKCS1_OAEP_PADDING;
    }

    try {
        return privateDecrypt(
            {
                key: privateKey.hidden,
                padding: algorithm,
            },
            buffer
        );
    } catch (err) {
        console.log("privateDecrypt_native error", err);
        return Buffer.alloc(1);
    }
}

export function publicEncrypt_long(buffer, publicKey, blockSize, padding, paddingAlgorithm) {
    if (paddingAlgorithm === undefined) {
        paddingAlgorithm = PaddingAlgorithm.RSA_PKCS1_OAEP_PADDING;
    }
    if (paddingAlgorithm !== RSA_PKCS1_PADDING && paddingAlgorithm !== RSA_PKCS1_OAEP_PADDING) {
        throw new Error("Invalid padding algorithm " + paddingAlgorithm);
    }

    const chunk_size = blockSize - padding;
    const nbBlocks = Math.ceil(buffer.length / chunk_size);

    const outputBuffer = createFastUninitializedBuffer(nbBlocks * blockSize);
    for (let i = 0; i < nbBlocks; i++) {
        const currentBlock = buffer.slice(chunk_size * i, chunk_size * (i + 1));

        const encrypted_chunk = publicEncrypt_native(currentBlock, publicKey, paddingAlgorithm);
        // istanbul ignore next
        if (encrypted_chunk.length !== blockSize) {
            throw new Error(`publicEncrypt_long unexpected chunk length ${encrypted_chunk.length}  expecting ${blockSize}`);
        }
        encrypted_chunk.copy(outputBuffer, i * blockSize);
    }
    return outputBuffer;
}

export function privateDecrypt_long(buffer, privateKey, blockSize, paddingAlgorithm) {
    paddingAlgorithm = paddingAlgorithm || RSA_PKCS1_OAEP_PADDING;
    // istanbul ignore next
    if (paddingAlgorithm !== RSA_PKCS1_PADDING && paddingAlgorithm !== RSA_PKCS1_OAEP_PADDING) {
        throw new Error("Invalid padding algorithm " + paddingAlgorithm);
    }

    const nbBlocks = Math.ceil(buffer.length / blockSize);

    const outputBuffer = createFastUninitializedBuffer(nbBlocks * blockSize);

    let total_length = 0;
    for (let i = 0; i < nbBlocks; i++) {
        const currentBlock = buffer.subarray(blockSize * i, Math.min(blockSize * (i + 1), buffer.length));
        const decrypted_buf = privateDecrypt_native(currentBlock, privateKey, paddingAlgorithm);
        decrypted_buf.copy(outputBuffer, total_length);
        total_length += decrypted_buf.length;
    }
    return outputBuffer.subarray(0, total_length);
}

export function readPrivateRsaKey(filename) {
    const content = fs.readFileSync(filename, "utf8");
    const sshKey = sshpk.parsePrivateKey(content, "auto");
    const key = sshKey.toString("pkcs1");
    const hidden = createPrivateKey({ format: "pem", type: "pkcs1", key });
    return { hidden };
}

function readPublicRsaKey(filename) {
    const content = fs.readFileSync(filename, "utf-8");
    const sshKey = sshpk.parseKey(content, "ssh");
    const key = sshKey.toString("pkcs1");
    console.log("publicKey=\n" + key);
    return createPublicKey({ format: "pem", type: "pkcs1", key });
}

const loremIpsum = loremIpsum1.loremIpsum({ count: 100 });

const bob_public_key = readPublicRsaKey("./test-fixtures/certs/bob_id_rsa.pub", "utf-8");
console.log(bob_public_key);

const bob_private_key = readPrivateRsaKey("./test-fixtures/certs/bob_id_rsa");

const initialBuffer = Buffer.from("Hello World");

const encryptedBuffer1 = publicEncrypt_long(initialBuffer, bob_public_key, 256, 11);
const encryptedBuffer2 = publicEncrypt_long(initialBuffer, bob_public_key, 256, 11);

encryptedBuffer1.toString("hex").should.not.equal(encryptedBuffer2.toString("hex"));

const decryptedBuffer1 = privateDecrypt_long(encryptedBuffer1, bob_private_key, 256);
const decryptedBuffer2 = privateDecrypt_long(encryptedBuffer2, bob_private_key, 256);

decryptedBuffer1.toString("hex").should.equal(decryptedBuffer2.toString("hex"));
console.log("decryptedBuffer1=", decryptedBuffer1.toString("utf-8"));
