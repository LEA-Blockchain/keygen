const { createBLAKE3 } = require('hash-wasm');
const { encode } = require('./bech32m');

const ADDRESS_HRP = 'lea';

/**
 * Derives the public address from a given keyset.
 * @param {Array} keyset - The keyset array.
 * @returns {Promise<string>} The Bech32m-encoded public address.
 */
async function getAddressFromKeyset(keyset) {
    const ed25519Sk = new Uint8Array(keyset[0]);
    const sphincsPk = new Uint8Array(keyset[1][1]);

    // The Ed25519 public key is the second half of the secret key.
    const ed25519Pk = ed25519Sk.slice(32);

    const blake3 = await createBLAKE3();
    blake3.init();
    blake3.update(ed25519Pk);
    blake3.update(sphincsPk);
    const addressHash = blake3.digest('binary');

    return encode(ADDRESS_HRP, addressHash);
}

/**
 * Generates a new keyset including Ed25519 and SPHINCS+ keys.
 * @returns {Promise<object>} An object containing the keyset and the derived public address.
 */
async function generateKeyset() {
    // Lazy-load WasmCrypto only when needed for generation
    const WasmCrypto = require('./wasmCrypto');
    const ed25519Wasm = require('./ed25519.wasm');
    const sphincsWasm = require('./sphincs256s.wasm');

    const ed25519 = new WasmCrypto(ed25519Wasm);
    await ed25519.init();
    const { pk: ed25519Pk, sk: ed25519Sk } = await ed25519.generateKeypair();

    const sphincs = new WasmCrypto(sphincsWasm);
    await sphincs.init();
    const { pk: sphincsPk, sk: sphincsSk } = await sphincs.generateKeypair();

    const blake3 = await createBLAKE3();
    blake3.init();
    blake3.update(ed25519Pk);
    blake3.update(sphincsPk);
    const addressHash = blake3.digest('binary');

    const address = encode(ADDRESS_HRP, addressHash);

    const keyset = [Array.from(ed25519Sk), [Array.from(sphincsSk), Array.from(sphincsPk)]];

    return { keyset, address };
}

module.exports = { generateKeyset, getAddressFromKeyset };
