const crypto = require('crypto');

class WasmCrypto {
    constructor(wasmBytes) {
        this.wasmBytes = wasmBytes;
        this.memory = null;
        this.instance = null;
        this.exports = {};
    }

    async init() {
        const importObject = {
            env: {
                __lea_abort: (_line) => {
                    const line = Number(_line);
                    console.error(`[ABORT] WASM aborted at line ${line}`);
                    process.exit(1);
                },
                __lea_randombytes: (ptr, len) => {
                    if (!this.memory) return;
                    const size = Number(len);
                    const rnd = crypto.randomBytes(size);
                    const mem = new Uint8Array(this.memory.buffer, ptr, size);
                    mem.set(rnd);
                },
            },
        };

        const { instance } = await WebAssembly.instantiate(this.wasmBytes, importObject);

        this.instance = instance;
        this.memory = instance.exports.memory;

        const {
            keygen,
            sign,
            verify,
            pk_bytes,
            sk_bytes,
            signature_bytes,
            __lea_malloc,
            __lea_allocator_reset,
        } = instance.exports;

        this.exports = {
            keygen,
            sign,
            verify,
            pk_bytes,
            sk_bytes,
            signature_bytes,
            __lea_malloc,
            __lea_allocator_reset,
        };
    }

    malloc(size) {
        return this.exports.__lea_malloc(Number(size));
    }

    getMemoryBuffer(ptr, len) {
        return new Uint8Array(this.memory.buffer, ptr, len);
    }

    async generateKeypair() {
        const pkLen = this.exports.pk_bytes();
        const skLen = this.exports.sk_bytes();

        const pkPtr = this.malloc(pkLen);
        const skPtr = this.malloc(skLen);

        const result = await this.exports.keygen(pkPtr, skPtr);
        if (result !== 0) throw new Error('Keygen failed');

        const pk = this.getMemoryBuffer(pkPtr, pkLen).slice();
        const sk = this.getMemoryBuffer(skPtr, skLen).slice();

        return { pk, sk };
    }
}

module.exports = WasmCrypto;
