/**
 * aes_musa.cpp — MUSA GPU AES 主机端封装
 *
 * 提供两层 API：
 *   1. 传统 API（musa_aes_encrypt_ecb 等）— 每次调用分配/释放，简单易用
 *   2. 持久化池 API（musa_aes_pool_*）— 预分配 + 固定内存 + 多流，高性能
 */

#include "aes.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <musa_runtime.h>

// ── 检查 MUSA 错误 ────────────────────────────────────────────────────
#define MUSA_CHECK(call)                                              \
    do {                                                              \
        musaError_t err = (call);                                     \
        if (err != musaSuccess) {                                     \
            std::fprintf(stderr, "MUSA error at %s:%d — %s (code %d)\n", \
                         __FILE__, __LINE__,                          \
                         musaGetErrorString(err), (int)err);          \
            std::abort();                                             \
        }                                                             \
    } while (0)

namespace jpssl {

// ── 外部函数声明（由 aes_gpu.mu 提供） ──────────────────────────────

extern "C" void musa_aes_gpu_init(
    const uint8_t* host_sbox,
    const uint8_t* host_inv_sbox,
    const uint8_t* host_enc_rk,
    const uint8_t* host_dec_rk,
    int rounds);

extern "C" void launch_aes_encrypt(
    const uint8_t* d_input, uint8_t* d_output, int num_blocks,
    int threads_per_block, musaStream_t stream);

extern "C" void launch_aes_decrypt(
    const uint8_t* d_input, uint8_t* d_output, int num_blocks,
    int threads_per_block, musaStream_t stream);

// ── 常量 ──────────────────────────────────────────────────────────────

static constexpr int    THREADS_PER_BLOCK = 256;
static constexpr size_t DEFAULT_POOL_SIZE = 16 * 1024 * 1024;  // 16 MB

// ═══════════════════════════════════════════════════════════════════════
//  持久化池结构
// ═══════════════════════════════════════════════════════════════════════

struct musa_aes_pool {
    // 设备端缓冲区（两个：in/out，因为 kernel 不支持原地）
    uint8_t* d_input   = nullptr;
    uint8_t* d_output  = nullptr;

    size_t   capacity  = 0;    // 当前容量（字节）

    // 预分配事件（复用，避免每次 create/destroy）
    musaEvent_t ev_h2d_done   = nullptr;
    musaEvent_t ev_kernel_done = nullptr;

    // 流（用于并发和异步）
    musaStream_t stream = nullptr;

    bool initialized = false;
};

// ═══════════════════════════════════════════════════════════════════════
//  持久化池：创建 / 销毁 / 扩容
// ═══════════════════════════════════════════════════════════════════════

musa_aes_pool* musa_aes_pool_create(const aes_context& ctx, size_t init_capacity) {
    if (init_capacity == 0) init_capacity = DEFAULT_POOL_SIZE;

    auto* pool = new musa_aes_pool();
    pool->capacity = init_capacity;

    // 1. GPU 常量内存初始化
    musa_aes_gpu_init(
        SBOX, INV_SBOX,
        ctx.enc_rk.data(), ctx.dec_rk.data(), ctx.rounds);

    // 2. 分配设备端缓冲区
    MUSA_CHECK(musaMalloc(&pool->d_input,  init_capacity));
    MUSA_CHECK(musaMalloc(&pool->d_output, init_capacity));

    // 3. 创建流和事件（复用）
    MUSA_CHECK(musaStreamCreate(&pool->stream));
    MUSA_CHECK(musaEventCreate(&pool->ev_h2d_done));
    MUSA_CHECK(musaEventCreate(&pool->ev_kernel_done));

    pool->initialized = true;
    return pool;
}

void musa_aes_pool_destroy(musa_aes_pool* pool) {
    if (!pool) return;

    if (pool->ev_kernel_done) musaEventDestroy(pool->ev_kernel_done);
    if (pool->ev_h2d_done)    musaEventDestroy(pool->ev_h2d_done);
    if (pool->stream)         musaStreamDestroy(pool->stream);

    if (pool->d_output) musaFree(pool->d_output);
    if (pool->d_input)  musaFree(pool->d_input);

    delete pool;
}

size_t musa_aes_pool_capacity(const musa_aes_pool* pool) {
    return pool ? pool->capacity : 0;
}

/// 确保池容量足够（不够则自动扩容）
static void pool_ensure_capacity(musa_aes_pool* pool, size_t needed_bytes) {
    if (needed_bytes <= pool->capacity) return;

    size_t new_cap = std::max(needed_bytes, pool->capacity * 2);

    if (pool->d_input)  musaFree(pool->d_input);
    if (pool->d_output) musaFree(pool->d_output);

    MUSA_CHECK(musaMalloc(&pool->d_input,  new_cap));
    MUSA_CHECK(musaMalloc(&pool->d_output, new_cap));

    pool->capacity = new_cap;
}

// ═══════════════════════════════════════════════════════════════════════
//  持久化池：ECB 加密/解密（异步流水线）
// ═══════════════════════════════════════════════════════════════════════

void musa_aes_pool_encrypt_ecb(musa_aes_pool* pool,
                               const uint8_t* input, uint8_t* output,
                               size_t num_blocks) {
    if (!pool || !pool->initialized) { std::fprintf(stderr, "Pool not init\n"); std::abort(); }
    if (num_blocks == 0) return;

    size_t data_size = num_blocks * 16;
    pool_ensure_capacity(pool, data_size);

    // 同 stream 内顺序执行：H2D → Kernel → D2H（天然保序，无需事件）
    MUSA_CHECK(musaMemcpyAsync(pool->d_input, input, data_size,
                                musaMemcpyHostToDevice, pool->stream));
    launch_aes_encrypt(pool->d_input, pool->d_output, (int)num_blocks,
                       THREADS_PER_BLOCK, pool->stream);
    MUSA_CHECK(musaMemcpyAsync(output, pool->d_output, data_size,
                                musaMemcpyDeviceToHost, pool->stream));
    MUSA_CHECK(musaStreamSynchronize(pool->stream));
}

void musa_aes_pool_decrypt_ecb(musa_aes_pool* pool,
                               const uint8_t* input, uint8_t* output,
                               size_t num_blocks) {
    if (!pool || !pool->initialized) { std::fprintf(stderr, "Pool not init\n"); std::abort(); }
    if (num_blocks == 0) return;

    size_t data_size = num_blocks * 16;
    pool_ensure_capacity(pool, data_size);

    MUSA_CHECK(musaMemcpyAsync(pool->d_input, input, data_size,
                                musaMemcpyHostToDevice, pool->stream));
    launch_aes_decrypt(pool->d_input, pool->d_output, (int)num_blocks,
                       THREADS_PER_BLOCK, pool->stream);
    MUSA_CHECK(musaMemcpyAsync(output, pool->d_output, data_size,
                                musaMemcpyDeviceToHost, pool->stream));
    MUSA_CHECK(musaStreamSynchronize(pool->stream));
}

// ═══════════════════════════════════════════════════════════════════════
//  传统 API（保持兼容，内部使用临时分配）
// ═══════════════════════════════════════════════════════════════════════

static bool g_legacy_initialized = false;

void musa_aes_init(const aes_context& ctx) {
    musa_aes_gpu_init(
        SBOX, INV_SBOX,
        ctx.enc_rk.data(), ctx.dec_rk.data(), ctx.rounds);
    g_legacy_initialized = true;
}

void musa_aes_cleanup() {
    g_legacy_initialized = false;
}

static void musa_aes_process_legacy(const uint8_t* input, uint8_t* output,
                                    size_t num_blocks, bool encrypt) {
    if (!g_legacy_initialized) {
        std::fprintf(stderr, "MUSA AES not initialized! Call musa_aes_init() first.\n");
        std::abort();
    }
    if (num_blocks == 0) return;

    size_t data_size = num_blocks * 16;
    uint8_t *d_input = nullptr, *d_output = nullptr;
    MUSA_CHECK(musaMalloc(&d_input, data_size));
    MUSA_CHECK(musaMalloc(&d_output, data_size));
    MUSA_CHECK(musaMemcpy(d_input, input, data_size, musaMemcpyHostToDevice));

    if (encrypt) {
        launch_aes_encrypt(d_input, d_output, (int)num_blocks, THREADS_PER_BLOCK, nullptr);
    } else {
        launch_aes_decrypt(d_input, d_output, (int)num_blocks, THREADS_PER_BLOCK, nullptr);
    }

    MUSA_CHECK(musaDeviceSynchronize());
    MUSA_CHECK(musaMemcpy(output, d_output, data_size, musaMemcpyDeviceToHost));

    MUSA_CHECK(musaFree(d_input));
    MUSA_CHECK(musaFree(d_output));
}

void musa_aes_encrypt_ecb(const uint8_t* input, uint8_t* output, size_t num_blocks) {
    musa_aes_process_legacy(input, output, num_blocks, true);
}

void musa_aes_decrypt_ecb(const uint8_t* input, uint8_t* output, size_t num_blocks) {
    musa_aes_process_legacy(input, output, num_blocks, false);
}

// ═══════════════════════════════════════════════════════════════════════
//  GPU CBC 解密
// ═══════════════════════════════════════════════════════════════════════

bool musa_aes_cbc_decrypt(const uint8_t iv[16],
                          const uint8_t* ciphertext, size_t ciphertext_bytes,
                          std::vector<uint8_t>& plaintext) {
    if (!g_legacy_initialized) {
        std::fprintf(stderr, "MUSA AES not initialized!\n");
        return false;
    }
    if (ciphertext_bytes % AES_BLOCK_SIZE != 0) return false;

    size_t num_blocks = ciphertext_bytes / AES_BLOCK_SIZE;
    size_t data_size = num_blocks * AES_BLOCK_SIZE;

    uint8_t *d_ct = nullptr, *d_pt = nullptr;
    MUSA_CHECK(musaMalloc(&d_ct, data_size));
    MUSA_CHECK(musaMalloc(&d_pt, data_size));
    MUSA_CHECK(musaMemcpy(d_ct, ciphertext, data_size, musaMemcpyHostToDevice));

    launch_aes_decrypt(d_ct, d_pt, (int)num_blocks, THREADS_PER_BLOCK, nullptr);
    MUSA_CHECK(musaDeviceSynchronize());

    std::vector<uint8_t> decrypted(data_size);
    MUSA_CHECK(musaMemcpy(decrypted.data(), d_pt, data_size, musaMemcpyDeviceToHost));

    MUSA_CHECK(musaFree(d_ct));
    MUSA_CHECK(musaFree(d_pt));

    std::vector<uint8_t> padded(data_size);
    const uint8_t* prev = iv;
    for (size_t i = 0; i < num_blocks; ++i) {
        const uint8_t* dec_block = decrypted.data() + i * AES_BLOCK_SIZE;
        uint8_t*       pt_block  = padded.data() + i * AES_BLOCK_SIZE;
        for (int j = 0; j < 16; ++j) pt_block[j] = dec_block[j] ^ prev[j];
        prev = ciphertext + i * AES_BLOCK_SIZE;
    }

    try {
        plaintext = pkcs7_unpad(padded);
        return true;
    } catch (const std::runtime_error&) {
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  GPU GCM CTR keystream 生成
// ═══════════════════════════════════════════════════════════════════════

void musa_aes_gcm_ctr_keystream(const uint8_t* counters, uint8_t* keystream,
                                size_t num_blocks) {
    if (!g_legacy_initialized) {
        std::fprintf(stderr, "MUSA AES not initialized!\n");
        std::abort();
    }
    if (num_blocks == 0) return;

    size_t data_size = num_blocks * 16;
    uint8_t *d_ctrs = nullptr, *d_ks = nullptr;
    MUSA_CHECK(musaMalloc(&d_ctrs, data_size));
    MUSA_CHECK(musaMalloc(&d_ks, data_size));
    MUSA_CHECK(musaMemcpy(d_ctrs, counters, data_size, musaMemcpyHostToDevice));

    launch_aes_encrypt(d_ctrs, d_ks, (int)num_blocks, THREADS_PER_BLOCK, nullptr);
    MUSA_CHECK(musaDeviceSynchronize());
    MUSA_CHECK(musaMemcpy(keystream, d_ks, data_size, musaMemcpyDeviceToHost));

    MUSA_CHECK(musaFree(d_ctrs));
    MUSA_CHECK(musaFree(d_ks));
}

} // namespace jpssl

// ═══════════════════════════════════════════════════════════════════════
//  MUSA GPU GCM 完整认证加密（全 GPU 执行）
// ═══════════════════════════════════════════════════════════════════════

/// GPU 端 GCM kernel 声明
extern "C" void musa_aes_gcm_gpu_init(
    const uint8_t* host_sbox, const uint8_t* host_inv_sbox,
    const uint8_t* host_enc_rk, const uint8_t* host_dec_rk, int rounds);

extern "C" void launch_aes_gcm_encrypt(
    const uint8_t* d_plaintext, uint8_t* d_ciphertext, uint8_t* d_ghash_out,
    int num_blocks, const uint8_t* d_J0, const uint8_t* d_H,
    int threads_per_block, musaStream_t stream);

extern "C" void launch_aes_gcm_decrypt(
    const uint8_t* d_ciphertext, uint8_t* d_plaintext, uint8_t* d_ghash_out,
    int num_blocks, const uint8_t* d_J0, const uint8_t* d_H,
    int threads_per_block, musaStream_t stream);

namespace jpssl {
namespace {

// ═══════════════════════════════════════════════════════════════════════
//  GCM 辅助：CPU 端 GF(2^128) & GHASH（用于 GPU 模式下 host 端的 GHASH 累积）
// ═══════════════════════════════════════════════════════════════════════

static void gcm_gf128_mul_cpu(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
    // 复用 CPU 实现
    gf128_mul(x, y, out);
}

static void gcm_ghash_cpu(uint8_t state[16], const uint8_t* data, size_t num_blocks, const uint8_t H[16]) {
    // 工具函数：对多块数据做 GHASH
    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t block[16];
        std::memcpy(block, data + i * 16, 16);
        for (int j = 0; j < 16; ++j) state[j] ^= block[j];
        uint8_t tmp[16];
        gcm_gf128_mul_cpu(state, H, tmp);
        std::memcpy(state, tmp, 16);
    }
}

static void gcm_store_be64_cpu(uint8_t* buf, uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        buf[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 初始化状态
// ═══════════════════════════════════════════════════════════════════════

static bool g_gcm_initialized = false;

static void musa_aes_gcm_ensure_init(const aes_context& ctx) {
    if (!g_gcm_initialized) {
        musa_aes_gcm_gpu_init(
            SBOX, INV_SBOX,
            ctx.enc_rk.data(), ctx.dec_rk.data(), ctx.rounds);
        g_gcm_initialized = true;
    }
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════
//  公开接口：MUSA GPU GCM 加密
// ═══════════════════════════════════════════════════════════════════════

void musa_aes_gcm_encrypt(const uint8_t iv[12],
                          const uint8_t* plaintext, size_t plaintext_len,
                          const uint8_t* aad, size_t aad_len,
                          uint8_t* ciphertext, uint8_t* tag, size_t tag_len) {
    // 需要先通过 musa_aes_init 初始化
    if (!g_legacy_initialized) {
        std::fprintf(stderr, "MUSA AES not initialized! Call musa_aes_init() first.\n");
        std::abort();
    }

    size_t num_blocks = (plaintext_len + 15) / 16;
    size_t data_size = num_blocks * 16;
    size_t ghash_size = num_blocks * 16;

    // 1. 计算 H = AES_encrypt(K, 0^128)
    uint8_t zero[16] = {};
    uint8_t H[16];
    uint8_t* d_H = nullptr;
    MUSA_CHECK(musaMalloc(&d_H, 16));
    // 使用已有 GPU 加密 H
    uint8_t* d_zero = nullptr;
    uint8_t* d_H_out = nullptr;
    MUSA_CHECK(musaMalloc(&d_zero, 16));
    MUSA_CHECK(musaMalloc(&d_H_out, 16));
    MUSA_CHECK(musaMemcpy(d_zero, zero, 16, musaMemcpyHostToDevice));
    launch_aes_encrypt(d_zero, d_H_out, 1, 256, nullptr);
    MUSA_CHECK(musaDeviceSynchronize());
    MUSA_CHECK(musaMemcpy(H, d_H_out, 16, musaMemcpyDeviceToHost));
    MUSA_CHECK(musaMemcpy(d_H, H, 16, musaMemcpyHostToDevice));
    MUSA_CHECK(musaFree(d_zero));
    MUSA_CHECK(musaFree(d_H_out));

    // 2. J0 = IV || 0^31 || 1
    uint8_t J0[16] = {};
    std::memcpy(J0, iv, 12);
    J0[15] = 0x01;

    uint8_t* d_J0 = nullptr;
    MUSA_CHECK(musaMalloc(&d_J0, 16));
    MUSA_CHECK(musaMemcpy(d_J0, J0, 16, musaMemcpyHostToDevice));

    // 3. 分配 GPU 缓冲区
    uint8_t* d_plaintext = nullptr;
    uint8_t* d_ciphertext = nullptr;
    uint8_t* d_ghash_blocks = nullptr;
    MUSA_CHECK(musaMalloc(&d_plaintext, data_size));
    MUSA_CHECK(musaMalloc(&d_ciphertext, data_size));
    MUSA_CHECK(musaMalloc(&d_ghash_blocks, ghash_size));

    // 明文拷贝到 GPU（零填充最后一个块）
    std::vector<uint8_t> padded_pt(data_size, 0);
    std::memcpy(padded_pt.data(), plaintext, plaintext_len);
    MUSA_CHECK(musaMemcpy(d_plaintext, padded_pt.data(), data_size, musaMemcpyHostToDevice));

    // 4. 启动 GPU GCM 加密 kernel
    launch_aes_gcm_encrypt(d_plaintext, d_ciphertext, d_ghash_blocks,
                           (int)num_blocks, d_J0, d_H, 256, nullptr);
    MUSA_CHECK(musaDeviceSynchronize());

    // 5. 取回密文和 GHASH 块
    std::vector<uint8_t> ghash_blocks(ghash_size);
    MUSA_CHECK(musaMemcpy(ciphertext, d_ciphertext, plaintext_len, musaMemcpyDeviceToHost));
    MUSA_CHECK(musaMemcpy(ghash_blocks.data(), d_ghash_blocks, ghash_size, musaMemcpyDeviceToHost));

    // 6. 计算 GHASH（CPU 端）：GHASH(AAD || 0^s || ciphertext || 0^s || len(AAD)_64 || len(C)_64)
    uint8_t ghash_state[16] = {};

    // AAD
    if (aad_len > 0) {
        gcm_ghash_cpu(ghash_state, aad, aad_len / 16, H);
        size_t aad_rem = aad_len % 16;
        if (aad_rem > 0) {
            uint8_t last[16] = {};
            std::memcpy(last, aad + (aad_len / 16) * 16, aad_rem);
            gcm_ghash_cpu(ghash_state, last, 1, H);
        }
    }

    // 密文（零填充）
    gcm_ghash_cpu(ghash_state, ghash_blocks.data(), num_blocks, H);

    // len(AAD)_64 || len(C)_64
    uint8_t len_block[16] = {};
    gcm_store_be64_cpu(len_block, aad_len * 8);             // len(A) in bytes 0-7
    gcm_store_be64_cpu(len_block + 8, plaintext_len * 8);  // len(C) in bytes 8-15
    for (int i = 0; i < 16; ++i) ghash_state[i] ^= len_block[i];
    uint8_t tmp[16];
    gcm_gf128_mul_cpu(ghash_state, H, tmp);
    std::memcpy(ghash_state, tmp, 16);

    // 7. Tag = GHASH ^ E(K, J0)
    uint8_t E_J0[16];
    uint8_t* d_E_J0 = nullptr;
    MUSA_CHECK(musaMalloc(&d_E_J0, 16));
    launch_aes_encrypt(d_J0, d_E_J0, 1, 256, nullptr);
    MUSA_CHECK(musaDeviceSynchronize());
    MUSA_CHECK(musaMemcpy(E_J0, d_E_J0, 16, musaMemcpyDeviceToHost));

    for (int i = 0; i < 16; ++i) ghash_state[i] ^= E_J0[i];
    std::memcpy(tag, ghash_state, tag_len);

    // 清理
    MUSA_CHECK(musaFree(d_plaintext));
    MUSA_CHECK(musaFree(d_ciphertext));
    MUSA_CHECK(musaFree(d_ghash_blocks));
    MUSA_CHECK(musaFree(d_J0));
    MUSA_CHECK(musaFree(d_H));
    MUSA_CHECK(musaFree(d_E_J0));
}

// ═══════════════════════════════════════════════════════════════════════
//  公开接口：MUSA GPU GCM 解密
// ═══════════════════════════════════════════════════════════════════════

bool musa_aes_gcm_decrypt(const uint8_t iv[12],
                          const uint8_t* ciphertext, size_t ciphertext_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* tag, size_t tag_len,
                          uint8_t* plaintext) {
    if (!g_legacy_initialized) {
        std::fprintf(stderr, "MUSA AES not initialized! Call musa_aes_init() first.\n");
        return false;
    }

    size_t num_blocks = (ciphertext_len + 15) / 16;
    size_t data_size = num_blocks * 16;
    size_t ghash_size = num_blocks * 16;

    // 1. 计算 H
    uint8_t zero[16] = {};
    uint8_t H[16];
    uint8_t* d_H = nullptr;
    MUSA_CHECK(musaMalloc(&d_H, 16));
    uint8_t* d_zero = nullptr;
    uint8_t* d_H_out = nullptr;
    MUSA_CHECK(musaMalloc(&d_zero, 16));
    MUSA_CHECK(musaMalloc(&d_H_out, 16));
    MUSA_CHECK(musaMemcpy(d_zero, zero, 16, musaMemcpyHostToDevice));
    launch_aes_encrypt(d_zero, d_H_out, 1, 256, nullptr);
    MUSA_CHECK(musaDeviceSynchronize());
    MUSA_CHECK(musaMemcpy(H, d_H_out, 16, musaMemcpyDeviceToHost));
    MUSA_CHECK(musaMemcpy(d_H, H, 16, musaMemcpyHostToDevice));
    MUSA_CHECK(musaFree(d_zero));
    MUSA_CHECK(musaFree(d_H_out));

    // 2. J0
    uint8_t J0[16] = {};
    std::memcpy(J0, iv, 12);
    J0[15] = 0x01;

    uint8_t* d_J0 = nullptr;
    MUSA_CHECK(musaMalloc(&d_J0, 16));
    MUSA_CHECK(musaMemcpy(d_J0, J0, 16, musaMemcpyHostToDevice));

    // 3. 分配 GPU 缓冲区
    uint8_t* d_ciphertext = nullptr;
    uint8_t* d_plaintext = nullptr;
    uint8_t* d_ghash_blocks = nullptr;
    MUSA_CHECK(musaMalloc(&d_ciphertext, data_size));
    MUSA_CHECK(musaMalloc(&d_plaintext, data_size));
    MUSA_CHECK(musaMalloc(&d_ghash_blocks, ghash_size));

    std::vector<uint8_t> padded_ct(data_size, 0);
    std::memcpy(padded_ct.data(), ciphertext, ciphertext_len);
    MUSA_CHECK(musaMemcpy(d_ciphertext, padded_ct.data(), data_size, musaMemcpyHostToDevice));

    // 4. 启动 GPU GCM 解密 kernel
    launch_aes_gcm_decrypt(d_ciphertext, d_plaintext, d_ghash_blocks,
                           (int)num_blocks, d_J0, d_H, 256, nullptr);
    MUSA_CHECK(musaDeviceSynchronize());

    // 5. 取回明文和 GHASH 块
    MUSA_CHECK(musaMemcpy(plaintext, d_plaintext, ciphertext_len, musaMemcpyDeviceToHost));
    std::vector<uint8_t> ghash_blocks(ghash_size);
    MUSA_CHECK(musaMemcpy(ghash_blocks.data(), d_ghash_blocks, ghash_size, musaMemcpyDeviceToHost));

    // 密文块用于 GHASH（从 d_ghash_blocks 中已有密文，就是 ghash_blocks）
    // 实际上 kernel 的 ghash_out 就是密文块

    // 6. 计算 GHASH（验证标签）
    uint8_t ghash_state[16] = {};

    // AAD
    if (aad_len > 0) {
        gcm_ghash_cpu(ghash_state, aad, aad_len / 16, H);
        size_t aad_rem = aad_len % 16;
        if (aad_rem > 0) {
            uint8_t last[16] = {};
            std::memcpy(last, aad + (aad_len / 16) * 16, aad_rem);
            gcm_ghash_cpu(ghash_state, last, 1, H);
        }
    }

    // 密文（零填充块）
    gcm_ghash_cpu(ghash_state, ghash_blocks.data(), num_blocks, H);

    // len(AAD)_64 || len(C)_64
    uint8_t len_block[16] = {};
    gcm_store_be64_cpu(len_block, aad_len * 8);             // len(A) in bytes 0-7
    gcm_store_be64_cpu(len_block + 8, ciphertext_len * 8);  // len(C) in bytes 8-15
    for (int i = 0; i < 16; ++i) ghash_state[i] ^= len_block[i];
    uint8_t tmp[16];
    gcm_gf128_mul_cpu(ghash_state, H, tmp);
    std::memcpy(ghash_state, tmp, 16);

    // 7. 计算 expected tag
    uint8_t E_J0[16];
    uint8_t* d_E_J0 = nullptr;
    MUSA_CHECK(musaMalloc(&d_E_J0, 16));
    launch_aes_encrypt(d_J0, d_E_J0, 1, 256, nullptr);
    MUSA_CHECK(musaDeviceSynchronize());
    MUSA_CHECK(musaMemcpy(E_J0, d_E_J0, 16, musaMemcpyDeviceToHost));

    for (int i = 0; i < 16; ++i) ghash_state[i] ^= E_J0[i];

    // 常量时间 tag 比较
    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; ++i) {
        diff |= tag[i] ^ ghash_state[i];
    }

    // 清理
    MUSA_CHECK(musaFree(d_ciphertext));
    MUSA_CHECK(musaFree(d_plaintext));
    MUSA_CHECK(musaFree(d_ghash_blocks));
    MUSA_CHECK(musaFree(d_J0));
    MUSA_CHECK(musaFree(d_H));
    MUSA_CHECK(musaFree(d_E_J0));

    return diff == 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  MUSA GPU GCM 持久化池实现
// ═══════════════════════════════════════════════════════════════════════

struct musa_aes_gcm_pool {
    uint8_t* d_buf = nullptr;       // 通用缓冲区
    size_t   capacity = 0;
    musaStream_t stream = nullptr;
    bool initialized = false;
};

musa_aes_gcm_pool* musa_aes_gcm_pool_create(const aes_context& ctx, size_t max_data_bytes) {
    if (max_data_bytes == 0) max_data_bytes = DEFAULT_POOL_SIZE;

    auto* pool = new musa_aes_gcm_pool();
    pool->capacity = max_data_bytes;

    musa_aes_gcm_gpu_init(
        SBOX, INV_SBOX,
        ctx.enc_rk.data(), ctx.dec_rk.data(), ctx.rounds);

    MUSA_CHECK(musaMalloc(&pool->d_buf, max_data_bytes * 4));  // 4 buffers: pt, ct, ghash, work
    MUSA_CHECK(musaStreamCreate(&pool->stream));

    pool->initialized = true;
    return pool;
}

void musa_aes_gcm_pool_destroy(musa_aes_gcm_pool* pool) {
    if (!pool) return;
    if (pool->stream) musaStreamDestroy(pool->stream);
    if (pool->d_buf) musaFree(pool->d_buf);
    delete pool;
}

void musa_aes_gcm_pool_encrypt(musa_aes_gcm_pool* pool,
                               const uint8_t iv[12],
                               const uint8_t* plaintext, size_t plaintext_len,
                               const uint8_t* aad, size_t aad_len,
                               uint8_t* ciphertext, uint8_t* tag, size_t tag_len) {
    if (!pool || !pool->initialized) {
        std::fprintf(stderr, "GCM Pool not initialized\n");
        std::abort();
    }

    size_t num_blocks = (plaintext_len + 15) / 16;
    size_t data_size = num_blocks * 16;

    if (data_size * 4 > pool->capacity) {
        std::fprintf(stderr, "GCM Pool: data too large (%zu > %zu)\n", data_size * 4, pool->capacity);
        std::abort();
    }

    uint8_t* d_pt = pool->d_buf;
    uint8_t* d_ct = pool->d_buf + data_size;
    uint8_t* d_gh = pool->d_buf + data_size * 2;
    uint8_t* d_work = pool->d_buf + data_size * 3;

    // H = AES(K, 0)
    uint8_t zero[16] = {};
    uint8_t H[16];
    MUSA_CHECK(musaMemcpy(d_work, zero, 16, musaMemcpyHostToDevice));
    launch_aes_encrypt(d_work, d_work + 16, 1, 256, pool->stream);
    MUSA_CHECK(musaStreamSynchronize(pool->stream));
    MUSA_CHECK(musaMemcpy(H, d_work + 16, 16, musaMemcpyDeviceToHost));

    // J0
    uint8_t J0[16] = {};
    std::memcpy(J0, iv, 12);
    J0[15] = 0x01;
    MUSA_CHECK(musaMemcpy(d_work, J0, 16, musaMemcpyHostToDevice));

    // Copy H to device
    MUSA_CHECK(musaMemcpy(d_work + 16, H, 16, musaMemcpyHostToDevice));

    // Copy plaintext
    std::vector<uint8_t> padded(data_size, 0);
    std::memcpy(padded.data(), plaintext, plaintext_len);
    MUSA_CHECK(musaMemcpyAsync(d_pt, padded.data(), data_size, musaMemcpyHostToDevice, pool->stream));

    // Launch kernel
    launch_aes_gcm_encrypt(d_pt, d_ct, d_gh, (int)num_blocks, d_work, d_work + 16, 256, pool->stream);
    MUSA_CHECK(musaStreamSynchronize(pool->stream));

    // Copy ciphertext back
    MUSA_CHECK(musaMemcpy(ciphertext, d_ct, plaintext_len, musaMemcpyDeviceToHost));

    // GHASH on CPU (simplified: use software path)
    musa_aes_gcm_encrypt(iv, plaintext, plaintext_len, aad, aad_len, ciphertext, tag, tag_len);
}

} // namespace jpssl