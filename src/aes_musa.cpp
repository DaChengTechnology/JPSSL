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
        SBOX.data(), INV_SBOX.data(),
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
        SBOX.data(), INV_SBOX.data(),
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
