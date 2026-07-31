/**
 * rsa_musa.cpp — RSA MUSA GPU 主机端封装（优化版）
 *
 * 调用 rsa_gpu.mu kernel 进行批量 Montgomery 模幂。
 *
 * 优化要点：
 *   1. 传入 R_mod_m（R mod n）和 exp_bits（指数有效位）到 GPU 常量内存
 *   2. 异步流支持：H2D → Kernel → D2H 流水线
 *   3. 持久化池复用设备内存 + 事件 + 流
 */

#include "rsa.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <musa_runtime.h>

namespace jpssl {

// ── MUSA 错误检查 ───────────────────────────────────────────────────
#define RSA_GPU_CHECK(call)                                              \
    do {                                                                 \
        musaError_t e = (call);                                          \
        if (e != musaSuccess) {                                          \
            std::fprintf(stderr, "RSA GPU error at %s:%d — %s (code %d)\n", \
                         __FILE__, __LINE__,                             \
                         musaGetErrorString(e), (int)e);                 \
            std::abort();                                                \
        }                                                                \
    } while (0)

// ── Kernel 外部声明（由 rsa_gpu.mu 提供）────────────────────────────

extern "C" void musa_rsa_gpu_init(
    const uint64_t* host_mod,
    const uint64_t* host_exp,
    uint64_t        host_m_prime,
    const uint64_t* host_R2,
    const uint64_t* host_R_mod,
    int             host_exp_bits);

extern "C" void launch_rsa_batch_decrypt(
    const uint64_t* d_ciphers,
    uint64_t*       d_plains,
    int             count,
    int             threads_per_block,
    musaStream_t    stream);

// ── 常量 ────────────────────────────────────────────────────────────

static constexpr int THREADS_PER_BLOCK = 4;   // safest — avoids cross-thread carry overflow
static constexpr size_t DEFAULT_BATCH_SIZE = 1024;

// ── 字节序转换（前向声明）───────────────────────────────────────────

static void bytes_to_words(uint64_t* dst, const uint8_t* src, size_t count);
static void words_to_bytes(uint8_t* dst, const uint64_t* src, size_t count);

// ═══════════════════════════════════════════════════════════════════════
//  持久化池结构
// ═══════════════════════════════════════════════════════════════════════

struct musa_rsa_pool {
    rsa_private_key key;
    size_t   batch_size = 0;

    // 设备端缓冲区
    uint64_t* d_ciphers = nullptr;
    uint64_t* d_plains  = nullptr;

    // 流（异步流水线）
    musaStream_t stream = nullptr;

    bool initialized = false;
};

// ═══════════════════════════════════════════════════════════════════════
//  池管理：创建 / 销毁
// ═══════════════════════════════════════════════════════════════════════

musa_rsa_pool* musa_rsa_pool_create(const rsa_private_key& prv, size_t batch_size) {
    if (batch_size == 0) batch_size = DEFAULT_BATCH_SIZE;

    auto* p = new musa_rsa_pool();
    p->key        = prv;
    p->batch_size = batch_size;

    // 1. 预计算 Montgomery 上下文
    auto mctx = rsa_mont_init(prv.n);

    // 2. 初始化 GPU 常量内存
    int exp_bits = prv.d.bit_length();
    musa_rsa_gpu_init(
        prv.n.d, prv.d.d,
        mctx.m_prime,
        mctx.R2_mod_m.d,
        mctx.R_mod_m.d,    // R mod n（Montgomery 域中 1 的表示）
        exp_bits            // 指数有效 bit 数
    );

    // 3. 分配设备端缓冲区
    size_t bytes = batch_size * RSA_2048_WORDS * sizeof(uint64_t);
    RSA_GPU_CHECK(musaMalloc(&p->d_ciphers, bytes));
    RSA_GPU_CHECK(musaMalloc(&p->d_plains,  bytes));

    // 4. 创建流（异步流水线）
    RSA_GPU_CHECK(musaStreamCreate(&p->stream));

    p->initialized = true;
    return p;
}

void musa_rsa_pool_destroy(musa_rsa_pool* pool) {
    if (!pool) return;

    if (pool->stream)    musaStreamDestroy(pool->stream);
    if (pool->d_plains)  musaFree(pool->d_plains);
    if (pool->d_ciphers) musaFree(pool->d_ciphers);

    delete pool;
}

// ═══════════════════════════════════════════════════════════════════════
//  批量解密（异步流水线：H2D → Kernel → D2H → Sync）
// ═══════════════════════════════════════════════════════════════════════

void musa_rsa_batch_decrypt(musa_rsa_pool* pool,
                            const uint8_t* ciphers,
                            uint8_t* plains,
                            size_t count) {
    if (!pool || !pool->initialized) {
        std::fprintf(stderr, "RSA pool not initialized\n");
        std::abort();
    }
    if (count == 0) return;
    if (count > pool->batch_size) count = pool->batch_size;

    // 向上取整到 THREADS_PER_BLOCK 的倍数
    size_t padded = ((count + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK) * THREADS_PER_BLOCK;
    if (padded > pool->batch_size) padded = pool->batch_size;

    size_t bytes = padded * RSA_2048_WORDS * sizeof(uint64_t);
    size_t nwords = padded * RSA_2048_WORDS;

    // 字节序转换：big-endian → native uint64_t
    std::vector<uint64_t> h_ciphers(nwords);
    bytes_to_words(h_ciphers.data(), ciphers, count);

    // 异步流水线：同一 stream 内顺序保证
    RSA_GPU_CHECK(musaMemcpyAsync(pool->d_ciphers, h_ciphers.data(), bytes,
                                   musaMemcpyHostToDevice, pool->stream));
    launch_rsa_batch_decrypt(pool->d_ciphers, pool->d_plains,
                             (int)padded, THREADS_PER_BLOCK, pool->stream);
    std::vector<uint64_t> h_plains(nwords);
    RSA_GPU_CHECK(musaMemcpyAsync(h_plains.data(), pool->d_plains, bytes,
                                   musaMemcpyDeviceToHost, pool->stream));
    RSA_GPU_CHECK(musaStreamSynchronize(pool->stream));

    // 字节序转换：native uint64_t → big-endian
    words_to_bytes(plains, h_plains.data(), count);
}

// ── 字节序转换（big-endian bytes ↔ native uint64_t[K]）────────────────

/// big-endian bytes → native uint64_t[K] (d[0]=LSW, d[K-1]=MSW)
static void bytes_to_words(uint64_t* dst, const uint8_t* src, size_t count) {
    for (size_t n = 0; n < count; ++n) {
        const uint8_t* s = src + n * RSA_2048_BYTES;
        uint64_t*      d = dst + n * RSA_2048_WORDS;
        for (int j = 0; j < RSA_2048_WORDS; ++j) {
            uint64_t v = 0;
            for (int k = 0; k < 8; ++k)
                v = (v << 8) | s[j * 8 + k];
            d[RSA_2048_WORDS - 1 - j] = v;
        }
    }
}

/// native uint64_t[K] → big-endian bytes
static void words_to_bytes(uint8_t* dst, const uint64_t* src, size_t count) {
    for (size_t n = 0; n < count; ++n) {
        uint8_t*       d = dst + n * RSA_2048_BYTES;
        const uint64_t* s = src + n * RSA_2048_WORDS;
        for (int j = 0; j < RSA_2048_WORDS; ++j) {
            uint64_t v = s[RSA_2048_WORDS - 1 - j];
            for (int k = 0; k < 8; ++k)
                d[j * 8 + k] = (uint8_t)(v >> (56 - k * 8));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  独立批量模幂（低层 API，每次分配/释放，用于 benchmark/debug）
// ═══════════════════════════════════════════════════════════════════════

void musa_rsa_batch_modpow(const rsa_bignum& mod,
                           const rsa_bignum& exp,
                           const mont_ctx&   mctx,
                           const uint8_t* bases,
                           uint8_t* results,
                           size_t count) {
    if (count == 0) return;

    // 向上取整到 THREADS_PER_BLOCK 的倍数（避免 count < tpb 时崩溃）
    size_t padded = ((count + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK) * THREADS_PER_BLOCK;

    // 初始化 GPU 常量
    int exp_bits = exp.bit_length();
    musa_rsa_gpu_init(mod.d, exp.d, mctx.m_prime, mctx.R2_mod_m.d,
                      mctx.R_mod_m.d, exp_bits);

    // 字节序转换：big-endian → native uint64_t（padding 填零）
    size_t bytes = padded * RSA_2048_WORDS * sizeof(uint64_t);
    std::vector<uint64_t> h_ciphers(padded * RSA_2048_WORDS, 0);
    std::vector<uint64_t> h_plains(padded * RSA_2048_WORDS);
    bytes_to_words(h_ciphers.data(), bases, count);

    // 临时分配 + 同步执行
    uint64_t *d_c = nullptr, *d_p = nullptr;
    RSA_GPU_CHECK(musaMalloc(&d_c, bytes));
    RSA_GPU_CHECK(musaMalloc(&d_p, bytes));

    RSA_GPU_CHECK(musaMemcpy(d_c, h_ciphers.data(), bytes, musaMemcpyHostToDevice));
    launch_rsa_batch_decrypt(d_c, d_p, (int)padded, THREADS_PER_BLOCK, nullptr);
    RSA_GPU_CHECK(musaDeviceSynchronize());
    RSA_GPU_CHECK(musaMemcpy(h_plains.data(), d_p, bytes, musaMemcpyDeviceToHost));

    // 字节序转换：native uint64_t → big-endian（仅前 count 个）
    words_to_bytes(results, h_plains.data(), count);

    RSA_GPU_CHECK(musaFree(d_p));
    RSA_GPU_CHECK(musaFree(d_c));
}

} // namespace jpssl
