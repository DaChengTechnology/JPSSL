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

extern "C" void musa_rsa_gpu_init4096(
    const uint64_t* host_mod,
    const uint64_t* host_exp,
    uint64_t        host_m_prime,
    const uint64_t* host_R2,
    const uint64_t* host_R_mod,
    int             host_exp_bits);

extern "C" void launch_rsa_batch_decrypt4096(
    const uint64_t* d_ciphers,
    uint64_t*       d_plains,
    int             count,
    int             threads_per_block,
    musaStream_t    stream);

extern "C" void musa_rsa_gpu_init_half(
    const uint64_t* host_mod,
    const uint64_t* host_exp,
    uint64_t        host_m_prime,
    const uint64_t* host_R2,
    const uint64_t* host_R_mod,
    int             host_exp_bits);

extern "C" void launch_rsa_batch_decrypt_half(
    const uint64_t* d_ciphers,
    uint64_t*       d_plains,
    int             count,
    int             threads_per_block,
    musaStream_t    stream);

// ── 常量 ────────────────────────────────────────────────────────────

static constexpr int THREADS_PER_BLOCK = 32;  // 满 warp 利用率, 消除大批量排队波次
static constexpr int THREADS_PER_BLOCK_4096 = 16;  // 4096: 264×4B×tpb ≤ 32KB 共享内存约束
static constexpr size_t DEFAULT_BATCH_SIZE = 1024;

// ── 字节序转换（前向声明）───────────────────────────────────────────

static void bytes_to_words(uint64_t* dst, const uint8_t* src, size_t count);
static void words_to_bytes(uint8_t* dst, const uint64_t* src, size_t count);
static void bytes_to_words4096(uint64_t* dst, const uint8_t* src, size_t count);
static void words_to_bytes4096(uint8_t* dst, const uint64_t* src, size_t count);

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

// ── 字节序转换（4096-bit）─────────────────────────────────────────────

/// big-endian 512 字节 → native uint64_t[64] (d[0]=LSW)
static void bytes_to_words4096(uint64_t* dst, const uint8_t* src, size_t count) {
    for (size_t n = 0; n < count; ++n) {
        const uint8_t* s = src + n * RSA_4096_BYTES;
        uint64_t*      d = dst + n * RSA_4096_WORDS;
        for (int j = 0; j < RSA_4096_WORDS; ++j) {
            uint64_t v = 0;
            for (int k = 0; k < 8; ++k)
                v = (v << 8) | s[j * 8 + k];
            d[RSA_4096_WORDS - 1 - j] = v;
        }
    }
}

/// native uint64_t[64] → big-endian 512 字节
static void words_to_bytes4096(uint8_t* dst, const uint64_t* src, size_t count) {
    for (size_t n = 0; n < count; ++n) {
        uint8_t*       d = dst + n * RSA_4096_BYTES;
        const uint64_t* s = src + n * RSA_4096_WORDS;
        for (int j = 0; j < RSA_4096_WORDS; ++j) {
            uint64_t v = s[RSA_4096_WORDS - 1 - j];
            for (int k = 0; k < 8; ++k) {
                d[j * 8 + k] = (uint8_t)(v >> (56 - 8 * k));
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  RSA-4096 批量模幂（真 GPU kernel）
// ═══════════════════════════════════════════════════════════════════════

void musa4096_rsa_batch_modpow(const rsa4096_bignum& mod,
                               const rsa4096_bignum& exp,
                               const mont_ctx4096&   mctx,
                               const uint8_t* bases,
                               uint8_t* results,
                               size_t count) {
    if (count == 0) return;

    // 向上取整到 THREADS_PER_BLOCK_4096 的倍数
    size_t padded = ((count + THREADS_PER_BLOCK_4096 - 1) / THREADS_PER_BLOCK_4096)
                    * THREADS_PER_BLOCK_4096;

    int exp_bits = exp.bit_length();
    musa_rsa_gpu_init4096(mod.d, exp.d, mctx.m_prime,
                          mctx.R2_mod_m.d, mctx.R_mod_m.d, exp_bits);

    // 字节序转换：big-endian → native uint64_t（padding 填零）
    size_t bytes = padded * RSA_4096_WORDS * sizeof(uint64_t);
    std::vector<uint64_t> h_ciphers(padded * RSA_4096_WORDS, 0);
    std::vector<uint64_t> h_plains(padded * RSA_4096_WORDS);
    bytes_to_words4096(h_ciphers.data(), bases, count);

    uint64_t *d_c = nullptr, *d_p = nullptr;
    RSA_GPU_CHECK(musaMalloc(&d_c, bytes));
    RSA_GPU_CHECK(musaMalloc(&d_p, bytes));

    RSA_GPU_CHECK(musaMemcpy(d_c, h_ciphers.data(), bytes, musaMemcpyHostToDevice));
    launch_rsa_batch_decrypt4096(d_c, d_p, (int)padded, THREADS_PER_BLOCK_4096, nullptr);
    RSA_GPU_CHECK(musaDeviceSynchronize());
    RSA_GPU_CHECK(musaMemcpy(h_plains.data(), d_p, bytes, musaMemcpyDeviceToHost));

    // 字节序转换：native uint64_t → big-endian（仅前 count 个）
    words_to_bytes4096(results, h_plains.data(), count);

    RSA_GPU_CHECK(musaFree(d_p));
    RSA_GPU_CHECK(musaFree(d_c));
}

// ═══════════════════════════════════════════════════════════════════════
//  CRT 批量解密（GPU 双 launch: c^dP mod p + c^dQ mod q → CPU Garner 合并）
// ═══════════════════════════════════════════════════════════════════════
size_t musa_crt_batch_decrypt(const rsa_crt_key& key, const uint8_t* cts,
                              uint8_t* pts, size_t count) {
    if (count == 0) return 0;
    size_t padded = ((count + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK) * THREADS_PER_BLOCK;

    // 1. 密文字节 → rsa_bignum, 并对 p/q 取模
    std::vector<rsa_bignum> c_vec(count), cp_vec(padded), cq_vec(padded);
    for (size_t i = 0; i < count; ++i) {
        c_vec[i] = rsa_bignum::from_bytes(cts + i * RSA_2048_BYTES, RSA_2048_BYTES);
        bn_mod(cp_vec[i], c_vec[i], key.p);
        bn_mod(cq_vec[i], c_vec[i], key.q);
    }
    // padding 填零
    for (size_t i = count; i < padded; ++i) {
        cp_vec[i].zero();
        cq_vec[i].zero();
    }

    // 2. 提取为 uint64_t 连续缓冲（每条 16 word = 128 字节）
    std::vector<uint64_t> cp_words(padded * RSA_1024_WORDS, 0);
    std::vector<uint64_t> cq_words(padded * RSA_1024_WORDS, 0);
    for (size_t i = 0; i < count; ++i) {
        memcpy(cp_words.data() + i * RSA_1024_WORDS, cp_vec[i].d, RSA_1024_WORDS * 8);
        memcpy(cq_words.data() + i * RSA_1024_WORDS, cq_vec[i].d, RSA_1024_WORDS * 8);
    }

    // 3. 计算 p 路径的 1024-bit Montgomery 上下文
    //    R = 2^1024 (而非 2^2048), 手动计算 R_mod 和 R2
    rsa_bignum R_half; R_half.zero(); R_half.d[16] = 1;  // 2^1024
    rsa_bignum R_mod_p, R2_mod_p;
    bn_mod(R_mod_p, R_half, key.p);
    bn_mul(R2_mod_p, R_mod_p, R_mod_p);
    bn_mod(R2_mod_p, R2_mod_p, key.p);
    auto mctx_full_p = rsa_mont_init(key.p);  // 取 m_prime
    uint32_t mp32_p = (uint32_t)mctx_full_p.m_prime;

    // 4. p-path GPU
    size_t bytes_half = padded * RSA_1024_WORDS * sizeof(uint64_t);
    uint64_t *d_cp = nullptr, *d_mp = nullptr;
    RSA_GPU_CHECK(musaMalloc(&d_cp, bytes_half));
    RSA_GPU_CHECK(musaMalloc(&d_mp, bytes_half));
    musa_rsa_gpu_init_half(key.p.d, key.dP.d, mp32_p,
                           R2_mod_p.d, R_mod_p.d, key.dP.bit_length());
    RSA_GPU_CHECK(musaMemcpy(d_cp, cp_words.data(), bytes_half, musaMemcpyHostToDevice));
    launch_rsa_batch_decrypt_half(d_cp, d_mp, (int)padded, THREADS_PER_BLOCK, nullptr);
    RSA_GPU_CHECK(musaDeviceSynchronize());
    std::vector<uint64_t> mp_words(padded * RSA_1024_WORDS);
    RSA_GPU_CHECK(musaMemcpy(mp_words.data(), d_mp, bytes_half, musaMemcpyDeviceToHost));

    // 5. q-path（同理）
    rsa_bignum R_mod_q, R2_mod_q;
    bn_mod(R_mod_q, R_half, key.q);
    bn_mul(R2_mod_q, R_mod_q, R_mod_q);
    bn_mod(R2_mod_q, R2_mod_q, key.q);
    auto mctx_full_q = rsa_mont_init(key.q);
    uint32_t mp32_q = (uint32_t)mctx_full_q.m_prime;

    musa_rsa_gpu_init_half(key.q.d, key.dQ.d, mp32_q,
                           R2_mod_q.d, R_mod_q.d, key.dQ.bit_length());
    RSA_GPU_CHECK(musaMemcpy(d_cp, cq_words.data(), bytes_half, musaMemcpyHostToDevice));
    launch_rsa_batch_decrypt_half(d_cp, d_mp, (int)padded, THREADS_PER_BLOCK, nullptr);
    RSA_GPU_CHECK(musaDeviceSynchronize());
    std::vector<uint64_t> mq_words(padded * RSA_1024_WORDS);
    RSA_GPU_CHECK(musaMemcpy(mq_words.data(), d_mp, bytes_half, musaMemcpyDeviceToHost));

    RSA_GPU_CHECK(musaFree(d_mp));
    RSA_GPU_CHECK(musaFree(d_cp));

    // 6. CPU Garner CRT 合并 + PKCS1 解填充
    size_t decrypted = 0;
    for (size_t i = 0; i < count; ++i) {
        rsa_bignum m1, m2;
        memset(&m1, 0, sizeof(m1)); memset(&m2, 0, sizeof(m2));
        memcpy(m1.d, mp_words.data() + i * RSA_1024_WORDS, RSA_1024_WORDS * 8);
        memcpy(m2.d, mq_words.data() + i * RSA_1024_WORDS, RSA_1024_WORDS * 8);

        // h = (m1 - m2) * qInv mod p
        rsa_bignum h, diff;
        if (m1 < m2) {
            rsa_bignum tmp;
            bn_sub(tmp, key.p, m2);
            bn_add(diff, m1, tmp);
        } else {
            bn_sub(diff, m1, m2);
        }
        rsa_bignum t;
        bn_mul(t, diff, key.qInv);
        bn_mod(h, t, key.p);

        // m = m2 + q * h
        rsa_bignum m, tmp;
        bn_mul(tmp, key.q, h);
        bn_add(m, m2, tmp);

        // PKCS1 v1.5 解填充（输出固定 256 字节槽位）
        uint8_t pad[256];
        m.to_bytes(pad);
        if (pad[0] != 0 || pad[1] != 2) continue;
        size_t sep = 2;
        while (sep < 256 && pad[sep] != 0) ++sep;
        if (sep >= 255) continue;
        size_t plen = 256 - sep - 1;
        uint8_t* out = pts + decrypted * RSA_2048_BYTES;
        memset(out, 0, RSA_2048_BYTES);
        memcpy(out, pad + sep + 1, plen);
        ++decrypted;
    }
    return decrypted;
}

// ═══════════════════════════════════════════════════════════════════════
//  4096 CRT 批量解密（复用 2048 kernel 计算 c^dP mod p + c^dQ mod q）
//  4096-bit 密文 → 模 p/q (2048-bit) → 2048 GPU kernel × 2 → 4096 merge
// ═══════════════════════════════════════════════════════════════════════
size_t musa4096_crt_batch_decrypt(const rsa4096_crt_key& key,
                                  const uint8_t* cts, uint8_t* pts,
                                  size_t count) {
    if (count == 0) return 0;
    size_t padded = ((count + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK) * THREADS_PER_BLOCK;

    // 1. 4096-bit 密文字节 → rsa4096_bignum, 对 p/q (2048-bit) 取模
    std::vector<rsa4096_bignum> c_vec(count);
    std::vector<rsa_bignum> cp_vec(padded), cq_vec(padded);
    for (size_t i = 0; i < count; ++i) {
        c_vec[i] = rsa4096_bignum::from_bytes(cts + i * RSA_4096_BYTES, RSA_4096_BYTES);
        // 取模: 4096-bit → 2048-bit (p/q 是 rsa_bignum, 但 bn_mod for 4096 重载接受 rsa_bignum? 
        // rsa_bignum 和 rsa4096_bignum 是不同的类型, bn_mod 有各自的 K 版本.
        // 用 rsa4096_bignum 临时变量, 然后提取低 32 words 到 rsa_bignum
        rsa4096_bignum tmp;
        bn_mod(tmp, c_vec[i], key.p);  // K=64 mod with 2048-bit p (key.p is rsa4096_bignum? 不, rsa4096_crt_key 的 p 是 rsa4096_bignum)
        memcpy(cp_vec[i].d, tmp.d, RSA_2048_WORDS * 8);
        bn_mod(tmp, c_vec[i], key.q);
        memcpy(cq_vec[i].d, tmp.d, RSA_2048_WORDS * 8);
    }
    for (size_t i = count; i < padded; ++i) {
        cp_vec[i].zero();
        cq_vec[i].zero();
    }

    // 2. 提取为 uint64_t 连续缓冲（每元素 32 words）
    std::vector<uint64_t> cp_words(padded * RSA_2048_WORDS, 0);
    std::vector<uint64_t> cq_words(padded * RSA_2048_WORDS, 0);
    for (size_t i = 0; i < count; ++i) {
        memcpy(cp_words.data() + i * RSA_2048_WORDS, cp_vec[i].d, RSA_2048_WORDS * 8);
        memcpy(cq_words.data() + i * RSA_2048_WORDS, cq_vec[i].d, RSA_2048_WORDS * 8);
    }

    // 3. p-path: 2048 GPU kernel with key.p, key.dP
    //    key.p/dP 是 rsa4096_bignum (64 words), 但 2048 kernel 只读前 32 words
    auto mctx_p = rsa_mont_init(*(const rsa_bignum*)key.p.d);  // reinterpret as 2048-bit
    musa_rsa_gpu_init(key.p.d, key.dP.d, mctx_p.m_prime,
                      mctx_p.R2_mod_m.d, mctx_p.R_mod_m.d, key.dP.bit_length());

    size_t bytes = padded * RSA_2048_WORDS * sizeof(uint64_t);
    uint64_t *d_cp = nullptr, *d_mp = nullptr;
    RSA_GPU_CHECK(musaMalloc(&d_cp, bytes));
    RSA_GPU_CHECK(musaMalloc(&d_mp, bytes));
    RSA_GPU_CHECK(musaMemcpy(d_cp, cp_words.data(), bytes, musaMemcpyHostToDevice));
    launch_rsa_batch_decrypt(d_cp, d_mp, (int)padded, THREADS_PER_BLOCK, nullptr);
    RSA_GPU_CHECK(musaDeviceSynchronize());
    std::vector<uint64_t> mp_words(padded * RSA_2048_WORDS);
    RSA_GPU_CHECK(musaMemcpy(mp_words.data(), d_mp, bytes, musaMemcpyDeviceToHost));

    // 4. q-path
    auto mctx_q = rsa_mont_init(*(const rsa_bignum*)key.q.d);
    musa_rsa_gpu_init(key.q.d, key.dQ.d, mctx_q.m_prime,
                      mctx_q.R2_mod_m.d, mctx_q.R_mod_m.d, key.dQ.bit_length());
    RSA_GPU_CHECK(musaMemcpy(d_cp, cq_words.data(), bytes, musaMemcpyHostToDevice));
    launch_rsa_batch_decrypt(d_cp, d_mp, (int)padded, THREADS_PER_BLOCK, nullptr);
    RSA_GPU_CHECK(musaDeviceSynchronize());
    std::vector<uint64_t> mq_words(padded * RSA_2048_WORDS);
    RSA_GPU_CHECK(musaMemcpy(mq_words.data(), d_mp, bytes, musaMemcpyDeviceToHost));
    RSA_GPU_CHECK(musaFree(d_mp));
    RSA_GPU_CHECK(musaFree(d_cp));

    // 5. CPU Garner CRT 合并 (4096-bit)
    size_t decrypted = 0;
    for (size_t i = 0; i < count; ++i) {
        rsa_bignum m1, m2;
        memset(&m1, 0, sizeof(m1)); memset(&m2, 0, sizeof(m2));
        memcpy(m1.d, mp_words.data() + i * RSA_2048_WORDS, RSA_2048_WORDS * 8);
        memcpy(m2.d, mq_words.data() + i * RSA_2048_WORDS, RSA_2048_WORDS * 8);

        // h = (m1 - m2) * qInv mod p (全精度: 2048×2048 = 4096-bit 中间结果)
        rsa4096_bignum d4096, qi4096, prod4096, h4096;
        memset(&d4096, 0, sizeof(d4096));
        if (m1 < m2) {
            rsa4096_bignum p4096, tmp;
            memset(&p4096, 0, sizeof(p4096)); memcpy(p4096.d, key.p.d, RSA_2048_WORDS*8);
            memset(&tmp, 0, sizeof(tmp)); memcpy(tmp.d, m2.d, RSA_2048_WORDS*8);
            bn_sub(p4096, p4096, tmp);   // p - m2
            memset(&tmp, 0, sizeof(tmp)); memcpy(tmp.d, m1.d, RSA_2048_WORDS*8);
            bn_add(d4096, tmp, p4096);
        } else {
            memset(&d4096, 0, sizeof(d4096));
            rsa4096_bignum m1_4096, m2_4096;
            memset(&m1_4096, 0, sizeof(m1_4096)); memcpy(m1_4096.d, m1.d, RSA_2048_WORDS*8);
            memset(&m2_4096, 0, sizeof(m2_4096)); memcpy(m2_4096.d, m2.d, RSA_2048_WORDS*8);
            bn_sub(d4096, m1_4096, m2_4096);
        }
        memset(&qi4096, 0, sizeof(qi4096));
        memcpy(qi4096.d, key.qInv.d, RSA_2048_WORDS*8);
        bn_mul(prod4096, d4096, qi4096);
        bn_mod(h4096, prod4096, key.p);
        rsa_bignum h; memcpy(h.d, h4096.d, RSA_2048_WORDS*8);

        // m = m2 + q * h → 4096-bit
        rsa4096_bignum qq, hh, prod, msg;
        memset(&qq, 0, sizeof(qq)); memcpy(qq.d, key.q.d, RSA_4096_WORDS * 8);
        memset(&hh, 0, sizeof(hh)); memcpy(hh.d, h.d, RSA_2048_WORDS * 8);
        memset(&msg, 0, sizeof(msg)); memcpy(msg.d, m2.d, RSA_2048_WORDS * 8);
        bn_mul(prod, qq, hh);
        bn_add(msg, msg, prod);

        // PKCS1 v1.5 解填充
        uint8_t pad[512];
        msg.to_bytes(pad);
        if (pad[0] != 0 || pad[1] != 2) continue;
        size_t sep = 2;
        while (sep < 512 && pad[sep] != 0) ++sep;
        if (sep >= 511) continue;
        size_t plen = 512 - sep - 1;
        uint8_t* out = pts + decrypted * RSA_4096_BYTES;
        memset(out, 0, RSA_4096_BYTES);
        memcpy(out, pad + sep + 1, plen);
        ++decrypted;
    }
    return decrypted;
}

} // namespace jpssl
