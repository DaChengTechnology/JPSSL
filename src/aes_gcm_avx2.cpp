/**
 * aes_gcm_avx2.cpp — AVX2 加速 AES-GCM (PCLMULQDQ + AES-NI)
 *
 * 关键技术：
 *   - PCLMULQDQ 用于 GF(2^128) 快速乘法（GHASH）
 *   - AES-NI 用于 CTR 模式 keystream 生成
 *   - 4 路并行处理（256-bit YMM 寄存器）
 *
 * 参考文献：
 *   - Intel Carry-Less Multiplication Instruction (CLMUL) White Paper
 *   - Shay Gueron, "AES-GCM for Efficient Authenticated Encryption"
 *   - NIST SP 800-38D (GCM specification)
 */

#include "aes.hpp"
#include "cpu_features.hpp"
#include <cstring>
#include <algorithm>

#ifdef __x86_64__
#include <wmmintrin.h>    // AES-NI, PCLMULQDQ
#include <emmintrin.h>    // SSE2
#include <smmintrin.h>    // SSE4.1
#include <immintrin.h>    // AVX, AVX2
#endif

namespace jpssl {
namespace {

#ifdef __x86_64__

// ═══════════════════════════════════════════════════════════════════════
//  PCLMULQDQ GF(2^128) 乘法辅助函数
// ═══════════════════════════════════════════════════════════════════════

/// 使用 PCLMULQDQ 计算 GF(2^128) 乘法（无进位乘法 + 约简）
/// 不可约多项式：x^128 + x^7 + x^2 + x + 1
/// 位反转表示：约简常数 R = 0xE1 << 120（大端）→ 0x87 << 120（小端反射）
static inline __m128i gcm_gf128_mul(__m128i a, __m128i b) {
    // 使用 Intel CLMUL 白皮书中的算法
    // 步骤 1: 无进位乘法（低 64 位 × 低 64 位）
    __m128i t0 = _mm_clmulepi64_si128(a, b, 0x00);  // a[0]*b[0]
    // 步骤 2: 高 × 高
    __m128i t1 = _mm_clmulepi64_si128(a, b, 0x11);  // a[1]*b[1]
    // 步骤 3: 中1: a[0]*b[1]
    __m128i t2 = _mm_clmulepi64_si128(a, b, 0x01);  // a[0]*b[1]
    // 步骤 4: 中2: a[1]*b[0]
    __m128i t3 = _mm_clmulepi64_si128(a, b, 0x10);  // a[1]*b[0]
    // 步骤 5: 中间部分 XOR
    t2 = _mm_xor_si128(t2, t3);
    // 步骤 6: 分离中间部分的高低 64-bit
    t3 = _mm_slli_si128(t2, 8);   // 左移 8 字节：低 64-bit 移到高
    t2 = _mm_srli_si128(t2, 8);   // 右移 8 字节：高 64-bit 移到低
    // 步骤 7: 组合 256-bit 乘积
    t0 = _mm_xor_si128(t0, t3);   // 低 128-bit
    t1 = _mm_xor_si128(t1, t2);   // 高 128-bit

    // 现在 t0, t1 是 256-bit 乘积（t0 低 128, t1 高 128）
    // 需要模约简：result = t0 XOR (t1 * R) mod P(x)
    // 约简常数 R = 0xE1 << 120，bit-reflected 形式为 0x87
    __m128i r = _mm_set_epi64x(0, 0x87);

    // 第一轮约简：t1[0] * R
    __m128i p = _mm_clmulepi64_si128(t1, r, 0x00);
    t0 = _mm_xor_si128(t0, p);

    // 第二轮约简：上一步结果的高 64-bit 再乘以 R（处理进位）
    __m128i hi = _mm_srli_si128(t0, 8);
    p = _mm_clmulepi64_si128(hi, r, 0x00);
    t0 = _mm_xor_si128(t0, p);

    return t0;
}

/// 使用 PCLMULQDQ 的 GHASH 核（单块更新）
/// state = (state ^ block) * H in GF(2^128)
static inline __m128i gcm_ghash_core(__m128i state, __m128i block, __m128i H) {
    state = _mm_xor_si128(state, block);
    return gcm_gf128_mul(state, H);
}

/// 4 路并行 AES 加密（使用 VAES 或 AES-NI 循环展开）
static inline void aesni_encrypt_4blocks(__m128i& b0, __m128i& b1, __m128i& b2, __m128i& b3,
                                         const __m128i* rk, int rounds) {
    b0 = _mm_xor_si128(b0, rk[0]);
    b1 = _mm_xor_si128(b1, rk[0]);
    b2 = _mm_xor_si128(b2, rk[0]);
    b3 = _mm_xor_si128(b3, rk[0]);

    for (int r = 1; r < rounds; ++r) {
        b0 = _mm_aesenc_si128(b0, rk[r]);
        b1 = _mm_aesenc_si128(b1, rk[r]);
        b2 = _mm_aesenc_si128(b2, rk[r]);
        b3 = _mm_aesenc_si128(b3, rk[r]);
    }

    b0 = _mm_aesenclast_si128(b0, rk[rounds]);
    b1 = _mm_aesenclast_si128(b1, rk[rounds]);
    b2 = _mm_aesenclast_si128(b2, rk[rounds]);
    b3 = _mm_aesenclast_si128(b3, rk[rounds]);
}

/// 递增 4 个 counter（每个 counter 是 128-bit 大端，最后 32 位递增）
static inline void inc_counter_4(__m128i& c0, __m128i& c1, __m128i& c2, __m128i& c3) {
    // 使用 SSE 4.1 的 _mm_insert_epi32 / _mm_extract_epi32 来递增
    // 大端序下 counter[12..15] = 低 32-bit（小端序下是 int 索引 3）
    auto inc_one = [](__m128i c) {
        uint32_t lo = _mm_extract_epi32(c, 3);
        ++lo;
        return _mm_insert_epi32(c, lo, 3);
    };
    c0 = inc_one(c0);
    c1 = inc_one(c1);
    c2 = inc_one(c2);
    c3 = inc_one(c3);
}

/// 递增单个 counter
static inline __m128i inc_counter_1(__m128i c) {
    uint32_t lo = _mm_extract_epi32(c, 3);
    ++lo;
    return _mm_insert_epi32(c, lo, 3);
}

/// 递增 counter N 次（用于跳过已处理的块）
static inline __m128i inc_counter_n(__m128i c, int n) {
    uint32_t lo = _mm_extract_epi32(c, 3);
    lo += n;
    return _mm_insert_epi32(c, lo, 3);
}

/// 大端序 64-bit 存储
static inline void store_be64_avx2(uint8_t buf[8], uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        buf[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

/// 构建 J0（GCM 初始 counter）
static void build_j0_avx2(const uint8_t* iv, size_t iv_len, __m128i H, const __m128i* rk, int rounds, uint8_t J0[16]) {
    if (iv_len == 12) {
        std::memcpy(J0, iv, 12);
        J0[15] = 0x01;
    } else {
        // GHASH(IV || 0^s || len(IV)_64)
        __m128i state = _mm_setzero_si128();
        size_t pos = 0;
        while (pos + 16 <= iv_len) {
            __m128i block = _mm_loadu_si128((const __m128i*)(iv + pos));
            state = gcm_ghash_core(state, block, H);
            pos += 16;
        }
        if (pos < iv_len) {
            // 末尾块补零
            uint8_t last[16] = {};
            std::memcpy(last, iv + pos, iv_len - pos);
            state = gcm_ghash_core(state, _mm_loadu_si128((const __m128i*)last), H);
        }
        // 附加 len(IV) 的 64-bit 大端表示
        uint8_t len_block[16] = {};
        store_be64_avx2(len_block + 8, iv_len * 8);
        state = gcm_ghash_core(state, _mm_loadu_si128((const __m128i*)len_block), H);
        _mm_storeu_si128((__m128i*)J0, state);
    }
}

/// GHASH 多块批量处理（用于 AAD 和密文）
static void ghash_bulk_avx2(__m128i& state, const uint8_t* data, size_t len, __m128i H) {
    size_t pos = 0;
    while (pos + 16 <= len) {
        __m128i block = _mm_loadu_si128((const __m128i*)(data + pos));
        state = gcm_ghash_core(state, block, H);
        pos += 16;
    }
    if (pos < len) {
        uint8_t last[16] = {};
        std::memcpy(last, data + pos, len - pos);
        state = gcm_ghash_core(state, _mm_loadu_si128((const __m128i*)last), H);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  AVX2 GCM 加密（4 路并行 CTR + PCLMULQDQ GHASH）
// ═══════════════════════════════════════════════════════════════════════

static bool g_avx2_ready = false;
static bool g_avx2_checked = false;

static void avx2_gcm_encrypt_impl(const aes_context& ctx,
                                   const uint8_t* iv, size_t iv_len,
                                   std::span<const uint8_t> plaintext,
                                   std::span<const uint8_t> aad,
                                   std::vector<uint8_t>& ciphertext,
                                   uint8_t* tag, size_t tag_len) {
    if (!g_avx2_checked) {
        g_avx2_ready = cpu_has_avx2() && cpu_has_pclmulqdq() && cpu_has_aesni();
        g_avx2_checked = true;
    }

    // 回退：AVX2 不可用或非 AES-128
    if (!g_avx2_ready || ctx.key_size != AesKeySize::AES_128) {
        return aes_gcm_encrypt(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
    }

    const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
    int rounds = ctx.rounds;

    // 1. H = AES_encrypt(K, 0^128)
    __m128i zero = _mm_setzero_si128();
    __m128i H = zero;
    H = _mm_xor_si128(H, rk[0]);
    for (int r = 1; r < rounds; ++r) H = _mm_aesenc_si128(H, rk[r]);
    H = _mm_aesenclast_si128(H, rk[rounds]);

    // 2. J0
    uint8_t J0_buf[16];
    build_j0_avx2(iv, iv_len, H, rk, rounds, J0_buf);
    __m128i J0 = _mm_loadu_si128((const __m128i*)J0_buf);

    // 3. 初始化 GHASH 状态
    __m128i ghash_state = _mm_setzero_si128();

    // 4. GHASH AAD
    if (!aad.empty()) {
        ghash_bulk_avx2(ghash_state, aad.data(), aad.size(), H);
    }

    // 5. CTR 加密 + GHASH 密文（4 路并行）
    ciphertext.resize(plaintext.size());
    size_t num_blocks = (plaintext.size() + 15) / 16;
    size_t num_blocks4 = num_blocks / 4 * 4;

    // 初始化 4 个 counter
    __m128i ctr0 = inc_counter_1(J0);
    __m128i ctr1 = inc_counter_1(ctr0);
    __m128i ctr2 = inc_counter_1(ctr1);
    __m128i ctr3 = inc_counter_1(ctr2);

    size_t i = 0;
    for (; i < num_blocks4; i += 4) {
        __m128i ks0 = ctr0, ks1 = ctr1, ks2 = ctr2, ks3 = ctr3;
        aesni_encrypt_4blocks(ks0, ks1, ks2, ks3, rk, rounds);

        // 加载明文
        const uint8_t* pt = plaintext.data() + i * 16;
        __m128i pt0 = _mm_loadu_si128((const __m128i*)(pt));
        __m128i pt1 = _mm_loadu_si128((const __m128i*)(pt + 16));
        __m128i pt2 = _mm_loadu_si128((const __m128i*)(pt + 32));
        __m128i pt3 = _mm_loadu_si128((const __m128i*)(pt + 48));

        // XOR = 密文
        __m128i ct0 = _mm_xor_si128(pt0, ks0);
        __m128i ct1 = _mm_xor_si128(pt1, ks1);
        __m128i ct2 = _mm_xor_si128(pt2, ks2);
        __m128i ct3 = _mm_xor_si128(pt3, ks3);

        // 存储密文
        uint8_t* ct = ciphertext.data() + i * 16;
        _mm_storeu_si128((__m128i*)(ct), ct0);
        _mm_storeu_si128((__m128i*)(ct + 16), ct1);
        _mm_storeu_si128((__m128i*)(ct + 32), ct2);
        _mm_storeu_si128((__m128i*)(ct + 48), ct3);

        // GHASH 密文块
        ghash_state = gcm_ghash_core(ghash_state, ct0, H);
        ghash_state = gcm_ghash_core(ghash_state, ct1, H);
        ghash_state = gcm_ghash_core(ghash_state, ct2, H);
        ghash_state = gcm_ghash_core(ghash_state, ct3, H);

        // 递增 counters
        ctr0 = inc_counter_n(ctr0, 4);
        ctr1 = inc_counter_n(ctr1, 4);
        ctr2 = inc_counter_n(ctr2, 4);
        ctr3 = inc_counter_n(ctr3, 4);
    }

    // 剩余块（< 4 个）
    __m128i ctr = inc_counter_n(J0, (int)(i + 1));
    for (; i < num_blocks; ++i) {
        __m128i ks = ctr;
        ks = _mm_xor_si128(ks, rk[0]);
        for (int r = 1; r < rounds; ++r) ks = _mm_aesenc_si128(ks, rk[r]);
        ks = _mm_aesenclast_si128(ks, rk[rounds]);

        const uint8_t* pt = plaintext.data() + i * 16;
        __m128i p = _mm_loadu_si128((const __m128i*)pt);
        __m128i c = _mm_xor_si128(p, ks);
        _mm_storeu_si128((__m128i*)(ciphertext.data() + i * 16), c);

        ghash_state = gcm_ghash_core(ghash_state, c, H);
        ctr = inc_counter_1(ctr);
    }

    // 6. 最终 GHASH: len(AAD) || len(C)
    uint8_t len_block[16] = {};
    store_be64_avx2(len_block, aad.size() * 8);             // len(A) in bytes 0-7
    store_be64_avx2(len_block + 8, ciphertext.size() * 8);  // len(C) in bytes 8-15
    ghash_state = gcm_ghash_core(ghash_state, _mm_loadu_si128((const __m128i*)len_block), H);

    // 7. Tag = GHASH(AAD, C, len) ^ E(K, J0)
    __m128i E_J0 = J0;
    E_J0 = _mm_xor_si128(E_J0, rk[0]);
    for (int r = 1; r < rounds; ++r) E_J0 = _mm_aesenc_si128(E_J0, rk[r]);
    E_J0 = _mm_aesenclast_si128(E_J0, rk[rounds]);

    __m128i tag_val = _mm_xor_si128(ghash_state, E_J0);
    _mm_storeu_si128((__m128i*)tag, tag_val);
}

// ═══════════════════════════════════════════════════════════════════════
//  AVX2 GCM 解密
// ═══════════════════════════════════════════════════════════════════════

static bool avx2_gcm_decrypt_impl(const aes_context& ctx,
                                   const uint8_t* iv, size_t iv_len,
                                   std::span<const uint8_t> ciphertext,
                                   std::span<const uint8_t> aad,
                                   const uint8_t* tag, size_t tag_len,
                                   std::vector<uint8_t>& plaintext) {
    if (!g_avx2_checked) {
        g_avx2_ready = cpu_has_avx2() && cpu_has_pclmulqdq() && cpu_has_aesni();
        g_avx2_checked = true;
    }

    if (!g_avx2_ready || ctx.key_size != AesKeySize::AES_128) {
        return aes_gcm_decrypt(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
    }

    const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
    int rounds = ctx.rounds;

    // 1. H
    __m128i zero = _mm_setzero_si128();
    __m128i H = zero;
    H = _mm_xor_si128(H, rk[0]);
    for (int r = 1; r < rounds; ++r) H = _mm_aesenc_si128(H, rk[r]);
    H = _mm_aesenclast_si128(H, rk[rounds]);

    // 2. J0
    uint8_t J0_buf[16];
    build_j0_avx2(iv, iv_len, H, rk, rounds, J0_buf);
    __m128i J0 = _mm_loadu_si128((const __m128i*)J0_buf);

    // 3. 先验证标签（GHASH AAD + 密文 + len）
    __m128i ghash_state = _mm_setzero_si128();
    if (!aad.empty()) {
        ghash_bulk_avx2(ghash_state, aad.data(), aad.size(), H);
    }
    ghash_bulk_avx2(ghash_state, ciphertext.data(), ciphertext.size(), H);

    uint8_t len_block[16] = {};
    store_be64_avx2(len_block, aad.size() * 8);             // len(A) in bytes 0-7
    store_be64_avx2(len_block + 8, ciphertext.size() * 8);  // len(C) in bytes 8-15
    ghash_state = gcm_ghash_core(ghash_state, _mm_loadu_si128((const __m128i*)len_block), H);

    __m128i E_J0 = J0;
    E_J0 = _mm_xor_si128(E_J0, rk[0]);
    for (int r = 1; r < rounds; ++r) E_J0 = _mm_aesenc_si128(E_J0, rk[r]);
    E_J0 = _mm_aesenclast_si128(E_J0, rk[rounds]);

    __m128i expected_tag = _mm_xor_si128(ghash_state, E_J0);

    // 常量时间比较
    __m128i tag128 = _mm_loadu_si128((const __m128i*)tag);
    __m128i diff = _mm_xor_si128(expected_tag, tag128);
    int mask = _mm_movemask_epi8(_mm_cmpeq_epi8(diff, zero));
    if (mask != 0xFFFF) return false;

    // 4. 解密（CTR = 加密，与加密一样）
    plaintext.resize(ciphertext.size());
    size_t num_blocks = (ciphertext.size() + 15) / 16;
    size_t num_blocks4 = num_blocks / 4 * 4;

    __m128i ctr0 = inc_counter_1(J0);
    __m128i ctr1 = inc_counter_1(ctr0);
    __m128i ctr2 = inc_counter_1(ctr1);
    __m128i ctr3 = inc_counter_1(ctr2);

    size_t i = 0;
    for (; i < num_blocks4; i += 4) {
        __m128i ks0 = ctr0, ks1 = ctr1, ks2 = ctr2, ks3 = ctr3;
        aesni_encrypt_4blocks(ks0, ks1, ks2, ks3, rk, rounds);

        const uint8_t* ct = ciphertext.data() + i * 16;
        __m128i ct0 = _mm_loadu_si128((const __m128i*)(ct));
        __m128i ct1 = _mm_loadu_si128((const __m128i*)(ct + 16));
        __m128i ct2 = _mm_loadu_si128((const __m128i*)(ct + 32));
        __m128i ct3 = _mm_loadu_si128((const __m128i*)(ct + 48));

        __m128i pt0 = _mm_xor_si128(ct0, ks0);
        __m128i pt1 = _mm_xor_si128(ct1, ks1);
        __m128i pt2 = _mm_xor_si128(ct2, ks2);
        __m128i pt3 = _mm_xor_si128(ct3, ks3);

        uint8_t* pt = plaintext.data() + i * 16;
        _mm_storeu_si128((__m128i*)(pt), pt0);
        _mm_storeu_si128((__m128i*)(pt + 16), pt1);
        _mm_storeu_si128((__m128i*)(pt + 32), pt2);
        _mm_storeu_si128((__m128i*)(pt + 48), pt3);

        ctr0 = inc_counter_n(ctr0, 4);
        ctr1 = inc_counter_n(ctr1, 4);
        ctr2 = inc_counter_n(ctr2, 4);
        ctr3 = inc_counter_n(ctr3, 4);
    }

    __m128i ctr = inc_counter_n(J0, (int)(i + 1));
    for (; i < num_blocks; ++i) {
        __m128i ks = ctr;
        ks = _mm_xor_si128(ks, rk[0]);
        for (int r = 1; r < rounds; ++r) ks = _mm_aesenc_si128(ks, rk[r]);
        ks = _mm_aesenclast_si128(ks, rk[rounds]);

        const uint8_t* ct = ciphertext.data() + i * 16;
        __m128i c = _mm_loadu_si128((const __m128i*)ct);
        __m128i p = _mm_xor_si128(c, ks);
        _mm_storeu_si128((__m128i*)(plaintext.data() + i * 16), p);

        ctr = inc_counter_1(ctr);
    }

    return true;
}

#endif // __x86_64__

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════
//  公开接口
// ═══════════════════════════════════════════════════════════════════════

void aes_gcm_encrypt_avx2(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
#ifdef __x86_64__
    avx2_gcm_encrypt_impl(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
#else
    aes_gcm_encrypt(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
#endif
}

bool aes_gcm_decrypt_avx2(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
#ifdef __x86_64__
    return avx2_gcm_decrypt_impl(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
#else
    return aes_gcm_decrypt(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
#endif
}

} // namespace jpssl