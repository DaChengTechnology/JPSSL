/**
 * aes_gcm_avx512.cpp — AVX512 加速 AES-GCM (VAES for CTR + PCLMULQDQ for GHASH)
 *
 * 架构：
 *   - CTR 模式：VAES 8 路并行加密（512-bit ZMM 寄存器）
 *   - GHASH：PCLMULQDQ 128-bit 乘法（与 AVX2 共享逻辑）
 *   - 回退：检测到 AVX512 不可用 → AVX2 → 软件
 */

#include "cipher_inplace.hpp"
#include "cpu_features.hpp"
#include <cstring>
#include <algorithm>

#ifdef __x86_64__
#include <wmmintrin.h>    // AES-NI, PCLMULQDQ
#include <emmintrin.h>    // SSE2
#include <smmintrin.h>    // SSE4.1
#include <immintrin.h>    // AVX512, VAES
#endif

namespace jpssl {
namespace {

#if defined(__x86_64__) && defined(JP_AVX512)

// ═══════════════════════════════════════════════════════════════════════
//  PCLMULQDQ GF(2^128) 乘法（128-bit，与 AVX2 版本相同）
// ═══════════════════════════════════════════════════════════════════════

static inline __m128i gcm_gf128_mul(__m128i a, __m128i b) {
    __m128i t0 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i t1 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i t2 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i t3 = _mm_clmulepi64_si128(a, b, 0x10);
    t2 = _mm_xor_si128(t2, t3);
    t3 = _mm_slli_si128(t2, 8);
    t2 = _mm_srli_si128(t2, 8);
    t0 = _mm_xor_si128(t0, t3);
    t1 = _mm_xor_si128(t1, t2);

    // 完整模约简（与 aes_gcm_avx2.cpp 相同，验证一致）
    __m128i r = _mm_set_epi64x(0, 0x87);
    __m128i q1 = _mm_clmulepi64_si128(t1, r, 0x01);   // t1[1]·R
    t0 = _mm_xor_si128(t0, _mm_clmulepi64_si128(t1, r, 0x00));
    t0 = _mm_xor_si128(t0, _mm_slli_si128(q1, 8));
    q1 = _mm_srli_si128(q1, 8);
    t0 = _mm_xor_si128(t0, _mm_clmulepi64_si128(q1, r, 0x00));
    return t0;
}

/// 逐字节位反转（NIST bit-reflected 字节序 ↔ 自然多项式基）
/// 注意高低半字节位置互换：bitrev(b) = rev4(高半字节) | rev4(低半字节)<<4
static inline __m128i gcm_bitrev(__m128i v) {
    const __m128i rev_lo = _mm_set_epi8(15,7,11,3,13,5,9,1,14,6,10,2,12,4,8,0);
    const __m128i rev_hi = _mm_set_epi8(0xF0,0x70,0xB0,0x30,0xD0,0x50,0x90,0x10,
                                        0xE0,0x60,0xA0,0x20,0xC0,0x40,0x80,0x00);
    __m128i lo = _mm_and_si128(v, _mm_set1_epi8(0x0F));
    __m128i hi = _mm_and_si128(_mm_srli_epi16(v, 4), _mm_set1_epi8(0x0F));
    return _mm_or_si128(_mm_shuffle_epi8(rev_lo, hi), _mm_shuffle_epi8(rev_hi, lo));
}

/// GHASH 核（单块更新）：state = (state ^ block) * H
/// state / block / H 均为自然域（已逐字节位反转）
static inline __m128i gcm_ghash_core(__m128i state, __m128i block, __m128i H) {
    return gcm_gf128_mul(_mm_xor_si128(state, block), H);
}

/// 8 路并行 GHASH：S' = (S^X1)·H^8 ^ X2·H^7 ^ ... ^ X8·H
/// 8 个乘法互不依赖，可并行执行
static inline __m128i gcm_ghash8(__m128i state, const __m128i b[8], const __m128i Hp[8]) {
    __m128i acc = gcm_gf128_mul(_mm_xor_si128(state, b[0]), Hp[7]);
    for (int i = 1; i < 8; ++i)
        acc = _mm_xor_si128(acc, gcm_gf128_mul(b[i], Hp[7 - i]));
    return acc;
}

/// 大端序 64-bit 存储
static inline void store_be64(uint8_t buf[8], uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        buf[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

/// GHASH 多块处理（state 保持自然域，H 为自然域）
static void ghash_bulk(__m128i& state, const uint8_t* data, size_t len, __m128i H) {
    size_t pos = 0;
    while (pos + 16 <= len) {
        __m128i block = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos)));
        state = gcm_ghash_core(state, block, H);
        pos += 16;
    }
    if (pos < len) {
        uint8_t last[16] = {};
        std::memcpy(last, data + pos, len - pos);
        state = gcm_ghash_core(state, gcm_bitrev(_mm_loadu_si128((const __m128i*)last)), H);
    }
}

/// 8 路并行版批量 GHASH（128 字节组走 gcm_ghash8，尾部逐块）
static void ghash_bulk_8way(__m128i& state, const uint8_t* data, size_t len,
                            const __m128i Hp[8]) {
    size_t pos = 0;
    while (pos + 128 <= len) {
        __m128i b[8];
        for (int i = 0; i < 8; ++i)
            b[i] = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos + 16 * i)));
        state = gcm_ghash8(state, b, Hp);
        pos += 128;
    }
    while (pos + 16 <= len) {
        __m128i block = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos)));
        state = gcm_ghash_core(state, block, Hp[0]);
        pos += 16;
    }
    if (pos < len) {
        uint8_t last[16] = {};
        std::memcpy(last, data + pos, len - pos);
        state = gcm_ghash_core(state, gcm_bitrev(_mm_loadu_si128((const __m128i*)last)), Hp[0]);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  AVX512 VAES：8 路并行 AES 加密
// ═══════════════════════════════════════════════════════════════════════

/// 将 128-bit 轮密钥广播到 512-bit 寄存器
static void precompute_rk_512(const __m128i* rk128, int rounds, __m512i* rk512) {
    for (int r = 0; r <= rounds; ++r) {
        rk512[r] = _mm512_broadcast_i32x4(rk128[r]);
    }
}

/// 8 路并行 AES 加密（两个 512-bit 寄存器，每个含 4 个 128-bit 块）
static inline void vaes_encrypt_8blocks(__m512i& b0, __m512i& b1,
                                         const __m512i* rk512, int rounds) {
    b0 = _mm512_xor_si512(b0, rk512[0]);
    b1 = _mm512_xor_si512(b1, rk512[0]);
    for (int r = 1; r < rounds; ++r) {
        b0 = _mm512_aesenc_epi128(b0, rk512[r]);
        b1 = _mm512_aesenc_epi128(b1, rk512[r]);
    }
    b0 = _mm512_aesenclast_epi128(b0, rk512[rounds]);
    b1 = _mm512_aesenclast_epi128(b1, rk512[rounds]);
}

/// 递增 128-bit counter（最后 32-bit 大端序递增）
static inline __m128i inc_counter(__m128i c) {
    uint32_t lo = __builtin_bswap32((uint32_t)_mm_extract_epi32(c, 3));
    ++lo;
    return _mm_insert_epi32(c, (int)__builtin_bswap32(lo), 3);
}

static inline __m128i inc_counter_n(__m128i c, int n) {
    uint32_t lo = __builtin_bswap32((uint32_t)_mm_extract_epi32(c, 3));
    lo += (uint32_t)n;
    return _mm_insert_epi32(c, (int)__builtin_bswap32(lo), 3);
}

// ═══════════════════════════════════════════════════════════════════════
//  检测缓存
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
//  AVX512 GCM 加密
// ═══════════════════════════════════════════════════════════════════════

/// 就地/直写加密核心：密文写入 out（容量 >= plaintext.size()）
static void avx512_gcm_encrypt_impl(const aes_context& ctx,
                                     const uint8_t* iv, size_t iv_len,
                                     std::span<const uint8_t> plaintext,
                                     std::span<const uint8_t> aad,
                                     uint8_t* out,
                                     uint8_t* tag, size_t tag_len) {
    const __m128i* rk128 = (const __m128i*)ctx.enc_rk.data();
    int rounds = ctx.rounds;

    __m512i rk512[15];
    precompute_rk_512(rk128, rounds, rk512);

    // 1. Compute H = AES_encrypt(K, 0^128)，转为 bit-reflected 表示
    __m128i zero = _mm_setzero_si128();
    __m128i H = zero;
    H = _mm_xor_si128(H, rk128[0]);
    for (int r = 1; r < rounds; ++r) H = _mm_aesenc_si128(H, rk128[r]);
    H = _mm_aesenclast_si128(H, rk128[rounds]);
    __m128i Hr = gcm_bitrev(H);   // 自然域 H
    __m128i Hp[8];
    Hp[0] = Hr;
    for (int i = 1; i < 8; ++i) Hp[i] = gcm_gf128_mul(Hp[i - 1], Hr);

    // 2. J0
    __m128i J0;
    if (iv_len == 12) {
        uint8_t J0_buf[16] = {};
        std::memcpy(J0_buf, iv, 12);
        J0_buf[15] = 0x01;
        J0 = _mm_loadu_si128((const __m128i*)J0_buf);
    } else {
        __m128i state = _mm_setzero_si128();
        ghash_bulk(state, iv, iv_len, Hr);
        uint8_t len_block[16] = {};
        store_be64(len_block + 8, iv_len * 8);
        state = gcm_ghash_core(state, gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block)), Hr);
        J0 = gcm_bitrev(state);
    }

    // 3. GHASH AAD
    __m128i ghash_state = _mm_setzero_si128();
    if (!aad.empty()) {
        ghash_bulk_8way(ghash_state, aad.data(), aad.size(), Hp);
    }

    // 4. CTR 加密 + GHASH 密文（8 路并行，直写 out）
    size_t num_blocks = (plaintext.size() + 15) / 16;
    // 只处理完整 128 字节组（8 块），含部分块的尾部交给逐块路径
    size_t num_blocks8 = (plaintext.size() / 128) * 8;

    // 准备 8 个 counters
    __m128i ctrs[8];
    ctrs[0] = inc_counter(J0);
    for (int i = 1; i < 8; ++i) ctrs[i] = inc_counter(ctrs[i - 1]);

    size_t i = 0;
    for (; i < num_blocks8; i += 8) {
        __m512i ctrs0 = _mm512_setzero_si512();
        __m512i ctrs1 = _mm512_setzero_si512();
        ctrs0=_mm512_inserti32x4(ctrs0,ctrs[0],0);ctrs0=_mm512_inserti32x4(ctrs0,ctrs[1],1);
        ctrs0=_mm512_inserti32x4(ctrs0,ctrs[2],2);ctrs0=_mm512_inserti32x4(ctrs0,ctrs[3],3);
        ctrs1=_mm512_inserti32x4(ctrs1,ctrs[4],0);ctrs1=_mm512_inserti32x4(ctrs1,ctrs[5],1);
        ctrs1=_mm512_inserti32x4(ctrs1,ctrs[6],2);ctrs1=_mm512_inserti32x4(ctrs1,ctrs[7],3);

        __m512i ks0 = ctrs0;
        __m512i ks1 = ctrs1;
        vaes_encrypt_8blocks(ks0, ks1, rk512, rounds);

        // 加载明文
        const uint8_t* pt = plaintext.data() + i * 16;
        __m512i pt0 = _mm512_loadu_si512((const __m512i*)(pt + 0));
        __m512i pt1 = _mm512_loadu_si512((const __m512i*)(pt + 64));

        // XOR = 密文
        __m512i ct0 = _mm512_xor_si512(pt0, ks0);
        __m512i ct1 = _mm512_xor_si512(pt1, ks1);

        // 存储密文
        uint8_t* ct = out + i * 16;
        _mm512_storeu_si512((__m512i*)(ct + 0), ct0);
        _mm512_storeu_si512((__m512i*)(ct + 64), ct1);

        __m128i b[8];
        b[0]=_mm512_extracti32x4_epi32(ct0,0);b[1]=_mm512_extracti32x4_epi32(ct0,1);
        b[2]=_mm512_extracti32x4_epi32(ct0,2);b[3]=_mm512_extracti32x4_epi32(ct0,3);
        b[4]=_mm512_extracti32x4_epi32(ct1,0);b[5]=_mm512_extracti32x4_epi32(ct1,1);
        b[6]=_mm512_extracti32x4_epi32(ct1,2);b[7]=_mm512_extracti32x4_epi32(ct1,3);
        for (int k = 0; k < 8; ++k) b[k] = gcm_bitrev(b[k]);
        ghash_state = gcm_ghash8(ghash_state, b, Hp);

        // 递增 counters
        for (int k = 0; k < 8; ++k)
            ctrs[k] = inc_counter_n(ctrs[k], 8);
    }

    // 剩余块（< 8 个），逐块处理（支持不完整尾部块）
    __m128i ctr = inc_counter_n(J0, (int)(i + 1));
    for (; i < num_blocks; ++i) {
        __m128i ks = ctr;
        ks = _mm_xor_si128(ks, rk128[0]);
        for (int r = 1; r < rounds; ++r) ks = _mm_aesenc_si128(ks, rk128[r]);
        ks = _mm_aesenclast_si128(ks, rk128[rounds]);

        size_t offset = i * 16;
        size_t remain = plaintext.size() - offset;
        if (remain >= 16) {
            __m128i pt_blk = _mm_loadu_si128((const __m128i*)(plaintext.data() + offset));
            __m128i ct_blk = _mm_xor_si128(pt_blk, ks);
            _mm_storeu_si128((__m128i*)(out + offset), ct_blk);
            ghash_state = gcm_ghash_core(ghash_state, gcm_bitrev(ct_blk), Hr);
        } else {
            uint8_t ks_buf[16], ct_buf[16] = {};
            _mm_storeu_si128((__m128i*)ks_buf, ks);
            for (size_t j = 0; j < remain; ++j)
                ct_buf[j] = plaintext[offset + j] ^ ks_buf[j];
            std::memcpy(out + offset, ct_buf, remain);
            ghash_state = gcm_ghash_core(
                ghash_state, gcm_bitrev(_mm_loadu_si128((const __m128i*)ct_buf)), Hr);
        }
        ctr = inc_counter(ctr);
    }

    // 5. 最终 GHASH: len(AAD) || len(C)
    uint8_t len_block[16] = {};
    store_be64(len_block, aad.size() * 8);             // len(A) in bytes 0-7
    store_be64(len_block + 8, plaintext.size() * 8);  // len(C) in bytes 8-15
    ghash_state = gcm_ghash_core(
        ghash_state, gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block)), Hr);
    ghash_state = gcm_bitrev(ghash_state);   // 还原 NIST 字节序

    // 6. Tag = GHASH ^ E(K, J0)
    __m128i E_J0 = J0;
    E_J0 = _mm_xor_si128(E_J0, rk128[0]);
    for (int r = 1; r < rounds; ++r) E_J0 = _mm_aesenc_si128(E_J0, rk128[r]);
    E_J0 = _mm_aesenclast_si128(E_J0, rk128[rounds]);

    __m128i tag_val = _mm_xor_si128(ghash_state, E_J0);
    uint8_t tag_buf[16];
    _mm_storeu_si128((__m128i*)tag_buf, tag_val);
    std::memcpy(tag, tag_buf, tag_len);
}

// ═══════════════════════════════════════════════════════════════════════
//  AVX512 GCM 解密
// ═══════════════════════════════════════════════════════════════════════

/// 就地/直写解密核心：明文写入 out（容量 >= ciphertext.size()）
static bool avx512_gcm_decrypt_impl(const aes_context& ctx,
                                     const uint8_t* iv, size_t iv_len,
                                     std::span<const uint8_t> ciphertext,
                                     std::span<const uint8_t> aad,
                                     const uint8_t* tag, size_t tag_len,
                                     uint8_t* out) {
    const __m128i* rk128 = (const __m128i*)ctx.enc_rk.data();
    int rounds = ctx.rounds;

    __m512i rk512[15];
    precompute_rk_512(rk128, rounds, rk512);

    // 1. H（bit-reflected 表示）
    __m128i zero = _mm_setzero_si128();
    __m128i H = zero;
    H = _mm_xor_si128(H, rk128[0]);
    for (int r = 1; r < rounds; ++r) H = _mm_aesenc_si128(H, rk128[r]);
    H = _mm_aesenclast_si128(H, rk128[rounds]);
    __m128i Hr = gcm_bitrev(H);
    __m128i Hp[8];
    Hp[0] = Hr;
    for (int i = 1; i < 8; ++i) Hp[i] = gcm_gf128_mul(Hp[i - 1], Hr);

    // 2. J0
    __m128i J0;
    if (iv_len == 12) {
        uint8_t J0_buf[16] = {};
        std::memcpy(J0_buf, iv, 12);
        J0_buf[15] = 0x01;
        J0 = _mm_loadu_si128((const __m128i*)J0_buf);
    } else {
        __m128i state = _mm_setzero_si128();
        ghash_bulk(state, iv, iv_len, Hr);
        uint8_t len_block[16] = {};
        store_be64(len_block + 8, iv_len * 8);
        state = gcm_ghash_core(state, gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block)), Hr);
        J0 = gcm_bitrev(state);
    }

    // 3. 先验证标签
    __m128i ghash_state = _mm_setzero_si128();
    if (!aad.empty()) {
        ghash_bulk_8way(ghash_state, aad.data(), aad.size(), Hp);
    }
    ghash_bulk_8way(ghash_state, ciphertext.data(), ciphertext.size(), Hp);

    uint8_t len_block[16] = {};
    store_be64(len_block, aad.size() * 8);             // len(A) in bytes 0-7
    store_be64(len_block + 8, ciphertext.size() * 8);  // len(C) in bytes 8-15
    ghash_state = gcm_ghash_core(
        ghash_state, gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block)), Hr);
    ghash_state = gcm_bitrev(ghash_state);

    __m128i E_J0 = J0;
    E_J0 = _mm_xor_si128(E_J0, rk128[0]);
    for (int r = 1; r < rounds; ++r) E_J0 = _mm_aesenc_si128(E_J0, rk128[r]);
    E_J0 = _mm_aesenclast_si128(E_J0, rk128[rounds]);

    __m128i expected_tag = _mm_xor_si128(ghash_state, E_J0);

    // 常量时间比较（仅比较 tag_len 字节）
    uint8_t expected_buf[16], actual_buf[16] = {};
    _mm_storeu_si128((__m128i*)expected_buf, expected_tag);
    std::memcpy(actual_buf, tag, tag_len);
    uint8_t diff = 0;
    for (size_t j = 0; j < tag_len; ++j)
        diff |= expected_buf[j] ^ actual_buf[j];
    if (diff != 0) return false;

    // 4. 解密（CTR，直写 out）
    size_t num_blocks = (ciphertext.size() + 15) / 16;
    size_t num_blocks8 = (ciphertext.size() / 128) * 8;

    __m128i ctrs[8];
    ctrs[0] = inc_counter(J0);
    for (int i = 1; i < 8; ++i) ctrs[i] = inc_counter(ctrs[i - 1]);

    size_t i = 0;
    for (; i < num_blocks8; i += 8) {
        __m512i ctrs0 = _mm512_setzero_si512();
        __m512i ctrs1 = _mm512_setzero_si512();
        ctrs0=_mm512_inserti32x4(ctrs0,ctrs[0],0);ctrs0=_mm512_inserti32x4(ctrs0,ctrs[1],1);
        ctrs0=_mm512_inserti32x4(ctrs0,ctrs[2],2);ctrs0=_mm512_inserti32x4(ctrs0,ctrs[3],3);
        ctrs1=_mm512_inserti32x4(ctrs1,ctrs[4],0);ctrs1=_mm512_inserti32x4(ctrs1,ctrs[5],1);
        ctrs1=_mm512_inserti32x4(ctrs1,ctrs[6],2);ctrs1=_mm512_inserti32x4(ctrs1,ctrs[7],3);

        __m512i ks0 = ctrs0;
        __m512i ks1 = ctrs1;
        vaes_encrypt_8blocks(ks0, ks1, rk512, rounds);

        const uint8_t* ct = ciphertext.data() + i * 16;
        __m512i ct0 = _mm512_loadu_si512((const __m512i*)(ct + 0));
        __m512i ct1 = _mm512_loadu_si512((const __m512i*)(ct + 64));

        __m512i pt0 = _mm512_xor_si512(ct0, ks0);
        __m512i pt1 = _mm512_xor_si512(ct1, ks1);

        uint8_t* pt = out + i * 16;
        _mm512_storeu_si512((__m512i*)(pt + 0), pt0);
        _mm512_storeu_si512((__m512i*)(pt + 64), pt1);

        for (int k = 0; k < 8; ++k)
            ctrs[k] = inc_counter_n(ctrs[k], 8);
    }

    // 剩余块（< 8 个），逐块处理（支持不完整尾部块）
    __m128i ctr = inc_counter_n(J0, (int)(i + 1));
    for (; i < num_blocks; ++i) {
        __m128i ks = ctr;
        ks = _mm_xor_si128(ks, rk128[0]);
        for (int r = 1; r < rounds; ++r) ks = _mm_aesenc_si128(ks, rk128[r]);
        ks = _mm_aesenclast_si128(ks, rk128[rounds]);

        size_t offset = i * 16;
        size_t remain = ciphertext.size() - offset;
        if (remain >= 16) {
            __m128i ct_blk = _mm_loadu_si128((const __m128i*)(ciphertext.data() + offset));
            __m128i pt_blk = _mm_xor_si128(ct_blk, ks);
            _mm_storeu_si128((__m128i*)(out + offset), pt_blk);
        } else {
            uint8_t ks_buf[16], pt_buf[16] = {};
            _mm_storeu_si128((__m128i*)ks_buf, ks);
            for (size_t j = 0; j < remain; ++j)
                pt_buf[j] = ciphertext[offset + j] ^ ks_buf[j];
            std::memcpy(out + offset, pt_buf, remain);
        }

        ctr = inc_counter(ctr);
    }

    return true;
}

#endif // __x86_64__ && JP_AVX512

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════
//  公开接口
// ═══════════════════════════════════════════════════════════════════════

/// 运行时检测：AVX512F + VL + VAES + VPCLMULQDQ（一次性）
static bool avx512_gcm_available() {
    static const bool ready = [] {
        return cpu_has_avx512() && cpu_has_vpclmulqdq_vaes();
    }();
    return ready;
}

void aes_gcm_encrypt_avx512(const aes_context& ctx,
                            const uint8_t* iv, size_t iv_len,
                            std::span<const uint8_t> plaintext,
                            std::span<const uint8_t> aad,
                            std::vector<uint8_t>& ciphertext,
                            uint8_t* tag, size_t tag_len) {
#if defined(__x86_64__) && defined(JP_AVX512)
    if (avx512_gcm_available()) {
        ciphertext.resize(plaintext.size());
        avx512_gcm_encrypt_impl(ctx, iv, iv_len, plaintext, aad, ciphertext.data(),
                                tag, tag_len);
        return;
    }
#endif
    aes_gcm_encrypt_avx2(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
}

bool aes_gcm_decrypt_avx512(const aes_context& ctx,
                            const uint8_t* iv, size_t iv_len,
                            std::span<const uint8_t> ciphertext,
                            std::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
#if defined(__x86_64__) && defined(JP_AVX512)
    if (avx512_gcm_available()) {
        plaintext.resize(ciphertext.size());
        return avx512_gcm_decrypt_impl(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                                       plaintext.data());
    }
#endif
    return aes_gcm_decrypt_avx2(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
}

/// 就地加密：buf 同时作为明文输入与密文输出（容量 >= data_len）
void aes_gcm_encrypt_avx512_inplace(const aes_context& ctx,
                                    const uint8_t* iv, size_t iv_len,
                                    uint8_t* buf, size_t data_len,
                                    std::span<const uint8_t> aad,
                                    uint8_t* tag, size_t tag_len) {
#if defined(__x86_64__) && defined(JP_AVX512)
    if (avx512_gcm_available()) {
        avx512_gcm_encrypt_impl(ctx, iv, iv_len,
                                std::span<const uint8_t>(buf, data_len), aad, buf,
                                tag, tag_len);
        return;
    }
#endif
    aes_gcm_encrypt_avx2_inplace(ctx, iv, iv_len, buf, data_len, aad, tag, tag_len);
}

/// 就地解密：buf 同时作为密文输入与明文输出（容量 >= data_len）
bool aes_gcm_decrypt_avx512_inplace(const aes_context& ctx,
                                    const uint8_t* iv, size_t iv_len,
                                    uint8_t* buf, size_t data_len,
                                    std::span<const uint8_t> aad,
                                    const uint8_t* tag, size_t tag_len) {
#if defined(__x86_64__) && defined(JP_AVX512)
    if (avx512_gcm_available()) {
        return avx512_gcm_decrypt_impl(ctx, iv, iv_len,
                                       std::span<const uint8_t>(buf, data_len), aad,
                                       tag, tag_len, buf);
    }
#endif
    return aes_gcm_decrypt_avx2_inplace(ctx, iv, iv_len, buf, data_len, aad, tag, tag_len);
}

} // namespace jpssl
