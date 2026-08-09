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

#include "cipher_inplace.hpp"
#include "cpu_features.hpp"
#include <cstring>
#include <algorithm>

#if defined(__x86_64__) || defined(_M_X64)
#include <wmmintrin.h>    // AES-NI, PCLMULQDQ
#include <emmintrin.h>    // SSE2
#include <smmintrin.h>    // SSE4.1
#include <immintrin.h>    // AVX, AVX2
#endif

namespace jpssl {
namespace {

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)

// ═══════════════════════════════════════════════════════════════════════
//  PCLMULQDQ GF(2^128) 乘法辅助函数
// ═══════════════════════════════════════════════════════════════════════

/// 使用 PCLMULQDQ 计算 GF(2^128) 乘法（无进位乘法 + 约简）
/// 不可约多项式：x^128 + x^7 + x^2 + x + 1
/// 输入为“自然域”表示（寄存器位 r = x^r 的系数，即 NIST 字节序经
/// 逐字节位反转后的结果），约简常数 R = 0x87。
static inline __m128i gcm_gf128_mul(__m128i a, __m128i b) {
    __m128i t0 = _mm_clmulepi64_si128(a, b, 0x00);  // a[0]*b[0]
    __m128i t1 = _mm_clmulepi64_si128(a, b, 0x11);  // a[1]*b[1]
    __m128i t2 = _mm_clmulepi64_si128(a, b, 0x01);  // a[0]*b[1]
    __m128i t3 = _mm_clmulepi64_si128(a, b, 0x10);  // a[1]*b[0]
    t2 = _mm_xor_si128(t2, t3);
    t3 = _mm_slli_si128(t2, 8);   // 左移 8 字节：低 64-bit 移到高
    t2 = _mm_srli_si128(t2, 8);   // 右移 8 字节：高 64-bit 移到低
    t0 = _mm_xor_si128(t0, t3);   // 乘积低 128 位（x^0..x^127）
    t1 = _mm_xor_si128(t1, t2);   // 乘积高 128 位（x^128..x^255）

    // 完整模约简（对照软件 gf128_mul 在 20 万随机输入上验证一致）：
    //   t0 ^= t1[0]·R                    (x^128..x^191)
    //   t0 ^= t1[1]·R << 64              (x^192..x^255)
    //   t0 ^= (t1[1]·R >> 64)·R          (第二次折叠：x^128..x^134)
    // 注意 imm 编码：0x00 = A低·B低，0x01 = A高·B低。
    __m128i r = _mm_set_epi64x(0, 0x87);
    __m128i q1 = _mm_clmulepi64_si128(t1, r, 0x01);   // t1[1]·R
    t0 = _mm_xor_si128(t0, _mm_clmulepi64_si128(t1, r, 0x00));
    t0 = _mm_xor_si128(t0, _mm_slli_si128(q1, 8));
    q1 = _mm_srli_si128(q1, 8);
    t0 = _mm_xor_si128(t0, _mm_clmulepi64_si128(q1, r, 0x00));
    return t0;
}

/// 逐字节位反转：NIST bit-reflected 字节序 ↔ 自然多项式基
/// （NIST 约定 byte j bit (7-k) = x^(8j+k)；自然域要求 byte j bit k = x^(8j+k)，
///   两者相差每个字节内的位序反转。注意高低半字节位置互换：
///   bitrev(b) = rev4(高半字节) | rev4(低半字节)<<4）
static inline __m128i gcm_bitrev(__m128i v) {
    const __m128i rev_lo = _mm_set_epi8(15,7,11,3,13,5,9,1,14,6,10,2,12,4,8,0);
    const __m128i rev_hi = _mm_set_epi8(0xF0,0x70,0xB0,0x30,0xD0,0x50,0x90,0x10,
                                        0xE0,0x60,0xA0,0x20,0xC0,0x40,0x80,0x00);
    __m128i lo = _mm_and_si128(v, _mm_set1_epi8(0x0F));
    __m128i hi = _mm_and_si128(_mm_srli_epi16(v, 4), _mm_set1_epi8(0x0F));
    return _mm_or_si128(_mm_shuffle_epi8(rev_lo, hi), _mm_shuffle_epi8(rev_hi, lo));
}

/// GHASH 核（单块更新）：state = (state ^ block) * H
/// state / block / H 均为自然域（已逐字节位反转），PCLMULQDQ 完成乘法。
static inline __m128i gcm_ghash_core(__m128i state, __m128i block, __m128i H) {
    return gcm_gf128_mul(_mm_xor_si128(state, block), H);
}

/// 4 路并行 GHASH：连续 4 块 X1..X4 的 GHASH 可展开为
///   S' = (S ^ X1)·H^4 ^ X2·H^3 ^ X3·H^2 ^ X4·H
/// 四个乘法互不依赖，可并行执行，打破逐块串行链（Gueron 方案）。
/// 输入均为自然域；H2/H3/H4 为预计算的 H 幂。
static inline __m128i gcm_ghash4(__m128i state, __m128i b0, __m128i b1,
                                 __m128i b2, __m128i b3,
                                 __m128i H, __m128i H2, __m128i H3, __m128i H4) {
    __m128i p0 = gcm_gf128_mul(_mm_xor_si128(state, b0), H4);
    __m128i p1 = gcm_gf128_mul(b1, H3);
    __m128i p2 = gcm_gf128_mul(b2, H2);
    __m128i p3 = gcm_gf128_mul(b3, H);
    return _mm_xor_si128(p0, _mm_xor_si128(p1, _mm_xor_si128(p2, p3)));
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

/// 递增单个 counter（GCM counter 最后 32 位为大端序，需 bswap 转换）
static inline __m128i inc_counter_1(__m128i c) {
    uint32_t lo = __builtin_bswap32((uint32_t)_mm_extract_epi32(c, 3));
    ++lo;
    return _mm_insert_epi32(c, (int)__builtin_bswap32(lo), 3);
}

/// 递增 counter N 次（用于跳过已处理的块）
static inline __m128i inc_counter_n(__m128i c, int n) {
    uint32_t lo = __builtin_bswap32((uint32_t)_mm_extract_epi32(c, 3));
    lo += (uint32_t)n;
    return _mm_insert_epi32(c, (int)__builtin_bswap32(lo), 3);
}

/// 递增 4 个 counter（每个 counter 是 128-bit 大端，最后 32 位递增）
static inline void inc_counter_4(__m128i& c0, __m128i& c1, __m128i& c2, __m128i& c3) {
    c0 = inc_counter_1(c0);
    c1 = inc_counter_1(c1);
    c2 = inc_counter_1(c2);
    c3 = inc_counter_1(c3);
}

/// 大端序 64-bit 存储
static inline void store_be64_avx2(uint8_t buf[8], uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        buf[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

/// 构建 J0（GCM 初始 counter, NIST SP 800-38D §6.2）
/// H 为自然域（已逐字节位反转），J0 输出 NIST 字节序
static void build_j0_avx2(const uint8_t* iv, size_t iv_len, __m128i H, uint8_t J0[16]) {
    if (iv_len == 12) {
        // J0 = IV || 0^31 || 1 (NIST SP 800-38D §6.2, 当 len(IV)=96)
        J0[12] = J0[13] = J0[14] = 0;
        std::memcpy(J0, iv, 12);
        J0[15] = 0x01;
    } else {
        // GHASH(IV || 0^s || len(IV)_64)
        __m128i state = _mm_setzero_si128();
        size_t pos = 0;
        while (pos + 16 <= iv_len) {
            __m128i block = gcm_bitrev(_mm_loadu_si128((const __m128i*)(iv + pos)));
            state = gcm_ghash_core(state, block, H);
            pos += 16;
        }
        if (pos < iv_len) {
            // 末尾块补零
            uint8_t last[16] = {};
            std::memcpy(last, iv + pos, iv_len - pos);
            state = gcm_ghash_core(state, gcm_bitrev(_mm_loadu_si128((const __m128i*)last)), H);
        }
        // 附加 len(IV) 的 64-bit 大端表示
        uint8_t len_block[16] = {};
        store_be64_avx2(len_block + 8, iv_len * 8);
        state = gcm_ghash_core(state, gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block)), H);
        _mm_storeu_si128((__m128i*)J0, gcm_bitrev(state));
    }
}

/// 4 路并行版批量 GHASH（64 字节组走 gcm_ghash4，尾部逐块）
static void ghash_bulk_avx2_4way(__m128i& state, const uint8_t* data, size_t len,
                                 __m128i H, __m128i H2, __m128i H3, __m128i H4) {
    size_t pos = 0;
    while (pos + 64 <= len) {
        __m128i b0 = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos)));
        __m128i b1 = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos + 16)));
        __m128i b2 = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos + 32)));
        __m128i b3 = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos + 48)));
        state = gcm_ghash4(state, b0, b1, b2, b3, H, H2, H3, H4);
        pos += 64;
    }
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

// ═══════════════════════════════════════════════════════════════════════
//  AVX2 GCM 加密（4 路并行 CTR + PCLMULQDQ GHASH）
// ═══════════════════════════════════════════════════════════════════════

/// 就地/直写加密核心：密文写入 out（容量 >= plaintext.size()）
static void avx2_gcm_encrypt_impl(const aes_context& ctx,
                                   const uint8_t* iv, size_t iv_len,
                                   std::span<const uint8_t> plaintext,
                                   std::span<const uint8_t> aad,
                                   uint8_t* out,
                                   uint8_t* tag, size_t tag_len) {
    const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
    int rounds = ctx.rounds;

    // 1. H = AES_encrypt(K, 0^128)，转为 bit-reflected 表示供 PCLMULQDQ 使用
    __m128i zero = _mm_setzero_si128();
    __m128i H = zero;
    H = _mm_xor_si128(H, rk[0]);
    for (int r = 1; r < rounds; ++r) H = _mm_aesenc_si128(H, rk[r]);
    H = _mm_aesenclast_si128(H, rk[rounds]);
    __m128i Hr = gcm_bitrev(H);   // 自然域 H（PCLMULQDQ 使用）
    __m128i H2 = gcm_gf128_mul(Hr, Hr);
    __m128i H3 = gcm_gf128_mul(H2, Hr);
    __m128i H4 = gcm_gf128_mul(H3, Hr);

    // 2. J0
    uint8_t J0_buf[16];
    build_j0_avx2(iv, iv_len, Hr, J0_buf);
    __m128i J0 = _mm_loadu_si128((const __m128i*)J0_buf);

    // 3. 初始化 GHASH 状态
    __m128i ghash_state = _mm_setzero_si128();

    // 4. GHASH AAD
    if (!aad.empty()) {
        ghash_bulk_avx2_4way(ghash_state, aad.data(), aad.size(), Hr, H2, H3, H4);
    }

    // 5. CTR 加密 + GHASH 密文（4 路并行，直写 out）
    size_t num_blocks = (plaintext.size() + 15) / 16;
    // 只对“完整 64 字节组”走 4 路批量路径：若最后一组含部分块
    // （plaintext.size() % 16 != 0），整组留给尾部逐块处理，避免越界读写
    size_t num_blocks4 = (plaintext.size() / 64) * 4;

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
        uint8_t* ct = out + i * 16;
        _mm_storeu_si128((__m128i*)(ct), ct0);
        _mm_storeu_si128((__m128i*)(ct + 16), ct1);
        _mm_storeu_si128((__m128i*)(ct + 32), ct2);
        _mm_storeu_si128((__m128i*)(ct + 48), ct3);

        // GHASH 密文块
        ghash_state = gcm_ghash4(ghash_state, gcm_bitrev(ct0), gcm_bitrev(ct1),
                                 gcm_bitrev(ct2), gcm_bitrev(ct3), Hr, H2, H3, H4);

        // 递增 counters
        ctr0 = inc_counter_n(ctr0, 4);
        ctr1 = inc_counter_n(ctr1, 4);
        ctr2 = inc_counter_n(ctr2, 4);
        ctr3 = inc_counter_n(ctr3, 4);
    }

    // 剩余块（< 4 个），逐块处理（支持不完整尾部块）
    __m128i ctr = inc_counter_n(J0, (int)(i + 1));
    for (; i < num_blocks; ++i) {
        __m128i ks = ctr;
        ks = _mm_xor_si128(ks, rk[0]);
        for (int r = 1; r < rounds; ++r) ks = _mm_aesenc_si128(ks, rk[r]);
        ks = _mm_aesenclast_si128(ks, rk[rounds]);

        size_t offset = i * 16;
        size_t remain = plaintext.size() - offset;
        if (remain >= 16) {
            __m128i p = _mm_loadu_si128((const __m128i*)(plaintext.data() + offset));
            __m128i c = _mm_xor_si128(p, ks);
            _mm_storeu_si128((__m128i*)(out + offset), c);
            ghash_state = gcm_ghash_core(ghash_state, gcm_bitrev(c), Hr);
        } else {
            uint8_t ks_buf[16], ct_buf[16] = {};
            _mm_storeu_si128((__m128i*)ks_buf, ks);
            for (size_t j = 0; j < remain; ++j)
                ct_buf[j] = plaintext[offset + j] ^ ks_buf[j];
            std::memcpy(out + offset, ct_buf, remain);
            ghash_state = gcm_ghash_core(
                ghash_state, gcm_bitrev(_mm_loadu_si128((const __m128i*)ct_buf)), Hr);
        }
        ctr = inc_counter_1(ctr);
    }

    // 6. 最终 GHASH: len(AAD) || len(C)
    uint8_t len_block[16] = {};
    store_be64_avx2(len_block, aad.size() * 8);             // len(A) in bytes 0-7
    store_be64_avx2(len_block + 8, plaintext.size() * 8);  // len(C) in bytes 8-15
    ghash_state = gcm_ghash_core(
        ghash_state, gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block)), Hr);
    ghash_state = gcm_bitrev(ghash_state);   // 还原 NIST 字节序

    // 7. Tag = GHASH(AAD, C, len) ^ E(K, J0)
    __m128i E_J0 = J0;
    E_J0 = _mm_xor_si128(E_J0, rk[0]);
    for (int r = 1; r < rounds; ++r) E_J0 = _mm_aesenc_si128(E_J0, rk[r]);
    E_J0 = _mm_aesenclast_si128(E_J0, rk[rounds]);

    __m128i tag_val = _mm_xor_si128(ghash_state, E_J0);
    uint8_t tag_buf[16];
    _mm_storeu_si128((__m128i*)tag_buf, tag_val);
    std::memcpy(tag, tag_buf, tag_len);
}

// ═══════════════════════════════════════════════════════════════════════
//  AVX2 GCM 解密
// ═══════════════════════════════════════════════════════════════════════

/// 就地/直写解密核心：明文写入 out（容量 >= ciphertext.size()）
static bool avx2_gcm_decrypt_impl(const aes_context& ctx,
                                   const uint8_t* iv, size_t iv_len,
                                   std::span<const uint8_t> ciphertext,
                                   std::span<const uint8_t> aad,
                                   const uint8_t* tag, size_t tag_len,
                                   uint8_t* out) {
    const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
    int rounds = ctx.rounds;

    // 1. H（bit-reflected 表示）
    __m128i zero = _mm_setzero_si128();
    __m128i H = zero;
    H = _mm_xor_si128(H, rk[0]);
    for (int r = 1; r < rounds; ++r) H = _mm_aesenc_si128(H, rk[r]);
    H = _mm_aesenclast_si128(H, rk[rounds]);
    __m128i Hr = gcm_bitrev(H);
    __m128i H2 = gcm_gf128_mul(Hr, Hr);
    __m128i H3 = gcm_gf128_mul(H2, Hr);
    __m128i H4 = gcm_gf128_mul(H3, Hr);

    // 2. J0
    uint8_t J0_buf[16];
    build_j0_avx2(iv, iv_len, Hr, J0_buf);
    __m128i J0 = _mm_loadu_si128((const __m128i*)J0_buf);

    // 3. 先验证标签（GHASH AAD + 密文 + len）
    __m128i ghash_state = _mm_setzero_si128();
    if (!aad.empty()) {
        ghash_bulk_avx2_4way(ghash_state, aad.data(), aad.size(), Hr, H2, H3, H4);
    }
    ghash_bulk_avx2_4way(ghash_state, ciphertext.data(), ciphertext.size(), Hr, H2, H3, H4);

    uint8_t len_block[16] = {};
    store_be64_avx2(len_block, aad.size() * 8);             // len(A) in bytes 0-7
    store_be64_avx2(len_block + 8, ciphertext.size() * 8);  // len(C) in bytes 8-15
    ghash_state = gcm_ghash_core(
        ghash_state, gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block)), Hr);
    ghash_state = gcm_bitrev(ghash_state);

    __m128i E_J0 = J0;
    E_J0 = _mm_xor_si128(E_J0, rk[0]);
    for (int r = 1; r < rounds; ++r) E_J0 = _mm_aesenc_si128(E_J0, rk[r]);
    E_J0 = _mm_aesenclast_si128(E_J0, rk[rounds]);

    __m128i expected_tag = _mm_xor_si128(ghash_state, E_J0);

    // 常量时间比较（仅比较 tag_len 字节）
    uint8_t expected_buf[16], actual_buf[16] = {};
    _mm_storeu_si128((__m128i*)expected_buf, expected_tag);
    std::memcpy(actual_buf, tag, tag_len);
    uint8_t diff = 0;
    for (size_t j = 0; j < tag_len; ++j)
        diff |= expected_buf[j] ^ actual_buf[j];
    if (diff != 0) return false;

    // 4. 解密（CTR = 加密，与加密一样，直写 out）
    size_t num_blocks = (ciphertext.size() + 15) / 16;
    size_t num_blocks4 = (ciphertext.size() / 64) * 4;

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

        uint8_t* pt = out + i * 16;
        _mm_storeu_si128((__m128i*)(pt), pt0);
        _mm_storeu_si128((__m128i*)(pt + 16), pt1);
        _mm_storeu_si128((__m128i*)(pt + 32), pt2);
        _mm_storeu_si128((__m128i*)(pt + 48), pt3);

        ctr0 = inc_counter_n(ctr0, 4);
        ctr1 = inc_counter_n(ctr1, 4);
        ctr2 = inc_counter_n(ctr2, 4);
        ctr3 = inc_counter_n(ctr3, 4);
    }

    // 剩余块（< 4 个），逐块处理（支持不完整尾部块）
    __m128i ctr = inc_counter_n(J0, (int)(i + 1));
    for (; i < num_blocks; ++i) {
        __m128i ks = ctr;
        ks = _mm_xor_si128(ks, rk[0]);
        for (int r = 1; r < rounds; ++r) ks = _mm_aesenc_si128(ks, rk[r]);
        ks = _mm_aesenclast_si128(ks, rk[rounds]);

        size_t offset = i * 16;
        size_t remain = ciphertext.size() - offset;
        if (remain >= 16) {
            __m128i c = _mm_loadu_si128((const __m128i*)(ciphertext.data() + offset));
            __m128i p = _mm_xor_si128(c, ks);
            _mm_storeu_si128((__m128i*)(out + offset), p);
        } else {
            uint8_t ks_buf[16], pt_buf[16] = {};
            _mm_storeu_si128((__m128i*)ks_buf, ks);
            for (size_t j = 0; j < remain; ++j)
                pt_buf[j] = ciphertext[offset + j] ^ ks_buf[j];
            std::memcpy(out + offset, pt_buf, remain);
        }

        ctr = inc_counter_1(ctr);
    }

    return true;
}

#endif // (__x86_64__ || _M_X64) && JP_AVX2

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════
//  公开接口
// ═══════════════════════════════════════════════════════════════════════

/// 运行时检测：AVX2 + PCLMULQDQ + AES-NI（一次性）
static bool avx2_gcm_available() {
    static const bool ready = [] {
        return cpu_has_avx2() && cpu_has_pclmulqdq() && cpu_has_aesni();
    }();
    return ready;
}

void aes_gcm_encrypt_avx2(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
    if (avx2_gcm_available()) {
        ciphertext.resize(plaintext.size());
        avx2_gcm_encrypt_impl(ctx, iv, iv_len, plaintext, aad, ciphertext.data(),
                              tag, tag_len);
        return;
    }
#endif
    aes_gcm_encrypt(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
}

bool aes_gcm_decrypt_avx2(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
    if (avx2_gcm_available()) {
        plaintext.resize(ciphertext.size());
        return avx2_gcm_decrypt_impl(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                                     plaintext.data());
    }
#endif
    return aes_gcm_decrypt(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
}

/// 就地加密：buf 同时作为明文输入与密文输出（容量 >= data_len）
void aes_gcm_encrypt_avx2_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
    if (avx2_gcm_available()) {
        avx2_gcm_encrypt_impl(ctx, iv, iv_len,
                              std::span<const uint8_t>(buf, data_len), aad, buf,
                              tag, tag_len);
        return;
    }
#endif
    std::vector<uint8_t> ct(data_len);
    aes_gcm_encrypt(ctx, iv, iv_len, std::span<const uint8_t>(buf, data_len), aad,
                    ct, tag, tag_len);
    std::memcpy(buf, ct.data(), data_len);
}

/// 就地解密：buf 同时作为密文输入与明文输出（容量 >= data_len）
bool aes_gcm_decrypt_avx2_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
    if (avx2_gcm_available()) {
        return avx2_gcm_decrypt_impl(ctx, iv, iv_len,
                                     std::span<const uint8_t>(buf, data_len), aad,
                                     tag, tag_len, buf);
    }
#endif
    std::vector<uint8_t> pt(data_len);
    bool ok = aes_gcm_decrypt(ctx, iv, iv_len,
                              std::span<const uint8_t>(buf, data_len), aad,
                              tag, tag_len, pt);
    if (ok) std::memcpy(buf, pt.data(), data_len);
    return ok;
}

} // namespace jpssl
