/**
 * aes_gcm_neon.cpp — ARM NEON 加速 AES-GCM（AESE/AESD + PMULL GHASH）
 *
 * 与 x86 的 AVX2 GCM 后端对应：
 *   - AES-CTR keystream 用 ARMv8 Crypto 的 AESE/AESD（4 块并行）
 *   - GHASH 用 PMULL（vmull_p64）做 GF(2^128) 快速乘法
 *   - 运行时由 cpu_features 检测 FEAT_AES + FEAT_PMULL 后分派
 *
 * 编译：-march=armv8-a+crypto 及以上。
 */

#include "aes.hpp"
#include "cipher_inplace.hpp"
#include "cpu_features.hpp"

// Apple Clang 不定义 __ARM_FEATURE_PMULL（GCC 才有），用 __ARM_FEATURE_CRYPTO 兜底。
// 本文件由 CMake 以 -march=armv8[-a|.1-a|.2-a|9-a]+crypto 编译，AES/PMULL 内在函数必可用。
#if defined(__aarch64__) && defined(JP_NEON) && \
    (defined(__ARM_FEATURE_AES) || defined(__ARM_FEATURE_CRYPTO))
#include <arm_neon.h>

#include <algorithm>
#include <cstring>
#include "jpssl_span.hpp"
#include <vector>

namespace jpssl {

namespace {

// ═══════════════════════════════════════════════════════════════════════
//  GF(2^128) 乘法（bit-reflected 域，GCM 约定）
// ═══════════════════════════════════════════════════════════════════════

/// 逐字节位反转（映射 NIST/GCM 字节约定 → PMULL 自然域，与 x86 gcm_bitrev 等价）
static inline uint8x16_t gcm_bitrev_neon(uint8x16_t x) {
    static const uint8_t rev_nib_tab[16] = {
        0x00, 0x08, 0x04, 0x0C, 0x02, 0x0A, 0x06, 0x0E,
        0x01, 0x09, 0x05, 0x0D, 0x03, 0x0B, 0x07, 0x0F
    };
    const uint8x16_t rev_nib = vld1q_u8(rev_nib_tab);
    uint8x16_t lo = vandq_u8(x, vdupq_n_u8(0x0F));
    uint8x16_t hi = vandq_u8(vshrq_n_u8(x, 4), vdupq_n_u8(0x0F));
    uint8x16_t rlo = vqtbl1q_u8(rev_nib, lo);
    uint8x16_t rhi = vqtbl1q_u8(rev_nib, hi);
    return vorrq_u8(vshlq_n_u8(rlo, 4), rhi);
}

/// 自然域 GF(2^128) 乘法 + 模约简（约简多项式 x^128 + x^7 + x^2 + x + 1）
static inline uint8x16_t gcm_gf128_mul_neon(uint8x16_t x, uint8x16_t y) {
    uint64x2_t X = vreinterpretq_u64_u8(x);
    uint64x2_t Y = vreinterpretq_u64_u8(y);
    poly64_t xl = (poly64_t)vgetq_lane_u64(X, 0);
    poly64_t xh = (poly64_t)vgetq_lane_u64(X, 1);
    poly64_t yl = (poly64_t)vgetq_lane_u64(Y, 0);
    poly64_t yh = (poly64_t)vgetq_lane_u64(Y, 1);

    poly128_t p00 = vmull_p64(xl, yl);
    poly128_t p01 = vmull_p64(xl, yh);
    poly128_t p10 = vmull_p64(xh, yl);
    poly128_t p11 = vmull_p64(xh, yh);

    uint64x2_t mid = veorq_u64(vreinterpretq_u64_p128(p01), vreinterpretq_u64_p128(p10));
    // mid << 64 == (0, mid.lo)；mid >> 64 == (mid.hi, 0)
    uint64x2_t pl = veorq_u64(vreinterpretq_u64_p128(p00),
                              vcombine_u64(vdup_n_u64(0), vget_low_u64(mid)));
    uint64x2_t ph = veorq_u64(vreinterpretq_u64_p128(p11),
                              vcombine_u64(vget_high_u64(mid), vdup_n_u64(0)));

    // Barrett 风格约简：f1 = ph.lo * R，f2 = ph.hi * R，R = 0x87
    poly128_t f1 = vmull_p64((poly64_t)vgetq_lane_u64(ph, 0), (poly64_t)0x87);
    poly128_t f2 = vmull_p64((poly64_t)vgetq_lane_u64(ph, 1), (poly64_t)0x87);
    uint64x2_t res = veorq_u64(pl, vreinterpretq_u64_p128(f1));
    res = veorq_u64(res, vcombine_u64(vdup_n_u64(0), vget_low_u64(vreinterpretq_u64_p128(f2))));
    uint64x2_t ov = vcombine_u64(vget_high_u64(vreinterpretq_u64_p128(f2)), vdup_n_u64(0));
    poly128_t f3 = vmull_p64((poly64_t)vgetq_lane_u64(ov, 0), (poly64_t)0x87);
    res = veorq_u64(res, vreinterpretq_u64_p128(f3));
    return vreinterpretq_u8_u64(res);
}

/// 单块 GHASH 累加：state = (state ^ block) * H
static inline uint8x16_t gcm_ghash_core_neon(uint8x16_t state, uint8x16_t block,
                                             uint8x16_t H) {
    return gcm_gf128_mul_neon(veorq_u8(state, block), H);
}

/// 4 路并行 GHASH：state' = (state+b0)*H^4 + b1*H^3 + b2*H^2 + b3*H
static inline uint8x16_t gcm_ghash4_neon(uint8x16_t state,
                                         uint8x16_t b0, uint8x16_t b1,
                                         uint8x16_t b2, uint8x16_t b3,
                                         uint8x16_t H, uint8x16_t H2,
                                         uint8x16_t H3, uint8x16_t H4) {
    uint8x16_t r0 = gcm_gf128_mul_neon(veorq_u8(state, b0), H4);
    uint8x16_t r1 = gcm_gf128_mul_neon(b1, H3);
    uint8x16_t r2 = gcm_gf128_mul_neon(b2, H2);
    uint8x16_t r3 = gcm_gf128_mul_neon(b3, H);
    return veorq_u8(veorq_u8(r0, r1), veorq_u8(r2, r3));
}

/// 批量 GHASH：64 字节组走 4 路并行，尾部逐块
static void ghash_bulk_neon_4way(uint8x16_t& state, const uint8_t* data, size_t len,
                                 uint8x16_t H, uint8x16_t H2, uint8x16_t H3,
                                 uint8x16_t H4) {
    size_t pos = 0;
    while (pos + 64 <= len) {
        uint8x16_t b0 = gcm_bitrev_neon(vld1q_u8(data + pos));
        uint8x16_t b1 = gcm_bitrev_neon(vld1q_u8(data + pos + 16));
        uint8x16_t b2 = gcm_bitrev_neon(vld1q_u8(data + pos + 32));
        uint8x16_t b3 = gcm_bitrev_neon(vld1q_u8(data + pos + 48));
        state = gcm_ghash4_neon(state, b0, b1, b2, b3, H, H2, H3, H4);
        pos += 64;
    }
    while (pos + 16 <= len) {
        state = gcm_ghash_core_neon(state, gcm_bitrev_neon(vld1q_u8(data + pos)), H);
        pos += 16;
    }
    if (pos < len) {
        uint8_t last[16] = {};
        std::memcpy(last, data + pos, len - pos);
        state = gcm_ghash_core_neon(state, gcm_bitrev_neon(vld1q_u8(last)), H);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  AES 块加密（NEON AESE）
// ═══════════════════════════════════════════════════════════════════════

/// 单块 AES 加密。
///
/// AESE(x,k) = ShiftRows(SubBytes(x ^ k))（密钥在 S-box 之前异或），与 AES-NI
/// 相反，但 OpenSSL aesv8-armx 密钥扩展输出的就是标准 FIPS-197 轮密钥
/// （enc_rk），配套循环结构为：AESE(rk0), MC, ..., AESE(rk_{nr-1}), EOR(rk_nr)。
static inline uint8x16_t aes_encrypt_block_neon(uint8x16_t state,
                                                const uint8_t* rk, int rounds) {
    for (int r = 0; r < rounds - 1; ++r) {
        state = vaeseq_u8(state, vld1q_u8(rk + r * 16));
        state = vaesmcq_u8(state);
    }
    state = vaeseq_u8(state, vld1q_u8(rk + (rounds - 1) * 16));
    state = veorq_u8(state, vld1q_u8(rk + rounds * 16));
    return state;
}

/// 4 块并行 AES 加密（CTR keystream）
static inline void aes_encrypt_4blocks_neon(uint8x16_t& b0, uint8x16_t& b1,
                                            uint8x16_t& b2, uint8x16_t& b3,
                                            const uint8_t* rk, int rounds) {
    b0 = aes_encrypt_block_neon(b0, rk, rounds);
    b1 = aes_encrypt_block_neon(b1, rk, rounds);
    b2 = aes_encrypt_block_neon(b2, rk, rounds);
    b3 = aes_encrypt_block_neon(b3, rk, rounds);
}

/// 单块 AES 解密（dec_rk_aesni：标准 enc 逆序 + 中间轮 InvMixColumns）：
/// AESD(rk0), AESIMC, ..., AESD(rk_{nr-1}), EOR(rk_nr)
static inline uint8x16_t aes_decrypt_block_neon(uint8x16_t state,
                                                const uint8_t* rk, int rounds) {
    for (int r = 0; r < rounds - 1; ++r) {
        state = vaesdq_u8(state, vld1q_u8(rk + r * 16));
        state = vaesimcq_u8(state);
    }
    state = vaesdq_u8(state, vld1q_u8(rk + (rounds - 1) * 16));
    state = veorq_u8(state, vld1q_u8(rk + rounds * 16));
    return state;
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 辅助
// ═══════════════════════════════════════════════════════════════════════

static inline void store_be64_neon(uint8_t buf[8], uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        buf[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

/// GCM 计数器递增（128-bit 大端，仅低 32 位 +1）
static inline uint8x16_t inc_counter_neon(uint8x16_t c) {
    uint8_t b[16];
    vst1q_u8(b, c);
    uint32_t lo = ((uint32_t)b[12] << 24) | ((uint32_t)b[13] << 16) |
                  ((uint32_t)b[14] << 8) | b[15];
    ++lo;
    b[12] = (uint8_t)(lo >> 24);
    b[13] = (uint8_t)(lo >> 16);
    b[14] = (uint8_t)(lo >> 8);
    b[15] = (uint8_t)lo;
    return vld1q_u8(b);
}

/// 构建 J0（NIST SP 800-38D §6.2）。H 为自然域表示，J0 输出 NIST 字节序
static void build_j0_neon(const uint8_t* iv, size_t iv_len, uint8x16_t H,
                          uint8_t J0[16]) {
    if (iv_len == 12) {
        std::memcpy(J0, iv, 12);
        J0[12] = J0[13] = J0[14] = 0;
        J0[15] = 0x01;
        return;
    }
    uint8x16_t state = vdupq_n_u8(0);
    size_t pos = 0;
    while (pos + 16 <= iv_len) {
        state = gcm_ghash_core_neon(state, gcm_bitrev_neon(vld1q_u8(iv + pos)), H);
        pos += 16;
    }
    if (pos < iv_len) {
        uint8_t last[16] = {};
        std::memcpy(last, iv + pos, iv_len - pos);
        state = gcm_ghash_core_neon(state, gcm_bitrev_neon(vld1q_u8(last)), H);
    }
    uint8_t len_block[16] = {};
    store_be64_neon(len_block + 8, iv_len * 8);
    state = gcm_ghash_core_neon(state, gcm_bitrev_neon(vld1q_u8(len_block)), H);
    vst1q_u8(J0, gcm_bitrev_neon(state));
}

// ═══════════════════════════════════════════════════════════════════════
//  加密核心（直写 out，允许 out == plaintext.data()）
// ═══════════════════════════════════════════════════════════════════════

static void neon_gcm_encrypt_impl(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  jpssl::span<const uint8_t> plaintext,
                                  jpssl::span<const uint8_t> aad,
                                  uint8_t* out,
                                  uint8_t* tag, size_t tag_len) {
    const uint8_t* rk = ctx.enc_rk.data();
    const int rounds = ctx.rounds;

    // 1. H = AES_K(0^128)，转自然域；预计算 H^2/H^3/H^4
    uint8x16_t H = aes_encrypt_block_neon(vdupq_n_u8(0), rk, rounds);
    uint8x16_t Hr = gcm_bitrev_neon(H);
    uint8x16_t H2 = gcm_gf128_mul_neon(Hr, Hr);
    uint8x16_t H3 = gcm_gf128_mul_neon(H2, Hr);
    uint8x16_t H4 = gcm_gf128_mul_neon(H3, Hr);

    // 2. J0
    uint8_t J0_buf[16];
    build_j0_neon(iv, iv_len, Hr, J0_buf);
    uint8x16_t J0 = vld1q_u8(J0_buf);

    // 3. GHASH AAD
    uint8x16_t ghash_state = vdupq_n_u8(0);
    if (!aad.empty())
        ghash_bulk_neon_4way(ghash_state, aad.data(), aad.size(), Hr, H2, H3, H4);

    // 4. CTR 加密 + GHASH 密文
    const size_t num_blocks = (plaintext.size() + 15) / 16;
    const size_t num_blocks4 = (plaintext.size() / 64) * 4;
    size_t i = 0;

    uint8x16_t ctr0 = inc_counter_neon(J0);
    uint8x16_t ctr1 = inc_counter_neon(ctr0);
    uint8x16_t ctr2 = inc_counter_neon(ctr1);
    uint8x16_t ctr3 = inc_counter_neon(ctr2);

    for (; i < num_blocks4; i += 4) {
        uint8x16_t ks0 = ctr0, ks1 = ctr1, ks2 = ctr2, ks3 = ctr3;
        aes_encrypt_4blocks_neon(ks0, ks1, ks2, ks3, rk, rounds);

        const uint8_t* pt = plaintext.data() + i * 16;
        uint8_t* ct = out + i * 16;
        uint8x16_t ct0 = veorq_u8(vld1q_u8(pt), ks0);
        uint8x16_t ct1 = veorq_u8(vld1q_u8(pt + 16), ks1);
        uint8x16_t ct2 = veorq_u8(vld1q_u8(pt + 32), ks2);
        uint8x16_t ct3 = veorq_u8(vld1q_u8(pt + 48), ks3);
        vst1q_u8(ct, ct0);
        vst1q_u8(ct + 16, ct1);
        vst1q_u8(ct + 32, ct2);
        vst1q_u8(ct + 48, ct3);

        ghash_state = gcm_ghash4_neon(ghash_state,
                                      gcm_bitrev_neon(ct0), gcm_bitrev_neon(ct1),
                                      gcm_bitrev_neon(ct2), gcm_bitrev_neon(ct3),
                                      Hr, H2, H3, H4);
        // 每块组的 4 个 counter 各自 +4
        for (int k = 0; k < 4; ++k) {
            ctr0 = inc_counter_neon(ctr0);
            ctr1 = inc_counter_neon(ctr1);
            ctr2 = inc_counter_neon(ctr2);
            ctr3 = inc_counter_neon(ctr3);
        }
    }

    // 剩余块（< 4 个），逐块处理（支持不完整尾部）
    uint8x16_t ctr = J0;
    for (int k = 0; k < (int)(i + 1); ++k) ctr = inc_counter_neon(ctr);
    for (; i < num_blocks; ++i) {
        uint8x16_t ks = aes_encrypt_block_neon(ctr, rk, rounds);
        const size_t offset = i * 16;
        const size_t remain = plaintext.size() - offset;
        if (remain >= 16) {
            uint8x16_t c = veorq_u8(vld1q_u8(plaintext.data() + offset), ks);
            vst1q_u8(out + offset, c);
            ghash_state = gcm_ghash_core_neon(ghash_state, gcm_bitrev_neon(c), Hr);
        } else {
            uint8_t ks_buf[16], ct_buf[16] = {};
            vst1q_u8(ks_buf, ks);
            for (size_t j = 0; j < remain; ++j)
                ct_buf[j] = plaintext[offset + j] ^ ks_buf[j];
            std::memcpy(out + offset, ct_buf, remain);
            ghash_state = gcm_ghash_core_neon(ghash_state,
                                              gcm_bitrev_neon(vld1q_u8(ct_buf)), Hr);
        }
        ctr = inc_counter_neon(ctr);
    }

    // 5. 最终 GHASH：len(AAD) || len(C)
    uint8_t len_block[16] = {};
    store_be64_neon(len_block, aad.size() * 8);
    store_be64_neon(len_block + 8, plaintext.size() * 8);
    ghash_state = gcm_ghash_core_neon(ghash_state, gcm_bitrev_neon(vld1q_u8(len_block)), Hr);
    ghash_state = gcm_bitrev_neon(ghash_state);  // 还原 NIST 字节序

    // 6. Tag = GHASH(...) ^ E(K, J0)
    uint8x16_t tag_val = veorq_u8(ghash_state,
                                  aes_encrypt_block_neon(J0, rk, rounds));
    uint8_t tag_buf[16];
    vst1q_u8(tag_buf, tag_val);
    std::memcpy(tag, tag_buf, tag_len);
}

// ═══════════════════════════════════════════════════════════════════════
//  解密核心
// ═══════════════════════════════════════════════════════════════════════

static bool neon_gcm_decrypt_impl(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  jpssl::span<const uint8_t> ciphertext,
                                  jpssl::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len,
                                  uint8_t* out) {
    const uint8_t* enc_rk = ctx.enc_rk.data();
    const uint8_t* dec_rk = ctx.dec_rk_aesni.data();
    const int rounds = ctx.rounds;

    uint8x16_t H = aes_encrypt_block_neon(vdupq_n_u8(0), enc_rk, rounds);
    uint8x16_t Hr = gcm_bitrev_neon(H);
    uint8x16_t H2 = gcm_gf128_mul_neon(Hr, Hr);
    uint8x16_t H3 = gcm_gf128_mul_neon(H2, Hr);
    uint8x16_t H4 = gcm_gf128_mul_neon(H3, Hr);

    uint8_t J0_buf[16];
    build_j0_neon(iv, iv_len, Hr, J0_buf);
    uint8x16_t J0 = vld1q_u8(J0_buf);

    uint8x16_t ghash_state = vdupq_n_u8(0);
    if (!aad.empty())
        ghash_bulk_neon_4way(ghash_state, aad.data(), aad.size(), Hr, H2, H3, H4);
    ghash_bulk_neon_4way(ghash_state, ciphertext.data(), ciphertext.size(),
                         Hr, H2, H3, H4);

    uint8_t len_block[16] = {};
    store_be64_neon(len_block, aad.size() * 8);
    store_be64_neon(len_block + 8, ciphertext.size() * 8);
    ghash_state = gcm_ghash_core_neon(ghash_state, gcm_bitrev_neon(vld1q_u8(len_block)), Hr);
    ghash_state = gcm_bitrev_neon(ghash_state);

    // 常量时间标签校验
    uint8x16_t expected = veorq_u8(ghash_state, aes_encrypt_block_neon(J0, enc_rk, rounds));
    uint8_t expected_buf[16], actual_buf[16];
    vst1q_u8(expected_buf, expected);
    std::memcpy(actual_buf, tag, tag_len);
    uint8_t diff = 0;
    for (size_t j = 0; j < tag_len; ++j) diff |= expected_buf[j] ^ actual_buf[j];
    if (diff != 0) return false;

    // CTR 解密（与加密同构，ks 直接 XOR 密文）
    const size_t num_blocks = (ciphertext.size() + 15) / 16;
    const size_t num_blocks4 = (ciphertext.size() / 64) * 4;
    size_t i = 0;

    uint8x16_t ctr0 = inc_counter_neon(J0);
    uint8x16_t ctr1 = inc_counter_neon(ctr0);
    uint8x16_t ctr2 = inc_counter_neon(ctr1);
    uint8x16_t ctr3 = inc_counter_neon(ctr2);

    for (; i < num_blocks4; i += 4) {
        uint8x16_t ks0 = ctr0, ks1 = ctr1, ks2 = ctr2, ks3 = ctr3;
        aes_encrypt_4blocks_neon(ks0, ks1, ks2, ks3, enc_rk, rounds);
        const uint8_t* ct = ciphertext.data() + i * 16;
        uint8_t* pt = out + i * 16;
        vst1q_u8(pt,      veorq_u8(vld1q_u8(ct),      ks0));
        vst1q_u8(pt + 16, veorq_u8(vld1q_u8(ct + 16), ks1));
        vst1q_u8(pt + 32, veorq_u8(vld1q_u8(ct + 32), ks2));
        vst1q_u8(pt + 48, veorq_u8(vld1q_u8(ct + 48), ks3));
        for (int k = 0; k < 4; ++k) {
            ctr0 = inc_counter_neon(ctr0);
            ctr1 = inc_counter_neon(ctr1);
            ctr2 = inc_counter_neon(ctr2);
            ctr3 = inc_counter_neon(ctr3);
        }
    }

    uint8x16_t ctr = J0;
    for (int k = 0; k < (int)(i + 1); ++k) ctr = inc_counter_neon(ctr);
    for (; i < num_blocks; ++i) {
        uint8x16_t ks = aes_encrypt_block_neon(ctr, enc_rk, rounds);
        const size_t offset = i * 16;
        const size_t remain = ciphertext.size() - offset;
        if (remain >= 16) {
            vst1q_u8(out + offset, veorq_u8(vld1q_u8(ciphertext.data() + offset), ks));
        } else {
            uint8_t ks_buf[16];
            vst1q_u8(ks_buf, ks);
            for (size_t j = 0; j < remain; ++j)
                out[offset + j] = ciphertext[offset + j] ^ ks_buf[j];
        }
        ctr = inc_counter_neon(ctr);
    }
    (void)dec_rk;  // 解密路径仅用 enc_rk（CTR 对称）；dec_rk_aesni 保留给单块 AES 用
    return true;
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════
//  公开接口（与 x86 后端同名约定；运行时检测后由 aes_gcm_auto 分派）
// ═══════════════════════════════════════════════════════════════════════

static bool neon_gcm_available() {
    static const bool ready = [] {
        return cpu_has_arm_aes() && cpu_has_arm_pmull();
    }();
    return ready;
}

void aes_gcm_encrypt_neon(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
    if (neon_gcm_available()) {
        ciphertext.resize(plaintext.size());
        neon_gcm_encrypt_impl(ctx, iv, iv_len, plaintext, aad, ciphertext.data(),
                              tag, tag_len);
        return;
    }
    aes_gcm_encrypt(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
}

bool aes_gcm_decrypt_neon(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
    if (neon_gcm_available()) {
        plaintext.resize(ciphertext.size());
        return neon_gcm_decrypt_impl(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                                     plaintext.data());
    }
    return aes_gcm_decrypt(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
}

void aes_gcm_encrypt_neon_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  jpssl::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len) {
    if (neon_gcm_available()) {
        neon_gcm_encrypt_impl(ctx, iv, iv_len,
                              jpssl::span<const uint8_t>(buf, data_len), aad, buf,
                              tag, tag_len);
        return;
    }
    std::vector<uint8_t> ct(data_len);
    aes_gcm_encrypt(ctx, iv, iv_len, jpssl::span<const uint8_t>(buf, data_len), aad,
                    ct, tag, tag_len);
    std::memcpy(buf, ct.data(), data_len);
}

bool aes_gcm_decrypt_neon_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  jpssl::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len) {
    if (neon_gcm_available()) {
        return neon_gcm_decrypt_impl(ctx, iv, iv_len,
                                     jpssl::span<const uint8_t>(buf, data_len), aad,
                                     tag, tag_len, buf);
    }
    std::vector<uint8_t> pt(data_len);
    bool ok = aes_gcm_decrypt(ctx, iv, iv_len, jpssl::span<const uint8_t>(buf, data_len),
                              aad, tag, tag_len, pt);
    if (ok) std::memcpy(buf, pt.data(), data_len);
    return ok;
}

} // namespace jpssl
#endif // __aarch64__ && JP_NEON && AES && PMULL
