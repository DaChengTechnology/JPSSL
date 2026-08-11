/**
 * aes_gcm_auto.cpp — AES-GCM 自动分派（AVX512 > VAES-256 > AVX2 > AES-NI+软件）
 *
 * 运行时根据 CPU 特性选择最优的 GCM 实现：
 *   3. AVX512F + AVX512VL + VAES + VPCLMULQDQ → 8 路并行（ZMM）
 *   2. VAES（VEX.256）+ VPCLMULQDQ + AVX2 → 4 路并行（2×YMM）
 *      Alder Lake / Raptor Lake 等消费级 CPU 熔断 AVX512 但仍支持
 *      256-bit VAES，无需 AVX512F/VL 即可使用
 *   1. AVX2 + PCLMULQDQ + AES-NI → 4 路并行（AES-NI 单块）
 *   0. 软件实现（AES-NI 加密 + PCLMULQDQ GHASH）
 */

#include "cipher_inplace.hpp"
#include "cpu_features.hpp"
#include <cstring>

namespace jpssl {

static bool g_auto_checked = false;
static int g_best_level = 0; // 0=software, 1=avx2, 2=vaes, 3=avx512

static void detect_best() {
    if (g_auto_checked) return;
    g_auto_checked = true;

    auto feats = cpu_features::detect();

#if defined(JP_NEON)
    if (feats.arm_aes && feats.arm_pmull) {
        g_best_level = 4; // ARM NEON（AESE + PMULL，4 路并行）
    } else
#endif
#if defined(JP_AVX512)
    if (feats.avx512 && feats.vpclmulqdq_vaes) {
        g_best_level = 3; // AVX512 (8 路 VAES)
    } else
#endif
#if defined(JP_VAES)
    if (feats.avx2 && feats.vpclmulqdq_vaes && feats.aesni) {
        g_best_level = 2; // VAES-256 (4 路)
    } else
#endif
    if (feats.avx2 && feats.pclmulqdq && feats.aesni) {
        g_best_level = 1; // AVX2
    } else {
        g_best_level = 0; // 软件
    }
}

void aes_gcm_encrypt_auto(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
    detect_best();
    switch (g_best_level) {
#if defined(JP_NEON)
        case 4:
            aes_gcm_encrypt_neon(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
            break;
#endif
#ifdef JP_AVX512
        case 3:
            aes_gcm_encrypt_avx512(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
            break;
#endif
#if defined(JP_VAES)
        case 2:
            aes_gcm_encrypt_vaes(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
            break;
#endif
#ifdef JP_AVX2
        case 1:
            aes_gcm_encrypt_avx2(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
            break;
#endif
        default:
            aes_gcm_encrypt(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
            break;
    }
}

bool aes_gcm_decrypt_auto(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
    detect_best();
    switch (g_best_level) {
#if defined(JP_NEON)
        case 4:
            return aes_gcm_decrypt_neon(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                                        plaintext);
#endif
#ifdef JP_AVX512
        case 3:
            return aes_gcm_decrypt_avx512(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                                          plaintext);
#endif
#if defined(JP_VAES)
        case 2:
            return aes_gcm_decrypt_vaes(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                                        plaintext);
#endif
#ifdef JP_AVX2
        case 1:
            return aes_gcm_decrypt_avx2(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                                        plaintext);
#endif
        default:
            return aes_gcm_decrypt(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  就地（in-place）接口：密文/明文直接写回输入缓冲，用于 TLS 记录层零拷贝
// ═══════════════════════════════════════════════════════════════════════

void aes_gcm_encrypt_inplace(const aes_context& ctx,
                             const uint8_t* iv, size_t iv_len,
                             uint8_t* buf, size_t data_len,
                             jpssl::span<const uint8_t> aad,
                             uint8_t* tag, size_t tag_len) {
    detect_best();
    switch (g_best_level) {
#if defined(JP_NEON)
        case 4:
            aes_gcm_encrypt_neon_inplace(ctx, iv, iv_len, buf, data_len, aad, tag, tag_len);
            return;
#endif
#ifdef JP_AVX512
        case 3:
            aes_gcm_encrypt_avx512_inplace(ctx, iv, iv_len, buf, data_len, aad, tag, tag_len);
            return;
#endif
#if defined(JP_VAES)
        case 2:
            aes_gcm_encrypt_vaes_inplace(ctx, iv, iv_len, buf, data_len, aad, tag, tag_len);
            return;
#endif
#ifdef JP_AVX2
        case 1:
            aes_gcm_encrypt_avx2_inplace(ctx, iv, iv_len, buf, data_len, aad, tag, tag_len);
            return;
#endif
        default:
            break;
    }
    // 软件回退：临时向量（无 SIMD 后端，仅保证正确性）
    std::vector<uint8_t> ct(data_len);
    aes_gcm_encrypt(ctx, iv, iv_len, jpssl::span<const uint8_t>(buf, data_len), aad,
                    ct, tag, tag_len);
    std::memcpy(buf, ct.data(), data_len);
}

bool aes_gcm_decrypt_inplace(const aes_context& ctx,
                             const uint8_t* iv, size_t iv_len,
                             uint8_t* buf, size_t data_len,
                             jpssl::span<const uint8_t> aad,
                             const uint8_t* tag, size_t tag_len) {
    detect_best();
    switch (g_best_level) {
#if defined(JP_NEON)
        case 4:
            return aes_gcm_decrypt_neon_inplace(ctx, iv, iv_len, buf, data_len, aad,
                                                tag, tag_len);
#endif
#ifdef JP_AVX512
        case 3:
            return aes_gcm_decrypt_avx512_inplace(ctx, iv, iv_len, buf, data_len, aad,
                                                  tag, tag_len);
#endif
#if defined(JP_VAES)
        case 2:
            return aes_gcm_decrypt_vaes_inplace(ctx, iv, iv_len, buf, data_len, aad,
                                                tag, tag_len);
#endif
#ifdef JP_AVX2
        case 1:
            return aes_gcm_decrypt_avx2_inplace(ctx, iv, iv_len, buf, data_len, aad,
                                                tag, tag_len);
#endif
        default:
            break;
    }
    std::vector<uint8_t> pt(data_len);
    bool ok = aes_gcm_decrypt(ctx, iv, iv_len, jpssl::span<const uint8_t>(buf, data_len),
                              aad, tag, tag_len, pt);
    if (ok) std::memcpy(buf, pt.data(), data_len);
    return ok;
}

} // namespace jpssl
