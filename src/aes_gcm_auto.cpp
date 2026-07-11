/**
 * aes_gcm_auto.cpp — AES-GCM 自动分派（AVX512 > AVX2 > AES-NI+软件）
 *
 * 运行时根据 CPU 特性选择最优的 GCM 实现：
 *   1. AVX512F + AVX512VL + VAES + VPCLMULQDQ → 8 路并行
 *   2. AVX2 + PCLMULQDQ + AES-NI → 4 路并行
 *   3. 软件实现（AES-NI 加密 + GF(2^128) 软件乘法）
 */

#include "aes.hpp"
#include "cpu_features.hpp"

namespace jpssl {

static bool g_auto_checked = false;
static int g_best_level = 0; // 0=software, 1=avx2, 2=avx512

static void detect_best() {
    if (g_auto_checked) return;
    g_auto_checked = true;

    auto feats = cpu_features::detect();

    if (feats.avx512 && feats.vpclmulqdq_vaes) {
        g_best_level = 2; // AVX512
    } else if (feats.avx2 && feats.pclmulqdq && feats.aesni) {
        g_best_level = 1; // AVX2
    } else {
        g_best_level = 0; // 软件
    }
}

void aes_gcm_encrypt_auto(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
    detect_best();
    switch (g_best_level) {
#ifdef JP_AVX512
        case 2:
            aes_gcm_encrypt_avx512(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
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
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
    detect_best();
    switch (g_best_level) {
#ifdef JP_AVX512
        case 2:
            return aes_gcm_decrypt_avx512(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
#endif
#ifdef JP_AVX2
        case 1:
            return aes_gcm_decrypt_avx2(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
#endif
        default:
            return aes_gcm_decrypt(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
    }
}

} // namespace jpssl