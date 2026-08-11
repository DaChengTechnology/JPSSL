/**
 * sm4_gcm_dispatch.cpp — SM4-GCM 自动分派（AVX512 > AVX2 > CPU）
 *
 * 根据 CPU 特性选择最优实现。当前 AVX2/AVX512 GCM 完整实现待补充。
 */
#include "sm4_gcm.hpp"
#include "cpu_features.hpp"

namespace jpssl {

static bool g_sm4_checked = false;
static int  g_sm4_level   = 0; // 0=CPU, 1=AVX2, 2=AVX512

static void sm4_detect_best() {
    if (g_sm4_checked) return;
    g_sm4_checked = true;
    auto feats = cpu_features::detect();
    if (feats.avx512)      g_sm4_level = 2;
    else if (feats.avx2)   g_sm4_level = 1;
    else                   g_sm4_level = 0;
}

void sm4_gcm_encrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
    sm4_detect_best();
    // Currently all levels use the same CPU implementation.
    // Future: add sm4_gcm_encrypt_avx2 / sm4_gcm_encrypt_avx512.
    (void)g_sm4_level;
    sm4_gcm_encrypt(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
}

bool sm4_gcm_decrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
    sm4_detect_best();
    (void)g_sm4_level;
    return sm4_gcm_decrypt(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
}

} // namespace jpssl
