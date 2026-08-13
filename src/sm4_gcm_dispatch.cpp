/**
 * sm4_gcm_dispatch.cpp - SM4-GCM runtime dispatch.
 *
 * Level selection (one-time CPUID detection):
 *   1 = AVX2  : 8-way parallel SM4-CTR + PCLMULQDQ/software GHASH
 *   0 = scalar: plain CPU SM4-CTR + PCLMULQDQ/software GHASH
 *   2+ is reserved for a future AVX-512 SM4 backend.
 *
 * Level 1 is only selected when the CPU actually has AVX2 (cpu_features),
 * regardless of whether the library was compiled with JP_AVX2.
 */
#include "sm4_gcm.hpp"
#include "cipher_inplace.hpp"
#include "cpu_features.hpp"

namespace jpssl {

static bool g_sm4_checked = false;
static int  g_sm4_level   = 0; // 0=CPU, 1=AVX2 (2+ reserved for AVX512)

static void sm4_detect_best() {
    if (g_sm4_checked) return;
    g_sm4_checked = true;
    auto feats = cpu_features::detect();
    if (feats.avx2) g_sm4_level = 1;
    else            g_sm4_level = 0;
}

int sm4_gcm_auto_level() {
    sm4_detect_best();
    return g_sm4_level;
}

void sm4_gcm_encrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
    sm4_detect_best();
    switch (g_sm4_level) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
        case 1:
            sm4_gcm_encrypt_avx2(ctx, iv, iv_len, plaintext, aad,
                                 ciphertext, tag, tag_len);
            break;
#endif
        default:
            sm4_gcm_encrypt(ctx, iv, iv_len, plaintext, aad,
                            ciphertext, tag, tag_len);
            break;
    }
}

bool sm4_gcm_decrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
    sm4_detect_best();
    switch (g_sm4_level) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
        case 1:
            return sm4_gcm_decrypt_avx2(ctx, iv, iv_len, ciphertext, aad,
                                        tag, tag_len, plaintext);
#endif
        default:
            return sm4_gcm_decrypt(ctx, iv, iv_len, ciphertext, aad,
                                   tag, tag_len, plaintext);
    }
}

// ------------------------------------------------------------------------
//  In-place (zero-copy) routing for the TLS 1.2 record layer
// ------------------------------------------------------------------------

void sm4_gcm_encrypt_inplace_auto(const sm4_ctx* ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len) {
    sm4_detect_best();
    switch (g_sm4_level) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
        case 1:
            sm4_gcm_encrypt_avx2_inplace(ctx, iv, iv_len, buf, data_len,
                                         aad, tag, tag_len);
            return;
#endif
        default:
            sm4_gcm_encrypt_inplace(ctx, iv, iv_len, buf, data_len,
                                    aad, tag, tag_len);
            return;
    }
}

bool sm4_gcm_decrypt_inplace_auto(const sm4_ctx* ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len) {
    sm4_detect_best();
    switch (g_sm4_level) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
        case 1:
            return sm4_gcm_decrypt_avx2_inplace(ctx, iv, iv_len, buf, data_len,
                                                aad, tag, tag_len);
#endif
        default:
            return sm4_gcm_decrypt_inplace(ctx, iv, iv_len, buf, data_len,
                                           aad, tag, tag_len);
    }
}

} // namespace jpssl
