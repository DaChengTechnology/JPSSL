/**
 * sm4_ccm_dispatch.cpp - SM4-CCM runtime dispatch.
 *
 * Level selection (one-time CPUID detection):
 *   1 = GFNI  : 8-way parallel SM4-CTR + fused single-pass CBC-MAC
 *   0 = scalar: plain CPU SM4-CCM
 *
 * The GFNI level is only selected when the CPU actually has the features
 * (cpu_features), regardless of whether the library was compiled with the
 * matching JP_* define.
 */
#include "sm4_ccm.hpp"
#include "cipher_inplace.hpp"
#include "cpu_features.hpp"

namespace jpssl {

static bool g_sm4_ccm_checked = false;
static int  g_sm4_ccm_level   = 0; // 0=CPU, 1=GFNI

static void sm4_ccm_detect_best() {
    if (g_sm4_ccm_checked) return;
    g_sm4_ccm_checked = true;
    auto feats = cpu_features::detect();
    if (feats.gfni && feats.avx2) g_sm4_ccm_level = 1;
    else                          g_sm4_ccm_level = 0;
}

int sm4_ccm_auto_level() {
    sm4_ccm_detect_best();
    return g_sm4_ccm_level;
}

void sm4_ccm_encrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* nonce, size_t nonce_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
    sm4_ccm_detect_best();
    switch (g_sm4_ccm_level) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
        case 1:
            sm4_ccm_encrypt_gfni(ctx, nonce, nonce_len, plaintext, aad,
                                 ciphertext, tag, tag_len);
            break;
#endif
        default:
            sm4_ccm_encrypt(ctx, nonce, nonce_len, plaintext, aad,
                            ciphertext, tag, tag_len);
            break;
    }
}

bool sm4_ccm_decrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* nonce, size_t nonce_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
    sm4_ccm_detect_best();
    switch (g_sm4_ccm_level) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
        case 1:
            return sm4_ccm_decrypt_gfni(ctx, nonce, nonce_len, ciphertext,
                                        aad, tag, tag_len, plaintext);
#endif
        default:
            return sm4_ccm_decrypt(ctx, nonce, nonce_len, ciphertext,
                                   aad, tag, tag_len, plaintext);
    }
}

// ------------------------------------------------------------------------
//  In-place (zero-copy) routing for the TLS record layer
// ------------------------------------------------------------------------

void sm4_ccm_encrypt_inplace_auto(const sm4_ctx* ctx,
                                  const uint8_t* nonce, size_t nonce_len,
                                  uint8_t* buf, size_t data_len,
                                  jpssl::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len) {
    sm4_ccm_detect_best();
    switch (g_sm4_ccm_level) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
        case 1:
            sm4_ccm_encrypt_gfni_inplace(ctx, nonce, nonce_len, buf, data_len,
                                         aad, tag, tag_len);
            return;
#endif
        default:
            sm4_ccm_encrypt_inplace(ctx, nonce, nonce_len, buf, data_len,
                                    aad, tag, tag_len);
            return;
    }
}

bool sm4_ccm_decrypt_inplace_auto(const sm4_ctx* ctx,
                                  const uint8_t* nonce, size_t nonce_len,
                                  uint8_t* buf, size_t data_len,
                                  jpssl::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len) {
    sm4_ccm_detect_best();
    switch (g_sm4_ccm_level) {
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
        case 1:
            return sm4_ccm_decrypt_gfni_inplace(ctx, nonce, nonce_len, buf,
                                                data_len, aad, tag, tag_len);
#endif
        default:
            return sm4_ccm_decrypt_inplace(ctx, nonce, nonce_len, buf,
                                           data_len, aad, tag, tag_len);
    }
}

} // namespace jpssl
