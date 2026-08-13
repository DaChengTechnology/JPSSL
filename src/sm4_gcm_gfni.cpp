/**
 * sm4_gcm_gfni.cpp - SM4-GCM GFNI backend.
 *
 * The CTR keystream phase uses the 8-way parallel, constant-time GFNI
 * SM4 engine from sm4_gfni.cpp; H/J0 derivation and GHASH reuse the
 * shared helpers in sm4_gcm.cpp (PCLMULQDQ fast path with software
 * fallback).
 *
 * Dispatched at runtime by sm4_gcm_dispatch.cpp via cpu_has_gfni().
 */
#include "sm4_gcm.hpp"
#include "sm4_gcm_internal.hpp"
#include "cipher_inplace.hpp"

#include <cstring>

namespace jpssl {

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)

namespace {

/// GCM CTR start: inc32(J0) for 12-byte IV, otherwise increment the whole block.
static void sm4_gcm_ctr_start(const uint8_t j0[16], size_t iv_len, uint8_t ctr[16]) {
    std::memcpy(ctr, j0, 16);
    if (iv_len == 12) {
        uint32_t* lw = (uint32_t*)(ctr + 12);
        uint32_t val = __builtin_bswap32(*lw);
        val++;
        *lw = __builtin_bswap32(val);
    } else {
        for (int i = 15; i >= 0; --i) {
            if (++ctr[i] != 0) break;
        }
    }
}

} // namespace

void sm4_gcm_encrypt_gfni(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
    uint8_t zero[16] = {};
    uint8_t H[16];
    sm4_encrypt_block(ctx, zero, H);

    uint8_t j0[16];
    sm4_gcm_make_j0(H, iv, iv_len, j0);

    uint8_t ctr[16];
    sm4_gcm_ctr_start(j0, iv_len, ctr);

    ciphertext.resize(plaintext.size());
    sm4_ctr_gfni(ctx, ctr, plaintext.data(), ciphertext.data(), plaintext.size());

    uint8_t gh_result[16];
    sm4_gcm_ghash(H, aad.data(), aad.size(),
                  ciphertext.data(), ciphertext.size(), gh_result);

    uint8_t enc_j0[16];
    sm4_encrypt_block(ctx, j0, enc_j0);
    for (size_t i = 0; i < tag_len; ++i)
        tag[i] = gh_result[i] ^ enc_j0[i];
}

bool sm4_gcm_decrypt_gfni(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
    uint8_t zero[16] = {};
    uint8_t H[16];
    sm4_encrypt_block(ctx, zero, H);

    uint8_t j0[16];
    sm4_gcm_make_j0(H, iv, iv_len, j0);

    // Verify tag first: GHASH over AAD + ciphertext + lengths.
    uint8_t gh_result[16];
    sm4_gcm_ghash(H, aad.data(), aad.size(),
                  ciphertext.data(), ciphertext.size(), gh_result);

    uint8_t enc_j0[16];
    sm4_encrypt_block(ctx, j0, enc_j0);

    uint8_t expected_tag[16];
    for (size_t i = 0; i < tag_len; ++i)
        expected_tag[i] = gh_result[i] ^ enc_j0[i];

    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; ++i)
        diff |= expected_tag[i] ^ tag[i];
    if (diff != 0) return false;

    uint8_t ctr[16];
    sm4_gcm_ctr_start(j0, iv_len, ctr);

    plaintext.resize(ciphertext.size());
    sm4_ctr_gfni(ctx, ctr, ciphertext.data(), plaintext.data(), ciphertext.size());
    return true;
}

// ------------------------------------------------------------------------
//  In-place (zero-copy) variants for the TLS record layer
// ------------------------------------------------------------------------

void sm4_gcm_encrypt_gfni_inplace(const sm4_ctx* ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len) {
    uint8_t zero[16] = {};
    uint8_t H[16];
    sm4_encrypt_block(ctx, zero, H);

    uint8_t j0[16];
    sm4_gcm_make_j0(H, iv, iv_len, j0);

    uint8_t ctr[16];
    sm4_gcm_ctr_start(j0, iv_len, ctr);
    sm4_ctr_gfni(ctx, ctr, buf, buf, data_len); // in-place safe

    uint8_t gh_result[16];
    sm4_gcm_ghash(H, aad.data(), aad.size(), buf, data_len, gh_result);

    uint8_t enc_j0[16];
    sm4_encrypt_block(ctx, j0, enc_j0);
    for (size_t i = 0; i < tag_len; ++i)
        tag[i] = gh_result[i] ^ enc_j0[i];
}

bool sm4_gcm_decrypt_gfni_inplace(const sm4_ctx* ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len) {
    uint8_t zero[16] = {};
    uint8_t H[16];
    sm4_encrypt_block(ctx, zero, H);

    uint8_t j0[16];
    sm4_gcm_make_j0(H, iv, iv_len, j0);

    uint8_t gh_result[16];
    sm4_gcm_ghash(H, aad.data(), aad.size(), buf, data_len, gh_result);

    uint8_t enc_j0[16];
    sm4_encrypt_block(ctx, j0, enc_j0);

    uint8_t expected_tag[16];
    for (size_t i = 0; i < tag_len; ++i)
        expected_tag[i] = gh_result[i] ^ enc_j0[i];

    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; ++i)
        diff |= expected_tag[i] ^ tag[i];
    if (diff != 0) return false;

    uint8_t ctr[16];
    sm4_gcm_ctr_start(j0, iv_len, ctr);
    sm4_ctr_gfni(ctx, ctr, buf, buf, data_len);
    return true;
}

#endif // (__x86_64__ || _M_X64) && JP_GFNI

} // namespace jpssl
