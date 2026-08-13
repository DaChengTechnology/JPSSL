#pragma once
/** sm4_ccm.hpp — SM4-CCM AEAD 模式 (NIST SP 800-38C, RFC 8998) */
#include "sm4.hpp"
#include <cstddef>
#include <cstdint>
#include "jpssl_span.hpp"
#include <vector>

namespace jpssl {

void sm4_ccm_encrypt(const sm4_ctx* ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     jpssl::span<const uint8_t> plaintext,
                     jpssl::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len = 16);

bool sm4_ccm_decrypt(const sm4_ctx* ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     jpssl::span<const uint8_t> ciphertext,
                     jpssl::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext);

// Auto-dispatch: GFNI > scalar CPU
void sm4_ccm_encrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* nonce, size_t nonce_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len = 16);

bool sm4_ccm_decrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* nonce, size_t nonce_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext);

// Current auto-dispatch level after detection:
//   0 = scalar CPU, 1 = GFNI (8-way CTR + constant-time S-Box).
int sm4_ccm_auto_level();

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
// GFNI backend: 8-way parallel SM4-CTR, fused single-pass CBC-MAC.
void sm4_ccm_encrypt_gfni(const sm4_ctx* ctx,
                          const uint8_t* nonce, size_t nonce_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len = 16);

bool sm4_ccm_decrypt_gfni(const sm4_ctx* ctx,
                          const uint8_t* nonce, size_t nonce_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext);
#endif // (__x86_64__ || _M_X64) && JP_GFNI

} // namespace jpssl
