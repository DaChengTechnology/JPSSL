#pragma once
/** sm4_gcm.hpp — SM4-GCM AEAD 模式 (NIST SP 800-38D) */
#include "sm4.hpp"
#include <cstdint>
#include "jpssl_span.hpp"
#include <vector>

namespace jpssl {

void sm4_gcm_encrypt(const sm4_ctx* ctx,
                     const uint8_t* iv, size_t iv_len,
                     jpssl::span<const uint8_t> plaintext,
                     jpssl::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len = 16);

bool sm4_gcm_decrypt(const sm4_ctx* ctx,
                     const uint8_t* iv, size_t iv_len,
                     jpssl::span<const uint8_t> ciphertext,
                     jpssl::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext);

// Auto-dispatch: GFNI > AVX2 > scalar CPU
void sm4_gcm_encrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len = 16);

bool sm4_gcm_decrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext);

// Current auto-dispatch level after detection:
//   0 = scalar CPU, 1 = AVX2, 2 = GFNI (8-way, constant-time S-Box).
int sm4_gcm_auto_level();

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
// AVX2 backend: 8-way parallel SM4-CTR + PCLMULQDQ/software GHASH.
void sm4_gcm_encrypt_avx2(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len = 16);

bool sm4_gcm_decrypt_avx2(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext);
#endif // (__x86_64__ || _M_X64) && JP_AVX2

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
// GFNI backend: 8-way parallel SM4-CTR with constant-time S-Box
// (VGF2P8AFFINEQB + VGF2P8AFFINEINVQB) + PCLMULQDQ/software GHASH.
void sm4_gcm_encrypt_gfni(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len = 16);

bool sm4_gcm_decrypt_gfni(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext);
#endif // (__x86_64__ || _M_X64) && JP_GFNI

} // namespace jpssl
