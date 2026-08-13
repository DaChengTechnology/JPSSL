#pragma once
/** sm4_gcm.hpp — SM4-GCM AEAD 模式 (NIST SP 800-38D) */
#include "sm4.hpp"
#include <cstdint>
#include <span>
#include <vector>

namespace jpssl {

void sm4_gcm_encrypt(const sm4_ctx* ctx,
                     const uint8_t* iv, size_t iv_len,
                     std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len = 16);

bool sm4_gcm_decrypt(const sm4_ctx* ctx,
                     const uint8_t* iv, size_t iv_len,
                     std::span<const uint8_t> ciphertext,
                     std::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext);

// Auto-dispatch: AVX512 > AVX2 > CPU
void sm4_gcm_encrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len = 16);

bool sm4_gcm_decrypt_auto(const sm4_ctx* ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext);

// Current auto-dispatch level after detection: 0 = scalar CPU, 1 = AVX2.
// Level 2 is reserved for a future AVX-512 SM4 backend.
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

} // namespace jpssl
