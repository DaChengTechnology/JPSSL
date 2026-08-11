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

// Auto-dispatch: AVX512 > AVX2 > CPU
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

} // namespace jpssl
