#pragma once
/** sm4_ccm.hpp — SM4-CCM AEAD 模式 (NIST SP 800-38C, RFC 8998) */
#include "sm4.hpp"
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

} // namespace jpssl
