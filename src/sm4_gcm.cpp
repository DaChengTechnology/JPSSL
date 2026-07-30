/** sm4_gcm.cpp — SM4-GCM AEAD 模式
 *
 *  复用 `gf128_mul` / `ghash` 的通用 GF(2^128) 实现，
 *  将底层分组密码替换为 SM4。
 *  NIST SP 800-38D 标准的 GCM 模式。
 */
#include "sm4_gcm.hpp"
#include "aes.hpp"        // gf128_mul, ghash (GF(2^128) implementation)
#include <cstring>

namespace jpssl {

// ── CTR 模式辅助 ────────────────────────────────────────────────────────

/// SM4 CTR 模式：对每个 16 字节块加密（加密或解密相同）
static void sm4_ctr_xor(const sm4_ctx* ctx,
                        const uint8_t ctr_block[16],
                        const uint8_t* input, uint8_t* output, size_t len) {
    uint8_t counter[16];
    std::memcpy(counter, ctr_block, 16);
    size_t pos = 0;
    while (pos < len) {
        uint8_t keystream[16];
        sm4_encrypt_block(ctx, counter, keystream);
        size_t n = (len - pos < 16) ? (len - pos) : 16;
        for (size_t i = 0; i < n; ++i)
            output[pos + i] = input[pos + i] ^ keystream[i];
        pos += n;

        // 递增 counter（大端序，从低字节开始）
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
    }
}

/// 从 IV 构造 J0（GCM 初始计数器块）
/// 若 IV 长度 == 12：J0 = IV || 0^31 || 1
/// 否则：J0 = GHASH_H(IV || 0^s || len(IV)_64)
static void sm4_gcm_make_j0(const uint8_t H[16],
                            const uint8_t* iv, size_t iv_len,
                            uint8_t j0[16]) {
    if (iv_len == 12) {
        std::memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        // GHASH over padded IV
        std::memset(j0, 0, 16);
        // Build input: IV || pad || len(IV)*8 as 64-bit big-endian
        std::vector<uint8_t> gh_input;
        gh_input.insert(gh_input.end(), iv, iv + iv_len);
        // zero-pad to 16-byte boundary
        size_t pad = (16 - (iv_len % 16)) % 16;
        gh_input.insert(gh_input.end(), pad, 0);
        // Append 64-bit IV length in bits (big-endian)
        uint64_t iv_bits = (uint64_t)iv_len * 8;
        for (int i = 7; i >= 0; --i)
            gh_input.push_back((uint8_t)(iv_bits >> (i * 8)));
        // Append 32 zero bits (second half of the 128-bit length block)
        for (int i = 0; i < 4; ++i) gh_input.push_back(0);

        ghash(H, std::span<const uint8_t>(gh_input), j0);
    }
}

// ── 公开 API ────────────────────────────────────────────────────────────

void sm4_gcm_encrypt(const sm4_ctx* ctx,
                     const uint8_t* iv, size_t iv_len,
                     std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len) {
    // 1. H = SM4_encrypt(0^128)
    uint8_t zero[16] = {};
    uint8_t H[16];
    sm4_encrypt_block(ctx, zero, H);

    // 2. J0 from IV
    uint8_t j0[16];
    sm4_gcm_make_j0(H, iv, iv_len, j0);

    // 3. CTR encrypt plaintext -> ciphertext
    //    CTR starts from inc32(J0) for 12-byte IV case
    uint8_t ctr[16];
    std::memcpy(ctr, j0, 16);
    // Increment J0 by 1: if IV is 12 bytes, inc32(last 4 bytes)
    if (iv_len == 12) {
        // inc32: increment the last 4 bytes (big-endian)
        uint32_t* lw = (uint32_t*)(ctr + 12);
        uint32_t val = __builtin_bswap32(*lw); // big-endian to native
        val++;
        *lw = __builtin_bswap32(val);          // native to big-endian
    } else {
        // Simple increment (big-endian, full 16 bytes)
        for (int i = 15; i >= 0; --i) {
            if (++ctr[i] != 0) break;
        }
    }

    ciphertext.resize(plaintext.size());
    sm4_ctr_xor(ctx, ctr, plaintext.data(), ciphertext.data(), plaintext.size());

    // 4. GHASH input: AAD || pad || C || pad || len(AAD)_64 || len(C)_64
    std::vector<uint8_t> gh_input;
    gh_input.insert(gh_input.end(), aad.begin(), aad.end());
    // zero-pad AAD to 16-byte boundary
    size_t aad_pad = (16 - (aad.size() % 16)) % 16;
    gh_input.insert(gh_input.end(), aad_pad, 0);
    // ciphertext
    gh_input.insert(gh_input.end(), ciphertext.begin(), ciphertext.end());
    // zero-pad ciphertext to 16-byte boundary
    size_t ct_pad = (16 - (ciphertext.size() % 16)) % 16;
    gh_input.insert(gh_input.end(), ct_pad, 0);
    // len(AAD)_64 || len(C)_64 (in bits, big-endian)
    uint64_t aad_bits = (uint64_t)aad.size() * 8;
    uint64_t ct_bits  = (uint64_t)ciphertext.size() * 8;
    for (int i = 7; i >= 0; --i)
        gh_input.push_back((uint8_t)(aad_bits >> (i * 8)));
    for (int i = 7; i >= 0; --i)
        gh_input.push_back((uint8_t)(ct_bits >> (i * 8)));

    uint8_t gh_result[16];
    ghash(H, std::span<const uint8_t>(gh_input), gh_result);

    // 5. Tag = GHASH_result XOR SM4_encrypt(J0)[0..tag_len-1]
    uint8_t enc_j0[16];
    sm4_encrypt_block(ctx, j0, enc_j0);
    for (size_t i = 0; i < tag_len; ++i)
        tag[i] = gh_result[i] ^ enc_j0[i];
}

bool sm4_gcm_decrypt(const sm4_ctx* ctx,
                     const uint8_t* iv, size_t iv_len,
                     std::span<const uint8_t> ciphertext,
                     std::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext) {
    // 1. H = SM4_encrypt(0^128)
    uint8_t zero[16] = {};
    uint8_t H[16];
    sm4_encrypt_block(ctx, zero, H);

    // 2. J0 from IV
    uint8_t j0[16];
    sm4_gcm_make_j0(H, iv, iv_len, j0);

    // 3. Compute expected tag for verification (same as encrypt)
    std::vector<uint8_t> gh_input;
    gh_input.insert(gh_input.end(), aad.begin(), aad.end());
    size_t aad_pad = (16 - (aad.size() % 16)) % 16;
    gh_input.insert(gh_input.end(), aad_pad, 0);
    gh_input.insert(gh_input.end(), ciphertext.begin(), ciphertext.end());
    size_t ct_pad = (16 - (ciphertext.size() % 16)) % 16;
    gh_input.insert(gh_input.end(), ct_pad, 0);
    uint64_t aad_bits = (uint64_t)aad.size() * 8;
    uint64_t ct_bits  = (uint64_t)ciphertext.size() * 8;
    for (int i = 7; i >= 0; --i)
        gh_input.push_back((uint8_t)(aad_bits >> (i * 8)));
    for (int i = 7; i >= 0; --i)
        gh_input.push_back((uint8_t)(ct_bits >> (i * 8)));

    uint8_t gh_result[16];
    ghash(H, std::span<const uint8_t>(gh_input), gh_result);

    uint8_t enc_j0[16];
    sm4_encrypt_block(ctx, j0, enc_j0);

    uint8_t expected_tag[16];
    for (size_t i = 0; i < tag_len; ++i)
        expected_tag[i] = gh_result[i] ^ enc_j0[i];

    // Constant-time comparison
    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; ++i)
        diff |= expected_tag[i] ^ tag[i];
    if (diff != 0) return false;

    // 4. CTR decrypt ciphertext -> plaintext
    uint8_t ctr[16];
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

    plaintext.resize(ciphertext.size());
    sm4_ctr_xor(ctx, ctr, ciphertext.data(), plaintext.data(), ciphertext.size());

    return true;
}

} // namespace jpssl
