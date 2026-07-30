/** sm4_ccm.cpp — SM4-CCM AEAD 模式 (NIST SP 800-38C) */
#include "sm4.hpp"
#include <cstring>
#include <vector>
#include <span>

namespace jpssl {

// ── CBC-MAC ─────────────────────────────────────────────────────────────

static void sm4_cbc_mac(const sm4_ctx* ctx,
                        const uint8_t* data, size_t len,
                        uint8_t mac[16], uint8_t tag_len) {
    std::memset(mac, 0, 16);
    size_t pos = 0;
    while (pos + 16 <= len) {
        for (int i = 0; i < 16; ++i) mac[i] ^= data[pos + i];
        sm4_encrypt_block(ctx, mac, mac);
        pos += 16;
    }
    if (pos < len) {
        for (size_t i = 0; i < len - pos; ++i) mac[i] ^= data[pos + i];
        sm4_encrypt_block(ctx, mac, mac);
    }
    (void)tag_len;
}

// ── CTR mode ────────────────────────────────────────────────────────────

static void sm4_ctr_crypt(const sm4_ctx* ctx,
                          const uint8_t ctr_block[16],
                          const uint8_t* input, uint8_t* output, size_t len) {
    uint8_t counter[16];
    std::memcpy(counter, ctr_block, 16);
    size_t pos = 0;
    while (pos < len) {
        uint8_t ks[16];
        sm4_encrypt_block(ctx, counter, ks);
        size_t n = (len - pos < 16) ? (len - pos) : 16;
        for (size_t i = 0; i < n; ++i)
            output[pos + i] = input[pos + i] ^ ks[i];
        pos += n;
        for (int i = 15; i >= 0; --i)
            if (++counter[i] != 0) break;
    }
}

// ── Formatting function ────────────────────────────────────────────────

static void sm4_ccm_format_b0(uint8_t b0[16],
                               bool has_aad, size_t m_len, size_t l_val,
                               const uint8_t* nonce, size_t nonce_len) {
    // First byte: flags
    int L = (int)l_val - 1; // L = number of octets for message length
    int M = 8; // tag length (default 16, encoded as (M-2)/2)
    int M_enc = ((16 - 2) / 2); // (16-2)/2 = 7
    b0[0] = (uint8_t)((has_aad ? 0x40 : 0) | ((M_enc & 7) << 3) | (L & 7));
    // Nonce
    std::memcpy(b0 + 1, nonce, nonce_len);
    // Message length
    size_t m = m_len;
    for (int i = 15; i > (int)nonce_len; --i) {
        b0[i] = (uint8_t)(m & 0xFF);
        m >>= 8;
    }
}

static void sm4_ccm_format_aad_len(uint8_t* buf, size_t& off, size_t aad_len) {
    if (aad_len == 0) return;
    if (aad_len < 65280) {
        buf[off++] = (uint8_t)(aad_len >> 8);
        buf[off++] = (uint8_t)(aad_len);
    } else {
        buf[off++] = 0xFF;
        buf[off++] = 0xFE;
        buf[off++] = (uint8_t)(aad_len >> 24);
        buf[off++] = (uint8_t)(aad_len >> 16);
        buf[off++] = (uint8_t)(aad_len >> 8);
        buf[off++] = (uint8_t)(aad_len);
    }
}

// ── Public API ──────────────────────────────────────────────────────────

void sm4_ccm_encrypt(const sm4_ctx* ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len) {
    // CCM parameters: L=2 (3-byte length), M=16
    int L = 2; // q = 15-L = 13 bytes for nonce
    // Note: for TLS 1.3, nonce_len = 12, L = 3
    if (nonce_len == 12) L = 3;
    else L = (int)(15 - nonce_len);

    // B0 block
    uint8_t b0[16];
    sm4_ccm_format_b0(b0, !aad.empty(), plaintext.size(), 15 - nonce_len, nonce, nonce_len);

    // CBC-MAC input: B0 || AAD_length || AAD || plaintext
    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(), b0, b0 + 16);

    if (!aad.empty()) {
        uint8_t aad_buf[8];
        size_t aad_off = 0;
        sm4_ccm_format_aad_len(aad_buf, aad_off, aad.size());
        mac_input.insert(mac_input.end(), aad_buf, aad_buf + aad_off);
        mac_input.insert(mac_input.end(), aad.begin(), aad.end());
    }

    // Pad MAC input to 16-byte boundary
    while (mac_input.size() % 16 != 0)
        mac_input.push_back(0);

    mac_input.insert(mac_input.end(), plaintext.begin(), plaintext.end());
    while (mac_input.size() % 16 != 0)
        mac_input.push_back(0);

    // Compute CBC-MAC
    uint8_t mac[16];
    sm4_cbc_mac(ctx, mac_input.data(), mac_input.size(), mac, (uint8_t)tag_len);

    // CTR: encrypt MAC to get tag
    uint8_t ctr0[16];
    sm4_ccm_format_b0(ctr0, false, 0, 15 - nonce_len, nonce, nonce_len);
    ctr0[0] &= 0x07; // reset flags, keep L; counter = 0
    uint8_t enc_mac[16];
    sm4_encrypt_block(ctx, ctr0, enc_mac);
    std::memcpy(tag, enc_mac, tag_len);

    // CTR encrypt plaintext
    ctr0[0] |= 0x01; // counter = 1 (increment LSB via bit 0)
    ciphertext.resize(plaintext.size());
    sm4_ctr_crypt(ctx, ctr0, plaintext.data(), ciphertext.data(), plaintext.size());
}

bool sm4_ccm_decrypt(const sm4_ctx* ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     std::span<const uint8_t> ciphertext,
                     std::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext) {
    int L = (nonce_len == 12) ? 3 : (int)(15 - nonce_len);

    // CTR decrypt ciphertext to get plaintext
    uint8_t ctr0[16];
    sm4_ccm_format_b0(ctr0, false, 0, 15 - nonce_len, nonce, nonce_len);
    ctr0[0] &= 0x07;
    ctr0[0] |= 0x01; // counter = 1

    plaintext.resize(ciphertext.size());
    sm4_ctr_crypt(ctx, ctr0, ciphertext.data(), plaintext.data(), ciphertext.size());

    // Compute expected MAC
    uint8_t b0[16];
    sm4_ccm_format_b0(b0, !aad.empty(), ciphertext.size(), 15 - nonce_len, nonce, nonce_len);

    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(), b0, b0 + 16);

    if (!aad.empty()) {
        uint8_t aad_buf[8];
        size_t aad_off = 0;
        sm4_ccm_format_aad_len(aad_buf, aad_off, aad.size());
        mac_input.insert(mac_input.end(), aad_buf, aad_buf + aad_off);
        mac_input.insert(mac_input.end(), aad.begin(), aad.end());
    }
    while (mac_input.size() % 16 != 0)
        mac_input.push_back(0);

    mac_input.insert(mac_input.end(), plaintext.begin(), plaintext.end());
    while (mac_input.size() % 16 != 0)
        mac_input.push_back(0);

    uint8_t expected_mac[16];
    sm4_cbc_mac(ctx, mac_input.data(), mac_input.size(), expected_mac, (uint8_t)tag_len);

    // Encrypt MAC (same as tag generation)
    uint8_t ctr0_mac[16];
    sm4_ccm_format_b0(ctr0_mac, false, 0, 15 - nonce_len, nonce, nonce_len);
    ctr0_mac[0] &= 0x07;
    uint8_t enc_mac[16];
    sm4_encrypt_block(ctx, ctr0_mac, enc_mac);

    // Verify tag
    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; ++i)
        diff |= expected_mac[i] ^ enc_mac[i] ^ tag[i];
    return diff == 0;
}

} // namespace jpssl
