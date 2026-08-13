/**
 * sm4_ccm_gfni.cpp - SM4-CCM GFNI backend.
 *
 * CBC-MAC is a serial chain by definition, so its per-block encrypt uses
 * the scalar block cipher (T-box on x86-64; FEAT_SM4 on aarch64). On
 * x86-64 the GFNI S-Box only wins with 8-way block parallelism: a single
 * GFNI block encrypt is latency-bound (two serial affine instructions per
 * round) and measures ~1.6x slower than the scalar T-box, while the 8-way
 * GFNI engine is ~2x faster per block than scalar. The CTR phase therefore
 * runs through the 8-way GFNI engine with CCM counter semantics
 * (increment the last 15 - nonce_len bytes).
 *
 * The CBC-MAC chain and the CTR phase are fused into a single pass over the
 * data: for every 8-block group the GFNI keystream is generated first, then
 * each block advances the serial MAC chain and is XOR-ed with its keystream
 * (the keystream generation hides under the MAC dependency chain).
 *
 * Byte-for-byte compatible with the scalar backend in sm4_ccm.cpp,
 * including the B0 layout (M=16, L=q-1) and zero-padding rules.
 * Dispatched at runtime by sm4_ccm_dispatch.cpp via cpu_has_gfni().
 */
#include "sm4_ccm.hpp"
#include "sm4_gcm_internal.hpp"
#include "cipher_inplace.hpp"

#include <cstring>
#include <vector>

namespace jpssl {

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)

namespace {

/// Build the CCM B0 / counter-0 block (same layout as the scalar backend).
static void sm4_ccm_format_b0(uint8_t b0[16], bool has_aad, size_t m_len,
                              size_t q, const uint8_t* nonce, size_t nonce_len) {
    const int M_enc = (16 - 2) / 2; // tag length 16 encoded as 7
    b0[0] = (uint8_t)((has_aad ? 0x40 : 0) | ((M_enc & 7) << 3) | ((q - 1) & 7));
    std::memcpy(b0 + 1, nonce, nonce_len);
    size_t m = m_len;
    for (int i = 15; i > (int)nonce_len; --i) {
        b0[i] = (uint8_t)(m & 0xFF);
        m >>= 8;
    }
}

/// AAD length prefix (RFC 3610 2.2), written into buf at offset off.
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

/// CCM counter increment: last q bytes, big-endian.
static void sm4_ccm_ctr_inc(uint8_t ctr[16], size_t q) {
    for (int i = 15; i >= 16 - (int)q; --i) {
        if (++ctr[i] != 0) break;
    }
}

/// Streaming CBC-MAC over B0 || [len(a)] || AAD; each part is zero-padded
/// to a block boundary (CCM semantics). The plaintext is fed through the
/// fused MAC+CTR core below.
struct sm4_ccm_mac_stream {
    uint8_t mac[16] = {};
    uint8_t buf[16] = {};
    size_t n = 0;

    void feed(const sm4_ctx* ctx, const uint8_t* p, size_t len) {
        while (len) {
            size_t take = (len < 16 - n) ? len : (16 - n);
            std::memcpy(buf + n, p, take);
            n += take;
            p += take;
            len -= take;
            if (n == 16) {
                for (int i = 0; i < 16; ++i) mac[i] ^= buf[i];
                sm4_encrypt_block(ctx, mac, mac);
                n = 0;
            }
        }
    }

    void finish(const sm4_ctx* ctx) {
        if (n) {
            for (size_t i = 0; i < n; ++i) mac[i] ^= buf[i];
            sm4_encrypt_block(ctx, mac, mac);
            n = 0;
        }
    }
};

/// Fused CBC-MAC + CTR over `data` (length len): the 8-way GFNI engine
/// generates keystream for each 8-block group, then the serial MAC chain
/// advances block by block with the scalar block cipher while the group is
/// XOR-ed into `out`. `out` may alias `data` (each block is read into a
/// local before it is written). When `mac_from_out` is true the MAC runs
/// over the XOR-ed output (decrypt: recovered plaintext), otherwise over
/// the input (encrypt: plaintext). Counters start at `ctr_start` (A1) and
/// advance with CCM increment over the last q bytes. On return `mac` holds
/// the CBC-MAC over the whole data range (CCM zero padding for a partial
/// tail).
static void sm4_ccm_mac_ctr_fused(const sm4_ctx* ctx,
                                  const uint8_t* data, uint8_t* out,
                                  size_t len,
                                  const uint8_t* ctr_start, size_t q,
                                  uint8_t mac[16], bool mac_from_out) {
    uint8_t base[16];
    std::memcpy(base, ctr_start, 16);
    uint8_t counters[128];  // 8 blocks * 16 bytes
    uint8_t keystream[128];

    size_t pos = 0;
    while (pos + 128 <= len) {
        for (int i = 0; i < 8; ++i) {
            std::memcpy(counters + i * 16, base, 16);
            uint32_t carry = (uint32_t)i;
            for (int j = 15; j >= 16 - (int)q && carry; --j) {
                uint32_t v = counters[i * 16 + j] + carry;
                counters[i * 16 + j] = (uint8_t)v;
                carry = v >> 8;
            }
        }
        sm4_encrypt_8blocks_gfni(ctx->rk, counters, keystream);
        for (int b = 0; b < 8; ++b) {
            const uint8_t* p = data + pos + b * 16;
            uint8_t* o = out + pos + b * 16;
            uint8_t tmp[16];
            for (int i = 0; i < 16; ++i)
                tmp[i] = p[i] ^ keystream[b * 16 + i];
            if (mac_from_out) {
                for (int i = 0; i < 16; ++i) mac[i] ^= tmp[i];
            } else {
                for (int i = 0; i < 16; ++i) mac[i] ^= p[i];
            }
            for (int i = 0; i < 16; ++i) o[i] = tmp[i];
            sm4_encrypt_block(ctx, mac, mac);
        }
        pos += 128;

        // Advance the base counter by 8 (CCM inc over the last q bytes).
        uint32_t carry = 8;
        for (int j = 15; j >= 16 - (int)q && carry; --j) {
            uint32_t v = base[j] + carry;
            base[j] = (uint8_t)v;
            carry = v >> 8;
        }
    }

    // Tail: up to 7 blocks, single-block keystream; a partial last block
    // is zero-padded for the MAC (only the valid bytes are XOR-ed).
    while (pos < len) {
        size_t n = (len - pos < 16) ? (len - pos) : 16;
        uint8_t ks[16];
        sm4_encrypt_block(ctx, base, ks);
        uint8_t tmp[16] = {};
        for (size_t i = 0; i < n; ++i)
            tmp[i] = data[pos + i] ^ ks[i];
        if (mac_from_out) {
            for (size_t i = 0; i < n; ++i) mac[i] ^= tmp[i];
        } else {
            for (size_t i = 0; i < n; ++i) mac[i] ^= data[pos + i];
        }
        for (size_t i = 0; i < n; ++i) out[pos + i] = tmp[i];
        sm4_encrypt_block(ctx, mac, mac);
        pos += n;
        sm4_ccm_ctr_inc(base, q);
    }
}

/// Encrypt core: MAC prefix (B0 + AAD), then fused MAC+CTR over the
/// plaintext (safe for in-place out == pt), then the tag block.
static void sm4_ccm_encrypt_impl_gfni(const sm4_ctx* ctx,
                                      const uint8_t* nonce, size_t nonce_len,
                                      const uint8_t* pt, size_t pt_len,
                                      jpssl::span<const uint8_t> aad,
                                      uint8_t* out, uint8_t* tag,
                                      size_t tag_len) {
    const size_t q = 15 - nonce_len;
    uint8_t b0[16], ctr0[16];
    sm4_ccm_format_b0(b0, !aad.empty(), pt_len, q, nonce, nonce_len);
    sm4_ccm_format_b0(ctr0, false, 0, q, nonce, nonce_len);
    ctr0[0] &= 0x07; // keep only the L flags

    sm4_ccm_mac_stream ms;
    ms.feed(ctx, b0, 16);
    if (!aad.empty()) {
        uint8_t aad_buf[8];
        size_t off = 0;
        sm4_ccm_format_aad_len(aad_buf, off, aad.size());
        ms.feed(ctx, aad_buf, off);
        ms.feed(ctx, aad.data(), aad.size());
    }
    ms.finish(ctx); // pad the AAD segment

    uint8_t ctr0_mac[16];
    std::memcpy(ctr0_mac, ctr0, 16); // A0 (counter 0) for the tag block
    sm4_ccm_ctr_inc(ctr0, q); // A1
    sm4_ccm_mac_ctr_fused(ctx, pt, out, pt_len, ctr0, q, ms.mac, false);

    uint8_t enc_mac[16];
    sm4_encrypt_block(ctx, ctr0_mac, enc_mac);
    for (size_t i = 0; i < tag_len; ++i)
        tag[i] = ms.mac[i] ^ enc_mac[i];
}

/// Decrypt core: CTR first, MAC over the recovered plaintext, constant-time
/// tag comparison. In-place safe (out may alias ct).
static bool sm4_ccm_decrypt_impl_gfni(const sm4_ctx* ctx,
                                      const uint8_t* nonce, size_t nonce_len,
                                      const uint8_t* ct, size_t ct_len,
                                      jpssl::span<const uint8_t> aad,
                                      const uint8_t* tag, size_t tag_len,
                                      uint8_t* out) {
    const size_t q = 15 - nonce_len;
    uint8_t b0[16], ctr0[16];
    sm4_ccm_format_b0(b0, !aad.empty(), ct_len, q, nonce, nonce_len);
    sm4_ccm_format_b0(ctr0, false, 0, q, nonce, nonce_len);
    ctr0[0] &= 0x07;
    uint8_t ctr0_mac[16];
    std::memcpy(ctr0_mac, ctr0, 16);

    sm4_ccm_mac_stream ms;
    ms.feed(ctx, b0, 16);
    if (!aad.empty()) {
        uint8_t aad_buf[8];
        size_t off = 0;
        sm4_ccm_format_aad_len(aad_buf, off, aad.size());
        ms.feed(ctx, aad_buf, off);
        ms.feed(ctx, aad.data(), aad.size());
    }
    ms.finish(ctx);

    sm4_ccm_ctr_inc(ctr0, q); // A1
    sm4_ccm_mac_ctr_fused(ctx, ct, out, ct_len, ctr0, q, ms.mac, true);

    uint8_t enc_mac[16];
    sm4_encrypt_block(ctx, ctr0_mac, enc_mac); // A0 block (counter 0)

    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; ++i)
        diff |= tag[i] ^ (ms.mac[i] ^ enc_mac[i]);
    return diff == 0;
}

} // namespace

void sm4_ccm_encrypt_gfni(const sm4_ctx* ctx,
                          const uint8_t* nonce, size_t nonce_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
    ciphertext.resize(plaintext.size());
    sm4_ccm_encrypt_impl_gfni(ctx, nonce, nonce_len,
                              plaintext.data(), plaintext.size(),
                              aad, ciphertext.data(), tag, tag_len);
}

bool sm4_ccm_decrypt_gfni(const sm4_ctx* ctx,
                          const uint8_t* nonce, size_t nonce_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
    plaintext.resize(ciphertext.size());
    return sm4_ccm_decrypt_impl_gfni(ctx, nonce, nonce_len,
                                     ciphertext.data(), ciphertext.size(),
                                     aad, tag, tag_len, plaintext.data());
}

void sm4_ccm_encrypt_gfni_inplace(const sm4_ctx* ctx,
                                  const uint8_t* nonce, size_t nonce_len,
                                  uint8_t* buf, size_t data_len,
                                  jpssl::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len) {
    sm4_ccm_encrypt_impl_gfni(ctx, nonce, nonce_len, buf, data_len,
                              aad, buf, tag, tag_len);
}

bool sm4_ccm_decrypt_gfni_inplace(const sm4_ctx* ctx,
                                  const uint8_t* nonce, size_t nonce_len,
                                  uint8_t* buf, size_t data_len,
                                  jpssl::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len) {
    return sm4_ccm_decrypt_impl_gfni(ctx, nonce, nonce_len, buf, data_len,
                                     aad, tag, tag_len, buf);
}

#endif // (__x86_64__ || _M_X64) && JP_GFNI

} // namespace jpssl
