/**
 * aes_ccm.cpp — AES-CCM 认证加密（AES-NI 加速 + 软件回退）
 *
 * NIST SP 800-38C / RFC 3610
 *
 * 性能设计（AES-NI 路径）：
 *   - CBC-MAC 是串行链（每块 E(mac ^ block)），无法并行，但状态全程留在
 *     寄存器，避免每块的内存往返
 *   - CTR keystream 每 4 块并行生成（4 路 AES-NI），与 MAC 链在同一次遍历中
 *     融合：读明文 → 串行 MAC + 向量 XOR 输出密文，无中间大缓冲
 *   - 计数器对 q <= 4（TLS 场景 q=2/3）用 bswap + 大端加法快速递增
 *
 * 核心为指针输出（就地安全：按块先读后写），公共 vector API 与内部
 * 零拷贝接口（aes_ccm_*_inplace，仅供 TLS 记录层）共用同一核心。
 */

#include "aes.hpp"
#include "cipher_inplace.hpp"   // 内部：零拷贝 AEAD 声明（TLS 记录层专用）
#include "cpu_features.hpp"
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64)
#include <wmmintrin.h>   // AES-NI intrinsics
#include <emmintrin.h>   // SSE2
#include <smmintrin.h>   // SSE4.1 (_mm_extract_epi32 / _mm_insert_epi32)
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif

namespace jpssl {

#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__)

#if defined(__x86_64__) || defined(_M_X64)

static inline uint32_t bswap32_u(uint32_t v) {
#if defined(_MSC_VER)
    return _byteswap_ulong(v);
#else
    return __builtin_bswap32(v);
#endif
}

static inline __m128i ccm_aes_enc1(__m128i s, const __m128i* rk, int rounds) {
    s = _mm_xor_si128(s, rk[0]);
    for (int r = 1; r < rounds; ++r)
        s = _mm_aesenc_si128(s, rk[r]);
    return _mm_aesenclast_si128(s, rk[rounds]);
}

static inline void ccm_aes_enc4(__m128i& b0, __m128i& b1, __m128i& b2, __m128i& b3,
                                const __m128i* rk, int rounds) {
    b0 = _mm_xor_si128(b0, rk[0]);
    b1 = _mm_xor_si128(b1, rk[0]);
    b2 = _mm_xor_si128(b2, rk[0]);
    b3 = _mm_xor_si128(b3, rk[0]);
    for (int r = 1; r < rounds; ++r) {
        b0 = _mm_aesenc_si128(b0, rk[r]);
        b1 = _mm_aesenc_si128(b1, rk[r]);
        b2 = _mm_aesenc_si128(b2, rk[r]);
        b3 = _mm_aesenc_si128(b3, rk[r]);
    }
    b0 = _mm_aesenclast_si128(b0, rk[rounds]);
    b1 = _mm_aesenclast_si128(b1, rk[rounds]);
    b2 = _mm_aesenclast_si128(b2, rk[rounds]);
    b3 = _mm_aesenclast_si128(b3, rk[rounds]);
}

/// 计数器块低 32 位大端 +n（仅 q <= 4；合法输入下不会进位到 nonce）
static inline __m128i ccm_ctr_inc_n(__m128i c, unsigned n) {
    uint32_t lo = bswap32_u((uint32_t)_mm_extract_epi32(c, 3));
    lo += n;
    return _mm_insert_epi32(c, (int)bswap32_u(lo), 3);
}

static inline __m128i ccm_mac_block(__m128i state, __m128i block,
                                    const __m128i* rk, int rounds) {
    return ccm_aes_enc1(_mm_xor_si128(state, block), rk, rounds);
}

static inline __m128i ccm_mac_data(__m128i state, const uint8_t* data, size_t len,
                                   const __m128i* rk, int rounds) {
    size_t pos = 0;
    while (pos + 16 <= len) {
        __m128i b = _mm_loadu_si128((const __m128i*)(data + pos));
        state = ccm_mac_block(state, b, rk, rounds);
        pos += 16;
    }
    if (pos < len) {
        uint8_t last[16] = {};
        std::memcpy(last, data + pos, len - pos);
        state = ccm_mac_block(state, _mm_loadu_si128((const __m128i*)last), rk, rounds);
    }
    return state;
}

// RFC 3610 搂2.2锛氶檮鍔犺閫佽瘉鏁版嵁 a 缂栫爜涓?[len(a)] || a锛屼笌闀垮害鍓嶇紑鍚屽潡鎷煎悗鎸?16 瀛楄妭琛ラ綈銆?
static inline __m128i ccm_mac_aad(__m128i state, const uint8_t* aad, size_t a_len,
                                  const __m128i* rk, int rounds) {
    uint8_t prefix[6];
    size_t plen;
    if (a_len < 0xFF00) {
        prefix[0] = (uint8_t)(a_len >> 8);
        prefix[1] = (uint8_t)(a_len & 0xFF);
        plen = 2;
    } else {
        prefix[0] = 0xFF; prefix[1] = 0xFE;
        prefix[2] = (uint8_t)(a_len >> 24);
        prefix[3] = (uint8_t)(a_len >> 16);
        prefix[4] = (uint8_t)(a_len >> 8);
        prefix[5] = (uint8_t)(a_len & 0xFF);
        plen = 6;
    }
    size_t first = (16 - plen < a_len) ? (16 - plen) : a_len;
    uint8_t block[16] = {};
    std::memcpy(block, prefix, plen);
    std::memcpy(block + plen, aad, first);
    state = ccm_mac_block(state, _mm_loadu_si128((const __m128i*)block), rk, rounds);
    size_t pos = first;
    while (pos + 16 <= a_len) {
        __m128i b = _mm_loadu_si128((const __m128i*)(aad + pos));
        state = ccm_mac_block(state, b, rk, rounds);
        pos += 16;
    }
    if (pos < a_len) {
        uint8_t last[16] = {};
        std::memcpy(last, aad + pos, a_len - pos);
        state = ccm_mac_block(state, _mm_loadu_si128((const __m128i*)last), rk, rounds);
    }
    return state;
}

#endif // __x86_64__ || _M_X64

/// 构造 AAD 长度前缀块（RFC 3610 §2.2），不足 16 字节补零
static void ccm_aad_prefix(uint8_t out[16], size_t a_len) {
    std::memset(out, 0, 16);
    if (a_len < 0xFF00) {
        out[0] = static_cast<uint8_t>((a_len >> 8) & 0xFF);
        out[1] = static_cast<uint8_t>(a_len & 0xFF);
    } else {
        out[0] = 0xFF;
        out[1] = 0xFE;
        out[2] = static_cast<uint8_t>((a_len >> 24) & 0xFF);
        out[3] = static_cast<uint8_t>((a_len >> 16) & 0xFF);
        out[4] = static_cast<uint8_t>((a_len >> 8) & 0xFF);
        out[5] = static_cast<uint8_t>(a_len & 0xFF);
    }
}

/// 构造 B0 与计数器块 0
static void ccm_build_b0(uint8_t B0[16], const uint8_t* nonce, size_t nonce_len,
                         size_t tag_len, bool has_aad, size_t q, size_t pt_len) {
    std::memset(B0, 0, 16);
    B0[0] = static_cast<uint8_t>(((tag_len - 2) / 2) << 3);
    if (has_aad) B0[0] |= 0x40;
    B0[0] |= static_cast<uint8_t>(q - 1);
    std::memcpy(B0 + 1, nonce, nonce_len);
    for (size_t i = 0; i < q; ++i) {
        B0[15 - i] = static_cast<uint8_t>(pt_len & 0xFF);
        pt_len >>= 8;
    }
}

/// 就地/直写加密核心：密文写入 out（容量 >= pt_len），允许 out == pt
static void aes_ccm_encrypt_impl(const aes_context& ctx,
                                 const uint8_t* nonce, size_t nonce_len,
                                 const uint8_t* pt, size_t pt_len,
                                 jpssl::span<const uint8_t> aad,
                                 uint8_t* out, uint8_t* tag, size_t tag_len) {
    size_t q = 15 - nonce_len;
    uint8_t B0[16], ctr0[16];
    ccm_build_b0(B0, nonce, nonce_len, tag_len, !aad.empty(), q, pt_len);
    ccm_build_b0(ctr0, nonce, nonce_len, tag_len, false, q, 0);
    ctr0[0] = static_cast<uint8_t>(q - 1);   // 计数器块：仅保留 L 标志

#if defined(__x86_64__) || defined(_M_X64)
    if (cpu_has_aesni()) {
        const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
        int rounds = ctx.rounds;

        __m128i mac_state = ccm_mac_block(_mm_setzero_si128(),
                                          _mm_loadu_si128((const __m128i*)B0),
                                          rk, rounds);
        if (!aad.empty()) {
            mac_state = ccm_mac_aad(mac_state, aad.data(), aad.size(), rk, rounds);
        }

        const bool fast_ctr = q <= 4;
        __m128i ctr = _mm_loadu_si128((const __m128i*)ctr0);
        size_t num_blocks = (pt_len + 15) / 16;
        size_t full4 = pt_len / 64;
        size_t i = 0;

        if (fast_ctr) {
            for (; i < full4 * 4; i += 4) {
                __m128i c0 = ccm_ctr_inc_n(ctr, 1);
                __m128i c1 = ccm_ctr_inc_n(ctr, 2);
                __m128i c2 = ccm_ctr_inc_n(ctr, 3);
                __m128i c3 = ccm_ctr_inc_n(ctr, 4);
                ctr = c3;
                __m128i ks0 = c0, ks1 = c1, ks2 = c2, ks3 = c3;
                ccm_aes_enc4(ks0, ks1, ks2, ks3, rk, rounds);

                const uint8_t* p = pt + i * 16;
                uint8_t* o = out + i * 16;

                __m128i p0 = _mm_loadu_si128((const __m128i*)(p));
                mac_state = ccm_mac_block(mac_state, p0, rk, rounds);
                _mm_storeu_si128((__m128i*)(o), _mm_xor_si128(p0, ks0));

                __m128i p1 = _mm_loadu_si128((const __m128i*)(p + 16));
                mac_state = ccm_mac_block(mac_state, p1, rk, rounds);
                _mm_storeu_si128((__m128i*)(o + 16), _mm_xor_si128(p1, ks1));

                __m128i p2 = _mm_loadu_si128((const __m128i*)(p + 32));
                mac_state = ccm_mac_block(mac_state, p2, rk, rounds);
                _mm_storeu_si128((__m128i*)(o + 32), _mm_xor_si128(p2, ks2));

                __m128i p3 = _mm_loadu_si128((const __m128i*)(p + 48));
                mac_state = ccm_mac_block(mac_state, p3, rk, rounds);
                _mm_storeu_si128((__m128i*)(o + 48), _mm_xor_si128(p3, ks3));
            }
        }

        for (; i < num_blocks; ++i) {
            if (fast_ctr) ctr = ccm_ctr_inc_n(ctr, 1);
            __m128i ks;
            if (fast_ctr) {
                ks = ccm_aes_enc1(ctr, rk, rounds);
            } else {
                uint8_t ctrb[16];
                _mm_storeu_si128((__m128i*)ctrb, ctr);
                for (int j = 15; j >= 16 - (int)q; --j) {
                    if (++ctrb[j] != 0) break;
                }
                ctr = _mm_loadu_si128((const __m128i*)ctrb);
                ks = ccm_aes_enc1(ctr, rk, rounds);
            }

            size_t offset = i * 16;
            size_t remain = pt_len - offset;
            if (remain >= 16) {
                __m128i p = _mm_loadu_si128((const __m128i*)(pt + offset));
                mac_state = ccm_mac_block(mac_state, p, rk, rounds);
                _mm_storeu_si128((__m128i*)(out + offset), _mm_xor_si128(p, ks));
            } else {
                uint8_t ks_buf[16], ct_buf[16] = {}, pt_buf[16] = {};
                _mm_storeu_si128((__m128i*)ks_buf, ks);
                std::memcpy(pt_buf, pt + offset, remain);
                for (size_t j = 0; j < remain; ++j)
                    ct_buf[j] = pt_buf[j] ^ ks_buf[j];
                std::memcpy(out + offset, ct_buf, remain);
                mac_state = ccm_mac_block(
                    mac_state, _mm_loadu_si128((const __m128i*)pt_buf), rk, rounds);
            }
        }

        __m128i ks0 = ccm_aes_enc1(_mm_loadu_si128((const __m128i*)ctr0), rk, rounds);
        uint8_t macb[16], ksb[16];
        _mm_storeu_si128((__m128i*)macb, mac_state);
        _mm_storeu_si128((__m128i*)ksb, ks0);
        for (size_t i = 0; i < tag_len; ++i)
            tag[i] = macb[i] ^ ksb[i];
        return;
    }
#endif

    // ── 软件回退 ──
    {
        uint8_t mac[16] = {};
        uint8_t block[16];
        std::memcpy(block, B0, 16);
        for (int j = 0; j < 16; ++j) mac[j] ^= block[j];
        aes_encrypt_block(ctx, mac, mac);

        if (!aad.empty()) {
            // RFC 3610：AAD = [len(a)] || a，拼接后按 16 字节补齐
            uint8_t prefix[6];
            size_t plen;
            if (aad.size() < 0xFF00) {
                prefix[0] = (uint8_t)(aad.size() >> 8);
                prefix[1] = (uint8_t)(aad.size() & 0xFF);
                plen = 2;
            } else {
                prefix[0] = 0xFF; prefix[1] = 0xFE;
                prefix[2] = (uint8_t)(aad.size() >> 24);
                prefix[3] = (uint8_t)(aad.size() >> 16);
                prefix[4] = (uint8_t)(aad.size() >> 8);
                prefix[5] = (uint8_t)(aad.size() & 0xFF);
                plen = 6;
            }
            size_t pos = 0;
            size_t total = plen + aad.size();
            while (pos + 16 <= total) {
                uint8_t block[16] = {};
                for (size_t k = 0; k < 16; ++k) {
                    size_t idx = pos + k;
                    block[k] = (idx < plen) ? prefix[idx] : aad[idx - plen];
                }
                for (int j = 0; j < 16; ++j) mac[j] ^= block[j];
                aes_encrypt_block(ctx, mac, mac);
                pos += 16;
            }
            if (pos < total) {
                uint8_t last[16] = {};
                for (size_t k = 0; k < total - pos; ++k) {
                    size_t idx = pos + k;
                    last[k] = (idx < plen) ? prefix[idx] : aad[idx - plen];
                }
                for (int j = 0; j < 16; ++j) mac[j] ^= last[j];
                aes_encrypt_block(ctx, mac, mac);
            }
        }

        size_t num_blocks = (pt_len + 15) / 16;
        uint8_t ctr[16];
        std::memcpy(ctr, ctr0, 16);
        std::vector<uint8_t> keystream((num_blocks + 1) * 16);
        for (size_t i = 0; i <= num_blocks; ++i) {
            if (i > 0) {
                for (int j = 15; j >= 16 - (int)q; --j) {
                    if (++ctr[j] != 0) break;
                }
            }
            aes_encrypt_block(ctx, ctr, keystream.data() + i * 16);
        }
        // 必须先基于明文计算 MAC：in-place 场景（out == pt）下，
        // 若先做 CTR XOR 会把明文覆盖为密文，导致 MAC 错误（仅标量路径有此问题，
        // AES-NI 路径先在寄存器中取明文再回写，不受影响）。
        size_t pos = 0;
        while (pos + 16 <= pt_len) {
            for (int j = 0; j < 16; ++j) mac[j] ^= pt[pos + j];
            aes_encrypt_block(ctx, mac, mac);
            pos += 16;
        }
        if (pos < pt_len) {
            uint8_t last[16] = {};
            std::memcpy(last, pt + pos, pt_len - pos);
            for (int j = 0; j < 16; ++j) mac[j] ^= last[j];
            aes_encrypt_block(ctx, mac, mac);
        }
        for (size_t i = 0; i < pt_len; ++i)
            out[i] = pt[i] ^ keystream[16 + i];
        for (size_t i = 0; i < tag_len; ++i)
            tag[i] = mac[i] ^ keystream[i];
    }
}

#endif // __x86_64__ || __aarch64__

// ──────────────────────────────────────────────────────────────────────────
//  公共 API（非零拷贝，vector 输出）
// ──────────────────────────────────────────────────────────────────────────

void aes_ccm_encrypt(const aes_context& ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     jpssl::span<const uint8_t> plaintext,
                     jpssl::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len) {
    size_t q = 15 - nonce_len;
    if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0)
        throw std::runtime_error("CCM: invalid tag length");
    if (nonce_len < 7 || nonce_len > 13)
        throw std::runtime_error("CCM: invalid nonce length");
    if (plaintext.size() >= (size_t{1} << (q * 8)))
        throw std::runtime_error("CCM: plaintext too large for given nonce length");

    ciphertext.resize(plaintext.size());
    aes_ccm_encrypt_impl(ctx, nonce, nonce_len, plaintext.data(), plaintext.size(),
                         aad, ciphertext.data(), tag, tag_len);
}

// ──────────────────────────────────────────────────────────────────────────
//  就地（zero-copy）接口：仅供 TLS 记录层使用（内部，不对外发布）
// ──────────────────────────────────────────────────────────────────────────

static bool aes_ccm_decrypt_impl(const aes_context& ctx,
                                 const uint8_t* nonce, size_t nonce_len,
                                 const uint8_t* ct, size_t ct_len,
                                 jpssl::span<const uint8_t> aad,
                                 const uint8_t* tag, size_t tag_len,
                                 uint8_t* out);

void aes_ccm_encrypt_inplace(const aes_context& ctx,
                             const uint8_t* nonce, size_t nonce_len,
                             uint8_t* buf, size_t data_len,
                             jpssl::span<const uint8_t> aad,
                             uint8_t* tag, size_t tag_len) {
    size_t q = 15 - nonce_len;
    if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0)
        throw std::runtime_error("CCM: invalid tag length");
    if (nonce_len < 7 || nonce_len > 13)
        throw std::runtime_error("CCM: invalid nonce length");
    if (data_len >= (size_t{1} << (q * 8)))
        throw std::runtime_error("CCM: plaintext too large for given nonce length");

    aes_ccm_encrypt_impl(ctx, nonce, nonce_len, buf, data_len, aad, buf, tag, tag_len);
}

bool aes_ccm_decrypt_inplace(const aes_context& ctx,
                             const uint8_t* nonce, size_t nonce_len,
                             uint8_t* buf, size_t data_len,
                             jpssl::span<const uint8_t> aad,
                             const uint8_t* tag, size_t tag_len) {
    size_t q = 15 - nonce_len;
    if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0) return false;
    if (nonce_len < 7 || nonce_len > 13) return false;
    if (data_len >= (size_t{1} << (q * 8))) return false;

    return aes_ccm_decrypt_impl(ctx, nonce, nonce_len, buf, data_len, aad, tag, tag_len,
                                buf);
}

// ──────────────────────────────────────────────────────────────────────────
//  解密核心 + 公共 API
// ──────────────────────────────────────────────────────────────────────────

/// 就地/直写解密核心：明文写入 out（容量 >= ct_len），允许 out == ct
static bool aes_ccm_decrypt_impl(const aes_context& ctx,
                                 const uint8_t* nonce, size_t nonce_len,
                                 const uint8_t* ct, size_t ct_len,
                                 jpssl::span<const uint8_t> aad,
                                 const uint8_t* tag, size_t tag_len,
                                 uint8_t* out) {
    size_t q = 15 - nonce_len;
    uint8_t B0[16], ctr0[16];
    ccm_build_b0(B0, nonce, nonce_len, tag_len, !aad.empty(), q, ct_len);
    ccm_build_b0(ctr0, nonce, nonce_len, tag_len, false, q, 0);
    ctr0[0] = static_cast<uint8_t>(q - 1);

#if defined(__x86_64__) || defined(_M_X64)
    if (cpu_has_aesni()) {
        const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
        int rounds = ctx.rounds;

        __m128i mac_state = ccm_mac_block(_mm_setzero_si128(),
                                          _mm_loadu_si128((const __m128i*)B0),
                                          rk, rounds);
        if (!aad.empty()) {
            mac_state = ccm_mac_aad(mac_state, aad.data(), aad.size(), rk, rounds);
        }

        // 先解密（直写 out）并同步累加 MAC
        const bool fast_ctr = q <= 4;
        __m128i ctr = _mm_loadu_si128((const __m128i*)ctr0);
        size_t num_blocks = (ct_len + 15) / 16;
        size_t full4 = ct_len / 64;
        size_t i = 0;

        if (fast_ctr) {
            for (; i < full4 * 4; i += 4) {
                __m128i c0 = ccm_ctr_inc_n(ctr, 1);
                __m128i c1 = ccm_ctr_inc_n(ctr, 2);
                __m128i c2 = ccm_ctr_inc_n(ctr, 3);
                __m128i c3 = ccm_ctr_inc_n(ctr, 4);
                ctr = c3;
                __m128i ks0 = c0, ks1 = c1, ks2 = c2, ks3 = c3;
                ccm_aes_enc4(ks0, ks1, ks2, ks3, rk, rounds);

                const uint8_t* c = ct + i * 16;
                uint8_t* o = out + i * 16;

                __m128i c0b = _mm_loadu_si128((const __m128i*)(c));
                __m128i p0 = _mm_xor_si128(c0b, ks0);
                mac_state = ccm_mac_block(mac_state, p0, rk, rounds);
                _mm_storeu_si128((__m128i*)(o), p0);

                __m128i c1b = _mm_loadu_si128((const __m128i*)(c + 16));
                __m128i p1 = _mm_xor_si128(c1b, ks1);
                mac_state = ccm_mac_block(mac_state, p1, rk, rounds);
                _mm_storeu_si128((__m128i*)(o + 16), p1);

                __m128i c2b = _mm_loadu_si128((const __m128i*)(c + 32));
                __m128i p2 = _mm_xor_si128(c2b, ks2);
                mac_state = ccm_mac_block(mac_state, p2, rk, rounds);
                _mm_storeu_si128((__m128i*)(o + 32), p2);

                __m128i c3b = _mm_loadu_si128((const __m128i*)(c + 48));
                __m128i p3 = _mm_xor_si128(c3b, ks3);
                mac_state = ccm_mac_block(mac_state, p3, rk, rounds);
                _mm_storeu_si128((__m128i*)(o + 48), p3);
            }
        }

        for (; i < num_blocks; ++i) {
            if (fast_ctr) ctr = ccm_ctr_inc_n(ctr, 1);
            __m128i ks;
            if (fast_ctr) {
                ks = ccm_aes_enc1(ctr, rk, rounds);
            } else {
                uint8_t ctrb[16];
                _mm_storeu_si128((__m128i*)ctrb, ctr);
                for (int j = 15; j >= 16 - (int)q; --j) {
                    if (++ctrb[j] != 0) break;
                }
                ctr = _mm_loadu_si128((const __m128i*)ctrb);
                ks = ccm_aes_enc1(ctr, rk, rounds);
            }

            size_t offset = i * 16;
            size_t remain = ct_len - offset;
            if (remain >= 16) {
                __m128i c = _mm_loadu_si128((const __m128i*)(ct + offset));
                __m128i p = _mm_xor_si128(c, ks);
                mac_state = ccm_mac_block(mac_state, p, rk, rounds);
                _mm_storeu_si128((__m128i*)(out + offset), p);
            } else {
                uint8_t ks_buf[16], ct_buf[16] = {}, pt_buf[16] = {};
                _mm_storeu_si128((__m128i*)ks_buf, ks);
                std::memcpy(ct_buf, ct + offset, remain);
                for (size_t j = 0; j < remain; ++j)
                    pt_buf[j] = ct_buf[j] ^ ks_buf[j];
                std::memcpy(out + offset, pt_buf, remain);
                mac_state = ccm_mac_block(
                    mac_state, _mm_loadu_si128((const __m128i*)pt_buf), rk, rounds);
            }
        }

        // 标签验证：expected = mac ^ E(counter 0)，常数时间比较
        uint8_t macb[16], ksb[16];
        _mm_storeu_si128((__m128i*)macb, mac_state);
        _mm_storeu_si128(
            (__m128i*)ksb,
            ccm_aes_enc1(_mm_loadu_si128((const __m128i*)ctr0), rk, rounds));
        uint8_t diff = 0;
        for (size_t i = 0; i < tag_len; ++i)
            diff |= tag[i] ^ (macb[i] ^ ksb[i]);
        return diff == 0;
    }
#endif

    // ── 软件回退 ──
    {
        size_t num_blocks = (ct_len + 15) / 16;
        uint8_t ctr[16];
        std::memcpy(ctr, ctr0, 16);
        std::vector<uint8_t> keystream((num_blocks + 1) * 16);
        for (size_t i = 0; i <= num_blocks; ++i) {
            if (i > 0) {
                for (int j = 15; j >= 16 - (int)q; --j) {
                    if (++ctr[j] != 0) break;
                }
            }
            aes_encrypt_block(ctx, ctr, keystream.data() + i * 16);
        }
        for (size_t i = 0; i < ct_len; ++i)
            out[i] = ct[i] ^ keystream[16 + i];

        uint8_t mac[16] = {};
        uint8_t block[16];
        std::memcpy(block, B0, 16);
        for (int j = 0; j < 16; ++j) mac[j] ^= block[j];
        aes_encrypt_block(ctx, mac, mac);

        if (!aad.empty()) {
            // RFC 3610：AAD = [len(a)] || a，拼接后按 16 字节补齐
            uint8_t prefix[6];
            size_t plen;
            if (aad.size() < 0xFF00) {
                prefix[0] = (uint8_t)(aad.size() >> 8);
                prefix[1] = (uint8_t)(aad.size() & 0xFF);
                plen = 2;
            } else {
                prefix[0] = 0xFF; prefix[1] = 0xFE;
                prefix[2] = (uint8_t)(aad.size() >> 24);
                prefix[3] = (uint8_t)(aad.size() >> 16);
                prefix[4] = (uint8_t)(aad.size() >> 8);
                prefix[5] = (uint8_t)(aad.size() & 0xFF);
                plen = 6;
            }
            size_t pos = 0;
            size_t total = plen + aad.size();
            while (pos + 16 <= total) {
                uint8_t block[16] = {};
                for (size_t k = 0; k < 16; ++k) {
                    size_t idx = pos + k;
                    block[k] = (idx < plen) ? prefix[idx] : aad[idx - plen];
                }
                for (int j = 0; j < 16; ++j) mac[j] ^= block[j];
                aes_encrypt_block(ctx, mac, mac);
                pos += 16;
            }
            if (pos < total) {
                uint8_t last[16] = {};
                for (size_t k = 0; k < total - pos; ++k) {
                    size_t idx = pos + k;
                    last[k] = (idx < plen) ? prefix[idx] : aad[idx - plen];
                }
                for (int j = 0; j < 16; ++j) mac[j] ^= last[j];
                aes_encrypt_block(ctx, mac, mac);
            }
        }
        size_t pos = 0;
        while (pos + 16 <= ct_len) {
            for (int j = 0; j < 16; ++j) mac[j] ^= out[pos + j];
            aes_encrypt_block(ctx, mac, mac);
            pos += 16;
        }
        if (pos < ct_len) {
            uint8_t last[16] = {};
            std::memcpy(last, out + pos, ct_len - pos);
            for (int j = 0; j < 16; ++j) mac[j] ^= last[j];
            aes_encrypt_block(ctx, mac, mac);
        }

        uint8_t keystream0[16];
        aes_encrypt_block(ctx, ctr0, keystream0);
        uint8_t diff = 0;
        for (size_t i = 0; i < tag_len; ++i)
            diff |= tag[i] ^ (mac[i] ^ keystream0[i]);
        return diff == 0;
    }
}

bool aes_ccm_decrypt(const aes_context& ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     jpssl::span<const uint8_t> ciphertext,
                     jpssl::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext) {
    size_t q = 15 - nonce_len;
    if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0) return false;
    if (nonce_len < 7 || nonce_len > 13) return false;
    if (ciphertext.size() >= (size_t{1} << (q * 8))) return false;

    plaintext.resize(ciphertext.size());
    return aes_ccm_decrypt_impl(ctx, nonce, nonce_len, ciphertext.data(),
                                ciphertext.size(), aad, tag, tag_len,
                                plaintext.data());
}

} // namespace jpssl
