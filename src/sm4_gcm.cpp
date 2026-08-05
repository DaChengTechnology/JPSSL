/** sm4_gcm.cpp - SM4-GCM AEAD mode
 *
 *  Reuses the generic GF(2^128) `ghash` as a software fallback;
 *  when PCLMULQDQ is available, GHASH runs incrementally with a
 *  fast CLMUL implementation instead of materializing the padded
 *  input buffer.  NIST SP 800-38D.
 */
#include "sm4_gcm.hpp"
#include "cipher_inplace.hpp"   // 内部：零拷贝 AEAD 声明（TLS 记录层专用）
#include "aes.hpp"        // gf128_mul, ghash (GF(2^128) software fallback)
#include "cpu_features.hpp"
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

namespace jpssl {

// ------------------------------------------------------------------------
//  CTR mode helper
// ------------------------------------------------------------------------

/// SM4 CTR: encrypt (or decrypt) a stream block by block.
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

        // Increment counter (big-endian, starting from the low byte).
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
    }
}

/// Build J0 from IV (GCM initial counter block).
/// IV length == 12: J0 = IV || 0^31 || 1.
/// Otherwise: J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64),
/// where s = 128*ceil(len(IV)/128) - len(IV) in bits (NIST SP 800-38D 7.1).
static void sm4_gcm_make_j0(const uint8_t H[16],
                            const uint8_t* iv, size_t iv_len,
                            uint8_t j0[16]) {
    if (iv_len == 12) {
        std::memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        std::memset(j0, 0, 16);
        // Build input: IV || 0^(s+64) || [len(IV)]_64
        std::vector<uint8_t> gh_input;
        gh_input.insert(gh_input.end(), iv, iv + iv_len);
        const size_t iv_bits = iv_len * 8;
        const size_t s = 128 * ((iv_bits + 127) / 128) - iv_bits;
        gh_input.insert(gh_input.end(), (s + 64) / 8, 0);
        // Append 64-bit IV length in bits (big-endian)
        const uint64_t iv_bits64 = iv_bits;
        for (int i = 7; i >= 0; --i)
            gh_input.push_back((uint8_t)(iv_bits64 >> (i * 8)));

        ghash(H, std::span<const uint8_t>(gh_input), j0);
    }
}

// ------------------------------------------------------------------------
//  Fast GHASH (PCLMULQDQ)
// ------------------------------------------------------------------------

#if defined(__x86_64__) || defined(_M_X64)

/// Bit reversal inside each byte.
/// Maps the NIST/GCM byte convention (byte 0 bit 7 = x^0) into the natural
/// CLMUL domain (bit 0 = x^0), where the reduction constant is 0x87.
static inline __m128i sm4_gcm_bitrev(__m128i x) {
    // Bit-reverse each nibble (index -> bit-reversed 4-bit value).
    const __m128i rev_nib = _mm_set_epi8(
        0x0F, 0x07, 0x0B, 0x03, 0x0D, 0x05, 0x09, 0x01,
        0x0E, 0x06, 0x0A, 0x02, 0x0C, 0x04, 0x08, 0x00);
    __m128i lo = _mm_and_si128(x, _mm_set1_epi8(0x0F));
    __m128i hi = _mm_and_si128(_mm_srli_epi16(x, 4), _mm_set1_epi8(0x0F));
    __m128i rlo = _mm_shuffle_epi8(rev_nib, lo);
    __m128i rhi = _mm_shuffle_epi8(rev_nib, hi);
    return _mm_or_si128(_mm_slli_epi16(rlo, 4), rhi);
}

/// Bit-reflected GF(2^128) multiply (GCM convention).
/// Operates in the full-reversed domain: raw CLMUL product followed by the
/// three-fold reduction with R = 0x87 (x^128 -> x^7 + x^2 + x + 1).
static inline __m128i sm4_gcm_gf128_mul(__m128i x, __m128i y) {
    __m128i p00 = _mm_clmulepi64_si128(x, y, 0x00); // x0*y0
    __m128i p11 = _mm_clmulepi64_si128(x, y, 0x11); // x1*y1
    __m128i p10 = _mm_clmulepi64_si128(x, y, 0x10); // x1*y0
    __m128i p01 = _mm_clmulepi64_si128(x, y, 0x01); // x0*y1

    // Compose the 256-bit product: PL = p00 ^ (mid_lo << 64),
    // PH = p11 ^ mid_hi, where mid = p10 ^ p01.
    __m128i mid = _mm_xor_si128(p10, p01);
    __m128i pl = _mm_xor_si128(p00, _mm_slli_si128(mid, 8));
    __m128i ph = _mm_xor_si128(p11, _mm_srli_si128(mid, 8));

    // Three-fold reduction with R = 0x87.
    __m128i r = _mm_set_epi64x(0, 0x87);
    __m128i f1 = _mm_clmulepi64_si128(ph, r, 0x00);          // PH_low * R
    __m128i ph_hi = _mm_srli_si128(ph, 8);
    __m128i f2 = _mm_clmulepi64_si128(ph_hi, r, 0x00);       // PH_high * R
    __m128i res = _mm_xor_si128(pl, f1);
    res = _mm_xor_si128(res, _mm_slli_si128(f2, 8));         // f2 << 64
    __m128i ov = _mm_srli_si128(f2, 8);                      // f2 >> 64
    res = _mm_xor_si128(res, _mm_clmulepi64_si128(ov, r, 0x00));
    return res;
}

/// Incremental GHASH: state = (state XOR block) * H,
/// zero-padding a partial final block (GCM padding semantics).
static inline void sm4_gcm_ghash_feed(__m128i& state, __m128i H,
                                      const uint8_t* data, size_t len) {
    size_t pos = 0;
    for (; pos + 16 <= len; pos += 16) {
        __m128i blk = sm4_gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos)));
        state = sm4_gcm_gf128_mul(_mm_xor_si128(state, blk), H);
    }
    if (pos < len) {
        uint8_t last[16] = {};
        std::memcpy(last, data + pos, len - pos);
        __m128i blk = sm4_gcm_bitrev(_mm_loadu_si128((const __m128i*)last));
        state = sm4_gcm_gf128_mul(_mm_xor_si128(state, blk), H);
    }
}

#endif // __x86_64__ || _M_X64

static bool g_sm4_gcm_pclmul_checked = false;
static bool g_sm4_gcm_pclmul_ok = false;

static void sm4_gcm_detect_pclmul() {
    if (g_sm4_gcm_pclmul_checked) return;
    g_sm4_gcm_pclmul_checked = true;
    g_sm4_gcm_pclmul_ok = cpu_has_pclmulqdq();
}

/// GHASH(AAD, C)
/// Input = AAD || 0-pad || C || 0-pad || len(A)_64 || len(C)_64.
static void sm4_gcm_ghash(const uint8_t H[16],
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* ct, size_t ct_len,
                          uint8_t out[16]) {
    sm4_gcm_detect_pclmul();
    const uint64_t aad_bits = (uint64_t)aad_len * 8;
    const uint64_t ct_bits  = (uint64_t)ct_len * 8;

#if defined(__x86_64__) || defined(_M_X64)
    if (g_sm4_gcm_pclmul_ok) {
        __m128i Hv = sm4_gcm_bitrev(_mm_loadu_si128((const __m128i*)H));
        __m128i state = _mm_setzero_si128();
        sm4_gcm_ghash_feed(state, Hv, aad, aad_len);
        sm4_gcm_ghash_feed(state, Hv, ct, ct_len);

        uint8_t len_block[16] = {};
        for (int i = 0; i < 8; ++i) {
            len_block[i]     = (uint8_t)(aad_bits >> (56 - i * 8));
            len_block[8 + i] = (uint8_t)(ct_bits  >> (56 - i * 8));
        }
        __m128i blk = sm4_gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block));
        state = sm4_gcm_gf128_mul(_mm_xor_si128(state, blk), Hv);
        _mm_storeu_si128((__m128i*)out, sm4_gcm_bitrev(state));
        return;
    }
#endif

    // Software fallback: build the padded input for the generic ghash.
    std::vector<uint8_t> gh_input;
    if (aad_len) gh_input.insert(gh_input.end(), aad, aad + aad_len);
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    gh_input.insert(gh_input.end(), aad_pad, 0);
    if (ct_len) gh_input.insert(gh_input.end(), ct, ct + ct_len);
    size_t ct_pad = (16 - (ct_len % 16)) % 16;
    gh_input.insert(gh_input.end(), ct_pad, 0);
    for (int i = 7; i >= 0; --i)
        gh_input.push_back((uint8_t)(aad_bits >> (i * 8)));
    for (int i = 7; i >= 0; --i)
        gh_input.push_back((uint8_t)(ct_bits >> (i * 8)));
    ghash(H, std::span<const uint8_t>(gh_input), out);
}

// ------------------------------------------------------------------------
//  Public API
// ------------------------------------------------------------------------

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
    //    CTR starts from inc32(J0) for the 12-byte IV case.
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

    ciphertext.resize(plaintext.size());
    sm4_ctr_xor(ctx, ctr, plaintext.data(), ciphertext.data(), plaintext.size());

    // 4. GHASH: AAD || pad || C || pad || len(A)_64 || len(C)_64
    uint8_t gh_result[16];
    sm4_gcm_ghash(H, aad.data(), aad.size(),
                  ciphertext.data(), ciphertext.size(), gh_result);

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

    // 3. Verify tag first (GHASH over AAD + ciphertext + lengths)
    uint8_t gh_result[16];
    sm4_gcm_ghash(H, aad.data(), aad.size(),
                  ciphertext.data(), ciphertext.size(), gh_result);

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

// ──────────────────────────────────────────────────────────────────────────
//  就地（zero-copy）接口：仅供 TLS 记录层使用（内部，不对外发布）
// ──────────────────────────────────────────────────────────────────────────

void sm4_gcm_encrypt_inplace(const sm4_ctx* ctx,
                             const uint8_t* iv, size_t iv_len,
                             uint8_t* buf, size_t data_len,
                             std::span<const uint8_t> aad,
                             uint8_t* tag, size_t tag_len) {
    uint8_t zero[16] = {};
    uint8_t H[16];
    sm4_encrypt_block(ctx, zero, H);

    uint8_t j0[16];
    sm4_gcm_make_j0(H, iv, iv_len, j0);

    // CTR 就地加密（sm4_ctr_xor 逐字节读 input 写 output，同缓冲安全）
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
    sm4_ctr_xor(ctx, ctr, buf, buf, data_len);

    // GHASH：AAD || pad || C || pad || len(A)_64 || len(C)_64
    uint8_t gh_result[16];
    sm4_gcm_ghash(H, aad.data(), aad.size(), buf, data_len, gh_result);

    uint8_t enc_j0[16];
    sm4_encrypt_block(ctx, j0, enc_j0);
    for (size_t i = 0; i < tag_len; ++i)
        tag[i] = gh_result[i] ^ enc_j0[i];
}

bool sm4_gcm_decrypt_inplace(const sm4_ctx* ctx,
                             const uint8_t* iv, size_t iv_len,
                             uint8_t* buf, size_t data_len,
                             std::span<const uint8_t> aad,
                             const uint8_t* tag, size_t tag_len) {
    uint8_t zero[16] = {};
    uint8_t H[16];
    sm4_encrypt_block(ctx, zero, H);

    uint8_t j0[16];
    sm4_gcm_make_j0(H, iv, iv_len, j0);

    // 先验签（GHASH 覆盖 AAD + 密文 + 长度）
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

    // 就地解密
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
    sm4_ctr_xor(ctx, ctr, buf, buf, data_len);
    return true;
}

} // namespace jpssl
