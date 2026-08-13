/**
 * sm4_gfni.cpp - GFNI accelerated SM4 block cipher / CTR keystream.
 *
 * The SM4 S-Box is evaluated with two GF(2^8) affine instructions
 * (VGF2P8AFFINEQB + VGF2P8AFFINEINVQB), replacing the lookup table with
 * fully constant-time SIMD logic:
 *
 *     S(x) = A2 * inv(A1 * x + C1) + C2
 *
 * GFNI field inversion is defined over the AES polynomial
 * x^8+x^4+x^3+x+1, while SM4 uses x^8+x^7+x^6+x^5+x^4+x^2+1; the two
 * affine layers convert between the representations and fold in the SM4
 * affine transforms. Constants from the SMGo project (BSD-3-Clause,
 * ePrint 2022/1154). Verified against the SM4 S-Box table on-device.
 *
 * Processes 8 x 128-bit blocks in parallel with 256-bit YMM registers;
 * the L transform uses the same SIMD rotations as the AVX2 backend.
 * Routed at runtime by sm4_gcm_dispatch.cpp via cpu_has_gfni().
 */
#include "sm4.hpp"
#include "cpu_features.hpp"
#include <cstring>

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
#include <immintrin.h>
#endif

namespace jpssl {
namespace {

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)

// Pre- and post-inversion affine matrices + constants (SMGo / ePrint 2022/1154).
static const __m256i GFNI_PRE_MATRIX =
    _mm256_set1_epi64x((long long)0x4c287db91a22505dULL);
static const __m256i GFNI_POST_MATRIX =
    _mm256_set1_epi64x((long long)0xf3ab34a974a6b589ULL);
static const int GFNI_PRE_CONST  = 0x3e;
static const int GFNI_POST_CONST = 0xd3;

// SM4 tau: S-box applied to every byte of the 256-bit vector.
static inline __m256i gfni_sm4_tau(__m256i x) {
    x = _mm256_gf2p8affine_epi64_epi8(x, GFNI_PRE_MATRIX, GFNI_PRE_CONST);
    x = _mm256_gf2p8affineinv_epi64_epi8(x, GFNI_POST_MATRIX, GFNI_POST_CONST);
    return x;
}

// L transform: L(B) = B ^ (B<<<2) ^ (B<<<10) ^ (B<<<18) ^ (B<<<24)
static inline __m256i gfni_sm4_L(__m256i b) {
    auto rot = [](__m256i x, int n) -> __m256i {
        return _mm256_or_si256(_mm256_slli_epi32(x, n),
                               _mm256_srli_epi32(x, 32 - n));
    };
    __m256i t = _mm256_xor_si256(b, rot(b, 2));
    t = _mm256_xor_si256(t, rot(b, 10));
    t = _mm256_xor_si256(t, rot(b, 18));
    return _mm256_xor_si256(t, rot(b, 24));
}

// Round function F on 8 blocks; rk is broadcast to all 8 lanes.
static inline __m256i gfni_sm4_F(__m256i x0, __m256i x1, __m256i x2,
                                 __m256i x3, __m256i rk) {
    __m256i t = _mm256_xor_si256(x1, x2);
    t = _mm256_xor_si256(t, x3);
    t = _mm256_xor_si256(t, rk);
    t = gfni_sm4_tau(t);
    t = gfni_sm4_L(t);
    return _mm256_xor_si256(x0, t);
}

/// Encrypt 8 blocks (16 bytes each) in parallel.
static void sm4_encrypt_8blocks_gfni(const uint32_t rk[32],
                                     const uint8_t* plain,
                                     uint8_t* cipher) {
    alignas(32) uint32_t buf[32]; // 8 blocks * 4 words
    for (int blk = 0; blk < 8; ++blk) {
        const uint8_t* p = plain + blk * 16;
        buf[blk]      = ((uint32_t)p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
        buf[blk + 8]  = ((uint32_t)p[4]<<24)|(p[5]<<16)|(p[6]<<8)|p[7];
        buf[blk + 16] = ((uint32_t)p[8]<<24)|(p[9]<<16)|(p[10]<<8)|p[11];
        buf[blk + 24] = ((uint32_t)p[12]<<24)|(p[13]<<16)|(p[14]<<8)|p[15];
    }
    __m256i x0 = _mm256_load_si256((const __m256i*)(buf));
    __m256i x1 = _mm256_load_si256((const __m256i*)(buf + 8));
    __m256i x2 = _mm256_load_si256((const __m256i*)(buf + 16));
    __m256i x3 = _mm256_load_si256((const __m256i*)(buf + 24));

    for (int r = 0; r < 32; ++r) {
        __m256i rkv = _mm256_set1_epi32((int)rk[r]);
        __m256i x4 = gfni_sm4_F(x0, x1, x2, x3, rkv);
        x0 = x1; x1 = x2; x2 = x3; x3 = x4;
    }

    // Output in reverse order: X35, X34, X33, X32
    _mm256_store_si256((__m256i*)(buf),      x3);
    _mm256_store_si256((__m256i*)(buf + 8),  x2);
    _mm256_store_si256((__m256i*)(buf + 16), x1);
    _mm256_store_si256((__m256i*)(buf + 24), x0);

    for (int blk = 0; blk < 8; ++blk) {
        uint8_t* c = cipher + blk * 16;
        uint32_t w0 = buf[blk], w1 = buf[blk+8], w2 = buf[blk+16], w3 = buf[blk+24];
        c[0]=w0>>24;c[1]=w0>>16;c[2]=w0>>8;c[3]=w0;
        c[4]=w1>>24;c[5]=w1>>16;c[6]=w1>>8;c[7]=w1;
        c[8]=w2>>24;c[9]=w2>>16;c[10]=w2>>8;c[11]=w2;
        c[12]=w3>>24;c[13]=w3>>16;c[14]=w3>>8;c[15]=w3;
    }
}

#endif // (__x86_64__ || _M_X64) && JP_GFNI

} // anonymous namespace

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)

/// Scalar CTR tail: byte-by-byte XOR with SM4 keystream, big-endian inc32.
static void sm4_ctr_xor_scalar(const sm4_ctx* ctx, const uint8_t ctr[16],
                               const uint8_t* input, uint8_t* output, size_t len) {
    uint8_t counter[16];
    std::memcpy(counter, ctr, 16);
    size_t pos = 0;
    while (pos < len) {
        uint8_t keystream[16];
        sm4_encrypt_block(ctx, counter, keystream);
        size_t n = (len - pos < 16) ? (len - pos) : 16;
        for (size_t i = 0; i < n; ++i)
            output[pos + i] = input[pos + i] ^ keystream[i];
        pos += n;
        // Increment counter (big-endian, low 32 bits - GCM inc32).
        for (int i = 15; i >= 12; --i) {
            if (++counter[i] != 0) break;
        }
    }
}

/// GFNI 8-way parallel SM4-CTR. `input` and `output` may alias (in-place).
void sm4_ctr_gfni(const sm4_ctx* ctx,
                  const uint8_t* ctr_block,
                  const uint8_t* input, uint8_t* output, size_t len) {
    uint8_t counters[128]; // 8 blocks * 16 bytes
    uint8_t keystream[128];

    // Initialize 8 consecutive counter values.
    uint8_t base_ctr[16];
    std::memcpy(base_ctr, ctr_block, 16);
    for (int i = 0; i < 8; ++i) {
        std::memcpy(counters + i * 16, base_ctr, 16);
        // Add i to the 32-bit counter part (big-endian).
        uint32_t carry = (uint32_t)i;
        for (int j = 15; j >= 12 && carry; --j) {
            uint32_t v = counters[i*16 + j] + carry;
            counters[i*16 + j] = (uint8_t)v;
            carry = v >> 8;
        }
    }

    size_t pos = 0;
    while (pos + 128 <= len) {
        sm4_encrypt_8blocks_gfni(ctx->rk, counters, keystream);
        for (int i = 0; i < 128; ++i)
            output[pos + i] = input[pos + i] ^ keystream[i];
        pos += 128;
        // Advance each of the 8 counters by 8 (big-endian inc32 per block).
        for (int blk = 0; blk < 8; ++blk) {
            uint32_t carry = 8;
            for (int j = 15; j >= 12 && carry; --j) {
                uint32_t v = counters[blk * 16 + j] + carry;
                counters[blk * 16 + j] = (uint8_t)v;
                carry = v >> 8;
            }
        }
    }

    // Remaining: fall back to scalar using the already-advanced counter state.
    if (pos < len) {
        sm4_ctr_xor_scalar(ctx, counters, input + pos, output + pos, len - pos);
    }
}

#endif // (__x86_64__ || _M_X64) && JP_GFNI

} // namespace jpssl
