/**
 * sha1_avx512.cpp -- SHA-1 AVX-512 acceleration (16-way multi-buffer).
 *
 * Mirror of the AVX2 kernel with 16 lanes: every ZMM lane holds one
 * message, so the whole schedule + round loop is lane-wise vectorized.
 *
 * Compile with -mavx512f -mavx512bw (GCC/Clang) or /arch:AVX512 (MSVC).
 */
#include "sha1.hpp"

#include <cstdint>
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

namespace jpssl {
namespace {

#if defined(__x86_64__) || defined(_M_X64)

inline __m512i rol_epi32(__m512i x, int n) {
    return _mm512_or_si512(_mm512_slli_epi32(x, n), _mm512_srli_epi32(x, 32 - n));
}

inline uint32_t be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

inline void store_be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

uint32_t sha1_k(int t) {
    if (t < 20) return 0x5A827999;
    if (t < 40) return 0x6ED9EBA1;
    if (t < 60) return 0x8F1BBCDC;
    return 0xCA62C1D6;
}

/// One compression step over 16 blocks: h[m] += f(block m).
void sha1_block16_avx512(uint32_t h[16][5], const uint8_t* const blk[16]) {
    __m512i W[80];
    for (int j = 0; j < 16; ++j) {
        alignas(64) uint32_t w[16];
        for (int m = 0; m < 16; ++m) w[m] = be32(blk[m] + 4 * j);
        W[j] = _mm512_load_si512((const void*)w);
    }
    for (int j = 16; j < 80; ++j) {
        __m512i x = _mm512_xor_si512(W[j - 3], W[j - 8]);
        x = _mm512_xor_si512(x, W[j - 14]);
        x = _mm512_xor_si512(x, W[j - 16]);
        W[j] = rol_epi32(x, 1);
    }

    __m512i a, b, c, d, e;
    {
        alignas(64) uint32_t v[16];
        for (int i = 0; i < 5; ++i) {
            for (int m = 0; m < 16; ++m) v[m] = h[m][i];
            const __m512i s = _mm512_load_si512((const void*)v);
            switch (i) {
            case 0: a = s; break;
            case 1: b = s; break;
            case 2: c = s; break;
            case 3: d = s; break;
            default: e = s; break;
            }
        }
    }
    const __m512i A0 = a, B0 = b, C0 = c, D0 = d, E0 = e;

    for (int t = 0; t < 80; ++t) {
        __m512i f;
        if (t < 20) {
            f = _mm512_xor_si512(d, _mm512_and_si512(b, _mm512_xor_si512(c, d)));
        } else if (t < 40) {
            f = _mm512_xor_si512(_mm512_xor_si512(b, c), d);
        } else if (t < 60) {
            f = _mm512_xor_si512(
                _mm512_xor_si512(_mm512_and_si512(b, c), _mm512_and_si512(b, d)),
                _mm512_and_si512(c, d));
        } else {
            f = _mm512_xor_si512(_mm512_xor_si512(b, c), d);
        }
        const __m512i k = _mm512_set1_epi32((int)sha1_k(t));
        __m512i tmp = _mm512_add_epi32(rol_epi32(a, 5), f);
        tmp = _mm512_add_epi32(tmp, e);
        tmp = _mm512_add_epi32(tmp, k);
        tmp = _mm512_add_epi32(tmp, W[t]);
        e = d; d = c; c = rol_epi32(b, 30); b = a; a = tmp;
    }

    a = _mm512_add_epi32(a, A0);
    b = _mm512_add_epi32(b, B0);
    c = _mm512_add_epi32(c, C0);
    d = _mm512_add_epi32(d, D0);
    e = _mm512_add_epi32(e, E0);

    alignas(64) uint32_t v[16];
    const __m512i s[5] = {a, b, c, d, e};
    for (int i = 0; i < 5; ++i) {
        _mm512_store_si512((void*)v, s[i]);
        for (int m = 0; m < 16; ++m) h[m][i] = v[m];
    }
}

#endif // x86-64

void sha1_pad_block(uint8_t* blk, const uint8_t* msg, size_t off, size_t r, uint64_t bits) {
    if (r) std::memcpy(blk, msg + off, r);
    blk[r] = 0x80;
    if (r < 56) {
        std::memset(blk + r + 1, 0, 55 - r);
        for (int i = 0; i < 8; ++i) blk[56 + i] = (uint8_t)(bits >> (56 - i * 8));
    } else {
        std::memset(blk + r + 1, 0, 63 - r);
        std::memset(blk + 64, 0, 56);
        for (int i = 0; i < 8; ++i) blk[120 + i] = (uint8_t)(bits >> (56 - i * 8));
    }
}

} // namespace

void sha1_multi_avx512(const uint8_t* const msgs[16], size_t len, uint8_t out[16][20]) {
#if defined(__x86_64__) || defined(_M_X64)
    uint32_t h[16][5];
    for (int m = 0; m < 16; ++m) {
        h[m][0] = 0x67452301;
        h[m][1] = 0xEFCDAB89;
        h[m][2] = 0x98BADCFE;
        h[m][3] = 0x10325476;
        h[m][4] = 0xC3D2E1F0;
    }

    size_t off = 0;
    while (off + 64 <= len) {
        const uint8_t* blk[16];
        for (int m = 0; m < 16; ++m) blk[m] = msgs[m] + off;
        sha1_block16_avx512(h, blk);
        off += 64;
    }

    const size_t r = len - off;
    const uint64_t bits = (uint64_t)len * 8;
    uint8_t tail[16][128];
    for (int m = 0; m < 16; ++m) sha1_pad_block(tail[m], msgs[m], off, r, bits);

    {
        const uint8_t* blk[16];
        for (int m = 0; m < 16; ++m) blk[m] = tail[m];
        sha1_block16_avx512(h, blk);
    }
    if (r >= 56) {
        const uint8_t* blk[16];
        for (int m = 0; m < 16; ++m) blk[m] = tail[m] + 64;
        sha1_block16_avx512(h, blk);
    }

    for (int m = 0; m < 16; ++m)
        for (int i = 0; i < 5; ++i) store_be(out[m] + 4 * i, h[m][i]);
#else
    // Portable fallback: hash each message with the scalar path.
    for (int m = 0; m < 16; ++m) {
        uint8_t d[20];
        sha1(msgs[m], len, d);
        std::memcpy(out[m], d, 20);
    }
#endif
}

} // namespace jpssl
