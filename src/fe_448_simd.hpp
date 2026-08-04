#pragma once
/**
 * fe_448_simd.hpp - N-way SIMD field arithmetic for GF(2^448 - 2^224 - 1)
 *
 * AVX2:  4 lanes (__m256i, 4 x 64-bit)
 * AVX512: 8 lanes (__m512i, 8 x 64-bit)
 *
 * Radix: 2^28, 16 limbs (16*28 = 448 exactly).  Lane-sliced layout:
 * feN.limb[i] holds limb i of all N independent elements, one per lane.
 *
 * Why 28-bit limbs: a product of two limbs is 28x28 -> 56 bits, produced by
 * a single vpmuludq (no 32-bit splitting needed), and a column of the 16x16
 * schoolbook product sums at most 16 such values -> < 2^62, so the whole
 * accumulation fits in plain 64-bit lanes with no carry chains.  The modulus
 * p = 2^448 - 2^224 - 1 folds as 2^448 == 2^224 + 1, i.e. an overflow out of
 * limb 15 lands in limbs 0 and 8.
 */
#include <immintrin.h>
#include <cstdint>
#include <cstring>

namespace jpssl {
namespace fe448_simd {

#if defined(__AVX512F__)
#define JF448_LANES 8
typedef __m512i jf448_v;
typedef __mmask8 jf448_m;

static inline jf448_v jf448_set1(uint64_t x) { return _mm512_set1_epi64((long long)x); }
static inline jf448_v jf448_zero() { return _mm512_setzero_si512(); }
static inline jf448_v jf448_add(jf448_v a, jf448_v b) { return _mm512_add_epi64(a, b); }
static inline jf448_v jf448_sub(jf448_v a, jf448_v b) { return _mm512_sub_epi64(a, b); }
static inline jf448_v jf448_and(jf448_v a, jf448_v b) { return _mm512_and_si512(a, b); }
static inline jf448_v jf448_or(jf448_v a, jf448_v b) { return _mm512_or_si512(a, b); }
static inline jf448_v jf448_xor(jf448_v a, jf448_v b) { return _mm512_xor_si512(a, b); }
static inline jf448_v jf448_slli(jf448_v a, int n) { return _mm512_slli_epi64(a, n); }
static inline jf448_v jf448_srli(jf448_v a, int n) { return _mm512_srli_epi64(a, n); }
static inline jf448_v jf448_mul_epu32(jf448_v a, jf448_v b) { return _mm512_mul_epu32(a, b); }
static inline jf448_m jf448_cmplt_u64(jf448_v a, jf448_v b) {
    return _mm512_cmp_epu64_mask(a, b, _MM_CMPINT_LT);
}
static inline jf448_m jf448_cmpgt_u64(jf448_v a, jf448_v b) {
    return _mm512_cmp_epu64_mask(a, b, _MM_CMPINT_GT);
}
static inline jf448_m jf448_cmpeq_u64(jf448_v a, jf448_v b) {
    return _mm512_cmp_epu64_mask(a, b, _MM_CMPINT_EQ);
}
static inline jf448_v jf448_frommask(jf448_m m) { return _mm512_maskz_set1_epi64(m, -1LL); }
static inline jf448_v jf448_blend(jf448_v a, jf448_v b, jf448_m m) {
    return _mm512_mask_blend_epi64(m, a, b);
}
static inline jf448_v jf448_set64(uint64_t e7, uint64_t e6, uint64_t e5, uint64_t e4,
                                  uint64_t e3, uint64_t e2, uint64_t e1, uint64_t e0) {
    return _mm512_set_epi64((long long)e7, (long long)e6, (long long)e5, (long long)e4,
                            (long long)e3, (long long)e2, (long long)e1, (long long)e0);
}
static inline void jf448_store64(uint64_t out[8], jf448_v v) {
    _mm512_storeu_si512((__m512i*)out, v);
}

#elif defined(__AVX2__)
#define JF448_LANES 4
typedef __m256i jf448_v;
typedef __m256i jf448_m;

static inline jf448_v jf448_set1(uint64_t x) { return _mm256_set1_epi64x((long long)x); }
static inline jf448_v jf448_zero() { return _mm256_setzero_si256(); }
static inline jf448_v jf448_add(jf448_v a, jf448_v b) { return _mm256_add_epi64(a, b); }
static inline jf448_v jf448_sub(jf448_v a, jf448_v b) { return _mm256_sub_epi64(a, b); }
static inline jf448_v jf448_and(jf448_v a, jf448_v b) { return _mm256_and_si256(a, b); }
static inline jf448_v jf448_or(jf448_v a, jf448_v b) { return _mm256_or_si256(a, b); }
static inline jf448_v jf448_xor(jf448_v a, jf448_v b) { return _mm256_xor_si256(a, b); }
static inline jf448_v jf448_slli(jf448_v a, int n) { return _mm256_slli_epi64(a, n); }
static inline jf448_v jf448_srli(jf448_v a, int n) { return _mm256_srli_epi64(a, n); }
static inline jf448_v jf448_mul_epu32(jf448_v a, jf448_v b) { return _mm256_mul_epu32(a, b); }
static inline jf448_m jf448_cmplt_u64(jf448_v a, jf448_v b) {
    const jf448_v SGN = jf448_set1(0x8000000000000000ULL);
    return _mm256_cmpgt_epi64(jf448_xor(b, SGN), jf448_xor(a, SGN));
}
static inline jf448_m jf448_cmpgt_u64(jf448_v a, jf448_v b) {
    const jf448_v SGN = jf448_set1(0x8000000000000000ULL);
    return _mm256_cmpgt_epi64(jf448_xor(a, SGN), jf448_xor(b, SGN));
}
static inline jf448_m jf448_cmpeq_u64(jf448_v a, jf448_v b) {
    return _mm256_cmpeq_epi64(a, b);
}
static inline jf448_v jf448_frommask(jf448_m m) { return m; }
static inline jf448_v jf448_blend(jf448_v a, jf448_v b, jf448_m m) {
    return _mm256_blendv_epi8(a, b, m);
}
static inline jf448_v jf448_set64(uint64_t e3, uint64_t e2, uint64_t e1, uint64_t e0) {
    return _mm256_set_epi64x((long long)e3, (long long)e2, (long long)e1, (long long)e0);
}
static inline void jf448_store64(uint64_t out[4], jf448_v v) {
    _mm256_storeu_si256((__m256i*)out, v);
}

#else
#error "fe_448_simd.hpp requires __AVX2__ or __AVX512F__"
#endif

// These are functions, not namespace-scope constants: a static const
// __m512i would need a dynamic initializer running before main() that
// executes AVX2/AVX512 instructions on every process linking the library.
static inline jf448_v jf448_mask28() { return jf448_set1(((uint64_t)1 << 28) - 1); }
static inline jf448_v jf448_mask32() { return jf448_set1(0xFFFFFFFFULL); }
static inline jf448_v jf448_one() { return jf448_set1(1); }

static inline jf448_v jf448_frommask01(jf448_m m) {
    return jf448_and(jf448_frommask(m), jf448_one());
}

#if JF448_LANES == 8
static inline jf448_m jf448_mand(jf448_m a, jf448_m b) { return a & b; }
static inline jf448_m jf448_mxor(jf448_m a, jf448_m b) { return a ^ b; }
static inline bool jf448_m_all(jf448_m m) { return m == (__mmask8)0xFF; }
static inline bool jf448_m_all_first(jf448_m m, int n) {
    __mmask8 mask = (__mmask8)((1u << n) - 1);
    return (m & mask) == mask;
}
static inline jf448_m jf448_mask_from_bits(const uint8_t bits[JF448_LANES]) {
    __mmask8 m = 0;
    for (int j = 0; j < JF448_LANES; ++j)
        if (bits[j]) m |= (__mmask8)(1u << j);
    return m;
}
static inline bool jf448_m_lane(jf448_m m, int j) {
    return (m >> j) & 1;
}
#else
static inline jf448_m jf448_mand(jf448_m a, jf448_m b) { return jf448_and(a, b); }
static inline jf448_m jf448_mxor(jf448_m a, jf448_m b) { return jf448_xor(a, b); }
static inline bool jf448_m_all(jf448_m m) {
    uint64_t l[4];
    jf448_store64(l, m);
    return l[0] != 0 && l[1] != 0 && l[2] != 0 && l[3] != 0;
}
static inline bool jf448_m_all_first(jf448_m m, int n) {
    uint64_t l[4];
    jf448_store64(l, m);
    for (int j = 0; j < n; ++j)
        if (l[j] == 0) return false;
    return true;
}
static inline jf448_m jf448_mask_from_bits(const uint8_t bits[JF448_LANES]) {
    uint64_t l[JF448_LANES];
    for (int j = 0; j < JF448_LANES; ++j) l[j] = bits[j] ? ~0ULL : 0ULL;
    return jf448_set64(l[3], l[2], l[1], l[0]);
}
static inline bool jf448_m_lane(jf448_m m, int j) {
    uint64_t l[4];
    jf448_store64(l, m);
    return l[j] != 0;
}
#endif

// ---- N-way field element: 16 x 28-bit limbs, lane-sliced ----
struct feN {
    jf448_v limb[16];
};

static inline void feN_zero(feN& h) {
    for (int i = 0; i < 16; ++i) h.limb[i] = jf448_zero();
}
static inline void feN_one(feN& h) {
    feN_zero(h);
    h.limb[0] = jf448_one();
}
static inline void feN_copy(feN& h, const feN& f) {
    for (int i = 0; i < 16; ++i) h.limb[i] = f.limb[i];
}
static inline void feN_add(feN& h, const feN& f, const feN& g) {
    for (int i = 0; i < 16; ++i) h.limb[i] = jf448_add(f.limb[i], g.limb[i]);
}

// Same semantics as the scalar fe448_sub: borrow chain over the radix-2^28
// limbs; if the result is negative add p by subtracting (2^224 + 1).
static inline void feN_sub(feN& h, const feN& f, const feN& g) {
    jf448_v borrow = jf448_zero();
    jf448_v hb[16];
    for (int i = 0; i < 16; ++i) {
        jf448_v gb = jf448_add(g.limb[i], borrow);
        jf448_v b1 = jf448_frommask01(jf448_cmplt_u64(gb, g.limb[i]));
        jf448_v b2 = jf448_frommask01(jf448_cmplt_u64(f.limb[i], gb));
        hb[i] = jf448_and(jf448_sub(f.limb[i], gb), jf448_mask28());
        borrow = jf448_or(b1, b2);
    }
    jf448_m foldm = jf448_cmpgt_u64(borrow, jf448_zero());
    jf448_v fb = jf448_one();
    jf448_v folded[16];
    for (int i = 0; i < 16; ++i) {
        jf448_v v = jf448_sub(hb[i], fb);
        fb = jf448_frommask01(jf448_cmpgt_u64(v, hb[i]));
        folded[i] = jf448_and(v, jf448_mask28());
    }
    fb = jf448_one();
    for (int i = 8; i < 16; ++i) {
        jf448_v v = jf448_sub(folded[i], fb);
        fb = jf448_frommask01(jf448_cmpgt_u64(v, folded[i]));
        folded[i] = jf448_and(v, jf448_mask28());
    }
    for (int i = 0; i < 16; ++i) h.limb[i] = jf448_blend(hb[i], folded[i], foldm);
}

static inline void feN_neg(feN& h, const feN& f) {
    feN z;
    feN_zero(z);
    feN_sub(h, z, f);
}

// ---- lane transpose ----
static inline void feN_load(feN& r, const uint64_t elems[JF448_LANES][16]) {
    for (int i = 0; i < 16; ++i) {
#if JF448_LANES == 8
        r.limb[i] = jf448_set64(elems[7][i], elems[6][i], elems[5][i], elems[4][i],
                                elems[3][i], elems[2][i], elems[1][i], elems[0][i]);
#else
        r.limb[i] = jf448_set64(elems[3][i], elems[2][i], elems[1][i], elems[0][i]);
#endif
    }
}
static inline void feN_store(uint64_t elems[JF448_LANES][16], const feN& r) {
    for (int i = 0; i < 16; ++i) {
        uint64_t lanes[JF448_LANES];
        jf448_store64(lanes, r.limb[i]);
        for (int j = 0; j < JF448_LANES; ++j) elems[j][i] = lanes[j];
    }
}

// Propagate carries so limbs < 2^28; overflow out of limb 15 folds as
// 2^448 == 2^224 + 1 into limbs 0 and 8.  Fixed passes: first pass carry
// < 2^34, then tiny; 3 passes guarantee convergence per lane.
static inline void carry_normalize(jf448_v v[16], int passes) {
    for (int p = 0; p < passes; ++p) {
        jf448_v carry = jf448_zero();
        for (int i = 0; i < 16; ++i) {
            jf448_v sum = jf448_add(v[i], carry);
            jf448_v ovf = jf448_frommask01(jf448_cmplt_u64(sum, carry));
            v[i] = jf448_and(sum, jf448_mask28());
            carry = jf448_or(jf448_srli(sum, 28), jf448_slli(ovf, 28));
        }
        v[0] = jf448_add(v[0], carry);
        v[8] = jf448_add(v[8], carry);
    }
}

// Conditional subtract of p (per lane): v >= p -> v -= p.
static inline void csub_p(jf448_v v[16]) {
    jf448_v w[16];
    for (int i = 0; i < 16; ++i) w[i] = v[i];
    jf448_v csub = jf448_one();
    for (int i = 0; i < 16; ++i) {
        jf448_v sum = jf448_add(w[i], csub);
        if (i == 8) sum = jf448_add(sum, jf448_one());
        w[i] = jf448_and(sum, jf448_mask28());
        csub = jf448_srli(sum, 28);
    }
    jf448_m m = jf448_cmpgt_u64(csub, jf448_zero());
    for (int i = 0; i < 16; ++i) v[i] = jf448_blend(v[i], w[i], m);
}

// 16x16 schoolbook multiply, radix 2^28.  Input limbs must be < 2^29 so a
// column sums at most 16 * 2^58 < 2^62: plain 64-bit accumulation, no
// carry chains.  Columns 16..30 fold with 2^448 == 2^224 + 1.
static inline void feN_mul(feN& h, const feN& f, const feN& g) {
    jf448_v acc[31];
    for (int i = 0; i < 31; ++i) acc[i] = jf448_zero();
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j)
            acc[i + j] = jf448_add(acc[i + j], jf448_mul_epu32(f.limb[i], g.limb[j]));
    }
    // fold: 2^(28*(16+m)) mod p:
    //   m < 8:  == 2^(28*m) + 2^(28*(8+m))
    //   m >= 8: == 2^(28*(m-8)) + 2*2^(28*m)
    for (int m = 0; m < 15; ++m) {
        jf448_v v = acc[16 + m];
        if (m < 8) {
            acc[m] = jf448_add(acc[m], v);
            acc[8 + m] = jf448_add(acc[8 + m], v);
        } else {
            acc[m - 8] = jf448_add(acc[m - 8], v);
            acc[m] = jf448_add(acc[m], jf448_add(v, v));
        }
    }
    jf448_v out[16];
    for (int i = 0; i < 16; ++i) out[i] = acc[i];
    carry_normalize(out, 3);
    csub_p(out);
    for (int i = 0; i < 16; ++i) h.limb[i] = out[i];
}

// 16x16 squaring: 16 diagonal + 120 doubled cross products.
static inline void feN_sq(feN& h, const feN& f) {
    jf448_v acc[31];
    for (int i = 0; i < 31; ++i) acc[i] = jf448_zero();
    for (int i = 0; i < 16; ++i) {
        jf448_v p = jf448_mul_epu32(f.limb[i], f.limb[i]);
        acc[2 * i] = jf448_add(acc[2 * i], p);
        for (int j = i + 1; j < 16; ++j) {
            jf448_v q = jf448_mul_epu32(f.limb[i], f.limb[j]);
            acc[i + j] = jf448_add(acc[i + j], q);
            acc[i + j] = jf448_add(acc[i + j], q);
        }
    }
    for (int m = 0; m < 15; ++m) {
        jf448_v v = acc[16 + m];
        if (m < 8) {
            acc[m] = jf448_add(acc[m], v);
            acc[8 + m] = jf448_add(acc[8 + m], v);
        } else {
            acc[m - 8] = jf448_add(acc[m - 8], v);
            acc[m] = jf448_add(acc[m], jf448_add(v, v));
        }
    }
    jf448_v out[16];
    for (int i = 0; i < 16; ++i) out[i] = acc[i];
    carry_normalize(out, 3);
    csub_p(out);
    for (int i = 0; i < 16; ++i) h.limb[i] = out[i];
}

// f * small constant (s < 2^16)
static inline void feN_mul_small(feN& h, const feN& f, uint64_t s) {
    jf448_v sV = jf448_set1(s);
    jf448_v carry = jf448_zero();
    for (int i = 0; i < 16; ++i) {
        jf448_v lo = jf448_mul_epu32(f.limb[i], sV);
        jf448_v sum = jf448_add(lo, carry);
        jf448_v ovf = jf448_frommask01(jf448_cmplt_u64(sum, lo));
        h.limb[i] = jf448_and(sum, jf448_mask28());
        carry = jf448_add(jf448_srli(sum, 28), ovf);
    }
    h.limb[0] = jf448_add(h.limb[0], carry);
    h.limb[8] = jf448_add(h.limb[8], carry);
    carry_normalize(h.limb, 3);
    csub_p(h.limb);
}

// invert: z^(p-2), p-2 = 2^448 - 2^224 - 3 (windowed, fixed pattern)
static inline void feN_invert(feN& out, const feN& z) {
    feN table[16];
    feN_one(table[0]);
    feN_copy(table[1], z);
    for (int i = 2; i < 16; ++i) feN_mul(table[i], table[i - 1], z);

    feN_copy(out, table[0xF]);
    for (int w = 110; w >= 57; --w) {
        for (int j = 0; j < 4; ++j) feN_sq(out, out);
        feN t;
        feN_mul(t, out, table[0xF]);
        feN_copy(out, t);
    }
    for (int j = 0; j < 4; ++j) feN_sq(out, out);
    feN t;
    feN_mul(t, out, table[0xE]);
    feN_copy(out, t);
    for (int w = 55; w >= 1; --w) {
        for (int j = 0; j < 4; ++j) feN_sq(out, out);
        feN t2;
        feN_mul(t2, out, table[0xF]);
        feN_copy(out, t2);
    }
    for (int j = 0; j < 4; ++j) feN_sq(out, out);
    feN t3;
    feN_mul(t3, out, table[0xD]);
    feN_copy(out, t3);
}

// sqrt: r = a^((p+1)/4) = a^(2^446 - 2^222)
static inline void feN_sqrt(feN& r, const feN& a) {
    feN b;
    feN_copy(b, a);
    for (int i = 0; i < 222; ++i) feN_sq(b, b);   // b = a^(2^222)
    feN c;
    feN_copy(c, b);
    feN t;
    feN_copy(t, b);
    for (int i = 1; i < 224; ++i) {
        feN_sq(t, t);
        feN_mul(c, c, t);                          // c = b^(2^224 - 1)
    }
    feN_copy(r, c);
}

// per-lane sign (limb0 bit 0)
static inline jf448_m feN_isnegative_mask(const feN& f) {
    feN t;
    feN_copy(t, f);
    carry_normalize(t.limb, 3);
    csub_p(t.limb);
    jf448_v bit = jf448_and(t.limb[0], jf448_one());
    return jf448_cmpgt_u64(bit, jf448_zero());
}

// negate lanes selected by mask
static inline void feN_cond_neg(feN& h, const feN& f, jf448_m m) {
    feN n;
    feN_neg(n, f);
    for (int i = 0; i < 16; ++i) h.limb[i] = jf448_blend(f.limb[i], n.limb[i], m);
}

// conditional swap per lane
static inline void feN_cswap(feN& a, feN& b, jf448_m m) {
    for (int i = 0; i < 16; ++i) {
        jf448_v t = jf448_blend(a.limb[i], b.limb[i], m);
        b.limb[i] = jf448_blend(b.limb[i], a.limb[i], m);
        a.limb[i] = t;
    }
}

// ---- byte conversion (56-byte little-endian <-> 16 x 28-bit limbs) ----
static inline void feN_frombytes(feN& h, const uint8_t* s[JF448_LANES]) {
    uint64_t tmp[JF448_LANES][16];
    for (int j = 0; j < JF448_LANES; ++j) {
        const uint8_t* p = s[j];
        for (int i = 0; i < 16; ++i) {
            int bit = 28 * i;
            int by = bit >> 3;
            int sh = bit & 7;
            uint64_t x = (uint64_t)p[by] | ((uint64_t)p[by + 1] << 8) |
                         ((uint64_t)p[by + 2] << 16) | ((uint64_t)p[by + 3] << 24);
            tmp[j][i] = (x >> sh) & (((uint64_t)1 << 28) - 1);
        }
    }
    feN_load(h, tmp);
}

static inline void feN_tobytes(uint8_t* s[JF448_LANES], const feN& h) {
    feN t;
    feN_copy(t, h);
    carry_normalize(t.limb, 3);
    csub_p(t.limb);
    uint64_t tmp[JF448_LANES][16];
    feN_store(tmp, t);
    for (int j = 0; j < JF448_LANES; ++j) {
        uint8_t* p = s[j];
        uint64_t v17[17];
        memcpy(v17, tmp[j], 16 * 8);
        v17[16] = 0;
        for (int b = 0; b < 56; ++b) {
            int bit = 8 * b;
            int li = bit / 28;
            int sh = bit % 28;
            uint8_t lo = (uint8_t)(v17[li] >> sh);
            uint8_t hi = (uint8_t)(v17[li + 1] << (28 - sh));
            p[b] = (uint8_t)(lo | hi);
        }
    }
}

} // namespace fe448_simd
} // namespace jpssl
