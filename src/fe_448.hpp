#pragma once
// fe_448.hpp - GF(2^448 - 2^224 - 1) field arithmetic (Goldilocks prime)
// Used by X448 (RFC 7748) and Ed448 (RFC 8032).
// 56-bit radix schoolbook + single-pass Goldilocks reduction.
//
// Performance notes:
//  - On MSVC, __uint128_t is emulated (jp_uint128) and 64x64->128 products
//    must go through _umul128. We use explicit lo/hi u64 accumulators so the
//    hot paths compile to single mul + adc sequences on both MSVC and GCC.
//  - fe448_mul: 64 products, single-pass fold, one carry chain.
//  - fe448_sq: dedicated squaring with 36 products (~1.8x cheaper than mul).
//  - fe448_invert: 4-bit windowed exponentiation for p-2.
//  - fe448_sqrt: exponent chain without a nested inversion.
#include <cstdint>
#include <cstring>

#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#endif

namespace jpssl {
namespace fe448_impl {

using fe448 = uint64_t[8];
static const uint64_t MASK56 = ((uint64_t)1 << 56) - 1;

// ---- 64x64 -> 128 multiply (native on both MSVC and GCC/Clang) ----
static inline uint64_t fe448_mul64(uint64_t a, uint64_t b, uint64_t* hi) {
#if defined(_MSC_VER) && !defined(__clang__)
    return _umul128(a, b, hi);
#else
    __uint128_t r = (__uint128_t)a * b;
    *hi = (uint64_t)(r >> 64);
    return (uint64_t)r;
#endif
}

// ---- add 128-bit value (slo | shi<<64) into (lo | hi<<64) ----
static inline void fe448_acc128(uint64_t* lo, uint64_t* hi,
                                uint64_t slo, uint64_t shi) {
#if defined(_MSC_VER) && !defined(__clang__)
    unsigned char c = _addcarry_u64(0, *lo, slo, lo);
    _addcarry_u64(c, *hi, shi, hi);
#else
    __uint128_t t = (__uint128_t)*lo | ((__uint128_t)*hi << 64);
    t += (__uint128_t)slo | ((__uint128_t)shi << 64);
    *lo = (uint64_t)t;
    *hi = (uint64_t)(t >> 64);
#endif
}

// ---- add small u64 into (lo | hi<<64) ----
static inline void fe448_acc_small(uint64_t* lo, uint64_t* hi, uint64_t v) {
#if defined(_MSC_VER) && !defined(__clang__)
    unsigned char c = _addcarry_u64(0, *lo, v, lo);
    _addcarry_u64(c, *hi, 0, hi);
#else
    __uint128_t t = (__uint128_t)*lo | ((__uint128_t)*hi << 64);
    t += v;
    *lo = (uint64_t)t;
    *hi = (uint64_t)(t >> 64);
#endif
}

inline void fe448_frombytes(fe448 h, const uint8_t* s) {
    for (int i = 0; i < 8; ++i) {
        const uint8_t* p = s + 7 * i;
        uint64_t v = 0;
        for (int j = 6; j >= 0; --j) v = (v << 8) | p[j];
        h[i] = v & MASK56;
    }
}

// Carry-propagate an 8-limb (limbs < 2^64) array in radix 2^56 with
// Goldilocks folding; returns limbs < 2^56 (value < 2^448 + 2^224 + 1).
static inline void fe448_carry_limbs(uint64_t v[8]) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sum = v[i] + carry;
        // If v[i]+carry overflowed u64, true sum is sum + 2^64.
        uint64_t ovf = (sum < carry) ? (uint64_t)1 << 8 : 0;
        v[i] = sum & MASK56;
        carry = (sum >> 56) + ovf;
    }
    if (carry) {
        // carry * 2^448 == carry * (2^224 + 1) (mod p)
        v[0] += carry; v[4] += carry;
        uint64_t c = 0;
        for (int i = 0; i < 8; ++i) {
            uint64_t sum = v[i] + c;
            uint64_t ovf = (sum < c) ? (uint64_t)1 << 8 : 0;
            v[i] = sum & MASK56;
            c = (sum >> 56) + ovf;
        }
        while (c) {
            v[0] += c; c = v[0] >> 56; v[0] &= MASK56;
            v[4] += c; c = v[4] >> 56; v[4] &= MASK56;
            for (int i = 1; i < 8; ++i) {
                if (i == 4) continue;
                v[i] += c; c = v[i] >> 56; v[i] &= MASK56;
                if (!c) break;
            }
        }
    }
}

// Conditional subtract of p: out < 2p, limbs < 2^56.
// Replaces out by out-p when out >= p (i.e. out + (2^224+1) overflows 2^448).
static inline void fe448_csub_p(uint64_t v[8]) {
    uint64_t w[8];
    memcpy(w, v, sizeof(w));
    uint64_t csub = 1;
    for (int i = 0; i < 8; ++i) {
        uint64_t sum = w[i] + csub;
        if (i == 4) sum += 1;  // +2^224 term
        w[i] = sum & MASK56;
        csub = sum >> 56;
    }
    if (csub != 0) memcpy(v, w, sizeof(w));
}

inline void fe448_tobytes(uint8_t* s, const fe448 h) {
    uint64_t v[8];
    memcpy(v, h, sizeof(v));
    fe448_carry_limbs(v);
    fe448_csub_p(v);
    for (int i = 0; i < 8; ++i) {
        uint64_t x = v[i];
        uint8_t* p = s + 7 * i;
        for (int j = 0; j < 7; ++j) p[j] = (uint8_t)(x >> (8 * j));
    }
}

static constexpr size_t FE448_BYTES = sizeof(uint64_t) * 8;
inline void fe448_0(fe448 h) { memset(h, 0, FE448_BYTES); }
inline void fe448_1(fe448 h) { fe448_0(h); h[0] = 1; }
inline void fe448_copy(fe448 h, const fe448 f) { memcpy(h, f, FE448_BYTES); }

inline void fe448_add(fe448 h, const fe448 f, const fe448 g) {
    for (int i = 0; i < 8; ++i) h[i] = f[i] + g[i];
}

inline void fe448_sub(fe448 h, const fe448 f, const fe448 g) {
    // Uniform borrow-chain subtraction with Goldilocks folding:
    // f-g (mod p), no assumptions on operand ordering.
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t gb = g[i] + borrow;
        borrow = (gb < g[i]) ? 1 : ((f[i] < gb) ? 1 : 0);
        h[i] = (f[i] - gb) & MASK56;
    }
    if (borrow) {
        // subtract 2^448+1 ("1" carry) then 2^224 term
        borrow = 1;
        for (int i = 0; i < 8; ++i) {
            uint64_t v = h[i] - borrow;
            borrow = (v > h[i]) ? 1 : 0;
            h[i] = v & MASK56;
        }
        borrow = 1;
        for (int i = 4; i < 8; ++i) {
            uint64_t v = h[i] - borrow;
            borrow = (v > h[i]) ? 1 : 0;
            h[i] = v & MASK56;
        }
    }
}

inline void fe448_neg(fe448 h, const fe448 f) {
    fe448 z;
    fe448_0(z);
    fe448_sub(h, z, f);
}

// Fully normalize (carry + Goldilocks fold + conditional subtract p).
inline void fe448_carry(fe448 h) {
    fe448_carry_limbs(h);
    fe448_csub_p(h);
}

inline void fe448_cswap(fe448 a, fe448 b, uint64_t mask) {
    uint64_t m = (uint64_t)(-(int64_t)(mask != 0));
    for (int i = 0; i < 8; ++i) {
        uint64_t t = m & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

inline int fe448_isnegative(const fe448 f) {
    uint8_t s[56];
    fe448_tobytes(s, f);
    return s[0] & 1;
}

// f * small constant (s < 2^16): u64-only products.
inline void fe448_mul_small(fe448 h, const fe448 f, uint64_t s) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t hi = 0;
        uint64_t p = fe448_mul64(f[i], s, &hi);
        uint64_t sum = p + carry;          // carry < 2^17, may wrap u64
        uint64_t ovf = (sum < p) ? (uint64_t)1 << 8 : 0;  // p+carry >= 2^64
        h[i] = sum & MASK56;
        carry = (sum >> 56) + (hi << 8) + ovf;  // hi is 2^64 units = 2^8 * 2^56
    }
    if (carry) {
        h[0] += carry; h[4] += carry;
        uint64_t c = 0;
        for (int i = 0; i < 8; ++i) {
            uint64_t sum = h[i] + c;
            uint64_t ovf = (sum < c) ? (uint64_t)1 << 8 : 0;
            h[i] = sum & MASK56;
            c = (sum >> 56) + ovf;
        }
        while (c) {
            h[0] += c; c = h[0] >> 56; h[0] &= MASK56;
            h[4] += c; c = h[4] >> 56; h[4] &= MASK56;
            for (int i = 1; i < 8; ++i) {
                if (i == 4) continue;
                h[i] += c; c = h[i] >> 56; h[i] &= MASK56;
                if (!c) break;
            }
        }
    }
    fe448_csub_p(h);
}

// ---- shared fold + carry for full[16] (lo/hi u64 pairs) ----
// Weight of limb 8+m is 2^(448+56m) == 2^(224+56m) + 2^(56m) (mod p):
//   m < 4: fold into limbs m and m+4
//   m >= 4: 2^(224+56m) == 2^(56m) + 2^(56(m-4)) -> limbs m (x2) and m-4
static inline void fe448_fold16(uint64_t tl[16], uint64_t th[16], uint64_t out[8]) {
    for (int m = 0; m < 8; ++m) {
        uint64_t lo = tl[8 + m];
        uint64_t hi = th[8 + m];
        if (hi != 0 || lo != 0) {
            if (m < 4) {
                fe448_acc128(&tl[m], &th[m], lo, hi);
                fe448_acc128(&tl[m + 4], &th[m + 4], lo, hi);
            } else {
                uint64_t l2 = lo << 1;
                uint64_t h2 = (hi << 1) | (lo >> 63);
                fe448_acc128(&tl[m], &th[m], l2, h2);
                fe448_acc128(&tl[m - 4], &th[m - 4], lo, hi);
            }
            tl[8 + m] = th[8 + m] = 0;
        }
    }
    // single carry chain (bounds keep carry < 2^62)
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sum = tl[i] + carry;
        uint64_t ovf = (sum < carry) ? 1 : 0;
        uint64_t thc = th[i] + ovf;
        out[i] = sum & MASK56;
        carry = (sum >> 56) + (thc << 8);
    }
    if (carry) {
        out[0] += carry; out[4] += carry;
        uint64_t c = 0;
        for (int i = 0; i < 8; ++i) {
            uint64_t sum = out[i] + c;
            uint64_t ovf = (sum < c) ? (uint64_t)1 << 8 : 0;
            out[i] = sum & MASK56;
            c = (sum >> 56) + ovf;
        }
        while (c) {
            out[0] += c; c = out[0] >> 56; out[0] &= MASK56;
            out[4] += c; c = out[4] >> 56; out[4] &= MASK56;
            for (int i = 1; i < 8; ++i) {
                if (i == 4) continue;
                out[i] += c; c = out[i] >> 56; out[i] &= MASK56;
                if (!c) break;
            }
        }
    }
}

inline void fe448_mul(fe448 h, const fe448 f, const fe448 g) {
    // Input limbs must be < 2^57 (callers keep add/sub results bounded);
    // products then fit in 112 bits and the u128 accumulators never overflow.
    uint64_t tl[16] = {0};
    uint64_t th[16] = {0};
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            uint64_t hi = 0;
            uint64_t lo = fe448_mul64(f[i], g[j], &hi);
            fe448_acc128(&tl[i + j], &th[i + j], lo, hi);
        }
    }
    uint64_t out[8];
    fe448_fold16(tl, th, out);
    fe448_csub_p(out);
    for (int i = 0; i < 8; ++i) h[i] = out[i];
}

inline void fe448_sq(fe448 h, const fe448 f) {
    // dedicated squaring: 36 products (diagonal + doubled off-diagonal)
    uint64_t tl[16] = {0};
    uint64_t th[16] = {0};
    for (int i = 0; i < 8; ++i) {
        uint64_t hi = 0;
        uint64_t lo = fe448_mul64(f[i], f[i], &hi);
        fe448_acc128(&tl[2 * i], &th[2 * i], lo, hi);
        for (int j = i + 1; j < 8; ++j) {
            uint64_t hi2 = 0;
            uint64_t lo2 = fe448_mul64(f[i], f[j], &hi2);
            // double the product (shift left by 1)
            uint64_t l2 = lo2 << 1;
            uint64_t h2 = (hi2 << 1) | (lo2 >> 63);
            fe448_acc128(&tl[i + j], &th[i + j], l2, h2);
        }
    }
    uint64_t out[8];
    fe448_fold16(tl, th, out);
    fe448_csub_p(out);
    for (int i = 0; i < 8; ++i) h[i] = out[i];
}

// invert: z^(p-2), p-2 = 2^448 - 2^224 - 3
// Binary: bit0=1, bit1=0, bits2..223=1, bit224=0, bits225..447=1.
// 4-bit windowed exponentiation over the fixed bit pattern:
//   windows 1..55 and 57..111 = 0xF,
//   window 56 (bits 224..227 = 0b0111) = 0xE,
//   window 0 (bits 3..0 = 0b1101) = 0xD.
// Cost: 444 sq + 111 mul + 14 table-entry muls.
inline void fe448_invert(fe448 out, const fe448 z) {
    fe448 table[16];
    fe448_1(table[0]);
    fe448_copy(table[1], z);
    for (int i = 2; i < 16; ++i)
        fe448_mul(table[i], table[i - 1], z);

    // top window (bits 447..444) = 0xF
    fe448_copy(out, table[0xF]);
    for (int w = 110; w >= 57; --w) {
        for (int j = 0; j < 4; ++j) fe448_sq(out, out);
        fe448 t;
        fe448_mul(t, out, table[0xF]);
        fe448_copy(out, t);
    }
    // window 56 (bits 224..227) = 0xE
    for (int j = 0; j < 4; ++j) fe448_sq(out, out);
    fe448 t;
    fe448_mul(t, out, table[0xE]);
    fe448_copy(out, t);
    // windows 55..1 = 0xF
    for (int w = 55; w >= 1; --w) {
        for (int j = 0; j < 4; ++j) fe448_sq(out, out);
        fe448 t2;
        fe448_mul(t2, out, table[0xF]);
        fe448_copy(out, t2);
    }
    // lowest window (bits 3..0) = 0xD
    for (int j = 0; j < 4; ++j) fe448_sq(out, out);
    fe448 t3;
    fe448_mul(t3, out, table[0xD]);
    fe448_copy(out, t3);
}

// sqrt: r = a^((p+1)/4) = a^(2^446 - 2^222)
// = (a^(2^222))^(2^224 - 1), computed with an all-ones chain, no inversion.
// Cost: 445 sq + 223 mul.
inline void fe448_sqrt(fe448 r, const fe448 a) {
    fe448 b;
    fe448_copy(b, a);
    for (int i = 0; i < 222; ++i) fe448_sq(b, b);   // b = a^(2^222)
    fe448 c;
    fe448_copy(c, b);
    fe448 t;
    fe448_copy(t, b);
    for (int i = 1; i < 224; ++i) {
        fe448_sq(t, t);
        fe448_mul(c, c, t);                          // c = b^(2^224 - 1)
    }
    fe448_copy(r, c);
}

} // namespace fe448_impl
} // namespace jpssl
