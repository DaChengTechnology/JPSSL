#pragma once
// fe_448.hpp - GF(2^448 - 2^224 - 1) 域运算 (Goldilocks 素数)
// 用于 X448 (RFC 7748) 和 Ed448 (RFC 8032)
// 56-bit radix schoolbook + Goldilocks reduction
#include <cstdint>
#include <cstring>

namespace jpssl {
namespace fe448_impl {

using fe448 = uint64_t[8];
static const uint64_t MASK56 = ((uint64_t)1 << 56) - 1;

inline void fe448_frombytes(fe448 h, const uint8_t* s) {
    for (int i = 0; i < 8; ++i) {
        const uint8_t* p = s + 7 * i;
        uint64_t v = 0;
        for (int j = 6; j >= 0; --j) v = (v << 8) | p[j];
        h[i] = v & MASK56;
    }
}

inline void fe448_tobytes(uint8_t* s, const fe448 h) {
    uint64_t v[8];
    unsigned __int128 carry = 0;
    for (int i = 0; i < 8; ++i) {
        unsigned __int128 c = (unsigned __int128)h[i] + carry;
        v[i] = (uint64_t)(c & MASK56); carry = c >> 56;
    }
    if (carry) {
        v[0] += (uint64_t)carry; v[4] += (uint64_t)carry;
        uint64_t c = 0;
        for (int i = 0; i < 8; ++i) { uint64_t val = v[i] + c; v[i] = val & MASK56; c = val >> 56; }
        while (c) {
            v[0] += c; c = v[0] >> 56; v[0] &= MASK56;
            v[4] += c; c = v[4] >> 56; v[4] &= MASK56;
            for (int i = 1; i < 8; ++i) { if (i == 4) continue; v[i] += c; c = v[i] >> 56; v[i] &= MASK56; if (!c) break; }
        }
    }
    {   uint64_t w[8]; memcpy(w, v, sizeof(w));
        uint64_t csub = 1;
        for (int i = 0; i < 8; ++i) {
            unsigned __int128 c = (unsigned __int128)w[i] + csub;
            if (i == 4) c += 1;  // 2^224 term
            w[i] = (uint64_t)(c & MASK56);
            csub = (uint64_t)(c >> 56);
        }
        if (csub != 0) memcpy(v, w, sizeof(v));
    }
    for (int i = 0; i < 8; ++i) {
        uint64_t x = v[i]; uint8_t* p = s + 7 * i;
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
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t gb = g[i] + borrow;
        borrow = (gb < g[i]) ? 1 : ((f[i] < gb) ? 1 : 0);
        h[i] = (f[i] - gb) & MASK56;
    }
    if (borrow) {
        // h = 2^448 + f - g (mod 2^448). Subtract (2^224 + 1) to get p + f - g.
        uint64_t c = 1;
        for (int i = 0; i < 8; ++i) {
            uint64_t v = h[i] - c;
            c = (v > h[i]) ? 1 : 0;
            h[i] = v & MASK56;
        }
        c = 1;
        for (int i = 4; i < 8; ++i) {
            uint64_t v = h[i] - c;
            c = (v > h[i]) ? 1 : 0;
            h[i] = v & MASK56;
        }
    }
}

inline void fe448_neg(fe448 h, const fe448 f) { fe448 z; fe448_0(z); fe448_sub(h, z, f); }

inline void fe448_cswap(fe448 a, fe448 b, uint64_t mask) {
    uint64_t m = (uint64_t)(-(int64_t)(mask != 0));
    for (int i = 0; i < 8; ++i) { uint64_t t = m & (a[i] ^ b[i]); a[i] ^= t; b[i] ^= t; }
}

inline int fe448_isnegative(const fe448 f) { uint8_t s[56]; fe448_tobytes(s, f); return s[0] & 1; }

inline void fe448_mul_small(fe448 h, const fe448 f, uint64_t s) {
    unsigned __int128 acc[8] = {0};
    for (int i = 0; i < 8; ++i) acc[i] = (unsigned __int128)f[i] * s;
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) { unsigned __int128 c = acc[i] + carry; h[i] = (uint64_t)(c & MASK56); carry = (uint64_t)(c >> 56); }
    if (carry) {
        h[0] += carry; h[4] += carry;
        uint64_t c = 0;
        for (int i = 0; i < 8; ++i) { uint64_t v = h[i] + c; h[i] = v & MASK56; c = v >> 56; }
        while (c) {
            h[0] += c; c = h[0] >> 56; h[0] &= MASK56;
            h[4] += c; c = h[4] >> 56; h[4] &= MASK56;
            for (int i = 1; i < 8; ++i) { if (i == 4) continue; h[i] += c; c = h[i] >> 56; h[i] &= MASK56; if (!c) break; }
        }
    }
    {
        uint64_t w[8]; memcpy(w, h, sizeof(w));
        uint64_t csub = 1;
        for (int i = 0; i < 8; ++i) {
            unsigned __int128 c = (unsigned __int128)w[i] + csub;
            if (i == 4) c += 1;
            w[i] = (uint64_t)(c & MASK56);
            csub = (uint64_t)(c >> 56);
        }
        if (csub != 0) memcpy(h, w, sizeof(w));
    }
}

// 56-bit schoolbook + Goldilocks reduction
// fold: full[8+m] (weight 2^(448+56m)) ≡ 2^(224+56m) + 2^(56m)
//   m<4: -> full[m] + full[m+4]
//   m>=4: 2^(224+56m) = 2^(56*(m+4)) 再次折叠 -> 2*hi to full[m], hi to full[m-4]
static inline void fe448_reduce(unsigned __int128 full[16], uint64_t out[8]) {
    bool again;
    do {
        again = false;
        for (int m = 0; m < 8; ++m) {
            unsigned __int128 hi = full[8 + m];
            if (hi != 0) {
                if (m < 4) { full[m] += hi; full[m + 4] += hi; }
                else { full[m] += 2*hi; full[m - 4] += hi; }
                full[8 + m] = 0;
                again = true;
            }
        }
    } while (again);
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        unsigned __int128 c = full[i] + carry;
        out[i] = (uint64_t)(c & MASK56);
        carry = (uint64_t)(c >> 56);
    }
    if (carry) {
        out[0] += carry; out[4] += carry;
        uint64_t c = 0;
        for (int i = 0; i < 8; ++i) { uint64_t val = out[i] + c; out[i] = val & MASK56; c = val >> 56; }
        while (c) {
            out[0] += c; c = out[0] >> 56; out[0] &= MASK56;
            out[4] += c; c = out[4] >> 56; out[4] &= MASK56;
            for (int i = 1; i < 8; ++i) { if (i == 4) continue; out[i] += c; c = out[i] >> 56; out[i] &= MASK56; if (!c) break; }
        }
    }
}

inline void fe448_mul(fe448 h, const fe448 f, const fe448 g) {
    // Normalize inputs via tobytes/frombytes to ensure limbs < 2^56
    fe448 f0, g0;
    uint8_t tmp[56];
    fe448_tobytes(tmp, f); fe448_frombytes(f0, tmp);
    fe448_tobytes(tmp, g); fe448_frombytes(g0, tmp);
    unsigned __int128 full[16] = {0};
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j)
            full[i + j] += (unsigned __int128)f0[i] * g0[j];
    uint64_t out[8];
    fe448_reduce(full, out);
    {
        uint64_t w[8]; memcpy(w, out, sizeof(w));
        uint64_t csub = 1;
        for (int i = 0; i < 8; ++i) {
            unsigned __int128 c = (unsigned __int128)w[i] + csub;
            if (i == 4) c += 1;
            w[i] = (uint64_t)(c & MASK56);
            csub = (uint64_t)(c >> 56);
        }
        if (csub != 0) memcpy(out, w, sizeof(out));
    }
    for (int i = 0; i < 8; ++i) h[i] = out[i];
}

inline void fe448_sq(fe448 h, const fe448 f) { fe448 t; fe448_copy(t, f); fe448_mul(h, t, t); }

// invert: z^(p-2), p-2 = 2^448 - 2^224 - 3
// bits: bit0=1,bit1=0,bit2..223=1,bit224=0,bit225..447=1
inline void fe448_invert(fe448 out, const fe448 z) {
    fe448 res; fe448_copy(res, z);
    fe448 acc; fe448_copy(acc, z);
    for (int i = 1; i < 448; ++i) {
        fe448_sq(acc, acc);
        bool bit = (i != 1 && i != 224);
        if (bit) fe448_mul(res, res, acc);
    }
    fe448_copy(out, res);
}

} // namespace fe448_impl
} // namespace jpssl
