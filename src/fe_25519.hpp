#pragma once
#include <cstdint>
#include <cstring>

namespace jpssl {
namespace fe_impl {

using fe = int32_t[10];

inline int32_t load_3(const uint8_t* in) {
    return ((int32_t)in[0]) | ((int32_t)in[1] << 8) | ((int32_t)in[2] << 16);
}
inline int64_t load_4(const uint8_t* in) {
    return ((int64_t)in[0]) | ((int64_t)in[1] << 8) | ((int64_t)in[2] << 16) | ((int64_t)in[3] << 24);
}

inline void fe_frombytes(fe h, const uint8_t* s) {
    int64_t h0 = load_4(s);
    int64_t h1 = load_3(s + 4) << 6;
    int64_t h2 = load_3(s + 7) << 5;
    int64_t h3 = load_3(s + 10) << 3;
    int64_t h4 = load_3(s + 13) << 2;
    int64_t h5 = load_4(s + 16);
    int64_t h6 = load_3(s + 20) << 7;
    int64_t h7 = load_3(s + 23) << 5;
    int64_t h8 = load_3(s + 26) << 4;
    int64_t h9 = (load_3(s + 29) & 0x7fffff) << 2;
    int64_t c;
    for (int pass = 0; pass < 2; pass++) {
        c = h0 >> 26; h1 += c; h0 -= c << 26;
        c = h1 >> 25; h2 += c; h1 -= c << 25;
        c = h2 >> 26; h3 += c; h2 -= c << 26;
        c = h3 >> 25; h4 += c; h3 -= c << 25;
        c = h4 >> 26; h5 += c; h4 -= c << 26;
        c = h5 >> 25; h6 += c; h5 -= c << 25;
        c = h6 >> 26; h7 += c; h6 -= c << 26;
        c = h7 >> 25; h8 += c; h7 -= c << 25;
        c = h8 >> 26; h9 += c; h8 -= c << 26;
        c = h9 >> 25; h0 += c * 19; h9 -= c << 25;
    }
    h[0] = (int32_t)h0; h[1] = (int32_t)h1; h[2] = (int32_t)h2; h[3] = (int32_t)h3;
    h[4] = (int32_t)h4; h[5] = (int32_t)h5; h[6] = (int32_t)h6; h[7] = (int32_t)h7;
    h[8] = (int32_t)h8; h[9] = (int32_t)h9;
}

inline void fe_tobytes(uint8_t* s, fe h) {
    int64_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
    int64_t h5 = h[5], h6 = h[6], h7 = h[7], h8 = h[8], h9 = h[9];
    int64_t c;

    // ref10 fe_tobytes carry: use floor division (h >> shift) for canonicalization
    // This handles both positive (carry overflow) and negative (borrow) correctly
    // Full carry chain from low to high with wrap-around
    for (int pass = 0; pass < 2; pass++) {
        c = h0 >> 26; h1 += c; h0 -= c << 26;
        c = h1 >> 25; h2 += c; h1 -= c << 25;
        c = h2 >> 26; h3 += c; h2 -= c << 26;
        c = h3 >> 25; h4 += c; h3 -= c << 25;
        c = h4 >> 26; h5 += c; h4 -= c << 26;
        c = h5 >> 25; h6 += c; h5 -= c << 25;
        c = h6 >> 26; h7 += c; h6 -= c << 26;
        c = h7 >> 25; h8 += c; h7 -= c << 25;
        c = h8 >> 26; h9 += c; h8 -= c << 26;
        c = h9 >> 25; h0 += c * 19; h9 -= c << 25;
    }

    uint32_t u0 = (uint32_t)h0, u1 = (uint32_t)h1, u2 = (uint32_t)h2;
    uint32_t u3 = (uint32_t)h3, u4 = (uint32_t)h4, u5 = (uint32_t)h5;
    uint32_t u6 = (uint32_t)h6, u7 = (uint32_t)h7, u8 = (uint32_t)h8, u9 = (uint32_t)h9;

    s[0] = (uint8_t)u0;
    s[1] = (uint8_t)(u0 >> 8);
    s[2] = (uint8_t)(u0 >> 16);
    s[3] = (uint8_t)((u0 >> 24) | ((u1 & 0x3f) << 2));
    s[4] = (uint8_t)(u1 >> 6);
    s[5] = (uint8_t)(u1 >> 14);
    s[6] = (uint8_t)((u1 >> 22) | ((u2 & 0x1f) << 3));
    s[7] = (uint8_t)(u2 >> 5);
    s[8] = (uint8_t)(u2 >> 13);
    s[9] = (uint8_t)((u2 >> 21) | ((u3 & 7) << 5));
    s[10] = (uint8_t)(u3 >> 3);
    s[11] = (uint8_t)(u3 >> 11);
    s[12] = (uint8_t)((u3 >> 19) | ((u4 & 3) << 6));
    s[13] = (uint8_t)(u4 >> 2);
    s[14] = (uint8_t)(u4 >> 10);
    s[15] = (uint8_t)(u4 >> 18);
    s[16] = (uint8_t)u5;
    s[17] = (uint8_t)(u5 >> 8);
    s[18] = (uint8_t)(u5 >> 16);
    s[19] = (uint8_t)((u5 >> 24) | ((u6 & 0x7f) << 1));
    s[20] = (uint8_t)(u6 >> 7);
    s[21] = (uint8_t)(u6 >> 15);
    s[22] = (uint8_t)((u6 >> 23) | ((u7 & 0x1f) << 3));
    s[23] = (uint8_t)(u7 >> 5);
    s[24] = (uint8_t)(u7 >> 13);
    s[25] = (uint8_t)((u7 >> 21) | ((u8 & 0xf) << 4));
    s[26] = (uint8_t)(u8 >> 4);
    s[27] = (uint8_t)(u8 >> 12);
    s[28] = (uint8_t)((u8 >> 20) | ((u9 & 3) << 6));
    s[29] = (uint8_t)(u9 >> 2);
    s[30] = (uint8_t)(u9 >> 10);
    s[31] = (uint8_t)(u9 >> 18);
}

inline void fe_0(fe h) { memset(h, 0, sizeof(int32_t) * 10); }
inline void fe_1(fe h) { memset(h, 0, sizeof(int32_t) * 10); h[0] = 1; }
inline void fe_copy(fe h, const fe f) { memcpy(h, f, sizeof(int32_t) * 10); }

inline void fe_add(fe h, const fe f, const fe g) { for (int i = 0; i < 10; ++i) h[i] = f[i] + g[i]; }
inline void fe_sub(fe h, const fe f, const fe g) { for (int i = 0; i < 10; ++i) h[i] = f[i] - g[i]; }
inline void fe_neg(fe h, const fe f) { for (int i = 0; i < 10; ++i) h[i] = -f[i]; }

inline void fe_mul(fe h, const fe f, const fe g) {
    int64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    int64_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
    int64_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    int64_t g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];
    int64_t g1_19 = g1 * 19, g2_19 = g2 * 19, g3_19 = g3 * 19, g4_19 = g4 * 19;
    int64_t g5_19 = g5 * 19, g6_19 = g6 * 19, g7_19 = g7 * 19, g8_19 = g8 * 19, g9_19 = g9 * 19;
    int64_t h0 = f0*g0 + f1*2*g9_19 + f2*g8_19 + f3*2*g7_19 + f4*g6_19 + f5*2*g5_19 + f6*g4_19 + f7*2*g3_19 + f8*g2_19 + f9*2*g1_19;
    int64_t h1 = f0*g1 + f1*g0 + f2*g9_19 + f3*g8_19 + f4*g7_19 + f5*g6_19 + f6*g5_19 + f7*g4_19 + f8*g3_19 + f9*g2_19;
    int64_t h2 = f0*g2 + f1*2*g1 + f2*g0 + f3*2*g9_19 + f4*g8_19 + f5*2*g7_19 + f6*g6_19 + f7*2*g5_19 + f8*g4_19 + f9*2*g3_19;
    int64_t h3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g9_19 + f5*g8_19 + f6*g7_19 + f7*g6_19 + f8*g5_19 + f9*g4_19;
    int64_t h4 = f0*g4 + f1*2*g3 + f2*g2 + f3*2*g1 + f4*g0 + f5*2*g9_19 + f6*g8_19 + f7*2*g7_19 + f8*g6_19 + f9*2*g5_19;
    int64_t h5 = f0*g5 + f1*g4 + f2*g3 + f3*g2 + f4*g1 + f5*g0 + f6*g9_19 + f7*g8_19 + f8*g7_19 + f9*g6_19;
    int64_t h6 = f0*g6 + f1*2*g5 + f2*g4 + f3*2*g3 + f4*g2 + f5*2*g1 + f6*g0 + f7*2*g9_19 + f8*g8_19 + f9*2*g7_19;
    int64_t h7 = f0*g7 + f1*g6 + f2*g5 + f3*g4 + f4*g3 + f5*g2 + f6*g1 + f7*g0 + f8*g9_19 + f9*g8_19;
    int64_t h8 = f0*g8 + f1*2*g7 + f2*g6 + f3*2*g5 + f4*g4 + f5*2*g3 + f6*g2 + f7*2*g1 + f8*g0 + f9*2*g9_19;
    int64_t h9 = f0*g9 + f1*g8 + f2*g7 + f3*g6 + f4*g5 + f5*g4 + f6*g3 + f7*g2 + f8*g1 + f9*g0;
    int64_t c;
    c = (h0 + (1 << 25)) >> 26; h1 += c; h0 -= c << 26;
    c = (h4 + (1 << 25)) >> 26; h5 += c; h4 -= c << 26;
    c = (h1 + (1 << 24)) >> 25; h2 += c; h1 -= c << 25;
    c = (h5 + (1 << 24)) >> 25; h6 += c; h5 -= c << 25;
    c = (h2 + (1 << 25)) >> 26; h3 += c; h2 -= c << 26;
    c = (h6 + (1 << 25)) >> 26; h7 += c; h6 -= c << 26;
    c = (h3 + (1 << 24)) >> 25; h4 += c; h3 -= c << 25;
    c = (h7 + (1 << 24)) >> 25; h8 += c; h7 -= c << 25;
    c = (h4 + (1 << 25)) >> 26; h5 += c; h4 -= c << 26;
    c = (h8 + (1 << 25)) >> 26; h9 += c; h8 -= c << 26;
    c = (h9 + (1 << 24)) >> 25; h0 += c * 19; h9 -= c << 25;
    c = (h0 + (1 << 25)) >> 26; h1 += c; h0 -= c << 26;
    c = (h1 + (1 << 24)) >> 25; h2 += c; h1 -= c << 25;
    h[0] = (int32_t)h0; h[1] = (int32_t)h1; h[2] = (int32_t)h2; h[3] = (int32_t)h3;
    h[4] = (int32_t)h4; h[5] = (int32_t)h5; h[6] = (int32_t)h6; h[7] = (int32_t)h7;
    h[8] = (int32_t)h8; h[9] = (int32_t)h9;
}

inline void fe_sq(fe h, const fe f) {
    fe_mul(h, f, f);
}

inline void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    fe_sq(t0, z); fe_sq(t1, t0); fe_sq(t1, t1);
    fe_mul(t1, z, t1); fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2); fe_sq(t2, t1);
    for (int i = 1; i < 5; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t1); fe_sq(t2, t1);
    for (int i = 1; i < 10; ++i) fe_sq(t2, t2);
    fe_mul(t2, t2, t1); fe_sq(t3, t2);
    for (int i = 1; i < 20; ++i) fe_sq(t3, t3);
    fe_mul(t2, t3, t2); fe_sq(t2, t2);
    for (int i = 1; i < 10; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t1); fe_sq(t2, t1);
    for (int i = 1; i < 50; ++i) fe_sq(t2, t2);
    fe_mul(t2, t2, t1); fe_sq(t3, t2);
    for (int i = 1; i < 100; ++i) fe_sq(t3, t3);
    fe_mul(t2, t3, t2); fe_sq(t2, t2);
    for (int i = 1; i < 50; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t1); fe_sq(t1, t1);
    for (int i = 1; i < 5; ++i) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

inline void fe_cswap(fe p, fe q, int b) {
    int32_t mask = (int32_t)(-(int32_t)b);
    for (int i = 0; i < 10; ++i) { int32_t t = mask & (p[i] ^ q[i]); p[i] ^= t; q[i] ^= t; }
}

inline int fe_isnegative(const fe f) {
    uint8_t s[32];
    fe_tobytes(s, const_cast<int32_t*>(f));
    return s[0] & 1;
}

inline int fe_isnonzero(const fe f) {
    uint8_t s[32];
    fe_tobytes(s, const_cast<int32_t*>(f));
    int r = 0;
    for (int i = 0; i < 32; ++i) r |= s[i];
    return r;
}

inline int fe_equal(const fe f, const fe g) {
    fe t;
    fe_sub(t, f, g);
    return !fe_isnonzero(t);
}

static const int32_t sqrtm1_limbs[10] = {958640, -7943707, 9377950, 3500422, 12389472, -272473, 8408223, -2005645, 326686, 11406484};

inline void fe_pow22523(fe out, const fe z) {
    fe t0, t1, t2, t3;
    fe_sq(t0, z); fe_sq(t1, t0); fe_sq(t1, t1);
    fe_mul(t1, z, t1); fe_mul(t0, t0, t1);
    fe_sq(t0, t0); fe_mul(t0, t1, t0);
    fe_sq(t2, t0);
    for (int i = 1; i < 5; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t0);
    fe_sq(t2, t1);
    for (int i = 1; i < 10; ++i) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 1; i < 20; ++i) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (int i = 1; i < 10; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (int i = 1; i < 50; ++i) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 1; i < 100; ++i) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (int i = 1; i < 50; ++i) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (int i = 1; i < 5; ++i) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

inline int fe_sqrt_ratio(fe out, const fe u, const fe v) {
    fe uv3, uv7, r, s;
    fe_sq(uv3, v); fe_mul(uv3, uv3, v);
    fe_sq(uv7, uv3); fe_mul(uv7, uv7, v); fe_mul(uv7, uv7, u);
    fe_mul(uv3, u, uv3);
    fe_pow22523(r, uv7);
    fe_mul(r, r, uv3);
    fe_sq(s, r); fe_mul(s, s, v);
    if (fe_equal(s, u)) { fe_copy(out, r); return 1; }
    fe_mul(r, r, sqrtm1_limbs);
    fe_sq(s, r); fe_mul(s, s, v);
    if (fe_equal(s, u)) { fe_copy(out, r); return 2; }
    fe_0(out);
    return 0;
}

} // namespace fe_impl
} // namespace jpssl
