#include "ed25519.hpp"
#include "fe_25519.hpp"
#include "sha512.hpp"
#include <cstring>
#include <random>

namespace jpssl {
namespace {

using fe = fe_impl::fe;
using fe_impl::fe_frombytes;
using fe_impl::fe_tobytes;
using fe_impl::fe_0;
using fe_impl::fe_1;
using fe_impl::fe_copy;
using fe_impl::fe_add;
using fe_impl::fe_sub;
using fe_impl::fe_neg;
using fe_impl::fe_mul;
using fe_impl::fe_sq;
using fe_impl::fe_invert;
using fe_impl::fe_cswap;
using fe_impl::fe_isnegative;
using fe_impl::fe_isnonzero;
using fe_impl::fe_equal;
using fe_impl::fe_pow22523;
using fe_impl::fe_sqrt_ratio;

// ═══════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════

// d = -(121665/121666) mod p
// d2 = 2*d mod p
// Basepoint B affine coordinates (RFC 8032 §5.1)
static const int32_t* d_limbs() {
    static fe d;
    static bool init = false;
    if (!init) {
        init = true;
        uint8_t bytes[32] = {163,120,89,19,202,77,235,117,171,216,65,65,77,10,112,0,152,232,121,119,121,64,199,140,115,254,111,43,238,108,3,82};
        fe_frombytes(d, bytes);
    }
    return d;
}
static const int32_t* d2_limbs() {
    static fe d;
    static bool init = false;
    if (!init) {
        init = true;
        uint8_t bytes[32] = {89,241,178,38,148,155,214,235,86,177,131,130,154,20,224,0,48,209,243,238,242,128,142,25,231,252,223,86,220,217,6,36};
        fe_frombytes(d, bytes);
    }
    return d;
}
static const int32_t* Bx_limbs() {
    static fe x;
    static bool init = false;
    if (!init) {
        init = true;
        uint8_t bytes[32] = {148,59,97,128,114,104,141,41,245,123,43,86,22,125,36,239,189,229,9,244,90,53,236,174,94,133,111,205,211,54,105,33};
        fe_frombytes(x, bytes);
    }
    return x;
}
static const int32_t* By_limbs() {
    static fe y;
    static bool init = false;
    if (!init) {
        init = true;
        uint8_t bytes[32] = {88,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102};
        fe_frombytes(y, bytes);
    }
    return y;
}

// ═══════════════════════════════════════════════════════════════════
//  Scalar arithmetic modulo l
//  l = 2^252 + 27742317777372353535851937790883648493
// ═══════════════════════════════════════════════════════════════════

static constexpr uint64_t L64[4] = {
    0x5812631a5cf5d3ed, 0x14def9dea2f79cd6,
    0x0000000000000000, 0x1000000000000000
};

static constexpr uint64_t S64[4] = {
    0xd6ec31748d98951d, 0xc6ef5bf4737dcf70,
    0xfffffffffffffffe, 0x0fffffffffffffff
};

static void sc_load_64(uint64_t r[4], const uint8_t* b) {
    for (int i = 0; i < 4; i++)
        r[i] = (uint64_t)b[8*i] | ((uint64_t)b[8*i+1] << 8) |
               ((uint64_t)b[8*i+2] << 16) | ((uint64_t)b[8*i+3] << 24) |
               ((uint64_t)b[8*i+4] << 32) | ((uint64_t)b[8*i+5] << 40) |
               ((uint64_t)b[8*i+6] << 48) | ((uint64_t)b[8*i+7] << 56);
}

static void sc_store_64(uint8_t* b, const uint64_t r[4]) {
    for (int i = 0; i < 4; i++) {
        b[8*i] = r[i] & 0xFF;
        b[8*i+1] = (r[i] >> 8) & 0xFF;
        b[8*i+2] = (r[i] >> 16) & 0xFF;
        b[8*i+3] = (r[i] >> 24) & 0xFF;
        b[8*i+4] = (r[i] >> 32) & 0xFF;
        b[8*i+5] = (r[i] >> 40) & 0xFF;
        b[8*i+6] = (r[i] >> 48) & 0xFF;
        b[8*i+7] = (r[i] >> 56) & 0xFF;
    }
}

static void sc_reduce(uint8_t h[64]) {
    uint64_t t[8];
    sc_load_64(t, h);
    sc_load_64(t + 4, h + 32);
    for (int pass = 0; pass < 200; pass++) {
        if ((t[4] | t[5] | t[6] | t[7]) == 0) break;
        uint64_t hi[4] = {t[4], t[5], t[6], t[7]};
        t[4] = t[5] = t[6] = t[7] = 0;
        for (int pos = 0; pos < 4; pos++) {
            if (hi[pos] == 0) continue;
            uint64_t p[5] = {0, 0, 0, 0, 0};
            unsigned __int128 carry = 0;
            for (int j = 0; j < 4; j++) {
                carry += (unsigned __int128)hi[pos] * S64[j] + p[j];
                p[j] = (uint64_t)carry;
                carry >>= 64;
            }
            p[4] = (uint64_t)carry;
            carry = 0;
            for (int j = 0; j < 5; j++) {
                carry += (unsigned __int128)t[j + pos] + p[j];
                t[j + pos] = (uint64_t)carry;
                carry >>= 64;
            }
            for (int j = 5 + pos; carry && j < 8; j++) {
                carry += t[j];
                t[j] = (uint64_t)carry;
                carry >>= 64;
            }
        }
    }
    for (int i = 0; i < 10; i++) {
        int cmp = 0;
        for (int j = 3; j >= 0; j--) {
            if (t[j] > L64[j]) { cmp = 1; break; }
            if (t[j] < L64[j]) { cmp = -1; break; }
        }
        if (cmp < 0) break;
        uint64_t borrow = 0;
        for (int j = 0; j < 4; j++) {
            unsigned __int128 r = (unsigned __int128)t[j] - L64[j] - borrow;
            t[j] = (uint64_t)r;
            borrow = (uint64_t)(r >> 64) & 1;
        }
    }
    sc_store_64(h, t);
}

static void sc_mul_add(uint8_t* out, const uint8_t* a, const uint8_t* b, const uint8_t* c) {
    uint64_t a_l[4], b_l[4], c_l[4];
    sc_load_64(a_l, a);
    sc_load_64(b_l, b);
    sc_load_64(c_l, c);
    uint64_t p[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            carry += (unsigned __int128)a_l[i] * b_l[j] + p[i + j];
            p[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        p[i + 4] += (uint64_t)carry;
    }
    unsigned __int128 carry = 0;
    for (int i = 0; i < 8; i++) {
        carry += p[i] + (i < 4 ? c_l[i] : 0);
        p[i] = (uint64_t)carry;
        carry >>= 64;
    }
    uint8_t buf[64];
    sc_store_64(buf, p);
    sc_store_64(buf + 32, p + 4);
    sc_reduce(buf);
    memcpy(out, buf, 32);
}

static void sc_negate(uint8_t r[32], const uint8_t a[32]) {
    uint64_t a_l[4];
    sc_load_64(a_l, a);
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 4; i++) {
        borrow = (unsigned __int128)L64[i] - a_l[i] - borrow;
        a_l[i] = (uint64_t)borrow;
        borrow >>= 64;
    }
    sc_store_64(r, a_l);
}

// ═══════════════════════════════════════════════════════════════════
//  Point types and operations
// ═══════════════════════════════════════════════════════════════════

struct ge_p3 { fe X, Y, Z, T; };
struct ge_p2 { fe X, Y, Z; };
struct ge_p1p1 { fe X, Y, Z, T; };
struct ge_precomp { fe y_plus_x, y_minus_x, xy2d; };

static void ge_p2_0(ge_p2* h) { fe_0(h->X); fe_1(h->Y); fe_1(h->Z); }
static void ge_p3_0(ge_p3* h) { fe_0(h->X); fe_1(h->Y); fe_1(h->Z); fe_0(h->T); }

static void ge_p3_to_p2(ge_p2* r, const ge_p3* p) {
    fe_copy(r->X, p->X); fe_copy(r->Y, p->Y); fe_copy(r->Z, p->Z);
}

static void ge_p3_to_p3(ge_p3* r, const ge_p3* p) {
    fe_copy(r->X, p->X); fe_copy(r->Y, p->Y);
    fe_copy(r->Z, p->Z); fe_copy(r->T, p->T);
}

static void ge_p1p1_to_p2(ge_p2* r, const ge_p1p1* p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
}

static void ge_p1p1_to_p3(ge_p3* r, const ge_p1p1* p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
    fe_mul(r->T, p->X, p->Y);
}

static void ge_p2_dbl(ge_p1p1* r, const ge_p2* p) {
    fe a, b, c, e, g, f, h, t;
    fe_sq(a, p->X);
    fe_sq(b, p->Y);
    fe_sq(c, p->Z);
    fe_add(c, c, c);
    fe_add(t, p->X, p->Y);
    fe_sq(t, t);
    fe_sub(t, t, a);
    fe_sub(e, t, b);
    fe_sub(g, b, a);
    fe_sub(f, g, c);
    fe_add(h, a, b);
    fe_neg(h, h);
    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h);
    fe_mul(r->Z, f, g);
}

static void ge_p3_dbl(ge_p1p1* r, const ge_p3* p) {
    ge_p2 q;
    ge_p3_to_p2(&q, p);
    ge_p2_dbl(r, &q);
}

static void ge_add(ge_p1p1* r, const ge_p3* p, const ge_p3* q) {
    fe a, b, c, d, e, f, g, h, t;
    fe_sub(a, p->Y, p->X);
    fe_sub(t, q->Y, q->X);
    fe_mul(a, a, t);
    fe_add(b, p->Y, p->X);
    fe_add(t, q->Y, q->X);
    fe_mul(b, b, t);
    fe_mul(c, p->T, q->T);
    fe_mul(c, c, d2_limbs());
    fe_mul(d, p->Z, q->Z);
    fe_add(d, d, d);
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);
    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h);
    fe_mul(r->Z, f, g);
}

static void ge_sub(ge_p1p1* r, const ge_p3* p, const ge_p3* q) {
    fe a, b, c, d, e, f, g, h, t;
    fe_sub(a, p->Y, p->X);
    fe_add(t, q->Y, q->X);
    fe_mul(a, a, t);
    fe_add(b, p->Y, p->X);
    fe_sub(t, q->Y, q->X);
    fe_mul(b, b, t);
    fe_mul(c, p->T, q->T);
    fe_mul(c, c, d2_limbs());
    fe_neg(c, c);
    fe_mul(d, p->Z, q->Z);
    fe_add(d, d, d);
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);
    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h);
    fe_mul(r->Z, f, g);
}

static void ge_madd(ge_p1p1* r, const ge_p3* p, const ge_precomp* q) {
    fe a, b, c, d, e, f, g, h;
    fe_sub(a, p->Y, p->X);
    fe_mul(a, a, q->y_minus_x);
    fe_add(b, p->Y, p->X);
    fe_mul(b, b, q->y_plus_x);
    fe_mul(c, p->T, q->xy2d);
    fe_add(d, p->Z, p->Z);
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);
    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h);
    fe_mul(r->Z, f, g);
}

static void ge_msub(ge_p1p1* r, const ge_p3* p, const ge_precomp* q) {
    fe a, b, c, d, e, f, g, h;
    fe_sub(a, p->Y, p->X);
    fe_mul(a, a, q->y_plus_x);
    fe_add(b, p->Y, p->X);
    fe_mul(b, b, q->y_minus_x);
    fe_mul(c, p->T, q->xy2d);
    fe_neg(c, c);
    fe_add(d, p->Z, p->Z);
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);
    fe_mul(r->X, e, f);
    fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h);
    fe_mul(r->Z, f, g);
}

// ═══════════════════════════════════════════════════════════════════
//  Point decompression / compression
// ═══════════════════════════════════════════════════════════════════

static int ge_frombytes(ge_p3* h, const uint8_t s[32]) {
    fe u, v;
    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq(u, h->Y);
    fe_mul(v, u, d_limbs());
    fe_add(v, v, h->Z);
    fe_sub(u, u, h->Z);
    int ret = fe_sqrt_ratio(h->X, u, v);
    if (ret == 0) return -1;
    fe_mul(h->T, h->X, h->Y);
    if (fe_isnegative(h->X) != (s[31] >> 7)) fe_neg(h->X, h->X);
    return 0;
}

static void ge_tobytes(uint8_t s[32], const ge_p3* h) {
    fe recip, x, y;
    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    if (fe_isnegative(x)) s[31] |= 0x80;
}

// ═══════════════════════════════════════════════════════════════════
//  Basepoint
// ═══════════════════════════════════════════════════════════════════

static const ge_p3* ge_get_basepoint() {
    static ge_p3 B;
    static int init = 0;
    if (!init) {
        init = 1;
        fe_copy(B.X, Bx_limbs());
        fe_copy(B.Y, By_limbs());
        fe_1(B.Z);
        fe_mul(B.T, B.X, B.Y);
    }
    return &B;
}

// ═══════════════════════════════════════════════════════════════════
//  Precomputed basepoint table
// ═══════════════════════════════════════════════════════════════════

static const ge_precomp* ge_get_table() {
    static ge_precomp table[32][8];
    static int init = 0;
    if (!init) {
        init = 1;
        const ge_p3* Bp = ge_get_basepoint();
        ge_p3 cur, sum, tmp;
        ge_p3_to_p3(&cur, Bp);
        ge_p3_to_p3(&sum, Bp);
        for (int i = 0; i < 32; i++) {
            for (int j = 0; j < 8; j++) {
                if (j == 0) {
                    fe_sub(table[i][j].y_minus_x, sum.Y, sum.X);
                    fe_add(table[i][j].y_plus_x, sum.Y, sum.X);
                    fe_mul(table[i][j].xy2d, sum.X, sum.Y);
                    fe_mul(table[i][j].xy2d, table[i][j].xy2d, d2_limbs());
                } else {
                    ge_p1p1 t;
                    ge_add(&t, &sum, Bp);
                    ge_p1p1_to_p3(&sum, &t);
                    fe_sub(table[i][j].y_minus_x, sum.Y, sum.X);
                    fe_add(table[i][j].y_plus_x, sum.Y, sum.X);
                    fe_mul(table[i][j].xy2d, sum.X, sum.Y);
                    fe_mul(table[i][j].xy2d, table[i][j].xy2d, d2_limbs());
                }
            }
            for (int j = 0; j < 8; j++) {
                ge_p1p1 t;
                ge_p2_dbl(&t, (const ge_p2*)&cur);
                ge_p1p1_to_p3(&cur, &t);
            }
            ge_p3_to_p3(&sum, &cur);
        }
    }
    return &table[0][0];
}

// ═══════════════════════════════════════════════════════════════════
//  Scalar multiplication
// ═══════════════════════════════════════════════════════════════════

static void ge_scalarmult_base(ge_p3* r, const uint8_t scalar[32]) {
    const ge_p3* B = ge_get_basepoint();
    int first = -1;
    for (int i = 255; i >= 0; i--)
        if ((scalar[i >> 3] >> (i & 7)) & 1) { first = i; break; }
    if (first < 0) { ge_p3_0(r); return; }
    ge_p3_to_p3(r, B);
    for (int i = first - 1; i >= 0; i--) {
        ge_p1p1 t;
        ge_p3_dbl(&t, r);
        ge_p1p1_to_p3(r, &t);
        if ((scalar[i >> 3] >> (i & 7)) & 1) {
            ge_p1p1 t2;
            ge_add(&t2, r, B);
            ge_p1p1_to_p3(r, &t2);
        }
    }
}

static void ge_scalarmult(ge_p3* r, const uint8_t scalar[32], const ge_p3* P) {
    int first = -1;
    for (int i = 255; i >= 0; i--)
        if ((scalar[i >> 3] >> (i & 7)) & 1) { first = i; break; }
    if (first < 0) { ge_p3_0(r); return; }
    ge_p3_to_p3(r, P);
    for (int i = first - 1; i >= 0; i--) {
        ge_p1p1 t;
        ge_p3_dbl(&t, r);
        ge_p1p1_to_p3(r, &t);
        if ((scalar[i >> 3] >> (i & 7)) & 1) {
            ge_p1p1 t2;
            ge_add(&t2, r, P);
            ge_p1p1_to_p3(r, &t2);
        }
    }
}

static void ge_double_scalarmult_vartime(ge_p3* r, const uint8_t a[32], const ge_p3* A,
                                          const uint8_t b[32], const ge_p3* B) {
    int first = -1;
    for (int i = 255; i >= 0; i--) {
        int bit_a = (a[i >> 3] >> (i & 7)) & 1;
        int bit_b = (b[i >> 3] >> (i & 7)) & 1;
        if (bit_a || bit_b) { first = i; break; }
    }
    if (first < 0) { ge_p3_0(r); return; }
    int ba = (a[first >> 3] >> (first & 7)) & 1;
    int bb = (b[first >> 3] >> (first & 7)) & 1;
    if (ba && bb) {
        ge_p1p1 t; ge_add(&t, A, B); ge_p1p1_to_p3(r, &t);
    } else if (ba) {
        ge_p3_to_p3(r, A);
    } else {
        ge_p3_to_p3(r, B);
    }
    for (int i = first - 1; i >= 0; i--) {
        ge_p1p1 t;
        ge_p3_dbl(&t, r);
        ge_p1p1_to_p3(r, &t);
        if ((a[i >> 3] >> (i & 7)) & 1) {
            ge_p1p1 t2; ge_add(&t2, r, A); ge_p1p1_to_p3(r, &t2);
        }
        if ((b[i >> 3] >> (i & 7)) & 1) {
            ge_p1p1 t2; ge_add(&t2, r, B); ge_p1p1_to_p3(r, &t2);
        }
    }
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════════

void ed25519_keygen(uint8_t pub[32], uint8_t priv[64]) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    uint8_t seed[32];
    for (int i = 0; i < 4; ++i) {
        uint64_t v = gen();
        memcpy(seed + i * 8, &v, 8);
    }
    memcpy(priv, seed, 32);
    uint8_t h[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, h);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    ge_p3 A;
    ge_scalarmult_base(&A, h);
    ge_tobytes(pub, &A);
    memcpy(priv + 32, pub, 32);
}

void ed25519_sign(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]) {
    uint8_t h[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, priv, 32);
    sha512_final(&ctx, h);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    uint8_t s[32];
    memcpy(s, h, 32);
    uint8_t* prefix = h + 32;
    uint8_t r_hash[64];
    sha512_init(&ctx);
    sha512_update(&ctx, prefix, 32);
    sha512_update(&ctx, msg, msg_len);
    sha512_final(&ctx, r_hash);
    sc_reduce(r_hash);
    uint8_t r_scalar[32];
    memcpy(r_scalar, r_hash, 32);
    ge_p3 R;
    ge_scalarmult_base(&R, r_scalar);
    ge_tobytes(sig, &R);
    sha512_init(&ctx);
    sha512_update(&ctx, sig, 32);
    sha512_update(&ctx, priv + 32, 32);
    sha512_update(&ctx, msg, msg_len);
    sha512_final(&ctx, r_hash);
    sc_reduce(r_hash);
    sc_mul_add(sig + 32, r_hash, s, r_scalar);
}

bool ed25519_verify(const uint8_t pub[32], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]) {
    ge_p3 A, R;
    if (ge_frombytes(&A, pub) != 0) return false;
    if (ge_frombytes(&R, sig) != 0) return false;
    {
        uint64_t s_l[4];
        sc_load_64(s_l, sig + 32);
        int cmp = 0;
        for (int j = 3; j >= 0; j--) {
            if (s_l[j] > L64[j]) { cmp = 1; break; }
            if (s_l[j] < L64[j]) { cmp = -1; break; }
        }
        if (cmp >= 0) return false;
    }
    uint8_t hram[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, sig, 32);
    sha512_update(&ctx, pub, 32);
    sha512_update(&ctx, msg, msg_len);
    sha512_final(&ctx, hram);
    sc_reduce(hram);
    uint8_t neg_k[32];
    sc_negate(neg_k, hram);
    const ge_p3* B = ge_get_basepoint();
    ge_p3 expected_R;
    ge_double_scalarmult_vartime(&expected_R, neg_k, &A, sig + 32, B);
    uint8_t expected_bytes[32], r_bytes[32];
    ge_tobytes(expected_bytes, &expected_R);
    ge_tobytes(r_bytes, &R);
    return memcmp(expected_bytes, r_bytes, 32) == 0;
}

} // namespace jpssl
