
#ifdef JPSSL_ED25519_R51
// r51 后端：fe 类型与 fe_* 操作由包含方 (ed25519_r51.cpp) 提供转发
#else
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
using fe_impl::fe_sq2;
#endif

// ═══════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════

// d = -(121665/121666) mod p
// d2 = 2*d mod p
// Basepoint B affine coordinates (RFC 8032 §5.1)
static const auto d_limbs() {
    static fe d;
    static bool init = false;
    if (!init) {
        init = true;
        uint8_t bytes[32] = {163,120,89,19,202,77,235,117,171,216,65,65,77,10,112,0,152,232,121,119,121,64,199,140,115,254,111,43,238,108,3,82};
        fe_frombytes(d, bytes);
    }
    return d;
}
static const auto d2_limbs() {
    static fe d;
    static bool init = false;
    if (!init) {
        init = true;
        uint8_t bytes[32] = {89,241,178,38,148,155,214,235,86,177,131,130,154,20,224,0,48,209,243,238,242,128,142,25,231,252,223,86,220,217,6,36};
        fe_frombytes(d, bytes);
    }
    return d;
}
static const auto Bx_limbs() {
    static fe x;
    static bool init = false;
    if (!init) {
        init = true;
        uint8_t bytes[32] = {26,213,37,143,96,45,86,201,178,167,37,149,96,199,44,105,92,220,214,253,49,226,164,192,254,83,110,205,211,54,105,33};
        fe_frombytes(x, bytes);
    }
    return x;
}
static const auto By_limbs() {
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
            __uint128_t carry = 0;
            for (int j = 0; j < 4; j++) {
                carry += (__uint128_t)hi[pos] * S64[j] + p[j];
                p[j] = (uint64_t)carry;
                carry >>= 64;
            }
            p[4] = (uint64_t)carry;
            carry = 0;
            for (int j = 0; j < 5; j++) {
                carry += (__uint128_t)t[j + pos] + p[j];
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
    for (int i = 0; i < 20; i++) {
        int cmp = 0;
        for (int j = 3; j >= 0; j--) {
            if (t[j] > L64[j]) { cmp = 1; break; }
            if (t[j] < L64[j]) { cmp = -1; break; }
        }
        if (cmp <= 0) break;
        uint64_t borrow = 0;
        for (int j = 0; j < 4; j++) {
            __uint128_t r = (__uint128_t)t[j] - L64[j] - borrow;
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
        __uint128_t carry = 0;
        for (int j = 0; j < 4; j++) {
            carry += (__uint128_t)a_l[i] * b_l[j] + p[i + j];
            p[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        // Propagate carry beyond the product range
        int idx = i + 4;
        while (carry && idx < 8) {
            carry += p[idx];
            p[idx] = (uint64_t)carry;
            carry >>= 64;
            idx++;
        }
    }
    __uint128_t carry = 0;
    for (int i = 0; i < 8; i++) {
        carry += (__uint128_t)p[i] + (i < 4 ? (__uint128_t)c_l[i] : (__uint128_t)0);
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
    __uint128_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        borrow = (__uint128_t)L64[i] - a_l[i] - borrow;
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
    fe t0;
    fe_sq(r->X, p->X);       // X = A = X^2
    fe_sq(r->Z, p->Y);       // Z = B = Y^2
    fe_sq2(r->T, p->Z);      // T = C = 2*Z^2
    fe_add(r->Y, p->X, p->Y); // Y = X+Y
    fe_sq(t0, r->Y);          // t0 = (X+Y)^2
    fe_add(r->Y, r->Z, r->X); // Y = B+A = A+B (H)
    fe_sub(r->Z, r->Z, r->X); // Z = B-A (G)
    fe_sub(r->X, t0, r->Y);   // X = (X+Y)^2 - (A+B) = 2XY (E)
    fe_sub(r->T, r->T, r->Z); // T = C - (B-A) = A-B+2Z^2 (F)
}

static void ge_p3_dbl(ge_p1p1* r, const ge_p3* p) {
    ge_p2 q;
    ge_p3_to_p2(&q, p);
    ge_p2_dbl(r, &q);
}

static void ge_add(ge_p1p1* r, const ge_p3* p, const ge_p3* q) {
    fe t0, a, b, c, d;
    fe_add(a, p->Y, p->X);          // a = Y1+X1
    fe_sub(b, p->Y, p->X);          // b = Y1-X1
    fe_sub(c, q->Y, q->X);          // c = Y2-X2
    fe_add(d, q->Y, q->X);          // d = Y2+X2
    fe_mul(a, a, d);                // a = (Y1+X1)*(Y2+X2)
    fe_mul(b, b, c);                // b = (Y1-X1)*(Y2-X2)
    fe_mul(c, p->T, q->T);
    fe_mul(c, c, d2_limbs());       // c = T1*T2*2d
    fe_mul(d, p->Z, q->Z);
    fe_add(d, d, d);                // d = 2*Z1*Z2
    fe_sub(r->X, a, b);             // X = E = (Y1+X1)(Y2+X2) - (Y1-X1)(Y2-X2)
    fe_add(r->Y, a, b);             // Y = H = (Y1+X1)(Y2+X2) + (Y1-X1)(Y2-X2)
    fe_add(r->Z, d, c);             // Z = G = 2*Z1*Z2 + T1*T2*2d
    fe_sub(r->T, d, c);             // T = F = 2*Z1*Z2 - T1*T2*2d
}

static void ge_sub(ge_p1p1* r, const ge_p3* p, const ge_p3* q) {
    fe a, b, c, d;
    fe_add(a, p->Y, p->X);          // a = Y1+X1
    fe_sub(b, p->Y, p->X);          // b = Y1-X1
    fe_add(c, q->Y, q->X);          // c = Y2+X2 (swapped for subtraction)
    fe_sub(d, q->Y, q->X);          // d = Y2-X2 (swapped for subtraction)
    fe_mul(a, a, d);                // a = (Y1+X1)*(Y2-X2)
    fe_mul(b, b, c);                // b = (Y1-X1)*(Y2+X2)
    fe_mul(c, p->T, q->T);
    fe_mul(c, c, d2_limbs());
    fe_neg(c, c);                   // c = -T1*T2*2d
    fe_mul(d, p->Z, q->Z);
    fe_add(d, d, d);                // d = 2*Z1*Z2
    fe_sub(r->X, a, b);             // X = E
    fe_add(r->Y, a, b);             // Y = H
    fe_add(r->Z, d, c);             // Z = G = 2*Z1*Z2 - T1*T2*2d
    fe_sub(r->T, d, c);             // T = F = 2*Z1*Z2 + T1*T2*2d
}

static void ge_madd(ge_p1p1* r, const ge_p3* p, const ge_precomp* q) {
    fe t0, a, b;
    fe_add(a, p->Y, p->X);          // a = Y1+X1
    fe_sub(b, p->Y, p->X);          // b = Y1-X1
    fe_mul(a, a, q->y_plus_x);      // a = (Y1+X1)*(Y2+X2)
    fe_mul(b, b, q->y_minus_x);     // b = (Y1-X1)*(Y2-X2)
    fe_mul(r->T, q->xy2d, p->T);    // T = T1*T2*2d
    fe_add(t0, p->Z, p->Z);        // t0 = 2*Z1 (Z2=1 for precomp)
    fe_sub(r->X, a, b);             // X = E
    fe_add(r->Y, a, b);             // Y = H
    fe_add(r->Z, t0, r->T);         // Z = G = 2*Z1 + T1*T2*2d
    fe_sub(r->T, t0, r->T);         // T = F = 2*Z1 - T1*T2*2d
}

static void ge_msub(ge_p1p1* r, const ge_p3* p, const ge_precomp* q) {
    fe t0, a, b;
    fe_add(a, p->Y, p->X);          // a = Y1+X1
    fe_sub(b, p->Y, p->X);          // b = Y1-X1
    fe_mul(a, a, q->y_minus_x);      // a = (Y1+X1)*(Y2-X2) (swapped for sub)
    fe_mul(b, b, q->y_plus_x);      // b = (Y1-X1)*(Y2+X2) (swapped for sub)
    fe_mul(r->T, q->xy2d, p->T);    // T = T1*T2*2d
    fe_neg(r->T, r->T);            // T = -T1*T2*2d
    fe_add(t0, p->Z, p->Z);        // t0 = 2*Z1
    fe_sub(r->X, a, b);             // X = E
    fe_add(r->Y, a, b);             // Y = H
    fe_add(r->Z, t0, r->T);         // Z = G = 2*Z1 - T1*T2*2d
    fe_sub(r->T, t0, r->T);         // T = F = 2*Z1 + T1*T2*2d
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
    if (fe_isnegative(h->X) != (s[31] >> 7)) fe_neg(h->X, h->X);
    fe_mul(h->T, h->X, h->Y);
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


// ═══════════════════════════════════════════════════════════════════
//  4-bit 窗口标量乘 + basepoint 预计算表 + 双标量乘（仿 ed448 已验证骨架）
// ═══════════════════════════════════════════════════════════════════

/// 构建 4-bit 窗口表：table[i] = i*P（i=0..15）
static void point_table_build(ge_p3 table[16], const ge_p3& P) {
    ge_p3_0(&table[0]);
    ge_p3_to_p3(&table[1], &P);
    for (int i = 2; i < 16; ++i) {
        ge_p1p1 t;
        ge_add(&t, &table[i - 1], &P);
        ge_p1p1_to_p3(&table[i], &t);
    }
}

/// 静态 basepoint 4-bit 窗口表（一次性构建）
static const ge_p3* basepoint_table() {
    static ge_p3 table[16];
    static bool init = false;
    if (!init) {
        point_table_build(table, *ge_get_basepoint());
        init = true;
    }
    return table;
}

/// 提取标量第 bitpos 位起的 4-bit 窗口（小端位序）
static inline int extract_window4(const uint8_t scalar[32], int bitpos) {
    int w = 0;
    for (int b = 0; b < 4; ++b) {
        int i = bitpos + b;
        w |= ((scalar[i >> 3] >> (i & 7)) & 1) << b;
    }
    return w;
}

/// 4-bit 窗口标量乘：R = scalar * P（P 用预计算表，256 位 = 64 窗口）
static void scalar_mult_windows(ge_p3& R, const uint8_t scalar[32], const ge_p3 table[16]) {
    ge_p3_0(&R);
    for (int wi = 63; wi >= 0; --wi) {
        for (int j = 0; j < 4; ++j) {
            ge_p1p1 d;
            ge_p3_dbl(&d, &R);
            ge_p1p1_to_p3(&R, &d);
        }
        int w = extract_window4(scalar, 4 * wi);
        ge_p1p1 tmp;
        ge_add(&tmp, &R, &table[w]);
        ge_p1p1_to_p3(&R, &tmp);
    }
}

/// 提取标量第 bitpos 位起的 8-bit 窗口
static inline int extract_window8(const uint8_t scalar[32], int bitpos) {
    int w = 0;
    for (int b = 0; b < 8; ++b) {
        int i = bitpos + b;
        if (i < 256) w |= ((scalar[i >> 3] >> (i & 7)) & 1) << b;
    }
    return w;
}

/// 8-bit 窗口标量乘（OpenSSL 同款 comb 表）：R = scalar * P，256 位 = 32 窗口
/// 表 256 项（w*P），省一半查表加（32 vs 64）
static void scalar_mult_windows8(ge_p3& R, const uint8_t scalar[32], const ge_p3 table[256]) {
    // 初始化为最高窗口
    ge_p3_to_p3(&R, &table[extract_window8(scalar, 248)]);
    for (int wi = 30; wi >= 0; --wi) {
        for (int j = 0; j < 8; ++j) {
            ge_p1p1 d;
            ge_p3_dbl(&d, &R);
            ge_p1p1_to_p3(&R, &d);
        }
        int w = extract_window8(scalar, 8 * wi);
        ge_p1p1 tmp;
        ge_add(&tmp, &R, &table[w]);
        ge_p1p1_to_p3(&R, &tmp);
    }
}

/// 静态 basepoint 8-bit 窗口表（256 项，一次性构建）
static const ge_p3* basepoint_table8() {
    static ge_p3 table[256];
    static bool init = false;
    if (!init) {
        ge_p3_0(&table[0]);
        ge_p3_to_p3(&table[1], ge_get_basepoint());
        for (int i = 2; i < 256; ++i) {
            ge_p1p1 t;
            ge_add(&t, &table[i - 1], ge_get_basepoint());
            ge_p1p1_to_p3(&table[i], &t);
        }
        init = true;
    }
    return table;
}

/// ge_p3 → ge_precomp（y_plus_x, y_minus_x, xy2d）
/// ge_madd 需要仿射坐标（Z=1），先归一化
static void ge_p3_to_precomp(ge_precomp* r, const ge_p3* p) {
    fe z_inv, x, y;
    fe_invert(z_inv, p->Z);
    fe_mul(x, p->X, z_inv);
    fe_mul(y, p->Y, z_inv);
    fe_add(r->y_plus_x, y, x);
    fe_sub(r->y_minus_x, y, x);
    fe_mul(r->xy2d, x, y);
    fe_mul(r->xy2d, r->xy2d, d2_limbs());
}

/// ge_precomp 8-bit 表（256 项 = w*B，OpenSSL 同款 ge_madd 部分加）
static const ge_precomp* basepoint_table8_precomp() {
    static ge_precomp table[256];
    static bool init = false;
    if (!init) {
        // 用现有 ge_p3 8-bit 表转换（basepoint_table8 已一次性构建）
        const ge_p3* p3 = basepoint_table8();
        for (int i = 0; i < 256; ++i)
            ge_p3_to_precomp(&table[i], &p3[i]);
        init = true;
    }
    return table;
}

/// 8-bit 窗口标量乘（ge_madd 部分加，省一半 fe_mul）
static void scalar_mult_windows8_precomp(ge_p3& R, const uint8_t scalar[32], const ge_precomp table[256]) {
    ge_p3_0(&R);
    for (int wi = 31; wi >= 0; --wi) {
        for (int j = 0; j < 8; ++j) {
            ge_p1p1 d;
            ge_p3_dbl(&d, &R);
            ge_p1p1_to_p3(&R, &d);
        }
        int w = extract_window8(scalar, 8 * wi);
        ge_p1p1 tmp;
        ge_madd(&tmp, &R, &table[w]);
        ge_p1p1_to_p3(&R, &tmp);
    }
}

/// 双标量乘（Strauss-Shamir 窗口化）：R = s1*P1 + s2*P2
/// 两标量同时扫描共享倍点链，64 窗口 × (4 倍点 + 2 查表加)
static void double_scalar_mult(ge_p3& R,
                               const uint8_t s1[32], const ge_p3 t1[16],
                               const uint8_t s2[32], const ge_p3 t2[16]) {
    ge_p3_0(&R);
    for (int wi = 63; wi >= 0; --wi) {
        for (int j = 0; j < 4; ++j) {
            ge_p1p1 d;
            ge_p3_dbl(&d, &R);
            ge_p1p1_to_p3(&R, &d);
        }
        int w1 = extract_window4(s1, 4 * wi);
        int w2 = extract_window4(s2, 4 * wi);
        ge_p1p1 tmp;
        ge_add(&tmp, &R, &t1[w1]);
        ge_p1p1_to_p3(&R, &tmp);
        ge_add(&tmp, &R, &t2[w2]);
        ge_p1p1_to_p3(&R, &tmp);
    }
}
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
    scalar_mult_windows8_precomp(A, h, basepoint_table8_precomp());
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
    scalar_mult_windows8_precomp(R, r_scalar, basepoint_table8_precomp());
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

    // k_neg = (L - k) mod L（字节减法；k==0 时归零）
    uint8_t k_neg[32];
    {
        static const uint8_t L_BYTES[32] = {
            0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10
        };
        uint64_t borrow = 0;
        for (int i = 0; i < 32; ++i) {
            uint64_t d = (uint64_t)L_BYTES[i] - (uint64_t)hram[i] - borrow;
            k_neg[i] = (uint8_t)d;
            borrow = (L_BYTES[i] < hram[i] + borrow) ? 1 : 0;
        }
        if (memcmp(k_neg, L_BYTES, 32) == 0) memset(k_neg, 0, 32);
    }

    // T = S*B + k_neg*A（双标量乘，共享倍点链）
    ge_p3 A_table[16];
    point_table_build(A_table, A);
    ge_p3 T;
    double_scalar_mult(T, sig + 32, basepoint_table(), k_neg, A_table);

    // 投影坐标相等性检查：T == R ⇔ (T.X*R.Z==R.X*T.Z) && (T.Y*R.Z==R.Y*T.Z)
    fe lhs_x, rhs_x, lhs_y, rhs_y;
    fe_mul(lhs_x, T.X, R.Z);
    fe_mul(rhs_x, R.X, T.Z);
    fe_mul(lhs_y, T.Y, R.Z);
    fe_mul(rhs_y, R.Y, T.Z);
    if (memcmp(lhs_x, rhs_x, sizeof(fe)) != 0) return false;
    if (memcmp(lhs_y, rhs_y, sizeof(fe)) != 0) return false;
    return true;
}
