/**
 * ed448_body.inc - Ed448 core implementation (shared by CPU/AVX2/AVX512 backends)
 *
 * Optimizations:
 *  - Extended coordinates (X,Y,Z,T): complete add 9M+1sM
 *    (Hisil-Wong-Carter-Dawson, a=1; safe for P=Q and identity),
 *    doubling 4M+4S including T3 (EFD dbl-2008-hwcd, a=1).
 *  - Fixed-base 4-bit precomputed table (112 windows x 16 points) for
 *    basepoint multiplication: 111 extended adds, no doublings.
 *  - Constant-time cmov table selection.
 *
 * Exports: ed448_keygen_impl / ed448_sign_impl / ed448_verify_impl
 * plus point helpers used by debug wrappers in ed448.cpp.
 */

using namespace jpssl::fe448_impl;

struct ed448_point_ext {
    fe448 X, Y, Z, T;   // extended coords, T = X*Y/Z
};

// d = -39081 mod p
static const uint8_t D_BYTES[56] = {
    0x56,0x67,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

// L (group order)
static const uint8_t L_BYTES[57] = {
    0xf3,0x44,0x58,0xab,0x92,0xc2,0x78,0x23,0x55,0x8f,0xc5,0x8d,
    0x72,0xc2,0x6c,0x21,0x90,0x36,0xd6,0xae,0x49,0xdb,0x4e,0xc4,
    0xe9,0x23,0xca,0x7c,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x3f,0x00
};

// Base point B (RFC 8032 Appendix A)
static const uint8_t B_ENCODED[57] = {
    0x14,0xfa,0x30,0xf2,0x5b,0x79,0x08,0x98,0xad,0xc8,0xd7,0x4e,
    0x2c,0x13,0xbd,0xfd,0xc4,0x39,0x7c,0xe6,0x1c,0xff,0xd3,0x3a,
    0xd7,0xc2,0xa0,0x05,0x1e,0x9c,0x78,0x87,0x40,0x98,0xa3,0x6c,
    0x73,0x73,0xea,0x4b,0x62,0xc7,0xc9,0x56,0x37,0x20,0x76,0x88,
    0x24,0xbc,0xb6,0x6e,0x71,0x46,0x3f,0x69,0x00
};

// ---- fast mod-L scalar arithmetic (u64 limbs; no generic bignum) ----
// L = 2^446 - delta; hence 2^448 == 4*delta (mod L), which lets us fold
// limbs >= 7 (weight 2^(64i) = 2^(64(i-7)) * 2^448) with one 64x226-bit
// multiply per limb.  After folding, a residue < 2^448 is conditionally
// reduced below L with at most 7 subtractions.
static const uint64_t SCALAR_L_LIMBS[7] = {
    0x2378c292ab5844f3ULL, 0x216cc2728dc58f55ULL, 0xc44edb49aed63690ULL,
    0xffffffff7cca23e9ULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL,
    0x3fffffffffffffffULL
};
static const uint64_t SCALAR_D4_LIMBS[4] = {
    0x721cf5b5529eec34ULL, 0x7a4cf635c8e9c2abULL, 0xeec492d944a725bfULL,
    0x000000020cd77058ULL
};

static bool scalar_ge_L(const uint64_t v[7]) {
    for (int i = 6; i >= 0; --i) {
        if (v[i] != SCALAR_L_LIMBS[i]) return v[i] > SCALAR_L_LIMBS[i];
    }
    return true;
}

// v -= L (requires v < 2L, i.e. at most one borrow chain)
static void scalar_sub_L(uint64_t v[7]) {
    uint64_t borrow = 0;
    for (int i = 0; i < 7; ++i) {
        uint64_t sub = SCALAR_L_LIMBS[i] + borrow;
        borrow = (sub < SCALAR_L_LIMBS[i] || v[i] < sub) ? 1 : 0;
        v[i] = v[i] - sub;
    }
}

// Reduce in (up to 16 little-endian u64 limbs) modulo L into out[7].
static void scalar_reduce_mod_L(uint64_t out[7], const uint64_t* in, int in_limbs) {
    uint64_t buf[18] = {0};
    if (in_limbs > 16) in_limbs = 16;
    memcpy(buf, in, (size_t)in_limbs * 8);

    for (int pass = 0; pass < 12; ++pass) {
        uint64_t acc[18] = {0};
        for (int i = 0; i < 7; ++i) acc[i] = buf[i];
        bool high = false;
        for (int i = 7; i < 18; ++i) {
            uint64_t xi = buf[i];
            if (!xi) continue;
            high = true;
            // t = xi * (4*delta), up to 5 limbs
            uint64_t t[5];
            uint64_t carry = 0;
            for (int k = 0; k < 4; ++k) {
                uint64_t hi = 0;
                uint64_t lo = fe448_mul64(xi, SCALAR_D4_LIMBS[k], &hi);
                uint64_t s = lo + carry;
                uint64_t ovf = (s < carry) ? 1 : 0;
                t[k] = s;
                carry = hi + ovf;
            }
            t[4] = carry;
            int j = i - 7;
            uint64_t c = 0;
            for (int k = 0; k < 5; ++k) {
                uint64_t s = acc[j + k] + t[k];
                uint64_t c1 = (s < acc[j + k]) ? 1 : 0;
                uint64_t s2 = s + c;
                uint64_t c2 = (s2 < s) ? 1 : 0;
                acc[j + k] = s2;
                c = c1 + c2;
            }
            int k = 5;
            while (c) {
                uint64_t s = acc[j + k] + c;
                c = (s < acc[j + k]) ? 1 : 0;
                acc[j + k] = s;
                ++k;
            }
        }
        memcpy(buf, acc, sizeof(buf));
        if (!high) break;
    }

    uint64_t v[7];
    memcpy(v, buf, sizeof(v));
    for (int tries = 0; tries < 8; ++tries) {
        if (!scalar_ge_L(v)) break;
        scalar_sub_L(v);
    }
    memcpy(out, v, sizeof(v));
}

// 8x8 (456-bit x 456-bit) schoolbook multiply -> 16 limbs.
static void scalar_mul_limbs(uint64_t p[16], const uint64_t a[8], const uint64_t b[8]) {
    memset(p, 0, 16 * sizeof(uint64_t));
    for (int i = 0; i < 8; ++i) {
        __uint128_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            carry += (__uint128_t)a[i] * b[j] + p[i + j];
            p[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        int k = i + 8;
        while (carry) {
            __uint128_t s = (__uint128_t)p[k] + (uint64_t)carry;
            p[k] = (uint64_t)s;
            carry = s >> 64;
            ++k;
        }
    }
}

// out = (a + b) mod L, with a, b < L (7 limbs each).
static void scalar_add_mod_L(uint64_t out[7], const uint64_t a[7], const uint64_t b[7]) {
    uint64_t carry = 0;
    for (int i = 0; i < 7; ++i) {
        uint64_t s = a[i] + b[i];
        uint64_t c1 = (s < a[i]) ? 1 : 0;
        uint64_t s2 = s + carry;
        uint64_t c2 = (s2 < s) ? 1 : 0;
        out[i] = s2;
        carry = c1 + c2;
    }
    (void)carry;  // a+b < 2L < 2^448: no limb-7 carry
    if (scalar_ge_L(out)) scalar_sub_L(out);
}

static void scalar_bytes_to_limbs(uint64_t* limbs, int n_limbs,
                                  const uint8_t* le, size_t n_bytes) {
    memset(limbs, 0, (size_t)n_limbs * 8);
    for (size_t i = 0; i < n_bytes && (i >> 3) < (size_t)n_limbs; ++i)
        limbs[i >> 3] |= (uint64_t)le[i] << (8 * (i & 7));
}

static void scalar_limbs_to_bytes(uint8_t* le, size_t n_bytes,
                                  const uint64_t* limbs, int n_limbs) {
    memset(le, 0, n_bytes);
    for (size_t i = 0; i < n_bytes && i < (size_t)n_limbs * 8; ++i)
        le[i] = (uint8_t)(limbs[i >> 3] >> (8 * (i & 7)));
}

// S (57 LE bytes) < L ?
static bool scalar_lt_L_bytes(const uint8_t le[57]) {
    for (int i = 56; i >= 0; --i) {
        if (le[i] != L_BYTES[i]) return le[i] < L_BYTES[i];
    }
    return false;
}

static void scalar_mod_L(const uint8_t in[114], uint8_t out[57]) {
    uint64_t limbs[15];
    scalar_bytes_to_limbs(limbs, 15, in, 114);
    uint64_t r[7];
    scalar_reduce_mod_L(r, limbs, 15);
    scalar_limbs_to_bytes(out, 57, r, 7);
}

// ---- field constants ----
static const fe448& fe448_one() {
    static fe448 one;
    static bool init = false;
    if (!init) { fe448_1(one); init = true; }
    return one;
}

static const fe448& get_d() {
    static fe448 d;
    static bool init = false;
    if (!init) { fe448_frombytes(d, D_BYTES); init = true; }
    return d;
}

// ---- point ops (extended coordinates) ----

static void point_zero(ed448_point_ext& P) {
    fe448_0(P.X); fe448_1(P.Y); fe448_1(P.Z); fe448_0(P.T);
}

static void point_copy(ed448_point_ext& dst, const ed448_point_ext& src) {
    fe448_copy(dst.X, src.X); fe448_copy(dst.Y, src.Y);
    fe448_copy(dst.Z, src.Z); fe448_copy(dst.T, src.T);
}

// Complete (strongly unified) addition for twisted Edwards, a=1
// (Hisil-Wong-Carter-Dawson). Works for P=Q and for the identity,
// so it is safe for table construction and windowed scalar mult.
// Cost: 9M + 1 mul-by-small-constant.
static void point_add_ext(ed448_point_ext& R,
                          const ed448_point_ext& P,
                          const ed448_point_ext& Q) {
    fe448 A, B, C, D, E, F, G, H, tmp, tmp2;

    fe448_mul(A, P.X, Q.X);
    fe448_mul(B, P.Y, Q.Y);
    fe448_mul(tmp, P.T, Q.T);
    fe448_mul_small(C, tmp, 39081);   // 39081*T1*T2
    fe448_neg(C, C);                  // C = d*T1*T2, d = -39081
    fe448_mul(D, P.Z, Q.Z);
    fe448_add(tmp, P.X, P.Y);
    fe448_add(tmp2, Q.X, Q.Y);
    fe448_mul(E, tmp, tmp2);
    fe448_sub(E, E, A);
    fe448_sub(E, E, B);               // E = (X1+Y1)(X2+Y2) - A - B
    fe448_sub(F, D, C);
    fe448_add(G, D, C);
    fe448_sub(H, B, A);
    fe448_mul(R.X, E, F);
    fe448_mul(R.Y, G, H);
    fe448_mul(R.T, E, H);
    fe448_mul(R.Z, F, G);
}

// Doubling, a=1 (EFD dbl-2008-hwcd): 4M + 4S, includes T3.
static void point_double_ext(ed448_point_ext& R, const ed448_point_ext& P) {
    fe448 A, B, C, E, F, G, H;
    fe448 tmp;

    fe448_sq(A, P.X);
    fe448_sq(B, P.Y);
    fe448_sq(C, P.Z);                  // C = Z^2
    fe448_add(tmp, P.X, P.Y);
    fe448_sq(E, tmp);
    fe448_sub(E, E, A);
    fe448_sub(E, E, B);                // E = (X+Y)^2 - A - B
    fe448_add(G, B, A);
    fe448_sub(H, A, B);
    // F = A + B - 2*Z^2 = (A - Z^2) + (B - Z^2).
    // Avoids feeding fe448_sub an operand >= 2^448 (A+B, 2Z^2 can reach 2p).
    fe448_sub(F, A, C);
    fe448_sub(tmp, B, C);
    fe448_add(F, F, tmp);
    fe448_mul(R.X, E, F);
    fe448_mul(R.Y, G, H);
    fe448_mul(R.T, E, H);
    fe448_mul(R.Z, F, G);
}

// ---- encode / decode ----

static void point_encode(const ed448_point_ext& P, uint8_t out[57]) {
    fe448 z_inv, x, y;
    fe448_invert(z_inv, P.Z);
    fe448_mul(x, P.X, z_inv);
    fe448_mul(y, P.Y, z_inv);
    uint8_t yb[56];
    fe448_tobytes(yb, y);
    memcpy(out, yb, 56);
    out[56] = fe448_isnegative(x) ? 0x80 : 0x00;
}

static bool point_decode(ed448_point_ext& P, const uint8_t in[57]) {
    uint8_t yb[56];
    memcpy(yb, in, 56);
    uint8_t sign = (in[56] >> 7) & 1;

    fe448 y;
    fe448_frombytes(y, yb);

    fe448 y_sq;
    fe448_sq(y_sq, y);
    fe448 u;
    fe448_sub(u, y_sq, fe448_one());
    fe448 tmp;
    fe448_mul(tmp, get_d(), y_sq);
    fe448 v;
    fe448_sub(v, tmp, fe448_one());

    fe448 v_inv;
    fe448_invert(v_inv, v);
    fe448 x_sq;
    fe448_mul(x_sq, u, v_inv);
    fe448 x;
    fe448_sqrt(x, x_sq);

    fe448 x_check;
    fe448_sq(x_check, x);
    fe448_mul(x_check, x_check, v);
    if (memcmp(x_check, u, sizeof(fe448)) != 0) return false;

    if (fe448_isnegative(x) != sign) fe448_neg(x, x);

    fe448_copy(P.X, x);
    fe448_copy(P.Y, y);
    fe448_1(P.Z);
    fe448_mul(P.T, x, y);
    return true;
}

// ---- scalar multiplication ----

/// Extract 4-bit window at bitpos (little-endian).
static inline int extract_window4(const uint8_t scalar[57], int bitpos) {
    int w = 0;
    for (int b = 0; b < 4; ++b) {
        int i = bitpos + b;
        w |= ((scalar[i >> 3] >> (i & 7)) & 1) << b;
    }
    return w;
}

/// Build table[16]: table[i] = i*P (15 extended adds).
static void point_table_build(ed448_point_ext table[16], const ed448_point_ext& P) {
    point_zero(table[0]);
    point_copy(table[1], P);
    for (int i = 2; i < 16; ++i)
        point_add_ext(table[i], table[i - 1], P);
}

/// Constant-time selection: r = table[idx] (cmov chain).
static void ct_select_point(ed448_point_ext& r,
                            const ed448_point_ext table[16], int idx) {
    for (int c = 0; c < 4; ++c) {
        const uint64_t* t0 = (c == 0) ? table[0].X
                            : (c == 1) ? table[0].Y
                            : (c == 2) ? table[0].Z : table[0].T;
        uint64_t acc[8];
        for (int i = 0; i < 8; ++i) acc[i] = t0[i];
        for (int j = 1; j < 16; ++j) {
            const uint64_t* tj = (c == 0) ? table[j].X
                                : (c == 1) ? table[j].Y
                                : (c == 2) ? table[j].Z : table[j].T;
            uint64_t mask = (uint64_t)(-(int64_t)(j == idx));
            for (int i = 0; i < 8; ++i)
                acc[i] ^= mask & (acc[i] ^ tj[i]);
        }
        uint64_t* dst = (c == 0) ? r.X : (c == 1) ? r.Y
                        : (c == 2) ? r.Z : r.T;
        for (int i = 0; i < 8; ++i) dst[i] = acc[i];
    }
}

/// 4-bit windowed double-and-add for an arbitrary point table:
/// R = scalar * P, 112 windows x (4 doubles + 1 add).
static void scalar_mult_windows(ed448_point_ext& R, const uint8_t scalar[57],
                                const ed448_point_ext table[16]) {
    point_zero(R);
    for (int wi = 111; wi >= 0; --wi) {
        for (int j = 0; j < 4; ++j) {
            ed448_point_ext d;
            point_double_ext(d, R);
            point_copy(R, d);
        }
        int w = extract_window4(scalar, 4 * wi);
        ed448_point_ext tmp;
        point_add_ext(tmp, R, table[w]);
        point_copy(R, tmp);
    }
}

/// Straus-Shamir double scalar: R = s1*P1 + s2*P2 (shared doubling chain).
static void double_scalar_mult(ed448_point_ext& R,
                               const uint8_t s1[57], const ed448_point_ext t1[16],
                               const uint8_t s2[57], const ed448_point_ext t2[16]) {
    point_zero(R);
    for (int wi = 111; wi >= 0; --wi) {
        for (int j = 0; j < 4; ++j) {
            ed448_point_ext d;
            point_double_ext(d, R);
            point_copy(R, d);
        }
        int w1 = extract_window4(s1, 4 * wi);
        int w2 = extract_window4(s2, 4 * wi);
        ed448_point_ext tmp;
        point_add_ext(tmp, R, t1[w1]);
        point_copy(R, tmp);
        point_add_ext(tmp, R, t2[w2]);
        point_copy(R, tmp);
    }
}

// ---- base point ----

static const ed448_point_ext& base_point() {
    static ed448_point_ext B;
    static bool init = false;
    if (!init) {
        if (!point_decode(B, B_ENCODED)) point_zero(B);
        init = true;
    }
    return B;
}

/// Classic 4-bit basepoint table: t[i] = i*B (built once).
static const ed448_point_ext* basepoint_table() {
    static ed448_point_ext table[16];
    static bool init = false;
    if (!init) {
        point_table_build(table, base_point());
        init = true;
    }
    return table;
}

/// Fixed-base 4-bit comb table: fb[w][j] = j * 2^(4w) * B.
/// Built once, lazily; constant-time selection during use.
static const ed448_point_ext* fixed_base_table() {
    static ed448_point_ext fb[112][16];
    static bool init = false;
    if (!init) {
        const ed448_point_ext& B = base_point();
        point_zero(fb[0][0]);
        point_copy(fb[0][1], B);
        for (int j = 2; j < 16; ++j)
            point_add_ext(fb[0][j], fb[0][j - 1], B);
        for (int w = 1; w < 112; ++w) {
            point_double_ext(fb[w][1], fb[w - 1][1]);
            point_double_ext(fb[w][1], fb[w][1]);
            point_double_ext(fb[w][1], fb[w][1]);
            point_double_ext(fb[w][1], fb[w][1]);
            point_zero(fb[w][0]);
            for (int j = 2; j < 16; ++j)
                point_add_ext(fb[w][j], fb[w][j - 1], fb[w][1]);
        }
        init = true;
    }
    return &fb[0][0];
}

/// Fixed-base scalar mult: R = scalar * B. 111 extended adds, no doublings.
static void fixed_base_mult(ed448_point_ext& R, const uint8_t scalar[57]) {
    const ed448_point_ext* fb = fixed_base_table();
    ct_select_point(R, fb + 0, extract_window4(scalar, 0));
    for (int w = 1; w < 112; ++w) {
        ed448_point_ext T;
        ct_select_point(T, fb + w * 16, extract_window4(scalar, 4 * w));
        point_add_ext(R, R, T);
    }
}

// ---- SHAKE256 ----

static void ed448_hash_raw(const uint8_t* data, size_t len, uint8_t out[114]) {
    jpssl::sha3_ctx ctx;
    jpssl::shake256_init(&ctx);
    jpssl::shake_update(&ctx, data, len);
    jpssl::shake_squeeze(&ctx, out, 114);
}

static const uint8_t DOM4_PREFIX[] = {
    'S','i','g','E','d','4','4','8', 0x00, 0x00
};

static void ed448_hash_dom4(const uint8_t* parts[], const size_t lens[],
                            int n_parts, uint8_t out[114]) {
    jpssl::sha3_ctx ctx;
    jpssl::shake256_init(&ctx);
    jpssl::shake_update(&ctx, DOM4_PREFIX, sizeof(DOM4_PREFIX));
    for (int i = 0; i < n_parts; ++i) {
        if (lens[i]) jpssl::shake_update(&ctx, parts[i], lens[i]);
    }
    jpssl::shake_squeeze(&ctx, out, 114);
}

static void prune_scalar(uint8_t s[57]) {
    s[0] &= 0xFC; s[55] |= 0x80; s[56] = 0x00;
}

// ---- public-ish impls ----

static void ed448_keygen_impl(uint8_t pub[57], uint8_t priv_seed[57]) {
    uint8_t h[114];
    ed448_hash_raw(priv_seed, 57, h);
    uint8_t s[57];
    memcpy(s, h, 57);
    prune_scalar(s);
    ed448_point_ext A;
    fixed_base_mult(A, s);
    point_encode(A, pub);
}

static void ed448_sign_impl(const uint8_t* priv, const uint8_t* msg,
                            size_t msg_len, uint8_t sig[114]) {
    const uint8_t* seed = priv;
    uint8_t h[114];
    ed448_hash_raw(seed, 57, h);
    uint8_t s_scalar[57];
    memcpy(s_scalar, h, 57);
    prune_scalar(s_scalar);

    const uint8_t* prefix = h + 57;

    uint8_t pub[57];
    {
        ed448_point_ext A;
        fixed_base_mult(A, s_scalar);
        point_encode(A, pub);
    }

    uint8_t r_scalar[57];
    {
        const uint8_t* dom4_parts[] = { prefix, msg };
        const size_t dom4_lens[] = { 57, msg_len };
        uint8_t rh[114];
        ed448_hash_dom4(dom4_parts, dom4_lens, msg_len ? 2 : 1, rh);
        scalar_mod_L(rh, r_scalar);
    }

    ed448_point_ext R;
    fixed_base_mult(R, r_scalar);
    uint8_t R_enc[57];
    point_encode(R, R_enc);

    uint8_t k_scalar[57];
    {
        const uint8_t* dom4_parts[] = { R_enc, pub, msg };
        const size_t dom4_lens[] = { 57, 57, msg_len };
        uint8_t kh[114];
        ed448_hash_dom4(dom4_parts, dom4_lens, msg_len ? 3 : 2, kh);
        scalar_mod_L(kh, k_scalar);
    }

    uint64_t r_l[8], s_l[8], k_l[8];
    scalar_bytes_to_limbs(r_l, 8, r_scalar, 57);
    scalar_bytes_to_limbs(s_l, 8, s_scalar, 57);
    scalar_bytes_to_limbs(k_l, 8, k_scalar, 57);
    uint64_t ks[16];
    scalar_mul_limbs(ks, k_l, s_l);
    uint64_t ks_mod[7];
    scalar_reduce_mod_L(ks_mod, ks, 16);
    uint64_t sum_l[7];
    scalar_add_mod_L(sum_l, r_l, ks_mod);
    uint8_t S_le[57];
    scalar_limbs_to_bytes(S_le, 57, sum_l, 7);

    memcpy(sig, R_enc, 57);
    memcpy(sig + 57, S_le, 57);
}

static bool ed448_verify_impl(const uint8_t pub[57], const uint8_t* msg,
                              size_t msg_len, const uint8_t sig[114]) {
    uint8_t R_enc[57];
    memcpy(R_enc, sig, 57);
    uint8_t S_le[57];
    memcpy(S_le, sig + 57, 57);

    ed448_point_ext R;
    if (!point_decode(R, R_enc)) return false;

    if (!scalar_lt_L_bytes(S_le)) return false;

    ed448_point_ext A;
    if (!point_decode(A, pub)) return false;

    uint8_t k_scalar[57];
    {
        const uint8_t* parts[] = { R_enc, pub, msg };
        const size_t lens[] = { 57, 57, msg_len };
        uint8_t h[114];
        ed448_hash_dom4(parts, lens, 3, h);
        scalar_mod_L(h, k_scalar);
    }

    // k_neg = (L - k) mod L (byte subtraction; zero when k == 0)
    uint8_t k_neg[57];
    {
        uint64_t borrow = 0;
        for (int i = 0; i < 57; ++i) {
            uint64_t d = (uint64_t)L_BYTES[i] - (uint64_t)k_scalar[i] - borrow;
            k_neg[i] = (uint8_t)d;
            borrow = (L_BYTES[i] < k_scalar[i] + borrow) ? 1 : 0;
        }
        if (memcmp(k_neg, L_BYTES, 57) == 0) memset(k_neg, 0, 57);
    }

    ed448_point_ext A_table[16];
    point_table_build(A_table, A);
    ed448_point_ext T;
    double_scalar_mult(T, S_le, basepoint_table(), k_neg, A_table);

    // Projective equality: T == R <=> (T.X*R.Z == R.X*T.Z) && (T.Y*R.Z == R.Y*T.Z)
    fe448 lhs_x, rhs_x, lhs_y, rhs_y;
    fe448_mul(lhs_x, T.X, R.Z);
    fe448_mul(rhs_x, R.X, T.Z);
    fe448_mul(lhs_y, T.Y, R.Z);
    fe448_mul(rhs_y, R.Y, T.Z);
    if (memcmp(lhs_x, rhs_x, sizeof(fe448)) != 0) return false;
    if (memcmp(lhs_y, rhs_y, sizeof(fe448)) != 0) return false;
    return true;
}
