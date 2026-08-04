/**
 * ed448_simd_body.inc - N-way SIMD Ed448 batch verification
 * (N = JF448_LANES: 4 on AVX2, 8 on AVX512).
 *
 * Each lane verifies an independent signature with the same windowed
 * double-scalar multiplication as the scalar backend; the field/point
 * arithmetic is done lane-wise in SIMD.  Per-signature work that is
 * byte-oriented (SHAKE256, mod-L, window extraction) stays scalar.
 */
using jpssl::fe448_impl::fe448_mul64;
using jpssl::sha3_ctx;
using jpssl::shake256_init;
using jpssl::shake_update;
using jpssl::shake_squeeze;
using namespace jpssl::fe448_simd;

// ---- constants (same as scalar backend) ----
static const uint8_t SIMD_L_BYTES[57] = {
    0xf3,0x44,0x58,0xab,0x92,0xc2,0x78,0x23,0x55,0x8f,0xc5,0x8d,
    0x72,0xc2,0x6c,0x21,0x90,0x36,0xd6,0xae,0x49,0xdb,0x4e,0xc4,
    0xe9,0x23,0xca,0x7c,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x3f,0x00
};

static const uint8_t SIMD_B_ENCODED[57] = {
    0x14,0xfa,0x30,0xf2,0x5b,0x79,0x08,0x98,0xad,0xc8,0xd7,0x4e,
    0x2c,0x13,0xbd,0xfd,0xc4,0x39,0x7c,0xe6,0x1c,0xff,0xd3,0x3a,
    0xd7,0xc2,0xa0,0x05,0x1e,0x9c,0x78,0x87,0x40,0x98,0xa3,0x6c,
    0x73,0x73,0xea,0x4b,0x62,0xc7,0xc9,0x56,0x37,0x20,0x76,0x88,
    0x24,0xbc,0xb6,0x6e,0x71,0x46,0x3f,0x69,0x00
};

static const feN& simd_feN_one() {
    static feN one;
    static bool init = false;
    if (!init) { feN_one(one); init = true; }
    return one;
}

// ---- scalar helpers (per lane) ----

static bool simd_lt_L_bytes(const uint8_t le[57]) {
    for (int i = 56; i >= 0; --i) {
        if (le[i] != SIMD_L_BYTES[i]) return le[i] < SIMD_L_BYTES[i];
    }
    return false;
}

static inline uint8_t simd_extract_window4(const uint8_t scalar[57], int bitpos) {
    int w = 0;
    for (int b = 0; b < 4; ++b) {
        int i = bitpos + b;
        w |= ((scalar[i >> 3] >> (i & 7)) & 1) << b;
    }
    return (uint8_t)w;
}

// mod-L via u64 limb folding (2^448 == 4*delta), same as scalar backend
static const uint64_t SIMD_SCALAR_L_LIMBS[7] = {
    0x2378c292ab5844f3ULL, 0x216cc2728dc58f55ULL, 0xc44edb49aed63690ULL,
    0xffffffff7cca23e9ULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL,
    0x3fffffffffffffffULL
};
static const uint64_t SIMD_SCALAR_D4_LIMBS[4] = {
    0x721cf5b5529eec34ULL, 0x7a4cf635c8e9c2abULL, 0xeec492d944a725bfULL,
    0x000000020cd77058ULL
};

static void simd_scalar_reduce_mod_L(uint64_t out[7], const uint64_t* in, int in_limbs) {
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
            uint64_t t[5];
            uint64_t carry = 0;
            for (int k = 0; k < 4; ++k) {
                uint64_t hi = 0;
                uint64_t lo = fe448_mul64(xi, SIMD_SCALAR_D4_LIMBS[k], &hi);
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
    memcpy(v, buf, 56);
    for (int tries = 0; tries < 8; ++tries) {
        bool ge = true;
        for (int i = 6; i >= 0; --i) {
            if (v[i] != SIMD_SCALAR_L_LIMBS[i]) { ge = v[i] > SIMD_SCALAR_L_LIMBS[i]; break; }
        }
        if (!ge) break;
        uint64_t borrow = 0;
        for (int i = 0; i < 7; ++i) {
            uint64_t sub = SIMD_SCALAR_L_LIMBS[i] + borrow;
            borrow = (sub < SIMD_SCALAR_L_LIMBS[i] || v[i] < sub) ? 1 : 0;
            v[i] = v[i] - sub;
        }
    }
    memcpy(out, v, 56);
}

static void simd_scalar_mod_L(const uint8_t in[114], uint8_t out[57]) {
    uint64_t limbs[15] = {0};
    for (int i = 0; i < 114; ++i) limbs[i >> 3] |= (uint64_t)in[i] << (8 * (i & 7));
    uint64_t r[7];
    simd_scalar_reduce_mod_L(r, limbs, 15);
    memset(out, 0, 57);
    for (int i = 0; i < 56; ++i) out[i] = (uint8_t)(r[i >> 3] >> (8 * (i & 7)));
}

static const uint8_t SIMD_DOM4_PREFIX[] = {
    'S','i','g','E','d','4','4','8', 0x00, 0x00
};

static void simd_hash_dom4(const uint8_t* parts[], const size_t lens[],
                           int n_parts, uint8_t out[114]) {
    sha3_ctx ctx;
    shake256_init(&ctx);
    shake_update(&ctx, SIMD_DOM4_PREFIX, sizeof(SIMD_DOM4_PREFIX));
    for (int i = 0; i < n_parts; ++i) {
        if (lens[i]) shake_update(&ctx, parts[i], lens[i]);
    }
    shake_squeeze(&ctx, out, 114);
}

// ---- N-way point (extended coordinates) ----

struct ptN {
    feN X, Y, Z, T;
};

// 16-entry table with a scalar (lane-major) mirror for per-lane selection
struct ptN_table16 {
    ptN simd[16];
    uint64_t scalar[16][4][JF448_LANES][16];  // [entry][coord][lane][limb]
};

static void ptN_zero(ptN& P) {
    feN_zero(P.X); feN_one(P.Y); feN_one(P.Z); feN_zero(P.T);
}
static void ptN_copy(ptN& d, const ptN& s) {
    feN_copy(d.X, s.X); feN_copy(d.Y, s.Y);
    feN_copy(d.Z, s.Z); feN_copy(d.T, s.T);
}

// per-lane encode (debug + tests)
static void ptN_encode(uint8_t* out[JF448_LANES], const ptN& P) {
    feN z_inv, x, y;
    feN_invert(z_inv, P.Z);
    feN_mul(x, P.X, z_inv);
    feN_mul(y, P.Y, z_inv);
    uint8_t yb[JF448_LANES][56];
    uint8_t* yp[JF448_LANES];
    for (int j = 0; j < JF448_LANES; ++j) yp[j] = yb[j];
    feN_tobytes(yp, y);
    jf448_m neg = feN_isnegative_mask(x);
    for (int j = 0; j < JF448_LANES; ++j) {
        memcpy(out[j], yb[j], 56);
        out[j][56] = jf448_m_lane(neg, j) ? 0x80 : 0x00;
    }
}

// complete (strongly unified) add, a=1
static void ptN_add(ptN& R, const ptN& P, const ptN& Q) {
    feN A, B, C, D, E, F, G, H, tmp, tmp2;
    feN_mul(A, P.X, Q.X);
    feN_mul(B, P.Y, Q.Y);
    feN_mul(tmp, P.T, Q.T);
    feN_mul_small(C, tmp, 39081);
    feN_neg(C, C);
    feN_mul(D, P.Z, Q.Z);
    feN_add(tmp, P.X, P.Y);
    feN_add(tmp2, Q.X, Q.Y);
    feN_mul(E, tmp, tmp2);
    feN_sub(E, E, A);
    feN_sub(E, E, B);
    feN_sub(F, D, C);
    feN_add(G, D, C);
    feN_sub(H, B, A);
    feN_mul(R.X, E, F);
    feN_mul(R.Y, G, H);
    feN_mul(R.T, E, H);
    feN_mul(R.Z, F, G);
}

static void ptN_double(ptN& R, const ptN& P) {
    feN A, B, C, E, F, G, H, tmp;
    feN_sq(A, P.X);
    feN_sq(B, P.Y);
    feN_sq(C, P.Z);
    feN_add(tmp, P.X, P.Y);
    feN_sq(E, tmp);
    feN_sub(E, E, A);
    feN_sub(E, E, B);
    feN_add(G, B, A);
    feN_sub(H, A, B);
    feN_sub(F, A, C);
    feN_sub(tmp, B, C);
    feN_add(F, F, tmp);
    feN_mul(R.X, E, F);
    feN_mul(R.Y, G, H);
    feN_mul(R.T, E, H);
    feN_mul(R.Z, F, G);
}

// per-lane decode; returns false if any lane fails the x^2 check
static bool ptN_decode(ptN& P, const uint8_t* enc[JF448_LANES]) {
    uint8_t yb[JF448_LANES][56];
    uint8_t sign[JF448_LANES];
    const uint8_t* yp[JF448_LANES];
    for (int j = 0; j < JF448_LANES; ++j) {
        memcpy(yb[j], enc[j], 56);
        sign[j] = (enc[j][56] >> 7) & 1;
        yp[j] = yb[j];
    }
    feN y;
    feN_frombytes(y, yp);

    feN y2;
    feN_sq(y2, y);
    feN u;
    feN_sub(u, y2, simd_feN_one());
    feN tmp;
    feN_mul_small(tmp, y2, 39081);
    feN_neg(tmp, tmp);
    feN v;
    feN_sub(v, tmp, simd_feN_one());

    feN v_inv;
    feN_invert(v_inv, v);
    feN x2;
    feN_mul(x2, u, v_inv);
    feN x;
    feN_sqrt(x, x2);

    // check x^2 * v == u per lane
    feN chk;
    feN_sq(chk, x);
    feN_mul(chk, chk, v);
    jf448_m m = jf448_cmpeq_u64(chk.limb[0], u.limb[0]);
    for (int i = 1; i < 8; ++i)
        m = jf448_mand(m, jf448_cmpeq_u64(chk.limb[i], u.limb[i]));
    if (!jf448_m_all(m)) return false;

    // sign handling per lane: negate where isnegative(x) != sign
    jf448_m isneg = feN_isnegative_mask(x);
    jf448_m sigm = jf448_mask_from_bits(sign);
    jf448_m neg = jf448_mxor(isneg, sigm);
    feN xa;
    feN_cond_neg(xa, x, neg);

    feN_copy(P.X, xa);
    feN_copy(P.Y, y);
    feN_copy(P.Z, simd_feN_one());
    feN_mul(P.T, xa, y);
    return true;
}

static void ptN_store_scalar(uint64_t out[4][JF448_LANES][16], const ptN& p) {
    feN_store(out[0], p.X);
    feN_store(out[1], p.Y);
    feN_store(out[2], p.Z);
    feN_store(out[3], p.T);
}

static void ptN_table_build(ptN_table16& tab, const ptN& P) {
    ptN_zero(tab.simd[0]);
    ptN_copy(tab.simd[1], P);
    for (int i = 2; i < 16; ++i) ptN_add(tab.simd[i], tab.simd[i - 1], P);
    for (int i = 0; i < 16; ++i) ptN_store_scalar(tab.scalar[i], tab.simd[i]);
}

// T = table[w[j]] per lane
static void ptN_select(ptN& T, const ptN_table16& tab, const uint8_t w[JF448_LANES]) {
    uint64_t x[JF448_LANES][16], y[JF448_LANES][16], z[JF448_LANES][16], t[JF448_LANES][16];
    for (int j = 0; j < JF448_LANES; ++j) {
        const uint64_t (*e)[JF448_LANES][16] = tab.scalar[w[j]];
        for (int i = 0; i < 16; ++i) {
            x[j][i] = e[0][j][i];
            y[j][i] = e[1][j][i];
            z[j][i] = e[2][j][i];
            t[j][i] = e[3][j][i];
        }
    }
    feN_load(T.X, x); feN_load(T.Y, y); feN_load(T.Z, z); feN_load(T.T, t);
}

// R = s1*P1 + s2*P2 with 4-bit windows and a shared doubling chain
static void double_scalar_mult_N(ptN& R, const uint8_t s1[JF448_LANES][57],
                                 const uint8_t s2[JF448_LANES][57],
                                 const ptN_table16& t1, const ptN_table16& t2) {
    ptN_zero(R);
    for (int wi = 111; wi >= 0; --wi) {
        for (int j = 0; j < 4; ++j) {
            ptN d;
            ptN_double(d, R);
            ptN_copy(R, d);
        }
        uint8_t w1[JF448_LANES], w2[JF448_LANES];
        for (int j = 0; j < JF448_LANES; ++j) {
            w1[j] = simd_extract_window4(s1[j], 4 * wi);
            w2[j] = simd_extract_window4(s2[j], 4 * wi);
        }
        ptN T;
        ptN_select(T, t1, w1);
        ptN_add(R, R, T);
        ptN_select(T, t2, w2);
        ptN_add(R, R, T);
    }
}

static const ptN_table16* simd_basepoint_table() {
    static ptN_table16 tab;
    static bool init = false;
    if (!init) {
        const uint8_t* enc[JF448_LANES];
        for (int j = 0; j < JF448_LANES; ++j) enc[j] = SIMD_B_ENCODED;
        ptN B;
        if (!ptN_decode(B, enc)) {
            ptN_zero(tab.simd[0]);
        } else {
            ptN_table_build(tab, B);
        }
        init = true;
    }
    return &tab;
}

// ---- batch verify core (count <= JF448_LANES) ----
static bool ed448_batch_verify_simd(
    const uint8_t* const* pubs, const uint8_t* const* msgs,
    const size_t* msg_lens, const uint8_t* const* sigs, int count)
{
    const ptN_table16& Btab = *simd_basepoint_table();
    if (count <= 0 || count > JF448_LANES) return false;

    uint8_t R_enc[JF448_LANES][57], S_le[JF448_LANES][57];
    uint8_t k_neg[JF448_LANES][57];
    const uint8_t* enc_R[JF448_LANES];
    const uint8_t* enc_A[JF448_LANES];

    for (int j = 0; j < JF448_LANES; ++j) {
        int src = (j < count) ? j : 0;   // duplicate lane 0 into padding lanes
        memcpy(R_enc[j], sigs[src], 57);
        memcpy(S_le[j], sigs[src] + 57, 57);
        if (!simd_lt_L_bytes(S_le[j])) return false;
        enc_R[j] = R_enc[j];
        enc_A[j] = pubs[src];
    }

    ptN R, A;
    if (!ptN_decode(R, enc_R)) return false;
    if (!ptN_decode(A, enc_A)) return false;

    // k = H(R || A || msg) mod L; k_neg = (L - k) mod L
    for (int j = 0; j < JF448_LANES; ++j) {
        int src = (j < count) ? j : 0;
        const uint8_t* parts[] = { R_enc[j], enc_A[j], msgs[src] };
        const size_t lens[] = { 57, 57, msg_lens[src] };
        uint8_t h[114];
        simd_hash_dom4(parts, lens, 3, h);
        uint8_t k[57];
        simd_scalar_mod_L(h, k);
        uint64_t borrow = 0;
        for (int i = 0; i < 57; ++i) {
            uint64_t d = (uint64_t)SIMD_L_BYTES[i] - (uint64_t)k[i] - borrow;
            k_neg[j][i] = (uint8_t)d;
            borrow = (SIMD_L_BYTES[i] < k[i] + borrow) ? 1 : 0;
        }
        if (memcmp(k_neg[j], SIMD_L_BYTES, 57) == 0) memset(k_neg[j], 0, 57);
    }

    ptN_table16 A_tab;
    ptN_table_build(A_tab, A);

    ptN T;
    double_scalar_mult_N(T, S_le, k_neg, Btab, A_tab);

    // projective equality T == R per lane
    feN lx, rx, ly, ry;
    feN_mul(lx, T.X, R.Z);
    feN_mul(rx, R.X, T.Z);
    feN_mul(ly, T.Y, R.Z);
    feN_mul(ry, R.Y, T.Z);
    jf448_m m = jf448_cmpeq_u64(lx.limb[0], rx.limb[0]);
    for (int i = 1; i < 8; ++i)
        m = jf448_mand(m, jf448_cmpeq_u64(lx.limb[i], rx.limb[i]));
    for (int i = 0; i < 8; ++i)
        m = jf448_mand(m, jf448_cmpeq_u64(ly.limb[i], ry.limb[i]));

    return jf448_m_all_first(m, count);
}
