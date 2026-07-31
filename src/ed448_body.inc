/**
 * ed448_body.inc — Ed448 核心实现（供 CPU/AVX2/AVX512 后端复用）
 *
 * 使用方式：各编译单元在独立的命名空间内 #include 本文件，
 * 配合对应的编译标志（-mavx2 / -mavx512f）让编译器自动向量化。
 *
 * 导出函数：
 *   ed448_verify(pub, msg, msg_len, sig) → bool
 */

using namespace jpssl::fe448_impl;

namespace {

// ─── 常量 ────────────────────────────────────────────────────────────

// d = -39081 mod p
static const uint8_t D_BYTES[56] = {
    0x56,0x67,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

// L (group order, RFC 8032 reference implementation)
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

// ─── 大整数辅助 ──────────────────────────────────────────────────────

static rsa_bignum bytes_le_to_bn(const uint8_t* le, size_t n) {
    uint8_t be[256] = {0};
    for (size_t i = 0; i < n; ++i) be[i] = le[n - 1 - i];
    return rsa_bignum::from_bytes(be, n);
}

static void bn_to_bytes_le(const rsa_bignum& v, uint8_t* out, size_t n) {
    uint8_t be[256] = {0};
    v.to_bytes(be);
    for (size_t i = 0; i < n; ++i) out[i] = be[255 - i];
}

static const rsa_bignum& get_P() {
    static const uint8_t pb[56] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };
    uint8_t pbe[56];
    for (int i = 0; i < 56; ++i) pbe[i] = pb[55 - i];
    static const rsa_bignum P = rsa_bignum::from_bytes(pbe, 56);
    return P;
}

static const rsa_bignum& get_L() {
    static const rsa_bignum L = bytes_le_to_bn(L_BYTES, 57);
    return L;
}

static void mod_L(const rsa_bignum& a, rsa_bignum& out) {
    jpssl::bn_mod(out, a, get_L());
}

static void scalar_mod_L(const uint8_t in[114], uint8_t out[57]) {
    rsa_bignum v = bytes_le_to_bn(in, 114);
    rsa_bignum r_val;
    mod_L(v, r_val);
    bn_to_bytes_le(r_val, out, 57);
}

// ─── 单位元素 ─────────────────────────────────────────────────────────

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

// ─── Ed448 点运算 ──────────────────────────────────────────────────

static void point_zero(ed448_point& P) {
    fe448_0(P.X); fe448_1(P.Y); fe448_1(P.Z);
}

static void point_copy(ed448_point& dst, const ed448_point& src) {
    fe448_copy(dst.X, src.X); fe448_copy(dst.Y, src.Y);
    fe448_copy(dst.Z, src.Z);
}

static void point_add(ed448_point& R, const ed448_point& P, const ed448_point& Q) {
    fe448 A, B, C, D, E, F, G, H;
    fe448 tmp, tmp2;

    fe448_mul(A, P.Z, Q.Z);
    fe448_sq(B, A);
    fe448_mul(C, P.X, Q.X);
    fe448_mul(D, P.Y, Q.Y);
    fe448_mul(tmp, C, D);
    fe448_mul(E, tmp, get_d());
    fe448_sub(F, B, E);
    fe448_add(G, B, E);
    fe448_add(tmp, P.X, P.Y);
    fe448_add(tmp2, Q.X, Q.Y);
    fe448_mul(H, tmp, tmp2);

    fe448_sub(tmp, H, C);
    fe448_sub(tmp, tmp, D);
    fe448_mul(tmp, A, tmp);
    fe448_mul(R.X, tmp, F);

    fe448_sub(tmp, D, C);
    fe448_mul(tmp, A, tmp);
    fe448_mul(R.Y, tmp, G);

    fe448_mul(R.Z, F, G);
}

static void point_double(ed448_point& R, const ed448_point& P) {
    // 用 fe448_carry 替代 tobytes/frombytes 归一化（省去序列化开销）
    fe448 B, C, D, E, H, J;
    fe448 tmp;

    fe448_add(tmp, P.X, P.Y); fe448_carry(tmp);
    fe448_sq(B, tmp);
    fe448_sq(C, P.X);
    fe448_sq(D, P.Y);
    fe448_add(E, C, D); fe448_carry(E);
    fe448_sq(H, P.Z);
    fe448_add(tmp, H, H); fe448_carry(tmp);
    fe448_sub(J, E, tmp);

    fe448_sub(tmp, B, E);
    fe448_mul(R.X, tmp, J);
    fe448_sub(tmp, C, D);
    fe448_mul(R.Y, E, tmp);
    fe448_mul(R.Z, E, J);
}

// ─── 编码/解码 ──────────────────────────────────────────────────────

static void point_encode(const ed448_point& P, uint8_t out[57]) {
    fe448 z_inv, x, y;
    fe448_invert(z_inv, P.Z);
    fe448_mul(x, P.X, z_inv);
    fe448_mul(y, P.Y, z_inv);
    uint8_t yb[56];
    fe448_tobytes(yb, y);
    memcpy(out, yb, 56);
    out[56] = fe448_isnegative(x) ? 0x80 : 0x00;
}

static bool point_decode(ed448_point& P, const uint8_t in[57]) {
    // 解码 y 坐标
    uint8_t yb[56];
    memcpy(yb, in, 56);
    uint8_t sign = (in[56] >> 7) & 1;
    fe448 y;
    fe448_frombytes(y, yb);

    // x² = (y² − 1) / (d·y² − 1)  (Edwards 曲线)
    fe448 y_sq; fe448_sq(y_sq, y);
    fe448 u;   fe448_sub(u, y_sq, fe448_one());
    fe448 tmp; fe448_mul(tmp, get_d(), y_sq);
    fe448 v;   fe448_sub(v, tmp, fe448_one());

    // x = sqrt(u/v)  纯 fe448 域运算，替代原 bn_modpow（~1000x 加速）
    fe448 v_inv; fe448_invert(v_inv, v);
    fe448 x_sq;  fe448_mul(x_sq, u, v_inv);
    fe448 x;     fe448_sqrt(x, x_sq);

    // 验证 x²·v == u（确保 x 是正确平方根）
    fe448 x_check; fe448_sq(x_check, x); fe448_mul(x_check, x_check, v);
    if (memcmp(x_check, u, sizeof(fe448)) != 0) return false;

    if (fe448_isnegative(x) != sign) fe448_neg(x, x);

    fe448_copy(P.X, x);
    fe448_copy(P.Y, y);
    fe448_1(P.Z);
    return true;
}

// ─── 标量乘法 ────────────────────────────────────────────────────────

static void scalar_mult(ed448_point& R, const uint8_t scalar[57], const ed448_point& P) {
    ed448_point Q; point_zero(Q);
    ed448_point cur; point_copy(cur, P);

    for (int i = 0; i < 448; ++i) {
        int byte_idx = i >> 3;
        int bit = (scalar[byte_idx] >> (i & 7)) & 1;
        if (bit) {
            ed448_point tmp;
            point_add(tmp, Q, cur);
            point_copy(Q, tmp);
        }
        ed448_point doubled;
        point_double(doubled, cur);
        point_copy(cur, doubled);
    }
    point_copy(R, Q);
}

static const ed448_point& base_point() {
    static ed448_point B;
    static bool init = false;
    if (!init) {
        if (!point_decode(B, B_ENCODED)) point_zero(B);
        init = true;
    }
    return B;
}

// ─── SHAKE256 哈希 ─────────────────────────────────────────────────

static void ed448_hash_raw(const uint8_t* data, size_t len, uint8_t out[114]) {
    jpssl::sha3_ctx ctx;
    jpssl::shake256_init(&ctx);
    jpssl::shake_update(&ctx, data, len);
    jpssl::shake_squeeze(&ctx, out, 114);
}

static const uint8_t DOM4_PREFIX[] = {
    'S','i','g','E','d','4','4','8', 0x00, 0x00
};

static void ed448_hash_dom4(const uint8_t* parts[], const size_t lens[], int n_parts, uint8_t out[114]) {
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

// ─── 密钥生成 ────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════
//  窗口化标量乘 + basepoint 预计算表 + 双标量乘
// ═══════════════════════════════════════════════════════════════════

/// 构建 4-bit 窗口表：table[i] = i*P（i=0..15）
static void point_table_build(ed448_point table[16], const ed448_point& P) {
    point_zero(table[0]);
    point_copy(table[1], P);
    for (int i = 2; i < 16; ++i)
        point_add(table[i], table[i - 1], P);
}

/// 静态 basepoint 4-bit 窗口表（一次性构建）
static const ed448_point* basepoint_table() {
    static ed448_point table[16];
    static bool init = false;
    if (!init) {
        point_table_build(table, base_point());
        init = true;
    }
    return table;
}

/// 提取标量第 bitpos 位起的 4-bit 窗口（小端位序）
static inline int extract_window4(const uint8_t scalar[57], int bitpos) {
    int w = 0;
    for (int b = 0; b < 4; ++b) {
        int i = bitpos + b;
        w |= ((scalar[i >> 3] >> (i & 7)) & 1) << b;
    }
    return w;
}

/// 4-bit 窗口标量乘：R = scalar * P（P 用预计算表，448 位 = 112 窗口）
static void scalar_mult_windows(ed448_point& R, const uint8_t scalar[57], const ed448_point table[16]) {
    point_zero(R);
    for (int wi = 111; wi >= 0; --wi) {
        for (int j = 0; j < 4; ++j) {
            ed448_point d;
            point_double(d, R);
            point_copy(R, d);
        }
        int w = extract_window4(scalar, 4 * wi);
        ed448_point tmp;
        point_add(tmp, R, table[w]);
        point_copy(R, tmp);
    }
}

/// 双标量乘（Strauss-Shamir 窗口化）：R = s1*P1 + s2*P2
/// 两标量同时扫描共享倍点链，128 窗口 × (4 倍点 + 2 查表加)
static void double_scalar_mult(ed448_point& R,
                               const uint8_t s1[57], const ed448_point t1[16],
                               const uint8_t s2[57], const ed448_point t2[16]) {
    point_zero(R);
    for (int wi = 111; wi >= 0; --wi) {
        for (int j = 0; j < 4; ++j) {
            ed448_point d;
            point_double(d, R);
            point_copy(R, d);
        }
        int w1 = extract_window4(s1, 4 * wi);
        int w2 = extract_window4(s2, 4 * wi);
        ed448_point tmp;
        point_add(tmp, R, t1[w1]);
        point_copy(R, tmp);
        point_add(tmp, R, t2[w2]);
        point_copy(R, tmp);
    }
}

static void ed448_keygen_impl(uint8_t pub[57], uint8_t priv_seed[57]) {
    uint8_t h[114];
    ed448_hash_raw(priv_seed, 57, h);
    uint8_t s[57];
    memcpy(s, h, 57);
    prune_scalar(s);
    ed448_point A;
    scalar_mult_windows(A, s, basepoint_table());
    point_encode(A, pub);
}

// ─── 签名 ────────────────────────────────────────────────────────────

static void ed448_sign_impl(const uint8_t* priv, const uint8_t* msg, size_t msg_len, uint8_t sig[114]) {
    const uint8_t* seed = priv;
    uint8_t h[114];
    ed448_hash_raw(seed, 57, h);
    uint8_t s_scalar[57];
    memcpy(s_scalar, h, 57);
    prune_scalar(s_scalar);

    const uint8_t* prefix = h + 57;

    uint8_t pub[57];
    {
        ed448_point A;
        scalar_mult_windows(A, s_scalar, basepoint_table());
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

    ed448_point R;
    scalar_mult_windows(R, r_scalar, basepoint_table());
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

    rsa_bignum r_bn = bytes_le_to_bn(r_scalar, 57);
    rsa_bignum s_bn = bytes_le_to_bn(s_scalar, 57);
    rsa_bignum k_bn = bytes_le_to_bn(k_scalar, 57);
    rsa_bignum ks; jpssl::bn_mul(ks, k_bn, s_bn);
    rsa_bignum ks_mod; mod_L(ks, ks_mod);
    rsa_bignum sum; jpssl::bn_add(sum, r_bn, ks_mod);
    rsa_bignum S_bn; mod_L(sum, S_bn);

    uint8_t S_le[57];
    bn_to_bytes_le(S_bn, S_le, 57);

    memcpy(sig, R_enc, 57);
    memcpy(sig + 57, S_le, 57);
}

// ─── 验证 ────────────────────────────────────────────────────────────

static bool ed448_verify_impl(const uint8_t pub[57], const uint8_t* msg, size_t msg_len, const uint8_t sig[114]) {
    uint8_t R_enc[57];
    memcpy(R_enc, sig, 57);
    uint8_t S_le[57];
    memcpy(S_le, sig + 57, 57);

    ed448_point R;
    if (!point_decode(R, R_enc)) return false;

    rsa_bignum S_bn = bytes_le_to_bn(S_le, 57);
    if (!(S_bn < get_L())) return false;

    ed448_point A;
    if (!point_decode(A, pub)) return false;

    uint8_t k_scalar[57];
    {
        const uint8_t* parts[] = { R_enc, pub, msg };
        const size_t lens[] = { 57, 57, msg_len };
        uint8_t h[114];
        ed448_hash_dom4(parts, lens, 3, h);
        scalar_mod_L(h, k_scalar);
    }

    uint8_t S_scalar[57];
    bn_to_bytes_le(S_bn, S_scalar, 57);

    // k_neg = (L - k) mod L（字节减法；k==0 时归零）
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

    // 验证目标：S*B == R + k*A  ⇔  S*B + (-k)*A == R
    // 双标量乘（Strauss-Shamir）共享倍点链一次完成：
    //   T = S*B + k_neg*A，然后检查 T == R
    ed448_point A_table[16];
    point_table_build(A_table, A);
    ed448_point T;
    double_scalar_mult(T, S_scalar, basepoint_table(), k_neg, A_table);

    // 投影坐标相等性检查：T == R ⇔ (T.X*R.Z == R.X*T.Z) && (T.Y*R.Z == R.Y*T.Z)
    // 避免两次 point_encode（各含 1 次 fe448_invert，约 671 次域运算）
    fe448 lhs_x, rhs_x, lhs_y, rhs_y;
    fe448_mul(lhs_x, T.X, R.Z);
    fe448_mul(rhs_x, R.X, T.Z);
    fe448_mul(lhs_y, T.Y, R.Z);
    fe448_mul(rhs_y, R.Y, T.Z);
    if (memcmp(lhs_x, rhs_x, sizeof(fe448)) != 0) return false;
    if (memcmp(lhs_y, rhs_y, sizeof(fe448)) != 0) return false;
    return true;
}

}
