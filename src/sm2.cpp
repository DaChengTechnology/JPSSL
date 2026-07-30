/** sm2.cpp — SM2 椭圆曲线公钥密码算法（GM/T 0003-2012）
 *
 *  基于 SM2 推荐曲线 sm2p256v1（a = -3 mod p，可用 dbl-2001-b 倍点公式）。
 *  内部 uint256 用小端序 limbs[0..3]。
 */
#include "sm2.hpp"
#include "sm3.hpp"
#include <cstring>
#include <random>

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  SM2 曲线参数 (GM/T 0003.5-2012) — 大端字节序
// ═══════════════════════════════════════════════════════════════════════

static const uint8_t S2_P_BYTES[32] = {
    0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

static const uint8_t S2_A_BYTES[32] = {
    0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc
};

static const uint8_t S2_B_BYTES[32] = {
    0x28,0xe9,0xfa,0x9e,0x9d,0x9f,0x5e,0x34,0x4d,0x5a,0x9e,0x4b,0xcf,0x65,0x09,0xa7,
    0xf3,0x97,0x89,0xf5,0x15,0xab,0x8f,0x92,0xdd,0xbc,0xbd,0x41,0x4d,0x94,0x0e,0x93
};

static const uint8_t S2_N_BYTES[32] = {
    0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0x72,0x03,0xdf,0x6b,0x21,0xc6,0x05,0x2b,0x53,0xbb,0xf4,0x09,0x39,0xd5,0x41,0x23
};

static const uint8_t S2_Gx_BYTES[32] = {
    0x32,0xc4,0xae,0x2c,0x1f,0x19,0x81,0x19,0x5f,0x99,0x04,0x46,0x6a,0x39,0xc9,0x94,
    0x8f,0xe3,0x0b,0xbf,0xf2,0x66,0x0b,0xe1,0x71,0x5a,0x45,0x89,0x33,0x4c,0x74,0xc7
};

static const uint8_t S2_Gy_BYTES[32] = {
    0xbc,0x37,0x36,0xa2,0xf4,0xf6,0x77,0x9c,0x59,0xbd,0xce,0xe3,0x6b,0x69,0x21,0x53,
    0xd0,0xa9,0x87,0x7c,0xc6,0x2a,0x47,0x40,0x02,0xdf,0x32,0xe5,0x21,0x39,0xf0,0xa0
};

// ═══════════════════════════════════════════════════════════════════════
//  256 位无符号整数 (little-endian limbs, v[0] = 最低位)
// ═══════════════════════════════════════════════════════════════════════

struct uint256 { uint64_t v[4]; };
struct uint512 { uint64_t v[8]; };

static void u256_from_be(uint256* r, const uint8_t b[32]) {
    for (int i = 0; i < 4; ++i) {
        int j = 32 - 8 * (i + 1);
        r->v[i] = ((uint64_t)b[j]   << 56) | ((uint64_t)b[j+1] << 48) |
                  ((uint64_t)b[j+2] << 40) | ((uint64_t)b[j+3] << 32) |
                  ((uint64_t)b[j+4] << 24) | ((uint64_t)b[j+5] << 16) |
                  ((uint64_t)b[j+6] << 8)  |  (uint64_t)b[j+7];
    }
}

static void u256_to_be(const uint256* a, uint8_t b[32]) {
    for (int i = 0; i < 4; ++i) {
        int j = 32 - 8 * (i + 1);
        b[j]   = (uint8_t)(a->v[i] >> 56);
        b[j+1] = (uint8_t)(a->v[i] >> 48);
        b[j+2] = (uint8_t)(a->v[i] >> 40);
        b[j+3] = (uint8_t)(a->v[i] >> 32);
        b[j+4] = (uint8_t)(a->v[i] >> 24);
        b[j+5] = (uint8_t)(a->v[i] >> 16);
        b[j+6] = (uint8_t)(a->v[i] >> 8);
        b[j+7] = (uint8_t)(a->v[i]);
    }
}

static bool u256_is_zero(const uint256* a) {
    return a->v[0]==0 && a->v[1]==0 && a->v[2]==0 && a->v[3]==0;
}

static bool u256_eq(const uint256* a, const uint256* b) {
    return a->v[0]==b->v[0] && a->v[1]==b->v[1] && a->v[2]==b->v[2] && a->v[3]==b->v[3];
}

static bool u256_lt(const uint256* a, const uint256* b) {
    for (int i = 3; i >= 0; --i) {
        if (a->v[i] < b->v[i]) return true;
        if (a->v[i] > b->v[i]) return false;
    }
    return false;
}

static uint64_t u256_add(uint256* r, const uint256* a, const uint256* b) {
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        __uint128_t t = (__uint128_t)a->v[i] + b->v[i] + carry;
        r->v[i] = (uint64_t)t;
        carry = (uint64_t)(t >> 64);
    }
    return carry;
}

static uint64_t u256_sub(uint256* r, const uint256* a, const uint256* b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        __uint128_t t = (__uint128_t)a->v[i] - b->v[i] - borrow;
        r->v[i] = (uint64_t)t;
        borrow = (t >> 64) ? 1 : 0;
    }
    return borrow;
}

static void u256_mul_full(uint512* r, const uint256* a, const uint256* b) {
    for (int i = 0; i < 8; ++i) r->v[i] = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            __uint128_t t = (__uint128_t)a->v[i] * b->v[j] + r->v[i+j] + carry;
            r->v[i+j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        r->v[i+4] = carry;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  模运算
// ═══════════════════════════════════════════════════════════════════════

static void mod_reduce_512(uint256* r, const uint512* a, const uint256* m) {
    uint64_t acc[5] = {0,0,0,0,0};
    uint64_t mlimb[5] = {m->v[0], m->v[1], m->v[2], m->v[3], 0};
    for (int i = 7; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            uint64_t carry = (a->v[i] >> bit) & 1;
            for (int j = 0; j < 5; ++j) {
                uint64_t nc = acc[j] >> 63;
                acc[j] = (acc[j] << 1) | carry;
                carry = nc;
            }
            bool ge = false;
            if (acc[4] > 0) ge = true;
            else {
                for (int j = 3; j >= 0; --j) {
                    if (acc[j] > mlimb[j]) { ge = true; break; }
                    if (acc[j] < mlimb[j]) { ge = false; break; }
                    if (j == 0) ge = true;
                }
            }
            if (ge) {
                uint64_t borrow = 0;
                for (int j = 0; j < 5; ++j) {
                    __uint128_t t = (__uint128_t)acc[j] - mlimb[j] - borrow;
                    acc[j] = (uint64_t)t;
                    borrow = (t >> 64) ? 1 : 0;
                }
            }
        }
    }
    r->v[0] = acc[0]; r->v[1] = acc[1]; r->v[2] = acc[2]; r->v[3] = acc[3];
}

static void mod_reduce_256(uint256* r, const uint256* a, const uint256* m) {
    if (u256_lt(a, m)) { *r = *a; return; }
    u256_sub(r, a, m);
}

static void mm_add(uint256* r, const uint256* a, const uint256* b, const uint256* m) {
    uint64_t carry = u256_add(r, a, b);
    if (carry || !u256_lt(r, m)) u256_sub(r, r, m);
}

static void mm_sub(uint256* r, const uint256* a, const uint256* b, const uint256* m) {
    uint64_t borrow = u256_sub(r, a, b);
    if (borrow) u256_add(r, r, m);
}

static void mm_mul(uint256* r, const uint256* a, const uint256* b, const uint256* m) {
    uint512 prod;
    u256_mul_full(&prod, a, b);
    mod_reduce_512(r, &prod, m);
}

static void mm_sqr(uint256* r, const uint256* a, const uint256* m) {
    mm_mul(r, a, a, m);
}

static void mm_inv(uint256* r, const uint256* a, const uint256* m) {
    uint256 two = {2,0,0,0};
    uint256 exp;
    u256_sub(&exp, m, &two);
    uint256 base = *a;
    uint256 result = {1,0,0,0};
    for (int i = 3; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            mm_sqr(&result, &result, m);
            if ((exp.v[i] >> bit) & 1)
                mm_mul(&result, &result, &base, m);
        }
    }
    *r = result;
}

// ═══════════════════════════════════════════════════════════════════════
//  Jacobian 坐标点运算
// ═══════════════════════════════════════════════════════════════════════

struct jac_point { uint256 X, Y, Z; };

static uint256 G_S2_P, G_S2_N, G_S2_Gx, G_S2_Gy;
static bool g_sm2_init = false;

static void sm2_init_params() {
    if (g_sm2_init) return;
    u256_from_be(&G_S2_P,  S2_P_BYTES);
    u256_from_be(&G_S2_N,  S2_N_BYTES);
    u256_from_be(&G_S2_Gx, S2_Gx_BYTES);
    u256_from_be(&G_S2_Gy, S2_Gy_BYTES);
    g_sm2_init = true;
}

static bool jac_is_inf(const jac_point* P) { return u256_is_zero(&P->Z); }

static void jac_inf(jac_point* P) {
    P->X = {1,0,0,0}; P->Y = {1,0,0,0}; P->Z = {0,0,0,0};
}

// 倍点 R = 2P (a = -3 mod p, dbl-2001-b)
static void jac_dbl(jac_point* R, const jac_point* P) {
    if (jac_is_inf(P)) { jac_inf(R); return; }
    const uint256* p = &G_S2_P;
    uint256 A, B, C, D, E, t, X3, Y3, Z3;

    mm_sqr(&A, &P->X, p);
    mm_sqr(&B, &P->Y, p);
    mm_sqr(&C, &B, p);
    mm_add(&t, &P->X, &B, p);
    mm_sqr(&t, &t, p);
    mm_sub(&t, &t, &A, p);
    mm_sub(&t, &t, &C, p);
    mm_add(&D, &t, &t, p);
    // E = 3*(X^2 - Z^4) [a = -3]
    mm_sqr(&t, &P->Z, p);
    mm_sqr(&t, &t, p);
    mm_sub(&t, &A, &t, p);
    mm_add(&E, &t, &t, p);
    mm_add(&E, &E, &t, p);
    // X3 = E^2 - 2D
    mm_sqr(&X3, &E, p);
    mm_add(&t, &D, &D, p);
    mm_sub(&X3, &X3, &t, p);
    // Y3 = E*(D - X3) - 8C
    mm_sub(&t, &D, &X3, p);
    mm_mul(&Y3, &E, &t, p);
    mm_add(&t, &C, &C, p);
    mm_add(&t, &t, &t, p);
    mm_add(&t, &t, &t, p);
    mm_sub(&Y3, &Y3, &t, p);
    // Z3 = 2*Y*Z
    mm_mul(&Z3, &P->Y, &P->Z, p);
    mm_add(&Z3, &Z3, &Z3, p);

    R->X = X3; R->Y = Y3; R->Z = Z3;
}

// 点加 R = P + Q (add-2007-bl)
static void jac_add(jac_point* R, const jac_point* P, const jac_point* Q) {
    if (jac_is_inf(P)) { *R = *Q; return; }
    if (jac_is_inf(Q)) { *R = *P; return; }
    const uint256* p = &G_S2_P;
    uint256 Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, V, r, t, X3, Y3, Z3;

    mm_sqr(&Z1Z1, &P->Z, p);
    mm_sqr(&Z2Z2, &Q->Z, p);
    mm_mul(&U1, &P->X, &Z2Z2, p);
    mm_mul(&U2, &Q->X, &Z1Z1, p);
    mm_mul(&S1, &P->Y, &Q->Z, p);
    mm_mul(&S1, &S1, &Z2Z2, p);
    mm_mul(&S2, &Q->Y, &P->Z, p);
    mm_mul(&S2, &S2, &Z1Z1, p);

    mm_sub(&H, &U2, &U1, p);
    mm_sub(&t, &S2, &S1, p);
    if (u256_is_zero(&H)) {
        if (u256_is_zero(&t)) { jac_dbl(R, P); return; }
        jac_inf(R); return;
    }
    mm_add(&r, &t, &t, p);
    mm_add(&t, &H, &H, p);
    mm_sqr(&I, &t, p);
    mm_mul(&J, &H, &I, p);
    mm_mul(&V, &U1, &I, p);
    // X3 = r^2 - J - 2V
    mm_sqr(&X3, &r, p);
    mm_sub(&X3, &X3, &J, p);
    mm_add(&t, &V, &V, p);
    mm_sub(&X3, &X3, &t, p);
    // Y3 = r*(V - X3) - 2*S1*J
    mm_sub(&t, &V, &X3, p);
    mm_mul(&Y3, &r, &t, p);
    mm_mul(&t, &S1, &J, p);
    mm_add(&t, &t, &t, p);
    mm_sub(&Y3, &Y3, &t, p);
    // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
    mm_add(&t, &P->Z, &Q->Z, p);
    mm_sqr(&t, &t, p);
    mm_sub(&t, &t, &Z1Z1, p);
    mm_sub(&t, &t, &Z2Z2, p);
    mm_mul(&Z3, &t, &H, p);

    R->X = X3; R->Y = Y3; R->Z = Z3;
}

static void scalar_mult(jac_point* R, const uint256* k, const jac_point* P) {
    jac_inf(R);
    for (int i = 3; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            jac_dbl(R, R);
            if ((k->v[i] >> bit) & 1)
                jac_add(R, R, P);
        }
    }
}

static void scalar_mult_G(jac_point* R, const uint256* k) {
    jac_point G;
    G.X = G_S2_Gx; G.Y = G_S2_Gy; G.Z = {1,0,0,0};
    scalar_mult(R, k, &G);
}

static void jac_to_affine(uint256* x, uint256* y, const jac_point* P) {
    if (jac_is_inf(P)) {
        if (x) std::memset(x, 0, sizeof(uint256));
        if (y) std::memset(y, 0, sizeof(uint256));
        return;
    }
    uint256 Zinv, Zinv2, Zinv3;
    mm_inv(&Zinv, &P->Z, &G_S2_P);
    mm_sqr(&Zinv2, &Zinv, &G_S2_P);
    mm_mul(&Zinv3, &Zinv2, &Zinv, &G_S2_P);
    if (x) mm_mul(x, &P->X, &Zinv2, &G_S2_P);
    if (y) mm_mul(y, &P->Y, &Zinv3, &G_S2_P);
}

// ═══════════════════════════════════════════════════════════════════════
//  辅助
// ═══════════════════════════════════════════════════════════════════════

static void rand_bytes(uint8_t* buf, size_t len) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    for (size_t i = 0; i < len; i += 8) {
        uint64_t v = gen();
        for (int j = 0; j < 8 && i + j < len; ++j)
            buf[i + j] = (uint8_t)(v >> (j * 8));
    }
}

static void rand_scalar(uint256* k) {
    uint8_t buf[32];
    do {
        rand_bytes(buf, 32);
        u256_from_be(k, buf);
        if (!u256_lt(k, &G_S2_N)) u256_sub(k, k, &G_S2_N);
    } while (u256_is_zero(k));
}

/// SM3 哈希，输出 32 字节（大端）
static void sm3_hash_bytes(const uint8_t* msg, size_t len, uint8_t digest[32]) {
    sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, msg, len);
    sm3_final(&ctx, digest);
}

/// 带 ZA 的 SM2 哈希：e = SM3(ZA || M)
static void sm2_hash(uint8_t e[32], const uint8_t* msg, size_t msg_len,
                     const uint8_t za[32]) {
    sm3_ctx ctx;
    sm3_init(&ctx);
    if (za != nullptr) {
        sm3_update(&ctx, za, SM2_ZA_SIZE);
    }
    sm3_update(&ctx, msg, msg_len);
    sm3_final(&ctx, e);
}

// ═══════════════════════════════════════════════════════════════════════
//  SM2 API
// ═══════════════════════════════════════════════════════════════════════

void sm2_keygen(uint8_t pub[SM2_PUB_SIZE], uint8_t priv[SM2_KEY_SIZE]) {
    sm2_init_params();
    uint256 d;
    rand_scalar(&d);
    u256_to_be(&d, priv);

    jac_point Q;
    scalar_mult_G(&Q, &d);
    uint256 Qx, Qy;
    jac_to_affine(&Qx, &Qy, &Q);
    u256_to_be(&Qx, pub);
    u256_to_be(&Qy, pub + 32);
}

void sm2_pub_from_priv(const uint8_t priv[SM2_KEY_SIZE],
                       uint8_t pub[SM2_PUB_SIZE]) {
    sm2_init_params();
    uint256 d;
    u256_from_be(&d, priv);

    jac_point Q;
    scalar_mult_G(&Q, &d);
    uint256 Qx, Qy;
    jac_to_affine(&Qx, &Qy, &Q);
    u256_to_be(&Qx, pub);
    u256_to_be(&Qy, pub + 32);
}

void sm2_sign(const uint8_t priv[SM2_KEY_SIZE],
              const uint8_t* msg, size_t msg_len,
              uint8_t sig[SM2_SIG_SIZE],
              const uint8_t za[SM2_ZA_SIZE]) {
    sm2_init_params();
    uint256 d;
    u256_from_be(&d, priv);

    // e = SM3(ZA || M)
    uint8_t e_bytes[32];
    sm2_hash(e_bytes, msg, msg_len, za);
    uint256 e;
    u256_from_be(&e, e_bytes);

    uint256 r, s, k, one_plus_d, inv_1d, rd, kr, x1;
    jac_point R;
    do {
        rand_scalar(&k);
        scalar_mult_G(&R, &k);
        jac_to_affine(&x1, nullptr, &R);
        // r = (e + x1) mod n
        mm_add(&r, &e, &x1, &G_S2_N);
        if (u256_is_zero(&r)) continue;
        // check r + k != n
        uint256 t;
        mm_add(&t, &r, &k, &G_S2_N);
        if (u256_is_zero(&t)) continue;
        // s = ((1+d)^-1 * (k - r*d)) mod n
        uint256 one = {1,0,0,0};
        mm_add(&one_plus_d, &one, &d, &G_S2_N);
        mm_inv(&inv_1d, &one_plus_d, &G_S2_N);
        mm_mul(&rd, &r, &d, &G_S2_N);
        mm_sub(&kr, &k, &rd, &G_S2_N);
        mm_mul(&s, &inv_1d, &kr, &G_S2_N);
    } while (u256_is_zero(&s));

    u256_to_be(&r, sig);
    u256_to_be(&s, sig + 32);
}

bool sm2_verify(const uint8_t pub[SM2_PUB_SIZE],
                const uint8_t* msg, size_t msg_len,
                const uint8_t sig[SM2_SIG_SIZE],
                const uint8_t za[SM2_ZA_SIZE]) {
    sm2_init_params();
    uint256 r, s;
    u256_from_be(&r, sig);
    u256_from_be(&s, sig + 32);

    // 检查 r, s ∈ [1, n-1]
    if (u256_is_zero(&r) || u256_is_zero(&s)) return false;
    if (!u256_lt(&r, &G_S2_N)) return false;
    if (!u256_lt(&s, &G_S2_N)) return false;

    // e = SM3(ZA || M)
    uint8_t e_bytes[32];
    sm2_hash(e_bytes, msg, msg_len, za);
    uint256 e;
    u256_from_be(&e, e_bytes);

    // t = (r + s) mod n
    uint256 t;
    mm_add(&t, &r, &s, &G_S2_N);
    if (u256_is_zero(&t)) return false;  // t == 0 → 无效

    // (x1, y1) = s * G + t * PA
    jac_point sG;
    scalar_mult_G(&sG, &s);

    jac_point Q;
    u256_from_be(&Q.X, pub);
    u256_from_be(&Q.Y, pub + 32);
    Q.Z = {1,0,0,0};

    jac_point tQ;
    scalar_mult(&tQ, &t, &Q);

    jac_point R;
    jac_add(&R, &sG, &tQ);

    if (jac_is_inf(&R)) return false;

    uint256 x1;
    jac_to_affine(&x1, nullptr, &R);

    // R' = (e + x1) mod n
    uint256 v;
    mm_add(&v, &e, &x1, &G_S2_N);

    return u256_eq(&v, &r);
}

void sm2_compute_za(const uint8_t* id, size_t id_len,
                    const uint8_t pub_x[SM2_KEY_SIZE],
                    const uint8_t pub_y[SM2_KEY_SIZE],
                    uint8_t za[SM2_ZA_SIZE]) {
    sm2_init_params();

    // ENTL: id bit length as big-endian 16-bit
    uint16_t entl = (uint16_t)(id_len * 8);
    uint8_t entl_buf[2] = { (uint8_t)(entl >> 8), (uint8_t)(entl) };

    // ZA = SM3(ENTL || ID || a || b || Gx || Gy || xA || yA)
    sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, entl_buf, 2);                 // ENTL (2 bytes)
    sm3_update(&ctx, id, id_len);                   // ID
    sm3_update(&ctx, S2_A_BYTES, 32);               // a (curve param)
    sm3_update(&ctx, S2_B_BYTES, 32);               // b (curve param)
    sm3_update(&ctx, S2_Gx_BYTES, 32);              // Gx
    sm3_update(&ctx, S2_Gy_BYTES, 32);              // Gy
    sm3_update(&ctx, pub_x, SM2_KEY_SIZE);           // xA (public key X)
    sm3_update(&ctx, pub_y, SM2_KEY_SIZE);           // yA (public key Y)
    sm3_final(&ctx, za);
}

} // namespace jpssl
