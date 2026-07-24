// ECDSA P-256 (secp256r1 / prime256v1) 完整实现
// 对外字节序：公钥/签名/私钥均为大端（标准格式）
// 内部 uint256 使用 little-endian limbs[0..3]（limbs[0] 为最低位）
#include "ecdsa.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include <cstring>
#include <random>

namespace jpssl {

// ════════════════════════════════════════════════════════════════════
//  P-256 域参数 (FIPS 186-4, NIST secp256r1) — 大端字节序
// ════════════════════════════════════════════════════════════════════

// 素域 p = 2^256 - 2^224 + 2^192 + 2^96 - 1
static const uint8_t P_BYTES[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};
static const uint8_t Gx_BYTES[32] = {
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96
};
static const uint8_t Gy_BYTES[32] = {
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
};
// 群阶 n
static const uint8_t N_BYTES[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51
};

// ════════════════════════════════════════════════════════════════════
//  256 位无符号整数 (little-endian limbs, v[0] = 最低位)
// ════════════════════════════════════════════════════════════════════

struct uint256 { uint64_t v[4]; };

// 512 位结果
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

// r = a + b, 返回进位
static uint64_t u256_add(uint256* r, const uint256* a, const uint256* b) {
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        __uint128_t t = (__uint128_t)a->v[i] + b->v[i] + carry;
        r->v[i] = (uint64_t)t;
        carry = (uint64_t)(t >> 64);
    }
    return carry;
}

// r = a - b, 返回借位 (1 表示 a < b)
static uint64_t u256_sub(uint256* r, const uint256* a, const uint256* b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        __uint128_t t = (__uint128_t)a->v[i] - b->v[i] - borrow;
        r->v[i] = (uint64_t)t;
        borrow = (t >> 64) ? 1 : 0;
    }
    return borrow;
}

// r = a << 1, 返回溢出位
static uint64_t u256_shl1(uint256* r, const uint256* a) {
    uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t nc = a->v[i] >> 63;
        r->v[i] = (a->v[i] << 1) | carry;
        carry = nc;
    }
    return carry;
}

// r = a * b (512 位)
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

// ════════════════════════════════════════════════════════════════════
//  模运算 (参数化模数 m, 正确性优先)
// ════════════════════════════════════════════════════════════════════

// r = (512 位 a) mod m, 二进制长除法
// acc 使用 5 limbs (320 位) 防止左移溢出丢失进位
static void mod_reduce_512(uint256* r, const uint512* a, const uint256* m) {
    uint64_t acc[5] = {0,0,0,0,0};
    uint64_t mlimb[5] = {m->v[0], m->v[1], m->v[2], m->v[3], 0};
    for (int i = 7; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            // acc = acc << 1 (320 位)
            uint64_t carry = (a->v[i] >> bit) & 1;
            for (int j = 0; j < 5; ++j) {
                uint64_t nc = acc[j] >> 63;
                acc[j] = (acc[j] << 1) | carry;
                carry = nc;
            }
            // 如果 acc >= m (比较 320 位，但 m 只有 256 位，acc[4] 为高 limb)
            bool ge = false;
            if (acc[4] > 0) ge = true;
            else {
                for (int j = 3; j >= 0; --j) {
                    if (acc[j] > mlimb[j]) { ge = true; break; }
                    if (acc[j] < mlimb[j]) { ge = false; break; }
                    if (j == 0) ge = true; // 相等也减
                }
            }
            if (ge) {
                // acc -= m
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

// r = a mod m (a 是 256 位, a < 2m)
static void mod_reduce_256(uint256* r, const uint256* a, const uint256* m) {
    if (u256_lt(a, m)) { *r = *a; return; }
    u256_sub(r, a, m);
}

// r = (a + b) mod m
static void mm_add(uint256* r, const uint256* a, const uint256* b, const uint256* m) {
    uint64_t carry = u256_add(r, a, b);
    if (carry || !u256_lt(r, m)) u256_sub(r, r, m);
}

// r = (a - b) mod m
static void mm_sub(uint256* r, const uint256* a, const uint256* b, const uint256* m) {
    uint64_t borrow = u256_sub(r, a, b);
    if (borrow) u256_add(r, r, m);
}

// r = (a * b) mod m
static void mm_mul(uint256* r, const uint256* a, const uint256* b, const uint256* m) {
    uint512 prod;
    u256_mul_full(&prod, a, b);
    mod_reduce_512(r, &prod, m);
}

// r = (a^2) mod m
static void mm_sqr(uint256* r, const uint256* a, const uint256* m) {
    mm_mul(r, a, a, m);
}

// r = a^{-1} mod m (Fermat: a^{m-2})
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

// ════════════════════════════════════════════════════════════════════
//  Jacobian 坐标点运算
//  (X,Y,Z) 表示仿射 (X/Z^2, Y/Z^3); 无穷远点 Z=0
// ════════════════════════════════════════════════════════════════════

struct jac_point { uint256 X, Y, Z; };

// 全局域参数 (init_params 填充)
static uint256 G_P, G_N, G_Gx, G_Gy;
static bool g_init = false;

static void init_params() {
    if (g_init) return;
    u256_from_be(&G_P,  P_BYTES);
    u256_from_be(&G_N,  N_BYTES);
    u256_from_be(&G_Gx, Gx_BYTES);
    u256_from_be(&G_Gy, Gy_BYTES);
    g_init = true;
}

static bool jac_is_inf(const jac_point* P) { return u256_is_zero(&P->Z); }
static void jac_inf(jac_point* P) {
    P->X = {1,0,0,0}; P->Y = {1,0,0,0}; P->Z = {0,0,0,0};
}

// 倍点 R = 2P, a = -3, EFD dbl-2001-b
static void jac_dbl(jac_point* R, const jac_point* P) {
    if (jac_is_inf(P)) { jac_inf(R); return; }
    const uint256* p = &G_P;
    uint256 A, B, C, D, E, t, X3, Y3, Z3;

    mm_sqr(&A, &P->X, p);              // A = X^2
    mm_sqr(&B, &P->Y, p);              // B = Y^2
    mm_sqr(&C, &B, p);                 // C = B^2
    // D = 2*((X+B)^2 - A - C)
    mm_add(&t, &P->X, &B, p);
    mm_sqr(&t, &t, p);
    mm_sub(&t, &t, &A, p);
    mm_sub(&t, &t, &C, p);
    mm_add(&D, &t, &t, p);
    // E = 3*(X^2 - Z^4)   [a = -3]
    mm_sqr(&t, &P->Z, p);             // Z^2
    mm_sqr(&t, &t, p);                // Z^4
    mm_sub(&t, &A, &t, p);            // X^2 - Z^4
    mm_add(&E, &t, &t, p);            // 2*(...)
    mm_add(&E, &E, &t, p);            // 3*(...)
    // X3 = E^2 - 2D
    mm_sqr(&X3, &E, p);
    mm_add(&t, &D, &D, p);
    mm_sub(&X3, &X3, &t, p);
    // Y3 = E*(D - X3) - 8C
    mm_sub(&t, &D, &X3, p);
    mm_mul(&Y3, &E, &t, p);
    mm_add(&t, &C, &C, p);
    mm_add(&t, &t, &t, p);
    mm_add(&t, &t, &t, p);            // 8C
    mm_sub(&Y3, &Y3, &t, p);
    // Z3 = 2*Y*Z
    mm_mul(&Z3, &P->Y, &P->Z, p);
    mm_add(&Z3, &Z3, &Z3, p);

    R->X = X3; R->Y = Y3; R->Z = Z3;
}

// 点加 R = P + Q (混合: P,Q 均 Jacobian), EFD add-2007-bl
static void jac_add(jac_point* R, const jac_point* P, const jac_point* Q) {
    if (jac_is_inf(P)) { *R = *Q; return; }
    if (jac_is_inf(Q)) { *R = *P; return; }
    const uint256* p = &G_P;
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
    mm_sub(&t, &S2, &S1, p);         // S2 - S1
    if (u256_is_zero(&H)) {
        if (u256_is_zero(&t)) { jac_dbl(R, P); return; }
        jac_inf(R); return;
    }
    mm_add(&r, &t, &t, p);        // r = 2*(S2-S1)
    mm_add(&t, &H, &H, p);        // t = 2H
    mm_sqr(&I, &t, p);            // I = (2H)^2
    mm_mul(&J, &H, &I, p);        // J = H*I
    mm_mul(&V, &U1, &I, p);       // V = U1*I
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

// 标量乘法 R = k * P (left-to-right double-and-add)
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

// R = k * G
static void scalar_mult_G(jac_point* R, const uint256* k) {
    jac_point G;
    G.X = G_Gx; G.Y = G_Gy; G.Z = {1,0,0,0};
    scalar_mult(R, k, &G);
}

// Jacobian -> 仿射
static void jac_to_affine(uint256* x, uint256* y, const jac_point* P) {
    if (jac_is_inf(P)) {
        if (x) memset(x, 0, 32);
        if (y) memset(y, 0, 32);
        return;
    }
    uint256 Zinv, Zinv2, Zinv3;
    mm_inv(&Zinv, &P->Z, &G_P);
    mm_sqr(&Zinv2, &Zinv, &G_P);
    mm_mul(&Zinv3, &Zinv2, &Zinv, &G_P);
    if (x) mm_mul(x, &P->X, &Zinv2, &G_P);
    if (y) mm_mul(y, &P->Y, &Zinv3, &G_P);
}

// ════════════════════════════════════════════════════════════════════
//  辅助
// ════════════════════════════════════════════════════════════════════

static void hash_to_e(const uint8_t* msg, size_t msg_len, uint8_t e[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, msg, msg_len);
    sha256_final(&ctx, e);
}

static void rand_bytes(uint8_t* buf, size_t len) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    for (size_t i = 0; i < len; i += 8) {
        uint64_t v = gen();
        for (int j = 0; j < 8 && i + j < len; ++j)
            buf[i + j] = (uint8_t)(v >> (j * 8));
    }
}

// 生成 [1, n-1] 随机标量
static void rand_scalar(uint256* k) {
    uint8_t buf[32];
    do {
        rand_bytes(buf, 32);
        u256_from_be(k, buf);
        if (!u256_lt(k, &G_N)) u256_sub(k, k, &G_N);
    } while (u256_is_zero(k));
}

// ════════════════════════════════════════════════════════════════════
//  ECDSA API
// ════════════════════════════════════════════════════════════════════

void ecdsa_p256_keygen(uint8_t pub[64], uint8_t priv[32]) {
    init_params();
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

void ecdsa_p256_sign(const uint8_t priv[32], const uint8_t* msg, size_t msg_len, uint8_t sig[64]) {
    init_params();
    uint256 d;
    u256_from_be(&d, priv);

    uint8_t e_bytes[32];
    hash_to_e(msg, msg_len, e_bytes);
    uint256 e;
    u256_from_be(&e, e_bytes);

    uint256 r, s, k, k_inv, rd, ed, Rx;
    jac_point R;
    do {
        rand_scalar(&k);
        scalar_mult_G(&R, &k);
        jac_to_affine(&Rx, nullptr, &R);
        mod_reduce_256(&r, &Rx, &G_N);
        if (u256_is_zero(&r)) continue;
        mm_inv(&k_inv, &k, &G_N);
        mm_mul(&rd, &r, &d, &G_N);
        mm_add(&ed, &e, &rd, &G_N);
        mm_mul(&s, &k_inv, &ed, &G_N);
    } while (u256_is_zero(&s));

    u256_to_be(&r, sig);
    u256_to_be(&s, sig + 32);
}

bool ecdsa_p256_verify(const uint8_t pub[64], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]) {
    init_params();
    uint256 r, s;
    u256_from_be(&r, sig);
    u256_from_be(&s, sig + 32);

    if (u256_is_zero(&r) || u256_is_zero(&s)) return false;
    if (!u256_lt(&r, &G_N)) return false;
    if (!u256_lt(&s, &G_N)) return false;

    uint8_t e_bytes[32];
    hash_to_e(msg, msg_len, e_bytes);
    uint256 e;
    u256_from_be(&e, e_bytes);

    uint256 w, u1, u2;
    mm_inv(&w, &s, &G_N);
    mm_mul(&u1, &e, &w, &G_N);
    mm_mul(&u2, &r, &w, &G_N);

    jac_point u1G;
    scalar_mult_G(&u1G, &u1);

    jac_point Q;
    u256_from_be(&Q.X, pub);
    u256_from_be(&Q.Y, pub + 32);
    Q.Z = {1,0,0,0};

    jac_point u2Q;
    scalar_mult(&u2Q, &u2, &Q);

    jac_point R;
    jac_add(&R, &u1G, &u2Q);

    if (jac_is_inf(&R)) return false;

    uint256 Rx;
    jac_to_affine(&Rx, nullptr, &R);
    uint256 v;
    mod_reduce_256(&v, &Rx, &G_N);

    return u256_eq(&v, &r);
}

// ════════════════════════════════════════════════════════════════════
//  ECDSA P-384 (secp384r1)
//  384 位大整数 = 6 × uint64_t, big-endian 对外接口
// ════════════════════════════════════════════════════════════════════

// P-384 域参数 (FIPS 186-4, NIST secp384r1) - 大端字节序
static const uint8_t P384_P_BYTES[48] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff
};
static const uint8_t P384_Gx_BYTES[48] = {
    0xaa,0x87,0xca,0x22,0xbe,0x8b,0x05,0x37,0x8e,0xb1,0xc7,0x1e,0xf3,0x20,0xad,0x74,
    0x6e,0x1d,0x3b,0x62,0x8b,0xa7,0x9b,0x98,0x59,0xf7,0x41,0xe0,0x82,0x54,0x2a,0x38,
    0x55,0x02,0xf2,0x5d,0xbf,0x55,0x29,0x6c,0x3a,0x54,0x5e,0x38,0x72,0x76,0x0a,0xb7
};
static const uint8_t P384_Gy_BYTES[48] = {
    0x36,0x17,0xde,0x4a,0x96,0x26,0x2c,0x6f,0x5d,0x9e,0x98,0xbf,0x92,0x92,0xdc,0x29,
    0xf8,0xf4,0x1d,0xbd,0x28,0x9a,0x14,0x7c,0xe9,0xda,0x31,0x13,0xb5,0xf0,0xb8,0xc0,
    0x0a,0x60,0xb1,0xce,0x1d,0x7e,0x81,0x9d,0x7a,0x43,0x1d,0x7c,0x90,0xea,0x0e,0x5f
};
static const uint8_t P384_N_BYTES[48] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc7,0x63,0x4d,0x81,0xf4,0x37,0x2d,0xdf,
    0x58,0x1a,0x0d,0xb2,0x48,0xb0,0xa7,0x7a,0xec,0xec,0x19,0x6a,0xcc,0xc5,0x29,0x73
};

// 384 位无符号整数 (little-endian limbs, v[0] = 最低位)
struct uint384 { uint64_t v[6]; };
struct uint768 { uint64_t v[12]; };

static void u384_from_be(uint384* r, const uint8_t b[48]) {
    for (int i = 0; i < 6; ++i) {
        int j = 48 - 8 * (i + 1);
        r->v[i] = ((uint64_t)b[j]   << 56) | ((uint64_t)b[j+1] << 48) |
                  ((uint64_t)b[j+2] << 40) | ((uint64_t)b[j+3] << 32) |
                  ((uint64_t)b[j+4] << 24) | ((uint64_t)b[j+5] << 16) |
                  ((uint64_t)b[j+6] << 8)  |  (uint64_t)b[j+7];
    }
}
static void u384_to_be(const uint384* a, uint8_t b[48]) {
    for (int i = 0; i < 6; ++i) {
        int j = 48 - 8 * (i + 1);
        b[j]   = (uint8_t)(a->v[i] >> 56); b[j+1] = (uint8_t)(a->v[i] >> 48);
        b[j+2] = (uint8_t)(a->v[i] >> 40); b[j+3] = (uint8_t)(a->v[i] >> 32);
        b[j+4] = (uint8_t)(a->v[i] >> 24); b[j+5] = (uint8_t)(a->v[i] >> 16);
        b[j+6] = (uint8_t)(a->v[i] >> 8);  b[j+7] = (uint8_t)(a->v[i]);
    }
}
static bool u384_is_zero(const uint384* a) {
    for (int i = 0; i < 6; ++i) if (a->v[i]) return false;
    return true;
}
static bool u384_eq(const uint384* a, const uint384* b) {
    for (int i = 0; i < 6; ++i) if (a->v[i] != b->v[i]) return false;
    return true;
}
static bool u384_lt(const uint384* a, const uint384* b) {
    for (int i = 5; i >= 0; --i) {
        if (a->v[i] < b->v[i]) return true;
        if (a->v[i] > b->v[i]) return false;
    }
    return false;
}
static uint64_t u384_add(uint384* r, const uint384* a, const uint384* b) {
    uint64_t carry = 0;
    for (int i = 0; i < 6; ++i) {
        __uint128_t t = (__uint128_t)a->v[i] + b->v[i] + carry;
        r->v[i] = (uint64_t)t;
        carry = (uint64_t)(t >> 64);
    }
    return carry;
}
static uint64_t u384_sub(uint384* r, const uint384* a, const uint384* b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 6; ++i) {
        __uint128_t t = (__uint128_t)a->v[i] - b->v[i] - borrow;
        r->v[i] = (uint64_t)t;
        borrow = (t >> 64) ? 1 : 0;
    }
    return borrow;
}
static void u384_mul_full(uint768* r, const uint384* a, const uint384* b) {
    for (int i = 0; i < 12; ++i) r->v[i] = 0;
    for (int i = 0; i < 6; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 6; ++j) {
            __uint128_t t = (__uint128_t)a->v[i] * b->v[j] + r->v[i+j] + carry;
            r->v[i+j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        r->v[i+6] = carry;
    }
}

// ── 模运算 (384 位, 参数化模数 m) ──

// r = (768 位 a) mod m, 二进制长除法, 7-limb (448 位) 累加器
static void mod384_reduce_768(uint384* r, const uint768* a, const uint384* m) {
    uint64_t acc[7] = {0,0,0,0,0,0,0};
    uint64_t ml[7] = {m->v[0], m->v[1], m->v[2], m->v[3], m->v[4], m->v[5], 0};
    for (int i = 11; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            uint64_t carry = (a->v[i] >> bit) & 1;
            for (int j = 0; j < 7; ++j) {
                uint64_t nc = acc[j] >> 63;
                acc[j] = (acc[j] << 1) | carry;
                carry = nc;
            }
            bool ge = false;
            if (acc[6] > 0) ge = true;
            else {
                for (int j = 5; j >= 0; --j) {
                    if (acc[j] > ml[j]) { ge = true; break; }
                    if (acc[j] < ml[j]) { ge = false; break; }
                    if (j == 0) ge = true;
                }
            }
            if (ge) {
                uint64_t borrow = 0;
                for (int j = 0; j < 7; ++j) {
                    __uint128_t t = (__uint128_t)acc[j] - ml[j] - borrow;
                    acc[j] = (uint64_t)t;
                    borrow = (t >> 64) ? 1 : 0;
                }
            }
        }
    }
    for (int i = 0; i < 6; ++i) r->v[i] = acc[i];
}
static void mod384_reduce_384(uint384* r, const uint384* a, const uint384* m) {
    if (u384_lt(a, m)) { *r = *a; return; }
    u384_sub(r, a, m);
}
static void mm384_add(uint384* r, const uint384* a, const uint384* b, const uint384* m) {
    uint64_t carry = u384_add(r, a, b);
    if (carry || !u384_lt(r, m)) u384_sub(r, r, m);
}
static void mm384_sub(uint384* r, const uint384* a, const uint384* b, const uint384* m) {
    uint64_t borrow = u384_sub(r, a, b);
    if (borrow) u384_add(r, r, m);
}
static void mm384_mul(uint384* r, const uint384* a, const uint384* b, const uint384* m) {
    uint768 prod;
    u384_mul_full(&prod, a, b);
    mod384_reduce_768(r, &prod, m);
}
static void mm384_sqr(uint384* r, const uint384* a, const uint384* m) {
    mm384_mul(r, a, a, m);
}
static void mm384_inv(uint384* r, const uint384* a, const uint384* m) {
    uint384 two = {2,0,0,0,0,0};
    uint384 exp;
    u384_sub(&exp, m, &two);
    uint384 base = *a;
    uint384 result = {1,0,0,0,0,0};
    for (int i = 5; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            mm384_sqr(&result, &result, m);
            if ((exp.v[i] >> bit) & 1)
                mm384_mul(&result, &result, &base, m);
        }
    }
    *r = result;
}

// ── P-384 Jacobian 点运算 ──

struct jac384_point { uint384 X, Y, Z; };

static uint384 G384_P, G384_N, G384_Gx, G384_Gy;
static bool g384_init = false;

static void init384_params() {
    if (g384_init) return;
    u384_from_be(&G384_P,  P384_P_BYTES);
    u384_from_be(&G384_N,  P384_N_BYTES);
    u384_from_be(&G384_Gx, P384_Gx_BYTES);
    u384_from_be(&G384_Gy, P384_Gy_BYTES);
    g384_init = true;
}

static bool jac384_is_inf(const jac384_point* P) { return u384_is_zero(&P->Z); }
static void jac384_inf(jac384_point* P) {
    P->X = {1,0,0,0,0,0}; P->Y = {1,0,0,0,0,0}; P->Z = {0,0,0,0,0,0};
}

// 倍点 R = 2P, a = -3, EFD dbl-2001-b
static void jac384_dbl(jac384_point* R, const jac384_point* P) {
    if (jac384_is_inf(P)) { jac384_inf(R); return; }
    const uint384* p = &G384_P;
    uint384 A, B, C, D, E, t, X3, Y3, Z3;

    mm384_sqr(&A, &P->X, p);
    mm384_sqr(&B, &P->Y, p);
    mm384_sqr(&C, &B, p);
    mm384_add(&t, &P->X, &B, p);
    mm384_sqr(&t, &t, p);
    mm384_sub(&t, &t, &A, p);
    mm384_sub(&t, &t, &C, p);
    mm384_add(&D, &t, &t, p);
    // E = 3*(X^2 - Z^4)  [a = -3]
    mm384_sqr(&t, &P->Z, p);
    mm384_sqr(&t, &t, p);
    mm384_sub(&t, &A, &t, p);
    mm384_add(&E, &t, &t, p);
    mm384_add(&E, &E, &t, p);
    // X3 = E^2 - 2D
    mm384_sqr(&X3, &E, p);
    mm384_add(&t, &D, &D, p);
    mm384_sub(&X3, &X3, &t, p);
    // Y3 = E*(D - X3) - 8C
    mm384_sub(&t, &D, &X3, p);
    mm384_mul(&Y3, &E, &t, p);
    mm384_add(&t, &C, &C, p);
    mm384_add(&t, &t, &t, p);
    mm384_add(&t, &t, &t, p);
    mm384_sub(&Y3, &Y3, &t, p);
    // Z3 = 2*Y*Z
    mm384_mul(&Z3, &P->Y, &P->Z, p);
    mm384_add(&Z3, &Z3, &Z3, p);

    R->X = X3; R->Y = Y3; R->Z = Z3;
}

// 点加 R = P + Q, EFD add-2007-bl
static void jac384_add(jac384_point* R, const jac384_point* P, const jac384_point* Q) {
    if (jac384_is_inf(P)) { *R = *Q; return; }
    if (jac384_is_inf(Q)) { *R = *P; return; }
    const uint384* p = &G384_P;
    uint384 Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, V, r, t, X3, Y3, Z3;

    mm384_sqr(&Z1Z1, &P->Z, p);
    mm384_sqr(&Z2Z2, &Q->Z, p);
    mm384_mul(&U1, &P->X, &Z2Z2, p);
    mm384_mul(&U2, &Q->X, &Z1Z1, p);
    mm384_mul(&S1, &P->Y, &Q->Z, p);
    mm384_mul(&S1, &S1, &Z2Z2, p);
    mm384_mul(&S2, &Q->Y, &P->Z, p);
    mm384_mul(&S2, &S2, &Z1Z1, p);

    mm384_sub(&H, &U2, &U1, p);
    mm384_sub(&t, &S2, &S1, p);
    if (u384_is_zero(&H)) {
        if (u384_is_zero(&t)) { jac384_dbl(R, P); return; }
        jac384_inf(R); return;
    }
    mm384_add(&r, &t, &t, p);
    mm384_add(&t, &H, &H, p);
    mm384_sqr(&I, &t, p);
    mm384_mul(&J, &H, &I, p);
    mm384_mul(&V, &U1, &I, p);
    // X3 = r^2 - J - 2V
    mm384_sqr(&X3, &r, p);
    mm384_sub(&X3, &X3, &J, p);
    mm384_add(&t, &V, &V, p);
    mm384_sub(&X3, &X3, &t, p);
    // Y3 = r*(V - X3) - 2*S1*J
    mm384_sub(&t, &V, &X3, p);
    mm384_mul(&Y3, &r, &t, p);
    mm384_mul(&t, &S1, &J, p);
    mm384_add(&t, &t, &t, p);
    mm384_sub(&Y3, &Y3, &t, p);
    // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
    mm384_add(&t, &P->Z, &Q->Z, p);
    mm384_sqr(&t, &t, p);
    mm384_sub(&t, &t, &Z1Z1, p);
    mm384_sub(&t, &t, &Z2Z2, p);
    mm384_mul(&Z3, &t, &H, p);

    R->X = X3; R->Y = Y3; R->Z = Z3;
}

// 标量乘法 R = k * P
static void scalar384_mult(jac384_point* R, const uint384* k, const jac384_point* P) {
    jac384_inf(R);
    for (int i = 5; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            jac384_dbl(R, R);
            if ((k->v[i] >> bit) & 1)
                jac384_add(R, R, P);
        }
    }
}

static void scalar384_mult_G(jac384_point* R, const uint384* k) {
    jac384_point G;
    G.X = G384_Gx; G.Y = G384_Gy; G.Z = {1,0,0,0,0,0};
    scalar384_mult(R, k, &G);
}

static void jac384_to_affine(uint384* x, uint384* y, const jac384_point* P) {
    if (jac384_is_inf(P)) {
        if (x) memset(x, 0, 48);
        if (y) memset(y, 0, 48);
        return;
    }
    uint384 Zinv, Zinv2, Zinv3;
    mm384_inv(&Zinv, &P->Z, &G384_P);
    mm384_sqr(&Zinv2, &Zinv, &G384_P);
    mm384_mul(&Zinv3, &Zinv2, &Zinv, &G384_P);
    if (x) mm384_mul(x, &P->X, &Zinv2, &G384_P);
    if (y) mm384_mul(y, &P->Y, &Zinv3, &G384_P);
}

// ── P-384 辅助 ──

static void hash384_to_e(const uint8_t* msg, size_t msg_len, uint8_t e[48]) {
    sha512_ctx ctx;
    sha384_init(&ctx);
    sha512_update(&ctx, msg, msg_len);
    sha512_final(&ctx, e);
}

static void rand384_scalar(uint384* k) {
    uint8_t buf[48];
    do {
        rand_bytes(buf, 48);
        u384_from_be(k, buf);
        if (!u384_lt(k, &G384_N)) u384_sub(k, k, &G384_N);
    } while (u384_is_zero(k));
}

// ── P-384 ECDSA API ──

void ecdsa_p384_keygen(uint8_t pub[96], uint8_t priv[48]) {
    init384_params();
    uint384 d;
    rand384_scalar(&d);
    u384_to_be(&d, priv);

    jac384_point Q;
    scalar384_mult_G(&Q, &d);
    uint384 Qx, Qy;
    jac384_to_affine(&Qx, &Qy, &Q);
    u384_to_be(&Qx, pub);
    u384_to_be(&Qy, pub + 48);
}

void ecdsa_p384_sign(const uint8_t priv[48], const uint8_t* msg, size_t msg_len, uint8_t sig[96]) {
    init384_params();
    uint384 d;
    u384_from_be(&d, priv);

    uint8_t e_bytes[48];
    hash384_to_e(msg, msg_len, e_bytes);
    uint384 e;
    u384_from_be(&e, e_bytes);

    uint384 r, s, k, k_inv, rd, ed, Rx;
    jac384_point R;
    do {
        rand384_scalar(&k);
        scalar384_mult_G(&R, &k);
        jac384_to_affine(&Rx, nullptr, &R);
        mod384_reduce_384(&r, &Rx, &G384_N);
        if (u384_is_zero(&r)) continue;
        mm384_inv(&k_inv, &k, &G384_N);
        mm384_mul(&rd, &r, &d, &G384_N);
        mm384_add(&ed, &e, &rd, &G384_N);
        mm384_mul(&s, &k_inv, &ed, &G384_N);
    } while (u384_is_zero(&s));

    u384_to_be(&r, sig);
    u384_to_be(&s, sig + 48);
}

bool ecdsa_p384_verify(const uint8_t pub[96], const uint8_t* msg, size_t msg_len, const uint8_t sig[96]) {
    init384_params();
    uint384 r, s;
    u384_from_be(&r, sig);
    u384_from_be(&s, sig + 48);

    if (u384_is_zero(&r) || u384_is_zero(&s)) return false;
    if (!u384_lt(&r, &G384_N)) return false;
    if (!u384_lt(&s, &G384_N)) return false;

    uint8_t e_bytes[48];
    hash384_to_e(msg, msg_len, e_bytes);
    uint384 e;
    u384_from_be(&e, e_bytes);

    uint384 w, u1, u2;
    mm384_inv(&w, &s, &G384_N);
    mm384_mul(&u1, &e, &w, &G384_N);
    mm384_mul(&u2, &r, &w, &G384_N);

    jac384_point u1G;
    scalar384_mult_G(&u1G, &u1);

    jac384_point Q;
    u384_from_be(&Q.X, pub);
    u384_from_be(&Q.Y, pub + 48);
    Q.Z = {1,0,0,0,0,0};

    jac384_point u2Q;
    scalar384_mult(&u2Q, &u2, &Q);

    jac384_point R;
    jac384_add(&R, &u1G, &u2Q);

    if (jac384_is_inf(&R)) return false;

    uint384 Rx;
    jac384_to_affine(&Rx, nullptr, &R);
    uint384 v;
    mod384_reduce_384(&v, &Rx, &G384_N);

    return u384_eq(&v, &r);
}

} // namespace jpssl
