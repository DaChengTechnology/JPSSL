/** sm2.cpp — SM2 椭圆曲线公钥密码算法（GM/T 0003-2012）
 *
 *  基于 SM2 推荐曲线 sm2p256v1（a = -3 mod p，Jacobian 坐标 + dbl-2001-b 倍点）。
 *
 *  优化（相对旧实现）：
 *   - 域运算改用 Montgomery 表示（R = 2^256），4×64 位 CIOS 乘法 / 对称平方，
 *     MSVC 用 _umul128/_addcarry_u64 intrinsic，GCC/Clang 用 __uint128_t；
 *   - 求逆用 Montgomery 快速幂（Fermat），支持批量仿射化（单次求逆）；
 *   - 标量乘改用宽度-5 wNAF：G 的奇倍点表全局预计算（仿射，混合加法），
 *     验签用 Shamir 双标量同时乘（共享倍点），较逐位 double-and-add 显著提速。
 */
#include "sm2.hpp"
#include "sm3.hpp"
#include "rand_os.hpp"
#include "sm2_mont_asm.hpp"
#include <cstring>
#include <random>

#ifdef _MSC_VER
#include <intrin.h>
#pragma intrinsic(_umul128, _addcarry_u64, _subborrow_u64)
#endif

namespace jpssl {

// ─── 曲线参数（GM/T 0003.5-2012，大端字节序）────────────────────────────

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

// ─── 256 位无符号整数（little-endian limbs, v[0] = 最低位）──────────────

struct bn256 { uint64_t v[4]; };

// 64x64 -> 128 位原语
static inline void mul64(uint64_t a, uint64_t b, uint64_t* lo, uint64_t* hi) {
#ifdef _MSC_VER
    *lo = _umul128(a, b, hi);
#else
    __uint128_t t = (__uint128_t)a * b;
    *lo = (uint64_t)t;
    *hi = (uint64_t)(t >> 64);
#endif
}

static inline uint64_t addc(uint64_t a, uint64_t b, uint64_t cin, uint64_t* out) {
#ifdef _MSC_VER
    return (uint64_t)_addcarry_u64((unsigned char)cin, a, b, out);
#else
    __uint128_t t = (__uint128_t)a + b + cin;
    *out = (uint64_t)t;
    return (uint64_t)(t >> 64);
#endif
}

static inline uint64_t subb(uint64_t a, uint64_t b, uint64_t bin, uint64_t* out) {
#ifdef _MSC_VER
    return (uint64_t)_subborrow_u64((unsigned char)bin, a, b, out);
#else
    __uint128_t t = (__uint128_t)a - b - bin;
    *out = (uint64_t)t;
    return (uint64_t)(t >> 64) & 1u;
#endif
}

// 把 (lo, hi) 累加到 t[pos], t[pos+1]，并处理进位；返回需要加到 t[pos+1] 的高字
// （学校乘法逐行模式：与 rsa_body.inc 的 CIOS 累加一致，并显式处理 hi 回绕进位）
static inline uint64_t acc_school(uint64_t* t, int pos, uint64_t lo, uint64_t hi,
                                  uint64_t cin) {
#ifdef _MSC_VER
    unsigned char cf1 = _addcarry_u64(0, lo, t[pos], &lo);
    unsigned char cf2 = _addcarry_u64(0, lo, cin, &lo);
    t[pos] = lo;
    uint64_t old = hi;
    hi = old + (uint64_t)cf1 + (uint64_t)cf2;
    if (hi < old) {  // 高字回绕：向 t[pos+2] 传播 +1
        for (int k = pos + 2; k < 10; ++k) {
            uint64_t s2 = t[k] + 1;
            t[k] = s2;
            if (s2) break;
        }
    }
    return hi;
#else
    __uint128_t s = (__uint128_t)t[pos] + lo + cin;
    t[pos] = (uint64_t)s;
    uint64_t cf = (uint64_t)(s >> 64);
    __uint128_t s2 = (__uint128_t)hi + cf;
    if (s2 >> 64) {
        for (int k = pos + 2; k < 10; ++k) {
            uint64_t s3 = t[k] + 1;
            t[k] = s3;
            if (s3) break;
        }
    }
    return (uint64_t)s2;
#endif
}

static void bn_from_be(bn256* r, const uint8_t b[32]) {
    for (int i = 0; i < 4; ++i) {
        int j = 32 - 8 * (i + 1);
        r->v[i] = ((uint64_t)b[j]   << 56) | ((uint64_t)b[j+1] << 48) |
                  ((uint64_t)b[j+2] << 40) | ((uint64_t)b[j+3] << 32) |
                  ((uint64_t)b[j+4] << 24) | ((uint64_t)b[j+5] << 16) |
                  ((uint64_t)b[j+6] << 8)  |  (uint64_t)b[j+7];
    }
}

static void bn_to_be(const bn256* a, uint8_t b[32]) {
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

static bool bn_is_zero(const bn256* a) {
    return a->v[0] == 0 && a->v[1] == 0 && a->v[2] == 0 && a->v[3] == 0;
}

static bool bn_eq(const bn256* a, const bn256* b) {
    return a->v[0] == b->v[0] && a->v[1] == b->v[1] &&
           a->v[2] == b->v[2] && a->v[3] == b->v[3];
}

static bool bn_lt(const bn256* a, const bn256* b) {
    for (int i = 3; i >= 0; --i) {
        if (a->v[i] < b->v[i]) return true;
        if (a->v[i] > b->v[i]) return false;
    }
    return false;
}

static bool bn_ge(const bn256* a, const bn256* b) { return !bn_lt(a, b); }

static uint64_t bn_add(bn256* r, const bn256* a, const bn256* b) {
    uint64_t c = 0;
    for (int i = 0; i < 4; ++i) c = addc(a->v[i], b->v[i], c, &r->v[i]);
    return c;
}

static uint64_t bn_sub(bn256* r, const bn256* a, const bn256* b) {
    uint64_t bo = 0;
    for (int i = 0; i < 4; ++i) bo = subb(a->v[i], b->v[i], bo, &r->v[i]);
    return bo;
}

static void bn_add_word(bn256* r, uint64_t w) {
    uint64_t c = addc(r->v[0], w, 0, &r->v[0]);
    for (int i = 1; c && i < 4; ++i) c = addc(r->v[i], 0, c, &r->v[i]);
}

static void bn_sub_word(bn256* r, uint64_t w) {
    uint64_t bo = subb(r->v[0], w, 0, &r->v[0]);
    for (int i = 1; bo && i < 4; ++i) bo = subb(r->v[i], 0, bo, &r->v[i]);
}

// ─── Montgomery 域（R = 2^256）──────────────────────────────────────────

struct mod_ctx {
    const bn256* m;   // 模数（奇素数，< 2^256）
    bn256  R2;        // R^2 mod m
    bn256  one;       // R mod m（Montgomery 表示下的 1）
    uint64_t mp;      // -m[0]^{-1} mod 2^64
};

static bn256 P, N, GX, GY, ONE, ZERO;
static mod_ctx MOD_P, MOD_N;
static bool g_sm2_init = false;

// 512 位乘积 t = a*b（t[9] 备用，结果 < 2^512）
static void mul_512(uint64_t t[10], const bn256* a, const bn256* b) {
    for (int k = 0; k < 10; ++k) t[k] = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t ca = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t lo, hi;
            mul64(a->v[i], b->v[j], &lo, &hi);
            ca = acc_school(t, i + j, lo, hi, ca);
        }
        if (ca) {
            for (int k = i + 4; ca && k < 10; ++k) {
                uint64_t s2 = t[k] + ca;
                t[k] = s2;
                ca = (s2 < ca) ? 1 : 0;
            }
        }
    }
}

// 对称平方 t = a*a（10 次 mul64 而非 16 次）
static void sqr_512(uint64_t t[10], const bn256* a) {
    for (int k = 0; k < 10; ++k) t[k] = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t lo, hi;
        mul64(a->v[i], a->v[i], &lo, &hi);
        uint64_t ca = acc_school(t, 2 * i, lo, hi, 0);
        if (ca) {
            for (int k = 2 * i + 1; ca && k < 10; ++k) {
                uint64_t s2 = t[k] + ca;
                t[k] = s2;
                ca = (s2 < ca) ? 1 : 0;
            }
        }
        for (int j = i + 1; j < 4; ++j) {
            mul64(a->v[i], a->v[j], &lo, &hi);
            // 2 * a[i] * a[j]（翻倍后可能占用 129 位，最高位单独传播）
            uint64_t top = hi >> 63;
            uint64_t c0 = lo >> 63;
            lo <<= 1;
            hi = (hi << 1) | c0;
            ca = acc_school(t, i + j, lo, hi, 0);
            if (ca) {
                for (int k = i + j + 1; ca && k < 10; ++k) {
                    uint64_t s2 = t[k] + ca;
                    t[k] = s2;
                    ca = (s2 < ca) ? 1 : 0;
                }
            }
            if (top) {
                for (int k = i + j + 2; k < 10; ++k) {
                    uint64_t s2 = t[k] + 1;
                    t[k] = s2;
                    if (s2) break;
                }
            }
        }
    }
}

// Montgomery 归约：t = T (512 位) → r = T * R^{-1} mod m
static void mont_reduce(bn256* r, uint64_t t[10], const mod_ctx& M) {
    for (int i = 0; i < 4; ++i) {
        uint64_t u = t[i] * M.mp;
        uint64_t ca = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t lo, hi;
            mul64(u, M.m->v[j], &lo, &hi);
            ca = acc_school(t, i + j, lo, hi, ca);
        }
        if (ca) {
            for (int k = i + 4; ca && k < 10; ++k) {
                uint64_t s2 = t[k] + ca;
                t[k] = s2;
                ca = (s2 < ca) ? 1 : 0;
            }
        }
    }
    for (int i = 0; i < 4; ++i) r->v[i] = t[i + 4];
    // 结果 < 2m，一次条件减法即可（含 t[8] 借位回绕的情况）
    if (t[8] || bn_ge(r, M.m)) bn_sub(r, r, M.m);
}

static void mont_mul(bn256* r, const bn256* a, const bn256* b, const mod_ctx& M) {
    if (sm2_mont_asm_available()) {
        sm2_mont_mul(r->v, a->v, b->v, M.m->v, M.mp);
        return;
    }
    uint64_t t[10];
    mul_512(t, a, b);
    mont_reduce(r, t, M);
}

static void mont_sqr(bn256* r, const bn256* a, const mod_ctx& M) {
    if (sm2_mont_asm_available()) {
        sm2_mont_sqr(r->v, a->v, M.m->v, M.mp);
        return;
    }
    uint64_t t[10];
    sqr_512(t, a);
    mont_reduce(r, t, M);
}

// 模加 / 模减（输入输出均在 [0, m)）
static void mod_add(bn256* r, const bn256* a, const bn256* b, const mod_ctx& M) {
    uint64_t c = bn_add(r, a, b);
    if (c || bn_ge(r, M.m)) bn_sub(r, r, M.m);
}

static void mod_sub(bn256* r, const bn256* a, const bn256* b, const mod_ctx& M) {
    uint64_t bo = bn_sub(r, a, b);
    if (bo) bn_add(r, r, M.m);
}

// 规约到 [0, m)：m > 2^255 时单次条件减法足够（输入 < 2^256）
static void mod_reduce(bn256* r, const bn256* a, const mod_ctx& M) {
    if (bn_ge(a, M.m)) bn_sub(r, a, M.m);
    else *r = *a;
}

// Montgomery 快速幂：r = base^exp（Montgomery 表示下成立，含求逆）
static void mont_pow(bn256* r, const bn256* base, const mod_ctx& M,
                     const bn256* exp) {
    bn256 acc = M.one;
    bn256 b = *base;
    for (int i = 3; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            mont_sqr(&acc, &acc, M);
            if ((exp->v[i] >> bit) & 1) mont_mul(&acc, &acc, &b, M);
        }
    }
    *r = acc;
}

// r = a^{-1} mod m（Fermat：a^{m-2}，m 为奇素数）
static void mod_inv(bn256* r, const bn256* a, const mod_ctx& M) {
    bn256 e;
    bn_sub(&e, M.m, &ONE);
    bn_sub(&e, &e, &ONE);
    mont_pow(r, a, M, &e);
}

// 初始化 Montgomery 上下文（惰性，一次性开销极小）
static void mod_init(mod_ctx* M, const bn256* m) {
    M->m = m;

    // mp = -m[0]^{-1} mod 2^64（Newton 迭代）
    uint64_t x = 1;
    for (int i = 0; i < 63; ++i) x = x * (2 - m->v[0] * x);
    M->mp = (uint64_t)(-(int64_t)x);

    // one = R mod m = 2^256 - m（m > 2^255）
    for (int i = 0; i < 4; ++i) M->one.v[i] = ~m->v[i];
    bn_add(&M->one, &M->one, &ONE);

    // R2 = 2^512 mod m（从 1 起 512 次倍增）
    bn256 r2 = {1, 0, 0, 0};
    for (int i = 0; i < 512; ++i) {
        uint64_t c = 0;
        for (int j = 0; j < 4; ++j) c = addc(r2.v[j], r2.v[j], c, &r2.v[j]);
        if (c || bn_ge(&r2, m)) bn_sub(&r2, &r2, m);
    }
    M->R2 = r2;
}

static void sm2_init_params() {
    if (g_sm2_init) return;
    ONE  = {1, 0, 0, 0};
    ZERO = {0, 0, 0, 0};
    bn_from_be(&P,  S2_P_BYTES);
    bn_from_be(&N,  S2_N_BYTES);
    bn_from_be(&GX, S2_Gx_BYTES);
    bn_from_be(&GY, S2_Gy_BYTES);
    mod_init(&MOD_P, &P);
    mod_init(&MOD_N, &N);
    g_sm2_init = true;
}

// ─── Jacobian 坐标（坐标值均为 Montgomery 表示 mod p）──────────────────

struct jac_point { bn256 X, Y, Z; };
struct aff_point { bn256 X, Y; };

static bool jac_is_inf(const jac_point* P) { return bn_is_zero(&P->Z); }

static void jac_inf(jac_point* P) {
    P->X = ONE; P->Y = ONE; P->Z = ZERO;
}

// 倍点 R = 2P（a = -3，dbl-2001-b：5S + 2M）
static void jac_dbl(jac_point* R, const jac_point* P) {
    if (jac_is_inf(P)) { jac_inf(R); return; }
    bn256 A, B, C, D, E, t, X3, Y3, Z3;

    mont_sqr(&A, &P->X, MOD_P);
    mont_sqr(&B, &P->Y, MOD_P);
    mont_sqr(&C, &B, MOD_P);
    mod_add(&t, &P->X, &B, MOD_P);
    mont_sqr(&t, &t, MOD_P);
    mod_sub(&t, &t, &A, MOD_P);
    mod_sub(&t, &t, &C, MOD_P);
    mod_add(&D, &t, &t, MOD_P);
    // E = 3*(X^2 - Z^4)（a = -3）
    mont_sqr(&t, &P->Z, MOD_P);
    mont_sqr(&t, &t, MOD_P);
    mod_sub(&t, &A, &t, MOD_P);
    mod_add(&E, &t, &t, MOD_P);
    mod_add(&E, &E, &t, MOD_P);
    // X3 = E^2 - 2D
    mont_sqr(&X3, &E, MOD_P);
    mod_add(&t, &D, &D, MOD_P);
    mod_sub(&X3, &X3, &t, MOD_P);
    // Y3 = E*(D - X3) - 8C
    mod_sub(&t, &D, &X3, MOD_P);
    mont_mul(&Y3, &E, &t, MOD_P);
    mod_add(&t, &C, &C, MOD_P);
    mod_add(&t, &t, &t, MOD_P);
    mod_add(&t, &t, &t, MOD_P);
    mod_sub(&Y3, &Y3, &t, MOD_P);
    // Z3 = 2*Y*Z
    mont_mul(&Z3, &P->Y, &P->Z, MOD_P);
    mod_add(&Z3, &Z3, &Z3, MOD_P);

    R->X = X3; R->Y = Y3; R->Z = Z3;
}

// 混合加法 R = P + Q（P: Jacobian，Q: 仿射，add-2007-bl：7M + 5S）
static void jac_madd(jac_point* R, const jac_point* P, const aff_point* Q) {
    if (jac_is_inf(P)) { R->X = Q->X; R->Y = Q->Y; R->Z = MOD_P.one; return; }
    bn256 Z1Z1, U2, S2, H, r, I, J, V, t, X3, Y3, Z3;

    mont_sqr(&Z1Z1, &P->Z, MOD_P);
    mont_mul(&U2, &Q->X, &Z1Z1, MOD_P);
    mont_mul(&S2, &Q->Y, &P->Z, MOD_P);
    mont_mul(&S2, &S2, &Z1Z1, MOD_P);
    mod_sub(&H, &U2, &P->X, MOD_P);
    mod_sub(&t, &S2, &P->Y, MOD_P);
    if (bn_is_zero(&H)) {
        if (bn_is_zero(&t)) { jac_dbl(R, P); return; }
        jac_inf(R); return;
    }
    mod_add(&r, &t, &t, MOD_P);
    mod_add(&t, &H, &H, MOD_P);
    mont_sqr(&I, &t, MOD_P);
    mont_mul(&J, &H, &I, MOD_P);
    mont_mul(&V, &P->X, &I, MOD_P);
    // X3 = r^2 - J - 2V
    mont_sqr(&X3, &r, MOD_P);
    mod_sub(&X3, &X3, &J, MOD_P);
    mod_add(&t, &V, &V, MOD_P);
    mod_sub(&X3, &X3, &t, MOD_P);
    // Y3 = r*(V - X3) - 2*Y1*J
    mod_sub(&t, &V, &X3, MOD_P);
    mont_mul(&Y3, &r, &t, MOD_P);
    mont_mul(&t, &P->Y, &J, MOD_P);
    mod_add(&t, &t, &t, MOD_P);
    mod_sub(&Y3, &Y3, &t, MOD_P);
    // Z3 = 2*Z1*H（add-2007-bl 混合形式，Z2=1）
    mod_add(&t, &P->Z, &P->Z, MOD_P);
    mont_mul(&Z3, &t, &H, MOD_P);

    R->X = X3; R->Y = Y3; R->Z = Z3;
}

// 批量仿射化：n 个 Jacobian 点 → n 个仿射点（仅一次求逆）
static void batch_affine(jac_point* pts, aff_point* out, int n) {
    bn256 pre[8];
    bn256 acc = MOD_P.one;
    for (int i = 0; i < n; ++i) {
        pre[i] = acc;
        mont_mul(&acc, &acc, &pts[i].Z, MOD_P);
    }
    bn256 inv;
    mod_inv(&inv, &acc, MOD_P);
    for (int i = n - 1; i >= 0; --i) {
        bn256 zinv, z2, z3;
        mont_mul(&zinv, &inv, &pre[i], MOD_P);
        mont_mul(&inv, &inv, &pts[i].Z, MOD_P);
        mont_sqr(&z2, &zinv, MOD_P);
        mont_mul(&z3, &z2, &zinv, MOD_P);
        mont_mul(&out[i].X, &pts[i].X, &z2, MOD_P);
        mont_mul(&out[i].Y, &pts[i].Y, &z3, MOD_P);
    }
}

// ─── wNAF 标量乘 ────────────────────────────────────────────────────────

// 宽度-5 wNAF：数字 ∈ {-15,-13,...,-1,1,...,15}（奇数）
static int wnaf5(const bn256* k, int8_t* digits, int cap) {
    bn256 t = *k;
    int i = 0;
    while (!bn_is_zero(&t)) {
        if (i >= cap) break;
        if (t.v[0] & 1u) {
            int d = (int)(t.v[0] & 31u);
            if (d >= 16) d -= 32;
            digits[i] = (int8_t)d;
            if (d > 0) bn_sub_word(&t, (uint64_t)d);
            else bn_add_word(&t, (uint64_t)(-d));
        } else {
            digits[i] = 0;
        }
        for (int j = 0; j < 3; ++j) t.v[j] = (t.v[j] >> 1) | (t.v[j+1] << 63);
        t.v[3] >>= 1;
        ++i;
    }
    return i;
}

// 计算 1Q,3Q,...,15Q 的仿射表（14 次混合加法 + 批量求逆）
static void build_odd_table(aff_point out[8], const aff_point* Q) {
    jac_point R;
    R.X = Q->X; R.Y = Q->Y; R.Z = MOD_P.one;
    jac_point pts[8];
    for (int i = 0; i < 8; ++i) {
        pts[i] = R;
        if (i < 7) {
            jac_madd(&R, &R, Q);
            jac_madd(&R, &R, Q);
        }
    }
    batch_affine(pts, out, 8);
}

// 单标量乘：R = k*P（table = P 的 1,3,...,15 倍仿射表）
static void wnaf_scalar_mult(jac_point* R, const bn256* k, const aff_point* table) {
    int8_t digits[260];
    int len = wnaf5(k, digits, 260);
    jac_inf(R);
    for (int i = len - 1; i >= 0; --i) {
        jac_dbl(R, R);
        int d = digits[i];
        if (d > 0) {
            jac_madd(R, R, &table[d >> 1]);
        } else if (d < 0) {
            aff_point neg = table[(-d) >> 1];
            mod_sub(&neg.Y, &ZERO, &neg.Y, MOD_P);
            jac_madd(R, R, &neg);
        }
    }
}

// 双标量乘（Shamir）：R = k1*P1 + k2*P2，共享倍点
static void wnaf_dual(jac_point* R, const bn256* k1, const aff_point* t1,
                      const bn256* k2, const aff_point* t2) {
    int8_t d1[260], d2[260];
    int l1 = wnaf5(k1, d1, 260);
    int l2 = wnaf5(k2, d2, 260);
    int len = (l1 > l2) ? l1 : l2;
    jac_inf(R);
    for (int i = len - 1; i >= 0; --i) {
        jac_dbl(R, R);
        int a = (i < l1) ? d1[i] : 0;
        int b = (i < l2) ? d2[i] : 0;
        if (a > 0) {
            jac_madd(R, R, &t1[a >> 1]);
        } else if (a < 0) {
            aff_point neg = t1[(-a) >> 1];
            mod_sub(&neg.Y, &ZERO, &neg.Y, MOD_P);
            jac_madd(R, R, &neg);
        }
        if (b > 0) {
            jac_madd(R, R, &t2[b >> 1]);
        } else if (b < 0) {
            aff_point neg = t2[(-b) >> 1];
            mod_sub(&neg.Y, &ZERO, &neg.Y, MOD_P);
            jac_madd(R, R, &neg);
        }
    }
}

// G 的奇倍点表（全局惰性预计算，仿射）
static aff_point G_ODD[8];
static bool g_odd_ready = false;

static void ensure_g_table() {
    if (g_odd_ready) return;
    aff_point G;
    mont_mul(&G.X, &GX, &MOD_P.R2, MOD_P);  // to_mont
    mont_mul(&G.Y, &GY, &MOD_P.R2, MOD_P);
    build_odd_table(G_ODD, &G);
    g_odd_ready = true;
}

static void scalar_mult_G(jac_point* R, const bn256* k) {
    ensure_g_table();
    wnaf_scalar_mult(R, k, G_ODD);
}

// ─── 辅助 ───────────────────────────────────────────────────────────────

static void rand_bytes(uint8_t* buf, size_t len) {
#ifdef _WIN32
    os_rand_bytes(buf, len);
#else
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    for (size_t i = 0; i < len; i += 8) {
        uint64_t v = gen();
        for (int j = 0; j < 8 && i + j < len; ++j)
            buf[i + j] = (uint8_t)(v >> (j * 8));
    }
#endif
}

// k ∈ [1, n-1]
static void rand_scalar(bn256* k) {
    uint8_t buf[32];
    do {
        rand_bytes(buf, 32);
        bn_from_be(k, buf);
        if (!bn_lt(k, &N)) bn_sub(k, k, &N);  // k < 2^256 < 2n
    } while (bn_is_zero(k));
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
    if (za != nullptr) sm3_update(&ctx, za, SM2_ZA_SIZE);
    sm3_update(&ctx, msg, msg_len);
    sm3_final(&ctx, e);
}

// ─── SM2 API ────────────────────────────────────────────────────────────

static void pub_from_priv_impl(const uint8_t priv[SM2_KEY_SIZE],
                               uint8_t pub[SM2_PUB_SIZE]) {
    bn256 d;
    bn_from_be(&d, priv);
    jac_point Q;
    scalar_mult_G(&Q, &d);
    aff_point A;
    batch_affine(&Q, &A, 1);
    bn256 x, y;
    mont_mul(&x, &A.X, &ONE, MOD_P);  // from_mont：乘普通整数 1
    mont_mul(&y, &A.Y, &ONE, MOD_P);
    bn_to_be(&x, pub);
    bn_to_be(&y, pub + 32);
}

void sm2_keygen(uint8_t pub[SM2_PUB_SIZE], uint8_t priv[SM2_KEY_SIZE]) {
    sm2_init_params();
    bn256 d;
    rand_scalar(&d);
    bn_to_be(&d, priv);
    pub_from_priv_impl(priv, pub);
}

void sm2_pub_from_priv(const uint8_t priv[SM2_KEY_SIZE],
                       uint8_t pub[SM2_PUB_SIZE]) {
    sm2_init_params();
    pub_from_priv_impl(priv, pub);
}

// 判断普通表示的点 (x, y) 是否在 SM2 曲线上：y^2 = x^3 - 3x + b (mod p)
static bool point_on_curve(const bn256* x, const bn256* y) {
    bn256 xm, ym, bm;
    mont_mul(&xm, x, &MOD_P.R2, MOD_P);
    mont_mul(&ym, y, &MOD_P.R2, MOD_P);
    bn_from_be(&bm, S2_B_BYTES);
    mont_mul(&bm, &bm, &MOD_P.R2, MOD_P);

    bn256 lhs, rhs, t, t3;
    mont_sqr(&lhs, &ym, MOD_P);          // lhs = y^2
    mont_sqr(&t, &xm, MOD_P);            // t = x^2
    mont_mul(&rhs, &t, &xm, MOD_P);      // rhs = x^3
    t3 = xm;
    mod_add(&t3, &t3, &xm, MOD_P);       // t3 = 2x
    mod_add(&t3, &t3, &xm, MOD_P);       // t3 = 3x
    mod_sub(&rhs, &rhs, &t3, MOD_P);     // rhs = x^3 - 3x
    mod_add(&rhs, &rhs, &bm, MOD_P);     // rhs = x^3 - 3x + b
    return bn_eq(&lhs, &rhs);
}

bool sm2_ecdh(uint8_t shared[SM2_KEY_SIZE],
              const uint8_t priv[SM2_KEY_SIZE],
              const uint8_t* peer_pub, size_t peer_pub_len) {
    sm2_init_params();
    if (shared == nullptr || priv == nullptr || peer_pub == nullptr) return false;

    const uint8_t* px = nullptr;
    const uint8_t* py = nullptr;
    if (peer_pub_len == SM2_PUB_SIZE) {
        px = peer_pub;
        py = peer_pub + 32;
    } else if (peer_pub_len == SM2_PUB_SIZE + 1 && peer_pub[0] == 0x04) {
        px = peer_pub + 1;
        py = peer_pub + 33;
    } else {
        return false;
    }

    bn256 d;
    bn_from_be(&d, priv);
    if (bn_is_zero(&d) || !bn_lt(&d, &N)) return false;

    bn256 qx, qy;
    bn_from_be(&qx, px);
    bn_from_be(&qy, py);
    if (!bn_lt(&qx, &P) || !bn_lt(&qy, &P)) return false;
    if (!point_on_curve(&qx, &qy)) return false;

    aff_point Q;
    mont_mul(&Q.X, &qx, &MOD_P.R2, MOD_P);
    mont_mul(&Q.Y, &qy, &MOD_P.R2, MOD_P);

    aff_point table[8];
    build_odd_table(table, &Q);
    jac_point R;
    wnaf_scalar_mult(&R, &d, table);
    if (jac_is_inf(&R)) return false;

    aff_point A;
    batch_affine(&R, &A, 1);
    bn256 x;
    mont_mul(&x, &A.X, &ONE, MOD_P);     // from_mont
    bn_to_be(&x, shared);
    return true;
}

void sm2_sign(const uint8_t priv[SM2_KEY_SIZE],
              const uint8_t* msg, size_t msg_len,
              uint8_t sig[SM2_SIG_SIZE],
              const uint8_t za[SM2_ZA_SIZE]) {
    sm2_init_params();

    bn256 d;
    bn_from_be(&d, priv);

    // e = SM3(ZA || M) mod n
    uint8_t e_bytes[32];
    sm2_hash(e_bytes, msg, msg_len, za);
    bn256 e;
    bn_from_be(&e, e_bytes);
    mod_reduce(&e, &e, MOD_N);

    bn256 e_m, d_m;
    mont_mul(&e_m, &e, &MOD_N.R2, MOD_N);
    mont_mul(&d_m, &d, &MOD_N.R2, MOD_N);

    bn256 r_m, s_m, k, k_m, one_plus_d, inv_1d, rd, kr, t;
    do {
        rand_scalar(&k);

        // (x1, y1) = k*G
        jac_point R;
        scalar_mult_G(&R, &k);
        aff_point A;
        batch_affine(&R, &A, 1);
        bn256 x1;
        mont_mul(&x1, &A.X, &ONE, MOD_P);
        mod_reduce(&x1, &x1, MOD_N);
        bn256 x1_m;
        mont_mul(&x1_m, &x1, &MOD_N.R2, MOD_N);

        // r = (e + x1) mod n
        mod_add(&r_m, &e_m, &x1_m, MOD_N);
        if (bn_is_zero(&r_m)) continue;

        // (r + k) mod n != 0
        mont_mul(&k_m, &k, &MOD_N.R2, MOD_N);
        mod_add(&t, &r_m, &k_m, MOD_N);
        if (bn_is_zero(&t)) continue;

        // s = (1+d)^{-1} * (k - r*d) mod n
        mod_add(&one_plus_d, &MOD_N.one, &d_m, MOD_N);
        mod_inv(&inv_1d, &one_plus_d, MOD_N);
        mont_mul(&rd, &r_m, &d_m, MOD_N);
        mod_sub(&kr, &k_m, &rd, MOD_N);
        mont_mul(&s_m, &inv_1d, &kr, MOD_N);

        bn256 s_plain;
        mont_mul(&s_plain, &s_m, &ONE, MOD_N);
        if (bn_is_zero(&s_plain)) continue;

        bn256 r_plain;
        mont_mul(&r_plain, &r_m, &ONE, MOD_N);
        bn_to_be(&r_plain, sig);
        bn_to_be(&s_plain, sig + 32);
        return;
    } while (true);
}

bool sm2_verify(const uint8_t pub[SM2_PUB_SIZE],
                const uint8_t* msg, size_t msg_len,
                const uint8_t sig[SM2_SIG_SIZE],
                const uint8_t za[SM2_ZA_SIZE]) {
    sm2_init_params();

    bn256 r, s;
    bn_from_be(&r, sig);
    bn_from_be(&s, sig + 32);
    if (bn_is_zero(&r) || bn_is_zero(&s)) return false;
    if (!bn_lt(&r, &N) || !bn_lt(&s, &N)) return false;

    // e = SM3(ZA || M) mod n
    uint8_t e_bytes[32];
    sm2_hash(e_bytes, msg, msg_len, za);
    bn256 e;
    bn_from_be(&e, e_bytes);
    mod_reduce(&e, &e, MOD_N);

    // t = (r + s) mod n
    bn256 t;
    mod_add(&t, &r, &s, MOD_N);
    if (bn_is_zero(&t)) return false;

    // 公钥 Q（坐标规约到 mod p 并转 Montgomery）
    bn256 qx, qy;
    bn_from_be(&qx, pub);
    bn_from_be(&qy, pub + 32);
    mod_reduce(&qx, &qx, MOD_P);
    mod_reduce(&qy, &qy, MOD_P);
    aff_point Q;
    mont_mul(&Q.X, &qx, &MOD_P.R2, MOD_P);
    mont_mul(&Q.Y, &qy, &MOD_P.R2, MOD_P);

    // (x1, y1) = s*G + t*Q（Shamir 双标量）
    aff_point qt[8];
    build_odd_table(qt, &Q);
    ensure_g_table();
    jac_point R;
    wnaf_dual(&R, &s, G_ODD, &t, qt);
    if (jac_is_inf(&R)) return false;

    aff_point A;
    batch_affine(&R, &A, 1);
    bn256 x1;
    mont_mul(&x1, &A.X, &ONE, MOD_P);
    mod_reduce(&x1, &x1, MOD_N);

    // R' = (e + x1) mod n
    bn256 v;
    mod_add(&v, &e, &x1, MOD_N);
    return bn_eq(&v, &r);
}

void sm2_compute_za(const uint8_t* id, size_t id_len,
                    const uint8_t pub_x[SM2_KEY_SIZE],
                    const uint8_t pub_y[SM2_KEY_SIZE],
                    uint8_t za[SM2_ZA_SIZE]) {
    sm2_init_params();

    uint16_t entl = (uint16_t)(id_len * 8);
    uint8_t entl_buf[2] = { (uint8_t)(entl >> 8), (uint8_t)(entl) };

    // ZA = SM3(ENTL || ID || a || b || Gx || Gy || xA || yA)
    sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, entl_buf, 2);
    sm3_update(&ctx, id, id_len);
    sm3_update(&ctx, S2_A_BYTES, 32);
    sm3_update(&ctx, S2_B_BYTES, 32);
    sm3_update(&ctx, S2_Gx_BYTES, 32);
    sm3_update(&ctx, S2_Gy_BYTES, 32);
    sm3_update(&ctx, pub_x, SM2_KEY_SIZE);
    sm3_update(&ctx, pub_y, SM2_KEY_SIZE);
    sm3_final(&ctx, za);
}

} // namespace jpssl
