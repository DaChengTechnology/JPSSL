// ECDSA P-256 (secp256r1 / prime256v1) 完整实现
// 对外字节序：公钥/签名/私钥均为大端（标准格式）
// 内部 uint256 使用 little-endian limbs[0..3]（limbs[0] 为最低位）
//
// 性能：域运算（P-256 4×64 位 / P-384 6×64 位）全程在 Montgomery 域
// （R = 2^(64N)）中运行，CIOS 乘法/对称平方/快速幂与 sm2.cpp 同源；
// 仅在标量乘入口（to_mont）与仿射化输出（from_mont）做进出域转换。
// GCC/Clang 的 __uint128_t 在 AArch64 上编译为 umulh/adc 序列。
#include "ecdsa.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "rand_os.hpp"
#include <cstring>
#include <random>

#ifdef _MSC_VER
#include <intrin.h>
#pragma intrinsic(_umul128, _addcarry_u64, _subborrow_u64)
#endif

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

// 全局域参数（init_params 填充）
static uint256 G_P, G_N, G_Gx, G_Gy;
static bool g_init = false;

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

// ════════════════════════════════════════════════════════════════════
//  Montgomery 域（R = 2^(64N)）CIOS 乘法 / 对称平方 / 快速幂
//  与 sm2.cpp 已验证实现同源；GCC/Clang 的 __uint128_t 在 AArch64 上
//  编译为 umulh/adc 序列，MSVC 经 jp_uint128（_umul128/_addcarry_u64）
// ════════════════════════════════════════════════════════════════════

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

// 把 (lo, hi) 累加到 t[pos..]，返回进位链高字（与 sm2.cpp acc_school 一致）
template <int T>
static inline uint64_t mont_acc(uint64_t* t, int pos, uint64_t lo, uint64_t hi,
                                uint64_t cin) {
#ifdef _MSC_VER
    unsigned char cf1 = _addcarry_u64(0, lo, t[pos], &lo);
    unsigned char cf2 = _addcarry_u64(0, lo, cin, &lo);
    t[pos] = lo;
    uint64_t old = hi;
    hi = old + (uint64_t)cf1 + (uint64_t)cf2;
    if (hi < old) {  // 高字回绕：向 t[pos+2..] 传播 +1
        for (int k = pos + 2; k < T; ++k) {
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
        for (int k = pos + 2; k < T; ++k) {
            uint64_t s3 = t[k] + 1;
            t[k] = s3;
            if (s3) break;
        }
    }
    return (uint64_t)s2;
#endif
}

// t = a*b（学校乘法，t 容量 2N+2）
template <int N>
static void mont_mul_school(uint64_t* t, const uint64_t* a, const uint64_t* b) {
    const int T = 2 * N + 2;
    for (int k = 0; k < T; ++k) t[k] = 0;
    for (int i = 0; i < N; ++i) {
        uint64_t ca = 0;
        for (int j = 0; j < N; ++j) {
            uint64_t lo, hi;
            mul64(a[i], b[j], &lo, &hi);
            ca = mont_acc<T>(t, i + j, lo, hi, ca);
        }
        if (ca) {
            for (int k = i + N; ca && k < T; ++k) {
                uint64_t s2 = t[k] + ca;
                t[k] = s2;
                ca = (s2 < ca) ? 1 : 0;
            }
        }
    }
}

// t = a*a（对称平方，N(N+1)/2 次 mul64）
template <int N>
static void mont_sqr_school(uint64_t* t, const uint64_t* a) {
    const int T = 2 * N + 2;
    for (int k = 0; k < T; ++k) t[k] = 0;
    for (int i = 0; i < N; ++i) {
        uint64_t lo, hi;
        mul64(a[i], a[i], &lo, &hi);
        uint64_t ca = mont_acc<T>(t, 2 * i, lo, hi, 0);
        if (ca) {
            for (int k = 2 * i + 1; ca && k < T; ++k) {
                uint64_t s2 = t[k] + ca;
                t[k] = s2;
                ca = (s2 < ca) ? 1 : 0;
            }
        }
        for (int j = i + 1; j < N; ++j) {
            mul64(a[i], a[j], &lo, &hi);
            // 2 * a[i] * a[j]（翻倍后最高位单独传播）
            uint64_t top = hi >> 63;
            uint64_t c0 = lo >> 63;
            lo <<= 1;
            hi = (hi << 1) | c0;
            ca = mont_acc<T>(t, i + j, lo, hi, 0);
            if (ca) {
                for (int k = i + j + 1; ca && k < T; ++k) {
                    uint64_t s2 = t[k] + ca;
                    t[k] = s2;
                    ca = (s2 < ca) ? 1 : 0;
                }
            }
            if (top) {
                for (int k = i + j + 2; k < T; ++k) {
                    uint64_t s2 = t[k] + 1;
                    t[k] = s2;
                    if (s2) break;
                }
            }
        }
    }
}

// Montgomery 归约：r = T * R^{-1} mod m（m 为 N 个 limb 的奇模数）
template <int N>
static void mont_reduce(uint64_t* r, uint64_t* t, const uint64_t* m, uint64_t mp) {
    const int T = 2 * N + 2;
    for (int i = 0; i < N; ++i) {
        uint64_t u = t[i] * mp;
        uint64_t ca = 0;
        for (int j = 0; j < N; ++j) {
            uint64_t lo, hi;
            mul64(u, m[j], &lo, &hi);
            ca = mont_acc<T>(t, i + j, lo, hi, ca);
        }
        if (ca) {
            for (int k = i + N; ca && k < T; ++k) {
                uint64_t s2 = t[k] + ca;
                t[k] = s2;
                ca = (s2 < ca) ? 1 : 0;
            }
        }
    }
    for (int i = 0; i < N; ++i) r[i] = t[i + N];
    // 结果 < 2m，一次条件减法即可（t[2N] 记录溢出）
    bool ge = t[2 * N] != 0;
    if (!ge) {
        for (int i = N - 1; i >= 0; --i) {
            if (r[i] > m[i]) { ge = true; break; }
            if (r[i] < m[i]) break;
            if (i == 0) ge = true;
        }
    }
    if (ge) {
        uint64_t borrow = 0;
        for (int i = 0; i < N; ++i) {
            __uint128_t s = (__uint128_t)r[i] - m[i] - borrow;
            r[i] = (uint64_t)s;
            borrow = (uint64_t)(s >> 64) & 1u;
        }
    }
}

template <int N>
static void mont_mul_impl(uint64_t* r, const uint64_t* a, const uint64_t* b,
                          const uint64_t* m, uint64_t mp) {
    uint64_t t[2 * N + 2];
    mont_mul_school<N>(t, a, b);
    mont_reduce<N>(r, t, m, mp);
}

template <int N>
static void mont_sqr_impl(uint64_t* r, const uint64_t* a,
                          const uint64_t* m, uint64_t mp) {
    uint64_t t[2 * N + 2];
    mont_sqr_school<N>(t, a);
    mont_reduce<N>(r, t, m, mp);
}

// Montgomery 快速幂（Montgomery 域内成立）：acc 从 one（= R mod m）出发，
// 每步 sqr/mul 都消掉一个 R^{-1}，最终 r = base^exp * R mod m
template <int N>
static void mont_pow_impl(uint64_t* r, const uint64_t* base, const uint64_t* one,
                          const uint64_t* m, uint64_t mp, const uint64_t* exp) {
    uint64_t acc[N], b[N];
    for (int i = 0; i < N; ++i) acc[i] = one[i];
    for (int i = 0; i < N; ++i) b[i] = base[i];
    for (int i = N - 1; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            mont_sqr_impl<N>(acc, acc, m, mp);
            if ((exp[i] >> bit) & 1)
                mont_mul_impl<N>(acc, acc, b, m, mp);
        }
    }
    for (int i = 0; i < N; ++i) r[i] = acc[i];
}

// r = a mod m (a 是 256 位, a < 2m)
static void mod_reduce_256(uint256* r, const uint256* a, const uint256* m) {
    if (u256_lt(a, m)) { *r = *a; return; }
    u256_sub(r, a, m);
}

// ── P-256 Montgomery 上下文（m = G_P 或 G_N）──
struct mont_ctx256 {
    const uint256* m;
    uint256  R2;    // R^2 mod m
    uint256  one;   // R mod m（Montgomery 表示下的 1）
    uint64_t mp;    // -m[0]^{-1} mod 2^64
};

static mont_ctx256 M256_P, M256_N;
static const uint256 ONE256 = {1, 0, 0, 0};

static void mont256_init(mont_ctx256* M, const uint256* m) {
    M->m = m;
    // mp = -m[0]^{-1} mod 2^64（Newton 迭代）
    uint64_t x = 1;
    for (int i = 0; i < 63; ++i) x = x * (2 - m->v[0] * x);
    M->mp = (uint64_t)(-(int64_t)x);
    // one = R mod m = 2^256 - m（m > 2^255）
    for (int i = 0; i < 4; ++i) M->one.v[i] = ~m->v[i];
    u256_add(&M->one, &M->one, &ONE256);
    // R2 = 2^512 mod m（从 1 起 512 次倍增）
    uint256 r2 = {1, 0, 0, 0};
    for (int i = 0; i < 512; ++i) {
        uint64_t c = 0;
        for (int j = 0; j < 4; ++j) {
            __uint128_t s = (__uint128_t)r2.v[j] + r2.v[j] + c;
            r2.v[j] = (uint64_t)s;
            c = (uint64_t)(s >> 64);
        }
        if (c || !u256_lt(&r2, m)) u256_sub(&r2, &r2, m);
    }
    M->R2 = r2;
}

// 进入 Montgomery 域：a' = a*R mod m（先规约到 [0, m)，兼容任意 256 位输入）
static void to_mont256(uint256* r, const uint256* a, const mont_ctx256& M) {
    uint256 t;
    mod_reduce_256(&t, a, M.m);
    mont_mul_impl<4>(r->v, t.v, M.R2.v, M.m->v, M.mp);
}

// 离开 Montgomery 域：a = a' * R^{-1} mod m
static void from_mont256(uint256* r, const uint256* a, const mont_ctx256& M) {
    mont_mul_impl<4>(r->v, a->v, ONE256.v, M.m->v, M.mp);
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

// r = (a * b) mod m（输入输出均为 Montgomery 表示）
static void mm_mul(uint256* r, const uint256* a, const uint256* b, const uint256* m) {
    const mont_ctx256& M = (m == &G_P) ? M256_P : M256_N;
    mont_mul_impl<4>(r->v, a->v, b->v, M.m->v, M.mp);
}

// r = (a^2) mod m（输入输出均为 Montgomery 表示）
static void mm_sqr(uint256* r, const uint256* a, const uint256* m) {
    const mont_ctx256& M = (m == &G_P) ? M256_P : M256_N;
    mont_sqr_impl<4>(r->v, a->v, M.m->v, M.mp);
}

// r = a^{-1} mod m（Fermat: a^{m-2}，Montgomery 域内求逆）
static void mm_inv(uint256* r, const uint256* a, const uint256* m) {
    const mont_ctx256& M = (m == &G_P) ? M256_P : M256_N;
    uint256 two = {2, 0, 0, 0};
    uint256 exp;
    u256_sub(&exp, m, &two);
    mont_pow_impl<4>(r->v, a->v, M.one.v, M.m->v, M.mp, exp.v);
}

// ════════════════════════════════════════════════════════════════════
//  Jacobian 坐标点运算
//  (X,Y,Z) 表示仿射 (X/Z^2, Y/Z^3); 无穷远点 Z=0
// ════════════════════════════════════════════════════════════════════

struct jac_point { uint256 X, Y, Z; };

static void init_params() {
    if (g_init) return;
    u256_from_be(&G_P,  P_BYTES);
    u256_from_be(&G_N,  N_BYTES);
    u256_from_be(&G_Gx, Gx_BYTES);
    u256_from_be(&G_Gy, Gy_BYTES);
    mont256_init(&M256_P, &G_P);
    mont256_init(&M256_N, &G_N);
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
    // 进入 Montgomery 域（仅此一次；点运算全程留在域内）
    jac_point Pd;
    to_mont256(&Pd.X, &P->X, M256_P);
    to_mont256(&Pd.Y, &P->Y, M256_P);
    to_mont256(&Pd.Z, &P->Z, M256_P);
    jac_inf(R);
    for (int i = 3; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            jac_dbl(R, R);
            if ((k->v[i] >> bit) & 1)
                jac_add(R, R, &Pd);
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
    mm_inv(&Zinv, &P->Z, &G_P);          // 域内求逆
    mm_sqr(&Zinv2, &Zinv, &G_P);
    mm_mul(&Zinv3, &Zinv2, &Zinv, &G_P);
    if (x) {
        mm_mul(x, &P->X, &Zinv2, &G_P);
        from_mont256(x, x, M256_P);      // 离开域
    }
    if (y) {
        mm_mul(y, &P->Y, &Zinv3, &G_P);
        from_mont256(y, y, M256_P);
    }
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
#ifdef _WIN32
    // Windows: MSVC 的 std::random_device 是确定性的，必须用系统 CSPRNG
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
    uint256 d_m, e_m;
    to_mont256(&d_m, &d, M256_N);
    to_mont256(&e_m, &e, M256_N);
    do {
        rand_scalar(&k);
        scalar_mult_G(&R, &k);
        jac_to_affine(&Rx, nullptr, &R);
        mod_reduce_256(&r, &Rx, &G_N);
        if (u256_is_zero(&r)) continue;
        uint256 k_m, r_m;
        to_mont256(&k_m, &k, M256_N);
        to_mont256(&r_m, &r, M256_N);
        mm_inv(&k_inv, &k_m, &G_N);
        mm_mul(&rd, &r_m, &d_m, &G_N);
        mm_add(&ed, &e_m, &rd, &G_N);
        mm_mul(&s, &k_inv, &ed, &G_N);
        from_mont256(&s, &s, M256_N);
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
    uint256 e_m, s_m, r_m;
    to_mont256(&e_m, &e, M256_N);
    to_mont256(&s_m, &s, M256_N);
    to_mont256(&r_m, &r, M256_N);
    mm_inv(&w, &s_m, &G_N);
    mm_mul(&u1, &e_m, &w, &G_N);
    mm_mul(&u2, &r_m, &w, &G_N);
    from_mont256(&u1, &u1, M256_N);
    from_mont256(&u2, &u2, M256_N);

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

// 全局域参数（init384_params 填充）
static uint384 G384_P, G384_N, G384_Gx, G384_Gy;
static bool g384_init = false;

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
// ── 模运算 (384 位, 参数化模数 m, Montgomery 域) ──

static void mod384_reduce_384(uint384* r, const uint384* a, const uint384* m) {
    if (u384_lt(a, m)) { *r = *a; return; }
    u384_sub(r, a, m);
}

// ── P-384 Montgomery 上下文（m = G384_P 或 G384_N）──
struct mont_ctx384 {
    const uint384* m;
    uint384  R2;    // R^2 mod m
    uint384  one;   // R mod m（Montgomery 表示下的 1）
    uint64_t mp;    // -m[0]^{-1} mod 2^64
};

static mont_ctx384 M384_P, M384_N;
static const uint384 ONE384 = {1, 0, 0, 0, 0, 0};

static void mont384_init(mont_ctx384* M, const uint384* m) {
    M->m = m;
    uint64_t x = 1;
    for (int i = 0; i < 63; ++i) x = x * (2 - m->v[0] * x);
    M->mp = (uint64_t)(-(int64_t)x);
    // one = R mod m = 2^384 - m（m > 2^383）
    for (int i = 0; i < 6; ++i) M->one.v[i] = ~m->v[i];
    u384_add(&M->one, &M->one, &ONE384);
    // R2 = 2^768 mod m（从 1 起 768 次倍增）
    uint384 r2 = {1, 0, 0, 0, 0, 0};
    for (int i = 0; i < 768; ++i) {
        uint64_t c = 0;
        for (int j = 0; j < 6; ++j) {
            __uint128_t s = (__uint128_t)r2.v[j] + r2.v[j] + c;
            r2.v[j] = (uint64_t)s;
            c = (uint64_t)(s >> 64);
        }
        if (c || !u384_lt(&r2, m)) u384_sub(&r2, &r2, m);
    }
    M->R2 = r2;
}

static void to_mont384(uint384* r, const uint384* a, const mont_ctx384& M) {
    uint384 t;
    mod384_reduce_384(&t, a, M.m);
    mont_mul_impl<6>(r->v, t.v, M.R2.v, M.m->v, M.mp);
}

static void from_mont384(uint384* r, const uint384* a, const mont_ctx384& M) {
    mont_mul_impl<6>(r->v, a->v, ONE384.v, M.m->v, M.mp);
}
static void mm384_add(uint384* r, const uint384* a, const uint384* b, const uint384* m) {
    uint64_t carry = u384_add(r, a, b);
    if (carry || !u384_lt(r, m)) u384_sub(r, r, m);
}
static void mm384_sub(uint384* r, const uint384* a, const uint384* b, const uint384* m) {
    uint64_t borrow = u384_sub(r, a, b);
    if (borrow) u384_add(r, r, m);
}
// r = (a * b) mod m（输入输出均为 Montgomery 表示）
static void mm384_mul(uint384* r, const uint384* a, const uint384* b, const uint384* m) {
    const mont_ctx384& M = (m == &G384_P) ? M384_P : M384_N;
    mont_mul_impl<6>(r->v, a->v, b->v, M.m->v, M.mp);
}
// r = (a^2) mod m（输入输出均为 Montgomery 表示）
static void mm384_sqr(uint384* r, const uint384* a, const uint384* m) {
    const mont_ctx384& M = (m == &G384_P) ? M384_P : M384_N;
    mont_sqr_impl<6>(r->v, a->v, M.m->v, M.mp);
}
// r = a^{-1} mod m（Fermat: a^{m-2}，Montgomery 域内求逆）
static void mm384_inv(uint384* r, const uint384* a, const uint384* m) {
    const mont_ctx384& M = (m == &G384_P) ? M384_P : M384_N;
    uint384 two = {2, 0, 0, 0, 0, 0};
    uint384 exp;
    u384_sub(&exp, m, &two);
    mont_pow_impl<6>(r->v, a->v, M.one.v, M.m->v, M.mp, exp.v);
}

// ── P-384 Jacobian 点运算 ──

struct jac384_point { uint384 X, Y, Z; };

static void init384_params() {
    if (g384_init) return;
    u384_from_be(&G384_P,  P384_P_BYTES);
    u384_from_be(&G384_N,  P384_N_BYTES);
    u384_from_be(&G384_Gx, P384_Gx_BYTES);
    u384_from_be(&G384_Gy, P384_Gy_BYTES);
    mont384_init(&M384_P, &G384_P);
    mont384_init(&M384_N, &G384_N);
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
    // 进入 Montgomery 域（仅此一次；点运算全程留在域内）
    jac384_point Pd;
    to_mont384(&Pd.X, &P->X, M384_P);
    to_mont384(&Pd.Y, &P->Y, M384_P);
    to_mont384(&Pd.Z, &P->Z, M384_P);
    jac384_inf(R);
    for (int i = 5; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            jac384_dbl(R, R);
            if ((k->v[i] >> bit) & 1)
                jac384_add(R, R, &Pd);
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
    mm384_inv(&Zinv, &P->Z, &G384_P);    // 域内求逆
    mm384_sqr(&Zinv2, &Zinv, &G384_P);
    mm384_mul(&Zinv3, &Zinv2, &Zinv, &G384_P);
    if (x) {
        mm384_mul(x, &P->X, &Zinv2, &G384_P);
        from_mont384(x, x, M384_P);      // 离开域
    }
    if (y) {
        mm384_mul(y, &P->Y, &Zinv3, &G384_P);
        from_mont384(y, y, M384_P);
    }
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
    uint384 d_m, e_m;
    to_mont384(&d_m, &d, M384_N);
    to_mont384(&e_m, &e, M384_N);
    do {
        rand384_scalar(&k);
        scalar384_mult_G(&R, &k);
        jac384_to_affine(&Rx, nullptr, &R);
        mod384_reduce_384(&r, &Rx, &G384_N);
        if (u384_is_zero(&r)) continue;
        uint384 k_m, r_m;
        to_mont384(&k_m, &k, M384_N);
        to_mont384(&r_m, &r, M384_N);
        mm384_inv(&k_inv, &k_m, &G384_N);
        mm384_mul(&rd, &r_m, &d_m, &G384_N);
        mm384_add(&ed, &e_m, &rd, &G384_N);
        mm384_mul(&s, &k_inv, &ed, &G384_N);
        from_mont384(&s, &s, M384_N);
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
    uint384 e_m, s_m, r_m;
    to_mont384(&e_m, &e, M384_N);
    to_mont384(&s_m, &s, M384_N);
    to_mont384(&r_m, &r, M384_N);
    mm384_inv(&w, &s_m, &G384_N);
    mm384_mul(&u1, &e_m, &w, &G384_N);
    mm384_mul(&u2, &r_m, &w, &G384_N);
    from_mont384(&u1, &u1, M384_N);
    from_mont384(&u2, &u2, M384_N);

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
