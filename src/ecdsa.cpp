// ecdsa.cpp — ECDSA P-256 / P-384 / P-521
//
// Phase 1 标量算法升级（相对旧实现）：
//   - 域/群运算改为 Montgomery 表示（R = 2^(64*N)），CIOS 乘法 / 对称平方；
//   - 验签：宽度-5 wNAF + Shamir 双标量（u1*G + u2*Q 共享同一条倍点链）；
//   - 签名/密钥生成：固定 4-bit 窗口 + 常数时间表选择（窗口数固定、无秘密索引）；
//   - G 的 1..15 倍仿射表全局懒预计算（Montgomery 表示，mod p）；
//   - 批量仿射化（一次求逆换 N 个逆）。
//
// 说明：签名路径在 Jacobian 混合加法的 H==0 例外分支上仍有一个概率可忽略
//      （~2^-N）的数据相关分支（与 src/sm2.cpp 一致）；主循环（窗口数、倍点
//      次数、表选择）均为常数时间。
#include "ecdsa.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "rand_os.hpp"
#include "cpu_features.hpp"
#include <cstring>
#include <random>
#include <vector>

#ifdef _MSC_VER
#include <intrin.h>
#pragma intrinsic(_umul128, _addcarry_u64, _subborrow_u64)
#endif

namespace jpssl {

#if defined(_MSC_VER) && defined(_M_X64)
// Windows x64 MASM 快速路径（src/ecdsa_p256_adx.asm，需 BMI2+ADX）
extern "C" void jpssl_p256_mul_adx(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern "C" void jpssl_p256_ord_mul_adx(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern "C" void jpssl_p256_dbl(uint64_t r[12], const uint64_t p[12]);
extern "C" void jpssl_p256_madd(uint64_t r[12], const uint64_t p[12], const uint64_t q[12]);
extern "C" void jpssl_p256_inv_adx(uint64_t r[4], const uint64_t a[4]);
#endif

namespace {

// P-256 ADX 汇编快速路径是否可用（ensure256 时初始化）
static bool g_p256_adx_ok = false;

#if defined(__aarch64__) && !defined(__APPLE__)
// NIST P-256 ARMv8 汇编（移植自 OpenSSL ecp_nistz256-armv8.pl，Apache-2.0）：
//   ecp_nistz256_mul_mont        r = a*b*R^-1 mod p
//   ecp_nistz256_sqr_mont        r = a*a*R^-1 mod p
//   ecp_nistz256_ord_mul_mont    r = a*b*R^-1 mod n
//   ecp_nistz256_point_double    Jacobian 倍点
//   ecp_nistz256_point_add_affine Jacobian + 仿射混合加法
//   ecp_nistz256_gather_w7 / neg / 生成元预计算表：固定点标量乘（7 位窗口）
extern "C" void ecp_nistz256_mul_mont(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern "C" void ecp_nistz256_sqr_mont(uint64_t r[4], const uint64_t a[4]);
extern "C" void ecp_nistz256_ord_mul_mont(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern "C" void ecp_nistz256_point_double(uint64_t r[12], const uint64_t p[12]);
extern "C" void ecp_nistz256_point_add_affine(uint64_t r[12], const uint64_t p[12],
                                               const uint64_t q[8]);
extern "C" void ecp_nistz256_gather_w7(uint64_t r[8], const uint64_t* table, int index);
extern "C" void ecp_nistz256_neg(uint64_t r[4], const uint64_t a[4]);
// 生成元预计算表：37 行 × 64 仿射点（7 位窗口 Booth 编码），
// 汇编 gather_w7 按字节平面组织：每点 64 字节、行大小 64*64 = 4096 字节
extern "C" const unsigned char ecp_nistz256_precomputed[37 * 4096];
static bool g_p256_arm_ok = false;
// 表构建期间禁用 pt_madd 汇编（构建用 pt_madd(R,R,G) 迭代，首轮 H==0，
// OpenSSL point_add_affine 不处理 H==0，需走 C++ 路径）
static bool g_pt_madd_asm = true;
#endif

// ── 通用 N×64 位无符号整数（little-endian limbs, v[0] = 最低位）──

template <int N>
struct bn { uint64_t v[N]; };

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

// 把 (lo, hi) 累加到 t[pos], t[pos+1]（schoolbook 乘积扫描），返回新的高字进位。
template <int T>
static inline uint64_t acc_school(uint64_t* t, int pos, uint64_t lo, uint64_t hi,
                                  uint64_t cin) {
#ifdef _MSC_VER
    unsigned char cf1 = _addcarry_u64(0, lo, t[pos], &lo);
    unsigned char cf2 = _addcarry_u64(0, lo, cin, &lo);
    t[pos] = lo;
    uint64_t old = hi;
    hi = old + (uint64_t)cf1 + (uint64_t)cf2;
    if (hi < old) {
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

template <int N>
static bool bn_is_zero(const bn<N>* a) {
    for (int i = 0; i < N; ++i)
        if (a->v[i]) return false;
    return true;
}

template <int N>
static bool bn_eq(const bn<N>* a, const bn<N>* b) {
    for (int i = 0; i < N; ++i)
        if (a->v[i] != b->v[i]) return false;
    return true;
}

template <int N>
static bool bn_lt(const bn<N>* a, const bn<N>* b) {
    for (int i = N - 1; i >= 0; --i) {
        if (a->v[i] < b->v[i]) return true;
        if (a->v[i] > b->v[i]) return false;
    }
    return false;
}

template <int N>
static bool bn_ge(const bn<N>* a, const bn<N>* b) { return !bn_lt(a, b); }

template <int N>
static uint64_t bn_add(bn<N>* r, const bn<N>* a, const bn<N>* b) {
    uint64_t c = 0;
    for (int i = 0; i < N; ++i) c = addc(a->v[i], b->v[i], c, &r->v[i]);
    return c;
}

template <int N>
static uint64_t bn_sub(bn<N>* r, const bn<N>* a, const bn<N>* b) {
    uint64_t bo = 0;
    for (int i = 0; i < N; ++i) bo = subb(a->v[i], b->v[i], bo, &r->v[i]);
    return bo;
}

template <int N>
static void bn_add_word(bn<N>* r, uint64_t w) {
    uint64_t c = addc(r->v[0], w, 0, &r->v[0]);
    for (int i = 1; c && i < N; ++i) c = addc(r->v[i], 0, c, &r->v[i]);
}

template <int N>
static void bn_sub_word(bn<N>* r, uint64_t w) {
    uint64_t bo = subb(r->v[0], w, 0, &r->v[0]);
    for (int i = 1; bo && i < N; ++i) bo = subb(r->v[i], 0, bo, &r->v[i]);
}

// r >>= 4
template <int N>
static void bn_shr4(bn<N>* r) {
    uint64_t carry = 0;
    for (int i = N - 1; i >= 0; --i) {
        uint64_t nxt = r->v[i] << 60;
        r->v[i] = (r->v[i] >> 4) | carry;
        carry = nxt;
    }
}

// 大端字节 → limbs。BYTES 允许不足 8*N（如 P-521 的 66 字节）。
template <int N, int BYTES>
static void bn_from_be(bn<N>* r, const uint8_t* b) {
    for (int i = 0; i < N; ++i) {
        uint64_t w = 0;
        if (i < N - 1) {
            int start = BYTES - 8 * (i + 1);
            for (int j = 0; j < 8; ++j) w = (w << 8) | b[start + j];
        } else {
            int topbytes = BYTES - 8 * (N - 1);
            for (int j = 0; j < topbytes; ++j) w = (w << 8) | b[j];
        }
        r->v[i] = w;
    }
}

template <int N, int BYTES>
static void bn_to_be(const bn<N>* a, uint8_t* b) {
    for (int i = 0; i < N; ++i) {
        uint64_t w = a->v[i];
        if (i < N - 1) {
            int start = BYTES - 8 * (i + 1);
            for (int j = 7; j >= 0; --j) { b[start + j] = (uint8_t)w; w >>= 8; }
        } else {
            int topbytes = BYTES - 8 * (N - 1);
            for (int j = topbytes - 1; j >= 0; --j) { b[j] = (uint8_t)w; w >>= 8; }
        }
    }
}

// ── Montgomery 域（R = 2^(64*N)）──

template <int N>
struct mod_ctx {
    const bn<N>* m;   // 模数（奇素数）
    bn<N>  R2;        // R^2 mod m
    bn<N>  one;       // R mod m（Montgomery 表示下的 1）
    uint64_t mp;      // -m[0]^{-1} mod 2^64
    int special;      // 0=通用 CIOS；1=P-256 域特殊归约；2=P-256 群阶特殊归约
};

template <int N>
static void mul_full(uint64_t* t, const bn<N>* a, const bn<N>* b) {
    const int T = 2 * N + 2;
    for (int k = 0; k < T; ++k) t[k] = 0;
    for (int i = 0; i < N; ++i) {
        uint64_t ca = 0;
        for (int j = 0; j < N; ++j) {
            uint64_t lo, hi;
            mul64(a->v[i], b->v[j], &lo, &hi);
            ca = acc_school<T>(t, i + j, lo, hi, ca);
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

// Montgomery 归约：t（2N 位）→ r = t * R^{-1} mod m
template <int N>
static void mont_reduce(bn<N>* r, uint64_t* t, const mod_ctx<N>& M) {
    const int T = 2 * N + 2;
    for (int i = 0; i < N; ++i) {
        uint64_t u = t[i] * M.mp;
        uint64_t ca = 0;
        for (int j = 0; j < N; ++j) {
            uint64_t lo, hi;
            mul64(u, M.m->v[j], &lo, &hi);
            ca = acc_school<T>(t, i + j, lo, hi, ca);
        }
        if (ca) {
            for (int k = i + N; ca && k < T; ++k) {
                uint64_t s2 = t[k] + ca;
                t[k] = s2;
                ca = (s2 < ca) ? 1 : 0;
            }
        }
    }
    for (int i = 0; i < N; ++i) r->v[i] = t[i + N];
    if (t[2 * N] || bn_ge(r, M.m)) bn_sub(r, r, M.m);
}

// P-256 特殊形式 Montgomery 归约（nistz256，参考 Go p256_asm_amd64.s）：
// p = 2^256 - 2^224 + 2^192 + 2^96 - 1，常数 0xffffffff00000001 = 2^64 - 2^32 + 1。
// 对 512 位乘积 t[0..7] 做 4 轮低字折叠 + 一次条件减 p，结果 < p。
static void p256_reduce_special(uint64_t t[8]) {
    uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t a = t[i];
        uint64_t lo, hi;
        mul64(a, 0xffffffff00000001ull, &lo, &hi);
        uint64_t s = a << 32;
        uint64_t h = a >> 32;
        // 折叠目标字模 4 回绕（与 nistz256 汇编一致）
        c = addc(t[(i + 1) % 4], s, 0, &t[(i + 1) % 4]);
        c = addc(t[(i + 2) % 4], h, c, &t[(i + 2) % 4]);
        c = addc(t[(i + 3) % 4], lo, c, &t[(i + 3) % 4]);
        c = addc(hi, 0, c, &t[i]);
    }
    // 把折叠后的低 256 位加到高 256 位（ADC 链，延续最后一步进位）
    c = addc(t[0], t[4], c, &t[0]);
    c = addc(t[1], t[5], c, &t[1]);
    c = addc(t[2], t[6], c, &t[2]);
    c = addc(t[3], t[7], c, &t[3]);
    // R = t + c·2^256 < 2p。若 R >= p（c==1 或 t >= p）则减 p 一次，
    // 否则（c==0 且 t < p）保留原值。
    uint64_t o0 = t[0], o1 = t[1], o2 = t[2], o3 = t[3];
    uint64_t bo = subb(t[0], 0xffffffffffffffffull, 0, &t[0]);
    bo = subb(t[1], 0x00000000ffffffffull, bo, &t[1]);
    bo = subb(t[2], 0, bo, &t[2]);
    bo = subb(t[3], 0xffffffff00000001ull, bo, &t[3]);
    if (c == 0 && bo) {
        t[0] = o0; t[1] = o1; t[2] = o2; t[3] = o3;
    }
}

template <int N>
static void mont_mul(bn<N>* r, const bn<N>* a, const bn<N>* b, const mod_ctx<N>& M) {
#if defined(_MSC_VER) && defined(_M_X64)
    if (M.special == 1 && g_p256_adx_ok) {
        jpssl_p256_mul_adx((uint64_t*)r->v, (const uint64_t*)a->v, (const uint64_t*)b->v);
        return;
    }
    if (M.special == 2 && g_p256_adx_ok) {
        jpssl_p256_ord_mul_adx((uint64_t*)r->v, (const uint64_t*)a->v, (const uint64_t*)b->v);
        return;
    }
#elif defined(__aarch64__) && !defined(__APPLE__)
    if (N == 4 && M.special == 1 && g_p256_arm_ok) {
        ecp_nistz256_mul_mont((uint64_t*)r->v, (const uint64_t*)a->v,
                              (const uint64_t*)b->v);
        return;
    }
    if (N == 4 && M.special == 2 && g_p256_arm_ok) {
        ecp_nistz256_ord_mul_mont((uint64_t*)r->v, (const uint64_t*)a->v,
                                  (const uint64_t*)b->v);
        return;
    }
#endif
    uint64_t t[2 * N + 2];
    mul_full(t, a, b);
    if (M.special == 1) {
        p256_reduce_special(t);
        for (int i = 0; i < N; ++i) r->v[i] = t[i];
        return;
    }
    mont_reduce(r, t, M);
}

template <int N>
static void mont_sqr(bn<N>* r, const bn<N>* a, const mod_ctx<N>& M) {
#if defined(__aarch64__) && !defined(__APPLE__)
    if (N == 4 && M.special == 1 && g_p256_arm_ok) {
        ecp_nistz256_sqr_mont((uint64_t*)r->v, (const uint64_t*)a->v);
        return;
    }
#endif
    mont_mul(r, a, a, M);
}

// 模加 / 模减（输入输出均在 [0, m)）
template <int N>
static void mod_add(bn<N>* r, const bn<N>* a, const bn<N>* b, const mod_ctx<N>& M) {
    uint64_t c = bn_add(r, a, b);
    if (c || bn_ge(r, M.m)) bn_sub(r, r, M.m);
}

template <int N>
static void mod_sub(bn<N>* r, const bn<N>* a, const bn<N>* b, const mod_ctx<N>& M) {
    uint64_t bo = bn_sub(r, a, b);
    if (bo) bn_add(r, r, M.m);
}

// 规约到 [0, m)：仅在 a < 2m 时调用
template <int N>
static void mod_reduce(bn<N>* r, const bn<N>* a, const mod_ctx<N>& M) {
    if (bn_ge(a, M.m)) bn_sub(r, a, M.m);
    else *r = *a;
}

template <int N>
static void to_mont(bn<N>* r, const bn<N>* a, const mod_ctx<N>& M) {
    mont_mul(r, a, &M.R2, M);
}

template <int N>
static void from_mont(bn<N>* r, const bn<N>* a, const mod_ctx<N>& M) {
    bn<N> one{};
    one.v[0] = 1;
    mont_mul(r, a, &one, M);
}

// Montgomery 快速幂（指数为公开值时可安全分支）
template <int N>
static void mont_pow(bn<N>* r, const bn<N>* base, const mod_ctx<N>& M,
                     const bn<N>* exp) {
    bn<N> acc = M.one;
    bn<N> b = *base;
    for (int i = N - 1; i >= 0; --i) {
        for (int bit = 63; bit >= 0; --bit) {
            mont_sqr(&acc, &acc, M);
            if ((exp->v[i] >> bit) & 1) mont_mul(&acc, &acc, &b, M);
        }
    }
    *r = acc;
}

// r = a^{-1} mod m（Fermat：a^{m-2}，m 为奇素数）
template <int N>
static void mod_inv(bn<N>* r, const bn<N>* a, const mod_ctx<N>& M) {
#if defined(_MSC_VER) && defined(_M_X64)
    if (N == 4 && M.special == 1 && g_p256_adx_ok) {
        // P-256 素数域专用加法链求逆：255 sq + 12 mul（addchain v0.4.0，
        // 与 crypto/internal/nistec/fiat/p256_invert.go 同源），比 Fermat 链快 ~1.5 倍
        jpssl_p256_inv_adx((uint64_t*)r->v, (const uint64_t*)a->v);
        return;
    }
#elif defined(__aarch64__) && !defined(__APPLE__)
    // P-256 素数域 Fermat 求逆（加法链，OpenSSL ecp_nistz256_mod_inverse）
    if (N == 4 && M.special == 1 && g_p256_arm_ok) {
        uint64_t p2[4], p4[4], p8[4], p16[4], p32[4], res[4];
        const uint64_t* in = (const uint64_t*)a->v;
        ecp_nistz256_sqr_mont(res, in);
        ecp_nistz256_mul_mont(p2, res, in);
        ecp_nistz256_sqr_mont(res, p2);
        ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(p4, res, p2);
        ecp_nistz256_sqr_mont(res, p4);
        for (int i = 0; i < 3; ++i) ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(p8, res, p4);
        ecp_nistz256_sqr_mont(res, p8);
        for (int i = 0; i < 7; ++i) ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(p16, res, p8);
        ecp_nistz256_sqr_mont(res, p16);
        for (int i = 0; i < 15; ++i) ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(p32, res, p16);
        ecp_nistz256_sqr_mont(res, p32);
        for (int i = 0; i < 31; ++i) ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(res, res, in);
        for (int i = 0; i < 32 * 4; ++i) ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(res, res, p32);
        for (int i = 0; i < 32; ++i) ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(res, res, p32);
        for (int i = 0; i < 16; ++i) ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(res, res, p16);
        for (int i = 0; i < 8; ++i) ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(res, res, p8);
        for (int i = 0; i < 4; ++i) ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(res, res, p4);
        ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(res, res, p2);
        ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_sqr_mont(res, res);
        ecp_nistz256_mul_mont(res, res, in);
        for (int i = 0; i < 4; ++i) r->v[i] = res[i];
        return;
    }
#endif
    bn<N> one{};
    one.v[0] = 1;
    bn<N> e;
    bn_sub(&e, M.m, &one);
    bn_sub(&e, &e, &one);
    mont_pow(r, a, M, &e);
}

template <int N>
static void mod_init(mod_ctx<N>* M, const bn<N>* m) {
    M->m = m;
    M->special = 0;
    // mp = -m[0]^{-1} mod 2^64（Newton 迭代）
    uint64_t x = 1;
    for (int i = 0; i < 63; ++i) x = x * (2 - m->v[0] * x);
    M->mp = (uint64_t)(-(int64_t)x);
    // one = R mod m = 2^(64N) mod m（逐次翻倍）
    bn<N> one{};
    one.v[0] = 1;
    for (int i = 0; i < 64 * N; ++i) {
        uint64_t c = bn_add(&one, &one, &one);
        if (c || bn_ge(&one, m)) bn_sub(&one, &one, m);
    }
    M->one = one;
    // R2 = 2^(128N) mod m
    bn<N> r2 = one;
    for (int i = 0; i < 64 * N; ++i) {
        uint64_t c = bn_add(&r2, &r2, &r2);
        if (c || bn_ge(&r2, m)) bn_sub(&r2, &r2, m);
    }
    M->R2 = r2;
}

// ── Jacobian 坐标点运算（坐标值均为 Montgomery 表示，mod p）──

template <int N>
struct jac_point { bn<N> X, Y, Z; };

template <int N>
struct aff_point { bn<N> X, Y; };

template <int N>
static bool jac_is_inf(const jac_point<N>* P) { return bn_is_zero(&P->Z); }

template <int N>
static void jac_inf(jac_point<N>* P, const mod_ctx<N>& M) {
    P->X = M.one;
    P->Y = M.one;
    P->Z = bn<N>{};
}

// 倍点 R = 2P（a = -3，dbl-2001-b）。无穷远哨兵 (1,1,0) 在该公式下保持稳定，
// 因此无需分支。
template <int N>
static void jac_dbl(jac_point<N>* R, const jac_point<N>* P, const mod_ctx<N>& M) {
#if defined(_MSC_VER) && defined(_M_X64)
    if (N == 4 && M.special == 1 && g_p256_adx_ok) {
        jpssl_p256_dbl((uint64_t*)R, (const uint64_t*)P);
        return;
    }
#elif defined(__aarch64__) && !defined(__APPLE__)
    // 哨兵（无穷远，Z=0）由 C++ 路径保持稳定；汇编 point_double 不处理 Z=0
    if (N == 4 && M.special == 1 && g_p256_arm_ok && !bn_is_zero(&P->Z)) {
        ecp_nistz256_point_double((uint64_t*)R, (const uint64_t*)P);
        return;
    }
#endif
    bn<N> A, B, C, D, E, t, X3, Y3, Z3;
    mont_sqr(&A, &P->X, M);
    mont_sqr(&B, &P->Y, M);
    mont_sqr(&C, &B, M);
    mod_add(&t, &P->X, &B, M);
    mont_sqr(&t, &t, M);
    mod_sub(&t, &t, &A, M);
    mod_sub(&t, &t, &C, M);
    mod_add(&D, &t, &t, M);
    // E = 3*(X^2 - Z^4)   [a = -3]
    mont_sqr(&t, &P->Z, M);
    mont_sqr(&t, &t, M);
    mod_sub(&t, &A, &t, M);
    mod_add(&E, &t, &t, M);
    mod_add(&E, &E, &t, M);
    // X3 = E^2 - 2D
    mont_sqr(&X3, &E, M);
    mod_add(&t, &D, &D, M);
    mod_sub(&X3, &X3, &t, M);
    // Y3 = E*(D - X3) - 8C
    mod_sub(&t, &D, &X3, M);
    mont_mul(&Y3, &E, &t, M);
    mod_add(&t, &C, &C, M);
    mod_add(&t, &t, &t, M);
    mod_add(&t, &t, &t, M);
    mod_sub(&Y3, &Y3, &t, M);
    // Z3 = 2*Y*Z
    mont_mul(&Z3, &P->Y, &P->Z, M);
    mod_add(&Z3, &Z3, &Z3, M);

    R->X = X3; R->Y = Y3; R->Z = Z3;
}

// 混合加法 R = P + Q。Q 为“仿射或无穷远”：Z=1 表示仿射点 (X,Y)，
// Z=0 表示无穷远（此时 X=Y=0）。P/Q 为无穷远的两种情况用常数时间掩码选择；
// H==0 例外分支（加倍或无穷远）概率 ~2^-N，与 src/sm2.cpp 一致。
template <int N>
static void pt_madd(jac_point<N>* R, const jac_point<N>* P,
                    const jac_point<N>* Q, const mod_ctx<N>& M) {
#if defined(_MSC_VER) && defined(_M_X64)
    if (N == 4 && M.special == 1 && g_p256_adx_ok) {
        jpssl_p256_madd((uint64_t*)R, (const uint64_t*)P, (const uint64_t*)Q);
        return;
    }
#elif defined(__aarch64__) && !defined(__APPLE__)
    // Q 为仿射（Z=1）或无穷远（Z=0）；P 非无穷远且 Q 非无穷远时用汇编
    // （OpenSSL point_add_affine 内部处理 in1/in2 无穷远，但不处理 H==0，
    // 后者概率 ~2^-256，与 x86 ADX 路径一致；表构建期间经 g_pt_madd_asm 关闭）
    if (N == 4 && M.special == 1 && g_p256_arm_ok && g_pt_madd_asm &&
        !bn_is_zero(&P->Z) && !bn_is_zero(&Q->Z)) {
        ecp_nistz256_point_add_affine((uint64_t*)R, (const uint64_t*)P,
                                      (const uint64_t*)Q->X.v);
        return;
    }
#endif
    bn<N> Z1Z1, U2, S2, H, t, X3, Y3, Z3, I, J, V, tmp;
    mont_sqr(&Z1Z1, &P->Z, M);
    mont_mul(&U2, &Q->X, &Z1Z1, M);
    mont_mul(&S2, &Q->Y, &P->Z, M);
    mont_mul(&S2, &S2, &Z1Z1, M);
    mod_sub(&H, &U2, &P->X, M);
    mod_sub(&t, &S2, &P->Y, M);
    if (bn_is_zero(&H)) {
        if (bn_is_zero(&t)) { jac_dbl(R, P, M); return; }
        jac_inf(R, M);
        return;
    }
    // r = 2*(S2-S1), I = (2H)^2, J = H*I, V = X1*I
    mod_add(&tmp, &t, &t, M);
    mod_add(&V, &H, &H, M);
    mont_sqr(&I, &V, M);
    mont_mul(&J, &H, &I, M);
    mont_mul(&V, &P->X, &I, M);
    // X3 = r^2 - J - 2V
    mont_sqr(&X3, &tmp, M);
    mod_sub(&X3, &X3, &J, M);
    mod_add(&t, &V, &V, M);
    mod_sub(&X3, &X3, &t, M);
    // Y3 = r*(V - X3) - 2*Y1*J
    mod_sub(&t, &V, &X3, M);
    mont_mul(&Y3, &tmp, &t, M);
    mont_mul(&t, &P->Y, &J, M);
    mod_add(&t, &t, &t, M);
    mod_sub(&Y3, &Y3, &t, M);
    // Z3 = 2*Z1*H
    mod_add(&t, &P->Z, &P->Z, M);
    mont_mul(&Z3, &t, &H, M);

    bool pz = bn_is_zero(&P->Z);
    bool qz = bn_is_zero(&Q->Z);
    for (int i = 0; i < N; ++i) {
        uint64_t pm = 0 - (uint64_t)pz;
        uint64_t qm = 0 - (uint64_t)qz;
        uint64_t keep = ~pm & ~qm;
        R->X.v[i] = (X3.v[i] & keep) | (Q->X.v[i] & pm) | (P->X.v[i] & qm);
        R->Y.v[i] = (Y3.v[i] & keep) | (Q->Y.v[i] & pm) | (P->Y.v[i] & qm);
        // Z：P 无穷远且 Q 为仿射点时取 one；Q 无穷远时取 P 的 Z（P 也无穷远时为 0）
        R->Z.v[i] = (Z3.v[i] & keep) | (M.one.v[i] & pm & ~qm) | (P->Z.v[i] & qm);
    }
}

// 完整 Jacobian 加法 R = P + Q（仅用于预计算表构建，非热点）
template <int N>
static void jac_add(jac_point<N>* R, const jac_point<N>* P, const jac_point<N>* Q,
                    const mod_ctx<N>& M) {
    bn<N> Z1Z1, Z2Z2, U1, U2, S1, S2, H, r, I, J, V, t, X3, Y3, Z3;
    mont_sqr(&Z1Z1, &P->Z, M);
    mont_sqr(&Z2Z2, &Q->Z, M);
    mont_mul(&U1, &P->X, &Z2Z2, M);
    mont_mul(&U2, &Q->X, &Z1Z1, M);
    mont_mul(&S1, &P->Y, &Q->Z, M);
    mont_mul(&S1, &S1, &Z2Z2, M);
    mont_mul(&S2, &Q->Y, &P->Z, M);
    mont_mul(&S2, &S2, &Z1Z1, M);
    mod_sub(&H, &U2, &U1, M);
    mod_sub(&r, &S2, &S1, M);
    if (bn_is_zero(&H)) {
        if (bn_is_zero(&r)) { jac_dbl(R, P, M); return; }
        jac_inf(R, M);
        return;
    }
    mod_add(&r, &r, &r, M);   // r = 2*(S2-S1)
    mod_add(&I, &H, &H, M);
    mont_sqr(&I, &I, M);
    mont_mul(&J, &H, &I, M);
    mont_mul(&V, &U1, &I, M);
    mont_sqr(&X3, &r, M);
    mod_sub(&X3, &X3, &J, M);
    mod_add(&t, &V, &V, M);
    mod_sub(&X3, &X3, &t, M);
    mod_sub(&t, &V, &X3, M);
    mont_mul(&Y3, &r, &t, M);
    mont_mul(&t, &S1, &J, M);
    mod_add(&t, &t, &t, M);
    mod_sub(&Y3, &Y3, &t, M);
    mod_add(&t, &P->Z, &Q->Z, M);
    mont_sqr(&t, &t, M);
    mod_sub(&t, &t, &Z1Z1, M);
    mod_sub(&t, &t, &Z2Z2, M);
    mont_mul(&Z3, &t, &H, M);
    R->X = X3; R->Y = Y3; R->Z = Z3;
}

// 批量仿射化：n 个 Jacobian 点 → n 个仿射点（仅一次求逆）
template <int N>
static void batch_affine(jac_point<N>* pts, aff_point<N>* out, int n,
                         const mod_ctx<N>& M) {
    bn<N> pre[16];
    bn<N> acc = M.one;
    for (int i = 0; i < n; ++i) {
        pre[i] = acc;
        mont_mul(&acc, &acc, &pts[i].Z, M);
    }
    bn<N> inv;
    mod_inv(&inv, &acc, M);
    for (int i = n - 1; i >= 0; --i) {
        bn<N> zinv, z2, z3;
        mont_mul(&zinv, &inv, &pre[i], M);
        mont_mul(&inv, &inv, &pts[i].Z, M);
        mont_sqr(&z2, &zinv, M);
        mont_mul(&z3, &z2, &zinv, M);
        mont_mul(&out[i].X, &pts[i].X, &z2, M);
        mont_mul(&out[i].Y, &pts[i].Y, &z3, M);
    }
}

// ── 标量乘 ──

// 宽度-5 wNAF：数字 ∈ {-15,-13,...,-1,1,...,15}（奇数）
template <int N>
static int wnaf5(const bn<N>* k, int8_t* digits, int cap) {
    bn<N> t = *k;
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
        // 右移 1 位：低 limb 从高 limb 的 bit0 取进位
        for (int j = 0; j < N - 1; ++j)
            t.v[j] = (t.v[j] >> 1) | ((t.v[j + 1] & 1u) << 63);
        t.v[N - 1] >>= 1;
        ++i;
    }
    return i;
}

// 计算 1Q, 3Q, ..., 15Q 的仿射表（7 次混合加法 + 批量求逆）
template <int N>
static void build_odd_table(aff_point<N> out[8], const aff_point<N>* Q,
                            const mod_ctx<N>& M) {
    jac_point<N> R;
    R.X = Q->X; R.Y = Q->Y; R.Z = M.one;
    jac_point<N> Qj = R;
    jac_point<N> pts[8];
#if defined(__aarch64__) && !defined(__APPLE__)
    const bool saved_pt_madd_asm = g_pt_madd_asm;
    g_pt_madd_asm = false;
#endif
    for (int i = 0; i < 8; ++i) {
        pts[i] = R;
        if (i < 7) {
            pt_madd(&R, &R, &Qj, M);
            pt_madd(&R, &R, &Qj, M);
        }
    }
#if defined(__aarch64__) && !defined(__APPLE__)
    g_pt_madd_asm = saved_pt_madd_asm;
#endif
    batch_affine(pts, out, 8, M);
}

// 单标量乘 R = k*P（table = P 的 1,3,...,15 倍仿射表；公开标量路径）
template <int N>
static void wnaf_scalar_mult(jac_point<N>* R, const bn<N>* k,
                             const aff_point<N>* table, const mod_ctx<N>& M) {
    int8_t digits[64 * N + 8];
    int len = wnaf5(k, digits, 64 * N + 8);
    jac_inf(R, M);
    jac_point<N> Q;
    bn<N> zero{};
    for (int i = len - 1; i >= 0; --i) {
        jac_dbl(R, R, M);
        int d = digits[i];
        if (d > 0) {
            Q.X = table[d >> 1].X;
            Q.Y = table[d >> 1].Y;
            Q.Z = M.one;
            pt_madd(R, R, &Q, M);
        } else if (d < 0) {
            Q.X = table[(-d) >> 1].X;
            mod_sub(&Q.Y, &zero, &table[(-d) >> 1].Y, M);
            Q.Z = M.one;
            pt_madd(R, R, &Q, M);
        }
    }
}

// 双标量乘（Shamir）：R = k1*P1 + k2*P2，共享倍点链
template <int N>
static void wnaf_dual(jac_point<N>* R, const bn<N>* k1, const aff_point<N>* t1,
                      const bn<N>* k2, const aff_point<N>* t2,
                      const mod_ctx<N>& M) {
    int8_t d1[64 * N + 8], d2[64 * N + 8];
    int l1 = wnaf5(k1, d1, 64 * N + 8);
    int l2 = wnaf5(k2, d2, 64 * N + 8);
    int len = (l1 > l2) ? l1 : l2;
    jac_inf(R, M);
    jac_point<N> Q;
    bn<N> zero{};
    for (int i = len - 1; i >= 0; --i) {
        jac_dbl(R, R, M);
        int a = (i < l1) ? d1[i] : 0;
        int b = (i < l2) ? d2[i] : 0;
        if (a > 0) {
            Q.X = t1[a >> 1].X; Q.Y = t1[a >> 1].Y; Q.Z = M.one;
            pt_madd(R, R, &Q, M);
        } else if (a < 0) {
            Q.X = t1[(-a) >> 1].X;
            mod_sub(&Q.Y, &zero, &t1[(-a) >> 1].Y, M);
            Q.Z = M.one;
            pt_madd(R, R, &Q, M);
        }
        if (b > 0) {
            Q.X = t2[b >> 1].X; Q.Y = t2[b >> 1].Y; Q.Z = M.one;
            pt_madd(R, R, &Q, M);
        } else if (b < 0) {
            Q.X = t2[(-b) >> 1].X;
            mod_sub(&Q.Y, &zero, &t2[(-b) >> 1].Y, M);
            Q.Z = M.one;
            pt_madd(R, R, &Q, M);
        }
    }
}

// 常数时间表选择：d ∈ [0,15]，table[i] = (i+1)*G（i=0..14），d=0 选无穷远
template <int N>
static void ct_select(jac_point<N>* Q, const aff_point<N>* table, int d,
                      const mod_ctx<N>& M) {
    uint64_t x[N], y[N];
    for (int i = 0; i < N; ++i) { x[i] = 0; y[i] = 0; }
    uint64_t any = 0;
    for (int i = 0; i < 15; ++i) {
        uint64_t m = 0 - (uint64_t)(d == i + 1);
        for (int j = 0; j < N; ++j) {
            x[j] |= m & table[i].X.v[j];
            y[j] |= m & table[i].Y.v[j];
        }
        any |= m;
    }
    for (int j = 0; j < N; ++j) {
        Q->X.v[j] = x[j];
        Q->Y.v[j] = y[j];
        Q->Z.v[j] = any & M.one.v[j];
    }
}

// 常数时间固定 4-bit 窗口标量乘（签名/密钥生成用，标量为秘密值）
template <int N>
static void ct_fixed_window(jac_point<N>* R, const bn<N>* k,
                            const aff_point<N>* table, const mod_ctx<N>& M,
                            int windows) {
    int8_t digits[136];
    bn<N> kk = *k;
    for (int i = 0; i < windows; ++i) {
        digits[i] = (int8_t)(kk.v[0] & 15u);
        bn_shr4(&kk);
    }
    jac_inf(R, M);
    jac_point<N> Q;
    for (int i = windows - 1; i >= 0; --i) {
        for (int j = 0; j < 4; ++j) jac_dbl(R, R, M);
        ct_select(&Q, table, digits[i], M);
        pt_madd(R, R, &Q, M);
    }
}

// 固定基点窗口组合（comb）：R = k*G = Σ d_i·2^(4i)·G，i 为公开循环下标，
// 每个窗口从对应子表 CT 选点后直接做混合加，热点路径零倍点。
// table[k][d-1] = d·2^(4k)·G（仿射，Montgomery 表示），d∈[1,15]。
template <int N>
static void comb_fixed_window(jac_point<N>* R, const bn<N>* k,
                              const aff_point<N> (*table)[15], const mod_ctx<N>& M,
                              int windows) {
    int8_t digits[64];
    bn<N> kk = *k;
    for (int i = 0; i < windows; ++i) {
        digits[i] = (int8_t)(kk.v[0] & 15u);
        bn_shr4(&kk);
    }
    jac_inf(R, M);
    jac_point<N> Q;
    for (int i = 0; i < windows; ++i) {
        ct_select(&Q, table[i], digits[i], M);
        pt_madd(R, R, &Q, M);
    }
}

#if defined(__aarch64__) && !defined(__APPLE__)
// ── NIST P-256 固定点标量乘（OpenSSL nistz256 结构）──
static inline uint32_t booth_recode_w7(uint32_t in) {
    uint32_t s = ~((in >> 7) - 1);
    uint32_t d = (1 << 8) - in - 1;
    d = (d & s) | (in & ~s);
    d = (d >> 1) + (d & 1);
    return (d << 1) + (s & 1);
}
static inline void copy_conditional(uint64_t dst[4], const uint64_t src[4],
                                    uint64_t move) {
    uint64_t mask1 = 0 - move;
    uint64_t mask2 = ~mask1;
    for (int i = 0; i < 4; ++i)
        dst[i] = (dst[i] & mask2) | (src[i] & mask1);
}
/// R = k*G（k < n），使用 OpenSSL 静态预计算表（7 位窗口 Booth 编码）
static void nistz256_scalar_mul_G(jac_point<4>* R, const bn<4>* k) {
    const unsigned int window_size = 7;
    const unsigned int mask = (1u << (window_size + 1)) - 1;
    unsigned char p_str[33] = {0};
    for (int i = 0; i < 4; ++i) {
        uint64_t d = k->v[i];
        for (int b = 0; b < 8; ++b)
            p_str[i * 8 + b] = (unsigned char)(d >> (8 * b));
    }
    unsigned int idx = 0;
    uint64_t p[12], t[12];
    unsigned int wvalue = (p_str[0] << 1) & mask;
    idx += window_size;
    wvalue = booth_recode_w7(wvalue);
    ecp_nistz256_gather_w7(p, (const uint64_t*)(ecp_nistz256_precomputed + 0 * 4096), wvalue >> 1);
    {
        uint64_t neg_y[4];
        ecp_nistz256_neg(neg_y, p + 4);
        copy_conditional(p + 4, neg_y, (uint64_t)(wvalue & 1));
    }
    {
        uint64_t infty = 0;
        for (int i = 0; i < 8; ++i) infty |= p[i];
        uint64_t inf_mask = 0 - (uint64_t)(infty == 0);
        uint64_t one[4] = {1, 0xffffffff00000000ull, 0xffffffffffffffffull, 0x00000000fffffffeull};
        for (int i = 0; i < 4; ++i)
            p[8 + i] = one[i] & ~inf_mask;
    }
    for (unsigned int i = 1; i < 37; ++i) {
        unsigned int off = (idx - 1) / 8;
        wvalue = p_str[off] | ((unsigned int)p_str[off + 1] << 8);
        wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
        idx += window_size;
        wvalue = booth_recode_w7(wvalue);
        ecp_nistz256_gather_w7(t, (const uint64_t*)(ecp_nistz256_precomputed + i * 4096), wvalue >> 1);
        {
            uint64_t neg_y[4];
            ecp_nistz256_neg(neg_y, t + 4);
            copy_conditional(t + 4, neg_y, (uint64_t)(wvalue & 1));
        }
        ecp_nistz256_point_add_affine(p, p, t);
    }
    for (int i = 0; i < 12; ++i) ((uint64_t*)R)[i] = p[i];
}
#endif

// ── 曲线上下文 ──

template <int N>
struct ecdsa_curve {
    bn<N> P, order, GX, GY;
    mod_ctx<N> MP, MN;
    aff_point<N> g_full[15];  // (i+1)*G，i=0..14（仿射，Montgomery 表示 mod p）
    aff_point<N> g_odd[8];    // 1G,3G,...,15G（wNAF 表）
    bool ready;
};

template <int N>
static void build_g_tables(ecdsa_curve<N>* c) {
    aff_point<N> G;
    to_mont(&G.X, &c->GX, c->MP);
    to_mont(&G.Y, &c->GY, c->MP);
    jac_point<N> R;
    R.X = G.X; R.Y = G.Y; R.Z = c->MP.one;
    jac_point<N> Gj = R;
    jac_point<N> pts[15];
#if defined(__aarch64__) && !defined(__APPLE__)
    const bool saved_pt_madd_asm = g_pt_madd_asm;
    g_pt_madd_asm = false;
#endif
    for (int i = 0; i < 15; ++i) {
        pts[i] = R;
        pt_madd(&R, &R, &Gj, c->MP);
    }
#if defined(__aarch64__) && !defined(__APPLE__)
    g_pt_madd_asm = saved_pt_madd_asm;
#endif
    batch_affine(pts, c->g_full, 15, c->MP);
    for (int i = 0; i < 8; ++i) c->g_odd[i] = c->g_full[2 * i];
    c->ready = true;
}

template <int N, int BYTES>
static void ecdsa_curve_init(ecdsa_curve<N>* c, const uint8_t* p, const uint8_t* n,
                             const uint8_t* gx, const uint8_t* gy) {
    bn_from_be<N, BYTES>(&c->P, p);
    bn_from_be<N, BYTES>(&c->order, n);
    bn_from_be<N, BYTES>(&c->GX, gx);
    bn_from_be<N, BYTES>(&c->GY, gy);
    mod_init(&c->MP, &c->P);
    mod_init(&c->MN, &c->order);
    build_g_tables(c);
}

// ── P-256 域参数（FIPS 186-4, NIST secp256r1）──

static const uint8_t P256_P_BYTES[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};
static const uint8_t P256_N_BYTES[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51
};
static const uint8_t P256_Gx_BYTES[32] = {
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96
};
static const uint8_t P256_Gy_BYTES[32] = {
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
};

static ecdsa_curve<4> C256;
static bool c256_ready = false;
// P-256 固定基点 comb 表：g_comb[k][d-1] = d·2^(4k)·G，k=0..63，d=1..15
static aff_point<4> g_comb[64][15];
static bool g_comb_ready = false;

static void build_comb_table() {
    if (g_comb_ready) return;
    jac_point<4> cur;
    cur.X = C256.g_full[0].X;
    cur.Y = C256.g_full[0].Y;
    cur.Z = C256.MP.one;                 // cur = 1G
    for (int k = 0; k < 64; ++k) {
        jac_point<4> pts[15];
        pts[0] = cur;
        for (int d = 1; d < 15; ++d) jac_add(&pts[d], &pts[d - 1], &cur, C256.MP);
        aff_point<4> out[15];
        batch_affine(pts, out, 15, C256.MP);
        for (int d = 0; d < 15; ++d) g_comb[k][d] = out[d];
        if (k < 63)
            for (int j = 0; j < 4; ++j) jac_dbl(&cur, &cur, C256.MP);  // cur *= 16
    }
    g_comb_ready = true;
}

static void ensure256() {
    if (!c256_ready) {
        ecdsa_curve_init<4, 32>(&C256, P256_P_BYTES, P256_N_BYTES,
                                P256_Gx_BYTES, P256_Gy_BYTES);
        C256.MP.special = 1;  // P-256 素数域走 nistz256 特殊形式归约
        C256.MN.special = 2;  // P-256 群阶走 ord 特殊形式归约
#if defined(_MSC_VER) && defined(_M_X64)
        g_p256_adx_ok = cpu_has_adx();
#elif defined(__aarch64__) && !defined(__APPLE__)
        g_p256_arm_ok = true;
#endif
        c256_ready = true;
    }
}

// ── P-384 域参数（FIPS 186-4, NIST secp384r1）──

static const uint8_t P384_P_BYTES[48] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff
};
static const uint8_t P384_N_BYTES[48] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc7,0x63,0x4d,0x81,0xf4,0x37,0x2d,0xdf,
    0x58,0x1a,0x0d,0xb2,0x48,0xb0,0xa7,0x7a,0xec,0xec,0x19,0x6a,0xcc,0xc5,0x29,0x73
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

static ecdsa_curve<6> C384;
static bool c384_ready = false;

static void ensure384() {
    if (!c384_ready) {
        ecdsa_curve_init<6, 48>(&C384, P384_P_BYTES, P384_N_BYTES,
                                P384_Gx_BYTES, P384_Gy_BYTES);
        c384_ready = true;
    }
}

// ── P-521 域参数（FIPS 186-4, NIST secp521r1，66 字节大端）──

static const uint8_t P521_P_BYTES[66] = {
    0x01,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff
};
static const uint8_t P521_N_BYTES[66] = {
    0x01,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xfa,0x51,0x86,0x87,0x83,0xbf,0x2f,0x96,0x6b,0x7f,0xcc,0x01,0x48,0xf7,0x09,0xa5,
    0xd0,0x3b,0xb5,0xc9,0xb8,0x89,0x9c,0x47,0xae,0xbb,0x6f,0xb7,0x1e,0x91,0x38,0x64,
    0x09
};
static const uint8_t P521_Gx_BYTES[66] = {
    0x00,0xc6,0x85,0x8e,0x06,0xb7,0x04,0x04,0xe9,0xcd,0x9e,0x3e,0xcb,0x66,0x23,0x95,
    0xb4,0x42,0x9c,0x64,0x81,0x39,0x05,0x3f,0xb5,0x21,0xf8,0x28,0xaf,0x60,0x6b,0x4d,
    0x3d,0xba,0xa1,0x4b,0x5e,0x77,0xef,0xe7,0x59,0x28,0xfe,0x1d,0xc1,0x27,0xa2,0xff,
    0xa8,0xde,0x33,0x48,0xb3,0xc1,0x85,0x6a,0x42,0x9b,0xf9,0x7e,0x7e,0x31,0xc2,0xe5,
    0xbd,0x66
};
static const uint8_t P521_Gy_BYTES[66] = {
    0x01,0x18,0x39,0x29,0x6a,0x78,0x9a,0x3b,0xc0,0x04,0x5c,0x8a,0x5f,0xb4,0x2c,0x7d,
    0x1b,0xd9,0x98,0xf5,0x44,0x49,0x57,0x9b,0x44,0x68,0x17,0xaf,0xbd,0x17,0x27,0x3e,
    0x66,0x2c,0x97,0xee,0x72,0x99,0x5e,0xf4,0x26,0x40,0xc5,0x50,0xb9,0x01,0x3f,0xad,
    0x07,0x61,0x35,0x3c,0x70,0x86,0xa2,0x72,0xc2,0x40,0x88,0xbe,0x94,0x76,0x9f,0xd1,
    0x66,0x50
};

static ecdsa_curve<9> C521;
static bool c521_ready = false;

static void ensure521() {
    if (!c521_ready) {
        ecdsa_curve_init<9, 66>(&C521, P521_P_BYTES, P521_N_BYTES,
                                P521_Gx_BYTES, P521_Gy_BYTES);
        c521_ready = true;
    }
}

// ── 辅助：哈希、随机数 ──

static void rand_bytes(uint8_t* buf, size_t len) {
#ifdef _WIN32
    os_rand_bytes(buf, len);
#else
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    for (size_t i = 0; i < len; i += 8) {
        uint64_t v = gen();
        for (size_t j = 0; j < 8 && i + j < len; ++j)
            buf[i + j] = (uint8_t)(v >> (j * 8));
    }
#endif
}

// k ∈ [1, n-1]；mask_top 用于 P-521（随机数限定在 521 位内）
template <int N, int BYTES>
static void rand_scalar(bn<N>* k, const bn<N>* n, bool mask_top) {
    uint8_t buf[BYTES];
    do {
        rand_bytes(buf, BYTES);
        if (mask_top) buf[0] &= 0x01;
        bn_from_be<N, BYTES>(k, buf);
        if (!bn_lt(k, n)) bn_sub(k, k, n);
    } while (bn_is_zero(k));
}

static void hash256_to_e(bn<4>* e, const uint8_t* msg, size_t msg_len) {
    uint8_t d[32];
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, msg, msg_len);
    sha256_final(&ctx, d);
    bn_from_be<4, 32>(e, d);
}

static void hash384_to_e(bn<6>* e, const uint8_t* msg, size_t msg_len) {
    uint8_t d[48];
    sha512_ctx ctx;
    sha384_init(&ctx);
    sha512_update(&ctx, msg, msg_len);
    sha512_final(&ctx, d);
    bn_from_be<6, 48>(e, d);
}

// P-521：e = bits2int(SHA-512(M))，512 位 < n，直接作为 521 位整数
static void hash521_to_e(bn<9>* e, const uint8_t* msg, size_t msg_len) {
    uint8_t h[64];
    sha512(msg, msg_len, h);
    uint8_t eb[66] = {0};
    memcpy(eb + 2, h, 64);
    bn_from_be<9, 66>(e, eb);
}

} // namespace（内部实现，以下为公共 API）

// ── ECDHE 共享密钥 ──

template <int N, int BYTES>
static bool ecdh_impl(uint8_t* shared, const uint8_t* priv, const uint8_t* pub,
                      const ecdsa_curve<N>& C, int windows) {
    bn<N> d;
    bn_from_be<N, BYTES>(&d, priv);
    if (bn_is_zero(&d) || !bn_lt(&d, &C.order)) return false;
    bn<N> qx, qy;
    bn_from_be<N, BYTES>(&qx, pub);
    bn_from_be<N, BYTES>(&qy, pub + BYTES);
    mod_reduce(&qx, &qx, C.MP);
    mod_reduce(&qy, &qy, C.MP);
    aff_point<N> Q;
    to_mont(&Q.X, &qx, C.MP);
    to_mont(&Q.Y, &qy, C.MP);
    aff_point<N> qt[8];
    build_odd_table(qt, &Q, C.MP);
    jac_point<N> R;
    wnaf_scalar_mult(&R, &d, qt, C.MP);
    if (jac_is_inf(&R)) return false;
    aff_point<N> A;
    batch_affine(&R, &A, 1, C.MP);
    bn<N> x;
    from_mont(&x, &A.X, C.MP);
    bn_to_be<N, BYTES>(&x, shared);
    return true;
}

bool ecdsa_p256_ecdh(uint8_t shared[32], const uint8_t priv[32], const uint8_t pub[64]) {
    ensure256();
    return ecdh_impl<4, 32>(shared, priv, pub, C256, 64);
}

bool ecdsa_p384_ecdh(uint8_t shared[48], const uint8_t priv[48], const uint8_t pub[96]) {
    ensure384();
    return ecdh_impl<6, 48>(shared, priv, pub, C384, 96);
}

// 批量仿射化：n 个 Jacobian 点 → n 个仿射点，整批仅一次 Fermat 求逆
// （Montgomery 批量求逆：1 次求逆 + 3(n-1) 次乘法）。Z=0 的点逐个求逆回退。
template <int N>
static void batch_affine_many(jac_point<N>* pts, aff_point<N>* out, int n,
                              const mod_ctx<N>& M) {
    if (n <= 0) return;
    std::vector<bn<N>> pre((size_t)n);
    bn<N> acc = M.one;
    bool any_zero = false;
    for (int i = 0; i < n; ++i) {
        pre[(size_t)i] = acc;
        if (bn_is_zero(&pts[i].Z)) any_zero = true;
        mont_mul(&acc, &acc, &pts[i].Z, M);
    }
    if (any_zero) {
        for (int i = 0; i < n; ++i) {
            if (bn_is_zero(&pts[i].Z)) {
                out[i].X = M.one;
                out[i].Y = M.one;
                continue;
            }
            bn<N> zinv, z2, z3;
            mod_inv(&zinv, &pts[i].Z, M);
            mont_sqr(&z2, &zinv, M);
            mont_mul(&z3, &z2, &zinv, M);
            mont_mul(&out[i].X, &pts[i].X, &z2, M);
            mont_mul(&out[i].Y, &pts[i].Y, &z3, M);
        }
        return;
    }
    bn<N> inv;
    mod_inv(&inv, &acc, M);
    for (int i = n - 1; i >= 0; --i) {
        bn<N> zinv, z2, z3;
        mont_mul(&zinv, &inv, &pre[(size_t)i], M);
        mont_mul(&inv, &inv, &pts[i].Z, M);
        mont_sqr(&z2, &zinv, M);
        mont_mul(&z3, &z2, &zinv, M);
        mont_mul(&out[i].X, &pts[i].X, &z2, M);
        mont_mul(&out[i].Y, &pts[i].Y, &z3, M);
    }
}

// 批量 ECDH：块内先构建各条奇倍表（Jacobian），统一一次求逆仿射化，
// 各自 wNAF 标量乘后再统一一次求逆，输出 X 坐标。
template <int N, int BYTES>
static bool ecdh_batch_impl(uint8_t* shared, const uint8_t* priv, const uint8_t* pub,
                            int count, const ecdsa_curve<N>& C, int windows) {
    const int CHUNK = 16;
    for (int off = 0; off < count; off += CHUNK) {
        int n = (count - off < CHUNK) ? count - off : CHUNK;
        jac_point<N> odd[CHUNK][8];
        aff_point<N> qt[CHUNK][8];
        bn<N> d[CHUNK];
        for (int i = 0; i < n; ++i) {
            bn_from_be<N, BYTES>(&d[i], priv + (size_t)(off + i) * BYTES);
            if (bn_is_zero(&d[i]) || !bn_lt(&d[i], &C.order)) return false;
            const uint8_t* p = pub + (size_t)(off + i) * (2 * BYTES);
            bn<N> qx, qy;
            bn_from_be<N, BYTES>(&qx, p);
            bn_from_be<N, BYTES>(&qy, p + BYTES);
            mod_reduce(&qx, &qx, C.MP);
            mod_reduce(&qy, &qy, C.MP);
            aff_point<N> Q;
            to_mont(&Q.X, &qx, C.MP);
            to_mont(&Q.Y, &qy, C.MP);
            jac_point<N> R;
            R.X = Q.X; R.Y = Q.Y; R.Z = C.MP.one;
            jac_point<N> Qj = R;
#if defined(__aarch64__) && !defined(__APPLE__)
            const bool saved_pt_madd_asm = g_pt_madd_asm;
            g_pt_madd_asm = false;  // 同点相加（首轮 H==0）走 C++
#endif
            for (int k = 0; k < 8; ++k) {
                odd[i][k] = R;
                if (k < 7) {
                    pt_madd(&R, &R, &Qj, C.MP);
                    pt_madd(&R, &R, &Qj, C.MP);
                }
            }
#if defined(__aarch64__) && !defined(__APPLE__)
            g_pt_madd_asm = saved_pt_madd_asm;
#endif
        }
        // 奇倍表统一仿射化（整块一次求逆）
        {
            std::vector<jac_point<N>> flat((size_t)(8 * n));
            std::vector<aff_point<N>> fout((size_t)(8 * n));
            for (int i = 0; i < n; ++i)
                for (int k = 0; k < 8; ++k) flat[(size_t)(i * 8 + k)] = odd[i][k];
            batch_affine_many(flat.data(), fout.data(), 8 * n, C.MP);
            for (int i = 0; i < n; ++i)
                for (int k = 0; k < 8; ++k) qt[i][k] = fout[(size_t)(i * 8 + k)];
        }
        jac_point<N> R[CHUNK];
        for (int i = 0; i < n; ++i)
            wnaf_scalar_mult(&R[i], &d[i], qt[i], C.MP);
        aff_point<N> A[CHUNK];
        batch_affine_many(R, A, n, C.MP);
        for (int i = 0; i < n; ++i) {
            bn<N> x;
            from_mont(&x, &A[i].X, C.MP);
            bn_to_be<N, BYTES>(&x, shared + (size_t)(off + i) * BYTES);
        }
    }
    return true;
}

bool ecdsa_p256_ecdh_batch(uint8_t* shared, const uint8_t* priv, const uint8_t* pub, int count) {
    if (count <= 0) return false;
    ensure256();
    return ecdh_batch_impl<4, 32>(shared, priv, pub, count, C256, 64);
}

bool ecdsa_p384_ecdh_batch(uint8_t* shared, const uint8_t* priv, const uint8_t* pub, int count) {
    if (count <= 0) return false;
    ensure384();
    return ecdh_batch_impl<6, 48>(shared, priv, pub, count, C384, 96);
}

// ── P-256 API ──

void ecdsa_p256_keygen(uint8_t pub[64], uint8_t priv[32]) {
    ensure256();
    bn<4> d;
    rand_scalar<4, 32>(&d, &C256.order, false);
    bn_to_be<4, 32>(&d, priv);
    jac_point<4> Q;
#if defined(__aarch64__) && !defined(__APPLE__)
    nistz256_scalar_mul_G(&Q, &d);
#else
    build_comb_table();
    comb_fixed_window(&Q, &d, g_comb, C256.MP, 64);
#endif
    aff_point<4> A;
    batch_affine(&Q, &A, 1, C256.MP);
    bn<4> x, y;
    from_mont(&x, &A.X, C256.MP);
    from_mont(&y, &A.Y, C256.MP);
    bn_to_be<4, 32>(&x, pub);
    bn_to_be<4, 32>(&y, pub + 32);
}

void ecdsa_p256_sign(const uint8_t priv[32], const uint8_t* msg,
                     size_t msg_len, uint8_t sig[64]) {
    ensure256();
    bn<4> d;
    bn_from_be<4, 32>(&d, priv);
    bn<4> e;
    hash256_to_e(&e, msg, msg_len);
    mod_reduce(&e, &e, C256.MN);
    bn<4> d_m, e_m;
    to_mont(&d_m, &d, C256.MN);
    to_mont(&e_m, &e, C256.MN);

    jac_point<4> R;
    aff_point<4> A;
    bn<4> Rx, r, s, k, r_m, k_m, k_inv_m, rd_m, ed_m, s_m, r_plain;
    do {
        rand_scalar<4, 32>(&k, &C256.order, false);
#if defined(__aarch64__) && !defined(__APPLE__)
        nistz256_scalar_mul_G(&R, &k);
#else
        comb_fixed_window(&R, &k, g_comb, C256.MP, 64);
#endif
        batch_affine(&R, &A, 1, C256.MP);
        from_mont(&Rx, &A.X, C256.MP);
        mod_reduce(&r, &Rx, C256.MN);
        if (bn_is_zero(&r)) continue;
        to_mont(&r_m, &r, C256.MN);
        to_mont(&k_m, &k, C256.MN);
        mod_inv(&k_inv_m, &k_m, C256.MN);
        mont_mul(&rd_m, &r_m, &d_m, C256.MN);
        mod_add(&ed_m, &e_m, &rd_m, C256.MN);
        mont_mul(&s_m, &k_inv_m, &ed_m, C256.MN);
        from_mont(&s, &s_m, C256.MN);
        if (bn_is_zero(&s)) continue;
        from_mont(&r_plain, &r_m, C256.MN);
        bn_to_be<4, 32>(&r_plain, sig);
        bn_to_be<4, 32>(&s, sig + 32);
        return;
    } while (true);
}

bool ecdsa_p256_verify(const uint8_t pub[64], const uint8_t* msg,
                       size_t msg_len, const uint8_t sig[64]) {
    ensure256();
    bn<4> r, s;
    bn_from_be<4, 32>(&r, sig);
    bn_from_be<4, 32>(&s, sig + 32);
    if (bn_is_zero(&r) || bn_is_zero(&s)) return false;
    if (!bn_lt(&r, &C256.order) || !bn_lt(&s, &C256.order)) return false;

    bn<4> e;
    hash256_to_e(&e, msg, msg_len);
    mod_reduce(&e, &e, C256.MN);

    bn<4> e_m, r_m, s_m, w_m, u1_m, u2_m, u1, u2;
    to_mont(&e_m, &e, C256.MN);
    to_mont(&r_m, &r, C256.MN);
    to_mont(&s_m, &s, C256.MN);
    mod_inv(&w_m, &s_m, C256.MN);
    mont_mul(&u1_m, &e_m, &w_m, C256.MN);
    mont_mul(&u2_m, &r_m, &w_m, C256.MN);
    from_mont(&u1, &u1_m, C256.MN);
    from_mont(&u2, &u2_m, C256.MN);

    bn<4> qx, qy;
    bn_from_be<4, 32>(&qx, pub);
    bn_from_be<4, 32>(&qy, pub + 32);
    mod_reduce(&qx, &qx, C256.MP);
    mod_reduce(&qy, &qy, C256.MP);
    aff_point<4> Q;
    to_mont(&Q.X, &qx, C256.MP);
    to_mont(&Q.Y, &qy, C256.MP);

    aff_point<4> qt[8];
    build_odd_table(qt, &Q, C256.MP);
    jac_point<4> R;
    wnaf_dual(&R, &u1, C256.g_odd, &u2, qt, C256.MP);
    if (jac_is_inf(&R)) return false;

    // v = R.x mod n == r  ⇔  X ≡ r·Z² (mod p) 或 X ≡ (r+n)·Z² (mod p)
    // （R.x < p < 2n，故 v ∈ {r, r+n}；用射影比较省去一次 Fermat 求逆）
    bn<4> Z2, rp, rn, t1, t2;
    mont_sqr(&Z2, &R.Z, C256.MP);
    to_mont(&rp, &r, C256.MP);
    mont_mul(&t1, &rp, &Z2, C256.MP);
    bn_add(&rn, &r, &C256.order);
    if (bn_ge(&rn, &C256.P)) bn_sub(&rn, &rn, &C256.P);
    to_mont(&rn, &rn, C256.MP);
    mont_mul(&t2, &rn, &Z2, C256.MP);
    return bn_eq(&R.X, &t1) || bn_eq(&R.X, &t2);
}

// ── P-384 API ──

void ecdsa_p384_keygen(uint8_t pub[96], uint8_t priv[48]) {
    ensure384();
    bn<6> d;
    rand_scalar<6, 48>(&d, &C384.order, false);
    bn_to_be<6, 48>(&d, priv);
    jac_point<6> Q;
    ct_fixed_window(&Q, &d, C384.g_full, C384.MP, 96);
    aff_point<6> A;
    batch_affine(&Q, &A, 1, C384.MP);
    bn<6> x, y;
    from_mont(&x, &A.X, C384.MP);
    from_mont(&y, &A.Y, C384.MP);
    bn_to_be<6, 48>(&x, pub);
    bn_to_be<6, 48>(&y, pub + 48);
}

void ecdsa_p384_sign(const uint8_t priv[48], const uint8_t* msg,
                     size_t msg_len, uint8_t sig[96]) {
    ensure384();
    bn<6> d;
    bn_from_be<6, 48>(&d, priv);
    bn<6> e;
    hash384_to_e(&e, msg, msg_len);
    mod_reduce(&e, &e, C384.MN);
    bn<6> d_m, e_m;
    to_mont(&d_m, &d, C384.MN);
    to_mont(&e_m, &e, C384.MN);

    jac_point<6> R;
    aff_point<6> A;
    bn<6> Rx, r, s, k, r_m, k_m, k_inv_m, rd_m, ed_m, s_m, r_plain;
    do {
        rand_scalar<6, 48>(&k, &C384.order, false);
        ct_fixed_window(&R, &k, C384.g_full, C384.MP, 96);
        batch_affine(&R, &A, 1, C384.MP);
        from_mont(&Rx, &A.X, C384.MP);
        mod_reduce(&r, &Rx, C384.MN);
        if (bn_is_zero(&r)) continue;
        to_mont(&r_m, &r, C384.MN);
        to_mont(&k_m, &k, C384.MN);
        mod_inv(&k_inv_m, &k_m, C384.MN);
        mont_mul(&rd_m, &r_m, &d_m, C384.MN);
        mod_add(&ed_m, &e_m, &rd_m, C384.MN);
        mont_mul(&s_m, &k_inv_m, &ed_m, C384.MN);
        from_mont(&s, &s_m, C384.MN);
        if (bn_is_zero(&s)) continue;
        from_mont(&r_plain, &r_m, C384.MN);
        bn_to_be<6, 48>(&r_plain, sig);
        bn_to_be<6, 48>(&s, sig + 48);
        return;
    } while (true);
}

bool ecdsa_p384_verify(const uint8_t pub[96], const uint8_t* msg,
                       size_t msg_len, const uint8_t sig[96]) {
    ensure384();
    bn<6> r, s;
    bn_from_be<6, 48>(&r, sig);
    bn_from_be<6, 48>(&s, sig + 48);
    if (bn_is_zero(&r) || bn_is_zero(&s)) return false;
    if (!bn_lt(&r, &C384.order) || !bn_lt(&s, &C384.order)) return false;

    bn<6> e;
    hash384_to_e(&e, msg, msg_len);
    mod_reduce(&e, &e, C384.MN);

    bn<6> e_m, r_m, s_m, w_m, u1_m, u2_m, u1, u2;
    to_mont(&e_m, &e, C384.MN);
    to_mont(&r_m, &r, C384.MN);
    to_mont(&s_m, &s, C384.MN);
    mod_inv(&w_m, &s_m, C384.MN);
    mont_mul(&u1_m, &e_m, &w_m, C384.MN);
    mont_mul(&u2_m, &r_m, &w_m, C384.MN);
    from_mont(&u1, &u1_m, C384.MN);
    from_mont(&u2, &u2_m, C384.MN);

    bn<6> qx, qy;
    bn_from_be<6, 48>(&qx, pub);
    bn_from_be<6, 48>(&qy, pub + 48);
    mod_reduce(&qx, &qx, C384.MP);
    mod_reduce(&qy, &qy, C384.MP);
    aff_point<6> Q;
    to_mont(&Q.X, &qx, C384.MP);
    to_mont(&Q.Y, &qy, C384.MP);

    aff_point<6> qt[8];
    build_odd_table(qt, &Q, C384.MP);
    jac_point<6> R;
    wnaf_dual(&R, &u1, C384.g_odd, &u2, qt, C384.MP);
    if (jac_is_inf(&R)) return false;

    bn<6> Z2, rp, rn, t1, t2;
    mont_sqr(&Z2, &R.Z, C384.MP);
    to_mont(&rp, &r, C384.MP);
    mont_mul(&t1, &rp, &Z2, C384.MP);
    bn_add(&rn, &r, &C384.order);
    if (bn_ge(&rn, &C384.P)) bn_sub(&rn, &rn, &C384.P);
    to_mont(&rn, &rn, C384.MP);
    mont_mul(&t2, &rn, &Z2, C384.MP);
    return bn_eq(&R.X, &t1) || bn_eq(&R.X, &t2);
}

// ── P-521 API ──

void ecdsa_p521_keygen(uint8_t pub[132], uint8_t priv[66]) {
    ensure521();
    bn<9> d;
    rand_scalar<9, 66>(&d, &C521.order, true);
    bn_to_be<9, 66>(&d, priv);
    jac_point<9> Q;
    ct_fixed_window(&Q, &d, C521.g_full, C521.MP, 131);
    aff_point<9> A;
    batch_affine(&Q, &A, 1, C521.MP);
    bn<9> x, y;
    from_mont(&x, &A.X, C521.MP);
    from_mont(&y, &A.Y, C521.MP);
    bn_to_be<9, 66>(&x, pub);
    bn_to_be<9, 66>(&y, pub + 66);
}

void ecdsa_p521_sign(const uint8_t priv[66], const uint8_t* msg,
                     size_t msg_len, uint8_t sig[132]) {
    ensure521();
    bn<9> d;
    bn_from_be<9, 66>(&d, priv);
    bn<9> e;
    hash521_to_e(&e, msg, msg_len);
    mod_reduce(&e, &e, C521.MN);
    bn<9> d_m, e_m;
    to_mont(&d_m, &d, C521.MN);
    to_mont(&e_m, &e, C521.MN);

    jac_point<9> R;
    aff_point<9> A;
    bn<9> Rx, r, s, k, r_m, k_m, k_inv_m, rd_m, ed_m, s_m, r_plain;
    do {
        rand_scalar<9, 66>(&k, &C521.order, true);
        ct_fixed_window(&R, &k, C521.g_full, C521.MP, 131);
        batch_affine(&R, &A, 1, C521.MP);
        from_mont(&Rx, &A.X, C521.MP);
        mod_reduce(&r, &Rx, C521.MN);
        if (bn_is_zero(&r)) continue;
        to_mont(&r_m, &r, C521.MN);
        to_mont(&k_m, &k, C521.MN);
        mod_inv(&k_inv_m, &k_m, C521.MN);
        mont_mul(&rd_m, &r_m, &d_m, C521.MN);
        mod_add(&ed_m, &e_m, &rd_m, C521.MN);
        mont_mul(&s_m, &k_inv_m, &ed_m, C521.MN);
        from_mont(&s, &s_m, C521.MN);
        if (bn_is_zero(&s)) continue;
        from_mont(&r_plain, &r_m, C521.MN);
        bn_to_be<9, 66>(&r_plain, sig);
        bn_to_be<9, 66>(&s, sig + 66);
        return;
    } while (true);
}

bool ecdsa_p521_verify(const uint8_t pub[132], const uint8_t* msg,
                       size_t msg_len, const uint8_t sig[132]) {
    ensure521();
    bn<9> r, s;
    bn_from_be<9, 66>(&r, sig);
    bn_from_be<9, 66>(&s, sig + 66);
    if (bn_is_zero(&r) || bn_is_zero(&s)) return false;
    if (!bn_lt(&r, &C521.order) || !bn_lt(&s, &C521.order)) return false;

    bn<9> e;
    hash521_to_e(&e, msg, msg_len);
    mod_reduce(&e, &e, C521.MN);

    bn<9> e_m, r_m, s_m, w_m, u1_m, u2_m, u1, u2;
    to_mont(&e_m, &e, C521.MN);
    to_mont(&r_m, &r, C521.MN);
    to_mont(&s_m, &s, C521.MN);
    mod_inv(&w_m, &s_m, C521.MN);
    mont_mul(&u1_m, &e_m, &w_m, C521.MN);
    mont_mul(&u2_m, &r_m, &w_m, C521.MN);
    from_mont(&u1, &u1_m, C521.MN);
    from_mont(&u2, &u2_m, C521.MN);

    bn<9> qx, qy;
    bn_from_be<9, 66>(&qx, pub);
    bn_from_be<9, 66>(&qy, pub + 66);
    mod_reduce(&qx, &qx, C521.MP);
    mod_reduce(&qy, &qy, C521.MP);
    aff_point<9> Q;
    to_mont(&Q.X, &qx, C521.MP);
    to_mont(&Q.Y, &qy, C521.MP);

    aff_point<9> qt[8];
    build_odd_table(qt, &Q, C521.MP);
    jac_point<9> R;
    wnaf_dual(&R, &u1, C521.g_odd, &u2, qt, C521.MP);
    if (jac_is_inf(&R)) return false;

    bn<9> Z2, rp, rn, t1, t2;
    mont_sqr(&Z2, &R.Z, C521.MP);
    to_mont(&rp, &r, C521.MP);
    mont_mul(&t1, &rp, &Z2, C521.MP);
    bn_add(&rn, &r, &C521.order);
    if (bn_ge(&rn, &C521.P)) bn_sub(&rn, &rn, &C521.P);
    to_mont(&rn, &rn, C521.MP);
    mont_mul(&t2, &rn, &Z2, C521.MP);
    return bn_eq(&R.X, &t1) || bn_eq(&R.X, &t2);
}

} // namespace jpssl
