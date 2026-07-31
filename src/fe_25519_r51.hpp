#pragma once
/**
 * fe_25519_r51.hpp — radix-2^51 域运算（5 × uint64_t limb）
 *
 * 域：p = 2^255 − 19
 * 表示：h = h[0] + h[1]*2^51 + h[2]*2^102 + h[3]*2^153 + h[4]*2^204
 *
 * 设计要点（参照 OpenSSL crypto/ec/curve25519.c 的成熟结构）：
 *  - fe51_mul / fe51_sq：5×5 schoolbook 乘法，高 limb 乘 19 折叠进低位，
 *    输出经完整进位传播后每个 limb < 2^51 + ε
 *  - fe51_sub：加 2^52 级别常数保证结果 limb 非负（无符号表示下无借位）
 *  - fe51_tobytes：完整 freeze（多轮进位 + 条件减 p）后编码
 *
 * 优势：25 次 64×64→128 乘法（vs 10-limb 的 100 次 32×32），
 *       配合 -mavx2 -madx 时编译器生成 MULX/ADCX/ADOX 双进位链。
 */
#include <cstdint>
#include <cstring>

namespace jpssl { namespace x25519_r51 {

using fe51 = uint64_t[5];

// 2^51 - 1（51 bits，13 hex digits：0x7 后 12 个 F）
static constexpr uint64_t MASK51 = 0x7FFFFFFFFFFFFULL;

// p 的 5-limb 表示：p[0]=2^51-19, p[1..4]=2^51-1 (MASK51)
static const uint64_t P51[5] = {
    0x7FFFFFFFFFFEDULL,
    0x7FFFFFFFFFFFFULL,
    0x7FFFFFFFFFFFFULL,
    0x7FFFFFFFFFFFFULL,
    0x7FFFFFFFFFFFFULL
};

// ──────────── 工具 ────────────

static inline uint64_t load8(const uint8_t* in) {
    return (uint64_t)in[0] | ((uint64_t)in[1] << 8)
        | ((uint64_t)in[2] << 16) | ((uint64_t)in[3] << 24)
        | ((uint64_t)in[4] << 32) | ((uint64_t)in[5] << 40)
        | ((uint64_t)in[6] << 48) | ((uint64_t)in[7] << 56);
}
static inline void store8(uint8_t* out, uint64_t v) {
    out[0] = (uint8_t)(v);       out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16); out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32); out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48); out[7] = (uint8_t)(v >> 56);
}

inline void fe51_copy(fe51 r, const fe51 a) { memcpy(r, a, sizeof(fe51)); }
inline void fe51_0(fe51 r)   { memset(r, 0, sizeof(fe51)); }
inline void fe51_1(fe51 r)   { fe51_0(r); r[0] = 1; }

// ──────────── 序列化 ────────────

/// 32 字节小端 → 5-limb（51-bit 边界拆分，忽略 bit 255）
inline void fe51_frombytes(fe51 h, const uint8_t s[32]) {
    uint64_t w0 = load8(s + 0), w1 = load8(s + 8);
    uint64_t w2 = load8(s + 16), w3 = load8(s + 24);
    h[0] = w0 & MASK51;
    h[1] = (w0 >> 51) | ((w1 & 0x3FFFFFFFFFULL) << 13);
    h[2] = (w1 >> 38) | ((w2 & 0x1FFFFFFULL) << 26);
    h[3] = (w2 >> 25) | ((w3 & 0xFFFULL) << 39);
    h[4] = (w3 >> 12) & MASK51;
}

/// 5-limb → 32 字节小端。调用前须完整 freeze（limb < 2^51 且 < p）。
inline void fe51_tobytes(uint8_t s[32], const fe51 h) {
    uint64_t t0 = h[0], t1 = h[1], t2 = h[2], t3 = h[3], t4 = h[4];
    uint64_t c;

    // 完整进位（多轮，直到每个 limb < 2^51）
    for (int pass = 0; pass < 4; pass++) {
        c = t0 >> 51; t1 += c; t0 &= MASK51;
        c = t1 >> 51; t2 += c; t1 &= MASK51;
        c = t2 >> 51; t3 += c; t2 &= MASK51;
        c = t3 >> 51; t4 += c; t3 &= MASK51;
        c = t4 >> 51; t4 &= MASK51;
        t0 += c * 19;
    }
    c = t0 >> 51; t1 += c; t0 &= MASK51;
    c = t1 >> 51; t2 += c; t1 &= MASK51;
    c = t2 >> 51; t3 += c; t2 &= MASK51;
    c = t3 >> 51; t4 += c; t3 &= MASK51;
    c = t4 >> 51; t4 &= MASK51;
    t0 += c * 19;
    c = t0 >> 51; t0 &= MASK51; t1 += c;
    // 现在所有 limb < 2^51（t1 可能 = 2^51，下一步条件减处理）

    // 条件减 p：t >= p 则 t -= p
    uint64_t q0 = t0 - P51[0]; uint64_t b0 = (t0 < P51[0]);
    uint64_t q1 = t1 - P51[1] - b0; uint64_t b1 = (t1 < P51[1] + b0);
    uint64_t q2 = t2 - P51[2] - b1; uint64_t b2 = (t2 < P51[2] + b1);
    uint64_t q3 = t3 - P51[3] - b2; uint64_t b3 = (t3 < P51[3] + b2);
    uint64_t q4 = t4 - P51[4] - b3; uint64_t b4 = (t4 < P51[4] + b3);
    uint64_t mask = b4 - 1;   // b4==0(≥p) → 全1；b4==1(<p) → 0
    t0 = (t0 & ~mask) | (q0 & mask);
    t1 = (t1 & ~mask) | (q1 & mask);
    t2 = (t2 & ~mask) | (q2 & mask);
    t3 = (t3 & ~mask) | (q3 & mask);
    t4 = (t4 & ~mask) | (q4 & mask);

    // 编码（交叉合并到 4 个 64-bit 字）
    uint64_t w0 = t0 | ((t1 & 0x1FFFULL) << 51);
    uint64_t w1 = (t1 >> 13) | ((t2 & 0x3FFFFFFULL) << 38);
    uint64_t w2 = (t2 >> 26) | ((t3 & 0x7FFFFFFFFFULL) << 25);
    uint64_t w3 = (t3 >> 39) | (t4 << 12);
    store8(s + 0, w0); store8(s + 8, w1);
    store8(s + 16, w2); store8(s + 24, w3);
}

// ──────────── 基本运算 ────────────

/// 加法（不约减；输入 limb < 2^53 时输出 < 2^54）
inline void fe51_add(fe51 r, const fe51 a, const fe51 b) {
    for (int i = 0; i < 5; i++) r[i] = a[i] + b[i];
}

/**
 * 减法（加 2^52 常数保证非负）。
 * 输入 limb < 2^51+ε 时：r[i] ∈ [C[i] − (2^51+ε), C[i] + 2^51+ε) > 0
 * 2^52 − 38 = 0x0FFFFFFFFFFFDA（14 hex digits），2^52 − 2 = 0x0FFFFFFFFFFFE
 */
/// 传播进位使每个 limb < 2^51（输入须非负，来自 mul/add/sub 输出）
inline void fe51_carry(fe51 r, const fe51 a) {
    uint64_t t0 = a[0], t1 = a[1], t2 = a[2], t3 = a[3], t4 = a[4];
    uint64_t c;
    c = t0 >> 51; t1 += c; t0 &= MASK51;
    c = t1 >> 51; t2 += c; t1 &= MASK51;
    c = t2 >> 51; t3 += c; t2 &= MASK51;
    c = t3 >> 51; t4 += c; t3 &= MASK51;
    c = t4 >> 51; t4 &= MASK51;
    t0 += c * 19;
    c = t0 >> 51; t1 += c; t0 &= MASK51;
    r[0] = t0; r[1] = t1; r[2] = t2; r[3] = t3; r[4] = t4;
}

inline void fe51_sub(fe51 r, const fe51 a, const fe51 b) {
    // 先 carry 输入使 limb < 2^51+ε，再加 2p 补偿保证非负。
    // 输出 ∈ (2p - 2^51, 2p + 2^51) ≈ (2^51, 2^52.6)，作为后续输入
    // 再经 carry 归一化，范围稳定不膨胀。
    uint64_t ca[5], cb[5];
    fe51_carry(ca, a);
    fe51_carry(cb, b);
    static const uint64_t TWO_P[5] = {
        0x0FFFFFFFFFFFDAULL,  // 2*(2^51-19)
        0xFFFFFFFFFFFFEULL,   // 2*(2^51-1)
        0xFFFFFFFFFFFFEULL,
        0xFFFFFFFFFFFFEULL,
        0xFFFFFFFFFFFFEULL,
    };
    for (int i = 0; i < 5; i++)
        r[i] = ca[i] + TWO_P[i] - cb[i];
}

// ────────────  乘法（核心） ────────────

/**
 * r = a * b  (mod p)
 *
 * 5x5 schoolbook（9 个位置乘积，全部 __uint128_t）
 * + 2^255 ≡ 19 折叠（r5..r8 乘 19 加到低 5 位）
 * + 51-bit 进位链（全程 __uint128_t，避免 64-bit 溢出丢进位）。
 *
 * 输入 limb 允许 [0, 2^53)；输出每个 limb < 2^51。
 */
inline void fe51_mul(fe51 r, const fe51 a, const fe51 b) {
    const uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    const uint64_t b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4];

    // 9 个位置乘积（i+j = 0..8），全部 128-bit 无溢出
    __uint128_t t0 = (__uint128_t)a0 * b0;
    __uint128_t t1 = (__uint128_t)a0 * b1 + (__uint128_t)a1 * b0;
    __uint128_t t2 = (__uint128_t)a0 * b2 + (__uint128_t)a1 * b1 + (__uint128_t)a2 * b0;
    __uint128_t t3 = (__uint128_t)a0 * b3 + (__uint128_t)a1 * b2 + (__uint128_t)a2 * b1 + (__uint128_t)a3 * b0;
    __uint128_t t4 = (__uint128_t)a0 * b4 + (__uint128_t)a1 * b3 + (__uint128_t)a2 * b2 + (__uint128_t)a3 * b1 + (__uint128_t)a4 * b0;
    __uint128_t t5 = (__uint128_t)a1 * b4 + (__uint128_t)a2 * b3 + (__uint128_t)a3 * b2 + (__uint128_t)a4 * b1;
    __uint128_t t6 = (__uint128_t)a2 * b4 + (__uint128_t)a3 * b3 + (__uint128_t)a4 * b2;
    __uint128_t t7 = (__uint128_t)a3 * b4 + (__uint128_t)a4 * b3;
    __uint128_t t8 = (__uint128_t)a4 * b4;

    // 折叠：位置 5+ 乘 19 加到低 5 位（2^255 ≡ 19）
    t0 += 19 * t5;
    t1 += 19 * t6;
    t2 += 19 * t7;
    t3 += 19 * t8;
    // t4 保持

    // 51-bit 进位链，全程 128-bit 累加避免溢出
    __uint128_t c;
    c = t0 >> 51; t0 &= MASK51; t1 += c;
    c = t1 >> 51; t1 &= MASK51; t2 += c;
    c = t2 >> 51; t2 &= MASK51; t3 += c;
    c = t3 >> 51; t3 &= MASK51; t4 += c;
    c = t4 >> 51; t4 &= MASK51;
    t0 += c * 19;
    c = t0 >> 51; t0 &= MASK51; t1 += c;

    r[0] = (uint64_t)t0; r[1] = (uint64_t)t1; r[2] = (uint64_t)t2;
    r[3] = (uint64_t)t3; r[4] = (uint64_t)t4;
}

inline void fe51_sq(fe51 r, const fe51 a) { fe51_mul(r, a, a); }

// ────────────  条件交换 ────────────

inline void fe51_cswap(fe51 p, fe51 q, uint64_t bit) {
    uint64_t mask = bit ? UINT64_MAX : 0;
    for (int i = 0; i < 5; i++) {
        uint64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t; q[i] ^= t;
    }
}

// ────────────  求逆（ref10 加法链） ────────────

/// r = z^{-1} mod p = z^(p-2)（255 sq + 11 mul 的加法链）
inline void fe51_invert(fe51 out, const fe51 z) {
    fe51 t0, t1, t2, t3;
    fe51_sq(t0, z);                       // z^2
    fe51_sq(t1, t0); fe51_sq(t1, t1);     // z^8
    fe51_mul(t1, z, t1);                  // z^9
    fe51_mul(t0, t0, t1);                 // z^11
    fe51_sq(t2, t0);                      // z^22
    fe51_mul(t1, t1, t2);                 // z^31
    fe51_sq(t2, t1);                      // z^62
    for (int i = 1; i < 5; i++) fe51_sq(t2, t2);   // z^992
    fe51_mul(t1, t2, t1);                 // z^1023
    fe51_sq(t2, t1);                      // z^2046
    for (int i = 1; i < 10; i++) fe51_sq(t2, t2);  // z^1047552
    fe51_mul(t2, t2, t1);                 // z^1048575
    fe51_sq(t3, t2);                      // z^2097150
    for (int i = 1; i < 20; i++) fe51_sq(t3, t3);  // z^1099511627776
    fe51_mul(t2, t3, t2);                 // z^1099512676351
    fe51_sq(t2, t2);                      // z^2199025352702
    for (int i = 1; i < 10; i++) fe51_sq(t2, t2);  // z^1125899906842624
    fe51_mul(t1, t2, t1);                 // z^1125900951699455
    fe51_sq(t2, t1);                      // z^2251801903398910
    for (int i = 1; i < 50; i++) fe51_sq(t2, t2);  // z^1267650600228229401496703205376
    fe51_mul(t2, t2, t1);                 // z^1267650600230531203390096604291
    fe51_sq(t3, t2);                      // z^2535301200461062406780193208582
    for (int i = 1; i < 100; i++) fe51_sq(t3, t3); // z^2^255 - 2^155 + ...
    fe51_mul(t2, t3, t2);                 // ...
    fe51_sq(t2, t2);                      // ...
    for (int i = 1; i < 50; i++) fe51_sq(t2, t2);  // ...
    fe51_mul(t1, t2, t1);                 // ...
    fe51_sq(t1, t1);                      // ...
    for (int i = 1; i < 5; i++) fe51_sq(t1, t1);   // ...
    fe51_mul(out, t1, t0);                // z^(2^255-21) = z^(p-2)
}


// ═══════════════════════════════════════════════════════════════════
//  以下为 ed25519 所需辅助运算（移植自 fe_25519.hpp 的 ref10 逻辑）
// ═══════════════════════════════════════════════════════════════════

/// h = -f (mod p)
inline void fe51_neg(fe51 h, const fe51 f) {
    // 先 carry 输入使 limb < 2^51+ε，再加 2p 补偿保证非负
    uint64_t cf[5];
    fe51_carry(cf, f);
    static const uint64_t TWO_P[5] = {
        0x0FFFFFFFFFFFDAULL,
        0xFFFFFFFFFFFFEULL,
        0xFFFFFFFFFFFFEULL,
        0xFFFFFFFFFFFFEULL,
        0xFFFFFFFFFFFFEULL,
    };
    for (int i = 0; i < 5; i++)
        h[i] = TWO_P[i] - cf[i];
}

/// h = 2 * f^2
inline void fe51_sq2(fe51 h, const fe51 f) {
    fe51_mul(h, f, f);
    fe51_add(h, h, h);
}

/// 返回 f 是否为负（符号位）
inline int fe51_isnegative(const fe51 f) {
    uint8_t s[32];
    fe51_tobytes(s, f);
    return s[0] & 1;
}

/// 返回 f 是否非零
inline int fe51_isnonzero(const fe51 f) {
    uint8_t s[32];
    fe51_tobytes(s, f);
    int r = 0;
    for (int i = 0; i < 32; i++) r |= s[i];
    return r;
}

/// 返回 f == g
inline int fe51_equal(const fe51 f, const fe51 g) {
    fe51 t;
    fe51_sub(t, f, g);
    return !fe51_isnonzero(t);
}

/// r = z^(2^252 - 3)（用于平方根）
inline void fe51_pow22523(fe51 out, const fe51 z) {
    fe51 t0, t1, t2;
    int i;
    fe51_sq(t0, z);
    fe51_sq(t1, t0);
    for (i = 1; i < 2; ++i) fe51_sq(t1, t1);
    fe51_mul(t1, z, t1);
    fe51_mul(t0, t0, t1);
    fe51_sq(t0, t0);
    fe51_mul(t0, t1, t0);
    fe51_sq(t1, t0);
    for (i = 1; i < 5; ++i) fe51_sq(t1, t1);
    fe51_mul(t0, t1, t0);
    fe51_sq(t1, t0);
    for (i = 1; i < 10; ++i) fe51_sq(t1, t1);
    fe51_mul(t1, t1, t0);
    fe51_sq(t2, t1);
    for (i = 1; i < 20; ++i) fe51_sq(t2, t2);
    fe51_mul(t1, t2, t1);
    fe51_sq(t1, t1);
    for (i = 1; i < 10; ++i) fe51_sq(t1, t1);
    fe51_mul(t0, t1, t0);
    fe51_sq(t1, t0);
    for (i = 1; i < 50; ++i) fe51_sq(t1, t1);
    fe51_mul(t1, t1, t0);
    fe51_sq(t2, t1);
    for (i = 1; i < 100; ++i) fe51_sq(t2, t2);
    fe51_mul(t1, t2, t1);
    fe51_sq(t1, t1);
    for (i = 1; i < 50; ++i) fe51_sq(t1, t1);
    fe51_mul(t0, t1, t0);
    fe51_sq(t0, t0);
    for (i = 1; i < 2; ++i) fe51_sq(t0, t0);
    fe51_mul(out, t0, z);
}

/// 计算 sqrt(u/v)；返回 1=存在, 2=存在(×sqrtm1), 0=不存在
inline int fe51_sqrt_ratio(fe51 out, const fe51 u, const fe51 v) {
    fe51 uv3, uv7, r, s;
    // sqrtm1 = 2^((p-1)/4)
    static const uint8_t sqrtm1_bytes[32] = {
        176,160,14,74,39,27,238,196,120,228,47,173,6,24,67,47,
        167,215,251,61,153,0,77,43,11,223,193,79,128,36,131,43
    };
    static fe51 sqrtm1;
    static bool sqrtm1_init = false;
    if (!sqrtm1_init) {
        sqrtm1_init = true;
        fe51_frombytes(sqrtm1, sqrtm1_bytes);
    }

    fe51_sq(uv3, v); fe51_mul(uv3, uv3, v);
    fe51_sq(uv7, uv3); fe51_mul(uv7, uv7, v); fe51_mul(uv7, uv7, u);
    fe51_mul(uv3, u, uv3);
    fe51_pow22523(r, uv7);
    fe51_mul(r, r, uv3);
    fe51_sq(s, r); fe51_mul(s, s, v);
    if (fe51_equal(s, u)) { fe51_copy(out, r); return 1; }
    fe51_mul(r, r, sqrtm1);
    fe51_sq(s, r); fe51_mul(s, s, v);
    if (fe51_equal(s, u)) { fe51_copy(out, r); return 2; }
    fe51_0(out);
    return 0;
}
} } // namespace jpssl::x25519_r51
