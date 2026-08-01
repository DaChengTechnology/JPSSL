#pragma once
/**
 * fe_avx2.hpp — AVX2 5×64-bit 域运算（4 路并行）
 *
 * 表示法：5 个 64-bit limb，基 2^51（每个 limb ∈ [0, 2^51)）
 * AVX2 处理：每个 limb 位置存储 4 个独立域元素的对应 limb
 *
 *   struct fe4 { __m256i limb[5]; };  // limb[i] = { elem0.l[i], elem1.l[i], elem2.l[i], elem3.l[i] }
 *
 * 关键操作：fe4_mul（4 路并行域乘法 = 批量性能核心）
 */
#include <immintrin.h>
#include <cstdint>

namespace jpssl { namespace ed25519_avx2 {

// ──────────── 常量 ────────────

// 域：p = 2^255 − 19
// 逆参数（用于 Barrett/Montgomery 约减）
static const uint64_t P0 = 0x7FFFFFFFFFFED;     // p 的低 51 位 (实际 p & ((1<<51)-1))
static const uint64_t P1 = 0x7FFFFFFFFFF;       // p >> 51 (低 51)
static const uint64_t P2 = 0x7FFFFFFFFFF;
static const uint64_t P3 = 0x7FFFFFFFFFF;
static const uint64_t P4 = 0x7FFFFFFFFFF;        // p >> 204
// 实际上 p 的 5-limb 表示：
// p = 2^255 - 19 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
// 按 51-bit 拆分：limb[0]=0x7FFFFFFFFFFED, limb[1..4]=0x7FFFFFFFFFF

/// 4 路并行 5-limb 域元素
struct fe4 {
    __m256i limb[5];   // limb[i] 包含 4 个元素的第 i 个 limb
};

// ──────────── 工具 ────────────

/// 广播 64-bit 常量到 4 个 lane
inline __m256i broadcast4(uint64_t x) {
    return _mm256_set1_epi64x((int64_t)x);
}

/// 从 4 个独立的 5-limb 域元素加载
inline void fe4_load(fe4* r, const uint64_t elem[4][5]) {
    for (int i = 0; i < 5; i++) {
        r->limb[i] = _mm256_set_epi64x(
            (int64_t)elem[3][i], (int64_t)elem[2][i],
            (int64_t)elem[1][i], (int64_t)elem[0][i]);
    }
}

/// 存储到 4 个独立的 5-limb 数组
inline void fe4_store(uint64_t elem[4][5], const fe4* r) {
    for (int i = 0; i < 5; i++) {
        uint64_t vals[4];
        _mm256_store_si256((__m256i*)vals, r->limb[i]);
        for (int j = 0; j < 4; j++) elem[j][i] = vals[j];
    }
}

// ──────────── 基本运算 ────────────

/// 4 路并行加法（不约减）
inline void fe4_add(fe4* r, const fe4* a, const fe4* b) {
    for (int i = 0; i < 5; i++)
        r->limb[i] = _mm256_add_epi64(a->limb[i], b->limb[i]);
}

/// 4 路并行减法（不约减）
inline void fe4_sub(fe4* r, const fe4* a, const fe4* b) {
    for (int i = 0; i < 5; i++)
        r->limb[i] = _mm256_sub_epi64(a->limb[i], b->limb[i]);
}

// ────────────  乘法辅助 ────────────

/// 51×51 → 102 乘法：返回 (lo_64, hi_38) 对
/// 注意：结果的高 38 位需要单独处理
inline void mul_51x51_4way(__m256i* lo, __m256i* hi, __m256i a, __m256i b) {
    // 分解为 32-bit 半部分:
    // a = a0 + a1*2^32,  b = b0 + b1*2^32
    const __m256i mask32 = broadcast4(0xFFFFFFFFULL);
    __m256i a0 = _mm256_and_si256(a, mask32);
    __m256i a1 = _mm256_srli_epi64(a, 32);
    __m256i b0 = _mm256_and_si256(b, mask32);
    __m256i b1 = _mm256_srli_epi64(b, 32);

    // p00 = a0 * b0  (32×32 → 64, 用 PMULUDQ 处理偶 lane，奇 lane 需额外处理)
    // AVX2 PMULUDQ 只计算 lane[0]×lane[0]→lane[0], lane[2]×lane[2]→lane[2]
    // 需要先将奇 lane 移到偶位置
    // 更简单的做法：用 AND + MUL 组合（用较慢但通用方式）
    // 精确做法（4路 × 32-bit 全乘）:
    //  p00[0..3] = a0[0..3] * b0[0..3]
    // PMULUDQ: 偶数lane乘法; 奇数lane需要shuffle

    // 偶数 lane (0,2):
    __m256i a0_even = _mm256_and_si256(a0, _mm256_set_epi64x(0,0xFFFFFFFF,0,0xFFFFFFFF));
    // 不对... PMULUDQ 取 64-bit lane 的低 32 位

    // 更简便：使用 VPMULLQ（仅 AVX512-DQ 支持），回退到标量模拟
    // 对 4 个值的 51-bit 乘法，用 uint128_t 模拟：

    uint64_t av[4], bv[4];
    _mm256_store_si256((__m256i*)av, a);
    _mm256_store_si256((__m256i*)bv, b);

    uint64_t lo_v[4], hi_v[4];
    for (int i = 0; i < 4; i++) {
        __uint128_t prod = (__uint128_t)av[i] * bv[i];
        lo_v[i] = (uint64_t)prod;
        hi_v[i] = (uint64_t)(prod >> 64);
    }

    *lo = _mm256_set_epi64x(lo_v[3], lo_v[2], lo_v[1], lo_v[0]);
    *hi = _mm256_set_epi64x(hi_v[3], hi_v[2], hi_v[3], hi_v[0]);
    // 注意 hi 只有 38 位有效（51×51 ≤ 2^102 < 2^128）
}

// ──────────── 核心：4 路并行 fe_mul ────────────

/**
 * r = a * b  (4 路并行)
 *
 * 5×5 limb 乘法 + carry 传播 + 模 p 约减
 */
inline void fe4_mul(fe4* r, const fe4* a, const fe4* b) {
    // 乘积 accumulation（每个 lane 一个 __int128 等价，但 SIMD 不支持 128-bit）
    // 策略：将乘积拆成 lo (64-bit) + hi (38-bit)，传播 carry

    // 临时：标量 fallback，后续用 AVX512-IFMA 或更精细的 AVX2 实现替代
    uint64_t av[4][5], bv[4][5];
    fe4_store(av, a);
    fe4_store(bv, b);

    uint64_t rv[4][5];
    for (int n = 0; n < 4; n++) {
        // 标量 5×5 limb 乘法 + reduction
        uint64_t t[10] = {0};
        for (int i = 0; i < 5; i++) {
            uint64_t carry = 0;
            for (int j = 0; j < 5; j++) {
                __uint128_t prod = (__uint128_t)av[n][i] * bv[n][j] + t[i+j] + carry;
                t[i+j] = (uint64_t)prod;
                carry = (uint64_t)(prod >> 64);
            }
            t[i+5] = carry;
        }

        // Reduce modulo p: t[0..4] = t mod (2^255-19)
        // 对于 limb k >= 5: 乘 19 加到低位
        // 简化：每个额外 limb × 19 加到 t[k-5]
        uint64_t c = 0;
        for (int k = 5; k < 10; k++) {
            __uint128_t add = (__uint128_t)t[k] * 19 + t[k-5] + c;
            t[k-5] = (uint64_t)add;
            c = (uint64_t)(add >> 64);
        }
        t[0] += c * 19;

        // Carry propagate
        for (int i = 0; i < 4; i++) {
            uint64_t carry = t[i] >> 51;
            t[i] &= 0x7FFFFFFFFFFFFULL;
            t[i+1] += carry;
        }
        t[4] &= 0x7FFFFFFFFFFFFULL;

        // Conditional subtract p
        // 检查 t ≥ p（用减法试）
        uint64_t borrow = 0;
        uint64_t r_sub[5];
        static const uint64_t P[5] = {
            0x7FFFFFFFFFFEDULL, 0x7FFFFFFFFFFULL,
            0x7FFFFFFFFFFULL, 0x7FFFFFFFFFFULL, 0x7FFFFFFFFFFULL
        };
        for (int i = 0; i < 5; i++) {
            __uint128_t diff = (__uint128_t)t[i] - P[i] - borrow;
            r_sub[i] = (uint64_t)diff;
            borrow = (uint64_t)(diff >> 64) & 1;
        }
        if (borrow) {
            // t < p: keep t
            for (int i = 0; i < 5; i++) rv[n][i] = t[i];
        } else {
            for (int i = 0; i < 5; i++) rv[n][i] = r_sub[i];
        }
    }
    fe4_load(r, rv);
}

/// 4 路并行平方
inline void fe4_sq(fe4* r, const fe4* a) {
    fe4_mul(r, a, a);
}

/// 广播单个标量 fe 到 4 个 lane（用于 ge_add 的基点等）
inline void fe4_broadcast_scalar(fe4* r, const uint64_t scalar[5]) {
    for (int i = 0; i < 5; i++)
        r->limb[i] = broadcast4(scalar[i]);
}

} // namespace ed25519_avx2
} // namespace jpssl
