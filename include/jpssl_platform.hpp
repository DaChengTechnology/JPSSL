#pragma once

/**
 * jpssl_platform.hpp — Windows (MSVC) 平台兼容层
 *
 * 解决的问题：
 *   1. MSVC x64 不提供 GCC/Clang 的 __uint128_t（128 位无符号整数）。
 *      本项目核心数学（RSA Montgomery、Ed25519/X25519 radix-51、Ed448、
 *      ECDSA、SM2 的乘法累加与借位链）依赖该类型。此头文件在 _MSC_VER 下
 *      提供行为等价的 jp_uint128 类，并 #define __uint128_t jp_uint128，
 *      使业务代码无需逐处改写（仅限 MSVC，GCC/Clang 继续使用原生类型）。
 *      实现基于 x64 intrinsic：_umul128 / _addcarry_u64 / _subborrow_u64 /
 *      _udiv128，全部 inline，/O2 下内联为单条指令序列。
 *   2. __builtin_bswap32 的 MSVC 等价（_byteswap_ulong）。
 *
 * 注意：CMake 的 MSVC 分支通过 /FI 强制包含本文件，无需修改业务代码 include。
 */

#include <cstdint>
#include <cstddef>

#if defined(_MSC_VER) && !defined(__clang__)

#include <intrin.h>

// ── __builtin_bswap32 → _byteswap_ulong ─────────────────────────────────
#define __builtin_bswap32(x) _byteswap_ulong((unsigned long)(x))

// ── 128 位无符号整数兼容层 ──────────────────────────────────────────────
struct jp_uint128 {
    uint64_t lo;
    uint64_t hi;

    jp_uint128() noexcept : lo(0), hi(0) {}
    jp_uint128(uint64_t v) noexcept : lo(v), hi(0) {}
    jp_uint128(int v) noexcept : lo((uint64_t)v), hi(0) {}

    /// 取低 64 位（(uint64_t)x 显式转换）。
    /// 注意：必须 explicit —— 隐式转换会让 jp_uint128 * uint64_t 在内置
    /// operator*(uint64_t,uint64_t)（经 operator uint64_t()）与自定义
    /// operator* 之间产生重载歧义 (MSVC C2666)。业务代码全部使用显式
    /// C 风格转换 (uint64_t)x，static_cast 语义可调用 explicit 转换函数。
    explicit operator uint64_t() const noexcept { return lo; }

    /// 布尔上下文（if / 三元 / && / || / !）：非零即 true。
    /// explicit operator bool 允许在条件表达式中隐式使用（C++11）。
    explicit operator bool() const noexcept { return lo != 0 || hi != 0; }

    // ── 加法 ──
    jp_uint128& operator+=(const jp_uint128& rhs) noexcept {
        unsigned char cf = _addcarry_u64(0, lo, rhs.lo, &lo);
        _addcarry_u64(cf, hi, rhs.hi, &hi);
        return *this;
    }
    jp_uint128& operator+=(uint64_t v) noexcept {
        unsigned char cf = _addcarry_u64(0, lo, v, &lo);
        _addcarry_u64(cf, hi, 0, &hi);
        return *this;
    }
    jp_uint128 operator+(const jp_uint128& rhs) const noexcept {
        jp_uint128 r = *this; r += rhs; return r;
    }

    // ── 减法（借位链）──
    jp_uint128& operator-=(const jp_uint128& rhs) noexcept {
        unsigned char bf = _subborrow_u64(0, lo, rhs.lo, &lo);
        _subborrow_u64(bf, hi, rhs.hi, &hi);
        return *this;
    }
    jp_uint128& operator-=(uint64_t v) noexcept {
        unsigned char bf = _subborrow_u64(0, lo, v, &lo);
        _subborrow_u64(bf, hi, 0, &hi);
        return *this;
    }
    jp_uint128 operator-(const jp_uint128& rhs) const noexcept {
        jp_uint128 r = *this; r -= rhs; return r;
    }
    jp_uint128 operator-(uint64_t v) const noexcept {
        jp_uint128 r = *this; r -= v; return r;
    }

    // ── 移位（0..127）──
    jp_uint128& operator>>=(int sh) noexcept {
        if (sh >= 128) { lo = hi = 0; }
        else if (sh == 64) { lo = hi; hi = 0; }
        else if (sh > 64) { lo = hi >> (sh - 64); hi = 0; }
        else if (sh > 0) { lo = (lo >> sh) | (hi << (64 - sh)); hi >>= sh; }
        return *this;
    }
    jp_uint128& operator<<=(int sh) noexcept {
        if (sh >= 128) { lo = hi = 0; }
        else if (sh == 64) { hi = lo; lo = 0; }
        else if (sh > 64) { hi = lo << (sh - 64); lo = 0; }
        else if (sh > 0) { hi = (hi << sh) | (lo >> (64 - sh)); lo <<= sh; }
        return *this;
    }
    jp_uint128 operator>>(int sh) const noexcept {
        jp_uint128 r = *this; r >>= sh; return r;
    }
    jp_uint128 operator<<(int sh) const noexcept {
        jp_uint128 r = *this; r <<= sh; return r;
    }

    // ── 位掩码 / 拼接 ──
    // 注意: 64 位掩码与 128 位值 & 时高位必须清零（GCC 原生 __uint128_t 语义）
    jp_uint128& operator&=(uint64_t mask) noexcept { lo &= mask; hi = 0; return *this; }
    jp_uint128 operator&(uint64_t mask) const noexcept {
        jp_uint128 r = *this; r &= mask; return r;
    }
    jp_uint128 operator|(uint64_t v) const noexcept {
        jp_uint128 r = *this; r.lo |= v; return r;
    }

    // ── 128 ÷ 64 取余（_udiv128，x64 专用）──
    uint64_t operator%(uint64_t d) const noexcept {
        // 快速路径: 32 位除数（bn_mod_small 小素数筛的常见场景），3 次 64 位除法，
        // 比通用 _udiv128 快约 2-3 倍
        if (d <= 0xFFFFFFFFULL) {
            uint64_t r = hi % d;
            r = ((r << 32) | (lo >> 32)) % d;
            r = ((r << 32) | (lo & 0xFFFFFFFFULL)) % d;
            return r;
        }
        uint64_t rem = 0;
        _udiv128(hi, lo, d, &rem);
        return rem;
    }

    // ── 比较 ──
    bool operator==(const jp_uint128& rhs) const noexcept { return lo == rhs.lo && hi == rhs.hi; }
    bool operator!=(const jp_uint128& rhs) const noexcept { return !(*this == rhs); }
    bool operator<(const jp_uint128& rhs) const noexcept {
        return hi < rhs.hi || (hi == rhs.hi && lo < rhs.lo);
    }
    bool operator>(const jp_uint128& rhs) const noexcept { return rhs < *this; }
    bool operator<=(const jp_uint128& rhs) const noexcept { return !(rhs < *this); }
    bool operator>=(const jp_uint128& rhs) const noexcept { return !(*this < rhs); }
};

/// 非成员乘法：覆盖 a*b / 19*t5 / c*19 等（任意一侧均可隐式转换）
/// 注意 _umul128(a,b,&hi) 返回低 64 位、指针输出高 64 位
inline jp_uint128 operator*(const jp_uint128& a, const jp_uint128& b) noexcept {
    uint64_t lo_out = 0, hi_out = 0;
    lo_out = _umul128(a.lo, b.lo, &hi_out);
    uint64_t t = 0;
    uint64_t mid1 = _umul128(a.lo, b.hi, &t);  // 交叉项低 64（高 64 丢弃：整体 128 位结果只需其低 64）
    uint64_t mid2 = _umul128(a.hi, b.lo, &t);
    unsigned char cf = _addcarry_u64(0, hi_out, mid1, &hi_out);
    _addcarry_u64(cf, hi_out, mid2, &hi_out);
    jp_uint128 r;
    r.lo = lo_out;
    r.hi = hi_out;
    return r;
}

#define __uint128_t jp_uint128

#endif // _MSC_VER
