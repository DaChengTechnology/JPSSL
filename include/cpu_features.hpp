#pragma once

#include <cstdint>

/**
 * cpu_features.hpp — 运行时 CPU 特性检测 + 分派
 *
 * 检测：
 *   - AES-NI (Intel/AMD AES 硬件加速)
 *   - AVX2   (256-bit SIMD，用于 ChaCha20 并行)
 *
 * GCC/Clang 使用 __builtin_cpu_supports()；MSVC 使用 __cpuidex/_xgetbv。
 */

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace jpssl {

// 内部 CPUID 辅助（仅 MSVC 需要）
#if defined(_MSC_VER) && defined(_M_X64)
namespace detail_cpu {
inline void cpuid(int leaf, int subleaf, int out[4]) {
    __cpuidex(out, leaf, subleaf);
}
inline uint64_t xgetbv0() {
    return _xgetbv(0);
}
/// OS 是否已保存/恢复 XMM+YMM 状态（AVX 可用前提）
inline bool os_avx_supported() {
    int r[4];
    cpuid(1, 0, r);
    if (!(r[2] & (1u << 27))) return false;  // OSXSAVE
    return (xgetbv0() & 0x6) == 0x6;
}
} // namespace detail_cpu
#endif

/// 检查 AES-NI 是否可用
inline bool cpu_has_aesni() {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
    int r[4];
    detail_cpu::cpuid(1, 0, r);
    return (r[2] & (1u << 25)) && (r[2] & (1u << 19));  // AES + SSE4.1
#else
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("sse4.1");
#endif
#else
    return false;
#endif
}

/// 检查 AVX2 是否可用
inline bool cpu_has_avx2() {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
    if (!detail_cpu::os_avx_supported()) return false;
    int r[4];
    detail_cpu::cpuid(7, 0, r);
    return (r[1] & (1u << 5)) != 0;  // AVX2
#else
    return __builtin_cpu_supports("avx2");
#endif
#else
    return false;
#endif
}

/// 检查 PCLMULQDQ 是否可用（用于 GF(2^128) 快速乘法）
inline bool cpu_has_pclmulqdq() {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
    int r[4];
    detail_cpu::cpuid(1, 0, r);
    return (r[2] & (1u << 1)) != 0;  // PCLMULQDQ
#else
    return __builtin_cpu_supports("pclmul");
#endif
#else
    return false;
#endif
}

/// 检查 AVX512F + AVX512VL 是否可用
inline bool cpu_has_avx512() {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
    if (!detail_cpu::os_avx_supported()) return false;
    int r[4];
    detail_cpu::cpuid(7, 0, r);
    return (r[1] & ((1u << 16) | (1u << 31))) == ((1u << 16) | (1u << 31));  // AVX512F + AVX512VL
#else
    return __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512vl");
#endif
#else
    return false;
#endif
}

/// 检查 VAES + VPCLMULQDQ 是否可用（AVX2/AVX512 向量化 AES/CLMUL）
inline bool cpu_has_vpclmulqdq_vaes() {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
    int r[4];
    detail_cpu::cpuid(7, 0, r);
    return (r[2] & ((1u << 9) | (1u << 10))) == ((1u << 9) | (1u << 10));  // VAES + VPCLMULQDQ
#else
    return __builtin_cpu_supports("vpclmulqdq") && __builtin_cpu_supports("vaes");
#endif
#else
    return false;
#endif
}

/// 检查 ADX (ADCX/ADOX/MULX) 是否可用
inline bool cpu_has_adx() {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
    int r[4];
    detail_cpu::cpuid(7, 0, r);
    return (r[1] & (1u << 19)) != 0;  // ADX
#else
    return __builtin_cpu_supports("adx");
#endif
#else
    return false;
#endif
}

/// 检查 SHA-NI (Intel SHA Extensions) 是否可用
inline bool cpu_has_sha_ni() {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
    int r[4];
    detail_cpu::cpuid(7, 0, r);
    return (r[1] & (1u << 29)) != 0;  // SHA-NI
#else
    return __builtin_cpu_supports("sha");
#endif
#else
    return false;
#endif
}

/// 一次性获取所有特性
struct cpu_features {
    bool aesni;
    bool avx2;
    bool pclmulqdq;
    bool avx512;
    bool vpclmulqdq_vaes;
    bool sha_ni;

    static cpu_features detect() {
        return {
            cpu_has_aesni(),
            cpu_has_avx2(),
            cpu_has_pclmulqdq(),
            cpu_has_avx512(),
            cpu_has_vpclmulqdq_vaes(),
            cpu_has_sha_ni()
        };
    }
};

} // namespace jpssl
