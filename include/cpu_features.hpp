#pragma once

/**
 * cpu_features.hpp — 运行时 CPU 特性检测 + 分派
 *
 * 检测：
 *   - AES-NI (Intel/AMD AES 硬件加速)
 *   - AVX2   (256-bit SIMD，用于 ChaCha20 并行)
 *
 * 使用 GCC/Clang __builtin_cpu_supports() 在运行时检测。
 */

namespace jpssl {

/// 检查 AES-NI 是否可用
inline bool cpu_has_aesni() {
#ifdef __x86_64__
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("sse4.1");
#else
    return false;
#endif
}

/// 检查 AVX2 是否可用
inline bool cpu_has_avx2() {
#ifdef __x86_64__
    return __builtin_cpu_supports("avx2");
#else
    return false;
#endif
}

/// 检查 PCLMULQDQ 是否可用（用于 GF(2^128) 快速乘法）
inline bool cpu_has_pclmulqdq() {
#ifdef __x86_64__
    return __builtin_cpu_supports("pclmul");
#else
    return false;
#endif
}

/// 检查 AVX512F + AVX512VL 是否可用
inline bool cpu_has_avx512() {
#ifdef __x86_64__
    return __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512vl");
#else
    return false;
#endif
}

/// 检查 VAES + VPCLMULQDQ 是否可用（AVX2/AVX512 向量化 AES/CLMUL）
inline bool cpu_has_vpclmulqdq_vaes() {
#ifdef __x86_64__
    return __builtin_cpu_supports("vpclmulqdq") && __builtin_cpu_supports("vaes");
#else
    return false;
#endif
}

/// 检查 ADX (ADCX/ADOX/MULX) 是否可用
inline bool cpu_has_adx() {
#ifdef __x86_64__
    return __builtin_cpu_supports("adx");
#else
    return false;
#endif
}

/// 检查 SHA-NI (Intel SHA Extensions) 是否可用
inline bool cpu_has_sha_ni() {
#ifdef __x86_64__
    return __builtin_cpu_supports("sha");
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