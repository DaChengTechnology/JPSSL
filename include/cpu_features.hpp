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

/// 一次性获取所有特性
struct cpu_features {
    bool aesni;
    bool avx2;

    static cpu_features detect() {
        return {cpu_has_aesni(), cpu_has_avx2()};
    }
};

} // namespace jpssl
