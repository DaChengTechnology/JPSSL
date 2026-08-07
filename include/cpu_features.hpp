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

#if defined(__aarch64__) && defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/types.h>
#endif

// OpenHarmony/HarmonyOS 与 Linux 同为 Linux 内核（musl libc），getauxval 可用。
// 部分鸿蒙 sysroot 不提供 <asm/hwcap.h>，此处用 __has_include 容错并手动补齐
// 所需的 HWCAP/HWCAP2 位定义（arm64 Linux UAPI 位值）。
#if defined(__aarch64__) && (defined(__linux__) || defined(__OHOS_FAMILY__) || defined(__OHOS__))
#include <sys/auxv.h>
#if defined(__has_include)
#if __has_include(<asm/hwcap.h>)
#include <asm/hwcap.h>
#endif
#endif
#ifndef HWCAP_AES
#define HWCAP_AES   (1u << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1u << 4)
#endif
#ifndef HWCAP_SHA1
#define HWCAP_SHA1  (1u << 5)
#endif
#ifndef HWCAP_SHA2
#define HWCAP_SHA2  (1u << 6)
#endif
#ifndef HWCAP_CRC32
#define HWCAP_CRC32 (1u << 7)
#endif
#ifndef HWCAP2_SHA512
#define HWCAP2_SHA512 (1u << 5)
#endif
#ifndef HWCAP2_SHA3
#define HWCAP2_SHA3   (1u << 1)
#endif
#ifndef HWCAP2_SM4
#define HWCAP2_SM4    (1u << 3)
#endif
#ifndef HWCAP2_SM3
#define HWCAP2_SM3    (1u << 2)
#endif
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

/// Checks for AVX512BW (byte-wise shuffle / maddubs, required by the base64 SIMD path).
inline bool cpu_has_avx512bw() {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
    if (!detail_cpu::os_avx_supported()) return false;
    int r[4];
    detail_cpu::cpuid(7, 0, r);
    return (r[1] & (1u << 30)) != 0;  // AVX512BW
#else
    return __builtin_cpu_supports("avx512bw");
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

// ═══════════════════════════════════════════════════════════════════════
//  ARMv8 / ARMv8.1 / ARMv8.2 / ARMv9 特性检测（aarch64）
//
//  macOS（Apple Silicon）: 通过 sysctlbyname("hw.optional.arm.FEAT_*") 查询
//  Linux / OpenHarmony(鸿蒙): getauxval(AT_HWCAP / AT_HWCAP2)（同为 Linux 内核）
//  其他 aarch64 平台:     回退到编译期 __ARM_FEATURE_* 宏（安全，无运行时检测时
//                         不会错误地启用 crypto 代码路径）
// ═══════════════════════════════════════════════════════════════════════

#if defined(__aarch64__) && defined(__APPLE__)
namespace detail_cpu {
inline bool sysctl_feature(const char* name) {
    int v = 0;
    size_t sz = sizeof(v);
    return sysctlbyname(name, &v, &sz, nullptr, 0) == 0 && v != 0;
}
} // namespace detail_cpu
#endif

/// NEON：ARMv8 起为必选扩展
inline bool cpu_has_neon() {
#if defined(__aarch64__) || defined(_M_ARM64)
    return true;
#else
    return false;
#endif
}

/// ARMv8 Crypto：AES 指令（AESE/AESD）
inline bool cpu_has_arm_aes() {
#if defined(__aarch64__) && defined(__APPLE__)
    return detail_cpu::sysctl_feature("hw.optional.arm.FEAT_AES");
#elif defined(__aarch64__) && (defined(__linux__) || defined(__OHOS_FAMILY__) || defined(__OHOS__))
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_AES)
    return true;
#else
    return false;
#endif
#else
    return false;
#endif
}

/// ARMv8 Crypto：PMULL（GF(2^128) 乘，GCM GHASH 硬件加速）
inline bool cpu_has_arm_pmull() {
#if defined(__aarch64__) && defined(__APPLE__)
    return detail_cpu::sysctl_feature("hw.optional.arm.FEAT_PMULL");
#elif defined(__aarch64__) && (defined(__linux__) || defined(__OHOS_FAMILY__) || defined(__OHOS__))
    return (getauxval(AT_HWCAP) & HWCAP_PMULL) != 0;
#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_PMULL)
    return true;
#else
    return false;
#endif
#else
    return false;
#endif
}

/// ARMv8 Crypto：SHA1 指令
inline bool cpu_has_arm_sha1() {
#if defined(__aarch64__) && defined(__APPLE__)
    return detail_cpu::sysctl_feature("hw.optional.arm.FEAT_SHA1");
#elif defined(__aarch64__) && (defined(__linux__) || defined(__OHOS_FAMILY__) || defined(__OHOS__))
    return (getauxval(AT_HWCAP) & HWCAP_SHA1) != 0;
#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_SHA1)
    return true;
#else
    return false;
#endif
#else
    return false;
#endif
}

/// ARMv8 Crypto：SHA-256 指令（ARMv8.0 可选 / ARMv8.2 常见）
inline bool cpu_has_arm_sha2() {
#if defined(__aarch64__) && defined(__APPLE__)
    return detail_cpu::sysctl_feature("hw.optional.arm.FEAT_SHA256");
#elif defined(__aarch64__) && (defined(__linux__) || defined(__OHOS_FAMILY__) || defined(__OHOS__))
    return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_SHA2)
    return true;
#else
    return false;
#endif
#else
    return false;
#endif
}

/// ARMv8.1：CRC32 指令
inline bool cpu_has_arm_crc32() {
#if defined(__aarch64__) && defined(__APPLE__)
    return detail_cpu::sysctl_feature("hw.optional.armv8_crc32");
#elif defined(__aarch64__) && (defined(__linux__) || defined(__OHOS_FAMILY__) || defined(__OHOS__))
    return (getauxval(AT_HWCAP) & HWCAP_CRC32) != 0;
#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_CRC32)
    return true;
#else
    return false;
#endif
#else
    return false;
#endif
}

/// ARMv8.2：SHA-512 指令
inline bool cpu_has_arm_sha512() {
#if defined(__aarch64__) && defined(__APPLE__)
    return detail_cpu::sysctl_feature("hw.optional.arm.FEAT_SHA512");
#elif defined(__aarch64__) && (defined(__linux__) || defined(__OHOS_FAMILY__) || defined(__OHOS__))
#if defined(HWCAP2_SHA512)
    return (getauxval(AT_HWCAP2) & HWCAP2_SHA512) != 0;
#else
    return false;
#endif
#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_SHA512)
    return true;
#else
    return false;
#endif
#else
    return false;
#endif
}

/// ARMv8.2：SHA3 指令
inline bool cpu_has_arm_sha3() {
#if defined(__aarch64__) && defined(__APPLE__)
    return detail_cpu::sysctl_feature("hw.optional.arm.FEAT_SHA3");
#elif defined(__aarch64__) && (defined(__linux__) || defined(__OHOS_FAMILY__) || defined(__OHOS__))
#if defined(HWCAP2_SHA3)
    return (getauxval(AT_HWCAP2) & HWCAP2_SHA3) != 0;
#else
    return false;
#endif
#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_SHA3)
    return true;
#else
    return false;
#endif
#else
    return false;
#endif
}

/// ARMv8.2：SM4 指令
inline bool cpu_has_arm_sm4() {
#if defined(__aarch64__) && defined(__APPLE__)
    return detail_cpu::sysctl_feature("hw.optional.arm.FEAT_SM4");
#elif defined(__aarch64__) && (defined(__linux__) || defined(__OHOS_FAMILY__) || defined(__OHOS__))
#if defined(HWCAP2_SM4)
    return (getauxval(AT_HWCAP2) & HWCAP2_SM4) != 0;
#else
    return false;
#endif
#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_SM4)
    return true;
#else
    return false;
#endif
#else
    return false;
#endif
}

/// ARMv8.2：SM3 指令
inline bool cpu_has_arm_sm3() {
#if defined(__aarch64__) && defined(__APPLE__)
    return detail_cpu::sysctl_feature("hw.optional.arm.FEAT_SM3");
#elif defined(__aarch64__) && (defined(__linux__) || defined(__OHOS_FAMILY__) || defined(__OHOS__))
#if defined(HWCAP2_SM3)
    return (getauxval(AT_HWCAP2) & HWCAP2_SM3) != 0;
#else
    return false;
#endif
#elif defined(__aarch64__)
#if defined(__ARM_FEATURE_SM3)
    return true;
#else
    return false;
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
    // ARMv8/v8.1/v8.2/v9
    bool neon;
    bool arm_aes;
    bool arm_pmull;
    bool arm_sha1;
    bool arm_sha2;
    bool arm_crc32;
    bool arm_sha512;
    bool arm_sha3;
    bool arm_sm4;
    bool arm_sm3;

    static cpu_features detect() {
        return {
            cpu_has_aesni(),
            cpu_has_avx2(),
            cpu_has_pclmulqdq(),
            cpu_has_avx512(),
            cpu_has_vpclmulqdq_vaes(),
            cpu_has_sha_ni(),
            cpu_has_neon(),
            cpu_has_arm_aes(),
            cpu_has_arm_pmull(),
            cpu_has_arm_sha1(),
            cpu_has_arm_sha2(),
            cpu_has_arm_crc32(),
            cpu_has_arm_sha512(),
            cpu_has_arm_sha3(),
            cpu_has_arm_sm4(),
            cpu_has_arm_sm3()
        };
    }
};

} // namespace jpssl
