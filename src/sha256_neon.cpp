/**
 * sha256_neon.cpp — ARMv8 SHA-256 硬件加速实现
 *
 * 使用 ARMv8 Crypto 扩展（FEAT_SHA256，ARMv8.0 可选 / ARMv8.2 常见）：
 *   - vsha256hq_u32 / vsha256h2q_u32：压缩函数（每指令 4 轮）
 *   - 消息调度（w[16..63]）用标量计算（与 sha256.cpp 相同公式），
 *     压缩函数用 NEON 指令，兼顾正确性与可读性。
 *
 * 编译：-march=armv8-a+crypto 及以上（Apple Silicon 默认支持）。
 * 运行时由 cpu_features 检测 FEAT_SHA256 后分派。
 */

#include "sha256.hpp"

#if defined(__aarch64__) && defined(JP_NEON) && defined(__ARM_FEATURE_SHA2)
#include <arm_neon.h>

namespace jpssl {

namespace {

static inline uint32_t ROR32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

} // namespace

/// 处理一个 64 字节块：与 sha256_transform 同接口
void sha256_transform_neon(uint32_t h[8], const uint8_t data[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | data[i * 4 + 3];
    }
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = s1 + w[i - 7] + s0 + w[i - 16];
    }

    uint32x4_t abcd = vld1q_u32(h);
    uint32x4_t efgh = vld1q_u32(h + 4);

    // 每对 vsha256hq/vsha256h2q 处理 4 轮；消息字需先加轮常数 K
    for (int i = 0; i < 16; ++i) {
        uint32x4_t wk = vaddq_u32(vld1q_u32(&w[i * 4]), vld1q_u32(&K[i * 4]));
        uint32x4_t tmp = vsha256hq_u32(abcd, efgh, wk);
        efgh = vsha256h2q_u32(efgh, abcd, wk);
        abcd = tmp;
    }

    vst1q_u32(h, vaddq_u32(abcd, vld1q_u32(h)));
    vst1q_u32(h + 4, vaddq_u32(efgh, vld1q_u32(h + 4)));
}

} // namespace jpssl
#endif // __aarch64__ && JP_NEON && __ARM_FEATURE_SHA2
