/**
 * sm4_neon.cpp — ARMv8.2 SM4 硬件加速实现（FEAT_SM4）
 *
 * 使用 ARMv8.2 Crypto 扩展的 SM4 指令：
 *   - vsm4eq_u32     : sm4e（单条指令处理 4 轮）
 *   - vsm4ekeyq_u32  : sm4ekey（密钥扩展，本项目密钥扩展仍用标量 T 表，
 *                      sm4ekey 仅用于与 OpenSSL 约定对拍验证）
 *
 * 块加密序列移植自 OpenSSL sm4-armv8.pl 的 enc_blk：
 *   1. rev32（每 lane 字节交换，大端 -> 小端内存序）
 *   2. 8 × vsm4eq_u32，轮密钥组按内存 uint32 顺序取 rk[4i..4i+3]
 *   3. rev64（lane0<->1、lane2<->3）
 *   4. ext #8（交换 64 位半）
 *   5. rev32
 * 该序列已用标量模拟器与 jpssl 标量实现对拍 100 组随机数据验证。
 *
 * 解密：轮密钥按组反向（每组 4 字整体倒序）后执行同一 enc_blk 序列，
 * 即第 g 次 sm4e 使用 {rk[31-4g], rk[30-4g], rk[29-4g], rk[28-4g]}；
 * 与 OpenSSL set_decrypt_key 的 rev64+ext 约定等价（已模拟验证）。
 *
 * 编译要求：-march=armv8.4-a+crypto 及以上（Apple Clang 下 FEAT_SM4
 * intrinsic 需 armv8.4-a 才定义）。运行时由 cpu_has_arm_sm4() 分派，
 * 不支持 FEAT_SM4 的机器自动回退到标量实现。
 */

#include "sm4.hpp"

#include "cpu_features.hpp"

#if defined(__aarch64__) && defined(JP_NEON) && defined(__ARM_FEATURE_SM4)
#include <arm_neon.h>

namespace jpssl {

/// 加密单个块（NEON）
void sm4_encrypt_block_neon(const uint32_t rk[32], const uint8_t in[16],
                            uint8_t out[16]) {
    uint32x4_t v = vld1q_u32(reinterpret_cast<const uint32_t*>(in));
    // 大端 -> 小端：每 32 位 lane 字节交换
    v = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v)));

    uint32x4_t rkv[8];
    for (int i = 0; i < 8; ++i) rkv[i] = vld1q_u32(&rk[4 * i]);
    for (int i = 0; i < 8; ++i) v = vsm4eq_u32(v, rkv[i]);

    // 输出调整：rev64（交换相邻 32 位 lane）+ ext #8（交换 64 位半）
    v = vreinterpretq_u32_u8(vrev64q_u8(vreinterpretq_u8_u32(v)));
    v = vextq_u32(v, v, 2);
    // 小端 -> 大端
    v = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v)));

    vst1q_u32(reinterpret_cast<uint32_t*>(out), v);
}

/// 解密单个块（NEON）：轮密钥组反向 + 同一 enc_blk 序列
void sm4_decrypt_block_neon(const uint32_t rk[32], const uint8_t in[16],
                            uint8_t out[16]) {
    uint32x4_t v = vld1q_u32(reinterpret_cast<const uint32_t*>(in));
    v = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v)));

    uint32x4_t rkv[8];
    uint32_t g[4];
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 4; ++j) g[j] = rk[31 - (4 * i + j)];
        rkv[i] = vld1q_u32(g);
    }
    for (int i = 0; i < 8; ++i) v = vsm4eq_u32(v, rkv[i]);

    v = vreinterpretq_u32_u8(vrev64q_u8(vreinterpretq_u8_u32(v)));
    v = vextq_u32(v, v, 2);
    v = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v)));

    vst1q_u32(reinterpret_cast<uint32_t*>(out), v);
}

/// 分派指针（定义在 sm4.cpp，默认 nullptr 即标量）
extern void (*sm4_encrypt_fn)(const uint32_t rk[32], const uint8_t[16],
                              uint8_t[16]);
extern void (*sm4_decrypt_fn)(const uint32_t rk[32], const uint8_t[16],
                              uint8_t[16]);

/// 静态初始化：FEAT_SM4 可用时接管加解密分派指针
static bool init_sm4_neon() {
    if (cpu_has_arm_sm4()) {
        sm4_encrypt_fn = sm4_encrypt_block_neon;
        sm4_decrypt_fn = sm4_decrypt_block_neon;
    }
    return true;
}
static const bool _sm4_neon_init = init_sm4_neon();

} // namespace jpssl
#endif // __aarch64__ && JP_NEON && __ARM_FEATURE_SM4
