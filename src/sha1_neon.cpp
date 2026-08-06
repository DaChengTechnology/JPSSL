/**
 * sha1_neon.cpp — ARMv8 SHA-1 硬件加速单块变换
 *
 * 使用 ARMv8 Crypto 扩展（FEAT_SHA1，ARMv8.0 可选扩展）：
 *   - SHA1C / SHA1P / SHA1M：20/20/20 轮的压缩函数（choose/parity/majority）
 *   - SHA1H：E = ROL(A, 30) 固定旋转
 *   - SHA1SU0 / SHA1SU1：消息调度扩展
 *
 * 移植自 OpenSSL sha1-armv8.pl（sha1_block_armv8）与 Jeffrey Walton 的
 * sha1-arm.c（公共领域，源自 ARM / mbedTLS）。逐块调用，语义与标量
 * sha1_transform 完全一致：对 h[5] 原地做一次 64 字节块压缩。
 *
 * 编译：-march=armv8-a+crypto 及以上（Apple Silicon 默认支持）。
 * 运行时由 cpu_features 检测 FEAT_SHA1 后分派。
 */

#include "sha1.hpp"

#if defined(__aarch64__) && defined(JP_NEON) && \
    (defined(__ARM_FEATURE_SHA2) || defined(__ARM_FEATURE_CRYPTO))
#include <arm_neon.h>

namespace jpssl {

void sha1_transform_neon(uint32_t h[5], const uint8_t data[64]) {
    // ABCD = {A, B, C, D}（lane 0 = A），E 单独存放（与 OpenSSL sha1_block_armv8 布局一致）
    uint32x4_t ABCD = vld1q_u32(h);
    uint32_t E0 = h[4];
    const uint32x4_t ABCD_SAVED = ABCD;
    const uint32_t E0_SAVED = E0;

    // 消息字按大端读入（rev32 相当于 4 字节交换）
    uint32x4_t MSG0 = vreinterpretq_u32_u8(
        vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(reinterpret_cast<const uint32_t*>(data)))));
    uint32x4_t MSG1 = vreinterpretq_u32_u8(
        vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(reinterpret_cast<const uint32_t*>(data + 16)))));
    uint32x4_t MSG2 = vreinterpretq_u32_u8(
        vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(reinterpret_cast<const uint32_t*>(data + 32)))));
    uint32x4_t MSG3 = vreinterpretq_u32_u8(
        vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(reinterpret_cast<const uint32_t*>(data + 48)))));

    uint32x4_t TMP0 = vaddq_u32(MSG0, vdupq_n_u32(0x5A827999));
    uint32x4_t TMP1 = vaddq_u32(MSG1, vdupq_n_u32(0x5A827999));

    /* Rounds 0-3 */
    uint32_t E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1cq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32(0x5A827999));
    MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

    /* Rounds 4-7 */
    E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1cq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG3, vdupq_n_u32(0x5A827999));
    MSG0 = vsha1su1q_u32(MSG0, MSG3);
    MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

    /* Rounds 8-11 */
    E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1cq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG0, vdupq_n_u32(0x5A827999));
    MSG1 = vsha1su1q_u32(MSG1, MSG0);
    MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

    /* Rounds 12-15 */
    E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1cq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG1, vdupq_n_u32(0x6ED9EBA1));
    MSG2 = vsha1su1q_u32(MSG2, MSG1);
    MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

    /* Rounds 16-19 */
    E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1cq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32(0x6ED9EBA1));
    MSG3 = vsha1su1q_u32(MSG3, MSG2);
    MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

    /* Rounds 20-23 */
    E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG3, vdupq_n_u32(0x6ED9EBA1));
    MSG0 = vsha1su1q_u32(MSG0, MSG3);
    MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

    /* Rounds 24-27 */
    E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG0, vdupq_n_u32(0x6ED9EBA1));
    MSG1 = vsha1su1q_u32(MSG1, MSG0);
    MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

    /* Rounds 28-31 */
    E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG1, vdupq_n_u32(0x6ED9EBA1));
    MSG2 = vsha1su1q_u32(MSG2, MSG1);
    MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

    /* Rounds 32-35 */
    E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32(0x8F1BBCDC));
    MSG3 = vsha1su1q_u32(MSG3, MSG2);
    MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

    /* Rounds 36-39 */
    E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG3, vdupq_n_u32(0x8F1BBCDC));
    MSG0 = vsha1su1q_u32(MSG0, MSG3);
    MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

    /* Rounds 40-43 */
    E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1mq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG0, vdupq_n_u32(0x8F1BBCDC));
    MSG1 = vsha1su1q_u32(MSG1, MSG0);
    MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

    /* Rounds 44-47 */
    E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1mq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG1, vdupq_n_u32(0x8F1BBCDC));
    MSG2 = vsha1su1q_u32(MSG2, MSG1);
    MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

    /* Rounds 48-51 */
    E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1mq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32(0x8F1BBCDC));
    MSG3 = vsha1su1q_u32(MSG3, MSG2);
    MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

    /* Rounds 52-55 */
    E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1mq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG3, vdupq_n_u32(0xCA62C1D6));
    MSG0 = vsha1su1q_u32(MSG0, MSG3);
    MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

    /* Rounds 56-59 */
    E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1mq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG0, vdupq_n_u32(0xCA62C1D6));
    MSG1 = vsha1su1q_u32(MSG1, MSG0);
    MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

    /* Rounds 60-63 */
    E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG1, vdupq_n_u32(0xCA62C1D6));
    MSG2 = vsha1su1q_u32(MSG2, MSG1);
    MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

    /* Rounds 64-67 */
    E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32(0xCA62C1D6));
    MSG3 = vsha1su1q_u32(MSG3, MSG2);
    MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

    /* Rounds 68-71 */
    E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG3, vdupq_n_u32(0xCA62C1D6));
    MSG0 = vsha1su1q_u32(MSG0, MSG3);

    /* Rounds 72-75 */
    E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E0, TMP0);

    /* Rounds 76-79 */
    E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);

    /* 累加进初始状态 */
    E0 += E0_SAVED;
    ABCD = vaddq_u32(ABCD_SAVED, ABCD);

    vst1q_u32(h, ABCD);
    h[4] = E0;
}

} // namespace jpssl
#endif // __aarch64__ && JP_NEON && (SHA2 || CRYPTO)
