/**
 * chacha20_neon.cpp — ChaCha20 ARM NEON 加速（4 块并行）
 *
 * 与 chacha20_avx2.cpp 相同的 transposed 布局：lane i = 第 i 个块，
 * 16 个 uint32x4_t 向量对应 16 个状态字位置，quarter round 用
 * 向量加/异或/旋转实现。一次处理 4 个 64 字节块。
 *
 * 编译：armv8-a 及以上（NEON 为 ARMv8 必选扩展）。
 */

#include "chacha20_poly1305.hpp"

#if defined(__aarch64__) && defined(JP_NEON)
#include <arm_neon.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include "jpssl_span.hpp"

namespace jpssl {

namespace {

// NEON vshlq_n_u32/vshrq_n_u32 要求移位量为编译期常量，故按角度显式展开
static inline uint32x4_t rotl16(uint32x4_t x) { return vorrq_u32(vshlq_n_u32(x, 16), vshrq_n_u32(x, 16)); }
static inline uint32x4_t rotl12(uint32x4_t x) { return vorrq_u32(vshlq_n_u32(x, 12), vshrq_n_u32(x, 20)); }
static inline uint32x4_t rotl8 (uint32x4_t x) { return vorrq_u32(vshlq_n_u32(x,  8), vshrq_n_u32(x, 24)); }
static inline uint32x4_t rotl7 (uint32x4_t x) { return vorrq_u32(vshlq_n_u32(x,  7), vshrq_n_u32(x, 25)); }

static inline void qr_neon(uint32x4_t& a, uint32x4_t& b,
                           uint32x4_t& c, uint32x4_t& d) {
    a = vaddq_u32(a, b); d = veorq_u32(d, a); d = rotl16(d);
    c = vaddq_u32(c, d); b = veorq_u32(b, c); b = rotl12(b);
    a = vaddq_u32(a, b); d = veorq_u32(d, a); d = rotl8(d);
    c = vaddq_u32(c, d); b = veorq_u32(b, c); b = rotl7(b);
}

/// 一次生成 4 个 keystream 块（256 字节），counter 为第 0 块的计数器
static void chacha20_4blocks(const uint8_t key[32], uint32_t counter,
                             const uint8_t nonce[12], uint8_t out[256]) {
    uint32_t k[8];
    std::memcpy(k, key, 32);
    uint32_t n[3];
    std::memcpy(n, nonce, 12);
    uint32_t ctrs[4] = {counter, counter + 1, counter + 2, counter + 3};

    uint32x4_t s[16];
    s[0] = vdupq_n_u32(0x61707865);
    s[1] = vdupq_n_u32(0x3320646e);
    s[2] = vdupq_n_u32(0x79622d32);
    s[3] = vdupq_n_u32(0x6b206574);
    for (int i = 0; i < 8; ++i) s[4 + i] = vdupq_n_u32(k[i]);
    s[12] = vld1q_u32(ctrs);
    s[13] = vdupq_n_u32(n[0]);
    s[14] = vdupq_n_u32(n[1]);
    s[15] = vdupq_n_u32(n[2]);

    uint32x4_t init[16];
    std::memcpy(init, s, sizeof(s));

    for (int i = 0; i < 10; ++i) {
        qr_neon(s[0], s[ 4], s[ 8], s[12]);
        qr_neon(s[1], s[ 5], s[ 9], s[13]);
        qr_neon(s[2], s[ 6], s[10], s[14]);
        qr_neon(s[3], s[ 7], s[11], s[15]);
        qr_neon(s[0], s[ 5], s[10], s[15]);
        qr_neon(s[1], s[ 6], s[11], s[12]);
        qr_neon(s[2], s[ 7], s[ 8], s[13]);
        qr_neon(s[3], s[ 4], s[ 9], s[14]);
    }

    for (int i = 0; i < 16; ++i) s[i] = vaddq_u32(s[i], init[i]);

    // 反交织：块 b 的第 i 个状态字 → out[b*64 + i*4 ..]
    uint32_t tmp[4];
    for (int i = 0; i < 16; ++i) {
        vst1q_u32(tmp, s[i]);  // tmp[b] = 块 b 的第 i 字
        for (int b = 0; b < 4; ++b) {
            const uint32_t w = tmp[b];
            uint8_t* p = out + b * 64 + i * 4;
            p[0] = (uint8_t)w;
            p[1] = (uint8_t)(w >> 8);
            p[2] = (uint8_t)(w >> 16);
            p[3] = (uint8_t)(w >> 24);
        }
    }
}

} // namespace

void chacha20_crypt_neon(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12],
                         jpssl::span<const uint8_t> input,
                         jpssl::span<uint8_t> output) {
    size_t pos = 0;
    while (input.size() - pos >= 256) {
        uint8_t ks[256];
        chacha20_4blocks(key, counter, nonce, ks);
        counter += 4;
        for (size_t i = 0; i < 256; ++i)
            output[pos + i] = input[pos + i] ^ ks[i];
        pos += 256;
    }
    // 尾部不足 256 字节：逐块处理（与标量一致）
    while (pos < input.size()) {
        uint8_t block[64];
        chacha20_block(key, counter, nonce, block);
        ++counter;
        const size_t chunk = std::min<size_t>(64, input.size() - pos);
        for (size_t i = 0; i < chunk; ++i)
            output[pos + i] = input[pos + i] ^ block[i];
        pos += chunk;
    }
}

} // namespace jpssl
#endif // __aarch64__ && JP_NEON
