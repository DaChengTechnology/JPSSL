/**
 * sm4_avx2.cpp — AVX2 加速 SM4 块加密
 *
 * 使用 AVX2 (256-bit YMM) 并行处理 8 个 128-bit 块。
 * S-Box 使用预计算查找表 + 标量提取/插入。
 * L 变换使用 SIMD 旋转和 XOR。
 *
 * 用于 CTR/GCM 模式的批量 keystream 生成。
 */
#include "sm4.hpp"
#include "cpu_features.hpp"
#include <cstring>

#ifdef __x86_64__
#include <immintrin.h>
#endif

namespace jpssl {
namespace {

#if defined(__x86_64__) && defined(JP_AVX2)

// SM4 S-Box (256 bytes)
static const uint8_t SM4_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// ── SIMD helper: apply S-box to 8 independent 32-bit words ──────────────

static inline __m256i avx2_sm4_tau(__m256i x) {
    // Extract 8 uint32 lanes, apply S-box bytewise, recombine
    alignas(32) uint32_t words[8];
    _mm256_store_si256((__m256i*)words, x);
    for (int i = 0; i < 8; ++i) {
        uint32_t w = words[i];
        words[i] = ((uint32_t)SM4_SBOX[(w >> 24) & 0xFF] << 24)
                 | ((uint32_t)SM4_SBOX[(w >> 16) & 0xFF] << 16)
                 | ((uint32_t)SM4_SBOX[(w >>  8) & 0xFF] <<  8)
                 |  (uint32_t)SM4_SBOX[ w        & 0xFF];
    }
    return _mm256_load_si256((const __m256i*)words);
}

// ── SIMD L transform: L(B) = B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24) ──

static inline __m256i avx2_sm4_L(__m256i b) {
    // ROTL 2, 10, 18, 24 using _mm256_slli_epi32 + _mm256_srli_epi32 + OR
    auto rot = [](__m256i x, int n) -> __m256i {
        return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
    };
    __m256i t = _mm256_xor_si256(b, rot(b, 2));
    t = _mm256_xor_si256(t, rot(b, 10));
    t = _mm256_xor_si256(t, rot(b, 18));
    return _mm256_xor_si256(t, rot(b, 24));
}

// ── L' transform (key expansion): L'(B) = B ⊕ (B<<<13) ⊕ (B<<<23) ──────

static inline __m256i avx2_sm4_Lp(__m256i b) {
    auto rot = [](__m256i x, int n) -> __m256i {
        return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
    };
    __m256i t = _mm256_xor_si256(b, rot(b, 13));
    return _mm256_xor_si256(t, rot(b, 23));
}

// ── Round function F on 8 blocks ────────────────────────────────────────

// Input: X0..X3 are 8-element vectors (each lane is one block's state word)
// rk is broadcast to all 8 lanes
static inline __m256i avx2_sm4_F(__m256i x0, __m256i x1, __m256i x2, __m256i x3, __m256i rk) {
    __m256i t = _mm256_xor_si256(x1, x2);
    t = _mm256_xor_si256(t, x3);
    t = _mm256_xor_si256(t, rk);
    t = avx2_sm4_tau(t);
    t = avx2_sm4_L(t);
    return _mm256_xor_si256(x0, t);
}

// ── 8-way SM4 block encryption (one round key set, 8 blocks) ────────────

/// Encrypt 8 blocks (16 bytes each) in parallel.
/// round_keys: 32 round keys (scalar, for key expansion)
/// plain: 128 bytes (8 * 16), cipher: 128 bytes (output)
static void sm4_encrypt_8blocks_avx2(const uint32_t rk[32],
                                      const uint8_t* plain,
                                      uint8_t* cipher) {
    // Load 8 blocks: each block is 4 x uint32 (big-endian)
    // We de-interleave: X0 gets all blocks' word 0, X1 gets word 1, etc.
    alignas(32) uint32_t buf[32]; // 8 blocks * 4 words
    for (int blk = 0; blk < 8; ++blk) {
        const uint8_t* p = plain + blk * 16;
        buf[blk]      = ((uint32_t)p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
        buf[blk + 8]  = ((uint32_t)p[4]<<24)|(p[5]<<16)|(p[6]<<8)|p[7];
        buf[blk + 16] = ((uint32_t)p[8]<<24)|(p[9]<<16)|(p[10]<<8)|p[11];
        buf[blk + 24] = ((uint32_t)p[12]<<24)|(p[13]<<16)|(p[14]<<8)|p[15];
    }
    __m256i x0 = _mm256_load_si256((const __m256i*)(buf));
    __m256i x1 = _mm256_load_si256((const __m256i*)(buf + 8));
    __m256i x2 = _mm256_load_si256((const __m256i*)(buf + 16));
    __m256i x3 = _mm256_load_si256((const __m256i*)(buf + 24));

    // 32 rounds
    for (int r = 0; r < 32; ++r) {
        __m256i rkv = _mm256_set1_epi32((int)rk[r]);
        __m256i x4 = avx2_sm4_F(x0, x1, x2, x3, rkv);
        x0 = x1; x1 = x2; x2 = x3; x3 = x4;
    }

    // Output in reverse order: X35, X34, X33, X32
    _mm256_store_si256((__m256i*)(buf),      x3);
    _mm256_store_si256((__m256i*)(buf + 8),  x2);
    _mm256_store_si256((__m256i*)(buf + 16), x1);
    _mm256_store_si256((__m256i*)(buf + 24), x0);

    // Store big-endian
    for (int blk = 0; blk < 8; ++blk) {
        uint8_t* c = cipher + blk * 16;
        uint32_t w0 = buf[blk], w1 = buf[blk+8], w2 = buf[blk+16], w3 = buf[blk+24];
        c[0]=w0>>24;c[1]=w0>>16;c[2]=w0>>8;c[3]=w0;
        c[4]=w1>>24;c[5]=w1>>16;c[6]=w1>>8;c[7]=w1;
        c[8]=w2>>24;c[9]=w2>>16;c[10]=w2>>8;c[11]=w2;
        c[12]=w3>>24;c[13]=w3>>16;c[14]=w3>>8;c[15]=w3;
    }
}

// ── CTR 模式 (8-way parallel) ───────────────────────────────────────────

static void sm4_ctr_avx2(const sm4_ctx* ctx,
                         const uint8_t* ctr_block,
                         const uint8_t* input, uint8_t* output, size_t len) {
    uint8_t counters[128]; // 8 blocks * 16 bytes
    uint8_t keystream[128];

    // Initialize 8 consecutive counter values
    uint8_t base_ctr[16];
    std::memcpy(base_ctr, ctr_block, 16);
    for (int i = 0; i < 8; ++i) {
        std::memcpy(counters + i * 16, base_ctr, 16);
        // Increment counter by i (big-endian)
        uint32_t carry = i;
        for (int j = 15; j >= 12 && carry; --j) {
            uint32_t v = counters[i*16 + j] + carry;
            counters[i*16 + j] = (uint8_t)v;
            carry = v >> 8;
        }
    }

    size_t pos = 0;
    while (pos + 128 <= len) {
        sm4_encrypt_8blocks_avx2(ctx->rk, counters, keystream);
        for (int i = 0; i < 128; ++i)
            output[pos + i] = input[pos + i] ^ keystream[i];
        pos += 128;
        // Increment all 8 counters by 8 (big-endian add)
        uint32_t carry = 8;
        for (int j = 15; j >= 12 && carry; --j) {
            uint32_t v = counters[j] + carry;
            counters[j] = (uint8_t)v;
            carry = v >> 8;
        }
    }

    // Remaining: fall back to scalar
    if (pos < len) {
        sm4_ctr_xor_scalar(ctx, ctr_block, input + pos, output + pos, len - pos, pos);
    }
}

#endif // __x86_64__ && JP_AVX2

} // anonymous namespace
} // namespace jpssl
