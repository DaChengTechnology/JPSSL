/**
 * chacha20_avx2.cpp — ChaCha20 AVX2 加速（8 路并行）
 *
 * 策略：transposed 布局，一次处理 8 个独立块。
 *   YMM[j] 的 lane i = 第 i 个块的第 j 个字（32-bit）
 *   16 个 YMM 寄存器对应 16 个状态字位置
 *   quarter round 对 4 个 YMM 做向量加减/异或/旋转
 *
 * 旋转（AVX2 无 VPROLD）：VPSLLD + VPSRLD + VPOR 组合
 *
 * 编译：-mavx2
 */
#include "chacha20_poly1305.hpp"
#include <immintrin.h>
#include <cstdint>
#include <cstring>
#include "jpssl_span.hpp"

namespace jpssl {

static inline __m256i rotl_epi32(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n),
                           _mm256_srli_epi32(x, 32 - n));
}

/// 4 路 quarter round（向量化）
static inline void qr_avx2(__m256i& a, __m256i& b, __m256i& c, __m256i& d) {
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = rotl_epi32(d, 16);
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = rotl_epi32(b, 12);
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = rotl_epi32(d, 8);
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = rotl_epi32(b, 7);
}

/// 一次生成 8 个块的 keystream（512 字节），counter 从 base 起连续
static void chacha20_blocks8_xor(const uint8_t key[32], uint32_t base_counter,
                                 const uint8_t nonce[12],
                                 const uint8_t* in, uint8_t* out) {
    // 常量 "expand 32-byte k"
    const __m256i C0 = _mm256_set1_epi32(0x61707865);
    const __m256i C1 = _mm256_set1_epi32(0x3320646e);
    const __m256i C2 = _mm256_set1_epi32(0x79622d32);
    const __m256i C3 = _mm256_set1_epi32(0x6b206574);

    // key：8 个字，每 lane 相同
    __m256i k[8];
    for (int i = 0; i < 8; ++i) {
        uint32_t w;
        std::memcpy(&w, key + 4*i, 4);
        k[i] = _mm256_set1_epi32((int)w);
    }

    // counter：8 个连续值（base .. base+7）
    const __m256i CTR = _mm256_set_epi32((int)(base_counter+7),(int)(base_counter+6),
                                         (int)(base_counter+5),(int)(base_counter+4),
                                         (int)(base_counter+3),(int)(base_counter+2),
                                         (int)(base_counter+1),(int)(base_counter+0));

    // nonce：3 个字，每 lane 相同
    __m256i n[3];
    for (int i = 0; i < 3; ++i) {
        uint32_t w;
        std::memcpy(&w, nonce + 4*i, 4);
        n[i] = _mm256_set1_epi32((int)w);
    }

    // 初始状态（16 个 YMM）
    __m256i s0=C0, s1=C1, s2=C2, s3=C3;
    __m256i s4=k[0], s5=k[1], s6=k[2], s7=k[3];
    __m256i s8=k[4], s9=k[5], s10=k[6], s11=k[7];
    __m256i s12=CTR, s13=n[0], s14=n[1], s15=n[2];

    __m256i i0=s0,i1=s1,i2=s2,i3=s3,i4=s4,i5=s5,i6=s6,i7=s7;
    __m256i i8=s8,i9=s9,i10=s10,i11=s11,i12=s12,i13=s13,i14=s14,i15=s15;

    // 10 轮 double round
    for (int r = 0; r < 10; ++r) {
        // column round
        qr_avx2(s0,s4,s8,s12);
        qr_avx2(s1,s5,s9,s13);
        qr_avx2(s2,s6,s10,s14);
        qr_avx2(s3,s7,s11,s15);
        // diagonal round
        qr_avx2(s0,s5,s10,s15);
        qr_avx2(s1,s6,s11,s12);
        qr_avx2(s2,s7,s8,s13);
        qr_avx2(s3,s4,s9,s14);
    }

    // 加初始状态
    s0=_mm256_add_epi32(s0,i0); s1=_mm256_add_epi32(s1,i1);
    s2=_mm256_add_epi32(s2,i2); s3=_mm256_add_epi32(s3,i3);
    s4=_mm256_add_epi32(s4,i4); s5=_mm256_add_epi32(s5,i5);
    s6=_mm256_add_epi32(s6,i6); s7=_mm256_add_epi32(s7,i7);
    s8=_mm256_add_epi32(s8,i8); s9=_mm256_add_epi32(s9,i9);
    s10=_mm256_add_epi32(s10,i10); s11=_mm256_add_epi32(s11,i11);
    s12=_mm256_add_epi32(s12,i12); s13=_mm256_add_epi32(s13,i13);
    s14=_mm256_add_epi32(s14,i14); s15=_mm256_add_epi32(s15,i15);

    // ── 寄存器内 8×8 转置（OpenSSL 风格，无 tmp 栈数组） ──
    // 前半字（s0..s7）转置 → 每块前 32B；后半字（s8..s15）转置 → 每块后 32B
    __m256i a0=s0,a1=s1,a2=s2,a3=s3,a4=s4,a5=s5,a6=s6,a7=s7;
    __m256i b0=s8,b1=s9,b2=s10,b3=s11,b4=s12,b5=s13,b6=s14,b7=s15;

    // 阶段1: 32-bit 交错
    __m256i t0=_mm256_unpacklo_epi32(a0,a1), t1=_mm256_unpackhi_epi32(a0,a1);
    __m256i t2=_mm256_unpacklo_epi32(a2,a3), t3=_mm256_unpackhi_epi32(a2,a3);
    __m256i t4=_mm256_unpacklo_epi32(a4,a5), t5=_mm256_unpackhi_epi32(a4,a5);
    __m256i t6=_mm256_unpacklo_epi32(a6,a7), t7=_mm256_unpackhi_epi32(a6,a7);
    __m256i u0=_mm256_unpacklo_epi32(b0,b1), u1=_mm256_unpackhi_epi32(b0,b1);
    __m256i u2=_mm256_unpacklo_epi32(b2,b3), u3=_mm256_unpackhi_epi32(b2,b3);
    __m256i u4=_mm256_unpacklo_epi32(b4,b5), u5=_mm256_unpackhi_epi32(b4,b5);
    __m256i u6=_mm256_unpacklo_epi32(b6,b7), u7=_mm256_unpackhi_epi32(b6,b7);

    // 阶段2: 64-bit 交错
    a0=_mm256_unpacklo_epi64(t0,t2); a1=_mm256_unpackhi_epi64(t0,t2);
    a2=_mm256_unpacklo_epi64(t1,t3); a3=_mm256_unpackhi_epi64(t1,t3);
    a4=_mm256_unpacklo_epi64(t4,t6); a5=_mm256_unpackhi_epi64(t4,t6);
    a6=_mm256_unpacklo_epi64(t5,t7); a7=_mm256_unpackhi_epi64(t5,t7);
    b0=_mm256_unpacklo_epi64(u0,u2); b1=_mm256_unpackhi_epi64(u0,u2);
    b2=_mm256_unpacklo_epi64(u1,u3); b3=_mm256_unpackhi_epi64(u1,u3);
    b4=_mm256_unpacklo_epi64(u4,u6); b5=_mm256_unpackhi_epi64(u4,u6);
    b6=_mm256_unpacklo_epi64(u5,u7); b7=_mm256_unpackhi_epi64(u5,u7);

    // 阶段3: 128-bit 跨半交换
    t0=_mm256_permute2x128_si256(a0,a4,0x20); t4=_mm256_permute2x128_si256(a0,a4,0x31);
    t1=_mm256_permute2x128_si256(a1,a5,0x20); t5=_mm256_permute2x128_si256(a1,a5,0x31);
    t2=_mm256_permute2x128_si256(a2,a6,0x20); t6=_mm256_permute2x128_si256(a2,a6,0x31);
    t3=_mm256_permute2x128_si256(a3,a7,0x20); t7=_mm256_permute2x128_si256(a3,a7,0x31);
    u0=_mm256_permute2x128_si256(b0,b4,0x20); u4=_mm256_permute2x128_si256(b0,b4,0x31);
    u1=_mm256_permute2x128_si256(b1,b5,0x20); u5=_mm256_permute2x128_si256(b1,b5,0x31);
    u2=_mm256_permute2x128_si256(b2,b6,0x20); u6=_mm256_permute2x128_si256(b2,b6,0x31);
    u3=_mm256_permute2x128_si256(b3,b7,0x20); u7=_mm256_permute2x128_si256(b3,b7,0x31);

    // 现在 t[i] = 块 i 的字 0..7（前 32B），u[i] = 块 i 的字 8..15（后 32B）
    // 直接 XOR 输出到 keystream
    _mm256_storeu_si256((__m256i*)(out +   0), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in +   0)), t0));
    _mm256_storeu_si256((__m256i*)(out +  32), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in +  32)), u0));
    _mm256_storeu_si256((__m256i*)(out +  64), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in +  64)), t1));
    _mm256_storeu_si256((__m256i*)(out +  96), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in +  96)), u1));
    _mm256_storeu_si256((__m256i*)(out + 128), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 128)), t2));
    _mm256_storeu_si256((__m256i*)(out + 160), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 160)), u2));
    _mm256_storeu_si256((__m256i*)(out + 192), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 192)), t3));
    _mm256_storeu_si256((__m256i*)(out + 224), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 224)), u3));
    _mm256_storeu_si256((__m256i*)(out + 256), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 256)), t4));
    _mm256_storeu_si256((__m256i*)(out + 288), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 288)), u4));
    _mm256_storeu_si256((__m256i*)(out + 320), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 320)), t5));
    _mm256_storeu_si256((__m256i*)(out + 352), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 352)), u5));
    _mm256_storeu_si256((__m256i*)(out + 384), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 384)), t6));
    _mm256_storeu_si256((__m256i*)(out + 416), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 416)), u6));
    _mm256_storeu_si256((__m256i*)(out + 448), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 448)), t7));
    _mm256_storeu_si256((__m256i*)(out + 480), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(in + 480)), u7));
}

/// AVX2 流加密入口
void chacha20_crypt_avx2(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12],
                         jpssl::span<const uint8_t> input,
                         jpssl::span<uint8_t> output) {
    size_t pos = 0;

    // 主循环：每次 512 字节（8 块）
    while (pos + 512 <= input.size()) {
        chacha20_blocks8_xor(key, counter, nonce,
                             input.data() + pos, output.data() + pos);
        counter += 8;
        pos += 512;
    }
    // 剩余：逐块标量
    while (pos < input.size()) {
        uint8_t block[64];
        chacha20_block(key, counter, nonce, block);
        ++counter;
        size_t chunk = std::min<size_t>(64, input.size() - pos);
        for (size_t i = 0; i < chunk; ++i)
            output[pos + i] = input[pos + i] ^ block[i];
        pos += chunk;
    }
}

} // namespace jpssl
