/**
 * chacha20_avx512.cpp — ChaCha20 AVX512 加速（16 路并行）
 *
 * 策略：transposed 布局，一次处理 16 个独立块。
 *   ZMM[j] 的 lane i = 第 i 个块的第 j 个字（32-bit）
 *   16 个 ZMM 寄存器对应 16 个状态字位置
 *
 * 旋转：VPROLD 单指令（AVX512F），比 AVX2 的组合移位更快
 *
 * 编译：-mavx512f
 */
#include "chacha20_poly1305.hpp"
#include <immintrin.h>
#include <cstdint>
#include <cstring>
#include "jpssl_span.hpp"

namespace jpssl {

/// 4 路 quarter round（向量化）
static inline void qr_avx512(__m512i& a, __m512i& b, __m512i& c, __m512i& d) {
    a = _mm512_add_epi32(a, b); d = _mm512_xor_si512(d, a); d = _mm512_rol_epi32(d, 16);
    c = _mm512_add_epi32(c, d); b = _mm512_xor_si512(b, c); b = _mm512_rol_epi32(b, 12);
    a = _mm512_add_epi32(a, b); d = _mm512_xor_si512(d, a); d = _mm512_rol_epi32(d, 8);
    c = _mm512_add_epi32(c, d); b = _mm512_xor_si512(b, c); b = _mm512_rol_epi32(b, 7);
}

/// 一次生成 16 个块的 keystream（1024 字节），counter 从 base 起连续
static void chacha20_blocks16(const uint8_t key[32], uint32_t base_counter,
                              const uint8_t nonce[12], uint8_t keystream[1024]) {
    const __m512i C0 = _mm512_set1_epi32(0x61707865);
    const __m512i C1 = _mm512_set1_epi32(0x3320646e);
    const __m512i C2 = _mm512_set1_epi32(0x79622d32);
    const __m512i C3 = _mm512_set1_epi32(0x6b206574);

    __m512i k[8];
    for (int i = 0; i < 8; ++i) {
        uint32_t w; std::memcpy(&w, key + 4*i, 4);
        k[i] = _mm512_set1_epi32((int)w);
    }

    // counter：16 个连续值（base .. base+15）
    alignas(64) int ctr[16];
    for (int i = 0; i < 16; ++i) ctr[i] = (int)(base_counter + i);
    const __m512i CTR = _mm512_load_si512((const void*)ctr);

    __m512i n[3];
    for (int i = 0; i < 3; ++i) {
        uint32_t w; std::memcpy(&w, nonce + 4*i, 4);
        n[i] = _mm512_set1_epi32((int)w);
    }

    __m512i s0=C0,s1=C1,s2=C2,s3=C3;
    __m512i s4=k[0],s5=k[1],s6=k[2],s7=k[3];
    __m512i s8=k[4],s9=k[5],s10=k[6],s11=k[7];
    __m512i s12=CTR,s13=n[0],s14=n[1],s15=n[2];

    __m512i i0=s0,i1=s1,i2=s2,i3=s3,i4=s4,i5=s5,i6=s6,i7=s7;
    __m512i i8=s8,i9=s9,i10=s10,i11=s11,i12=s12,i13=s13,i14=s14,i15=s15;

    for (int r = 0; r < 10; ++r) {
        qr_avx512(s0,s4,s8,s12);
        qr_avx512(s1,s5,s9,s13);
        qr_avx512(s2,s6,s10,s14);
        qr_avx512(s3,s7,s11,s15);
        qr_avx512(s0,s5,s10,s15);
        qr_avx512(s1,s6,s11,s12);
        qr_avx512(s2,s7,s8,s13);
        qr_avx512(s3,s4,s9,s14);
    }

    s0=_mm512_add_epi32(s0,i0); s1=_mm512_add_epi32(s1,i1);
    s2=_mm512_add_epi32(s2,i2); s3=_mm512_add_epi32(s3,i3);
    s4=_mm512_add_epi32(s4,i4); s5=_mm512_add_epi32(s5,i5);
    s6=_mm512_add_epi32(s6,i6); s7=_mm512_add_epi32(s7,i7);
    s8=_mm512_add_epi32(s8,i8); s9=_mm512_add_epi32(s9,i9);
    s10=_mm512_add_epi32(s10,i10); s11=_mm512_add_epi32(s11,i11);
    s12=_mm512_add_epi32(s12,i12); s13=_mm512_add_epi32(s13,i13);
    s14=_mm512_add_epi32(s14,i14); s15=_mm512_add_epi32(s15,i15);

    // 转置写回：ZMM[j] lane i → 块 i 的字 j
    alignas(64) uint32_t tmp[16][16];
    _mm512_store_si512((void*)tmp[0], s0);
    _mm512_store_si512((void*)tmp[1], s1);
    _mm512_store_si512((void*)tmp[2], s2);
    _mm512_store_si512((void*)tmp[3], s3);
    _mm512_store_si512((void*)tmp[4], s4);
    _mm512_store_si512((void*)tmp[5], s5);
    _mm512_store_si512((void*)tmp[6], s6);
    _mm512_store_si512((void*)tmp[7], s7);
    _mm512_store_si512((void*)tmp[8], s8);
    _mm512_store_si512((void*)tmp[9], s9);
    _mm512_store_si512((void*)tmp[10], s10);
    _mm512_store_si512((void*)tmp[11], s11);
    _mm512_store_si512((void*)tmp[12], s12);
    _mm512_store_si512((void*)tmp[13], s13);
    _mm512_store_si512((void*)tmp[14], s14);
    _mm512_store_si512((void*)tmp[15], s15);

    for (int blk = 0; blk < 16; ++blk) {
        uint8_t* ks = keystream + 64*blk;
        for (int j = 0; j < 16; ++j)
            std::memcpy(ks + 4*j, &tmp[j][blk], 4);
    }
}

/// AVX512 流加密入口
void chacha20_crypt_avx512(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12],
                           jpssl::span<const uint8_t> input,
                           jpssl::span<uint8_t> output) {
    uint8_t keystream[1024];
    size_t pos = 0;

    while (pos + 1024 <= input.size()) {
        chacha20_blocks16(key, counter, nonce, keystream);
        const uint8_t* in = input.data() + pos;
        uint8_t* out = output.data() + pos;
        for (int b = 0; b < 16; ++b) {
            __m512i k = _mm512_loadu_si512((const void*)(keystream + 64 * b));
            __m512i v = _mm512_loadu_si512((const void*)(in + 64 * b));
            _mm512_storeu_si512((void*)(out + 64 * b), _mm512_xor_si512(v, k));
        }
        counter += 16;
        pos += 1024;
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
