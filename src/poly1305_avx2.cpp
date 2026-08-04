/**
 * poly1305_avx2.cpp — Poly1305 AVX2 加速（4 块并行，26-bit 肢体）
 *
 * 算法（参考 OpenSSL poly1305-x86_64.pl 的 AVX2 思路，独立实现）：
 *   - 26-bit 肢体，5 肢体 / 16B 块；4 块并行，lane j = 块 j 的同位肢体。
 *   - 预计算 r、r²、r³、r⁴ 的 26-bit 肢体及 5r 折叠系数。
 *   - 每 64B 块组：
 *       h' = (h + m0)·r⁴ + m1·r³ + m2·r² + m3·r   (mod 2^130-5)
 *     其中各块的乘积通过 5×5 卷积 + 折叠一次算完，4 块由 lane 并行。
 *   - 进位链后取 lane0 作为下一轮 h（广播）。
 *
 * 编译：MSVC /arch:AVX2；GCC/Clang -mavx2。
 */
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include "chacha20_poly1305.hpp"

namespace jpssl {
namespace poly_avx2 {

namespace {

constexpr uint64_t M26 = 0x3ffffffULL;
constexpr uint64_t M44 = 0xfffffffffffULL;
constexpr uint64_t M42 = 0x3ffffffffffULL;

#if defined(_MSC_VER)
#define JP_POLY_AVX2_INLINE __forceinline
#else
#define JP_POLY_AVX2_INLINE inline __attribute__((always_inline))
#endif

static inline __m256i v26(uint64_t x) {
    return _mm256_set1_epi64x((long long)x);
}

// lane0 += x（其余 lane 不变）：x = m + (h,0,0,0)
static inline __m256i add_lane0(__m256i v, uint64_t x) {
    return _mm256_add_epi64(v, _mm256_set_epi64x(0, 0, 0, (long long)x));
}

// 26-bit modular multiply: out = a * b mod 2^130-5
static void mul26(const uint64_t a[5], const uint64_t b[5], uint64_t out[5]) {
    uint64_t dv[10] = {0};
    for (int i = 0; i < 5; ++i)
        for (int j = 0; j < 5; ++j) dv[i + j] += a[i] * b[j];
    for (int t = 0; t < 5; ++t) dv[t] += dv[t + 5] * 5;
    uint64_t c;
    c = dv[0] >> 26; dv[0] &= M26; dv[1] += c;
    c = dv[1] >> 26; dv[1] &= M26; dv[2] += c;
    c = dv[2] >> 26; dv[2] &= M26; dv[3] += c;
    c = dv[3] >> 26; dv[3] &= M26; dv[4] += c;
    c = dv[4] >> 26; dv[4] &= M26; dv[0] += c * 5;
    c = dv[0] >> 26; dv[0] &= M26; dv[1] += c;
    c = dv[1] >> 26; dv[1] &= M26; dv[2] += c;
    c = dv[2] >> 26; dv[2] &= M26; dv[3] += c;
    c = dv[3] >> 26; dv[3] &= M26; dv[4] += c;
    c = dv[4] >> 26; dv[4] &= M26; dv[0] += c * 5;
    dv[0] &= M26;
    for (int i = 0; i < 5; ++i) out[i] = dv[i];
}

static void to26(uint64_t r0, uint64_t r1, uint64_t r2, uint64_t out[5]) {
    out[0] = r0 & M26;
    out[1] = ((r0 >> 26) | (r1 << 18)) & M26;
    out[2] = (r1 >> 8) & M26;
    out[3] = ((r1 >> 34) | (r2 << 10)) & M26;
    out[4] = (r2 >> 16) & M26;
}

}  // namespace

void init(State& st, const uint8_t key[32]) {
    uint8_t rb[16];
    std::memcpy(rb, key, 16);
    rb[3] &= 15; rb[7] &= 15; rb[11] &= 15; rb[15] &= 15;
    rb[4] &= 252; rb[8] &= 252; rb[12] &= 252;
    uint64_t rw0, rw1;
    std::memcpy(&rw0, rb, 8);
    std::memcpy(&rw1, rb + 8, 8);
    uint64_t r0 = rw0 & M44;
    uint64_t r1 = ((rw0 >> 44) | (rw1 << 20)) & M44;
    uint64_t r2 = (rw1 >> 24) & M42;
    uint64_t rL[5], powL[4][5];
    to26(r0, r1, r2, rL);
    for (int i = 0; i < 5; ++i) powL[0][i] = rL[i];
    for (int pw = 1; pw < 4; ++pw) mul26(powL[pw - 1], rL, powL[pw]);
    // tbl[b] = coefficients of r^(4-b), placed in lane b (vpmuludq pairs
    // lane b of the message vector with lane b of the coefficient vector).
    uint64_t c[9][4] = {};
    for (int b = 0; b < 4; ++b) {
        const uint64_t* p = powL[3 - b];
        c[0][b] = p[0];
        c[1][b] = p[1];
        c[2][b] = p[2];
        c[3][b] = p[3];
        c[4][b] = p[4];
        c[5][b] = p[1] * 5;
        c[6][b] = p[2] * 5;
        c[7][b] = p[3] * 5;
        c[8][b] = p[4] * 5;
    }
    for (int i = 0; i < 9; ++i)
        for (int b = 0; b < 4; ++b) st.c[i][b] = c[i][b];
    st.h0 = st.h1 = st.h2 = st.h3 = st.h4 = 0;
}

// load 4 message blocks (64B) into limb vectors m0..m4
static void load_blocks(const uint8_t* p, __m256i& m0, __m256i& m1,
                        __m256i& m2, __m256i& m3, __m256i& m4) {
    uint64_t w[8];
    std::memcpy(w, p, 64);
    __m256i lo = _mm256_set_epi64x((long long)w[6], (long long)w[4],
                                   (long long)w[2], (long long)w[0]);
    __m256i hi = _mm256_set_epi64x((long long)w[7], (long long)w[5],
                                   (long long)w[3], (long long)w[1]);
    m0 = _mm256_and_si256(lo, v26(M26));
    m1 = _mm256_and_si256(_mm256_srli_epi64(lo, 26), v26(M26));
    m2 = _mm256_and_si256(
        _mm256_or_si256(_mm256_srli_epi64(lo, 52), _mm256_slli_epi64(hi, 12)),
        v26(M26));
    m3 = _mm256_and_si256(_mm256_srli_epi64(hi, 14), v26(M26));
    m4 = _mm256_or_si256(_mm256_and_si256(_mm256_srli_epi64(hi, 40),
                                          v26(0xffffff)),
                         v26(1u << 24));  // 2^128 pad
}

// process 64 bytes (4 blocks)
static JP_POLY_AVX2_INLINE void feed64(State& st, const uint8_t* p) {
    __m256i m0, m1, m2, m3, m4;
    load_blocks(p, m0, m1, m2, m3, m4);

    // x = m with h added in lane 0 only (lane 0 = block 0's chain)
    __m256i x0 = add_lane0(m0, st.h0);
    __m256i x1 = add_lane0(m1, st.h1);
    __m256i x2 = add_lane0(m2, st.h2);
    __m256i x3 = add_lane0(m3, st.h3);
    __m256i x4 = add_lane0(m4, st.h4);
    // normalize x4 (message limb4 has 2^128 pad; fold overflow as *5)
    __m256i x5 = _mm256_srli_epi64(x4, 26);
    x4 = _mm256_and_si256(x4, v26(M26));
    __m256i f = _mm256_add_epi64(_mm256_slli_epi64(x5, 2), x5);
    x0 = _mm256_add_epi64(x0, f);

    // 5x5 convolution with folded coefficients: d_k = sum_{i+j=k} x_i * r_j
    // (r4 terms folded via 5r; each lane holds its block's coefficient)
    __m256i t0 = _mm256_loadu_si256((const __m256i*)st.c[0]);
    __m256i t1 = _mm256_loadu_si256((const __m256i*)st.c[1]);
    __m256i t2 = _mm256_loadu_si256((const __m256i*)st.c[2]);
    __m256i t3 = _mm256_loadu_si256((const __m256i*)st.c[3]);
    __m256i t4 = _mm256_loadu_si256((const __m256i*)st.c[4]);
    __m256i u1 = _mm256_loadu_si256((const __m256i*)st.c[5]);
    __m256i u2 = _mm256_loadu_si256((const __m256i*)st.c[6]);
    __m256i u3 = _mm256_loadu_si256((const __m256i*)st.c[7]);
    __m256i u4 = _mm256_loadu_si256((const __m256i*)st.c[8]);
    __m256i d0 = _mm256_mul_epu32(x0, t0);
    __m256i d1 = _mm256_mul_epu32(x1, t0);
    __m256i d2 = _mm256_mul_epu32(x2, t0);
    __m256i d3 = _mm256_mul_epu32(x3, t0);
    __m256i d4 = _mm256_mul_epu32(x4, t0);
    d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(x1, u4));
    d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(x2, u4));
    d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(x3, u4));
    d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(x4, u4));
    d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(x2, u3));
    d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(x3, u3));
    d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(x4, u3));
    d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(x3, u2));
    d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(x4, u2));
    d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(x4, u1));
    d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(x0, t1));
    d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(x1, t1));
    d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(x2, t1));
    d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(x3, t1));
    d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(x0, t2));
    d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(x1, t2));
    d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(x2, t2));
    d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(x0, t3));
    d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(x1, t3));
    d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(x0, t4));

    // carry chain (vectorized, all lanes)
    __m256i c;
    c = _mm256_srli_epi64(d0, 26); d0 = _mm256_and_si256(d0, v26(M26));
    d1 = _mm256_add_epi64(d1, c);
    c = _mm256_srli_epi64(d1, 26); d1 = _mm256_and_si256(d1, v26(M26));
    d2 = _mm256_add_epi64(d2, c);
    c = _mm256_srli_epi64(d2, 26); d2 = _mm256_and_si256(d2, v26(M26));
    d3 = _mm256_add_epi64(d3, c);
    c = _mm256_srli_epi64(d3, 26); d3 = _mm256_and_si256(d3, v26(M26));
    d4 = _mm256_add_epi64(d4, c);
    c = _mm256_srli_epi64(d4, 26); d4 = _mm256_and_si256(d4, v26(M26));
    d0 = _mm256_add_epi64(d0, _mm256_add_epi64(_mm256_slli_epi64(c, 2), c));
    c = _mm256_srli_epi64(d0, 26); d0 = _mm256_and_si256(d0, v26(M26));
    d1 = _mm256_add_epi64(d1, c);
    c = _mm256_srli_epi64(d1, 26); d1 = _mm256_and_si256(d1, v26(M26));
    d2 = _mm256_add_epi64(d2, c);
    c = _mm256_srli_epi64(d2, 26); d2 = _mm256_and_si256(d2, v26(M26));
    d3 = _mm256_add_epi64(d3, c);
    c = _mm256_srli_epi64(d3, 26); d3 = _mm256_and_si256(d3, v26(M26));
    d4 = _mm256_add_epi64(d4, c);
    c = _mm256_srli_epi64(d4, 26); d4 = _mm256_and_si256(d4, v26(M26));
    d0 = _mm256_add_epi64(d0, _mm256_add_epi64(_mm256_slli_epi64(c, 2), c));
    d0 = _mm256_and_si256(d0, v26(M26));

    // 4 个 lane = 4 个块的独立贡献，横向求和得到总哈希。
    // 向量化：低 128 与高 128 相加，再 lane0+lane1、lane2+lane3 相加。
    __m256i t = _mm256_permute2x128_si256(d0, d0, 0x81);  // 高128<->低128
    t = _mm256_add_epi64(t, d0);
    uint64_t s0 = (uint64_t)_mm256_extract_epi64(t, 0) +
                  (uint64_t)_mm256_extract_epi64(t, 1);
    t = _mm256_permute2x128_si256(d1, d1, 0x81);
    t = _mm256_add_epi64(t, d1);
    uint64_t s1 = (uint64_t)_mm256_extract_epi64(t, 0) +
                  (uint64_t)_mm256_extract_epi64(t, 1);
    t = _mm256_permute2x128_si256(d2, d2, 0x81);
    t = _mm256_add_epi64(t, d2);
    uint64_t s2 = (uint64_t)_mm256_extract_epi64(t, 0) +
                  (uint64_t)_mm256_extract_epi64(t, 1);
    t = _mm256_permute2x128_si256(d3, d3, 0x81);
    t = _mm256_add_epi64(t, d3);
    uint64_t s3 = (uint64_t)_mm256_extract_epi64(t, 0) +
                  (uint64_t)_mm256_extract_epi64(t, 1);
    t = _mm256_permute2x128_si256(d4, d4, 0x81);
    t = _mm256_add_epi64(t, d4);
    uint64_t s4 = (uint64_t)_mm256_extract_epi64(t, 0) +
                  (uint64_t)_mm256_extract_epi64(t, 1);
    // 求和可能超出 26 位，再做一轮进位
    uint64_t cc;
    cc = s0 >> 26; s0 &= M26; s1 += cc;
    cc = s1 >> 26; s1 &= M26; s2 += cc;
    cc = s2 >> 26; s2 &= M26; s3 += cc;
    cc = s3 >> 26; s3 &= M26; s4 += cc;
    cc = s4 >> 26; s4 &= M26; s0 += cc * 5;
    cc = s0 >> 26; s0 &= M26; s1 += cc;
    cc = s1 >> 26; s1 &= M26; s2 += cc;
    cc = s2 >> 26; s2 &= M26; s3 += cc;
    cc = s3 >> 26; s3 &= M26; s4 += cc;
    cc = s4 >> 26; s4 &= M26; s0 += cc * 5;
    s0 &= M26;
    st.h0 = s0;
    st.h1 = s1;
    st.h2 = s2;
    st.h3 = s3;
    st.h4 = s4;
}

void feed(State& st, const uint8_t* p, size_t n) {
    while (n >= 64) {
        feed64(st, p);
        p += 64;
        n -= 64;
    }
    // 剩余 16 字节块由调用方（poly1305_feed64）用标量路径处理：
    // AVX2 feed 只负责 64 字节整块，保证 4 个块都真实带 2^128 pad。
}

// convert 26-bit hash to 44/44/42-bit limbs; tag via scalar finish
void finish(const State& st, const uint8_t key[32], uint8_t tag[16]) {
    uint64_t h0 = st.h0, h1 = st.h1, h2 = st.h2, h3 = st.h3, h4 = st.h4;
    uint64_t s0 = h0 | ((h1 & 0x3ffff) << 26);
    uint64_t s1 = (h1 >> 18) | (h2 << 8) | ((h3 & 0x3ff) << 34);
    uint64_t s2 = (h3 >> 10) | (h4 << 16);
    uint64_t hh0 = s0 & M44;
    uint64_t hh1 = s1 & M44;
    uint64_t hh2 = s2 & M42;
    uint64_t c;
    c = hh1 >> 44; hh1 &= M44; hh2 += c;
    c = hh2 >> 42; hh2 &= M42; hh0 += c * 5;
    c = hh0 >> 44; hh0 &= M44; hh1 += c;
    c = hh1 >> 44; hh1 &= M44; hh2 += c;
    c = hh2 >> 42; hh2 &= M42; hh0 += c * 5;
    c = hh0 >> 44; hh0 &= M44; hh1 += c;
    uint64_t g0 = hh0 + 5; c = g0 >> 44; g0 &= M44;
    uint64_t g1 = hh1 + c; c = g1 >> 44; g1 &= M44;
    uint64_t g2 = hh2 + c - (1ULL << 42);
    c = (g2 >> 63) - 1;
    g0 &= c; g1 &= c; g2 &= c;
    c = ~c;
    hh0 = (hh0 & c) | g0; hh1 = (hh1 & c) | g1; hh2 = (hh2 & c) | g2;
    uint64_t lo = hh0 | (hh1 << 44);
    uint64_t hi = (hh1 >> 20) | (hh2 << 24);
    uint64_t f0, f1;
    std::memcpy(&f0, key + 16, 8);
    std::memcpy(&f1, key + 24, 8);
    uint64_t t0 = lo + f0;
    uint64_t t1 = hi + f1 + (t0 < lo);
    std::memcpy(tag, &t0, 8);
    std::memcpy(tag + 8, &t1, 8);
}

}  // namespace poly_avx2
}  // namespace jpssl
