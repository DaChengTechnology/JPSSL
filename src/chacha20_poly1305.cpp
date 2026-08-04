/**
 * chacha20_poly1305.cpp — ChaCha20-Poly1305 AEAD 完整实现（RFC 8439）
 *
 * 参考实现基于：
 *   - RFC 8439 "ChaCha20 and Poly1305 for IETF Protocols"
 *   - libsodium / OpenSSL / BoringSSL 的参考代码
 */

#include "chacha20_poly1305.hpp"
#include "cpu_features.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#endif
#ifdef JP_MUSA
#include <musa_runtime.h>
#endif

#if defined(_MSC_VER) && !defined(__clang__)
#define JP_POLY_FORCEINLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define JP_POLY_FORCEINLINE inline __attribute__((always_inline))
#else
#define JP_POLY_FORCEINLINE inline
#endif

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  辅助：little-endian 读写 uint32_t
// ═══════════════════════════════════════════════════════════════════════

static inline uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/// 32-bit 循环左移
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20 Quarter Round
// ═══════════════════════════════════════════════════════════════════════

#define QR(a, b, c, d) do { \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d,  8); \
    c += d; b ^= c; b = rotl32(b,  7); \
} while (0)

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20 块函数（生成 64 字节 keystream）
// ═══════════════════════════════════════════════════════════════════════

void chacha20_block(const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12], uint8_t keystream[64]) {
    // 初始化状态（16 × 32-bit words）
    uint32_t s[16];

    // 常量 "expand 32-byte k"
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    // 密钥（256-bit = 8 × 32-bit）
    for (int i = 0; i < 8; ++i) {
        s[4 + i] = load32_le(key + i * 4);
    }

    // 计数器
    s[12] = counter;

    // Nonce（96-bit = 3 × 32-bit）
    s[13] = load32_le(nonce);
    s[14] = load32_le(nonce + 4);
    s[15] = load32_le(nonce + 8);

    // 保存初始状态（用于最后相加）
    uint32_t init[16];
    std::memcpy(init, s, sizeof(s));

    // 20 轮（10 个 double round）
    for (int i = 0; i < 10; ++i) {
        // Column round
        QR(s[0], s[4], s[ 8], s[12]);
        QR(s[1], s[5], s[ 9], s[13]);
        QR(s[2], s[6], s[10], s[14]);
        QR(s[3], s[7], s[11], s[15]);
        // Diagonal round
        QR(s[0], s[5], s[10], s[15]);
        QR(s[1], s[6], s[11], s[12]);
        QR(s[2], s[7], s[ 8], s[13]);
        QR(s[3], s[4], s[ 9], s[14]);
    }

    // 最终状态 = 原始状态 + 轮后状态
    for (int i = 0; i < 16; ++i) {
        s[i] += init[i];
    }

    // 序列化为 little-endian 字节流
    for (int i = 0; i < 16; ++i) {
        store32_le(keystream + i * 4, s[i]);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20 流加密
// ═══════════════════════════════════════════════════════════════════════

void chacha20_crypt(const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12],
                    std::span<const uint8_t> input,
                    std::span<uint8_t> output) {
    // 运行时扩展检测：优先 AVX512，其次 AVX2，回退标量
    if (cpu_has_avx512()) {
        chacha20_crypt_avx512(key, counter, nonce, input, output);
        return;
    }
    if (cpu_has_avx2()) {
        chacha20_crypt_avx2(key, counter, nonce, input, output);
        return;
    }
    uint8_t block[64];
    size_t pos = 0;

    while (pos < input.size()) {
        chacha20_block(key, counter, nonce, block);
        ++counter;

        size_t chunk = std::min<size_t>(64, input.size() - pos);
        for (size_t i = 0; i < chunk; ++i) {
            output[pos + i] = input[pos + i] ^ block[i];
        }
        pos += chunk;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Poly1305（基于 26-bit limbs 实现，可移植且简单）
// ═══════════════════════════════════════════════════════════════════════

/// Clamp r：清除/设置特定位
static void poly1305_clamp(uint8_t r[16]) {
    r[3]  &= 15;
    r[7]  &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4]  &= 252;
    r[8]  &= 252;
    r[12] &= 252;
}

/// 将 16 字节 little-endian 读入 5 个 26-bit limbs

// ============================================================
//  Fast Poly1305: 3-limb (44/44/42-bit) representation.
//  h = h0 + h1*B + h2*B^2 with B = 2^44; mod 2^130-5:
//    B^3 = 2^132 = 20,  B^4 = 2^176 = 20*B
//  Only 9 64x64->128 multiplies per 16-byte block.
// ============================================================

static JP_POLY_FORCEINLINE uint64_t poly_load64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}

static JP_POLY_FORCEINLINE void poly_store64(uint8_t* p, uint64_t v) {
    std::memcpy(p, &v, 8);
}

// 128-bit product/accumulation helpers using native x64 intrinsics.
// MSVC has no __int128; emulated jp_uint128 costs 3 muls + call overhead
// per 64x64 multiply, so Poly1305 uses explicit lo/hi arithmetic instead.
struct P128 {
    uint64_t lo, hi;
};

static JP_POLY_FORCEINLINE P128 p128_mul(uint64_t a, uint64_t b) {
#if defined(_MSC_VER) && !defined(__clang__)
    uint64_t hi;
    uint64_t lo = _umul128(a, b, &hi);
    return P128{lo, hi};
#else
    __uint128_t r = (__uint128_t)a * b;
    return P128{(uint64_t)r, (uint64_t)(r >> 64)};
#endif
}

static JP_POLY_FORCEINLINE P128 p128_add(P128 a, P128 b) {
#if defined(_MSC_VER) && !defined(__clang__)
    unsigned char c = _addcarry_u64(0, a.lo, b.lo, &a.lo);
    _addcarry_u64(c, a.hi, b.hi, &a.hi);
    return a;
#else
    __uint128_t t = (__uint128_t)a.lo | ((__uint128_t)a.hi << 64);
    t += (__uint128_t)b.lo | ((__uint128_t)b.hi << 64);
    return P128{(uint64_t)t, (uint64_t)(t >> 64)};
#endif
}

static JP_POLY_FORCEINLINE P128 p128_add_u64(P128 a, uint64_t b) {
#if defined(_MSC_VER) && !defined(__clang__)
    unsigned char c = _addcarry_u64(0, a.lo, b, &a.lo);
    _addcarry_u64(c, a.hi, 0, &a.hi);
    return a;
#else
    __uint128_t t = (__uint128_t)a.lo | ((__uint128_t)a.hi << 64);
    t += b;
    return P128{(uint64_t)t, (uint64_t)(t >> 64)};
#endif
}

// a * k where k is a small constant (fits in 64 bits: hi*a <= 64 bits)
static JP_POLY_FORCEINLINE P128 p128_mul_u64(P128 a, uint64_t k) {
#if defined(_MSC_VER) && !defined(__clang__)
    uint64_t hi;
    uint64_t lo = _umul128(a.lo, k, &hi);
    hi += a.hi * k;
    return P128{lo, hi};
#else
    __uint128_t r = (__uint128_t)a.lo * k;
    uint64_t lo = (uint64_t)r;
    uint64_t hi = (uint64_t)(r >> 64) + a.hi * k;
    return P128{lo, hi};
#endif
}

// h *= r (mod 2^130-5), with r already clamped
static JP_POLY_FORCEINLINE void poly_mul3(uint64_t& h0, uint64_t& h1, uint64_t& h2,
                                          uint64_t r0, uint64_t r1, uint64_t r2) {
    const uint64_t M44 = 0xfffffffffffULL;
    const uint64_t M42 = 0x3ffffffffffULL;
    P128 p0 = p128_mul(h0, r0);
    P128 p1 = p128_add(p128_mul(h0, r1), p128_mul(h1, r0));
    P128 p2 = p128_add(p128_add(p128_mul(h0, r2), p128_mul(h1, r1)),
                       p128_mul(h2, r0));
    P128 p3 = p128_add(p128_mul(h1, r2), p128_mul(h2, r1));
    P128 p4 = p128_mul(h2, r2);

    // fold B^3=2^132=20 and B^4=2^176=20*B into limbs 0 and 1
    P128 d0 = p128_add(p0, p128_mul_u64(p3, 20));
    P128 d1 = p128_add(p1, p128_mul_u64(p4, 20));
    P128 d2 = p2;

    // carry propagation; overflow of the 42-bit h2 limb is 2^130 = 5
    uint64_t c;
    h0 = d0.lo & M44; c = (d0.hi << 20) | (d0.lo >> 44);
    d1 = p128_add_u64(d1, c);
    h1 = d1.lo & M44; c = (d1.hi << 20) | (d1.lo >> 44);
    d2 = p128_add_u64(d2, c);
    h2 = d2.lo & M42; c = (d2.hi << 22) | (d2.lo >> 42);
    h0 += c * 5;
    c = h0 >> 44; h0 &= M44; h1 += c;
    c = h1 >> 44; h1 &= M44; h2 += c;
    c = h2 >> 42; h2 &= M42; h0 += c * 5;
    c = h0 >> 44; h0 &= M44; h1 += c;
}

// load a 16-byte block into 3 limbs, with optional 2^128 pad bit
static JP_POLY_FORCEINLINE void poly_load_block(const uint8_t* p, uint64_t& m0,
                                                uint64_t& m1, uint64_t& m2,
                                                bool pad_bit) {
    const uint64_t M44 = 0xfffffffffffULL;
    const uint64_t M42 = 0x3ffffffffffULL;
    uint64_t w0 = poly_load64(p);
    uint64_t w1 = poly_load64(p + 8);
    m0 = w0 & M44;
    m1 = ((w0 >> 44) | (w1 << 20)) & M44;
    m2 = (w1 >> 24) & M42;
    if (pad_bit) m2 += (1ULL << 40);
}

// add one 16-byte block (with optional 0x01 pad bit at bit 128) and multiply
static JP_POLY_FORCEINLINE void poly_add_block3(uint64_t& h0, uint64_t& h1,
                                                uint64_t& h2, const uint8_t* p,
                                                uint64_t r0, uint64_t r1,
                                                uint64_t r2, bool pad_bit) {
    uint64_t m0, m1, m2;
    poly_load_block(p, m0, m1, m2, pad_bit);
    h0 += m0; h1 += m1; h2 += m2;
    poly_mul3(h0, h1, h2, r0, r1, r2);
}

// process 4 consecutive 16-byte blocks in parallel:
//   h' = (h+m0)*r^4 + m1*r^3 + m2*r^2 + m3*r
// The four products are independent, giving 4-way ILP.
static JP_POLY_FORCEINLINE void poly_blocks4(uint64_t& h0, uint64_t& h1,
                                             uint64_t& h2, const uint8_t* m,
                                             uint64_t r0, uint64_t r1,
                                             uint64_t r2,
                                             uint64_t r20, uint64_t r21,
                                             uint64_t r22,
                                             uint64_t r30, uint64_t r31,
                                             uint64_t r32,
                                             uint64_t r40, uint64_t r41,
                                             uint64_t r42) {
    const uint64_t M44 = 0xfffffffffffULL;
    const uint64_t M42 = 0x3ffffffffffULL;
    uint64_t a0, a1, a2, b0, b1, b2, c0, c1, c2, d0, d1, d2;
    poly_load_block(m,      a0, a1, a2, true);
    poly_load_block(m + 16, b0, b1, b2, true);
    poly_load_block(m + 32, c0, c1, c2, true);
    poly_load_block(m + 48, d0, d1, d2, true);

    uint64_t A0 = a0 + h0, A1 = a1 + h1, A2 = a2 + h2;
    poly_mul3(A0, A1, A2, r40, r41, r42);
    poly_mul3(b0, b1, b2, r30, r31, r32);
    poly_mul3(c0, c1, c2, r20, r21, r22);
    poly_mul3(d0, d1, d2, r0, r1, r2);

    // accumulate incrementally so the compiler can free product registers
    uint64_t s0 = A0 + b0;
    uint64_t s1 = A1 + b1;
    uint64_t s2 = A2 + b2;
    s0 += c0; s1 += c1; s2 += c2;
    s0 += d0; s1 += d1; s2 += d2;

    uint64_t carry;
    carry = s0 >> 44; s0 &= M44; s1 += carry;
    carry = s1 >> 44; s1 &= M44; s2 += carry;
    carry = s2 >> 42; s2 &= M42; s0 += carry * 5;

    h0 = s0; h1 = s1; h2 = s2;
}

// Reusable Poly1305 state (3-limb) so the AEAD path can feed ciphertext
// blocks as they are produced by the ChaCha stream, without a second pass.
struct Poly1305State64 {
    uint64_t h0 = 0, h1 = 0, h2 = 0;
    uint64_t r0, r1, r2;
    uint64_t r20, r21, r22;
    uint64_t r30, r31, r32;
    uint64_t r40, r41, r42;
    poly_avx2::State avx;      // AVX2 路径状态（26-bit 肢体）
    uint8_t key[32] = {};      // 一次性密钥（finish 需要）
    bool use_avx = false;      // 本消息是否已走 AVX2 路径
};

static void poly1305_init64(Poly1305State64& st, const uint8_t key[32]) {
    const uint64_t M44 = 0xfffffffffffULL;
    const uint64_t M42 = 0x3ffffffffffULL;

    uint8_t rbytes[16];
    std::memcpy(rbytes, key, 16);
    poly1305_clamp(rbytes);
    uint64_t rw0 = poly_load64(rbytes);
    uint64_t rw1 = poly_load64(rbytes + 8);
    st.r0 = rw0 & M44;
    st.r1 = ((rw0 >> 44) | (rw1 << 20)) & M44;
    st.r2 = (rw1 >> 24) & M42;

    // precompute r^2, r^3, r^4 for the 4-way block routine
    st.r20 = st.r0; st.r21 = st.r1; st.r22 = st.r2;
    poly_mul3(st.r20, st.r21, st.r22, st.r0, st.r1, st.r2);
    st.r30 = st.r20; st.r31 = st.r21; st.r32 = st.r22;
    poly_mul3(st.r30, st.r31, st.r32, st.r0, st.r1, st.r2);
    st.r40 = st.r30; st.r41 = st.r31; st.r42 = st.r32;
    poly_mul3(st.r40, st.r41, st.r42, st.r0, st.r1, st.r2);
    std::memcpy(st.key, key, 32);
    st.use_avx = false;
}

// Feed n bytes. For the AEAD layout (AAD || pad(AAD) || ct || pad(ct) ...)
// the trailing partial block is zero-padded to 16 and gets the 2^128 pad bit.
static void poly1305_feed64(Poly1305State64& st, const uint8_t* p, size_t n) {
    static const bool has_avx2 = cpu_has_avx2();
    // AVX2 路径只处理完整的 64 字节块；剩余不足 64B 的交给标量路径，
    // 避免 16B 尾部块在 AVX2 中把零填充块也纳入多项式。
    if (has_avx2 && n >= 64) {
        if (!st.use_avx) {
            poly_avx2::init(st.avx, st.key);
            // 迁移已有标量 44-bit 哈希到 AVX2 26-bit 状态
            uint64_t s0 = st.h0, s1 = st.h1, s2 = st.h2;
            st.avx.h0 = s0 & 0x3ffffff;
            st.avx.h1 = ((s0 >> 26) | (s1 << 18)) & 0x3ffffff;
            st.avx.h2 = (s1 >> 8) & 0x3ffffff;
            st.avx.h3 = ((s1 >> 34) | (s2 << 10)) & 0x3ffffff;
            st.avx.h4 = (s2 >> 16) & 0x3ffffff;
            st.use_avx = true;
        }
        size_t n64 = n & ~(size_t)63;
        poly_avx2::feed(st.avx, p, n64);
        p += n64;
        n -= n64;
        if (n == 0) return;
        // 剩余 <64B：转回标量继续
        uint64_t h0 = st.avx.h0, h1 = st.avx.h1, h2 = st.avx.h2,
                 h3 = st.avx.h3, h4 = st.avx.h4;
        st.h0 = h0 | ((h1 & 0x3ffff) << 26);
        st.h1 = (h1 >> 18) | (h2 << 8) | ((h3 & 0x3ff) << 34);
        st.h2 = (h3 >> 10) | (h4 << 16);
        st.h0 &= 0xfffffffffffULL;
        st.h1 &= 0xfffffffffffULL;
        st.h2 &= 0x3ffffffffffULL;
        st.use_avx = false;
    }
    if (st.use_avx) {
        // 已走 AVX2 路径但遇到非 16 倍数输入：把 AVX2 哈希转回标量
        uint64_t h0 = st.avx.h0, h1 = st.avx.h1, h2 = st.avx.h2,
                 h3 = st.avx.h3, h4 = st.avx.h4;
        st.h0 = h0 | ((h1 & 0x3ffff) << 26);
        st.h1 = (h1 >> 18) | (h2 << 8) | ((h3 & 0x3ff) << 34);
        st.h2 = (h3 >> 10) | (h4 << 16);
        st.h0 &= 0xfffffffffffULL;
        st.h1 &= 0xfffffffffffULL;
        st.h2 &= 0x3ffffffffffULL;
        st.use_avx = false;
    }
    while (n >= 64) {
        poly_blocks4(st.h0, st.h1, st.h2, p,
                     st.r0, st.r1, st.r2,
                     st.r20, st.r21, st.r22,
                     st.r30, st.r31, st.r32,
                     st.r40, st.r41, st.r42);
        p += 64;
        n -= 64;
    }
    while (n >= 16) {
        poly_add_block3(st.h0, st.h1, st.h2, p, st.r0, st.r1, st.r2, true);
        p += 16;
        n -= 16;
    }
    if (n) {
        uint8_t t[16] = {0};
        std::memcpy(t, p, n);
        poly_add_block3(st.h0, st.h1, st.h2, t, st.r0, st.r1, st.r2, true);
    }
}

// Software-pipelined fused ChaCha20 stream + Poly1305 feed.
// Processes CH bytes per iteration. The SIMD ChaCha work for the NEXT chunk
// is issued before the scalar Poly1305 work of the CURRENT chunk, so the two
// use different execution ports and overlap, and the freshly written
// ciphertext is still in L1 when Poly1305 reads it (no second DRAM pass).
static void chacha20_crypt_feed_poly(
    const uint8_t key[32], const uint8_t nonce[12],
    std::span<const uint8_t> in, std::span<uint8_t> out,
    std::span<const uint8_t> ct, Poly1305State64& st) {
    constexpr size_t CH = 4096;  // 64 ChaCha blocks
    const size_t n = in.size();
    size_t pos = 0;

    bool use512 = cpu_has_avx512();
    bool use256 = cpu_has_avx2();
    auto gen = [&](size_t p, size_t len) {
        uint32_t ctr = 1 + (uint32_t)(p / 64);
        if (use512)
            chacha20_crypt_avx512(key, ctr, nonce, in.subspan(p, len), out.subspan(p, len));
        else if (use256)
            chacha20_crypt_avx2(key, ctr, nonce, in.subspan(p, len), out.subspan(p, len));
        else
            chacha20_crypt(key, ctr, nonce, in.subspan(p, len), out.subspan(p, len));
    };

    if (n >= CH) { gen(0, CH); pos = CH; }
    while (pos + CH <= n) {
        gen(pos, CH);  // SIMD ChaCha for the next chunk (independent of poly)
        poly1305_feed64(st, ct.data() + pos - CH, CH);  // scalar Poly1305
        pos += CH;
    }
    if (pos >= CH)
        poly1305_feed64(st, ct.data() + pos - CH, CH);  // last full chunk
    if (pos < n) {
        gen(pos, n - pos);
        poly1305_feed64(st, ct.data() + pos, n - pos);
    }
}

// 若当前状态走的是 AVX2 路径，把 26-bit 哈希转回 44-bit 标量 limb
static void poly1305_sync_scalar(Poly1305State64& st) {
    if (!st.use_avx) return;
    uint64_t h0 = st.avx.h0, h1 = st.avx.h1, h2 = st.avx.h2,
             h3 = st.avx.h3, h4 = st.avx.h4;
    st.h0 = h0 | ((h1 & 0x3ffff) << 26);
    st.h1 = (h1 >> 18) | (h2 << 8) | ((h3 & 0x3ff) << 34);
    st.h2 = (h3 >> 10) | (h4 << 16);
    st.h0 &= 0xfffffffffffULL;
    st.h1 &= 0xfffffffffffULL;
    st.h2 &= 0x3ffffffffffULL;
    st.use_avx = false;
}

// finish: full reduction mod 2^130-5, select h < p, then tag = (h + s) mod 2^128
static void poly1305_finish3(uint64_t h0, uint64_t h1, uint64_t h2,
                             const uint8_t key[32], uint8_t tag[16]) {
    const uint64_t M44 = 0xfffffffffffULL;
    const uint64_t M42 = 0x3ffffffffffULL;

    uint64_t c;
    c = h1 >> 44; h1 &= M44; h2 += c;
    c = h2 >> 42; h2 &= M42; h0 += c * 5;
    c = h0 >> 44; h0 &= M44; h1 += c;
    c = h1 >> 44; h1 &= M44; h2 += c;
    c = h2 >> 42; h2 &= M42; h0 += c * 5;
    c = h0 >> 44; h0 &= M44; h1 += c;

    // select h if h < p, else h - p (= h + 5 - 2^130)
    uint64_t g0 = h0 + 5; c = g0 >> 44; g0 &= M44;
    uint64_t g1 = h1 + c; c = g1 >> 44; g1 &= M44;
    uint64_t g2 = h2 + c - (1ULL << 42);
    c = (g2 >> 63) - 1;
    g0 &= c; g1 &= c; g2 &= c;
    c = ~c;
    h0 = (h0 & c) | g0;
    h1 = (h1 & c) | g1;
    h2 = (h2 & c) | g2;

    // tag = (h + s) mod 2^128
    uint64_t lo = h0 | (h1 << 44);
    uint64_t hi = (h1 >> 20) | (h2 << 24);
    uint64_t f0 = lo + poly_load64(key + 16);
    uint64_t f1 = hi + poly_load64(key + 24) + (f0 < lo);
    poly_store64(tag, f0);
    poly_store64(tag + 8, f1);
}

// Poly1305 over the AEAD layout AAD || pad(AAD) || ct || pad(ct) || len64 || len64,
// without building a concatenated message buffer.
static void poly1305_mac_parts64(const uint8_t key[32],
                                 std::span<const uint8_t> aad,
                                 std::span<const uint8_t> ct,
                                 uint8_t tag[16]) {
    Poly1305State64 st;
    poly1305_init64(st, key);
    poly1305_feed64(st, aad.data(), aad.size());
    poly1305_feed64(st, ct.data(), ct.size());

    uint8_t lenblock[16];
    poly_store64(lenblock, (uint64_t)aad.size());
    poly_store64(lenblock + 8, (uint64_t)ct.size());
    poly1305_feed64(st, lenblock, 16);
    if (st.use_avx) {
        uint64_t h0 = st.avx.h0, h1 = st.avx.h1, h2 = st.avx.h2,
                 h3 = st.avx.h3, h4 = st.avx.h4;
        st.h0 = h0 | ((h1 & 0x3ffff) << 26);
        st.h1 = (h1 >> 18) | (h2 << 8) | ((h3 & 0x3ff) << 34);
        st.h2 = (h3 >> 10) | (h4 << 16);
        st.h0 &= 0xfffffffffffULL;
        st.h1 &= 0xfffffffffffULL;
        st.h2 &= 0x3ffffffffffULL;
    }
    poly1305_finish3(st.h0, st.h1, st.h2, key, tag);
}

void poly1305_mac(const uint8_t key[32],
                  std::span<const uint8_t> msg,
                  uint8_t tag[16]) {
    // Fast 3-limb (44/44/42-bit) Poly1305 over a raw message span:
    // full 16-byte blocks get the 2^128 bit; a final partial block is
    // appended with 0x01 and zero-padded to 16 bytes (no 2^128 bit).
    uint8_t rbytes[16];
    std::memcpy(rbytes, key, 16);
    poly1305_clamp(rbytes);

    const uint64_t M44 = 0xfffffffffffULL;
    const uint64_t M42 = 0x3ffffffffffULL;
    uint64_t rw0 = poly_load64(rbytes);
    uint64_t rw1 = poly_load64(rbytes + 8);
    uint64_t r0 = rw0 & M44;
    uint64_t r1 = ((rw0 >> 44) | (rw1 << 20)) & M44;
    uint64_t r2 = (rw1 >> 24) & M42;

    // precompute r^2, r^3, r^4 for the 4-way block routine
    uint64_t r20 = r0, r21 = r1, r22 = r2;
    poly_mul3(r20, r21, r22, r0, r1, r2);
    uint64_t r30 = r20, r31 = r21, r32 = r22;
    poly_mul3(r30, r31, r32, r0, r1, r2);
    uint64_t r40 = r30, r41 = r31, r42 = r32;
    poly_mul3(r40, r41, r42, r0, r1, r2);

    uint64_t h0 = 0, h1 = 0, h2 = 0;
    size_t pos = 0;
    while (msg.size() - pos >= 64) {
        poly_blocks4(h0, h1, h2, msg.data() + pos,
                     r0, r1, r2, r20, r21, r22, r30, r31, r32, r40, r41, r42);
        pos += 64;
    }
    while (msg.size() - pos >= 16) {
        poly_add_block3(h0, h1, h2, msg.data() + pos, r0, r1, r2, true);
        pos += 16;
    }
    if (pos < msg.size()) {
        uint8_t t[16] = {0};
        size_t n = msg.size() - pos;
        std::memcpy(t, msg.data() + pos, n);
        t[n] = 1;
        poly_add_block3(h0, h1, h2, t, r0, r1, r2, false);
    }
    poly1305_finish3(h0, h1, h2, key, tag);
}

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20-Poly1305 AEAD（RFC 8439 §2.8）
// ═══════════════════════════════════════════════════════════════════════

void chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    std::vector<uint8_t>& ciphertext,
    uint8_t tag[16]) {
    // 1. 用 counter=0 生成 Poly1305 一次性密钥（32 字节）
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);

    // 2. 用 counter=1 加密明文
    ciphertext.resize(plaintext.size());

    // 3. 边加密边累计 Poly1305（单遍，流水线重叠 SIMD 与标量）
    Poly1305State64 st;
    poly1305_init64(st, poly_key);
    poly1305_feed64(st, aad.data(), aad.size());
    chacha20_crypt_feed_poly(key, nonce, plaintext, ciphertext, ciphertext, st);

    // 4. 认证消息尾部：len(AAD)_64 || len(ciphertext)_64
    uint8_t lenblock[16];
    poly_store64(lenblock, (uint64_t)aad.size());
    poly_store64(lenblock + 8, (uint64_t)plaintext.size());
    poly1305_feed64(st, lenblock, 16);
    poly1305_sync_scalar(st);
    poly1305_finish3(st.h0, st.h1, st.h2, poly_key, tag);
}

bool chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> aad,
    const uint8_t tag[16],
    std::vector<uint8_t>& plaintext) {
    // 1. 用 counter=0 生成 Poly1305 一次性密钥
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);

    // 2. 先验签再解密：失败时不输出任何明文
    uint8_t expected_tag[16];
    Poly1305State64 st;
    poly1305_init64(st, poly_key);
    poly1305_feed64(st, aad.data(), aad.size());
    poly1305_feed64(st, ciphertext.data(), ciphertext.size());
    uint8_t lenblock[16];
    poly_store64(lenblock, (uint64_t)aad.size());
    poly_store64(lenblock + 8, (uint64_t)ciphertext.size());
    poly1305_feed64(st, lenblock, 16);
    poly1305_sync_scalar(st);
    poly1305_finish3(st.h0, st.h1, st.h2, poly_key, expected_tag);

    // 3. 常数时间比较 tag
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= tag[i] ^ expected_tag[i];
    if (diff != 0) return false;

    // 4. 解密密文
    plaintext.resize(ciphertext.size());
    chacha20_crypt(key, 1, nonce, ciphertext, plaintext);

    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  MUSA GPU 封装
// ═══════════════════════════════════════════════════════════════════════

#define CHACHA_MUSA_CHECK(call)                                       \
    do {                                                              \
        musaError_t e = (call);                                       \
        if (e != musaSuccess) {                                       \
            std::fprintf(stderr, "MUSA error at %s:%d — %s (%d)\n",  \
                         __FILE__, __LINE__, musaGetErrorString(e), (int)e); \
            std::abort();                                             \
        }                                                             \
    } while (0)

#ifdef JP_MUSA

// ── 外部函数（由 chacha20_gpu.mu 提供） ────────────────────────────

extern "C" void musa_chacha20_gpu_init(const uint8_t* key, const uint8_t* nonce);
extern "C" void musa_chacha20_gpu_set_nonce(const uint8_t* nonce);
extern "C" void launch_chacha20_keystream(uint8_t* d_keystream, uint32_t counter,
                                          int num_blocks, int threads, musaStream_t stream);
extern "C" void launch_chacha20_xor(const uint8_t* d_in, uint8_t* d_out,
                                    uint32_t counter, int num_blocks,
                                    int threads, musaStream_t stream);

static constexpr int CC20_THREADS = 128;
static constexpr size_t CC20_DEFAULT_CAP = 16 * 1024 * 1024;

struct musa_chacha20_pool {
    uint8_t       key[32]   = {};        // 密钥副本
    uint8_t       nonce[12] = {};        // 当前 nonce
    uint8_t*      d_buf     = nullptr;   // 设备端缓冲区
    size_t        capacity  = 0;
    musaStream_t  stream    = nullptr;
    bool          init      = false;
};

musa_chacha20_pool* musa_chacha20_pool_create(
    const uint8_t key[32], const uint8_t nonce[12], size_t init_capacity)
{
    if (init_capacity == 0) init_capacity = CC20_DEFAULT_CAP;
    auto* p = new musa_chacha20_pool();
    p->capacity = init_capacity;
    std::memcpy(p->key, key, 32);
    std::memcpy(p->nonce, nonce, 12);

    musa_chacha20_gpu_init(key, nonce);

    CHACHA_MUSA_CHECK(musaMalloc(&p->d_buf, init_capacity));
    CHACHA_MUSA_CHECK(musaStreamCreate(&p->stream));
    p->init = true;
    return p;
}

void musa_chacha20_pool_destroy(musa_chacha20_pool* pool) {
    if (!pool) return;
    if (pool->stream) musaStreamDestroy(pool->stream);
    if (pool->d_buf)  musaFree(pool->d_buf);
    delete pool;
}

void musa_chacha20_pool_set_nonce(musa_chacha20_pool* pool, const uint8_t nonce[12]) {
    if (!pool) return;
    std::memcpy(pool->nonce, nonce, 12);
    musa_chacha20_gpu_set_nonce(nonce);
}

static void pool_ensure(musa_chacha20_pool* p, size_t need) {
    if (need <= p->capacity) return;
    size_t nc = std::max(need, p->capacity * 2);
    if (p->d_buf) musaFree(p->d_buf);
    CHACHA_MUSA_CHECK(musaMalloc(&p->d_buf, nc));
    p->capacity = nc;
}

void musa_chacha20_pool_keystream(musa_chacha20_pool* pool,
                                  uint8_t* keystream, size_t num_blocks,
                                  uint32_t base_counter) {
    if (!pool || !pool->init) return;
    if (num_blocks == 0) return;
    size_t bytes = num_blocks * 64;
    pool_ensure(pool, bytes);

    launch_chacha20_keystream(pool->d_buf, base_counter, (int)num_blocks,
                              CC20_THREADS, pool->stream);
    CHACHA_MUSA_CHECK(musaStreamSynchronize(pool->stream));
    CHACHA_MUSA_CHECK(musaMemcpy(keystream, pool->d_buf, bytes, musaMemcpyDeviceToHost));
}

void musa_chacha20_pool_xor(musa_chacha20_pool* pool,
                            const uint8_t* input, uint8_t* output,
                            size_t num_blocks, uint32_t base_counter) {
    if (!pool || !pool->init) return;
    if (num_blocks == 0) return;
    size_t bytes = num_blocks * 64;
    pool_ensure(pool, bytes);
    // 需要两个设备缓冲区（in+out）或使用 d_buf 复用
    // 简化：使用 CPU keystream + XOR
    std::vector<uint8_t> ks(bytes);
    musa_chacha20_pool_keystream(pool, ks.data(), num_blocks, base_counter);
    for (size_t i = 0; i < bytes; ++i) output[i] = input[i] ^ ks[i];
}

void musa_chacha20_pool_aead_encrypt(
    musa_chacha20_pool* pool, const uint8_t nonce[12],
    std::span<const uint8_t> pt, std::span<const uint8_t> aad,
    std::vector<uint8_t>& ct, uint8_t tag[16])
{
    if (!pool || !pool->init) return;

    // 更新 nonce
    musa_chacha20_pool_set_nonce(pool, nonce);

    // Poly1305 一次性密钥：CPU 生成（counter=0，只需 1 块）
    uint8_t poly_key[64];
    chacha20_block(pool->key, 0, nonce, poly_key);

    // CTR 加密：GPU 生成 keystream（counter=1）
    ct.resize(pt.size());
    size_t num_blocks = (pt.size() + 63) / 64;
    std::vector<uint8_t> ks(ct.size());
    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t block[64];
        chacha20_block(pool->key, (uint32_t)(1 + i), nonce, block);
        size_t chunk = std::min<size_t>(64, pt.size() - i * 64);
        std::memcpy(ks.data() + i * 64, block, 64);
    }
    for (size_t i = 0; i < pt.size(); ++i) ct[i] = pt[i] ^ ks[i];

    // Poly1305 认证（CPU，调用已有函数）
    // 构造 poly_msg 并计算 tag
    std::vector<uint8_t> poly_msg;
    poly_msg.reserve(aad.size() + ct.size() + 32);
    poly_msg.insert(poly_msg.end(), aad.begin(), aad.end());
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);
    poly_msg.insert(poly_msg.end(), ct.begin(), ct.end());
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);
    uint64_t aad_len = aad.size(), ct_len = ct.size();
    for (int i = 0; i < 8; ++i) poly_msg.push_back((uint8_t)(aad_len >> (i*8)));
    for (int i = 0; i < 8; ++i) poly_msg.push_back((uint8_t)(ct_len >> (i*8)));
    poly1305_mac(poly_key, poly_msg, tag);
}

bool musa_chacha20_pool_aead_decrypt(
    musa_chacha20_pool* pool, const uint8_t nonce[12],
    std::span<const uint8_t> ct, std::span<const uint8_t> aad,
    const uint8_t tag[16], std::vector<uint8_t>& pt)
{
    if (!pool || !pool->init) return false;

    musa_chacha20_pool_set_nonce(pool, nonce);

    // Poly1305 一次性密钥
    uint8_t poly_key[64];
    chacha20_block(pool->key, 0, nonce, poly_key);

    // 验证 tag
    std::vector<uint8_t> poly_msg;
    poly_msg.reserve(aad.size() + ct.size() + 32);
    poly_msg.insert(poly_msg.end(), aad.begin(), aad.end());
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);
    poly_msg.insert(poly_msg.end(), ct.begin(), ct.end());
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);
    uint64_t aad_len = aad.size(), ct_len = ct.size();
    for (int i = 0; i < 8; ++i) poly_msg.push_back((uint8_t)(aad_len >> (i*8)));
    for (int i = 0; i < 8; ++i) poly_msg.push_back((uint8_t)(ct_len >> (i*8)));
    uint8_t expected_tag[16];
    poly1305_mac(poly_key, poly_msg, expected_tag);

    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= tag[i] ^ expected_tag[i];
    if (diff != 0) return false;

    // 解密
    pt.resize(ct.size());
    size_t num_blocks = (ct.size() + 63) / 64;
    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t block[64];
        chacha20_block(pool->key, (uint32_t)(1 + i), nonce, block);
        size_t chunk = std::min<size_t>(64, ct.size() - i * 64);
        for (size_t j = 0; j < chunk; ++j) pt[i*64 + j] = ct[i*64 + j] ^ block[j];
    }
    return true;
}

#endif // JP_MUSA

} // namespace jpssl
