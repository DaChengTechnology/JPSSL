/**
 * aes_gcm_vaes.cpp — VAES 加速 AES-GCM（256-bit VAES + PCLMULQDQ）
 *
 * 关键技术：
 *   - VAES（Vector AES）：一条 vaesenc/vaesenclast 指令同时处理 2 个
 *     128-bit 块（256-bit YMM），AES-NI 只处理 1 块 → AES 吞吐约 2x
 *   - 4 路并行：2 个 YMM 寄存器 = 4 块/组
 *   - PCLMULQDQ + 4 路并行 GHASH（H^1..H^4，Gueron 方案）
 *
 * 与 AVX512 后端的区别：
 *   AVX512 VAES（ZMM，8 块）需要完整 AVX512F；而 VEX.256 编码的 VAES
 *   只要求 VAES + AVX，不要求 AVX512F/VL。Alder Lake / Raptor Lake
 *   等消费级 CPU 熔断了 AVX512 但仍支持 256-bit VAES + VPCLMULQDQ，
 *   本后端让这类机器也能用上向量化 AES。
 *
 * 实现方式：VAES 指令用内联汇编（GCC/Clang 的 _mm256_aesenc_epi128
 * 内在函数被 -mavx512vl 守卫，直接启用会令编译器输出 AVX512 指令，
 * 在无 AVX512 的 CPU 上 SIGILL）。编译参数见 CMakeLists：
 *   -mavx2 -maes -mpclmul -mvaes
 *
 * 运行时检测：cpu_has_avx2() && cpu_has_vpclmulqdq_vaes() && cpu_has_aesni()
 */

#include "cipher_inplace.hpp"
#include "cpu_features.hpp"
#include <cstring>
#include <algorithm>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <immintrin.h>
#endif

namespace jpssl {
namespace {

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))

// ═══════════════════════════════════════════════════════════════════════
//  GF(2^128) 乘法 / GHASH（与 aes_gcm_avx2.cpp 相同，已验证）
// ═══════════════════════════════════════════════════════════════════════

static inline __m128i gcm_gf128_mul(__m128i a, __m128i b) {
    __m128i t0 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i t1 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i t2 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i t3 = _mm_clmulepi64_si128(a, b, 0x10);
    t2 = _mm_xor_si128(t2, t3);
    t3 = _mm_slli_si128(t2, 8);
    t2 = _mm_srli_si128(t2, 8);
    t0 = _mm_xor_si128(t0, t3);
    t1 = _mm_xor_si128(t1, t2);

    __m128i r = _mm_set_epi64x(0, 0x87);
    __m128i q1 = _mm_clmulepi64_si128(t1, r, 0x01);
    t0 = _mm_xor_si128(t0, _mm_clmulepi64_si128(t1, r, 0x00));
    t0 = _mm_xor_si128(t0, _mm_slli_si128(q1, 8));
    q1 = _mm_srli_si128(q1, 8);
    t0 = _mm_xor_si128(t0, _mm_clmulepi64_si128(q1, r, 0x00));
    return t0;
}

/// 逐字节位反转（NIST bit-reflected 字节序 ↔ 自然多项式基）
/// 注意高低半字节位置互换：bitrev(b) = rev4(高半字节) | rev4(低半字节)<<4
static inline __m128i gcm_bitrev(__m128i v) {
    const __m128i rev_lo = _mm_set_epi8(15,7,11,3,13,5,9,1,14,6,10,2,12,4,8,0);
    const __m128i rev_hi = _mm_set_epi8(0xF0,0x70,0xB0,0x30,0xD0,0x50,0x90,0x10,
                                        0xE0,0x60,0xA0,0x20,0xC0,0x40,0x80,0x00);
    __m128i lo = _mm_and_si128(v, _mm_set1_epi8(0x0F));
    __m128i hi = _mm_and_si128(_mm_srli_epi16(v, 4), _mm_set1_epi8(0x0F));
    return _mm_or_si128(_mm_shuffle_epi8(rev_lo, hi), _mm_shuffle_epi8(rev_hi, lo));
}

static inline __m128i gcm_ghash_core(__m128i state, __m128i block, __m128i H) {
    return gcm_gf128_mul(_mm_xor_si128(state, block), H);
}

/// 一条 ymm vpclmulqdq 指令同时做两个独立的 128-bit 无进位乘法（逐 lane）
template <int imm>
static inline __m256i vpclmul_2lane(__m256i a, __m256i b) {
    __m256i r;
    __asm__ __volatile__("vpclmulqdq %3, %2, %1, %0" : "=x"(r) : "x"(a), "x"(b), "i"(imm));
    return r;
}

/// GCM counter 每 lane 的 32 位 big-endian 字段 +8（进位安全）
/// dword3 存 big-endian 字节反转值：先 32 位 bswap 成小端整数，+8 的
/// 进位自然传播（255→256 时进到次高字节），再 bswap 还原
static inline __m256i counter_add8(__m256i v) {
    const __m256i bs = _mm256_set_epi8(
        28,29,30,31, 24,25,26,27, 20,21,22,23, 16,17,18,19,
        12,13,14,15,  8, 9,10,11,  4, 5, 6, 7,  0, 1, 2, 3);
    __m256i s = _mm256_shuffle_epi8(v, bs);
    s = _mm256_add_epi32(s, _mm256_set_epi32(8, 0, 0, 0, 8, 0, 0, 0));  // e7/e3 = 每 lane 的 dword3 +8
    return _mm256_shuffle_epi8(s, bs);
}

/// 逐 lane 64-bit 移位（permute + mask；imm 位序：result[i] = v[imm[2i+1:2i]]）
static inline __m256i lane_sll64(__m256i v) {
    return _mm256_and_si256(_mm256_permute4x64_epi64(v, 0xA0),
                            _mm256_set_epi64x(-1, 0, -1, 0));
}
static inline __m256i lane_srl64(__m256i v) {
    return _mm256_and_si256(_mm256_permute4x64_epi64(v, 0xF5),
                            _mm256_set_epi64x(0, -1, 0, -1));
}

/// 2-lane 自然域 GF(2^128) 乘法：lane0 = a0·b0, lane1 = a1·b1（各自完整约简）
/// 与 128-bit gcm_gf128_mul 在 20 万随机输入上逐 lane 验证一致
static inline __m256i gcm_gf128_mul_2lane(__m256i a, __m256i b) {
    __m256i t0 = vpclmul_2lane<0x00>(a, b);
    __m256i t1 = vpclmul_2lane<0x11>(a, b);
    __m256i t2 = vpclmul_2lane<0x01>(a, b);
    __m256i t3 = vpclmul_2lane<0x10>(a, b);
    __m256i m = _mm256_xor_si256(t2, t3);
    t0 = _mm256_xor_si256(t0, lane_sll64(m));
    t1 = _mm256_xor_si256(t1, lane_srl64(m));

    __m256i r = _mm256_set_epi64x(0, 0x87, 0, 0x87);
    __m256i q1 = vpclmul_2lane<0x01>(t1, r);   // 每 lane: t1_hi·R_lo
    t0 = _mm256_xor_si256(t0, vpclmul_2lane<0x00>(t1, r));
    t0 = _mm256_xor_si256(t0, lane_sll64(q1));
    q1 = lane_srl64(q1);
    t0 = _mm256_xor_si256(t0, vpclmul_2lane<0x00>(q1, r));
    return t0;
}

/// 4 路并行 GHASH：S' = (S^X1)·H^4 ^ X2·H^3 ^ X3·H^2 ^ X4·H
/// 四个乘积打包成两个 2-lane 乘法（vpclmulqdq ymm），clmul 指令数减半
static inline __m128i gcm_ghash4(__m128i state, __m128i b0, __m128i b1,
                                 __m128i b2, __m128i b3,
                                 __m128i H, __m128i H2, __m128i H3, __m128i H4) {
    __m256i r0 = gcm_gf128_mul_2lane(_mm256_set_m128i(b1, _mm_xor_si128(state, b0)),
                                     _mm256_set_m128i(H3, H4));
    __m256i r1 = gcm_gf128_mul_2lane(_mm256_set_m128i(b3, b2),
                                     _mm256_set_m128i(H, H2));
    __m256i acc = _mm256_xor_si256(r0, r1);
    return _mm_xor_si128(_mm256_extracti128_si256(acc, 0),
                         _mm256_extracti128_si256(acc, 1));
}

// ═══════════════════════════════════════════════════════════════════════
//  256-bit VAES：4 块并行（2 个 YMM，每个含 2 个 128-bit 块）
// ═══════════════════════════════════════════════════════════════════════

/// 对两个 YMM（各 2 块，共 4 块）做一轮 AES 加密
static inline void vaes_encrypt_4blocks(__m256i& b0, __m256i& b1,
                                        const __m128i* rk, int rounds) {
    __m256i r0 = _mm256_broadcastsi128_si256(rk[0]);
    b0 = _mm256_xor_si256(b0, r0);
    b1 = _mm256_xor_si256(b1, r0);
    for (int r = 1; r < rounds; ++r) {
        __m256i rr = _mm256_broadcastsi128_si256(rk[r]);
        __asm__ __volatile__("vaesenc %2, %1, %0" : "+x"(b0) : "x"(b0), "x"(rr));
        __asm__ __volatile__("vaesenc %2, %1, %0" : "+x"(b1) : "x"(b1), "x"(rr));
    }
    __m256i rr = _mm256_broadcastsi128_si256(rk[rounds]);
    __asm__ __volatile__("vaesenclast %2, %1, %0" : "+x"(b0) : "x"(b0), "x"(rr));
    __asm__ __volatile__("vaesenclast %2, %1, %0" : "+x"(b1) : "x"(b1), "x"(rr));
}

/// 对 4 个 YMM（8 个 128-bit 块）做一轮 AES 加密（VAES，4 路并行）
static inline void vaes_encrypt_8blocks(__m256i& b0, __m256i& b1, __m256i& b2,
                                        __m256i& b3, const __m128i* rk, int rounds) {
    __m256i r0 = _mm256_broadcastsi128_si256(rk[0]);
    b0 = _mm256_xor_si256(b0, r0);
    b1 = _mm256_xor_si256(b1, r0);
    b2 = _mm256_xor_si256(b2, r0);
    b3 = _mm256_xor_si256(b3, r0);
    for (int r = 1; r < rounds; ++r) {
        __m256i rr = _mm256_broadcastsi128_si256(rk[r]);
        __asm__ __volatile__("vaesenc %2, %1, %0" : "+x"(b0) : "x"(b0), "x"(rr));
        __asm__ __volatile__("vaesenc %2, %1, %0" : "+x"(b1) : "x"(b1), "x"(rr));
        __asm__ __volatile__("vaesenc %2, %1, %0" : "+x"(b2) : "x"(b2), "x"(rr));
        __asm__ __volatile__("vaesenc %2, %1, %0" : "+x"(b3) : "x"(b3), "x"(rr));
    }
    __m256i rr = _mm256_broadcastsi128_si256(rk[rounds]);
    __asm__ __volatile__("vaesenclast %2, %1, %0" : "+x"(b0) : "x"(b0), "x"(rr));
    __asm__ __volatile__("vaesenclast %2, %1, %0" : "+x"(b1) : "x"(b1), "x"(rr));
    __asm__ __volatile__("vaesenclast %2, %1, %0" : "+x"(b2) : "x"(b2), "x"(rr));
    __asm__ __volatile__("vaesenclast %2, %1, %0" : "+x"(b3) : "x"(b3), "x"(rr));
}

// ═══════════════════════════════════════════════════════════════════════
//  Counter / J0 辅助
// ═══════════════════════════════════════════════════════════════════════

static inline __m128i inc_counter_1(__m128i c) {
    uint32_t lo = __builtin_bswap32((uint32_t)_mm_extract_epi32(c, 3));
    ++lo;
    return _mm_insert_epi32(c, (int)__builtin_bswap32(lo), 3);
}

static inline __m128i inc_counter_n(__m128i c, int n) {
    uint32_t lo = __builtin_bswap32((uint32_t)_mm_extract_epi32(c, 3));
    lo += (uint32_t)n;
    return _mm_insert_epi32(c, (int)__builtin_bswap32(lo), 3);
}

static inline void store_be64_vaes(uint8_t buf[8], uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        buf[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

/// 构建 J0（H 为自然域，J0 输出 NIST 字节序）
static void build_j0_vaes(const uint8_t* iv, size_t iv_len, __m128i H, uint8_t J0[16]) {
    if (iv_len == 12) {
        J0[12] = J0[13] = J0[14] = 0;
        std::memcpy(J0, iv, 12);
        J0[15] = 0x01;
    } else {
        __m128i state = _mm_setzero_si128();
        size_t pos = 0;
        while (pos + 16 <= iv_len) {
            __m128i block = gcm_bitrev(_mm_loadu_si128((const __m128i*)(iv + pos)));
            state = gcm_ghash_core(state, block, H);
            pos += 16;
        }
        if (pos < iv_len) {
            uint8_t last[16] = {};
            std::memcpy(last, iv + pos, iv_len - pos);
            state = gcm_ghash_core(state,
                                   gcm_bitrev(_mm_loadu_si128((const __m128i*)last)), H);
        }
        uint8_t len_block[16] = {};
        store_be64_vaes(len_block + 8, iv_len * 8);
        state = gcm_ghash_core(
            state, gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block)), H);
        _mm_storeu_si128((__m128i*)J0, gcm_bitrev(state));
    }
}

/// 4 路并行批量 GHASH（64 字节组走 gcm_ghash4，尾部逐块）
static void ghash_bulk_4way(__m128i& state, const uint8_t* data, size_t len,
                            __m128i H, __m128i H2, __m128i H3, __m128i H4) {
    size_t pos = 0;
    while (pos + 64 <= len) {
        __m128i b0 = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos)));
        __m128i b1 = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos + 16)));
        __m128i b2 = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos + 32)));
        __m128i b3 = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos + 48)));
        state = gcm_ghash4(state, b0, b1, b2, b3, H, H2, H3, H4);
        pos += 64;
    }
    while (pos + 16 <= len) {
        __m128i block = gcm_bitrev(_mm_loadu_si128((const __m128i*)(data + pos)));
        state = gcm_ghash_core(state, block, H);
        pos += 16;
    }
    if (pos < len) {
        uint8_t last[16] = {};
        std::memcpy(last, data + pos, len - pos);
        state = gcm_ghash_core(state,
                               gcm_bitrev(_mm_loadu_si128((const __m128i*)last)), H);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  VAES GCM 加密
// ═══════════════════════════════════════════════════════════════════════

/// 就地/直写加密核心：密文写入 out（容量 >= plaintext.size()），
/// 允许 out 与 plaintext 指向同一缓冲（先读后写，按组 load-then-store）。
static void vaes_gcm_encrypt_impl(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  std::span<const uint8_t> plaintext,
                                  std::span<const uint8_t> aad,
                                  uint8_t* out,
                                  uint8_t* tag, size_t tag_len) {

    const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
    int rounds = ctx.rounds;

    // 1. H = AES_encrypt(K, 0^128)，转自然域
    __m128i zero = _mm_setzero_si128();
    __m128i H = zero;
    H = _mm_xor_si128(H, rk[0]);
    for (int r = 1; r < rounds; ++r) H = _mm_aesenc_si128(H, rk[r]);
    H = _mm_aesenclast_si128(H, rk[rounds]);
    __m128i Hr = gcm_bitrev(H);
    __m128i H2 = gcm_gf128_mul(Hr, Hr);
    __m128i H3 = gcm_gf128_mul(H2, Hr);
    __m128i H4 = gcm_gf128_mul(H3, Hr);

    // 2. J0
    uint8_t J0_buf[16];
    build_j0_vaes(iv, iv_len, Hr, J0_buf);
    __m128i J0 = _mm_loadu_si128((const __m128i*)J0_buf);

    // 3. GHASH AAD
    __m128i ghash_state = _mm_setzero_si128();
    if (!aad.empty()) {
        ghash_bulk_4way(ghash_state, aad.data(), aad.size(), Hr, H2, H3, H4);
    }

    // 4. CTR 加密（4 块并行，2 个 YMM）+ GHASH 密文（直写 out）
    size_t num_blocks = (plaintext.size() + 15) / 16;
    size_t num_blocks8 = (plaintext.size() / 128) * 8;  // 完整 128 字节组（8 块）

    // 8 个 counter → 4 个 YMM（每 YMM 2 个 128-bit 块）。每 lane 的末 dword 即
    // GCM big-endian 计数器的低 4 字节，整体 +8 不越 32 位边界（GCM 2^32 限制内）
    __m128i c0 = inc_counter_1(J0);
    __m128i c1 = inc_counter_1(c0);
    __m128i c2 = inc_counter_1(c1);
    __m128i c3 = inc_counter_1(c2);
    __m128i c4 = inc_counter_1(c3);
    __m128i c5 = inc_counter_1(c4);
    __m128i c6 = inc_counter_1(c5);
    __m128i c7 = inc_counter_1(c6);
    __m256i yc[4] = {
        _mm256_set_m128i(c1, c0),
        _mm256_set_m128i(c3, c2),
        _mm256_set_m128i(c5, c4),
        _mm256_set_m128i(c7, c6),
    };

    size_t i = 0;
    __m256i ct0, ct1, ct2, ct3;  // 上一组密文（YMM 形式）
    auto enc_group = [&](size_t off) {
        __m256i t0 = yc[0], t1 = yc[1], t2 = yc[2], t3 = yc[3];  // 拷贝 counter
        vaes_encrypt_8blocks(t0, t1, t2, t3, rk, rounds);
        const uint8_t* p = plaintext.data() + off * 16;
        __m256i p0 = _mm256_loadu_si256((const __m256i*)(p));
        __m256i p1 = _mm256_loadu_si256((const __m256i*)(p + 32));
        __m256i p2 = _mm256_loadu_si256((const __m256i*)(p + 64));
        __m256i p3 = _mm256_loadu_si256((const __m256i*)(p + 96));
        ct0 = _mm256_xor_si256(p0, t0);
        ct1 = _mm256_xor_si256(p1, t1);
        ct2 = _mm256_xor_si256(p2, t2);
        ct3 = _mm256_xor_si256(p3, t3);
        uint8_t* co = out + off * 16;
        _mm256_storeu_si256((__m256i*)(co), ct0);
        _mm256_storeu_si256((__m256i*)(co + 32), ct1);
        _mm256_storeu_si256((__m256i*)(co + 64), ct2);
        _mm256_storeu_si256((__m256i*)(co + 96), ct3);
    };
    auto ghash_group = [&]() {
        __m128i b0 = _mm256_extracti128_si256(ct0, 0);
        __m128i b1 = _mm256_extracti128_si256(ct0, 1);
        __m128i b2 = _mm256_extracti128_si256(ct1, 0);
        __m128i b3 = _mm256_extracti128_si256(ct1, 1);
        __m128i b4 = _mm256_extracti128_si256(ct2, 0);
        __m128i b5 = _mm256_extracti128_si256(ct2, 1);
        __m128i b6 = _mm256_extracti128_si256(ct3, 0);
        __m128i b7 = _mm256_extracti128_si256(ct3, 1);
        ghash_state = gcm_ghash4(ghash_state, gcm_bitrev(b0), gcm_bitrev(b1),
                                 gcm_bitrev(b2), gcm_bitrev(b3), Hr, H2, H3, H4);
        ghash_state = gcm_ghash4(ghash_state, gcm_bitrev(b4), gcm_bitrev(b5),
                                 gcm_bitrev(b6), gcm_bitrev(b7), Hr, H2, H3, H4);
    };

    // 软件流水：迭代内 GHASH(上一组密文) 与 AES(本组) 无数据依赖，
    // 由乱序执行重叠，隐藏 GHASH 乘法链与 AES 轮的互相等待
    if (num_blocks8 >= 8) {
        enc_group(0);
        i = 8;
    }
    for (; i + 8 <= num_blocks8; i += 8) {
        ghash_group();
        for (int k = 0; k < 4; ++k) yc[k] = counter_add8(yc[k]);
        enc_group(i);
    }
    if (num_blocks8 >= 8) ghash_group();  // 最后一组密文 → GHASH

    __m128i ctr = inc_counter_n(J0, (int)(i + 1));
    for (; i < num_blocks; ++i) {
        __m128i ks = ctr;
        ks = _mm_xor_si128(ks, rk[0]);
        for (int r = 1; r < rounds; ++r) ks = _mm_aesenc_si128(ks, rk[r]);
        ks = _mm_aesenclast_si128(ks, rk[rounds]);

        size_t offset = i * 16;
        size_t remain = plaintext.size() - offset;
        if (remain >= 16) {
            __m128i p = _mm_loadu_si128((const __m128i*)(plaintext.data() + offset));
            __m128i c = _mm_xor_si128(p, ks);
            _mm_storeu_si128((__m128i*)(out + offset), c);
            ghash_state = gcm_ghash_core(ghash_state, gcm_bitrev(c), Hr);
        } else {
            uint8_t ks_buf[16], ct_buf[16] = {};
            _mm_storeu_si128((__m128i*)ks_buf, ks);
            for (size_t j = 0; j < remain; ++j)
                ct_buf[j] = plaintext[offset + j] ^ ks_buf[j];
            std::memcpy(out + offset, ct_buf, remain);
            ghash_state = gcm_ghash_core(
                ghash_state, gcm_bitrev(_mm_loadu_si128((const __m128i*)ct_buf)), Hr);
        }
        ctr = inc_counter_1(ctr);
    }

    // 5. 最终 GHASH: len(AAD) || len(C)
    uint8_t len_block[16] = {};
    store_be64_vaes(len_block, aad.size() * 8);
    store_be64_vaes(len_block + 8, plaintext.size() * 8);
    ghash_state = gcm_ghash_core(
        ghash_state, gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block)), Hr);
    ghash_state = gcm_bitrev(ghash_state);

    // 6. Tag = GHASH ^ E(K, J0)
    __m128i E_J0 = J0;
    E_J0 = _mm_xor_si128(E_J0, rk[0]);
    for (int r = 1; r < rounds; ++r) E_J0 = _mm_aesenc_si128(E_J0, rk[r]);
    E_J0 = _mm_aesenclast_si128(E_J0, rk[rounds]);

    __m128i tag_val = _mm_xor_si128(ghash_state, E_J0);
    uint8_t tag_buf[16];
    _mm_storeu_si128((__m128i*)tag_buf, tag_val);
    std::memcpy(tag, tag_buf, tag_len);
}

// ═══════════════════════════════════════════════════════════════════════
//  VAES GCM 解密
// ═══════════════════════════════════════════════════════════════════════

/// 就地/直写解密核心：明文写入 out（容量 >= ciphertext.size()），
/// 允许 out 与 ciphertext 指向同一缓冲（先验标签后按组 load-then-store）。
static bool vaes_gcm_decrypt_impl(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  std::span<const uint8_t> ciphertext,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len,
                                  uint8_t* out) {

    const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
    int rounds = ctx.rounds;

    __m128i zero = _mm_setzero_si128();
    __m128i H = zero;
    H = _mm_xor_si128(H, rk[0]);
    for (int r = 1; r < rounds; ++r) H = _mm_aesenc_si128(H, rk[r]);
    H = _mm_aesenclast_si128(H, rk[rounds]);
    __m128i Hr = gcm_bitrev(H);
    __m128i H2 = gcm_gf128_mul(Hr, Hr);
    __m128i H3 = gcm_gf128_mul(H2, Hr);
    __m128i H4 = gcm_gf128_mul(H3, Hr);

    uint8_t J0_buf[16];
    build_j0_vaes(iv, iv_len, Hr, J0_buf);
    __m128i J0 = _mm_loadu_si128((const __m128i*)J0_buf);

    // 先验证标签（GHASH AAD + 密文 + len）
    __m128i ghash_state = _mm_setzero_si128();
    if (!aad.empty()) {
        ghash_bulk_4way(ghash_state, aad.data(), aad.size(), Hr, H2, H3, H4);
    }
    ghash_bulk_4way(ghash_state, ciphertext.data(), ciphertext.size(), Hr, H2, H3, H4);

    uint8_t len_block[16] = {};
    store_be64_vaes(len_block, aad.size() * 8);
    store_be64_vaes(len_block + 8, ciphertext.size() * 8);
    ghash_state = gcm_ghash_core(
        ghash_state, gcm_bitrev(_mm_loadu_si128((const __m128i*)len_block)), Hr);
    ghash_state = gcm_bitrev(ghash_state);

    __m128i E_J0 = J0;
    E_J0 = _mm_xor_si128(E_J0, rk[0]);
    for (int r = 1; r < rounds; ++r) E_J0 = _mm_aesenc_si128(E_J0, rk[r]);
    E_J0 = _mm_aesenclast_si128(E_J0, rk[rounds]);

    __m128i expected_tag = _mm_xor_si128(ghash_state, E_J0);
    uint8_t expected_buf[16], actual_buf[16] = {};
    _mm_storeu_si128((__m128i*)expected_buf, expected_tag);
    std::memcpy(actual_buf, tag, tag_len);
    uint8_t diff = 0;
    for (size_t j = 0; j < tag_len; ++j)
        diff |= expected_buf[j] ^ actual_buf[j];
    if (diff != 0) return false;

    // 解密（CTR，直写 out）
    size_t num_blocks = (ciphertext.size() + 15) / 16;
    size_t num_blocks8 = (ciphertext.size() / 128) * 8;

    __m128i c0 = inc_counter_1(J0);
    __m128i c1 = inc_counter_1(c0);
    __m128i c2 = inc_counter_1(c1);
    __m128i c3 = inc_counter_1(c2);
    __m128i c4 = inc_counter_1(c3);
    __m128i c5 = inc_counter_1(c4);
    __m128i c6 = inc_counter_1(c5);
    __m128i c7 = inc_counter_1(c6);
    __m256i yc[4] = {
        _mm256_set_m128i(c1, c0),
        _mm256_set_m128i(c3, c2),
        _mm256_set_m128i(c5, c4),
        _mm256_set_m128i(c7, c6),
    };

    size_t i = 0;
    for (; i + 8 <= num_blocks8; i += 8) {
        __m256i t0 = yc[0], t1 = yc[1], t2 = yc[2], t3 = yc[3];  // 拷贝 counter
        vaes_encrypt_8blocks(t0, t1, t2, t3, rk, rounds);
        const uint8_t* ct = ciphertext.data() + i * 16;
        __m256i c0v = _mm256_loadu_si256((const __m256i*)(ct));
        __m256i c1v = _mm256_loadu_si256((const __m256i*)(ct + 32));
        __m256i c2v = _mm256_loadu_si256((const __m256i*)(ct + 64));
        __m256i c3v = _mm256_loadu_si256((const __m256i*)(ct + 96));
        __m256i p0 = _mm256_xor_si256(c0v, t0);
        __m256i p1 = _mm256_xor_si256(c1v, t1);
        __m256i p2 = _mm256_xor_si256(c2v, t2);
        __m256i p3 = _mm256_xor_si256(c3v, t3);
        uint8_t* po = out + i * 16;
        _mm256_storeu_si256((__m256i*)(po), p0);
        _mm256_storeu_si256((__m256i*)(po + 32), p1);
        _mm256_storeu_si256((__m256i*)(po + 64), p2);
        _mm256_storeu_si256((__m256i*)(po + 96), p3);
        for (int k = 0; k < 4; ++k) yc[k] = counter_add8(yc[k]);
    }

    __m128i ctr = inc_counter_n(J0, (int)(i + 1));
    for (; i < num_blocks; ++i) {
        __m128i ks = ctr;
        ks = _mm_xor_si128(ks, rk[0]);
        for (int r = 1; r < rounds; ++r) ks = _mm_aesenc_si128(ks, rk[r]);
        ks = _mm_aesenclast_si128(ks, rk[rounds]);

        size_t offset = i * 16;
        size_t remain = ciphertext.size() - offset;
        if (remain >= 16) {
            __m128i c = _mm_loadu_si128((const __m128i*)(ciphertext.data() + offset));
            __m128i p = _mm_xor_si128(c, ks);
            _mm_storeu_si128((__m128i*)(out + offset), p);
        } else {
            uint8_t ks_buf[16], pt_buf[16] = {};
            _mm_storeu_si128((__m128i*)ks_buf, ks);
            for (size_t j = 0; j < remain; ++j)
                pt_buf[j] = ciphertext[offset + j] ^ ks_buf[j];
            std::memcpy(out + offset, pt_buf, remain);
        }
        ctr = inc_counter_1(ctr);
    }

    return true;
}

#endif // __x86_64__ && (GNUC || clang)

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════
//  公开接口
// ═══════════════════════════════════════════════════════════════════════

/// 运行时检测：AVX2 + VAES + VPCLMULQDQ + AES-NI（一次性）
static bool vaes_gcm_available() {
    static const bool ready = [] {
        return cpu_has_avx2() && cpu_has_vpclmulqdq_vaes() && cpu_has_aesni();
    }();
    return ready;
}

void aes_gcm_encrypt_vaes(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> plaintext,
                          std::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len) {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    if (vaes_gcm_available()) {
        ciphertext.resize(plaintext.size());
        vaes_gcm_encrypt_impl(ctx, iv, iv_len, plaintext, aad, ciphertext.data(),
                              tag, tag_len);
        return;
    }
#endif
    aes_gcm_encrypt(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
}

bool aes_gcm_decrypt_vaes(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          std::span<const uint8_t> ciphertext,
                          std::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext) {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    if (vaes_gcm_available()) {
        plaintext.resize(ciphertext.size());
        return vaes_gcm_decrypt_impl(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                                     plaintext.data());
    }
#endif
    return aes_gcm_decrypt(ctx, iv, iv_len, ciphertext, aad, tag, tag_len, plaintext);
}

/// 就地加密：buf 同时作为明文输入与密文输出（容量 >= data_len）
void aes_gcm_encrypt_vaes_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len) {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    if (vaes_gcm_available()) {
        vaes_gcm_encrypt_impl(ctx, iv, iv_len,
                              std::span<const uint8_t>(buf, data_len), aad, buf,
                              tag, tag_len);
        return;
    }
#endif
    // 回退：临时向量（无 VAES 机器，仅保证正确性）
    std::vector<uint8_t> ct(data_len);
    aes_gcm_encrypt(ctx, iv, iv_len, std::span<const uint8_t>(buf, data_len), aad,
                    ct, tag, tag_len);
    std::memcpy(buf, ct.data(), data_len);
}

/// 就地解密：buf 同时作为密文输入与明文输出（容量 >= data_len）
bool aes_gcm_decrypt_vaes_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len) {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    if (vaes_gcm_available()) {
        return vaes_gcm_decrypt_impl(ctx, iv, iv_len,
                                     std::span<const uint8_t>(buf, data_len), aad,
                                     tag, tag_len, buf);
    }
#endif
    std::vector<uint8_t> pt(data_len);
    bool ok = aes_gcm_decrypt(ctx, iv, iv_len,
                              std::span<const uint8_t>(buf, data_len), aad,
                              tag, tag_len, pt);
    if (ok) std::memcpy(buf, pt.data(), data_len);
    return ok;
}

} // namespace jpssl
