/**
 * aes_cpu.cpp — CPU 端 AES-128/192/256 实现
 *
 * 包含：
 *   - 密钥扩展（Key Expansion）
 *   - 单个块加密/解密
 *   - ECB 模式批量加密/解密
 *   - GCM 模式（AES-NI CTR + PCLMULQDQ GHASH 加速）
 */

#include "aes.hpp"
#include "cpu_features.hpp"
#include <cstring>

#ifdef __x86_64__
#include <wmmintrin.h>  // AES-NI, PCLMULQDQ intrinsics
#include <emmintrin.h>   // SSE2
#include <smmintrin.h>   // SSE4.1 (_mm_extract_epi32, _mm_insert_epi32)
#endif

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  AES-NI 硬件加速实现（x86_64 only）
// ═══════════════════════════════════════════════════════════════════════

#ifdef __x86_64__

/// AES-NI 单块加密
static void aesni_encrypt_block(const aes_context& ctx,
                                const uint8_t plain[16], uint8_t cipher[16]) {
    __m128i state = _mm_loadu_si128((const __m128i*)plain);
    const __m128i* rk = (const __m128i*)ctx.enc_rk.data();

    state = _mm_xor_si128(state, rk[0]);
    for (int r = 1; r < ctx.rounds; ++r)
        state = _mm_aesenc_si128(state, rk[r]);
    state = _mm_aesenclast_si128(state, rk[ctx.rounds]);

    _mm_storeu_si128((__m128i*)cipher, state);
}

/// AES-NI 单块解密
static void aesni_decrypt_block(const aes_context& ctx,
                                const uint8_t cipher[16], uint8_t plain[16]) {
    __m128i state = _mm_loadu_si128((const __m128i*)cipher);
    const __m128i* rk = (const __m128i*)ctx.dec_rk_aesni.data();

    state = _mm_xor_si128(state, rk[0]);
    for (int r = 1; r < ctx.rounds; ++r)
        state = _mm_aesdec_si128(state, rk[r]);
    state = _mm_aesdeclast_si128(state, rk[ctx.rounds]);

    _mm_storeu_si128((__m128i*)plain, state);
}

/// AES-NI 密钥扩展辅助（通过 switch 展开立即数）
static inline __m128i aesni_key_expand(__m128i key, int rcon) {
    __m128i t;
    switch (rcon) {
        case 0x01: t = _mm_aeskeygenassist_si128(key, 0x01); break;
        case 0x02: t = _mm_aeskeygenassist_si128(key, 0x02); break;
        case 0x04: t = _mm_aeskeygenassist_si128(key, 0x04); break;
        case 0x08: t = _mm_aeskeygenassist_si128(key, 0x08); break;
        case 0x10: t = _mm_aeskeygenassist_si128(key, 0x10); break;
        case 0x20: t = _mm_aeskeygenassist_si128(key, 0x20); break;
        case 0x40: t = _mm_aeskeygenassist_si128(key, 0x40); break;
        case 0x80: t = _mm_aeskeygenassist_si128(key, 0x80); break;
        case 0x1B: t = _mm_aeskeygenassist_si128(key, 0x1B); break;
        case 0x36: t = _mm_aeskeygenassist_si128(key, 0x36); break;
        default: t = _mm_aeskeygenassist_si128(key, 0x01); break;
    }
    t = _mm_shuffle_epi32(t, 0xFF);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, t);
}

/// AES-NI 密钥扩展（AES-128）
static void aesni_key_expansion_128(const uint8_t key[16], uint8_t rk_buf[176]) {
    __m128i* rk = (__m128i*)rk_buf;
    rk[0] = _mm_loadu_si128((const __m128i*)key);
    rk[1] = aesni_key_expand(rk[0], 0x01);
    rk[2] = aesni_key_expand(rk[1], 0x02);
    rk[3] = aesni_key_expand(rk[2], 0x04);
    rk[4] = aesni_key_expand(rk[3], 0x08);
    rk[5] = aesni_key_expand(rk[4], 0x10);
    rk[6] = aesni_key_expand(rk[5], 0x20);
    rk[7] = aesni_key_expand(rk[6], 0x40);
    rk[8] = aesni_key_expand(rk[7], 0x80);
    rk[9] = aesni_key_expand(rk[8], 0x1B);
    rk[10] = aesni_key_expand(rk[9], 0x36);
}

/// AES-NI 密钥扩展（AES-192）
static void aesni_key_expansion_192(const uint8_t key[24], uint8_t rk_buf[208]) {
    __m128i* rk = (__m128i*)rk_buf;
    rk[0] = _mm_loadu_si128((const __m128i*)key);
    // 加载后 8 字节作为第二个 128-bit 的前半部分
    __m128i tmp = _mm_loadu_si128((const __m128i*)(key + 8));
    // 将 tmp 的低 64-bit 移到 rk[1] 的低 64-bit
    rk[1] = _mm_set_epi64x(0, _mm_extract_epi64(tmp, 0));

    // AES-192: 密钥扩展需要 8 轮（生成 13 个 128-bit 轮密钥）
    // 使用 6-word 密钥调度
    int rcons[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    for (int i = 0; i < 8; ++i) {
        __m128i t = _mm_aeskeygenassist_si128(rk[i], rcons[i]);
        t = _mm_shuffle_epi32(t, 0x55);  // 广播 word 1 到所有位置
        rk[i + 1] = _mm_xor_si128(rk[i + 1], _mm_slli_si128(rk[i + 1], 4));
        rk[i + 1] = _mm_xor_si128(rk[i + 1], _mm_slli_si128(rk[i + 1], 4));
        rk[i + 1] = _mm_xor_si128(rk[i + 1], _mm_slli_si128(rk[i + 1], 4));
        rk[i + 1] = _mm_xor_si128(rk[i + 1], t);

        // 对奇数索引，需要额外处理
        if (i < 7) {
            __m128i next = _mm_xor_si128(rk[i + 1], rk[i]);
            rk[i + 2] = _mm_slli_si128(next, 8);
            rk[i + 2] = _mm_xor_si128(rk[i + 2], _mm_srli_si128(next, 8));
        }
    }
}

/// AES-NI 密钥扩展（AES-256）
static void aesni_key_expansion_256(const uint8_t key[32], uint8_t rk_buf[240]) {
    __m128i* rk = (__m128i*)rk_buf;
    rk[0] = _mm_loadu_si128((const __m128i*)key);
    rk[1] = _mm_loadu_si128((const __m128i*)(key + 16));

    int rcons[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};
    for (int i = 0; i < 7; ++i) {
        // 偶数轮：标准扩展
        __m128i t = _mm_aeskeygenassist_si128(rk[i * 2 + 1], rcons[i]);
        t = _mm_shuffle_epi32(t, 0xFF);
        __m128i k = rk[i * 2];
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        rk[i * 2 + 2] = _mm_xor_si128(k, t);

        // 奇数轮：SubWord 后 XOR
        t = _mm_aeskeygenassist_si128(rk[i * 2 + 2], 0x00);
        t = _mm_shuffle_epi32(t, 0xAA);
        k = rk[i * 2 + 1];
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        rk[i * 2 + 3] = _mm_xor_si128(k, t);
    }
}

/// AES-NI 生成解密轮密钥（对中间轮应用 _mm_aesimc_si128）
static void aesni_make_decrypt_keys(__m128i* dec_rk, const __m128i* enc_rk, int rounds) {
    dec_rk[0] = enc_rk[rounds];
    for (int r = 1; r < rounds; ++r)
        dec_rk[r] = _mm_aesimc_si128(enc_rk[rounds - r]);
    dec_rk[rounds] = enc_rk[0];
}

// ═══════════════════════════════════════════════════════════════════════
//  PCLMULQDQ 加速 GF(2^128) 乘法（用于 GCM GHASH）
// ═══════════════════════════════════════════════════════════════════════

/// 使用 PCLMULQDQ 计算 GF(2^128) 乘法（无进位乘法 + 模约简）
/// 不可约多项式：x^128 + x^7 + x^2 + x + 1
/// bit-reflected 约简常数：R = 0xE1 << 120 → 0x87
static inline __m128i pclmul_gf128_mul(__m128i a, __m128i b) {
    __m128i t0 = _mm_clmulepi64_si128(a, b, 0x00);  // a[0] * b[0]
    __m128i t1 = _mm_clmulepi64_si128(a, b, 0x11);  // a[1] * b[1]
    __m128i t2 = _mm_clmulepi64_si128(a, b, 0x01);  // a[0] * b[1]
    __m128i t3 = _mm_clmulepi64_si128(a, b, 0x10);  // a[1] * b[0]

    t2 = _mm_xor_si128(t2, t3);
    t3 = _mm_slli_si128(t2, 8);
    t2 = _mm_srli_si128(t2, 8);
    t0 = _mm_xor_si128(t0, t3);
    t1 = _mm_xor_si128(t1, t2);

    // 模约简
    __m128i r = _mm_set_epi64x(0, 0x87);
    __m128i p = _mm_clmulepi64_si128(t1, r, 0x00);
    t0 = _mm_xor_si128(t0, p);

    __m128i hi = _mm_srli_si128(t0, 8);
    p = _mm_clmulepi64_si128(hi, r, 0x00);
    t0 = _mm_xor_si128(t0, p);

    return t0;
}

/// PCLMULQDQ 加速的 GHASH（替代软件 gf128_mul 逐位版本）
static void pclmul_ghash(const uint8_t H[16], std::span<const uint8_t> data, uint8_t out[16]) {
    __m128i Hv = _mm_loadu_si128((const __m128i*)H);
    __m128i state = _mm_setzero_si128();

    size_t pos = 0;
    size_t len = data.size();

    while (pos + 16 <= len) {
        __m128i block = _mm_loadu_si128((const __m128i*)(data.data() + pos));
        state = _mm_xor_si128(state, block);
        state = pclmul_gf128_mul(state, Hv);
        pos += 16;
    }

    if (pos < len) {
        uint8_t last[16] = {};
        std::memcpy(last, data.data() + pos, len - pos);
        state = _mm_xor_si128(state, _mm_loadu_si128((const __m128i*)last));
        state = pclmul_gf128_mul(state, Hv);
    }

    _mm_storeu_si128((__m128i*)out, state);
}

static bool g_use_aesni = false;
static bool g_use_pclmul = false;

#endif // __x86_64__

// ═══════════════════════════════════════════════════════════════════════
//  密钥扩展
// ═══════════════════════════════════════════════════════════════════════

static void rot_word(uint8_t* w) {
    uint8_t t = w[0];
    w[0] = w[1]; w[1] = w[2]; w[2] = w[3]; w[3] = t;
}

static void sub_word(uint8_t* w) {
    for (int i = 0; i < 4; ++i) w[i] = SBOX[w[i]];
}

void key_expansion(const uint8_t* key, AesKeySize ks, uint8_t* rk_buf) {
    int nk = static_cast<int>(ks) / 4;  // 密钥字数（4/6/8）
    int nr = aes_rounds(ks);            // 轮数（10/12/14）
    int total_words = 4 * (nr + 1);     // 总字数

    // 复制原始密钥
    std::memcpy(rk_buf, key, static_cast<size_t>(ks));

    uint8_t temp[4];
    for (int i = nk; i < total_words; ++i) {
        std::memcpy(temp, rk_buf + (i - 1) * 4, 4);

        if (i % nk == 0) {
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= RCON[i / nk];
        } else if (nk > 6 && i % nk == 4) {
            sub_word(temp);
        }

        for (int j = 0; j < 4; ++j) {
            rk_buf[i * 4 + j] = rk_buf[(i - nk) * 4 + j] ^ temp[j];
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  aes_context
// ═══════════════════════════════════════════════════════════════════════

void aes_context::init_impl(std::span<const uint8_t> key, AesKeySize ks) {
    key_size = ks;
    rounds    = aes_rounds(ks);

#ifdef __x86_64__
    // 检测 CPU 特性
    static bool detected = false;
    if (!detected) {
        g_use_aesni = cpu_has_aesni();
        g_use_pclmul = cpu_has_pclmulqdq();
        detected = true;
    }

    if (g_use_aesni) {
        switch (ks) {
            case AesKeySize::AES_128:
                aesni_key_expansion_128(key.data(), enc_rk.data());
                break;
            case AesKeySize::AES_192:
                aesni_key_expansion_192(key.data(), enc_rk.data());
                break;
            case AesKeySize::AES_256:
                aesni_key_expansion_256(key.data(), enc_rk.data());
                break;
        }
        // 软件格式 dec_rk（为 GPU/软件回退保留）
        for (int r = 0; r <= rounds; ++r)
            std::memcpy(dec_rk.data() + r*16, enc_rk.data() + (rounds-r)*16, 16);
        // AES-NI 格式 dec_rk_aesni（已应用 _mm_aesimc_si128）
        aesni_make_decrypt_keys((__m128i*)dec_rk_aesni.data(), (const __m128i*)enc_rk.data(), rounds);
        return;
    }
#endif

    // 软件回退
    key_expansion(key.data(), ks, enc_rk.data());
    for (int r = 0; r <= rounds; ++r) {
        std::memcpy(dec_rk.data() + r * 16,
                    enc_rk.data() + (rounds - r) * 16, 16);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  单块加密
// ═══════════════════════════════════════════════════════════════════════

void aes_encrypt_block(const aes_context& ctx,
                       const uint8_t plain[16],
                       uint8_t cipher[16]) {
#ifdef __x86_64__
    if (g_use_aesni) {
        aesni_encrypt_block(ctx, plain, cipher);
        return;
    }
#endif
    std::memcpy(cipher, plain, 16);
    const uint8_t* rk = ctx.enc_rk.data();

    // 初始轮密钥加
    add_round_key(cipher, rk);
    rk += 16;

    // 中间轮
    for (int r = 1; r < ctx.rounds; ++r) {
        sub_bytes(cipher);
        shift_rows(cipher);
        mix_columns(cipher);
        add_round_key(cipher, rk);
        rk += 16;
    }

    // 最后一轮（无 MixColumns）
    sub_bytes(cipher);
    shift_rows(cipher);
    add_round_key(cipher, rk);
}

// ═══════════════════════════════════════════════════════════════════════
//  单块解密
// ═══════════════════════════════════════════════════════════════════════

void aes_decrypt_block(const aes_context& ctx,
                       const uint8_t cipher[16],
                       uint8_t plain[16]) {
#ifdef __x86_64__
    if (g_use_aesni) {
        aesni_decrypt_block(ctx, cipher, plain);
        return;
    }
#endif
    std::memcpy(plain, cipher, 16);

    const uint8_t* rk = ctx.dec_rk.data();

    // 初始轮密钥加
    add_round_key(plain, rk);
    rk += 16;

    // 中间轮
    for (int r = 1; r < ctx.rounds; ++r) {
        inv_shift_rows(plain);
        inv_sub_bytes(plain);
        add_round_key(plain, rk);
        inv_mix_columns(plain);
        rk += 16;
    }

    // 最后一轮（无 InvMixColumns）
    inv_shift_rows(plain);
    inv_sub_bytes(plain);
    add_round_key(plain, rk);
}

// ═══════════════════════════════════════════════════════════════════════
//  ECB 模式批量加密/解密
// ═══════════════════════════════════════════════════════════════════════

void aes_encrypt_ecb(const aes_context& ctx,
                     std::span<const uint8_t> input,
                     std::span<uint8_t> output) {
    size_t n = input.size() / 16;
    for (size_t i = 0; i < n; ++i) {
        aes_encrypt_block(ctx, input.data() + i * 16, output.data() + i * 16);
    }
}

void aes_decrypt_ecb(const aes_context& ctx,
                     std::span<const uint8_t> input,
                     std::span<uint8_t> output) {
    size_t n = input.size() / 16;
    for (size_t i = 0; i < n; ++i) {
        aes_decrypt_block(ctx, input.data() + i * 16, output.data() + i * 16);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  PKCS7 填充 / 去填充
// ═══════════════════════════════════════════════════════════════════════

std::vector<uint8_t> pkcs7_pad(std::span<const uint8_t> data) {
    size_t pad_len = AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE);
    if (pad_len == 0) pad_len = AES_BLOCK_SIZE;  // 完整块时填充整个块

    std::vector<uint8_t> result;
    result.reserve(data.size() + pad_len);
    result.assign(data.begin(), data.end());
    result.insert(result.end(), pad_len, static_cast<uint8_t>(pad_len));
    return result;
}

std::vector<uint8_t> pkcs7_unpad(std::span<const uint8_t> data) {
    if (data.empty()) {
        throw std::runtime_error("PKCS7 unpad: empty data");
    }
    if (data.size() % AES_BLOCK_SIZE != 0) {
        throw std::runtime_error("PKCS7 unpad: data not block-aligned");
    }

    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > AES_BLOCK_SIZE) {
        throw std::runtime_error("PKCS7 unpad: invalid padding byte");
    }

    // 验证所有填充字节
    for (size_t i = 0; i < pad_len; ++i) {
        if (data[data.size() - 1 - i] != pad_len) {
            throw std::runtime_error("PKCS7 unpad: padding verification failed");
        }
    }

    return std::vector<uint8_t>(data.begin(), data.end() - pad_len);
}

// ═══════════════════════════════════════════════════════════════════════
//  CBC 模式
// ═══════════════════════════════════════════════════════════════════════

void aes_cbc_encrypt(const aes_context& ctx,
                     const uint8_t iv[16],
                     std::span<const uint8_t> plaintext,
                     std::vector<uint8_t>& ciphertext) {
    // PKCS7 填充
    auto padded = pkcs7_pad(plaintext);
    size_t num_blocks = padded.size() / AES_BLOCK_SIZE;

    ciphertext.resize(padded.size());

    uint8_t prev[16];
    std::memcpy(prev, iv, 16);

    for (size_t i = 0; i < num_blocks; ++i) {
        const uint8_t* pt_block = padded.data() + i * AES_BLOCK_SIZE;
        uint8_t*       ct_block = ciphertext.data() + i * AES_BLOCK_SIZE;

        // XOR with previous ciphertext (or IV)
        uint8_t xored[16];
        for (int j = 0; j < 16; ++j) xored[j] = pt_block[j] ^ prev[j];

        // Encrypt
        aes_encrypt_block(ctx, xored, ct_block);

        // Update previous
        std::memcpy(prev, ct_block, 16);
    }
}

bool aes_cbc_decrypt(const aes_context& ctx,
                     const uint8_t iv[16],
                     std::span<const uint8_t> ciphertext,
                     std::vector<uint8_t>& plaintext) {
    if (ciphertext.size() % AES_BLOCK_SIZE != 0) return false;

    size_t num_blocks = ciphertext.size() / AES_BLOCK_SIZE;
    std::vector<uint8_t> padded(num_blocks * AES_BLOCK_SIZE);

    const uint8_t* prev = iv;

    for (size_t i = 0; i < num_blocks; ++i) {
        const uint8_t* ct_block = ciphertext.data() + i * AES_BLOCK_SIZE;
        uint8_t*       pt_block = padded.data() + i * AES_BLOCK_SIZE;

        // Decrypt
        aes_decrypt_block(ctx, ct_block, pt_block);

        // XOR with previous ciphertext (or IV)
        for (int j = 0; j < 16; ++j) pt_block[j] ^= prev[j];

        prev = ct_block;
    }

    // PKCS7 去填充
    try {
        plaintext = pkcs7_unpad(padded);
        return true;
    } catch (const std::runtime_error&) {
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 辅助：GF(2^128) 乘法 & GHASH
// ═══════════════════════════════════════════════════════════════════════

/// 右移 128-bit 值（小端序，用于 bit-reflected GF(2^128) 乘法）
static void shr128_le(uint8_t x[16]) {
    uint8_t carry = 0;
    for (int i = 0; i < 16; ++i) {
        uint8_t new_carry = x[i] & 1;
        x[i] = (x[i] >> 1) | (carry << 7);
        carry = new_carry;
    }
}

/// 左移 128-bit 值
static void shl128(uint8_t x[16]) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        uint8_t new_carry = x[i] >> 7;
        x[i] = (x[i] << 1) | carry;
        carry = new_carry;
    }
}

/// XOR 两个 128-bit 值 src ^= other
static void xor128(uint8_t* dst, const uint8_t* src) {
    for (int i = 0; i < 16; ++i) dst[i] ^= src[i];
}

void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
#ifdef __x86_64__
    if (g_use_pclmul) {
        __m128i a = _mm_loadu_si128((const __m128i*)x);
        __m128i b = _mm_loadu_si128((const __m128i*)y);
        __m128i r = pclmul_gf128_mul(a, b);
        _mm_storeu_si128((__m128i*)out, r);
        return;
    }
#endif
    // GF(2^128) multiplication for GCM.
    // Bit-reflected (little-endian) representation: byte 0 bit 0 = x^0,
    // byte 15 bit 7 = x^127. Right-shift = multiply by x.
    // Irreducible polynomial: p(x) = x^128 + x^7 + x^2 + x + 1.
    // When the x^0 coefficient is shifted out (right-shift carry),
    // reduce x^128 to x^7 + x^2 + x + 1:
    //   x^7 -> bit 7 of byte 0 (0x80)
    //   x^2 -> bit 2 of byte 0 (0x04)
    //   x^1 -> bit 1 of byte 0 (0x02)
    //   x^0 -> bit 0 of byte 0 (0x01)
    // Reduction constant: 0x80|0x04|0x02|0x01 = 0x87

    uint8_t V[16];
    std::memcpy(V, y, 16);   // V = Y

    uint8_t Z[16] = {};      // Z = 0

    for (int i = 0; i < 128; ++i) {
        // Check bit i of X (little-endian: byte 0 bit 0 = bit 0)
        int byte_idx = i / 8;
        int bit_idx  = i % 8;
        if (x[byte_idx] & (1 << bit_idx)) {
            xor128(Z, V);
        }

        // V = V >> 1, with conditional reduction
        bool lsb = V[0] & 1;
        shr128_le(V);
        if (lsb) {
            V[0] ^= 0x87;
        }
    }

    std::memcpy(out, Z, 16);
}

void ghash(const uint8_t H[16], std::span<const uint8_t> data, uint8_t out[16]) {
#ifdef __x86_64__
    if (g_use_pclmul) {
        pclmul_ghash(H, data, out);
        return;
    }
#endif
    std::memset(out, 0, 16);

    size_t num_blocks = (data.size() + 15) / 16;

    for (size_t i = 0; i < num_blocks; ++i) {
        // Current block (zero-padded if last partial block)
        uint8_t block[16] = {};
        size_t offset = i * 16;
        size_t len = std::min<size_t>(16, data.size() - offset);
        std::memcpy(block, data.data() + offset, len);

        // XOR with current GHASH state
        xor128(out, block);

        // Multiply by H in GF(2^128)
        uint8_t tmp[16];
        gf128_mul(out, H, tmp);
        std::memcpy(out, tmp, 16);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 辅助：递增 32-bit counter（高 32 位，大端序）
// ═══════════════════════════════════════════════════════════════════════

/// 递增 128-bit counter 的最后 32 位（大端序：counter[12..15] 是低 32 位）
static void inc32(uint8_t counter[16]) {
    // counter is big-endian; the last 4 bytes are the least significant
    for (int i = 15; i >= 12; --i) {
        if (++counter[i] != 0) break;
    }
}

/// 将 size_t 转换为大端序 64-bit，写入 buf（buf 有 8 字节空间）
static void store_be64(uint8_t* buf, uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        buf[i] = static_cast<uint8_t>(val & 0xFF);
        val >>= 8;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 加密
// ═══════════════════════════════════════════════════════════════════════

void aes_gcm_encrypt(const aes_context& ctx,
                     const uint8_t* iv, size_t iv_len,
                     std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len) {
    // ── 1. Compute H = AES_encrypt(K, 0^128) ──
    uint8_t H[16];
    uint8_t zero[16] = {};
    aes_encrypt_block(ctx, zero, H);

    // ── 2. Compute J0 ──
    uint8_t J0[16] = {};
    if (iv_len == 12) {
        // J0 = IV || 0^31 || 1
        std::memcpy(J0, iv, 12);
        J0[15] = 0x01;
    } else {
        // J0 = GHASH_H(IV || 0^s || len(IV)_64)
        ghash(H, std::span<const uint8_t>(iv, iv_len), J0);
        // Inline: also hash the padding and length
        // Actually, GHASH already handles zero-padding internally (block-by-block)
        // But we also need len(IV) in bits. Complete J0 = GHASH(IV || 0^s || [len(IV)]_64)
        // For simplicity, use a temporary buffer
        std::vector<uint8_t> iv_data(iv, iv + iv_len);
        // zero-pad to block boundary
        size_t pad_len = (16 - (iv_len % 16)) % 16;
        iv_data.insert(iv_data.end(), pad_len, 0);
        // append 64-bit length (0 for now, we already did GHASH)
        // Actually better: recompute with full input
        uint8_t iv_len_be[8] = {};
        store_be64(iv_len_be, iv_len * 8);
        iv_data.insert(iv_data.end(), iv_len_be, iv_len_be + 8);
        ghash(H, iv_data, J0);
    }

    // ── 3. Generate CTR keystream and encrypt ──
    ciphertext.resize(plaintext.size());
    size_t num_ctr_blocks = (plaintext.size() + 15) / 16;

    // Allocate keystream buffer (full blocks)
    std::vector<uint8_t> keystream(num_ctr_blocks * 16);
    uint8_t counter[16];
    std::memcpy(counter, J0, 16);

    for (size_t i = 0; i < num_ctr_blocks; ++i) {
        inc32(counter);  // First counter = J0 + 1
        aes_encrypt_block(ctx, counter, keystream.data() + i * 16);
    }

    // XOR plaintext with keystream
    for (size_t i = 0; i < plaintext.size(); ++i) {
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }

    // ── 4. Compute GHASH(AAD || ciphertext || len(AAD) || len(C)) ──
    std::vector<uint8_t> ghash_input;
    // AAD
    ghash_input.insert(ghash_input.end(), aad.begin(), aad.end());
    // zero-pad AAD to 16-byte boundary
    size_t aad_pad = (16 - (aad.size() % 16)) % 16;
    ghash_input.insert(ghash_input.end(), aad_pad, 0);
    // ciphertext
    ghash_input.insert(ghash_input.end(), ciphertext.begin(), ciphertext.end());
    // zero-pad ciphertext to 16-byte boundary
    size_t ct_pad = (16 - (ciphertext.size() % 16)) % 16;
    ghash_input.insert(ghash_input.end(), ct_pad, 0);
    // len(AAD)_64 || len(C)_64 (in bits, big-endian)
    uint8_t len_block[16] = {};
    store_be64(len_block, aad.size() * 8);             // len(A) in bytes 0-7
    store_be64(len_block + 8, ciphertext.size() * 8);  // len(C) in bytes 8-15
    ghash_input.insert(ghash_input.end(), len_block, len_block + 16);

    uint8_t S[16];
    ghash(H, ghash_input, S);

    // ── 5. Compute tag = S ⊕ AES_encrypt(K, J0) ──
    uint8_t E_J0[16];
    aes_encrypt_block(ctx, J0, E_J0);
    for (int i = 0; i < 16; ++i) S[i] ^= E_J0[i];

    // Tag is first tag_len bytes of S
    std::memcpy(tag, S, tag_len);
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 解密
// ═══════════════════════════════════════════════════════════════════════

bool aes_gcm_decrypt(const aes_context& ctx,
                     const uint8_t* iv, size_t iv_len,
                     std::span<const uint8_t> ciphertext,
                     std::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext) {
    // ── 1. Compute H = AES_encrypt(K, 0^128) ──
    uint8_t H[16];
    uint8_t zero[16] = {};
    aes_encrypt_block(ctx, zero, H);

    // ── 2. Compute J0 (same as encrypt) ──
    uint8_t J0[16] = {};
    if (iv_len == 12) {
        std::memcpy(J0, iv, 12);
        J0[15] = 0x01;
    } else {
        std::vector<uint8_t> iv_data(iv, iv + iv_len);
        size_t pad_len = (16 - (iv_len % 16)) % 16;
        iv_data.insert(iv_data.end(), pad_len, 0);
        uint8_t iv_len_be[8] = {};
        store_be64(iv_len_be, iv_len * 8);
        iv_data.insert(iv_data.end(), iv_len_be, iv_len_be + 8);
        ghash(H, iv_data, J0);
    }

    // ── 3. Compute expected tag: GHASH(AAD || CT || len(AAD) || len(CT)) ⊕ E(K, J0) ──
    std::vector<uint8_t> ghash_input;
    ghash_input.insert(ghash_input.end(), aad.begin(), aad.end());
    size_t aad_pad = (16 - (aad.size() % 16)) % 16;
    ghash_input.insert(ghash_input.end(), aad_pad, 0);
    ghash_input.insert(ghash_input.end(), ciphertext.begin(), ciphertext.end());
    size_t ct_pad = (16 - (ciphertext.size() % 16)) % 16;
    ghash_input.insert(ghash_input.end(), ct_pad, 0);
    uint8_t len_block[16] = {};
    store_be64(len_block, aad.size() * 8);             // len(A) in bytes 0-7
    store_be64(len_block + 8, ciphertext.size() * 8);  // len(C) in bytes 8-15
    ghash_input.insert(ghash_input.end(), len_block, len_block + 16);

    uint8_t S[16];
    ghash(H, ghash_input, S);

    uint8_t E_J0[16];
    aes_encrypt_block(ctx, J0, E_J0);
    for (int i = 0; i < 16; ++i) S[i] ^= E_J0[i];

    // ── 4. Constant-time tag comparison ──
    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; ++i) {
        diff |= tag[i] ^ S[i];
    }
    if (diff != 0) return false;  // Tag mismatch

    // ── 5. Decrypt (CTR mode: same as encrypt) ──
    plaintext.resize(ciphertext.size());
    size_t num_ctr_blocks = (ciphertext.size() + 15) / 16;

    std::vector<uint8_t> keystream(num_ctr_blocks * 16);
    uint8_t counter[16];
    std::memcpy(counter, J0, 16);

    for (size_t i = 0; i < num_ctr_blocks; ++i) {
        inc32(counter);
        aes_encrypt_block(ctx, counter, keystream.data() + i * 16);
    }

    for (size_t i = 0; i < ciphertext.size(); ++i) {
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }

    return true;
}

} // namespace jpssl