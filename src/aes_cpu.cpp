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
///
/// 委托给软件 key_expansion（FIPS 197 标准字节实现）。原 intrinsic 版本存在缺陷：
/// _mm_aeskeygenassist 的通道/Rcon 语义在本 GCC 环境与 SDM 不符（ch0 取自 63:32、
/// Rcon 落在低字节），且循环只生成 rk[0..8]（缺 rk[9..12] 四轮），产生错误轮密钥。
/// 密钥扩展仅在 init 时执行一次，软件实现无性能影响。
static void aesni_key_expansion_192(const uint8_t key[24], uint8_t rk_buf[208]) {
    key_expansion(key, AesKeySize::AES_192, rk_buf);
}

/// AES-NI 密钥扩展（AES-256）
static void aesni_key_expansion_256(const uint8_t key[32], uint8_t rk_buf[240]) {
    __m128i* rk = (__m128i*)rk_buf;
    rk[0] = _mm_loadu_si128((const __m128i*)key);
    rk[1] = _mm_loadu_si128((const __m128i*)(key + 16));
    for (int i = 0; i < 7; ++i) {
        __m128i t;
        switch (i) {
            case 0: t = _mm_aeskeygenassist_si128(rk[1], 0x01); break;
            case 1: t = _mm_aeskeygenassist_si128(rk[3], 0x02); break;
            case 2: t = _mm_aeskeygenassist_si128(rk[5], 0x04); break;
            case 3: t = _mm_aeskeygenassist_si128(rk[7], 0x08); break;
            case 4: t = _mm_aeskeygenassist_si128(rk[9], 0x10); break;
            case 5: t = _mm_aeskeygenassist_si128(rk[11], 0x20); break;
            case 6: t = _mm_aeskeygenassist_si128(rk[13], 0x40); break;
        }
        t = _mm_shuffle_epi32(t, 0xFF);
        __m128i k = rk[i * 2];
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
        rk[i * 2 + 2] = _mm_xor_si128(k, t);
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

/// 逐字节位反转：NIST bit-reflected 字节序 ↔ 自然多项式基
/// （NIST 约定 byte j bit (7-k) = x^(8j+k)；PCLMULQDQ 需要 byte j bit k = x^(8j+k)）
/// 注意高低半字节位置互换：bitrev(b) = rev4(高半字节) | rev4(低半字节)<<4
static inline __m128i gf128_bitrev(__m128i v) {
    const __m128i rev_lo = _mm_set_epi8(15,7,11,3,13,5,9,1,14,6,10,2,12,4,8,0);
    const __m128i rev_hi = _mm_set_epi8(0xF0,0x70,0xB0,0x30,0xD0,0x50,0x90,0x10,
                                        0xE0,0x60,0xA0,0x20,0xC0,0x40,0x80,0x00);
    __m128i lo = _mm_and_si128(v, _mm_set1_epi8(0x0F));
    __m128i hi = _mm_and_si128(_mm_srli_epi16(v, 4), _mm_set1_epi8(0x0F));
    return _mm_or_si128(_mm_shuffle_epi8(rev_lo, hi), _mm_shuffle_epi8(rev_hi, lo));
}

/// 自然域 GF(2^128) 乘法（PCLMULQDQ，完整模约简）
/// 与软件 gf128_mul 在 20 万随机输入上逐字节一致（经 gf128_bitrev 变换）。
/// 注意：约简必须同时折叠 t1 的低 64 位（clmul 0x00）与高 64 位
/// （clmul 0x01 = A高·B低），再处理第二次溢出；旧实现漏掉高 64 位导致结果错误。
static inline __m128i pclmul_gf128_mul_natural(__m128i a, __m128i b) {
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

/// PCLMULQDQ 加速的 GHASH（替代软件 gf128_mul 逐位版本）
static void pclmul_ghash(const uint8_t H[16], std::span<const uint8_t> data, uint8_t out[16]) {
    __m128i Hv = gf128_bitrev(_mm_loadu_si128((const __m128i*)H));
    __m128i state = _mm_setzero_si128();

    size_t pos = 0;
    size_t len = data.size();

    while (pos + 16 <= len) {
        __m128i block = gf128_bitrev(_mm_loadu_si128((const __m128i*)(data.data() + pos)));
        state = pclmul_gf128_mul_natural(_mm_xor_si128(state, block), Hv);
        pos += 16;
    }

    if (pos < len) {
        uint8_t last[16] = {};
        std::memcpy(last, data.data() + pos, len - pos);
        __m128i block = gf128_bitrev(_mm_loadu_si128((const __m128i*)last));
        state = pclmul_gf128_mul_natural(_mm_xor_si128(state, block), Hv);
    }

    state = gf128_bitrev(state);
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
        } else if (nk > 6 && i % nk == 4) {   // 仅 AES-256 (Nk=8) 才进入此分支 (FIPS 197 §5.2)
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
//  纯软件单块加密（无 AES-NI 分派）
// ═══════════════════════════════════════════════════════════════════════

void aes_encrypt_block_sw(const aes_context& ctx,
                          const uint8_t plain[16],
                          uint8_t cipher[16]) {
    std::memcpy(cipher, plain, 16);
    const uint8_t* rk = ctx.enc_rk.data();

    add_round_key(cipher, rk);
    rk += 16;

    for (int r = 1; r < ctx.rounds; ++r) {
        sub_bytes(cipher);
        shift_rows(cipher);
        mix_columns(cipher);
        add_round_key(cipher, rk);
        rk += 16;
    }

    sub_bytes(cipher);
    shift_rows(cipher);
    add_round_key(cipher, rk);
}

/// 纯软件单块解密（无 AES-NI 分派），供 _sw 路径直接复用
static void aes_decrypt_block_sw_impl(const aes_context& ctx,
                                       const uint8_t cipher[16],
                                       uint8_t plain[16]) {
    std::memcpy(plain, cipher, 16);
    const uint8_t* rk = ctx.dec_rk.data();
    add_round_key(plain, rk);
    rk += 16;
    for (int r = 1; r < ctx.rounds; ++r) {
        inv_shift_rows(plain);
        inv_sub_bytes(plain);
        add_round_key(plain, rk);
        inv_mix_columns(plain);
        rk += 16;
    }
    inv_shift_rows(plain);
    inv_sub_bytes(plain);
    add_round_key(plain, rk);
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
    aes_decrypt_block_sw_impl(ctx, cipher, plain);
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
//  ECB + PKCS7/PKCS5 填充模式（AES-128/192/256）
//  PKCS5 在 AES（块大小 16）下与 PKCS7 行为完全一致，复用同一实现。
//  三个入口：默认（自动分派）、_sw（纯标量）、_aesni（硬件，不支持时回退 _sw）
// ═══════════════════════════════════════════════════════════════════════

/// ECB + PKCS7 加密 - 纯标量实现
void aes_encrypt_ecb_pkcs7_sw(const aes_context& ctx,
                               std::span<const uint8_t> plaintext,
                               std::vector<uint8_t>& ciphertext) {
    auto padded = pkcs7_pad(plaintext);
    ciphertext.resize(padded.size());
    size_t n = padded.size() / AES_BLOCK_SIZE;
    for (size_t i = 0; i < n; ++i) {
        aes_encrypt_block_sw(ctx, padded.data() + i * AES_BLOCK_SIZE,
                             ciphertext.data() + i * AES_BLOCK_SIZE);
    }
}

/// ECB + PKCS7 解密 - 纯标量实现
bool aes_decrypt_ecb_pkcs7_sw(const aes_context& ctx,
                               std::span<const uint8_t> ciphertext,
                               std::vector<uint8_t>& plaintext) {
    if (ciphertext.empty() || ciphertext.size() % AES_BLOCK_SIZE != 0)
        return false;

    std::vector<uint8_t> padded(ciphertext.size());
    size_t n = ciphertext.size() / AES_BLOCK_SIZE;
    for (size_t i = 0; i < n; ++i) {
        aes_decrypt_block_sw_impl(ctx, ciphertext.data() + i * AES_BLOCK_SIZE,
                                  padded.data() + i * AES_BLOCK_SIZE);
    }

    try {
        plaintext = pkcs7_unpad(padded);
        return true;
    } catch (const std::runtime_error&) {
        plaintext.clear();
        return false;
    }
}

#ifdef __x86_64__
/// ECB + PKCS7 加密 - AES-NI 硬件加速
void aes_encrypt_ecb_pkcs7_aesni(const aes_context& ctx,
                                  std::span<const uint8_t> plaintext,
                                  std::vector<uint8_t>& ciphertext) {
    if (!g_use_aesni) {
        aes_encrypt_ecb_pkcs7_sw(ctx, plaintext, ciphertext);
        return;
    }
    auto padded = pkcs7_pad(plaintext);
    ciphertext.resize(padded.size());
    size_t n = padded.size() / AES_BLOCK_SIZE;
    const __m128i* rk = (const __m128i*)ctx.enc_rk.data();
    for (size_t i = 0; i < n; ++i) {
        __m128i state = _mm_loadu_si128((const __m128i*)(padded.data() + i * AES_BLOCK_SIZE));
        state = _mm_xor_si128(state, rk[0]);
        for (int r = 1; r < ctx.rounds; ++r)
            state = _mm_aesenc_si128(state, rk[r]);
        state = _mm_aesenclast_si128(state, rk[ctx.rounds]);
        _mm_storeu_si128((__m128i*)(ciphertext.data() + i * AES_BLOCK_SIZE), state);
    }
}

/// ECB + PKCS7 解密 - AES-NI 硬件加速
bool aes_decrypt_ecb_pkcs7_aesni(const aes_context& ctx,
                                  std::span<const uint8_t> ciphertext,
                                  std::vector<uint8_t>& plaintext) {
    if (ciphertext.empty() || ciphertext.size() % AES_BLOCK_SIZE != 0)
        return false;
    if (!g_use_aesni) {
        return aes_decrypt_ecb_pkcs7_sw(ctx, ciphertext, plaintext);
    }

    std::vector<uint8_t> padded(ciphertext.size());
    size_t n = ciphertext.size() / AES_BLOCK_SIZE;
    const __m128i* rk = (const __m128i*)ctx.dec_rk_aesni.data();
    for (size_t i = 0; i < n; ++i) {
        __m128i state = _mm_loadu_si128((const __m128i*)(ciphertext.data() + i * AES_BLOCK_SIZE));
        state = _mm_xor_si128(state, rk[0]);
        for (int r = 1; r < ctx.rounds; ++r)
            state = _mm_aesdec_si128(state, rk[r]);
        state = _mm_aesdeclast_si128(state, rk[ctx.rounds]);
        _mm_storeu_si128((__m128i*)(padded.data() + i * AES_BLOCK_SIZE), state);
    }

    try {
        plaintext = pkcs7_unpad(padded);
        return true;
    } catch (const std::runtime_error&) {
        plaintext.clear();
        return false;
    }
}
#else
void aes_encrypt_ecb_pkcs7_aesni(const aes_context& ctx,
                                  std::span<const uint8_t> plaintext,
                                  std::vector<uint8_t>& ciphertext) {
    aes_encrypt_ecb_pkcs7_sw(ctx, plaintext, ciphertext);
}

bool aes_decrypt_ecb_pkcs7_aesni(const aes_context& ctx,
                                  std::span<const uint8_t> ciphertext,
                                  std::vector<uint8_t>& plaintext) {
    return aes_decrypt_ecb_pkcs7_sw(ctx, ciphertext, plaintext);
}
#endif

/// ECB + PKCS7 加密 - 自动分派（AES-NI / 软件）
void aes_encrypt_ecb_pkcs7(const aes_context& ctx,
                            std::span<const uint8_t> plaintext,
                            std::vector<uint8_t>& ciphertext) {
    aes_encrypt_ecb_pkcs7_aesni(ctx, plaintext, ciphertext);
}

/// ECB + PKCS7 解密 - 自动分派（AES-NI / 软件）
bool aes_decrypt_ecb_pkcs7(const aes_context& ctx,
                            std::span<const uint8_t> ciphertext,
                            std::vector<uint8_t>& plaintext) {
    return aes_decrypt_ecb_pkcs7_aesni(ctx, ciphertext, plaintext);
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

/// CBC 加密内部实现（通过函数指针选择块加密后端）
static void cbc_encrypt_impl(const aes_context& ctx,
                             const uint8_t iv[16],
                             std::span<const uint8_t> plaintext,
                             std::vector<uint8_t>& ciphertext,
                             void (*enc_block)(const aes_context&,
                                               const uint8_t[16], uint8_t[16])) {
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
        enc_block(ctx, xored, ct_block);

        // Update previous
        std::memcpy(prev, ct_block, 16);
    }
}

/// CBC 解密内部实现（通过函数指针选择块解密后端）
static bool cbc_decrypt_impl(const aes_context& ctx,
                             const uint8_t iv[16],
                             std::span<const uint8_t> ciphertext,
                             std::vector<uint8_t>& plaintext,
                             void (*dec_block)(const aes_context&,
                                               const uint8_t[16], uint8_t[16])) {
    if (ciphertext.size() % AES_BLOCK_SIZE != 0) return false;

    size_t num_blocks = ciphertext.size() / AES_BLOCK_SIZE;
    std::vector<uint8_t> padded(num_blocks * AES_BLOCK_SIZE);

    const uint8_t* prev = iv;

    for (size_t i = 0; i < num_blocks; ++i) {
        const uint8_t* ct_block = ciphertext.data() + i * AES_BLOCK_SIZE;
        uint8_t*       pt_block = padded.data() + i * AES_BLOCK_SIZE;

        // Decrypt
        dec_block(ctx, ct_block, pt_block);

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

#ifdef __x86_64__
/// AES-NI 单块加密（对外暴露的静态包装，用于 CBC/GCM 函数指针分派）
static void aesni_enc_block_wrap(const aes_context& ctx,
                                  const uint8_t plain[16], uint8_t cipher[16]) {
    aesni_encrypt_block(ctx, plain, cipher);
}

/// AES-NI 单块解密（对外暴露的静态包装，用于 CBC 函数指针分派）
static void aesni_dec_block_wrap(const aes_context& ctx,
                                  const uint8_t cipher[16], uint8_t plain[16]) {
    aesni_decrypt_block(ctx, cipher, plain);
}
#endif

/// CBC 加密 - 纯标量实现
void aes_cbc_encrypt_sw(const aes_context& ctx,
                        const uint8_t iv[16],
                        std::span<const uint8_t> plaintext,
                        std::vector<uint8_t>& ciphertext) {
    cbc_encrypt_impl(ctx, iv, plaintext, ciphertext, aes_encrypt_block_sw);
}

/// CBC 解密 - 纯标量实现
bool aes_cbc_decrypt_sw(const aes_context& ctx,
                        const uint8_t iv[16],
                        std::span<const uint8_t> ciphertext,
                        std::vector<uint8_t>& plaintext) {
    return cbc_decrypt_impl(ctx, iv, ciphertext, plaintext, aes_decrypt_block_sw_impl);
}

/// CBC 加密 - AES-NI 硬件加速
void aes_cbc_encrypt_aesni(const aes_context& ctx,
                           const uint8_t iv[16],
                           std::span<const uint8_t> plaintext,
                           std::vector<uint8_t>& ciphertext) {
#ifdef __x86_64__
    if (g_use_aesni) {
        cbc_encrypt_impl(ctx, iv, plaintext, ciphertext, aesni_enc_block_wrap);
        return;
    }
#endif
    aes_cbc_encrypt_sw(ctx, iv, plaintext, ciphertext);
}

/// CBC 解密 - AES-NI 硬件加速
bool aes_cbc_decrypt_aesni(const aes_context& ctx,
                           const uint8_t iv[16],
                           std::span<const uint8_t> ciphertext,
                           std::vector<uint8_t>& plaintext) {
#ifdef __x86_64__
    if (g_use_aesni) {
        return cbc_decrypt_impl(ctx, iv, ciphertext, plaintext, aesni_dec_block_wrap);
    }
#endif
    return aes_cbc_decrypt_sw(ctx, iv, ciphertext, plaintext);
}

/// CBC 加密 - 自动分派（AES-NI / 软件）
void aes_cbc_encrypt(const aes_context& ctx,
                     const uint8_t iv[16],
                     std::span<const uint8_t> plaintext,
                     std::vector<uint8_t>& ciphertext) {
    aes_cbc_encrypt_aesni(ctx, iv, plaintext, ciphertext);
}

/// CBC 解密 - 自动分派（AES-NI / 软件）
bool aes_cbc_decrypt(const aes_context& ctx,
                     const uint8_t iv[16],
                     std::span<const uint8_t> ciphertext,
                     std::vector<uint8_t>& plaintext) {
    return aes_cbc_decrypt_aesni(ctx, iv, ciphertext, plaintext);
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 辅助：GF(2^128) 乘法 & GHASH
// ═══════════════════════════════════════════════════════════════════════


/// XOR 128-bit: dst ^= src
static void xor128(uint8_t* dst, const uint8_t* src) {
    for (int i = 0; i < 16; ++i) dst[i] ^= src[i];
}

void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
    // GF(2^128) multiplication per NIST SP 800-38D §6.3.
    // Bit-reflected (NIST) convention: byte 0 bit 7 = x^0 coefficient.
    //   byte 0 bit 7 = a_0, byte 0 bit 6 = a_1, ..., byte 0 bit 0 = a_7,
    //   byte 1 bit 7 = a_8, ...
    // Irreducible polynomial: P(x) = x^128 + x^7 + x^2 + x + 1.
    // Multiply-by-x = right-shift within each byte, LSB carries to next byte's MSB.
    // Reduction: when a_127 (byte 15 bit 0) overflows to x^128 after multiply-by-x,
    //   reduce x^128 → x^7 + x^2 + x + 1, which in bit-reflected form is:
    //     x^7 → byte 0 bit 0 (0x01)
    //     x^2 → byte 0 bit 5 (0x20)
    //     x^1 → byte 0 bit 6 (0x40)
    //     x^0 → byte 0 bit 7 (0x80)
    //   Reduction constant = 0xE1 at byte 0.
    // Algorithm: iterate bits of X MSB-first (byte 0 bit 7 down to byte 15 bit 0),
    // accumulating Z = Z ⊕ V when X's bit is 1, then V = V · x with reduction.

#ifdef __x86_64__
    if (g_use_pclmul) {
        __m128i ar = gf128_bitrev(_mm_loadu_si128((const __m128i*)x));
        __m128i br = gf128_bitrev(_mm_loadu_si128((const __m128i*)y));
        __m128i rr = gf128_bitrev(pclmul_gf128_mul_natural(ar, br));
        _mm_storeu_si128((__m128i*)out, rr);
        return;
    }
#endif

    uint8_t V[16];
    std::memcpy(V, y, 16);   // V = Y

    uint8_t Z[16] = {};      // Z = 0

    // Iterate bits of X from MSB to LSB (bit-reflected order)
    for (int i_byte = 0; i_byte < 16; ++i_byte) {
        uint8_t mask = 0x80;  // start from bit 7 (x^0 position)
        for (int i_bit = 0; i_bit < 8; ++i_bit, mask >>= 1) {
            // If this bit of X is set, accumulate V into Z
            if (x[i_byte] & mask) {
                xor128(Z, V);
            }

            // V = V · x  (multiply by x in bit-reflected: right-shift, carry LSB→MSB)
            uint8_t carry = 0;
            for (int j = 0; j < 16; ++j) {
                uint8_t next_carry = (V[j] & 1) << 7;  // LSB → next byte's MSB
                V[j] = (V[j] >> 1) | carry;
                carry = next_carry;
            }
            // If V_127 overflowed (byte 15 bit 0 was 1), reduce
            if (carry) {
                V[0] ^= 0xE1;  // reduction: x^128 → x^7 + x^2 + x + 1
            }
        }
    }

    std::memcpy(out, Z, 16);
}

void ghash(const uint8_t H[16], std::span<const uint8_t> data, uint8_t out[16]) {
    // GHASH per NIST SP 800-38D §6.4:
    //   X = X_1 || X_2 || ... || X_m  (m blocks of 128 bits each)
    //   Y_0 = 0^128
    //   Y_i = (Y_{i-1} ⊕ X_i) · H   for i = 1..m
    //   return Y_m
    //
    // All arithmetic is in GF(2^128) with polynomial x^128 + x^7 + x^2 + x + 1.
    // Data is in NIST big-endian convention: byte 0 bit 0 = x^0 coefficient.
    // gf128_mul operates directly on this big-endian representation with
    // reduction constant 0x87 at byte 0 for the x^128 → x^7+x^2+x+1 reduction.

#ifdef __x86_64__
    if (g_use_pclmul) {
        pclmul_ghash(H, data, out);
        return;
    }
#endif

    std::memset(out, 0, 16);
    size_t num_blocks = (data.size() + 15) / 16;

    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t block[16] = {};
        size_t offset = i * 16;
        size_t len = std::min<size_t>(16, data.size() - offset);
        std::memcpy(block, data.data() + offset, len);

        // Y_i = (Y_{i-1} ⊕ X_i)
        xor128(out, block);

        // Y_i = (Y_{i-1} ⊕ X_i) · H
        uint8_t tmp[16];
        gf128_mul(out, H, tmp);
        std::memcpy(out, tmp, 16);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  增量 GHASH（流式）与 GCM 完整认证哈希
// ═══════════════════════════════════════════════════════════════════════

void ghash_init(ghash_ctx* ctx, const uint8_t H[16]) {
    std::memcpy(ctx->H, H, 16);
    std::memset(ctx->state, 0, 16);
    ctx->buf_len = 0;
}

void ghash_update(ghash_ctx* ctx, const uint8_t* data, size_t len) {
    // 先补满暂存块
    if (ctx->buf_len) {
        size_t take = std::min<size_t>(len, 16 - ctx->buf_len);
        std::memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == 16) {
            uint8_t tmp[16];
            xor128(ctx->state, ctx->buf);
            gf128_mul(ctx->state, ctx->H, tmp);
            std::memcpy(ctx->state, tmp, 16);
            ctx->buf_len = 0;
        }
        if (len == 0) return;
    }
    // 整块处理（PCLMULQDQ 加速的 gf128_mul）
    while (len >= 16) {
        uint8_t tmp[16];
        xor128(ctx->state, data);
        gf128_mul(ctx->state, ctx->H, tmp);
        std::memcpy(ctx->state, tmp, 16);
        data += 16;
        len -= 16;
    }
    // 剩余不足一块的暂存
    if (len) {
        std::memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

void ghash_final(ghash_ctx* ctx, uint8_t out[16]) {
    if (ctx->buf_len) {
        std::memset(ctx->buf + ctx->buf_len, 0, 16 - ctx->buf_len);
        uint8_t tmp[16];
        xor128(ctx->state, ctx->buf);
        gf128_mul(ctx->state, ctx->H, tmp);
        std::memcpy(ctx->state, tmp, 16);
        ctx->buf_len = 0;
    }
    std::memcpy(out, ctx->state, 16);
}

void gcm_ghash(const uint8_t H[16],
               std::span<const uint8_t> aad, std::span<const uint8_t> data,
               uint8_t out[16]) {
    ghash_ctx ctx;
    ghash_init(&ctx, H);

    ghash_update(&ctx, aad.data(), aad.size());
    if (aad.size() % 16) {
        static const uint8_t zero[16] = {};
        ghash_update(&ctx, zero, 16 - aad.size() % 16);
    }

    ghash_update(&ctx, data.data(), data.size());
    if (data.size() % 16) {
        static const uint8_t zero[16] = {};
        ghash_update(&ctx, zero, 16 - data.size() % 16);
    }

    uint8_t lenblock[16] = {};
    uint64_t la = (uint64_t)aad.size() * 8, lc = (uint64_t)data.size() * 8;
    for (int i = 7; i >= 0; --i) {
        lenblock[i] = (uint8_t)(la & 0xFF);
        la >>= 8;
        lenblock[8 + i] = (uint8_t)(lc & 0xFF);
        lc >>= 8;
    }
    ghash_update(&ctx, lenblock, 16);
    ghash_final(&ctx, out);
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

/// GCM 加密内部实现（通过函数指针选择块加密后端）
static void gcm_encrypt_impl(const aes_context& ctx,
                              const uint8_t* iv, size_t iv_len,
                              std::span<const uint8_t> plaintext,
                              std::span<const uint8_t> aad,
                              std::vector<uint8_t>& ciphertext,
                              uint8_t* tag, size_t tag_len,
                              void (*enc_block)(const aes_context&,
                                                const uint8_t[16], uint8_t[16])) {
    // ── 1. Compute H = AES_encrypt(K, 0^128) ──
    uint8_t H[16];
    uint8_t zero[16] = {};
    enc_block(ctx, zero, H);

    // ── 2. Compute J0 ──
    uint8_t J0[16] = {};
    if (iv_len == 12) {
        // J0 = IV || 0^31 || 1
        std::memcpy(J0, iv, 12);
        J0[15] = 0x01;
    } else {
        // J0 = GHASH_H(IV || 0^{s+64} || [len(IV)]_64)  (NIST SP 800-38D §5.2.1.1)
        std::vector<uint8_t> iv_data(iv, iv + iv_len);
        size_t pad_len = (16 - (iv_len % 16)) % 16;
        iv_data.insert(iv_data.end(), pad_len, 0);
        iv_data.insert(iv_data.end(), 8, 0);
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
        enc_block(ctx, counter, keystream.data() + i * 16);
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
    enc_block(ctx, J0, E_J0);

    for (int i = 0; i < 16; ++i) S[i] ^= E_J0[i];

    // Tag is first tag_len bytes of S
    std::memcpy(tag, S, tag_len);
}

/// GCM 解密内部实现（通过函数指针选择块加密后端）
static bool gcm_decrypt_impl(const aes_context& ctx,
                              const uint8_t* iv, size_t iv_len,
                              std::span<const uint8_t> ciphertext,
                              std::span<const uint8_t> aad,
                              const uint8_t* tag, size_t tag_len,
                              std::vector<uint8_t>& plaintext,
                              void (*enc_block)(const aes_context&,
                                                const uint8_t[16], uint8_t[16])) {
    // ── 1. Compute H = AES_encrypt(K, 0^128) ──
    uint8_t H[16];
    uint8_t zero[16] = {};
    enc_block(ctx, zero, H);

    // ── 2. Compute J0 (same as encrypt) ──
    uint8_t J0[16] = {};
    if (iv_len == 12) {
        std::memcpy(J0, iv, 12);
        J0[15] = 0x01;
    } else {
        // J0 = GHASH_H(IV || 0^{s+64} || [len(IV)]_64)  (NIST SP 800-38D §5.2.1.1)
        std::vector<uint8_t> iv_data(iv, iv + iv_len);
        size_t pad_len = (16 - (iv_len % 16)) % 16;
        iv_data.insert(iv_data.end(), pad_len, 0);
        iv_data.insert(iv_data.end(), 8, 0);
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
    enc_block(ctx, J0, E_J0);
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
        enc_block(ctx, counter, keystream.data() + i * 16);
    }

    for (size_t i = 0; i < ciphertext.size(); ++i) {
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }

    return true;
}

/// GCM 加密 - 纯标量实现
void aes_gcm_encrypt_sw(const aes_context& ctx,
                         const uint8_t* iv, size_t iv_len,
                         std::span<const uint8_t> plaintext,
                         std::span<const uint8_t> aad,
                         std::vector<uint8_t>& ciphertext,
                         uint8_t* tag, size_t tag_len) {
    gcm_encrypt_impl(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len,
                     aes_encrypt_block_sw);
}

/// GCM 解密 - 纯标量实现
bool aes_gcm_decrypt_sw(const aes_context& ctx,
                         const uint8_t* iv, size_t iv_len,
                         std::span<const uint8_t> ciphertext,
                         std::span<const uint8_t> aad,
                         const uint8_t* tag, size_t tag_len,
                         std::vector<uint8_t>& plaintext) {
    return gcm_decrypt_impl(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                             plaintext, aes_encrypt_block_sw);
}

/// GCM 加密 - AES-NI 硬件加速
void aes_gcm_encrypt_aesni(const aes_context& ctx,
                            const uint8_t* iv, size_t iv_len,
                            std::span<const uint8_t> plaintext,
                            std::span<const uint8_t> aad,
                            std::vector<uint8_t>& ciphertext,
                            uint8_t* tag, size_t tag_len) {
#ifdef __x86_64__
    if (g_use_aesni) {
        gcm_encrypt_impl(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len,
                         aesni_enc_block_wrap);
        return;
    }
#endif
    aes_gcm_encrypt_sw(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
}

/// GCM 解密 - AES-NI 硬件加速
bool aes_gcm_decrypt_aesni(const aes_context& ctx,
                            const uint8_t* iv, size_t iv_len,
                            std::span<const uint8_t> ciphertext,
                            std::span<const uint8_t> aad,
                            const uint8_t* tag, size_t tag_len,
                            std::vector<uint8_t>& plaintext) {
#ifdef __x86_64__
    if (g_use_aesni) {
        return gcm_decrypt_impl(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                                plaintext, aesni_enc_block_wrap);
    }
#endif
    return aes_gcm_decrypt_sw(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                             plaintext);
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 加密 - 自动分派（AES-NI / 软件）
// ═══════════════════════════════════════════════════════════════════════

void aes_gcm_encrypt(const aes_context& ctx,
                     const uint8_t* iv, size_t iv_len,
                     std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len) {
    aes_gcm_encrypt_aesni(ctx, iv, iv_len, plaintext, aad, ciphertext, tag, tag_len);
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 解密 - 自动分派（AES-NI / 软件）
// ═══════════════════════════════════════════════════════════════════════

bool aes_gcm_decrypt(const aes_context& ctx,
                     const uint8_t* iv, size_t iv_len,
                     std::span<const uint8_t> ciphertext,
                     std::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext) {
    return aes_gcm_decrypt_aesni(ctx, iv, iv_len, ciphertext, aad, tag, tag_len,
                                 plaintext);
}

} // namespace jpssl
