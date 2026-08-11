#pragma once

/**
 * jpssl — AES-128/192/256 加密/解密（CPU + MUSA GPU）
 *
 * 本头文件提供：
 *   - 编译期常量 (S-Box, Rcon, 轮数表)
 *   - AES 上下文类型 aes_context
 *   - CPU 端加解密接口
 *   - MUSA GPU 端加解密接口
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include "jpssl_span.hpp"
#include <stdexcept>
#include <string>
#include <vector>

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  编译期常量
// ═══════════════════════════════════════════════════════════════════════

/// AES 块大小（字节）
constexpr size_t AES_BLOCK_SIZE = 16;

/// 密钥长度枚举
enum class AesKeySize : int { AES_128 = 16, AES_192 = 24, AES_256 = 32 };

/// 根据密钥长度返回轮数
constexpr int aes_rounds(AesKeySize ks) {
    // C++11 兼容写法：constexpr 函数体仅允许 return。
    return ks == AesKeySize::AES_128 ? 10
         : ks == AesKeySize::AES_192 ? 12
         : 14;
}

/// 扩展后的轮密钥大小（字节）：(rounds + 1) * 16
constexpr int expanded_key_bytes(AesKeySize ks) {
    return (aes_rounds(ks) + 1) * 16;
}

/// GF(2^8) 乘法（运行时 MixColumns 等使用；S-Box 为硬编码常量表）
inline uint8_t gf28_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B; // AES 不可约多项式 x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

/// S-Box 常量（AES FIPS-197，编译期硬编码表，兼容 C++11/14）
constexpr uint8_t SBOX[256] = {99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22
};
/// 逆 S-Box 常量
constexpr uint8_t INV_SBOX[256] = {82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125
};
/// 轮常数 Rcon（密钥扩展）
constexpr uint8_t RCON[16] = {0,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154
};

// ═══════════════════════════════════════════════════════════════════════
//  核心操作（内联 / constexpr）
// ═══════════════════════════════════════════════════════════════════════

/// SubBytes — 对整个 16 字节状态应用 S-Box
inline void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) state[i] = SBOX[state[i]];
}

/// InvSubBytes — 对整个 16 字节状态应用逆 S-Box
inline void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) state[i] = INV_SBOX[state[i]];
}

/// ShiftRows
inline void shift_rows(uint8_t state[16]) {
    // 第 1 行（索引 1,5,9,13）：左移 1
    uint8_t t = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = t;
    // 第 2 行（索引 2,6,10,14）：左移 2
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    // 第 3 行（索引 3,7,11,15）：左移 3（= 右移 1）
    t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = state[3];
    state[3]  = t;
}

/// InvShiftRows
inline void inv_shift_rows(uint8_t state[16]) {
    // 第 1 行：右移 1
    uint8_t t = state[13];
    state[13] = state[9];
    state[9]  = state[5];
    state[5]  = state[1];
    state[1]  = t;
    // 第 2 行：右移 2
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    // 第 3 行：右移 3（= 左移 1）
    t = state[3];
    state[3]  = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = t;
}

/// GF(2^8) 乘以 2（xtime），用于 MixColumns
inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
}

/// MixColumns — 单列（4 字节）
/// 矩阵乘法：[02 03 01 01; 01 02 03 01; 01 01 02 03; 03 01 01 02]
inline void mix_column(uint8_t* r) {
    uint8_t a[4], b[4];
    for (int i = 0; i < 4; ++i) {
        a[i] = r[i];
        b[i] = xtime(r[i]);
    }
    r[0] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
    r[1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
    r[2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
    r[3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
}

/// MixColumns — 对整个状态
inline void mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; ++c) mix_column(&state[c * 4]);
}

/// InvMixColumns — 单列
inline void inv_mix_column(uint8_t* col) {
    uint8_t a[4];
    for (int i = 0; i < 4; ++i) a[i] = col[i];
    // 使用 0x0E, 0x0B, 0x0D, 0x09 的 GF(2^8) 乘法
    col[0] = gf28_mul(a[0], 0x0E) ^ gf28_mul(a[1], 0x0B) ^ gf28_mul(a[2], 0x0D) ^ gf28_mul(a[3], 0x09);
    col[1] = gf28_mul(a[0], 0x09) ^ gf28_mul(a[1], 0x0E) ^ gf28_mul(a[2], 0x0B) ^ gf28_mul(a[3], 0x0D);
    col[2] = gf28_mul(a[0], 0x0D) ^ gf28_mul(a[1], 0x09) ^ gf28_mul(a[2], 0x0E) ^ gf28_mul(a[3], 0x0B);
    col[3] = gf28_mul(a[0], 0x0B) ^ gf28_mul(a[1], 0x0D) ^ gf28_mul(a[2], 0x09) ^ gf28_mul(a[3], 0x0E);
}

/// InvMixColumns — 对整个状态
inline void inv_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; ++c) inv_mix_column(&state[c * 4]);
}

/// AddRoundKey — 轮密钥 XOR
inline void add_round_key(uint8_t state[16], const uint8_t* rk) {
    for (int i = 0; i < 16; ++i) state[i] ^= rk[i];
}

// ═══════════════════════════════════════════════════════════════════════
//  密钥扩展
// ═══════════════════════════════════════════════════════════════════════

/// 生成轮密钥（写入 rk_buf，长度 = (rounds+1)*16 字节）
void key_expansion(const uint8_t* key, AesKeySize ks, uint8_t* rk_buf);

// ═══════════════════════════════════════════════════════════════════════
//  AES 上下文
// ═══════════════════════════════════════════════════════════════════════

constexpr size_t MAX_EXPANDED_KEY = expanded_key_bytes(AesKeySize::AES_256); // 240 字节

struct aes_context {
    // 轮密钥缓冲按 16 字节对齐：AES-NI 路径以 __m128i* 访问（movdqa/movaps），
    // 若不满足对齐会在密钥扩展/加解密时触发 SIGSEGV。
    alignas(16) std::array<uint8_t, MAX_EXPANDED_KEY> enc_rk{};      // 加密轮密钥
    alignas(16) std::array<uint8_t, MAX_EXPANDED_KEY> dec_rk{};      // 解密轮密钥（软件格式）
    alignas(16) std::array<uint8_t, MAX_EXPANDED_KEY> dec_rk_aesni{}; // 解密轮密钥（AES-NI 格式，_mm_aesimc 变换）
    AesKeySize key_size;
    int rounds;

    /// 从原始密钥初始化
    void init(jpssl::span<const uint8_t, 16> key) { init_impl(key, AesKeySize::AES_128); }
    void init(jpssl::span<const uint8_t, 24> key) { init_impl(key, AesKeySize::AES_192); }
    void init(jpssl::span<const uint8_t, 32> key) { init_impl(key, AesKeySize::AES_256); }

private:
    void init_impl(jpssl::span<const uint8_t> key, AesKeySize ks);
};

// ═══════════════════════════════════════════════════════════════════════
//  CPU 端加解密 API
// ═══════════════════════════════════════════════════════════════════════

/// 加密单个 16 字节块（CPU）
void aes_encrypt_block(const aes_context& ctx, const uint8_t plain[16], uint8_t cipher[16]);

/// 纯软件 AES 加密单个 16 字节块（无 AES-NI）
void aes_encrypt_block_sw(const aes_context& ctx, const uint8_t plain[16], uint8_t cipher[16]);

/// 解密单个 16 字节块（CPU）
void aes_decrypt_block(const aes_context& ctx, const uint8_t cipher[16], uint8_t plain[16]);

/// ECB 模式加密（CPU）
/// input / output 长度必须为 16 的倍数
void aes_encrypt_ecb(const aes_context& ctx,
                     jpssl::span<const uint8_t> input,
                     jpssl::span<uint8_t> output);

/// ECB 模式解密（CPU）
void aes_decrypt_ecb(const aes_context& ctx,
                     jpssl::span<const uint8_t> input,
                     jpssl::span<uint8_t> output);

// ═══════════════════════════════════════════════════════════════════════
//  ECB + PKCS7/PKCS5 填充模式（AES-128/192/256）
//  PKCS5 在 AES（块大小 16）下与 PKCS7 行为完全一致，复用同一实现。
//  每组提供三个入口：
//    - 默认（自动分派 AES-NI / 软件）
//    - _sw  纯标量实现（无 AES-NI）
//    - _aesni 强制 AES-NI（CPU 不支持时回退到 _sw）
// ═══════════════════════════════════════════════════════════════════════

/// ECB + PKCS7 加密（自动分派 AES-NI / 软件）
/// @param plaintext  明文（任意长度）
/// @param ciphertext 输出密文（自动调整大小，长度为 16 的倍数）
void aes_encrypt_ecb_pkcs7(const aes_context& ctx,
                            jpssl::span<const uint8_t> plaintext,
                            std::vector<uint8_t>& ciphertext);

/// ECB + PKCS7 解密（自动分派，自动去填充）
/// @return true 成功, false 填充验证失败
bool aes_decrypt_ecb_pkcs7(const aes_context& ctx,
                            jpssl::span<const uint8_t> ciphertext,
                            std::vector<uint8_t>& plaintext);

/// ECB + PKCS7 加密（纯标量实现，无 AES-NI）
void aes_encrypt_ecb_pkcs7_sw(const aes_context& ctx,
                               jpssl::span<const uint8_t> plaintext,
                               std::vector<uint8_t>& ciphertext);

/// ECB + PKCS7 解密（纯标量实现，自动去填充）
bool aes_decrypt_ecb_pkcs7_sw(const aes_context& ctx,
                               jpssl::span<const uint8_t> ciphertext,
                               std::vector<uint8_t>& plaintext);

/// ECB + PKCS7 加密（AES-NI 硬件加速；CPU 不支持时回退到 _sw）
void aes_encrypt_ecb_pkcs7_aesni(const aes_context& ctx,
                                  jpssl::span<const uint8_t> plaintext,
                                  std::vector<uint8_t>& ciphertext);

/// ECB + PKCS7 解密（AES-NI 硬件加速；CPU 不支持时回退到 _sw）
bool aes_decrypt_ecb_pkcs7_aesni(const aes_context& ctx,
                                  jpssl::span<const uint8_t> ciphertext,
                                  std::vector<uint8_t>& plaintext);

/// ECB + PKCS5 加密（自动分派；PKCS5 在 AES 下与 PKCS7 等价）
inline void aes_encrypt_ecb_pkcs5(const aes_context& ctx,
                                   jpssl::span<const uint8_t> plaintext,
                                   std::vector<uint8_t>& ciphertext) {
    aes_encrypt_ecb_pkcs7(ctx, plaintext, ciphertext);
}

/// ECB + PKCS5 解密（自动分派；PKCS5 在 AES 下与 PKCS7 等价）
inline bool aes_decrypt_ecb_pkcs5(const aes_context& ctx,
                                   jpssl::span<const uint8_t> ciphertext,
                                   std::vector<uint8_t>& plaintext) {
    return aes_decrypt_ecb_pkcs7(ctx, ciphertext, plaintext);
}

/// ECB + PKCS5 加密（纯标量实现）
inline void aes_encrypt_ecb_pkcs5_sw(const aes_context& ctx,
                                      jpssl::span<const uint8_t> plaintext,
                                      std::vector<uint8_t>& ciphertext) {
    aes_encrypt_ecb_pkcs7_sw(ctx, plaintext, ciphertext);
}

/// ECB + PKCS5 解密（纯标量实现）
inline bool aes_decrypt_ecb_pkcs5_sw(const aes_context& ctx,
                                      jpssl::span<const uint8_t> ciphertext,
                                      std::vector<uint8_t>& plaintext) {
    return aes_decrypt_ecb_pkcs7_sw(ctx, ciphertext, plaintext);
}

/// ECB + PKCS5 加密（AES-NI 硬件加速）
inline void aes_encrypt_ecb_pkcs5_aesni(const aes_context& ctx,
                                         jpssl::span<const uint8_t> plaintext,
                                         std::vector<uint8_t>& ciphertext) {
    aes_encrypt_ecb_pkcs7_aesni(ctx, plaintext, ciphertext);
}

/// ECB + PKCS5 解密（AES-NI 硬件加速）
inline bool aes_decrypt_ecb_pkcs5_aesni(const aes_context& ctx,
                                         jpssl::span<const uint8_t> ciphertext,
                                         std::vector<uint8_t>& plaintext) {
    return aes_decrypt_ecb_pkcs7_aesni(ctx, ciphertext, plaintext);
}

// ═══════════════════════════════════════════════════════════════════════
//  MUSA GPU 端加解密 API
// ═══════════════════════════════════════════════════════════════════════

/// 初始化 GPU 资源（S-Box, 轮密钥等）
/// 需要在调用 GPU 加密前调用一次
void musa_aes_init(const aes_context& ctx);

/// 释放 GPU 资源
void musa_aes_cleanup();

/// ECB 模式加密（MUSA GPU）
/// input / output 在主机内存中；内部会自动进行 H2D / D2H 拷贝
void musa_aes_encrypt_ecb(const uint8_t* input, uint8_t* output, size_t num_blocks);

/// ECB 模式解密（MUSA GPU）
void musa_aes_decrypt_ecb(const uint8_t* input, uint8_t* output, size_t num_blocks);

// ═══════════════════════════════════════════════════════════════════════
//  PKCS7 填充（AES 块大小 16，PKCS5 与 PKCS7 行为一致）
// ═══════════════════════════════════════════════════════════════════════

/// PKCS7 填充：返回填充后的数据（自动添加 1-16 字节填充）
std::vector<uint8_t> pkcs7_pad(jpssl::span<const uint8_t> data);

/// PKCS7 去填充：返回去填充后的数据，失败抛出 std::runtime_error
std::vector<uint8_t> pkcs7_unpad(jpssl::span<const uint8_t> data);

// ═══════════════════════════════════════════════════════════════════════
//  CBC 模式（CPU 端）
// ═══════════════════════════════════════════════════════════════════════

/// CBC 加密（自动 PKCS7 填充）
/// @param ctx   AES 上下文
/// @param iv    16 字节初始化向量
/// @param plaintext  明文（任意长度）
/// @param ciphertext 输出密文（自动调整大小）
void aes_cbc_encrypt(const aes_context& ctx,
                     const uint8_t iv[16],
                     jpssl::span<const uint8_t> plaintext,
                     std::vector<uint8_t>& ciphertext);

/// CBC 解密（自动 PKCS7 去填充）
/// @return true 成功, false 填充验证失败
bool aes_cbc_decrypt(const aes_context& ctx,
                     const uint8_t iv[16],
                     jpssl::span<const uint8_t> ciphertext,
                     std::vector<uint8_t>& plaintext);

/// CBC 加密（纯标量实现，无 AES-NI，自动 PKCS7 填充）
void aes_cbc_encrypt_sw(const aes_context& ctx,
                        const uint8_t iv[16],
                        jpssl::span<const uint8_t> plaintext,
                        std::vector<uint8_t>& ciphertext);

/// CBC 解密（纯标量实现，自动 PKCS7 去填充）
bool aes_cbc_decrypt_sw(const aes_context& ctx,
                        const uint8_t iv[16],
                        jpssl::span<const uint8_t> ciphertext,
                        std::vector<uint8_t>& plaintext);

/// CBC 加密（AES-NI 硬件加速；CPU 不支持时回退到 _sw）
void aes_cbc_encrypt_aesni(const aes_context& ctx,
                           const uint8_t iv[16],
                           jpssl::span<const uint8_t> plaintext,
                           std::vector<uint8_t>& ciphertext);

/// CBC 解密（AES-NI 硬件加速；CPU 不支持时回退到 _sw）
bool aes_cbc_decrypt_aesni(const aes_context& ctx,
                           const uint8_t iv[16],
                           jpssl::span<const uint8_t> ciphertext,
                           std::vector<uint8_t>& plaintext);

// ═══════════════════════════════════════════════════════════════════════
//  GCM 模式（CPU 端 - Galois/Counter Mode，AEAD 认证加密）
// ═══════════════════════════════════════════════════════════════════════

/// GF(2^128) 乘法 — NIST SP 800-38D §6.3
/// 不可约多项式：P(x) = x^128 + x^7 + x^2 + x + 1
/// 数据采用 NIST 大端序约定：byte 0 bit 0 = x^0 系数。
/// 约简常数 0x87（在 byte 0）对应 x^128 → x^7+x^2+x+1。
/// @param x   乘数（128-bit，大端序）
/// @param y   被乘数（128-bit，大端序）
/// @param out 乘积 x·y in GF(2^128)（128-bit，大端序）
void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]);

/// GHASH — NIST SP 800-38D §6.4
/// 通用哈希函数，是 GCM 认证标签的核心组件。
/// 定义：GHASH_H(X) = Y_m，其中：
///   X = X_1 || X_2 || ... || X_m  （m 个 128-bit 块）
///   Y_0 = 0^128
///   Y_i = (Y_{i-1} ⊕ X_i) · H   （GF(2^128) 乘法）
/// 输入字节序：采用 NIST 大端序约定，byte 0 bit 0 = x^0 系数。
/// 当 data.size() 不是 16 的倍数时，最后一块用零填充到 16 字节。
/// @param H    hash subkey = AES_encrypt(K, 0^128)（128-bit，大端序）
/// @param data GHASH 输入（如 AAD || ciphertext || len_block），大端序
/// @param out  GHASH 输出（128-bit，大端序）
void ghash(const uint8_t H[16], jpssl::span<const uint8_t> data, uint8_t out[16]);

/// GHASH 增量（流式）计算上下文
/// 与一次性 ghash 语义一致：data 分块喂入，末尾不足 16 字节的块在
/// ghash_final 时补零。注意：GCM 中 AAD 与密文是**分别**补零的，
/// 直接用于 GCM 请用 gcm_ghash（已处理长度块与分段补零）。
struct ghash_ctx {
    uint8_t H[16];      ///< hash subkey = AES_encrypt(K, 0^128)
    uint8_t state[16];  ///< 当前 GHASH 状态 Y_i
    uint8_t buf[16];    ///< 未满块暂存
    size_t buf_len;     ///< buf 中有效字节数
};

/// 初始化增量 GHASH 上下文
void ghash_init(ghash_ctx* ctx, const uint8_t H[16]);

/// 追加数据（任意长度，可多次调用）
void ghash_update(ghash_ctx* ctx, const uint8_t* data, size_t len);

/// 结束并输出 GHASH（末尾不足块补零）
void ghash_final(ghash_ctx* ctx, uint8_t out[16]);

/// GCM 完整认证哈希：GHASH_H(AAD || 0-pad || data || 0-pad || [len(A)]_64 || [len(C)]_64)
/// 等价于 GCM 加密/解密中的 S 值（不含 E(K, J0) 异或），可用于构建
/// 自定义 GCM 兼容认证、或对照验证测试向量。
/// @param H    hash subkey
/// @param aad  附加认证数据（可为空）
/// @param data 密文（或明文）
/// @param out  GHASH 输出（128-bit）
void gcm_ghash(const uint8_t H[16],
               jpssl::span<const uint8_t> aad, jpssl::span<const uint8_t> data,
               uint8_t out[16]);

/// GCM 加密（带 AAD + 认证标签）
/// @param iv        初始化向量（推荐 12 字节）
/// @param iv_len    IV 长度
/// @param plaintext 明文
/// @param aad       附加认证数据（可为空）
/// @param ciphertext 输出密文（与明文等长，自动调整大小）
/// @param tag       输出认证标签（调用者分配，至少 tag_len 字节）
/// @param tag_len   标签长度（推荐 12/13/14/15/16，默认 16）
void aes_gcm_encrypt(const aes_context& ctx,
                     const uint8_t* iv, size_t iv_len,
                     jpssl::span<const uint8_t> plaintext,
                     jpssl::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len = 16);

/// GCM 解密（验证认证标签）
/// @return true 标签验证通过, false 验证失败（输出不应被使用）
bool aes_gcm_decrypt(const aes_context& ctx,
                     const uint8_t* iv, size_t iv_len,
                     jpssl::span<const uint8_t> ciphertext,
                     jpssl::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext);

/// GCM 加密（纯标量实现，无 AES-NI；GHASH 使用软件 GF(2^128) 乘法）
void aes_gcm_encrypt_sw(const aes_context& ctx,
                         const uint8_t* iv, size_t iv_len,
                         jpssl::span<const uint8_t> plaintext,
                         jpssl::span<const uint8_t> aad,
                         std::vector<uint8_t>& ciphertext,
                         uint8_t* tag, size_t tag_len = 16);

/// GCM 解密（纯标量实现）
bool aes_gcm_decrypt_sw(const aes_context& ctx,
                         const uint8_t* iv, size_t iv_len,
                         jpssl::span<const uint8_t> ciphertext,
                         jpssl::span<const uint8_t> aad,
                         const uint8_t* tag, size_t tag_len,
                         std::vector<uint8_t>& plaintext);

/// GCM 加密（AES-NI 硬件加速 CTR；GHASH 仍用软件实现，CPU 不支持时回退到 _sw）
void aes_gcm_encrypt_aesni(const aes_context& ctx,
                            const uint8_t* iv, size_t iv_len,
                            jpssl::span<const uint8_t> plaintext,
                            jpssl::span<const uint8_t> aad,
                            std::vector<uint8_t>& ciphertext,
                            uint8_t* tag, size_t tag_len = 16);

/// GCM 解密（AES-NI 硬件加速 CTR；CPU 不支持时回退到 _sw）
bool aes_gcm_decrypt_aesni(const aes_context& ctx,
                            const uint8_t* iv, size_t iv_len,
                            jpssl::span<const uint8_t> ciphertext,
                            jpssl::span<const uint8_t> aad,
                            const uint8_t* tag, size_t tag_len,
                            std::vector<uint8_t>& plaintext);

// ═══════════════════════════════════════════════════════════════════════
//  GCM 模式 - AVX2 / AVX512 硬件加速（PCLMULQDQ + VAES）
// ═══════════════════════════════════════════════════════════════════════

#if defined(JP_AVX2)
/// AVX2 GCM 加密（4 路并行，需要 PCLMULQDQ + AES-NI）
/// 自动分派：如果 CPU 不支持 AVX2，回退到软件实现
void aes_gcm_encrypt_avx2(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len = 16);

/// AVX2 GCM 解密
bool aes_gcm_decrypt_avx2(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext);
#endif // JP_AVX2

#if defined(JP_AVX512)
/// AVX512 GCM 加密（8 路并行，需要 VAES + VPCLMULQDQ + AVX512F + AVX512VL）
/// 自动分派：如果 CPU 不支持 AVX512，回退到 AVX2 / 软件
void aes_gcm_encrypt_avx512(const aes_context& ctx,
                            const uint8_t* iv, size_t iv_len,
                            jpssl::span<const uint8_t> plaintext,
                            jpssl::span<const uint8_t> aad,
                            std::vector<uint8_t>& ciphertext,
                            uint8_t* tag, size_t tag_len = 16);

/// AVX512 GCM 解密
bool aes_gcm_decrypt_avx512(const aes_context& ctx,
                            const uint8_t* iv, size_t iv_len,
                            jpssl::span<const uint8_t> ciphertext,
                            jpssl::span<const uint8_t> aad,
                            const uint8_t* tag, size_t tag_len,
                            std::vector<uint8_t>& plaintext);
#endif // JP_AVX512

#if defined(__x86_64__) && defined(JP_VAES)
/// VAES GCM 加密（256-bit VAES，4 块并行，需要 VAES + VPCLMULQDQ + AVX2）
/// 适用于 Alder Lake / Raptor Lake 等“AVX512 熔断但保留 256-bit VAES”的 CPU；
/// 不满足条件时回退到软件实现
void aes_gcm_encrypt_vaes(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len = 16);

/// VAES GCM 解密
bool aes_gcm_decrypt_vaes(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext);
#endif // __x86_64__

#if defined(JP_NEON) && defined(__aarch64__)
/// ARM NEON AES-GCM 加密（AESE + PMULL，4 块并行；不满足条件时回退软件）
void aes_gcm_encrypt_neon(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len = 16);

/// ARM NEON AES-GCM 解密
bool aes_gcm_decrypt_neon(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext);
#endif

/// GCM 加密 — 自动选择最优实现（AVX512 > VAES-256 > AVX2 > AES-NI > 软件）
/// 统一入口，内部根据 CPU 特性自动分派
void aes_gcm_encrypt_auto(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> plaintext,
                          jpssl::span<const uint8_t> aad,
                          std::vector<uint8_t>& ciphertext,
                          uint8_t* tag, size_t tag_len = 16);

/// GCM 解密 — 自动选择最优实现
bool aes_gcm_decrypt_auto(const aes_context& ctx,
                          const uint8_t* iv, size_t iv_len,
                          jpssl::span<const uint8_t> ciphertext,
                          jpssl::span<const uint8_t> aad,
                          const uint8_t* tag, size_t tag_len,
                          std::vector<uint8_t>& plaintext);


// ═══════════════════════════════════════════════════════════════════════
//  CCM 模式（CPU 端 — Counter with CBC-MAC，AEAD 认证加密）
//  NIST SP 800-38C / RFC 3610
// ═══════════════════════════════════════════════════════════════════════

/// CCM 加密（带 AAD + 认证标签）
/// @param nonce       临时值（7-13 字节）
/// @param nonce_len   nonce 长度
/// @param plaintext   明文
/// @param aad         附加认证数据（可为空）
/// @param ciphertext  输出密文（与明文等长，自动调整大小）
/// @param tag         输出认证标签（调用者分配，至少 tag_len 字节）
/// @param tag_len     标签长度（4/6/8/10/12/14/16）
void aes_ccm_encrypt(const aes_context& ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     jpssl::span<const uint8_t> plaintext,
                     jpssl::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len);

/// CCM 解密（验证认证标签）
/// @return true 标签验证通过, false 验证失败（输出不应被使用）
bool aes_ccm_decrypt(const aes_context& ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     jpssl::span<const uint8_t> ciphertext,
                     jpssl::span<const uint8_t> aad,
                     const uint8_t* tag, size_t tag_len,
                     std::vector<uint8_t>& plaintext);

// ═══════════════════════════════════════════════════════════════════════
//  MUSA GPU 端扩展：CBC 解密、GCM CTR 加密（CPU 做 XOR/GHASH）
// ═══════════════════════════════════════════════════════════════════════

/// GPU CBC 解密（GPU 并行 ECB 解密 + CPU XOR 链，自动 PKCS7 去填充）
bool musa_aes_cbc_decrypt(const uint8_t iv[16],
                          const uint8_t* ciphertext, size_t ciphertext_bytes,
                          std::vector<uint8_t>& plaintext);

/// GPU GCM CTR keystream 生成（GPU ECB 加密 counter values → keystream）
/// @param counters  输入 counter blocks（J0+1, J0+2, ...）
/// @param keystream 输出 keystream（与 counters 等长）
/// @param num_blocks counter 块数
void musa_aes_gcm_ctr_keystream(const uint8_t* counters, uint8_t* keystream,
                                size_t num_blocks);

// ═══════════════════════════════════════════════════════════════════════
//  MUSA GPU GCM 完整认证加密（全 GPU 执行：CTR + GHASH）
// ═══════════════════════════════════════════════════════════════════════

/// MUSA GPU GCM 加密（CTR 生成 + GHASH 全部在 GPU 完成）
/// @param iv         初始化向量（必须 12 字节，NIST 推荐）
/// @param plaintext  主机端明文缓冲区
/// @param aad        主机端附加认证数据
/// @param ciphertext 输出主机端密文（与明文等长）
/// @param tag        输出 16 字节认证标签（主机端）
/// @param tag_len    标签长度（8-16，默认 16）
void musa_aes_gcm_encrypt(const uint8_t iv[12],
                          const uint8_t* plaintext, size_t plaintext_len,
                          const uint8_t* aad, size_t aad_len,
                          uint8_t* ciphertext, uint8_t* tag, size_t tag_len = 16);

/// MUSA GPU GCM 解密 + 标签验证（全部在 GPU 完成）
/// @return true 标签验证通过，false 验证失败
bool musa_aes_gcm_decrypt(const uint8_t iv[12],
                          const uint8_t* ciphertext, size_t ciphertext_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* tag, size_t tag_len,
                          uint8_t* plaintext);

// ═══════════════════════════════════════════════════════════════════════
//  MUSA GPU GCM 持久化池 API（预分配，零分配开销）
// ═══════════════════════════════════════════════════════════════════════

struct musa_aes_gcm_pool;

/// 创建持久化 GPU GCM 池（预分配大缓冲区，高并发场景）
musa_aes_gcm_pool* musa_aes_gcm_pool_create(const aes_context& ctx, size_t max_data_bytes = 0);

/// 销毁持久化 GCM 池
void musa_aes_gcm_pool_destroy(musa_aes_gcm_pool* pool);

/// 使用持久化池进行 GPU GCM 加密
void musa_aes_gcm_pool_encrypt(musa_aes_gcm_pool* pool,
                               const uint8_t iv[12],
                               const uint8_t* plaintext, size_t plaintext_len,
                               const uint8_t* aad, size_t aad_len,
                               uint8_t* ciphertext, uint8_t* tag, size_t tag_len = 16);

// ═══════════════════════════════════════════════════════════════════════
//  MUSA GPU 高并发优化：持久化内存池 + 固定内存 + 多流并发
// ═══════════════════════════════════════════════════════════════════════

/// 持久化 GPU AES 会话（预分配缓冲区，零分配开销）
struct musa_aes_pool;

/// 创建持久化池
/// @param ctx          AES 上下文（用于初始化 GPU __constant__ 内存）
/// @param init_capacity 初始缓冲区大小（字节），0 = 默认 16MB
/// @return 池指针，失败返回 nullptr
musa_aes_pool* musa_aes_pool_create(const aes_context& ctx, size_t init_capacity = 0);

/// 销毁持久化池
void musa_aes_pool_destroy(musa_aes_pool* pool);

/// 使用持久化池进行 ECB 加密（自动扩容，零 malloc/free）
/// 内部使用固定内存 + 异步流传输
void musa_aes_pool_encrypt_ecb(musa_aes_pool* pool,
                               const uint8_t* input, uint8_t* output,
                               size_t num_blocks);

/// 使用持久化池进行 ECB 解密
void musa_aes_pool_decrypt_ecb(musa_aes_pool* pool,
                               const uint8_t* input, uint8_t* output,
                               size_t num_blocks);

/// 获取池当前容量（字节数）
size_t musa_aes_pool_capacity(const musa_aes_pool* pool);

} // namespace jpssl
