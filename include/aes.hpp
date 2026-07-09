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
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  编译期常量
// ═══════════════════════════════════════════════════════════════════════

/// AES 块大小（字节）
inline constexpr size_t AES_BLOCK_SIZE = 16;

/// 密钥长度枚举
enum class AesKeySize : int { AES_128 = 16, AES_192 = 24, AES_256 = 32 };

/// 根据密钥长度返回轮数
constexpr int aes_rounds(AesKeySize ks) {
    switch (ks) {
        case AesKeySize::AES_128: return 10;
        case AesKeySize::AES_192: return 12;
        case AesKeySize::AES_256: return 14;
    }
    return 10; // unreachable
}

/// 扩展后的轮密钥大小（字节）：(rounds + 1) * 16
constexpr int expanded_key_bytes(AesKeySize ks) {
    return (aes_rounds(ks) + 1) * 16;
}

/// GF(2^8) 乘法（用于 S-Box 计算和运行时 MixColumns）
constexpr uint8_t gf28_mul(uint8_t a, uint8_t b) {
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

/// GF(2^8) 乘法逆元
consteval uint8_t gf28_inv(uint8_t a) {
    if (a == 0) return 0;
    // 使用扩展欧几里得或费马小定理：a^(254) = a^(-1) in GF(2^8)
    uint8_t r = 1;
    uint8_t base = a;
    for (int i = 0; i < 8; ++i) {
        if ((254 >> i) & 1) r = gf28_mul(r, base);
        base = gf28_mul(base, base);
    }
    return r;
}

/// 编译期生成 S-Box（256 字节）
consteval std::array<uint8_t, 256> make_sbox() {
    std::array<uint8_t, 256> sbox{};
    for (int i = 0; i < 256; ++i) {
        uint8_t inv = gf28_inv(static_cast<uint8_t>(i));
        // 仿射变换
        uint8_t s = inv;
        s ^= (inv << 1) | (inv >> 7);
        s ^= (inv << 2) | (inv >> 6);
        s ^= (inv << 3) | (inv >> 5);
        s ^= (inv << 4) | (inv >> 4);
        s ^= 0x63;
        sbox[i] = s;
    }
    return sbox;
}

/// 编译期生成逆 S-Box
consteval std::array<uint8_t, 256> make_inv_sbox(const std::array<uint8_t, 256>& sbox) {
    std::array<uint8_t, 256> inv{};
    for (int i = 0; i < 256; ++i) {
        inv[sbox[i]] = static_cast<uint8_t>(i);
    }
    return inv;
}

/// S-Box 常量
inline constexpr auto SBOX = make_sbox();

/// 逆 S-Box 常量
inline constexpr auto INV_SBOX = make_inv_sbox(SBOX);

/// 轮常数 Rcon（用于密钥扩展）
consteval std::array<uint8_t, 16> make_rcon() {
    std::array<uint8_t, 16> rcon{};
    uint8_t x = 1;
    for (int i = 1; i < 16; ++i) {
        rcon[i] = x;
        x = gf28_mul(x, 2);
    }
    return rcon;
}

inline constexpr auto RCON = make_rcon();

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
    std::array<uint8_t, MAX_EXPANDED_KEY> enc_rk{};      // 加密轮密钥
    std::array<uint8_t, MAX_EXPANDED_KEY> dec_rk{};      // 解密轮密钥（软件格式）
    std::array<uint8_t, MAX_EXPANDED_KEY> dec_rk_aesni{}; // 解密轮密钥（AES-NI 格式，_mm_aesimc 变换）
    AesKeySize key_size;
    int rounds;

    /// 从原始密钥初始化
    void init(std::span<const uint8_t, 16> key) { init_impl(key, AesKeySize::AES_128); }
    void init(std::span<const uint8_t, 24> key) { init_impl(key, AesKeySize::AES_192); }
    void init(std::span<const uint8_t, 32> key) { init_impl(key, AesKeySize::AES_256); }

private:
    void init_impl(std::span<const uint8_t> key, AesKeySize ks);
};

// ═══════════════════════════════════════════════════════════════════════
//  CPU 端加解密 API
// ═══════════════════════════════════════════════════════════════════════

/// 加密单个 16 字节块（CPU）
void aes_encrypt_block(const aes_context& ctx, const uint8_t plain[16], uint8_t cipher[16]);

/// 解密单个 16 字节块（CPU）
void aes_decrypt_block(const aes_context& ctx, const uint8_t cipher[16], uint8_t plain[16]);

/// ECB 模式加密（CPU）
/// input / output 长度必须为 16 的倍数
void aes_encrypt_ecb(const aes_context& ctx,
                     std::span<const uint8_t> input,
                     std::span<uint8_t> output);

/// ECB 模式解密（CPU）
void aes_decrypt_ecb(const aes_context& ctx,
                     std::span<const uint8_t> input,
                     std::span<uint8_t> output);

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
std::vector<uint8_t> pkcs7_pad(std::span<const uint8_t> data);

/// PKCS7 去填充：返回去填充后的数据，失败抛出 std::runtime_error
std::vector<uint8_t> pkcs7_unpad(std::span<const uint8_t> data);

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
                     std::span<const uint8_t> plaintext,
                     std::vector<uint8_t>& ciphertext);

/// CBC 解密（自动 PKCS7 去填充）
/// @return true 成功, false 填充验证失败
bool aes_cbc_decrypt(const aes_context& ctx,
                     const uint8_t iv[16],
                     std::span<const uint8_t> ciphertext,
                     std::vector<uint8_t>& plaintext);

// ═══════════════════════════════════════════════════════════════════════
//  GCM 模式（CPU 端 — Galois/Counter Mode，AEAD 认证加密）
// ═══════════════════════════════════════════════════════════════════════

/// GF(2^128) 乘法（用于 GHASH，不可约多项式 x^128+x^7+x^2+x+1）
void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]);

/// GHASH：GCM 的认证组件
/// @param H    AES_encrypt(K, 0^128) 结果
/// @param data 输入数据（AAD || ciphertext）
/// @param out  128-bit GHASH 输出
void ghash(const uint8_t H[16], std::span<const uint8_t> data, uint8_t out[16]);

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
                     std::span<const uint8_t> plaintext,
                     std::span<const uint8_t> aad,
                     std::vector<uint8_t>& ciphertext,
                     uint8_t* tag, size_t tag_len = 16);

/// GCM 解密（验证认证标签）
/// @return true 标签验证通过, false 验证失败（输出不应被使用）
bool aes_gcm_decrypt(const aes_context& ctx,
                     const uint8_t* iv, size_t iv_len,
                     std::span<const uint8_t> ciphertext,
                     std::span<const uint8_t> aad,
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
