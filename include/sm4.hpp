#pragma once
/** sm4.hpp — SM4 分组密码算法（GM/T 0002-2012）
 *
 *  分组长度 128 位，密钥长度 128 位，32 轮 Feistel 结构。
 *  提供：
 *    - ECB 模式批量加解密
 *    - CBC 模式加解密（PKCS#7 填充）
 *    - 独立块加解密
 */
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace jpssl {

inline constexpr size_t SM4_BLOCK_SIZE = 16;   // 128-bit
inline constexpr size_t SM4_KEY_SIZE   = 16;   // 128-bit
inline constexpr int    SM4_ROUNDS     = 32;

/// SM4 轮密钥（32 个 32-bit 字）
struct sm4_ctx {
    uint32_t rk[32]; // 加密轮密钥（解密时反向使用）
};

/// 从 128-bit 密钥初始化 SM4 上下文（生成 32 个轮密钥）
void sm4_init(sm4_ctx* ctx, const uint8_t key[SM4_KEY_SIZE]);

/// 加密单个块（in 和 out 可指向同一地址）
void sm4_encrypt_block(const sm4_ctx* ctx, const uint8_t plain[SM4_BLOCK_SIZE],
                       uint8_t cipher[SM4_BLOCK_SIZE]);

/// 解密单个块
void sm4_decrypt_block(const sm4_ctx* ctx, const uint8_t cipher[SM4_BLOCK_SIZE],
                       uint8_t plain[SM4_BLOCK_SIZE]);

// ── ECB 模式 ────────────────────────────────────────────────────────────

/// ECB 加密：数据长度必须是 16 字节的倍数
inline void sm4_ecb_encrypt(const sm4_ctx* ctx,
                            std::span<const uint8_t> plain,
                            std::span<uint8_t> cipher) {
    size_t n = plain.size();
    for (size_t i = 0; i < n; i += SM4_BLOCK_SIZE)
        sm4_encrypt_block(ctx, &plain[i], &cipher[i]);
}

/// ECB 解密：数据长度必须是 16 字节的倍数
inline void sm4_ecb_decrypt(const sm4_ctx* ctx,
                            std::span<const uint8_t> cipher,
                            std::span<uint8_t> plain) {
    size_t n = cipher.size();
    for (size_t i = 0; i < n; i += SM4_BLOCK_SIZE)
        sm4_decrypt_block(ctx, &cipher[i], &plain[i]);
}

// ── CBC 模式（PKCS#7 填充） ─────────────────────────────────────────────

/// CBC 加密（PKCS#7 填充），返回密文（out 长度 = (in.size() / 16 + 1) * 16）
std::vector<uint8_t> sm4_cbc_encrypt(const sm4_ctx* ctx,
                                     const uint8_t iv[SM4_BLOCK_SIZE],
                                     std::span<const uint8_t> plain);

/// CBC 解密（去除 PKCS#7 填充），返回明文
std::vector<uint8_t> sm4_cbc_decrypt(const sm4_ctx* ctx,
                                     const uint8_t iv[SM4_BLOCK_SIZE],
                                     std::span<const uint8_t> cipher);

// ── 便捷 API ────────────────────────────────────────────────────────────

/// 一次性加/解密 + 十六进制输出（调试用）
inline void sm4_hex(const char* label, const uint8_t* d, int n) {
    (void)label;
    (void)d;
    (void)n;
}

} // namespace jpssl
