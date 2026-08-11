#pragma once

/**
 * chacha20_poly1305.hpp — ChaCha20-Poly1305 AEAD（RFC 8439）
 *
 * ChaCha20：256-bit 密钥流密码（Daniel J. Bernstein）
 * Poly1305：128-bit 一次性消息认证码
 *
 * 组合：ChaCha20 加密 + Poly1305 认证密文/AAD
 * 广泛用于 TLS 1.3、SSH、WireGuard、QUIC
 *
 * API 风格与 libsodium 兼容 (crypto_aead_chacha20poly1305_ietf_*)
 */

#include <cstddef>
#include <cstdint>
#include "jpssl_span.hpp"
#include <vector>

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  常量
// ═══════════════════════════════════════════════════════════════════════

/// ChaCha20 密钥大小（字节）
constexpr size_t CHACHA20_KEY_SIZE   = 32;  // 256-bit
/// ChaCha20-Poly1305 Nonce 大小（字节，IETF 变体）
constexpr size_t CHACHA20_NONCE_SIZE = 12;  // 96-bit
/// Poly1305 认证标签大小（字节）
constexpr size_t POLY1305_TAG_SIZE   = 16;  // 128-bit

/// ChaCha20 块大小（字节）
constexpr size_t CHACHA20_BLOCK_SIZE = 64;

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20 底层
// ═══════════════════════════════════════════════════════════════════════

/// ChaCha20 块加密：生成 keystream 块
/// @param key       32 字节密钥
/// @param counter   32-bit 块计数器
/// @param nonce     12 字节 nonce（96-bit）
/// @param keystream 输出 64 字节 keystream 块
void chacha20_block(const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12], uint8_t keystream[64]);

/// ChaCha20 流加密（XOR keystream → ciphertext）
/// 加密和解密操作相同（对称 XOR）
/// @param key      32 字节密钥
/// @param counter  初始块计数器（AEAD 使用 1，初始块 0 用于 Poly1305 密钥）
/// @param nonce    12 字节 nonce
/// @param input    明文（或密文）
/// @param output   密文（或明文），与 input 等长
void chacha20_crypt(const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12],
                    jpssl::span<const uint8_t> input,
                    jpssl::span<uint8_t> output);

// ═══════════════════════════════════════════════════════════════════════
//  Poly1305 底层
// ═══════════════════════════════════════════════════════════════════════

/// Poly1305 一次性认证
/// @param key  32 字节一次性密钥（前 16 字节 clamp 后作 r，后 16 字节作 s）
/// @param msg  待认证消息
/// @param tag  输出 16 字节认证标签
void poly1305_mac(const uint8_t key[32],
                  jpssl::span<const uint8_t> msg,
                  uint8_t tag[16]);

// ═══════════════════════════════════════════════════════════════════════
//  Poly1305 AVX2 加速（poly1305_avx2.cpp，运行时检测后由内部 dispatch 调用）
// ═══════════════════════════════════════════════════════════════════════

namespace poly_avx2 {

/// AVX2 内部状态（布局固定，poly1305_avx2.cpp 内部按 __m256i 使用）
struct State {
    // 26-bit 哈希肢体（lane0 为链；下一块组前广播）
    uint64_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    // r 幂系数表：r0..r4 与 5r1..5r4，每个 4×64 位 lane（块 0..3）
    uint64_t c[9][4] = {};
};

void init(State& st, const uint8_t key[32]);
/// 处理 n 字节（调用方保证 n 是 16 的倍数）
void feed(State& st, const uint8_t* p, size_t n);
/// 输出 16 字节标签
void finish(const State& st, const uint8_t key[32], uint8_t tag[16]);

}  // namespace poly_avx2

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20-Poly1305 AEAD（RFC 8439 §2.8）
// ═══════════════════════════════════════════════════════════════════════

/// AEAD 加密
/// @param key        32 字节密钥
/// @param nonce      12 字节 nonce（每次加密必须唯一！）
/// @param plaintext  明文（任意长度）
/// @param aad        附加认证数据（可为空）
/// @param ciphertext 输出密文（与明文等长，自动调整大小）
/// @param tag        输出 16 字节认证标签
void chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    jpssl::span<const uint8_t> plaintext,
    jpssl::span<const uint8_t> aad,
    std::vector<uint8_t>& ciphertext,
    uint8_t tag[16]);

/// AEAD 解密（验证标签）
/// @return true 认证通过, false 认证失败（密文被篡改）
bool chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    jpssl::span<const uint8_t> ciphertext,
    jpssl::span<const uint8_t> aad,
    const uint8_t tag[16],
    std::vector<uint8_t>& plaintext);

// ═══════════════════════════════════════════════════════════════════════
//  便捷接口：流加密（非 AEAD，仅 ChaCha20 XOR）
// ═══════════════════════════════════════════════════════════════════════

/// ChaCha20 流加密（无认证，XOR keystream）
/// @param key     32 字节密钥
/// @param nonce   12 字节 nonce
/// @param input   输入数据
/// @param output  输出数据（等长）
// SIMD 加速实现（chacha20_avx2.cpp / chacha20_avx512.cpp，运行时扩展检测后调用）
void chacha20_crypt_avx2(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12],
                         jpssl::span<const uint8_t> input,
                         jpssl::span<uint8_t> output);
void chacha20_crypt_avx512(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12],
                           jpssl::span<const uint8_t> input,
                           jpssl::span<uint8_t> output);
#if defined(JP_NEON) && defined(__aarch64__)
/// ARM NEON 加速流加密（chacha20_neon.cpp，4 块并行）
void chacha20_crypt_neon(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12],
                         jpssl::span<const uint8_t> input,
                         jpssl::span<uint8_t> output);
#endif

inline void chacha20_stream_xor(const uint8_t key[32], const uint8_t nonce[12],
                                jpssl::span<const uint8_t> input,
                                jpssl::span<uint8_t> output) {
    chacha20_crypt(key, 0, nonce, input, output);
}

#ifdef JP_MUSA
// ═══════════════════════════════════════════════════════════════════════
//  MUSA GPU 加速
// ═══════════════════════════════════════════════════════════════════════

struct musa_chacha20_pool;

musa_chacha20_pool* musa_chacha20_pool_create(
    const uint8_t key[32], const uint8_t nonce[12], size_t init_capacity = 0);
void musa_chacha20_pool_destroy(musa_chacha20_pool* pool);
void musa_chacha20_pool_set_nonce(musa_chacha20_pool* pool, const uint8_t nonce[12]);
void musa_chacha20_pool_keystream(musa_chacha20_pool* pool, uint8_t* keystream,
                                  size_t num_blocks, uint32_t base_counter);
void musa_chacha20_pool_xor(musa_chacha20_pool* pool, const uint8_t* input,
                            uint8_t* output, size_t num_blocks, uint32_t base_counter);
void musa_chacha20_pool_aead_encrypt(musa_chacha20_pool* pool, const uint8_t nonce[12],
                                     jpssl::span<const uint8_t> pt, jpssl::span<const uint8_t> aad,
                                     std::vector<uint8_t>& ct, uint8_t tag[16]);
bool musa_chacha20_pool_aead_decrypt(musa_chacha20_pool* pool, const uint8_t nonce[12],
                                     jpssl::span<const uint8_t> ct, jpssl::span<const uint8_t> aad,
                                     const uint8_t tag[16], std::vector<uint8_t>& pt);
#endif

} // namespace jpssl
