#pragma once
/**
 * ed448.hpp — Ed448 签名算法 (RFC 8032 §5.2)
 *
 * 曲线参数:
 *   p = 2^448 - 2^224 - 1
 *   d = -39081 mod p
 *   L = 2^446 - 13818066809895115352007386748515426880336692474882178609894552837804553022741537
 *   c = 2 (cofactor)
 *   Base point B 由预计算
 *
 * Ed448 钥格式: 57 字节私钥 (seed)
 * 公钥: 57 字节 (y 编码 + sign bit)
 * 签名: 114 字节 (R || S)
 *
 * 使用 SHAKE256 作为 hash 函数 (domain: 0x448[0] | 0x448[1] | 0x00 | 0x00 | 0x00)
 */
#include <cstddef>
#include <cstdint>
namespace jpssl {

inline constexpr size_t ED448_KEY_SIZE   = 57;   // 公钥/私钥字节数
inline constexpr size_t ED448_SEED_SIZE  = 57;   // 私钥 seed
inline constexpr size_t ED448_SIG_SIZE   = 114;  // 签名字节数 (R + S)
inline constexpr size_t ED448_PRIV_SIZE  = 114;  // 完整私钥 = seed || pub

/// Ed448 公钥派生：从 57 字节 seed 计算 57 字节公钥
void ed448_keygen(uint8_t pub[57], uint8_t priv_seed[57]);

/// 完整密钥对生成（私钥 seed + 公钥，输出 114 字节 priv）
/// priv[0..56]   = seed
/// priv[57..113] = public key
void ed448_generate_keypair(uint8_t pub[57], uint8_t priv[114]);

/// Ed448 签名
/// priv: 114 字节（seed || pub）或 57 字节 seed
/// msg: 待签名消息
/// 输出: sig[114]
void ed448_sign(const uint8_t* priv, const uint8_t* msg, size_t msg_len, uint8_t sig[114]);

/// Ed448 验证
/// pub: 57 字节公钥
/// msg: 消息
/// sig: 114 字节签名
bool ed448_verify(const uint8_t pub[57], const uint8_t* msg, size_t msg_len, const uint8_t sig[114]);

// ─── Debug / 测试接口 ─────────────────────────────────────────────────
struct ed448_point {
    uint64_t X[8], Y[8], Z[8];
};

bool ed448_debug_decode(ed448_point& P, const uint8_t in[57]);
void ed448_debug_encode(const ed448_point& P, uint8_t out[57]);
void ed448_debug_scalar_mult(ed448_point& R, const uint8_t scalar[57], const ed448_point& P);
void ed448_debug_point_add(ed448_point& R, const ed448_point& P, const ed448_point& Q);
void ed448_debug_point_double(ed448_point& R, const ed448_point& P);
const ed448_point& ed448_debug_base_point();

} // namespace jpssl
