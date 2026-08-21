#pragma once
#include <cstddef>
#include <cstdint>
namespace jpssl {

// ── P-256 (secp256r1) ──
constexpr size_t ECDSA_P256_KEY_SIZE=32, ECDSA_P256_SIG_SIZE=64, ECDSA_P256_PUB_SIZE=64;

void ecdsa_p256_keygen(uint8_t pub[64],uint8_t priv[32]);
void ecdsa_p256_sign(const uint8_t priv[32],const uint8_t* msg,size_t msg_len,uint8_t sig[64]);
bool ecdsa_p256_verify(const uint8_t pub[64],const uint8_t* msg,size_t msg_len,const uint8_t sig[64]);

// ── P-384 (secp384r1) ──
constexpr size_t ECDSA_P384_KEY_SIZE=48, ECDSA_P384_SIG_SIZE=96, ECDSA_P384_PUB_SIZE=96;

void ecdsa_p384_keygen(uint8_t pub[96],uint8_t priv[48]);
void ecdsa_p384_sign(const uint8_t priv[48],const uint8_t* msg,size_t msg_len,uint8_t sig[96]);
bool ecdsa_p384_verify(const uint8_t pub[96],const uint8_t* msg,size_t msg_len,const uint8_t sig[96]);

// ── P-521 (secp521r1) ──
constexpr size_t ECDSA_P521_KEY_SIZE=66, ECDSA_P521_SIG_SIZE=132, ECDSA_P521_PUB_SIZE=132;

void ecdsa_p521_keygen(uint8_t pub[132],uint8_t priv[66]);
void ecdsa_p521_sign(const uint8_t priv[66],const uint8_t* msg,size_t msg_len,uint8_t sig[132]);
bool ecdsa_p521_verify(const uint8_t pub[132],const uint8_t* msg,size_t msg_len,const uint8_t sig[132]);

// ── ECDHE 共享密钥（TLS key exchange 用）──
// shared = X(priv * pub)，pub 为大端 x||y（无 0x04 前缀），
// 共享密钥为大端 X 坐标（RFC 8446 §4.2.8.2 / 传统 ECDHE 定义）。
/// P-256：shared 32 字节，priv 32 字节，pub 64 字节（x||y）
bool ecdsa_p256_ecdh(uint8_t shared[32], const uint8_t priv[32], const uint8_t pub[64]);
/// P-384：shared 48 字节，priv 48 字节，pub 96 字节（x||y）
bool ecdsa_p384_ecdh(uint8_t shared[48], const uint8_t priv[48], const uint8_t pub[96]);
bool ecdsa_p521_ecdh(uint8_t shared[66], const uint8_t priv[66],
                     const uint8_t pub[132]);

// ── 批量 ECDHE（多条共享密钥一次计算，批量求逆摊薄模逆成本）──
// 布局：shared/priv/pub 均为连续数组（每项 32/64 字节，P-384 为 48/96）。
// count ≥ 1；批量内部按 16 条一块处理，块内仅 2 次 Fermat 求逆。
bool ecdsa_p256_ecdh_batch(uint8_t* shared, const uint8_t* priv, const uint8_t* pub, int count);
bool ecdsa_p384_ecdh_batch(uint8_t* shared, const uint8_t* priv, const uint8_t* pub, int count);

}
