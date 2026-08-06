#pragma once
#include <cstddef>
#include <cstdint>
namespace jpssl {
inline constexpr size_t ED25519_KEY_SIZE=32, ED25519_SIG_SIZE=64, ED25519_SEED_SIZE=32;

void ed25519_keygen(uint8_t pub[32],uint8_t priv[64]);
/// 从 32 字节 seed 派生 32 字节公钥 (RFC 8032 §5.1.5)
void ed25519_derive_public_key(const uint8_t seed[32], uint8_t pub[32]);
void ed25519_sign(const uint8_t priv[64],const uint8_t* msg,size_t msg_len,uint8_t sig[64]);
bool ed25519_verify(const uint8_t pub[32],const uint8_t* msg,size_t msg_len,const uint8_t sig[64]);

// radix-2^51 后端（ed25519_r51.cpp）：默认调度目标，域乘法快 ~2.7x
void ed25519_keygen_r51(uint8_t pub[32],uint8_t priv[64]);
void ed25519_derive_public_key_r51(const uint8_t seed[32], uint8_t pub[32]);
void ed25519_sign_r51(const uint8_t priv[64],const uint8_t* msg,size_t msg_len,uint8_t sig[64]);
bool ed25519_verify_r51(const uint8_t pub[32],const uint8_t* msg,size_t msg_len,const uint8_t sig[64]);
}