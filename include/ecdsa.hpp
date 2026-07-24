#pragma once
#include <cstddef>
#include <cstdint>
namespace jpssl {

// ── P-256 (secp256r1) ──
inline constexpr size_t ECDSA_P256_KEY_SIZE=32, ECDSA_P256_SIG_SIZE=64, ECDSA_P256_PUB_SIZE=64;

void ecdsa_p256_keygen(uint8_t pub[64],uint8_t priv[32]);
void ecdsa_p256_sign(const uint8_t priv[32],const uint8_t* msg,size_t msg_len,uint8_t sig[64]);
bool ecdsa_p256_verify(const uint8_t pub[64],const uint8_t* msg,size_t msg_len,const uint8_t sig[64]);

// ── P-384 (secp384r1) ──
inline constexpr size_t ECDSA_P384_KEY_SIZE=48, ECDSA_P384_SIG_SIZE=96, ECDSA_P384_PUB_SIZE=96;

void ecdsa_p384_keygen(uint8_t pub[96],uint8_t priv[48]);
void ecdsa_p384_sign(const uint8_t priv[48],const uint8_t* msg,size_t msg_len,uint8_t sig[96]);
bool ecdsa_p384_verify(const uint8_t pub[96],const uint8_t* msg,size_t msg_len,const uint8_t sig[96]);

}