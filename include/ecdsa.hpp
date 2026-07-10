#pragma once
#include <cstddef>
#include <cstdint>
namespace jpssl {
inline constexpr size_t ECDSA_P256_KEY_SIZE=32, ECDSA_P256_SIG_SIZE=64, ECDSA_P256_PUB_SIZE=64;

void ecdsa_p256_keygen(uint8_t pub[64],uint8_t priv[32]);
void ecdsa_p256_sign(const uint8_t priv[32],const uint8_t* msg,size_t msg_len,uint8_t sig[64]);
bool ecdsa_p256_verify(const uint8_t pub[64],const uint8_t* msg,size_t msg_len,const uint8_t sig[64]);
}