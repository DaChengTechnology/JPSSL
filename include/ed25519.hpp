#pragma once
#include <cstddef>
#include <cstdint>
namespace jpssl {
inline constexpr size_t ED25519_KEY_SIZE=32, ED25519_SIG_SIZE=64, ED25519_SEED_SIZE=32;

void ed25519_keygen(uint8_t pub[32],uint8_t priv[64]);
void ed25519_sign(const uint8_t priv[64],const uint8_t* msg,size_t msg_len,uint8_t sig[64]);
bool ed25519_verify(const uint8_t pub[32],const uint8_t* msg,size_t msg_len,const uint8_t sig[64]);
}