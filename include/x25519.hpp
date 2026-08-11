#pragma once
#include <cstddef>
#include <cstdint>
namespace jpssl {
constexpr size_t X25519_KEY_SIZE=32;
void x25519_scalar_mult(uint8_t out[32],const uint8_t scalar[32],const uint8_t point[32]);
void x25519_generate_keypair(uint8_t pub[32],uint8_t priv[32]);
}
