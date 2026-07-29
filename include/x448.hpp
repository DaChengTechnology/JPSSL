#pragma once
#include <cstddef>
#include <cstdint>
namespace jpssl {
inline constexpr size_t X448_KEY_SIZE=56;
void x448_scalar_mult(uint8_t out[56], const uint8_t scalar[56], const uint8_t point[56]);
void x448_generate_keypair(uint8_t pub[56], uint8_t priv[56]);
}
