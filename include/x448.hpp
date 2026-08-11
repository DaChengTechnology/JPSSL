#pragma once
#include <cstddef>
#include <cstdint>
namespace jpssl {
constexpr size_t X448_KEY_SIZE=56;
void x448_scalar_mult(uint8_t out[56], const uint8_t scalar[56], const uint8_t point[56]);
void x448_generate_keypair(uint8_t pub[56], uint8_t priv[56]);

/// Batch X448 scalar multiplication: processes count independent inputs,
/// using the widest available SIMD backend (AVX512=8, AVX2=4, scalar=1).
void x448_scalar_mult_batch(uint8_t out[][56],
                            const uint8_t* const* scalars,
                            const uint8_t* const* points,
                            int count);

#if defined(JP_AVX2)
void x448_scalar_mult_batch_avx2(uint8_t out[][56],
                                 const uint8_t* const* scalars,
                                 const uint8_t* const* points,
                                 int count);
#endif
#if defined(JP_AVX512)
void x448_scalar_mult_batch_avx512(uint8_t out[][56],
                                   const uint8_t* const* scalars,
                                   const uint8_t* const* points,
                                   int count);
#endif
}
