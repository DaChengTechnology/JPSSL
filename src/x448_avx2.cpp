/**
 * x448_avx2.cpp - X448 batch scalar multiplication, AVX2 4-way vectorized
 */
#include "x448.hpp"
#include "fe_448.hpp"
#include "fe_448_simd.hpp"
#include <cstring>

namespace jpssl { namespace x448_avx2_impl {
#include "x448_simd_body.inc"
} }

namespace jpssl {

void x448_scalar_mult_batch_avx2(uint8_t out[][56],
                                 const uint8_t* const* scalars,
                                 const uint8_t* const* points,
                                 int count)
{
    x448_avx2_impl::x448_scalar_mult_batch_simd(out, scalars, points, count);
}

} // namespace jpssl
