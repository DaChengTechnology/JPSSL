/**
 * x448_avx512.cpp — AVX512 backend (compiled with -mavx512f)
 */
#include "x448.hpp"
#include "fe_448.hpp"
#include <cstring>

namespace jpssl { namespace x448_avx512_impl {
#include "x448_body.inc"

void x448_scalar_mult_avx512(uint8_t out[56], const uint8_t scalar[56], const uint8_t point[56]) {
    x448_scalar_mult_impl(out, scalar, point);
}
} } // namespace jpssl::x448_avx512_impl
