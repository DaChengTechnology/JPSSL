/**
 * x448_avx2.cpp — AVX2 backend (compiled with -mavx2)
 */
#include "x448.hpp"
#include "fe_448.hpp"
#include <cstring>

namespace jpssl { namespace x448_avx2_impl {
#include "x448_body.inc"

void x448_scalar_mult_avx2(uint8_t out[56], const uint8_t scalar[56], const uint8_t point[56]) {
    x448_scalar_mult_impl(out, scalar, point);
}
} } // namespace jpssl::x448_avx2_impl
