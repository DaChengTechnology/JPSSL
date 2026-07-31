/**
 * x25519_avx512.cpp — AVX512 加速版本 (编译标志: -mavx512f -mavx512dq)
 *
 * 通过 AVX512 自动向量化加速 fe_25519.hpp 中的 10-limb 域运算。
 * fe_mul 和 fe_sq 的循环被编译器自动展开为 512-bit SIMD。
 */
#include "x25519.hpp"
#include <cstring>
#include <random>

namespace jpssl { namespace x25519_avx512_impl {
#include "x25519_body.inc"

void x25519_scalar_mult_avx512(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    x25519_scalar_mult_impl(out, scalar, point);
}

} } // namespace jpssl::x25519_avx512_impl
