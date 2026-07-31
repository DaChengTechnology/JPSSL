/**
 * x25519.cpp — X25519 密钥协商（调度层 + radix-2^51 标量基线）
 *
 * 按优先级调度：
 *   - 若 AVX512 可用 → x25519_avx512_impl::x25519_scalar_mult_avx512
 *   - 否则 → 内联标量实现（fe_25519_r51.hpp，radix-2^51）
 */
#include "x25519.hpp"
#include "cpu_features.hpp"
#include <cstring>
#include <random>

// ── 标量基线 ──
namespace jpssl { namespace x25519_cpu_impl {
#include "x25519_body.inc"

static void x25519_scalar_mult_cpu(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    x25519_scalar_mult_impl(out, scalar, point);
}

} } // namespace jpssl::x25519_cpu_impl

// ── 前向声明 ──
namespace jpssl { namespace x25519_avx512_impl {
void x25519_scalar_mult_avx512(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
} }

namespace jpssl {

void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    if (cpu_has_avx512()) {
        x25519_avx512_impl::x25519_scalar_mult_avx512(out, scalar, point);
        return;
    }
    x25519_cpu_impl::x25519_scalar_mult_cpu(out, scalar, point);
}

void x25519_generate_keypair(uint8_t pub[32], uint8_t priv[32]) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    for (int i = 0; i < 4; ++i) {
        uint64_t v = gen();
        memcpy(priv + i * 8, &v, 8);
    }
    priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;
    x25519_scalar_mult(pub, priv, nullptr);
}

} // namespace jpssl
