#include "x448.hpp"
#include "fe_448.hpp"
#include "cpu_features.hpp"
#include <cstring>
#include <random>

namespace jpssl { namespace x448_cpu_impl {
#include "x448_body.inc"
} }

namespace jpssl {

void x448_scalar_mult(uint8_t out[56], const uint8_t scalar[56], const uint8_t point[56]) {
    x448_cpu_impl::x448_scalar_mult_impl(out, scalar, point);
}

void x448_scalar_mult_batch(uint8_t out[][56],
                            const uint8_t* const* scalars,
                            const uint8_t* const* points,
                            int count)
{
    if (count <= 0) return;
#if defined(JP_AVX512)
    if (cpu_has_avx512()) {
        x448_scalar_mult_batch_avx512(out, scalars, points, count);
        return;
    }
#endif
#if defined(JP_AVX2)
    if (cpu_has_avx2()) {
        x448_scalar_mult_batch_avx2(out, scalars, points, count);
        return;
    }
#endif
    for (int i = 0; i < count; ++i)
        x448_cpu_impl::x448_scalar_mult_impl(out[i], scalars[i],
                                             points ? points[i] : nullptr);
}

void x448_generate_keypair(uint8_t pub[56], uint8_t priv[56]) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    for (int i = 0; i < 7; ++i) {
        uint64_t v = gen();
        memcpy(priv + i * 8, &v, 8);
    }
    priv[0] &= 0xFC;
    priv[55] |= 0x80;
    x448_scalar_mult(pub, priv, nullptr);
}

} // namespace jpssl
