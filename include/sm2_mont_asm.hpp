#pragma once
/**
 * sm2_mont_asm.hpp - SM2 256-bit Montgomery multiplication, ADX fast path
 *
 * Provides the BMI2 (MULX) + ADX (ADCX/ADOX) accelerated Montgomery
 * multiplication used by src/sm2.cpp. Same semantics as the portable CIOS
 * path: r = a*b*R^{-1} mod m with R = 2^256, a,b in [0,m), r in [0,m).
 */
#include <cstdint>

namespace jpssl {

/// BMI2 (MULX) + ADX (ADCX/ADOX) availability (cached after first call).
bool sm2_mont_asm_available();

/// r = a*b*R^{-1} mod m. Only call when sm2_mont_asm_available() is true;
/// otherwise src/sm2.cpp keeps using its portable C path.
void sm2_mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4],
                  const uint64_t m[4], uint64_t mp);

/// r = a*a*R^{-1} mod m (currently implemented as mul(a, a)).
void sm2_mont_sqr(uint64_t r[4], const uint64_t a[4],
                  const uint64_t m[4], uint64_t mp);

} // namespace jpssl
