#include "x25519.hpp"
#include "fe_25519.hpp"
#include <cstring>
#include <random>

namespace jpssl {

using fe = fe_impl::fe;
using fe_impl::fe_frombytes;
using fe_impl::fe_tobytes;
using fe_impl::fe_add;
using fe_impl::fe_sub;
using fe_impl::fe_mul;
using fe_impl::fe_sq;
using fe_impl::fe_invert;
using fe_impl::fe_cswap;
using fe_impl::fe_copy;

void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0] &= 248; e[31] &= 127; e[31] |= 64;

    static const uint8_t base[32] = {9};
    const uint8_t* u = point ? point : base;

    fe x1, x2, z2, x3, z3, a, b, c, d, da, cb, t;
    fe_frombytes(x1, u);

    memset(x2, 0, sizeof(int32_t) * 10); x2[0] = 1;
    memset(z2, 0, sizeof(int32_t) * 10);
    fe_frombytes(x3, u);
    memset(z3, 0, sizeof(int32_t) * 10); z3[0] = 1;

    fe a24; memset(a24, 0, sizeof(int32_t) * 10); a24[0] = 121665;

    int swap = 0;
    for (int i = 254; i >= 0; --i) {
        int b_val = (e[i >> 3] >> (i & 7)) & 1;
        swap ^= b_val;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b_val;

        fe_add(a, x2, z2);
        fe_sub(b, x2, z2);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b);
        fe_add(x3, da, cb);
        fe_sq(x3, x3);
        fe_sub(t, da, cb);
        fe_sq(z3, t);
        fe_mul(z3, x1, z3);
        fe_sq(x2, a);
        fe_sq(z2, b);
        fe_sub(t, x2, z2);
        fe_copy(a, x2);      // save AA
        fe_mul(x2, x2, z2);  // x2 = AA * BB
        fe_mul(z2, t, a24);
        fe_add(z2, z2, a);   // z2 = E*a24 + AA
        fe_mul(z2, z2, t);   // z2 = (E*a24 + AA) * E
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);
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
