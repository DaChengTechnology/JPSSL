/**
 * x448_body.inc — X448 core implementation (Montgomery ladder, RFC 7748)
 */
using namespace jpssl::fe448_impl;
using fe = fe448;

static void x448_scalar_mult_impl(uint8_t out[56], const uint8_t scalar[56], const uint8_t point[56]) {
    uint8_t e[56]; memcpy(e, scalar, 56);
    e[0] &= 0xFC; e[55] |= 0x80;

    static const uint8_t base[56] = {5};
    const uint8_t* u = point ? point : base;

    fe x1, x2, z2, x3, z3, a, b, c, d, da, cb, t, a24;
    fe448_frombytes(x1, u);
    fe448_1(x2); fe448_0(z2);
    fe448_frombytes(x3, u); fe448_1(z3);
    fe448_0(a24); a24[0] = 39081;

    int sw = 0;
    for (int i = 447; i >= 0; --i) {
        int bit = (e[i>>3] >> (i&7)) & 1;
        sw ^= bit;
        fe448_cswap(x2, x3, sw);
        fe448_cswap(z2, z3, sw);
        sw = bit;

        fe448_add(a, x2, z2);
        fe448_sub(b, x2, z2);
        fe448_add(c, x3, z3);
        fe448_sub(d, x3, z3);
        fe448_mul(da, d, a);
        fe448_mul(cb, c, b);
        fe448_add(x3, da, cb);
        fe448_sq(x3, x3);
        fe448_sub(t, da, cb);
        fe448_sq(z3, t);
        fe448_mul(z3, z3, x1);
        fe448_sq(x2, a);
        fe448_sq(z2, b);
        // RFC 7748: E = A^2 - B^2
        fe448_sub(t, x2, z2);
        // a24_scratch = A^2 (save before x2 overwritten)
        fe448_copy(a, x2);
        // x2 = A^2 * B^2
        fe448_mul(x2, x2, z2);
        // z2 = E * (a24_scratch + a24 * E)
        fe448_mul_small(z2, t, 39081);
        fe448_add(z2, z2, a);
        fe448_mul(z2, z2, t);
    }
    fe448_cswap(x2, x3, sw);
    fe448_cswap(z2, z3, sw);

    fe result;
    fe448_invert(z2, z2);
    fe448_mul(result, x2, z2);
    fe448_tobytes(out, result);
}
