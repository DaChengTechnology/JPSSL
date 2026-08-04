/**
 * x448_simd_body.inc - N-way SIMD X448 Montgomery ladder
 * (N = JF448_LANES: 4 on AVX2, 8 on AVX512).
 *
 * Each lane runs an independent RFC 7748 scalar multiplication with the
 * lane-sliced feN field arithmetic; the swap mask is lane-dependent.
 */
#include "fe_448_simd.hpp"
#include <cstring>

using namespace jpssl::fe448_simd;

static void x448_scalar_mult_batch_simd(uint8_t out[][56],
                                        const uint8_t* const* scalars,
                                        const uint8_t* const* points,
                                        int count)
{
    static const uint8_t x448_base[56] = {5};
    for (int off = 0; off < count; off += JF448_LANES) {
        int n = (off + JF448_LANES <= count) ? JF448_LANES : (count - off);

        uint8_t e[JF448_LANES][56];
        uint8_t u[JF448_LANES][56];
        const uint8_t* up[JF448_LANES];
        for (int j = 0; j < JF448_LANES; ++j) {
            int src = (j < n) ? off + j : off;
            memcpy(e[j], scalars[src], 56);
            const uint8_t* p = (points && points[src]) ? points[src] : x448_base;
            memcpy(u[j], p, 56);
            e[j][0] &= 0xFC;
            e[j][55] |= 0x80;
            up[j] = u[j];
        }

        feN x1, x2, z2, x3, z3, a, b, c, d, da, cb, t, a24;
        feN_frombytes(x1, up);
        feN_one(x2); feN_zero(z2);
        feN_frombytes(x3, up); feN_one(z3);
        feN_zero(a24);
        a24.limb[0] = jf448_set1(39081);

        int sw[JF448_LANES] = {0};
        for (int i = 447; i >= 0; --i) {
            uint8_t bits[JF448_LANES];
            for (int j = 0; j < JF448_LANES; ++j) {
                sw[j] ^= (e[j][i >> 3] >> (i & 7)) & 1;
                bits[j] = (uint8_t)sw[j];
            }
            jf448_m swm = jf448_mask_from_bits(bits);
            feN_cswap(x2, x3, swm);
            feN_cswap(z2, z3, swm);
            for (int j = 0; j < JF448_LANES; ++j)
                bits[j] = (uint8_t)((e[j][i >> 3] >> (i & 7)) & 1);
            for (int j = 0; j < JF448_LANES; ++j) sw[j] = bits[j];

            feN_add(a, x2, z2);
            feN_sub(b, x2, z2);
            feN_add(c, x3, z3);
            feN_sub(d, x3, z3);
            feN_mul(da, d, a);
            feN_mul(cb, c, b);
            feN_add(t, da, cb);
            feN_sq(x3, t);
            feN_sub(t, da, cb);
            feN_sq(z3, t);
            feN_mul(z3, z3, x1);
            feN_sq(x2, a);
            feN_sq(z2, b);
            feN_sub(t, x2, z2);
            feN_copy(a, x2);
            feN_mul(x2, x2, z2);
            feN_mul_small(z2, t, 39081);
            feN_add(z2, z2, a);
            feN_mul(z2, z2, t);
        }

        uint8_t swb[JF448_LANES];
        for (int j = 0; j < JF448_LANES; ++j) swb[j] = (uint8_t)sw[j];
        jf448_m swm = jf448_mask_from_bits(swb);
        feN_cswap(x2, x3, swm);
        feN_cswap(z2, z3, swm);

        feN z2_inv;
        feN_invert(z2_inv, z2);
        feN res;
        feN_mul(res, x2, z2_inv);
        uint8_t scratch[JF448_LANES][56];
        uint8_t* rp[JF448_LANES];
        for (int j = 0; j < n; ++j) rp[j] = out[off + j];
        for (int j = n; j < JF448_LANES; ++j) rp[j] = scratch[j];  // padding lane
        feN_tobytes(rp, res);
    }
}
