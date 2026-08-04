/**
 * test_x448_batch.cpp - X448 SIMD batch scalar multiplication test
 */
#include "x448.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>

using namespace jpssl;

static int rnd_state = 12345;
static uint8_t rnd8() {
    rnd_state = (rnd_state * 1103515245 + 12345) & 0x7fffffff;
    return (uint8_t)(rnd_state >> 16);
}

int main() {
    bool all = true;

    // RFC 7748 X448 vector: scalar=0x3d... base point
    {
        uint8_t scalar[56] = {0};
        scalar[0] = 0x3d;
        const uint8_t* scalars[4];
        const uint8_t* points[4] = { 0, 0, 0, 0 };
        uint8_t out[4][56];
        for (int i = 0; i < 4; ++i) scalars[i] = scalar;
        x448_scalar_mult_batch(out, scalars, points, 4);
        uint8_t ref[56];
        x448_scalar_mult(ref, scalar, nullptr);
        bool ok = true;
        for (int i = 0; i < 4; ++i) ok &= memcmp(out[i], ref, 56) == 0;
        printf("[%s] X448 batch RFC-vector matches scalar\n", ok ? "PASS" : "FAIL");
        all &= ok;
    }

    // random batches vs scalar, including odd counts
    for (int t = 0; t < 20; ++t) {
        int n = 1 + (t % 7);
        uint8_t sc[8][56], pt[8][56], out[8][56];
        const uint8_t* scalars[8];
        const uint8_t* points[8];
        for (int i = 0; i < n; ++i) {
            for (int b = 0; b < 56; ++b) { sc[i][b] = rnd8(); pt[i][b] = rnd8(); }
            scalars[i] = sc[i];
            points[i] = pt[i];
        }
        x448_scalar_mult_batch(out, scalars, points, n);
        bool ok = true;
        for (int i = 0; i < n; ++i) {
            uint8_t ref[56];
            x448_scalar_mult(ref, sc[i], pt[i]);
            if (memcmp(out[i], ref, 56) != 0) {
                ok = false;
                printf("  mismatch trial %d lane %d\n", t, i);
            }
        }
        printf("[%s] X448 batch random n=%d matches scalar\n", ok ? "PASS" : "FAIL", n);
        all &= ok;
    }

    printf("\n%s\n", all ? "ALL X448 BATCH TESTS PASSED" : "SOME X448 BATCH TESTS FAILED");
    return all ? 0 : 1;
}
