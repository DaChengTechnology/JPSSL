// Minimal debug: verify fe_frombytes ↔ fe_tobytes roundtrip
#include "fe_25519.hpp"
#include <cstdio>
#include <cstring>

using fe = jpssl::fe_impl::fe;
using jpssl::fe_impl::fe_frombytes;
using jpssl::fe_impl::fe_tobytes;
using jpssl::fe_impl::fe_mul;
using jpssl::fe_impl::fe_add;
using jpssl::fe_impl::fe_sub;

void hex(const char* label, const uint8_t* d, int n) {
    printf("%s: ", label);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

int main() {
    // Test 1: fe_frombytes + fe_tobytes roundtrip for value 9
    uint8_t nine[32] = {9};
    fe x;
    fe_frombytes(x, nine);
    uint8_t out[32];
    fe_tobytes(out, x);
    printf("Test 1 - Roundtrip 9: %s\n", memcmp(nine, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(nine, out, 32)) { hex("  Got     ", out, 32); hex("  Expected", nine, 32); }

    // Test 2: fe_frombytes + fe_tobytes for value 0
    uint8_t zero[32] = {};
    fe_frombytes(x, zero);
    fe_tobytes(out, x);
    printf("Test 2 - Roundtrip 0: %s\n", memcmp(zero, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(zero, out, 32)) { hex("  Got     ", out, 32); hex("  Expected", zero, 32); }

    // Test 3: fe_frombytes + fe_tobytes for value 1
    uint8_t one[32] = {1};
    fe_frombytes(x, one);
    fe_tobytes(out, x);
    printf("Test 3 - Roundtrip 1: %s\n", memcmp(one, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(one, out, 32)) { hex("  Got     ", out, 32); hex("  Expected", one, 32); }

    // Test 4: fe_mul basic: 0 * 1 = 0
    fe a, b, c;
    fe_frombytes(a, zero);
    fe_frombytes(b, one);
    fe_mul(c, a, b);
    fe_tobytes(out, c);
    printf("Test 4 - 0*1=0:     %s\n", memcmp(zero, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(zero, out, 32)) { hex("  Got     ", out, 32); }

    // Test 5: fe_mul: 1 * 1 = 1
    fe_mul(c, b, b);
    fe_tobytes(out, c);
    printf("Test 5 - 1*1=1:     %s\n", memcmp(one, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(one, out, 32)) { hex("  Got     ", out, 32); }

    // Test 6: fe_mul: 9 * 1 = 9
    fe_frombytes(a, nine);
    fe_mul(c, a, b);
    fe_tobytes(out, c);
    printf("Test 6 - 9*1=9:     %s\n", memcmp(nine, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(nine, out, 32)) { hex("  Got     ", out, 32); }

    // Test 7: fe_mul: 9 * 9 = 81 (in GF(2^255-19), 9^2 mod p)
    uint8_t expected_81[32] = {81}; // 9*9=81 < p, so no reduction
    fe_mul(c, a, a);
    fe_tobytes(out, c);
    printf("Test 7 - 9*9=81:    %s\n", memcmp(expected_81, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(expected_81, out, 32)) { hex("  Got     ", out, 32); hex("  Expected", expected_81, 32); }

    // Test 8: fe_add: 1+1=2
    fe_add(c, b, b);
    fe_tobytes(out, c);
    uint8_t two[32] = {2};
    printf("Test 8 - 1+1=2:     %s\n", memcmp(two, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(two, out, 32)) { hex("  Got     ", out, 32); }

    printf("\nDone.\n");
    return 0;
}
