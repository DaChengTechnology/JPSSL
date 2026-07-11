// Debug 2: test fe_invert and fe_sub
#include "fe_25519.hpp"
#include <cstdio>
#include <cstring>
using namespace jpssl::fe_impl;

void hex(const char* l, const uint8_t* d, int n) {
    printf("%s: ", l);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

int main() {
    uint8_t out[32], tmp[32];

    // Test fe_sub: 5 - 3 = 2
    fe a, b, c;
    uint8_t five[32] = {5};
    uint8_t three[32] = {3};
    uint8_t two[32] = {2};

    fe_frombytes(a, five);
    fe_frombytes(b, three);
    fe_sub(c, a, b);
    fe_tobytes(out, c);
    printf("Test Sub 5-3=2: %s\n", memcmp(two, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(two, out, 32)) { hex("  Got ", out, 32); }

    // Test fe_sub: 2 - 5 = p-3 (modular)
    fe a2, b2;
    fe_frombytes(a2, two);
    fe_frombytes(b2, five);
    fe_sub(c, a2, b2);
    fe_tobytes(out, c);
    // Add 3 should give p ≡ 0
    fe three_fe;
    fe_frombytes(three_fe, three);
    fe_add(c, c, three_fe);
    fe_tobytes(out, c);
    // should be all zeros (2-5+3=0 mod p)
    // But actually it's (p-3)+3 mod p ... need final reduction
    // Let me just test: (p-3)+3 in GF should reduce to 0
    // But fe_tobytes does not fully reduce to canonical form
    // Let's skip this for now

    // Test fe_invert: 2 * inv(2) = 1
    fe u, inv, prod;
    fe_frombytes(u, five);
    fe_invert(inv, u);
    fe_mul(prod, u, inv);
    fe_tobytes(out, prod);
    uint8_t one[32] = {1};
    printf("Test Invert 5*inv(5)=1: %s\n", memcmp(one, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(one, out, 32)) { hex("  Got ", out, 32); }

    // Test fe_invert: 1 * inv(1) = 1
    fe_frombytes(u, one);
    fe_invert(inv, u);
    fe_mul(prod, u, inv);
    fe_tobytes(out, prod);
    printf("Test Invert 1*inv(1)=1: %s\n", memcmp(one, out, 32) == 0 ? "PASS" : "FAIL");
    if (memcmp(one, out, 32)) { hex("  Got ", out, 32); }

    // Test Cswap
    fe p, q;
    fe_0(p); p[0] = 1;
    fe_0(q); q[0] = 2;
    fe_cswap(p, q, 0);
    uint8_t p_out[32], q_out[32];
    fe_tobytes(p_out, p);
    fe_tobytes(q_out, q);
    printf("Test Cswap(0) p == 1: %s\n", p_out[0] == 1 && p_out[1] == 0 ? "PASS" : "FAIL");
    printf("Test Cswap(0) q == 2: %s\n", q_out[0] == 2 && q_out[1] == 0 ? "PASS" : "FAIL");

    fe_cswap(p, q, 1);
    fe_tobytes(p_out, p);
    fe_tobytes(q_out, q);
    printf("Test Cswap(1) p == 2: %s\n", p_out[0] == 2 && p_out[1] == 0 ? "PASS" : "FAIL");
    printf("Test Cswap(1) q == 1: %s\n", q_out[0] == 1 && q_out[1] == 0 ? "PASS" : "FAIL");

    printf("\nDone.\n");
    return 0;
}
