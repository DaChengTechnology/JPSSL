// Simplified test: ge_scalarmult with small scalars vs direct ops
#include "sha512.hpp"
#include "ed25519.cpp"
#include <cstdio>
#include <cstring>
using namespace jpssl;
using namespace jpssl::ed25519_ref10_impl;
using namespace fe_impl;

static void hex(const char* label, const uint8_t* d, int n) {
    printf("%s: ", label);
    for (int i=0;i<n;i++) printf("%02x",d[i]);
    printf("\n");
}

int main() {
    uint8_t pub[32] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    ge_p3 A;
    ge_frombytes(&A, pub);
    
    // Test: 2*A via scalar mult vs direct doubling 
    printf("=== 2*A: scalar mult vs direct dbl ===\n");
    uint8_t s2[32] = {2,0};
    ge_p3 r2;
    ge_scalarmult(&r2, s2, &A);
    uint8_t r2_enc[32]; ge_tobytes(r2_enc, &r2);
    hex("2*A (scalar)", r2_enc, 32);
    
    ge_p1p1 t;
    ge_p3_dbl(&t, &A);
    ge_p3 dblA;
    ge_p1p1_to_p3(&dblA, &t);
    uint8_t dbl_enc[32]; ge_tobytes(dbl_enc, &dblA);
    hex("2*A (direct)", dbl_enc, 32);
    printf("Match: %s\n\n", memcmp(r2_enc, dbl_enc, 32)==0?"YES":"NO");
    
    // Test: A + A should also equal 2*A
    printf("=== A + A vs 2*A ===\n");
    ge_p1p1 ta;
    ge_add(&ta, &A, &A);
    ge_p3 AplusA;
    ge_p1p1_to_p3(&AplusA, &ta);
    uint8_t add_enc[32]; ge_tobytes(add_enc, &AplusA);
    hex("A + A      ", add_enc, 32);
    hex("2*A (dbl)  ", dbl_enc, 32);
    printf("Match: %s\n\n", memcmp(add_enc, dbl_enc, 32)==0?"YES":"NO");
    
    // Test: 4*A via scalar mult vs 2*(2*A)
    printf("=== 4*A: scalar mult vs 2*(2*A) ===\n");
    uint8_t s4[32] = {4,0};
    ge_p3 r4;
    ge_scalarmult(&r4, s4, &A);
    uint8_t r4_enc[32]; ge_tobytes(r4_enc, &r4);
    hex("4*A (scalar)", r4_enc, 32);
    
    ge_p1p1 t2d;
    ge_p3_dbl(&t2d, &dblA);
    ge_p3 quadA;
    ge_p1p1_to_p3(&quadA, &t2d);
    uint8_t quad_enc[32]; ge_tobytes(quad_enc, &quadA);
    hex("4*A (2*2*A) ", quad_enc, 32);
    printf("Match: %s\n\n", memcmp(r4_enc, quad_enc, 32)==0?"YES":"NO");
    
    // Test: k*A with k from RFC test (lots of bits)
    printf("=== k*A with large k ===\n");
    uint8_t k[32] = {0x04,0x54,0x52,0x2e,0x16,0x7e,0x3e,0x8a,0x13,0x2c,0xec,0x31,0x61,0x25,0xd8,0xf8,0x6c,0xdf,0x00,0xc6,0xe7,0x04,0x05,0x29,0x3d,0x19,0x96,0x4c,0x8e,0xea,0xbc,0x86};
    ge_p3 kA;
    ge_scalarmult(&kA, k, &A);
    uint8_t kA_enc[32]; ge_tobytes(kA_enc, &kA);
    hex("k*A (large k)", kA_enc, 32);
    
    // Trace: do step-by-step for first 8 bits 
    printf("\n=== Step-by-step first 8 bits of k*A ===\n");
    int first = -1;
    for (int i = 255; i >= 0; i--)
        if ((k[i >> 3] >> (i & 7)) & 1) { first = i; break; }
    printf("First set bit: %d\n", first);
    
    ge_p3 acc;
    ge_p3_to_p3(&acc, &A);
    
    for (int i = first - 1; i >= first - 8 && i >= 0; i--) {
        ge_p1p1 dt;
        ge_p3_dbl(&dt, &acc);
        ge_p1p1_to_p3(&acc, &dt);
        int bit = (k[i >> 3] >> (i & 7)) & 1;
        if (bit) {
            ge_p1p1 at;
            ge_add(&at, &acc, &A);
            ge_p1p1_to_p3(&acc, &at);
        }
        uint8_t acc_enc[32]; ge_tobytes(acc_enc, &acc);
        printf("  after bit %d (%d): ", i, bit);
        for (int j=0;j<16;j++) printf("%02x", acc_enc[j]);
        printf("...\n");
    }
    
    return 0;
}
