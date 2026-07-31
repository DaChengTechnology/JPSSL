// Test: ge_scalarmult_base with RFC Test 1 clamped scalar
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
    // RFC 8032 Test 1: compute pub = clamped_scalar * B
    uint8_t seed[32] = {
        0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
        0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
        0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
    };
    uint8_t expected_pub[32] = {
        0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
        0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
        0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
    };
    
    // SHA-512(seed) + clamp
    uint8_t h[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, h);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    
    hex("clamped scalar", h, 32);
    
    ge_p3 A;
    ge_scalarmult_base(&A, h);
    uint8_t pub[32];
    ge_tobytes(pub, &A);
    
    hex("computed pub", pub, 32);
    hex("expected pub ", expected_pub, 32);
    printf("Match: %s\n", memcmp(pub, expected_pub, 32)==0?"YES":"NO");
    
    // Also test with a small scalar: clamped 2  
    uint8_t s2[32] = {2,0};
    ge_p3 r2;
    ge_scalarmult_base(&r2, s2);
    uint8_t r2_enc[32]; ge_tobytes(r2_enc, &r2);
    const ge_p3* B = ge_get_basepoint();
    ge_p1p1 t;
    ge_p3_dbl(&t, B);
    ge_p3 dblB;
    ge_p1p1_to_p3(&dblB, &t);
    uint8_t dbl_enc[32]; ge_tobytes(dbl_enc, &dblB);
    printf("\n2*B via scalar: "); for(int i=0;i<32;i++) printf("%02x", r2_enc[i]); printf("\n");
    printf("2*B via dbl:    "); for(int i=0;i<32;i++) printf("%02x", dbl_enc[i]); printf("\n");
    printf("Match: %s\n", memcmp(r2_enc, dbl_enc, 32)==0?"YES":"NO");
    
    // Test clamped scalar with all bits set (full 256-bit)
    // Use k from RFC verification test 
    uint8_t k[32] = {0x04,0x54,0x52,0x2e,0x16,0x7e,0x3e,0x8a,0x13,0x2c,0xec,0x31,0x61,0x25,0xd8,0xf8,0x6c,0xdf,0x00,0xc6,0xe7,0x04,0x05,0x29,0x3d,0x19,0x96,0x4c,0x8e,0xea,0xbc,0x86};
    ge_p3 kB;
    ge_scalarmult_base(&kB, k);
    uint8_t kB_enc[32]; ge_tobytes(kB_enc, &kB);
    printf("\nk*B via scalar_base: %s", "");
    for(int i=0;i<32;i++) printf("%02x", kB_enc[i]); printf("\n");
    
    // Same but with ge_scalarmult
    ge_p3 kB2;
    ge_scalarmult(&kB2, k, B);
    uint8_t kB2_enc[32]; ge_tobytes(kB2_enc, &kB2);
    printf("k*B via scalar_mult:  %s", "");
    for(int i=0;i<32;i++) printf("%02x", kB2_enc[i]); printf("\n");
    printf("Match: %s\n", memcmp(kB_enc, kB2_enc, 32)==0?"YES":"NO");
    
    return 0;
}
