// Direct verify step-by-step test
#include "sha512.hpp"
#include "ed25519.cpp"
#include <cstdio>
#include <cstring>
using namespace jpssl;
using namespace fe_impl;

static void hex(const char* label, const uint8_t* d, int n) {
    printf("%s: ", label);
    for (int i=0;i<n;i++) printf("%02x",d[i]);
    printf("\n");
}

int main() {
    uint8_t pub[32] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    uint8_t sig[64] = {
        0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
        0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
        0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
        0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
    };
    
    // Step 1: Decode A and R
    ge_p3 A, R;
    if (ge_frombytes(&A, pub) != 0) { printf("Failed to decode A\n"); return 1; }
    if (ge_frombytes(&R, sig) != 0) { printf("Failed to decode R\n"); return 1; }
    printf("Decode: OK\n");
    
    // Step 2: Check S < l
    uint64_t L64[4] = {0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000};
    uint64_t s_l[4];
    sc_load_64(s_l, sig + 32);
    int cmp = 0;
    for (int j = 3; j >= 0; j--) {
        if (s_l[j] > L64[j]) { cmp = 1; break; }
        if (s_l[j] < L64[j]) { cmp = -1; break; }
    }
    printf("S < l: %s (cmp=%d)\n", cmp < 0 ? "OK" : "FAIL", cmp);
    
    // Step 3: Compute k = SHA-512(R || pub || msg)
    uint8_t hram[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, sig, 32);
    sha512_update(&ctx, pub, 32);
    sha512_final(&ctx, hram);
    
    hex("SHA-512(R||A) full", hram, 64);
    
    sc_reduce(hram);
    hex("k (sc_reduce)", hram, 32);
    
    // Compare with Python
    uint8_t k_expected[32] = {0x04,0x54,0x52,0x2e,0x16,0x7e,0x3e,0x8a,0x13,0x2c,0xec,0x31,0x61,0x25,0xd8,0xf8,0x6c,0xdf,0x00,0xc6,0xe7,0x04,0x05,0x29,0x3d,0x19,0x96,0x4c,0x8e,0xea,0xbc,0x86};
    printf("k match expected: %s\n", memcmp(hram, k_expected, 32)==0?"YES":"NO");
    
    // Step 4: neg_k = l - k
    uint8_t neg_k[32];
    sc_negate(neg_k, hram);
    hex("neg_k", neg_k, 32);
    
    // Step 5: S*B
    ge_p3 SB;
    ge_scalarmult_base(&SB, sig + 32);
    uint8_t SB_enc[32]; ge_tobytes(SB_enc, &SB);
    hex("S*B", SB_enc, 32);
    
    // Step 6: neg_k*A
    ge_p3 negKA;
    ge_scalarmult(&negKA, neg_k, &A);
    uint8_t negKA_enc[32]; ge_tobytes(negKA_enc, &negKA);
    hex("neg_k*A", negKA_enc, 32);
    
    // Step 7: SB + negKA (should equal R)
    ge_p1p1 t;
    ge_add(&t, &SB, &negKA);
    ge_p3 expected_R;
    ge_p1p1_to_p3(&expected_R, &t);
    uint8_t expected_R_enc[32]; ge_tobytes(expected_R_enc, &expected_R);
    hex("SB+negKA", expected_R_enc, 32);
    hex("R (sig)", sig, 32);
    printf("Match: %s\n", memcmp(expected_R_enc, sig, 32)==0?"YES":"NO");
    
    // Alternative: S*B - k*A using ge_sub
    printf("\n=== Alternative: SB - kA ===\n");
    ge_p3 kA;
    uint8_t k_copy[32];
    memcpy(k_copy, hram, 32);
    ge_scalarmult(&kA, k_copy, &A);
    uint8_t kA_enc[32]; ge_tobytes(kA_enc, &kA);
    hex("k*A", kA_enc, 32);
    
    ge_p1p1 t_sub;
    ge_sub(&t_sub, &SB, &kA);
    ge_p3 expected_R2;
    ge_p1p1_to_p3(&expected_R2, &t_sub);
    uint8_t expected_R2_enc[32]; ge_tobytes(expected_R2_enc, &expected_R2);
    hex("SB-kA", expected_R2_enc, 32);
    hex("R (sig)", sig, 32);
    printf("Match: %s\n", memcmp(expected_R2_enc, sig, 32)==0?"YES":"NO");
    
    return 0;
}
