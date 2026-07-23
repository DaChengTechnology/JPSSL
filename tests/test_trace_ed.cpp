// Direct test: ge_scalarmult with scalar=1 and known values
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
    // RFC 8032 Test 1 public key
    uint8_t pub[32] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    
    // Decode A
    ge_p3 A;
    int ret = ge_frombytes(&A, pub);
    printf("Decode A: ret=%d\n\n", ret);
    
    // Test 1: 1*A should equal A (ge_scalarmult)
    printf("=== Test: 1*A via ge_scalarmult ===\n");
    uint8_t s1[32] = {1,0};
    ge_p3 r1;
    ge_scalarmult(&r1, s1, &A);
    uint8_t r1_enc[32]; ge_tobytes(r1_enc, &r1);
    hex("1*A", r1_enc, 32);
    hex("A  ", pub, 32);
    printf("Match: %s\n\n", memcmp(r1_enc, pub, 32)==0?"YES":"NO");
    
    // Test 2: ge_double_scalarmult_vartime with k and S from RFC test
    printf("=== Test: S*B - k*A using ge_double_scalarmult_vartime ===\n");
    
    // k from RFC test (verified correct)
    uint8_t k[32] = {0x04,0x54,0x52,0x2e,0x16,0x7e,0x3e,0x8a,0x13,0x2c,0xec,0x31,0x61,0x25,0xd8,0xf8,0x6c,0xdf,0x00,0xc6,0xe7,0x04,0x05,0x29,0x3d,0x19,0x96,0x4c,0x8e,0xea,0xbc,0x86};
    // S from RFC test
    uint8_t S[32] = {0x0b,0x10,0x7a,0x8e,0x43,0x41,0x51,0x65,0x24,0xbe,0x5b,0x59,0xf0,0xf5,0x5b,0xd2,0x6b,0xb4,0xf9,0x1c,0x70,0x39,0x1e,0xc6,0xac,0x3b,0xa3,0x90,0x15,0x82,0xb8,0x5f};
    // R from signature
    uint8_t R[32] = {0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55};
    
    // Method 1: neg_k = l - k, then S*B + neg_k*A
    uint8_t neg_k[32];
    sc_negate(neg_k, k);
    hex("neg_k", neg_k, 32);
    
    ge_p3 SB, negKA;
    ge_scalarmult_base(&SB, S);
    ge_scalarmult(&negKA, neg_k, &A);
    
    ge_p1p1 t;
    ge_add(&t, &SB, &negKA);
    ge_p3 expected_R;
    ge_p1p1_to_p3(&expected_R, &t);
    uint8_t expected_R_enc[32];
    ge_tobytes(expected_R_enc, &expected_R);
    hex("S*B + neg_k*A", expected_R_enc, 32);
    hex("R (sig)", R, 32);
    printf("Match: %s\n\n", memcmp(expected_R_enc, R, 32)==0?"YES":"NO");
    
    // Method 2: use ge_sub
    ge_p3 kA;
    ge_scalarmult(&kA, k, &A);
    uint8_t kA_enc[32]; ge_tobytes(kA_enc, &kA);
    hex("k*A", kA_enc, 32);
    
    ge_p1p1 t_sub;
    ge_sub(&t_sub, &SB, &kA);
    ge_p3 expected_R2;
    ge_p1p1_to_p3(&expected_R2, &t_sub);
    uint8_t expected_R2_enc[32];
    ge_tobytes(expected_R2_enc, &expected_R2);
    hex("S*B - k*A (sub)", expected_R2_enc, 32);
    printf("Match (sub): %s\n\n", memcmp(expected_R2_enc, R, 32)==0?"YES":"NO");
    
    // Method 3: use ge_double_scalarmult_vartime with (neg_k, A, S, B)
    const ge_p3* B = ge_get_basepoint();
    ge_p3 result_vt;
    ge_double_scalarmult_vartime(&result_vt, neg_k, &A, S, B);
    uint8_t result_vt_enc[32];
    ge_tobytes(result_vt_enc, &result_vt);
    hex("vartime(neg_k,S)", result_vt_enc, 32);
    printf("Match (vartime): %s\n\n", memcmp(result_vt_enc, R, 32)==0?"YES":"NO");
    
    // Method 4: S*B - k*A via ge_double_scalarmult_vartime with (S, B, neg_k, A)
    // This computes S*B + neg_k*A = R
    ge_p3 result_vt2;
    ge_double_scalarmult_vartime(&result_vt2, S, B, neg_k, &A);
    uint8_t result_vt2_enc[32];
    ge_tobytes(result_vt2_enc, &result_vt2);
    hex("vartime(S,neg_k)", result_vt2_enc, 32);
    printf("Match (vartime2): %s\n\n", memcmp(result_vt2_enc, R, 32)==0?"YES":"NO");
    
    return 0;
}
