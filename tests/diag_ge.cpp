// Focused test: scalar mult vs direct operations
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
    const ge_p3* B = ge_get_basepoint();
    
    // Test 1: ge_scalarmult_base with scalar=1 should give B (though Ed25519 scalars are clamped)
    // Actually for unclamped scalar=1, bit 0 is set
    // first set bit = 0, then the loop doesn't execute (first-1 = -1), so r = B
    // Result should be B
    printf("=== Test: 1*B via scalar mult ===\n");
    uint8_t s1[32] = {1,0};
    ge_p3 r1;
    ge_scalarmult_base(&r1, s1);
    uint8_t r1_enc[32]; ge_tobytes(r1_enc, &r1);
    uint8_t B_enc[32]; ge_tobytes(B_enc, B);
    hex("1*B", r1_enc, 32);
    hex("B  ", B_enc, 32);
    printf("Match: %s\n\n", memcmp(r1_enc, B_enc, 32)==0?"YES":"NO");
    
    // Test 2: 2*B via scalar mult vs direct doubling
    printf("=== Test: 2*B via scalar mult ===\n");
    uint8_t s2[32] = {2,0};
    ge_p3 r2;
    ge_scalarmult_base(&r2, s2);
    uint8_t r2_enc[32]; ge_tobytes(r2_enc, &r2);
    hex("2B (scalar mult)", r2_enc, 32);
    
    // Direct doubling
    ge_p1p1 t;
    ge_p3_dbl(&t, B);
    ge_p3 dbl_B;
    ge_p1p1_to_p3(&dbl_B, &t);
    uint8_t dbl_enc[32]; ge_tobytes(dbl_enc, &dbl_B);
    hex("2B (direct dbl) ", dbl_enc, 32);
    printf("Match: %s\n\n", memcmp(r2_enc, dbl_enc, 32)==0?"YES":"NO");
    
    // Test 3: 3*B via scalar mult
    // 3 = 0b11: bit 1 first set, r=B, then double at i=0: r=2B, test bit 0=1: add B => r=3B
    printf("=== Test: 3*B via scalar mult ===\n");
    uint8_t s3[32] = {3,0};
    ge_p3 r3;
    ge_scalarmult_base(&r3, s3);
    uint8_t r3_enc[32]; ge_tobytes(r3_enc, &r3);
    hex("3B (scalar mult)", r3_enc, 32);
    
    // Compute 3B = 2B + B via direct ops
    ge_p1p1 t_add;
    ge_add(&t_add, &dbl_B, B);
    ge_p3 B3;
    ge_p1p1_to_p3(&B3, &t_add);
    uint8_t B3_enc[32]; ge_tobytes(B3_enc, &B3);
    hex("3B (2B+B direct)", B3_enc, 32);
    printf("Match: %s\n\n", memcmp(r3_enc, B3_enc, 32)==0?"YES":"NO");
    
    // Test 4: Verify 1*B == B (also test with ge_p3_0 and single add)
    printf("=== Test: B + 0 = B via ge_add ===\n");
    ge_p3 zero;
    ge_p3_0(&zero);
    ge_p1p1 t0;
    ge_add(&t0, B, &zero);
    ge_p3 B0;
    ge_p1p1_to_p3(&B0, &t0);
    uint8_t B0_enc[32]; ge_tobytes(B0_enc, &B0);
    hex("B + 0", B0_enc, 32);
    hex("B    ", B_enc, 32);
    printf("Match: %s\n\n", memcmp(B0_enc, B_enc, 32)==0?"YES":"NO");
    
    return 0;
}
