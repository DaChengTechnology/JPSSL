// Test fe_add + fe_tobytes for value 157687840
#include "fe_25519.hpp"
#include <cstdio>
using namespace jpssl::fe_impl;

int main() {
    fe x2, z2, a;
    uint8_t out[32];
    
    // x2 = 6400
    uint8_t x2b[32] = {0x00,0x19};
    // z2 = 157681440 = 0x09660720
    uint8_t z2b[32] = {0x20,0x07,0x66,0x09};
    
    fe_frombytes(x2, x2b);
    fe_frombytes(z2, z2b);
    
    // Print internal limbs
    printf("x2 limbs: [");
    for(int i=0;i<10;i++) printf("%d%s", x2[i], i<9?",":"");
    printf("]\n");
    printf("z2 limbs: [");
    for(int i=0;i<10;i++) printf("%d%s", z2[i], i<9?",":"");
    printf("]\n");
    
    fe_add(a, x2, z2);
    
    printf("a limbs: [");
    for(int i=0;i<10;i++) printf("%d%s", a[i], i<9?",":"");
    printf("]\n");
    
    fe_tobytes(out, a);
    
    printf("output bytes: ");
    for(int i=0;i<32;i++) printf("%02x", out[i]);
    printf("\n");
    printf("expected:     2020660900000000000000000000000000000000000000000000000000000000\n");
    
    return 0;
}
