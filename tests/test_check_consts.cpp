// Test: add r to k*s with carry propagation
#include <cstdio>
#include <cstdint>

int main() {
    uint64_t ks[8] = {
        0xf18873fc9713913c, 0x7906a68a31b700c8, 0x56752efc4ae0ab80, 0xf76442ea49ca3312,
        0xa9d1d68810a182f0, 0x93ace177a5dc099a, 0xd96761e9746cfeec, 0x198da25eea5c6145
    };
    uint64_t r[4] = {0xc58f75ac58a07404, 0x2249107418afc2ed, 0xf244787db4af5368, 0xf38907308c893dea};
    
    // Step 1: manual addition
    unsigned __int128 carry = 0;
    for (int i = 0; i < 8; i++) {
        carry += ks[i] + (i < 4 ? r[i] : 0);
        ks[i] = (uint64_t)carry;
        carry >>= 64;
    }
    
    printf("After manual add:\n");
    for (int i = 0; i < 8; i++) printf("  p[%d]=%016lx\n", i, ks[i]);
    
    // Python says:
    // p[1] should be 9b4fb6fe4a66c3b6 (from Python)
    // p[3] should be eaed4a1ad65370fd
    // p[4] should be a9d1d68810a182f1
    uint64_t py_p1 = 0x9b4fb6fe4a66c3b6;
    uint64_t py_p3 = 0xeaed4a1ad65370fd;
    uint64_t py_p4 = 0xa9d1d68810a182f1;
    
    printf("p[1] match: %s (got %016lx, expected %016lx)\n", ks[1]==py_p1?"YES":"NO", ks[1], py_p1);
    printf("p[3] match: %s (got %016lx, expected %016lx)\n", ks[3]==py_p3?"YES":"NO", ks[3], py_p3);
    printf("p[4] match: %s (got %016lx, expected %016lx)\n", ks[4]==py_p4?"YES":"NO", ks[4], py_p4);
    
    return 0;
}
