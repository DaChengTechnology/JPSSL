// Test: fe_frombytes ↔ fe_tobytes roundtrip for random values
#include "fe_25519.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
using namespace jpssl::fe_impl;

int main() {
    srand(42);
    int ok = 0, fail = 0;
    for (int t = 0; t < 10000; t++) {
        uint8_t orig[32];
        for (int i = 0; i < 32; i++) orig[i] = rand() & 0xFF;
        
        fe x;
        fe_frombytes(x, orig);
        uint8_t out[32];
        fe_tobytes(out, x);
        
        if (memcmp(orig, out, 32) == 0) ok++; else {
            if (fail < 5) {
                printf("FAIL roundtrip:\n  in: "); for(int i=0;i<32;i++) printf("%02x",orig[i]);
                printf("\n out: "); for(int i=0;i<32;i++) printf("%02x",out[i]);
                printf("\n");
            }
            fail++;
        }
    }
    printf("Roundtrip: %d OK, %d FAIL\n", ok, fail);
    return fail > 0 ? 1 : 0;
}
