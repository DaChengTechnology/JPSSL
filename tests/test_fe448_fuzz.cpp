// Test fe448_mul with random values against Python reference
#include "fe_448.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>

using namespace jpssl::fe448_impl;

// Compute correct result using Python big ints (embedded)
// We'll use a simpler approach: verify that (a*b)*a_inv == b when a != 0
int main() {
    srand(12345);
    int failures = 0;
    
    // Test 1: for random a, verify (a*a)*(a^-1) == a
    for (int t = 0; t < 50; t++) {
        uint8_t abytes[56];
        for (int i = 0; i < 56; i++) abytes[i] = rand() & 0xff;
        abytes[55] &= 0x7f; // ensure < p
        
        fe448 a, a_sq, a_inv, prod;
        fe448_frombytes(a, abytes);
        
        // Skip zero
        bool is_zero = true;
        for (int i = 0; i < 8; i++) if (a[i] != 0) is_zero = false;
        if (is_zero) continue;
        
        fe448_sq(a_sq, a);        // a_sq = a^2
        fe448_invert(a_inv, a);   // a_inv = a^-1
        fe448_mul(prod, a_sq, a_inv); // prod = a^2 * a^-1 = a
        
        uint8_t orig[56], result[56];
        fe448_tobytes(orig, a);
        fe448_tobytes(result, prod);
        
        if (memcmp(orig, result, 56) != 0) {
            failures++;
            printf("FAIL %d: a^2 * a^-1 != a\n", t);
            // Show limp values
            printf("  a:      "); for(int i=0;i<8;i++) printf("%016lx ", a[i]); printf("\n");
            printf("  a_sq:   "); for(int i=0;i<8;i++) printf("%016lx ", a_sq[i]); printf("\n");
            printf("  a_inv:  "); for(int i=0;i<8;i++) printf("%016lx ", a_inv[i]); printf("\n");
            printf("  prod:   "); for(int i=0;i<8;i++) printf("%016lx ", prod[i]); printf("\n");
            if (failures >= 3) break;
        }
    }
    printf("a^2 * a^-1 == a: %d failures / 50\n", failures);
    
    // Test 2: for random a,b, verify a*b == b*a
    failures = 0;
    for (int t = 0; t < 100; t++) {
        uint8_t fa[56], fb[56];
        for (int i = 0; i < 56; i++) { fa[i] = rand() & 0xff; fb[i] = rand() & 0xff; }
        fa[55] &= 0x7f; fb[55] &= 0x7f;
        
        fe448 a, b, ab, ba;
        fe448_frombytes(a, fa);
        fe448_frombytes(b, fb);
        
        fe448_mul(ab, a, b);
        fe448_mul(ba, b, a);
        
        uint8_t ab_bytes[56], ba_bytes[56];
        fe448_tobytes(ab_bytes, ab);
        fe448_tobytes(ba_bytes, ba);
        
        if (memcmp(ab_bytes, ba_bytes, 56) != 0) {
            failures++;
            printf("FAIL %d: a*b != b*a\n", t);
            if (failures >= 3) break;
        }
    }
    printf("a*b == b*a: %d failures / 100\n", failures);
    
    // Test 3: for random a, verify (a^2)*(a^2) == a^4 via repeated sq
    failures = 0;
    for (int t = 0; t < 50; t++) {
        uint8_t fa[56];
        for (int i = 0; i < 56; i++) fa[i] = rand() & 0xff;
        fa[55] &= 0x7f;
        
        fe448 a, a2, a4a, a4b;
        fe448_frombytes(a, fa);
        
        fe448_sq(a2, a);           // a2 = a^2
        fe448_sq(a4a, a2);         // a4a = (a^2)^2 = a^4
        
        // Compute a^4 via: a2*a2
        fe448_mul(a4b, a2, a2);
        
        uint8_t b1[56], b2[56];
        fe448_tobytes(b1, a4a);
        fe448_tobytes(b2, a4b);
        
        if (memcmp(b1, b2, 56) != 0) {
            failures++;
            printf("FAIL %d: (a^2)^2 != a^2 * a^2\n", t);
            if (failures >= 3) break;
        }
    }
    printf("(a^2)^2 == a^2*a^2: %d failures / 50\n", failures);
    
    return 0;
}
