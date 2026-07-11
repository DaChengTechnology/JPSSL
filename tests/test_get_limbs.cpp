// Print limb ranges after fe_frombytes for random inputs
#include "fe_25519.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
using namespace jpssl::fe_impl;

int main() {
    srand(42);
    int32_t min_limb[10], max_limb[10];
    for (int i = 0; i < 10; i++) { min_limb[i]=1<<30; max_limb[i]=-(1<<30); }
    
    for (int t = 0; t < 10000; t++) {
        uint8_t buf[32];
        for (int i=0;i<32;i++) buf[i]=rand()&0xFF;
        fe x;
        fe_frombytes(x, buf);
        for (int i=0;i<10;i++) {
            if (x[i] < min_limb[i]) min_limb[i] = x[i];
            if (x[i] > max_limb[i]) max_limb[i] = x[i];
        }
    }
    printf("Limb ranges after fe_frombytes:\n");
    for (int i=0;i<10;i++) printf("  h[%d]: [%d, %d]\n", i, min_limb[i], max_limb[i]);
    
    // Also check fe_tobytes produces the right range
    printf("\nNow test fe_tobytes reduction:\n");
    for (int t = 0; t < 10; t++) {
        uint8_t buf[32];
        for (int i=0;i<32;i++) buf[i]=rand()&0xFF;
        fe x;
        fe_frombytes(x, buf);
        // simulate what fe_tobytes does internally
        int32_t h[10];
        for (int i=0;i<10;i++) h[i]=x[i];
        // apply fe_tobytes carry chain (2 passes)
        for (int pass=0;pass<2;pass++) {
            int32_t c;
            c = (h[9] + (1<<24))>>25; h[0]+=c*19; h[9]-=c<<25;
            c = (h[1] + (1<<24))>>25; h[2]+=c; h[1]-=c<<25;
            c = (h[3] + (1<<24))>>25; h[4]+=c; h[3]-=c<<25;
            c = (h[5] + (1<<24))>>25; h[6]+=c; h[5]-=c<<25;
            c = (h[7] + (1<<24))>>25; h[8]+=c; h[7]-=c<<25;
            c = (h[0] + (1<<25))>>26; h[1]+=c; h[0]-=c<<26;
            c = (h[2] + (1<<25))>>26; h[3]+=c; h[2]-=c<<26;
            c = (h[4] + (1<<25))>>26; h[5]+=c; h[4]-=c<<26;
            c = (h[6] + (1<<25))>>26; h[7]+=c; h[6]-=c<<26;
            c = (h[8] + (1<<25))>>26; h[9]+=c; h[8]-=c<<26;
        }
        // check if any limb is negative
        bool neg = false;
        for (int i=0;i<10;i++) if (h[i] < 0) neg = true;
        if (neg && t<3) {
            printf("Example %d: negative limbs after reduction: ", t);
            for (int i=0;i<10;i++) printf("%d ", h[i]);
            printf("\n");
        }
    }
    
    return 0;
}
