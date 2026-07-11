// C++: output 5 rounds of ladder with RFC test vector
#include "fe_25519.hpp"
#include <cstdio>
#include <cstring>
using namespace jpssl::fe_impl;

void print_fe(const char* l, const fe v) {
    uint8_t b[32]; fe_tobytes(b, v);
    printf("%s=", l);
    for (int i=0;i<32;i++) printf("%02x", b[i]);
    printf("\n");
}

void ladder_step(fe x1, fe& x2, fe& z2, fe& x3, fe& z3, fe a24,
                 fe& a, fe& b, fe& c, fe& d, fe& da, fe& cb, fe& t) {
    fe_add(a, x2, z2);
    fe_sub(b, x2, z2);
    fe_add(c, x3, z3);
    fe_sub(d, x3, z3);
    fe_mul(da, d, a);
    fe_mul(cb, c, b);
    fe_add(x3, da, cb);
    fe_sq(x3, x3);
    fe_sub(t, da, cb);
    fe_sq(z3, t);
    fe_mul(z3, x1, z3);
    fe_sq(x2, a);
    fe_sq(z2, b);
    fe_sub(t, x2, z2);
    fe_copy(a, x2);
    fe_mul(x2, x2, z2);
    fe_mul(z2, t, a24);
    fe_add(z2, z2, a);
    fe_mul(z2, z2, t);
}

int main() {
    uint8_t scalar[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
        0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
        0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    };
    uint8_t e[32]; memcpy(e, scalar, 32);
    e[0] &= 248; e[31] &= 127; e[31] |= 64;
    
    uint8_t base[32] = {9};
    fe x1; fe_frombytes(x1, base);
    fe x2, z2, x3, z3;
    memset(x2,0,sizeof(x2)); x2[0]=1;
    memset(z2,0,sizeof(z2));
    fe_frombytes(x3, base);
    memset(z3,0,sizeof(z3)); z3[0]=1;
    
    fe a24; memset(a24,0,sizeof(a24)); a24[0]=121665;
    fe a,b,c,d,da,cb,t;
    
    int swap = 0;
    for (int i = 254; i >= 250; --i) { // first 5 rounds
        int kt = (e[i >> 3] >> (i & 7)) & 1;
        swap ^= kt;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = kt;
        
        ladder_step(x1, x2, z2, x3, z3, a24, a, b, c, d, da, cb, t);
        
        printf("Round %d (kt=%d):\n", 254-i, kt);
        printf("  "); print_fe("x2", x2);
        printf("  "); print_fe("z2", z2);
        printf("  "); print_fe("x3", x3);
        printf("  "); print_fe("z3", z3);
    }
    printf("final swap=%d\n", swap);
    return 0;
}
