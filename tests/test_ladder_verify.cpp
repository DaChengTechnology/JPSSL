// Verify ladder fix by doing just 2 rounds
#include "fe_25519.hpp"
#include <cstdio>
#include <cstring>
using namespace jpssl::fe_impl;

void hx2(const char* l, const fe v, int64_t expected) {
    uint8_t b[32]; fe_tobytes(b, v);
    uint64_t lo = 0;
    for (int i=0;i<8;i++) lo |= (uint64_t)b[i] << (i*8);
    printf("%s: val=%lu expected=%ld %s\n", l, lo, expected, lo==(uint64_t)expected?"PASS":"FAIL");
}

// Exact ladder step copy from current x25519.cpp
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
    fe_copy(a, x2);       // save AA
    fe_mul(x2, x2, z2);   // x2 = AA * BB
    fe_mul(z2, t, a24);
    fe_add(z2, z2, a);    // z2 = E*a24 + AA
    fe_mul(z2, z2, t);    // z2 = (E*a24 + AA) * E
}

int main() {
    uint8_t nine[32] = {9};
    fe x1, x2, z2, x3, z3;
    fe_frombytes(x1, nine);
    memset(x2,0,sizeof(x2)); x2[0]=1;
    memset(z2,0,sizeof(z2));
    fe_frombytes(x3, nine);
    memset(z3,0,sizeof(z3)); z3[0]=1;
    
    fe a24; memset(a24,0,sizeof(a24)); a24[0]=121665;
    fe a,b,c,d,da,cb,t;
    
    // Round 1
    ladder_step(x1, x2, z2, x3, z3, a24, a, b, c, d, da, cb, t);
    printf("Round 1:\n");
    hx2("  x2", x2, 1);
    hx2("  z2", z2, 0);
    hx2("  x3", x3, 324);
    hx2("  z3", z3, 36);
    
    // cswap
    fe_cswap(x2, x3, 1);
    fe_cswap(z2, z3, 1);
    
    // Round 2
    ladder_step(x1, x2, z2, x3, z3, a24, a, b, c, d, da, cb, t);
    printf("Round 2:\n");
    hx2("  x2", x2, 10749542400LL);
    hx2("  z2", z2, 264844269527040LL);
    hx2("  x3", x3, 419904);
    hx2("  z3", z3, 46656);
    
    printf("\nAll done.\n");
    return 0;
}
