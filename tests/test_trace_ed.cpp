#include "fe_448.hpp"
#include <cstdio>
using namespace jpssl::fe448_impl;

static void pr(const char* label, fe448 f) {
    printf("%s: ", label);
    for(int i=0;i<8;i++) printf("%016lx ", f[i]); printf("\n");
}

int main() {
    fe448 x1,x2,z2,x3,z3,a,b,c,d,da,cb,t,a24;
    fe448_0(a24); a24[0]=39081;
    uint8_t u[56]={5};
    fe448_frombytes(x1,u);

    // Set state to iter 445 after computation, with swap=1
    fe448_0(x2); x2[1]=0x0081586da3ac4000; x2[2]=0x0008c8155b419b20; x2[3]=0x00a9863943b317a5; x2[4]=0x0000003149439ff6;
    fe448_0(z2); z2[1]=0x004c4d403472e000; z2[2]=0x0039b53c73e1bbc3; z2[3]=0x009191dc0b353964; z2[4]=0x000007b4d72bd7de;
    fe448_0(x3); x3[1]=0x00e1f60155402f10; x3[2]=0x00bcda127a3f507a; x3[3]=0x00009156bfce08c2;
    fe448_0(z3); z3[1]=0x0047040034e81ed0; z3[2]=0x009d3dfb2a4d7b27; z3[3]=0x0000000bc9d2719e;

    // iter 444: swap starts at 1 (from iter 445), bit=1, XOR gives 0 → NO SWAP
    int sw=1, bit=1;
    sw^=bit; // sw=0
    fe448_cswap(x2,x3,sw); fe448_cswap(z2,z3,sw);  // no swap
    sw=bit; // sw=1

    printf("after cswap (no swap):\n");
    pr("x2", x2); pr("z2", z2);

    fe448_add(a,x2,z2); fe448_sub(b,x2,z2);
    fe448_add(c,x3,z3); fe448_sub(d,x3,z3);
    fe448_mul(da,d,a); fe448_mul(cb,c,b);
    fe448_add(x3,da,cb); fe448_sq(x3,x3);
    fe448_sub(t,da,cb); fe448_sq(z3,t); fe448_mul(z3,x1,z3);
    fe448_sq(x2,a); fe448_sq(z2,b);
    fe448_sub(t,x2,z2); fe448_copy(a24,x2);
    fe448_mul(x2,x2,z2);
    fe448_mul_small(z2,t,39081); fe448_add(z2,z2,a24); fe448_mul(z2,z2,t);
    fe448_0(a24); a24[0]=39081;

    printf("\nfinal:\n");
    pr("x2", x2); pr("z2", z2);
    return 0;
}
