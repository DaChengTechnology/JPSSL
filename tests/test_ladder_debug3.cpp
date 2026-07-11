// Deep debug: compare round 1 intermediate values
#include "fe_25519.hpp"
#include <cstdio>
#include <cstring>
using namespace jpssl::fe_impl;

void hex(const char* l, const fe v) {
    uint8_t b[32]; fe_tobytes(b, v);
    printf("%s: ", l);
    for (int i=0;i<32;i++) printf("%02x", b[i]);
    printf("\n");
}

void ladder_step_debug(fe x1, fe& x2, fe& z2, fe& x3, fe& z3, fe a24,
                        fe& a, fe& b, fe& c, fe& d, fe& da, fe& cb, fe& t) {
    fe_add(a, x2, z2);                hex("A", a);
    fe_sub(b, x2, z2);                 hex("B", b);
    fe_add(c, x3, z3);                 hex("C", c);
    fe_sub(d, x3, z3);                 hex("D", d);
    fe_mul(da, d, a);                  hex("DA", da);
    fe_mul(cb, c, b);                  hex("CB", cb);
    fe_add(x3, da, cb);                hex("DA+CB", x3);
    fe_sq(x3, x3);                     hex("x3=(DA+CB)^2", x3);
    fe_sub(t, da, cb);                 hex("DA-CB", t);
    fe_sq(z3, t);                      hex("(DA-CB)^2", z3);
    fe_mul(z3, x1, z3);                hex("z3=x1*(.)^2", z3);
    fe_sq(x2, a);                      hex("AA", x2);
    fe_sq(z2, b);                      hex("BB", z2);
    fe_sub(t, x2, z2);                 hex("E=AA-BB", t);
    fe_copy(a, x2);                    // save AA
    fe_mul(x2, x2, z2);                hex("x2=AA*BB", x2);
    fe_mul(z2, t, a24);                hex("z2=E*a24", z2);
    fe_add(z2, z2, a);                 hex("z2=E*a24+AA", z2);
    fe_mul(z2, z2, t);                 hex("z2=z2*E", z2);
}

int main() {
    // After round 0 (with swap):
    // x2=6400, z2=157681440, x3=324, z3=36
    uint8_t x2b[32] = {}; x2b[0]=0x00;x2b[1]=0x19; // 6400 = 0x1900 LE
    uint8_t z2b[32] = {}; z2b[0]=0x20;z2b[1]=0x07;z2b[2]=0x66;z2b[3]=0x09; // 157681440
    uint8_t x3b[32] = {}; x3b[0]=0x44;x3b[1]=0x01; // 324
    uint8_t z3b[32] = {}; z3b[0]=0x24; // 36
    
    fe x1, x2, z2, x3, z3;
    uint8_t nine[32]={9}; fe_frombytes(x1, nine);
    fe_frombytes(x2, x2b);
    fe_frombytes(z2, z2b);
    fe_frombytes(x3, x3b);
    fe_frombytes(z3, z3b);
    
    fe a24; memset(a24,0,sizeof(a24)); a24[0]=121665;
    fe a,b,c,d,da,cb,t;
    
    printf("=== Round 1 debug (kt=1, no swap) ===\n");
    ladder_step_debug(x1, x2, z2, x3, z3, a24, a, b, c, d, da, cb, t);
    
    printf("\n=== Expected from Python ===\n");
    printf("A = 157687840 = 0x%x\n", 157687840);
    printf("B = -157675040 mod p\n");
    printf("C = 360 = 0x%x\n", 360);
    printf("D = 288 = 0x%x\n", 288);
    printf("DA = 288*157687840 = 0x%llx\n", 288LL * 157687840LL);
    printf("CB = 360*(-157675040) mod p : needs GF(p)\n");
    // ... etc
    
    // Expected from Python:
    // x2=618190473570807639392492584960000
    // z2=2082843567142055078422118400000
    // x3=128797905270015590400
    // z3=93961460538485062041600
    
    return 0;
}
