// Detailed debug: print first round of ladder
#include "fe_25519.hpp"
#include <cstdio>
#include <cstring>
using namespace jpssl::fe_impl;

void pr(const char* l, const fe v) {
    printf("%s = [", l);
    for (int i = 0; i < 10; i++) printf("%d%s", v[i], i<9?",":"");
    printf("]\n");
}
void hx(const char* l, const fe v) {
    uint8_t b[32];
    fe_tobytes(b, v);
    printf("%s = ", l);
    for (int i=0;i<32;i++) printf("%02x", b[i]);
    printf("\n");
}

int main() {
    uint8_t nine_bytes[32] = {9};
    
    fe x1, x2, z2, x3, z3;
    fe_frombytes(x1, nine_bytes);   // x1 = 9
    
    // x2 = 1, z2 = 0
    memset(x2, 0, sizeof(x2)); x2[0] = 1;
    memset(z2, 0, sizeof(z2));
    // x3 = 9, z3 = 1
    fe_frombytes(x3, nine_bytes);
    memset(z3, 0, sizeof(z3)); z3[0] = 1;
    
    fe a24; memset(a24, 0, sizeof(a24)); a24[0] = 121665;
    
    fe a, b, c, d, da, cb, t;
    
    fe_add(a, x2, z2);   pr("A", a);
    fe_sub(b, x2, z2);   pr("B", b);
    fe_add(c, x3, z3);   pr("C", c);
    fe_sub(d, x3, z3);   pr("D", d);
    fe_mul(da, d, a);    pr("DA", da);
    fe_mul(cb, c, b);    pr("CB", cb);
    fe_add(x3, da, cb);  pr("DA+CB", x3);
    fe_sq(x3, x3);       pr("x3=(DA+CB)^2", x3); hx("x3 hex", x3);
    fe_sub(t, da, cb);   pr("DA-CB", t);
    fe_sq(z3, t);        pr("(DA-CB)^2", z3);
    fe_mul(z3, x1, z3);  pr("z3=x1*(DA-CB)^2", z3); hx("z3 hex", z3);
    fe_sq(x2, a);        pr("x2=A^2", x2);
    fe_sq(z2, b);        pr("z2=B^2", z2);
    fe_sub(t, x2, z2);   pr("t=x2-z2", t);
    fe_mul(x2, x2, z2);  pr("x2=x2*z2", x2);
    fe_mul(z2, t, a24);  pr("z2=t*a24", z2);
    fe_add(z2, z2, x2);  pr("z2=t*a24+x2", z2);
    fe_mul(z2, z2, t);   pr("z2=z2*t", z2);
    
    hx("Final x2", x2);
    hx("Final z2", z2);
    hx("Final x3", x3);
    hx("Final z3", z3);
    
    printf("\nFirst round done.\n");
    return 0;
}
