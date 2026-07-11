// Debug: compare 2 rounds of ladder with Python reference values
#include "fe_25519.hpp"
#include <cstdio>
#include <cstring>
using namespace jpssl::fe_impl;

void hx2(const char* l, const fe v, int64_t expected) {
    uint8_t b[32];
    fe_tobytes(b, v);
    // Read as little-endian integer (less than 2^256)
    uint64_t lo = 0;
    for (int i=0;i<8;i++) lo |= (uint64_t)b[i] << (i*8);
    printf("%s: hex=", l);
    for (int i=0;i<8;i++) printf("%02x", b[i]);
    printf("... val=%lu expected=%ld %s\n", lo, expected, lo==(uint64_t)expected?"PASS":"FAIL");
}

int main() {
    uint8_t nine_bytes[32] = {9};
    fe x1, x2, z2, x3, z3;
    fe_frombytes(x1, nine_bytes);
    memset(x2, 0, sizeof(x2)); x2[0] = 1;
    memset(z2, 0, sizeof(z2));
    fe_frombytes(x3, nine_bytes);
    memset(z3, 0, sizeof(z3)); z3[0] = 1;
    fe a24; memset(a24, 0, sizeof(a24)); a24[0] = 121665;
    fe a,b,c,d,da,cb,t;

    // Round 1
    fe_add(a, x2, z2); fe_sub(b, x2, z2);
    fe_add(c, x3, z3); fe_sub(d, x3, z3);
    fe_mul(da, d, a); fe_mul(cb, c, b);
    fe_add(x3, da, cb); fe_sq(x3, x3);
    fe_sub(t, da, cb); fe_sq(z3, t); fe_mul(z3, x1, z3);
    fe_sq(x2, a); fe_sq(z2, b);
    fe_sub(t, x2, z2);
    fe_mul(x2, x2, z2);
    fe_mul(z2, t, a24);
    fe_add(z2, z2, x2);
    fe_mul(z2, z2, t);

    printf("=== Round 1 ===\n");
    hx2("x2", x2, 1);
    hx2("z2", z2, 0);
    hx2("x3", x3, 324);
    hx2("z3", z3, 36);

    // cswap to simulate bit=1
    fe_cswap(x2, x3, 1);
    fe_cswap(z2, z3, 1);

    // Round 2
    fe_add(a, x2, z2); fe_sub(b, x2, z2);
    fe_add(c, x3, z3); fe_sub(d, x3, z3);
    fe_mul(da, d, a); fe_mul(cb, c, b);
    fe_add(x3, da, cb); fe_sq(x3, x3);
    fe_sub(t, da, cb); fe_sq(z3, t); fe_mul(z3, x1, z3);
    fe_sq(x2, a); fe_sq(z2, b);
    fe_sub(t, x2, z2);
    fe_mul(x2, x2, z2);
    fe_mul(z2, t, a24);
    fe_add(z2, z2, x2);
    fe_mul(z2, z2, t);

    printf("\n=== Round 2 (after swap) ===\n");
    // Expected from Python:
    // x2=10749542400, z2=264844269527040, x3=419904, z3=46656
    hx2("x2", x2, 10749542400LL);
    hx2("z2", z2, 264844269527040LL);
    hx2("x3", x3, 419904);
    hx2("z3", z3, 46656);

    // Check the intermediate A and B too
    fe aa, bb;
    fe_add(aa, x2, z2); fe_sub(bb, x2, z2);
    // But these are after the round... need to recompute with original values
    // Actually recalc with the values we fed into round 2
    // After cswap: x2 was 324, z2 was 36; x3 was 1, z3 was 0
    // So A = 324+36 = 360, B = 324-36 = 288
    
    // Re-initialize for round 2
    fe xx2, zz2, xx3, zz3;
    memset(xx2,0,sizeof(xx2)); xx2[0]=324;
    memset(zz2,0,sizeof(zz2)); zz2[0]=36;
    memset(xx3,0,sizeof(xx3)); xx3[0]=1;
    memset(zz3,0,sizeof(zz3));
    
    fe_add(a, xx2, zz2); fe_sub(b, xx2, zz2);
    fe_add(c, xx3, zz3); fe_sub(d, xx3, zz3);
    fe_mul(da, d, a); fe_mul(cb, c, b);
    fe_add(x3, da, cb); fe_sq(x3, x3);
    fe_sub(t, da, cb); fe_sq(z3, t); fe_mul(z3, x1, z3);
    fe_sq(xx2, a); fe_sq(zz2, b);
    fe_sub(t, xx2, zz2);
    fe_mul(xx2, xx2, zz2);
    fe_mul(zz2, t, a24);
    fe_add(zz2, zz2, xx2);
    fe_mul(zz2, zz2, t);
    
    printf("\n=== Round 2 (recalculated with small values) ===\n");
    hx2("x2", xx2, 10749542400LL);
    hx2("z2", zz2, 264844269527040LL);
    hx2("x3", x3, 419904);
    hx2("z3", z3, 46656);

    printf("\nDone.\n");
    return 0;
}
