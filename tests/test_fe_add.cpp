// Check limb ranges after ge_frombytes(A)
#include "fe_25519.hpp"
#include "ed25519.cpp"
#include <cstdio>
#include <cstring>
#include <algorithm>
using namespace jpssl;
using namespace fe_impl;

int main() {
    uint8_t pub[32] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    ge_p3 A;
    ge_frombytes(&A, pub);
    
    printf("A.X limbs: ");
    for(int i=0;i<10;i++) printf("%d ", A.X[i]);
    printf("\nmin=%d max=%d\n", *std::min_element(A.X,A.X+10), *std::max_element(A.X,A.X+10));
    
    printf("A.Y limbs: ");
    for(int i=0;i<10;i++) printf("%d ", A.Y[i]);
    printf("\nmin=%d max=%d\n", *std::min_element(A.Y,A.Y+10), *std::max_element(A.Y,A.Y+10));
    
    printf("A.Z limbs: ");
    for(int i=0;i<10;i++) printf("%d ", A.Z[i]);
    printf("\n");
    
    printf("A.T limbs: ");
    for(int i=0;i<10;i++) printf("%d ", A.T[i]);
    printf("\nmin=%d max=%d\n", *std::min_element(A.T,A.T+10), *std::max_element(A.T,A.T+10));
    
    // Compare with B
    const ge_p3* B = ge_get_basepoint();
    printf("\nB.X limbs: ");
    for(int i=0;i<10;i++) printf("%d ", B->X[i]);
    printf("\nmin=%d max=%d\n", *std::min_element(B->X,B->X+10), *std::max_element(B->X,B->X+10));
    
    printf("B.Y limbs: ");
    for(int i=0;i<10;i++) printf("%d ", B->Y[i]);
    printf("\nmin=%d max=%d\n", *std::min_element(B->Y,B->Y+10), *std::max_element(B->Y,B->Y+10));
    
    // Test: fe_mul(A.T, A.X, A.Y) -- does this match what ge_frombytes computed?
    fe t2;
    fe_mul(t2, A.X, A.Y);
    printf("\nA.T == A.X*A.Y: %s\n", memcmp(A.T, t2, sizeof(fe))==0?"YES":"NO");
    
    // Check if A.T satisfies T = X*Y/Z invariant
    fe xy, zt;
    fe_mul(xy, A.X, A.Y);  // X*Y
    fe_mul(zt, A.Z, A.T);  // Z*T
    uint8_t xy_bytes[32], zt_bytes[32];
    fe_tobytes(xy_bytes, xy);
    fe_tobytes(zt_bytes, zt);
    printf("X*Y == Z*T: %s\n", memcmp(xy_bytes, zt_bytes, 32)==0?"YES":"NO");
    
    return 0;
}
