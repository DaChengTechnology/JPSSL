// Test verify: negate kA via coords then add
#include "sha512.hpp"
#include "ed25519.cpp"
#include <cstdio>
#include <cstring>
using namespace jpssl;

static void hexb(const char* l, const uint8_t* d, int n) {
    printf("  %s: ", l); for(int i=0;i<n;i++) printf("%02x",d[i]); printf("\n");
}

int main() {
    uint8_t pub[32] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    uint8_t sig[64] = {0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b};
    
    ge_p3 A, R;
    ge_frombytes(&A, pub);
    ge_frombytes(&R, sig);
    
    // Compute k
    uint8_t hram[64], k[32];
    sha512_ctx ctx;
    sha512_init(&ctx); sha512_update(&ctx, sig, 32); sha512_update(&ctx, pub, 32); sha512_final(&ctx, hram);
    sc_reduce(hram); memcpy(k, hram, 32);
    hexb("k", k, 32);
    
    // Compute kA
    ge_p3 kA;
    ge_scalarmult(&kA, k, &A);
    uint8_t ka[32]; ge_tobytes(ka, &kA); hexb("k*A", ka, 32);
    
    // Negate kA: -(X, Y, Z, T) = (-X, Y, Z, -T)
    ge_p3 neg_kA;
    fe_copy(neg_kA.Y, kA.Y);
    fe_copy(neg_kA.Z, kA.Z);
    fe_neg(neg_kA.X, kA.X);
    fe_neg(neg_kA.T, kA.T);
    uint8_t nka[32]; ge_tobytes(nka, &neg_kA); hexb("negated kA", nka, 32);
    
    // Compute S*B
    ge_p3 SB;
    ge_scalarmult_base(&SB, sig + 32);
    uint8_t sb[32]; ge_tobytes(sb, &SB); hexb("S*B", sb, 32);
    
    // SB + neg_kA using ge_add
    ge_p1p1 t;
    ge_add(&t, &SB, &neg_kA);
    ge_p3 result;
    ge_p1p1_to_p3(&result, &t);
    uint8_t res[32]; ge_tobytes(res, &result); hexb("SB+neg_kA", res, 32);
    hexb("R", sig, 32);
    printf("Match: %s\n", memcmp(res, sig, 32)==0?"YES":"NO");
    
    // Also try: SB - kA using ge_sub (alternative)
    ge_p1p1 t2;
    ge_sub(&t2, &SB, &kA);
    ge_p3 result2;
    ge_p1p1_to_p3(&result2, &t2);
    uint8_t res2[32]; ge_tobytes(res2, &result2); hexb("SB-kA", res2, 32);
    printf("Match (ge_sub): %s\n", memcmp(res2, sig, 32)==0?"YES":"NO");
    
    return 0;
}
