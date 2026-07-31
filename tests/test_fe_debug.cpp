// Full ed25519 sign/verify test with RFC 8032 vectors
#include "sha512.hpp"
#include "ed25519.cpp"
#include <cstdio>
#include <cstring>
using namespace jpssl;
using namespace jpssl::ed25519_ref10_impl;

static void hex(const char* label, const uint8_t* d, int n) {
    printf("%s: ", label);
    for (int i=0;i<n;i++) printf("%02x",d[i]);
    printf("\n");
}

int main() {
    uint8_t pub[32] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    uint8_t expected_sig[64] = {
        0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
        0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
        0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
        0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
    };
    
    // Test 1: Sign with RFC seed, compare with expected
    printf("=== Sign with RFC Test 1 seed ===\n");
    uint8_t seed[32] = {
        0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
        0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
        0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
    };
    
    // SHA-512(seed) + clamp
    uint8_t h[64], priv[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, h);
    memcpy(priv, seed, 32);
    // pub key already computed correctly: ge_scalarmult_base gives expected pub
    h[0] &= 248; h[31] &= 127; h[31] |= 64;
    
    // Sign with priv = seed || pub
    // ed25519_sign expects priv[0..31]=seed, priv[32..63]=pub
    // We need to generate pub first
    ge_p3 A_ge;
    ge_scalarmult_base(&A_ge, h);
    uint8_t our_pub[32];
    ge_tobytes(our_pub, &A_ge);
    memcpy(priv + 32, our_pub, 32);
    
    hex("pub key", priv + 32, 32);
    hex("expected", pub, 32);
    
    uint8_t sig[64];
    jpssl::ed25519_sign(priv, nullptr, 0, sig);
    
    hex("R (sig)", sig, 32);
    hex("S (sig)", sig + 32, 32);
    hex("R (exp)", expected_sig, 32);
    hex("S (exp)", expected_sig + 32, 32);
    
    bool sig_match = memcmp(sig, expected_sig, 64) == 0;
    printf("Signature match: %s\n", sig_match ? "YES" : "NO");
    
    // Test 2: Verify RFC signature
    printf("\n=== Verify RFC signature ===\n");
    bool v_ok = jpssl::ed25519_verify(pub, nullptr, 0, expected_sig);
    printf("Verify: %s\n", v_ok ? "PASS" : "FAIL");
    
    // Test 3: Verify our own signature
    bool v_ok2 = jpssl::ed25519_verify(pub, nullptr, 0, sig);
    printf("Verify (own sig): %s\n", v_ok2 ? "PASS" : "FAIL");
    
    return 0;
}
