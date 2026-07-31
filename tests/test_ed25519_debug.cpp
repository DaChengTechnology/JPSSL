// Minimal round-trip test
#include "sha512.hpp"
#include "ed25519.cpp"
#include <cstdio>
#include <cstring>
using namespace jpssl;
using namespace jpssl::ed25519_ref10_impl;

int main() {
    // Test with known seed from RFC
    uint8_t seed[32] = {
        0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
        0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
        0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
    };
    
    uint8_t priv[64];
    memcpy(priv, seed, 32);
    
    // Generate pub key using manual scalar mult (same as keygen)
    // We need to call ed25519.cpp internals...
    
    // Actually let's use ed25519_keygen with a FIXED seed
    // ed25519_keygen uses random_device, we can't control it.
    // Instead, manually construct priv key
    // First get the clamped scalar
    // We know RFC pub key
    uint8_t pub[32] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    memcpy(priv + 32, pub, 32);
    
    // Sign with empty message
    uint8_t sig[64];
    ed25519_sign(priv, nullptr, 0, sig);
    
    printf("Sign with seed + empty msg:\n");
    printf("  R: "); for(int i=0;i<32;i++) printf("%02x", sig[i]); printf("\n");
    printf("  S: "); for(int i=32;i<64;i++) printf("%02x", sig[i]); printf("\n");
    
    bool ok = ed25519_verify(pub, nullptr, 0, sig);
    printf("Verify: %s\n", ok ? "PASS" : "FAIL");
    
    // Now test with keygen
    printf("\n=== Keygen + Sign + Verify ===\n");
    uint8_t pk[32], sk[64];
    ed25519_keygen(pk, sk);
    
    const char* msg = "test";
    ed25519_sign(sk, (const uint8_t*)msg, strlen(msg), sig);
    
    printf("  pub: "); for(int i=0;i<32;i++) printf("%02x", pk[i]); printf("\n");
    printf("  R:   "); for(int i=0;i<32;i++) printf("%02x", sig[i]); printf("\n");
    printf("  S:   "); for(int i=32;i<64;i++) printf("%02x", sig[i]); printf("\n");
    
    bool ok2 = ed25519_verify(pk, (const uint8_t*)msg, strlen(msg), sig);
    printf("Round-trip: %s\n", ok2 ? "PASS" : "FAIL");
    
    return 0;
}
