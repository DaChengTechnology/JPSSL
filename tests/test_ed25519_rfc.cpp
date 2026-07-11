#include "ed25519.hpp"
#include "sha512.hpp"
#include <cstdio>
#include <cstring>

static void hexb(const char* label, const uint8_t* d, int n) {
    printf("  %s: ", label);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

// RFC 8032 Section 7.1 TEST 1
// https://www.rfc-editor.org/rfc/rfc8032#section-7.1

int main() {
    using namespace jpssl;

    // Secret key seed (32 bytes)
    uint8_t seed[32] = {
        0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
        0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
        0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
    };

    // Expected public key
    uint8_t expected_pub[32] = {
        0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
        0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
        0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
    };

    // Expected signature of empty message
    uint8_t expected_sig[64] = {
        0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,
        0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
        0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,
        0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
        0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,
        0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
        0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,
        0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
    };

    int fail = 0;

    // Test 1: Compute public key from seed
    printf("=== Test 1: Keygen from seed ===\n");

    // We need to compute: SHA-512(seed), clamp, then scalar mult basepoint
    uint8_t h[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, h);

    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    // Compute public key using ed25519_keygen equivalent (but from known seed)
    // Can't use ed25519_keygen directly because it generates random seed
    // Let's compute it by calling the internal functions through the public API

    // Actually, let's construct priv[64] = seed[32] || pub[32]
    uint8_t priv[64];
    memcpy(priv, seed, 32);
    uint8_t pub[32];

    // Use the ed25519_derive_pubkey pattern: scalar mult base
    // We don't have a public "derive public key from seed" function
    // so let's use a workaround: create a priv key with the seed, then call sign,
    // and extract pub from priv+32

    // Actually the cleanest approach: compute it step by step
    // SHA-512(seed), clamp, scalar mult base
    // Then sign and verify against expected

    // For now, test verification directly:
    printf("  Verifying known-good signature...\n");
    bool ok = ed25519_verify(expected_pub, (const uint8_t*)"", 0, expected_sig);
    printf("  RFC 8032 test vector 1 verify: %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fail++;

    // Test 2: Generate keypair and sign/verify self-consistency
    printf("\n=== Test 2: Self-consistency ===\n");
    uint8_t priv2[64], pub2[32], sig2[64];
    ed25519_keygen(pub2, priv2);
    const char* msg2 = "Hello Ed25519!";
    ed25519_sign(priv2, (const uint8_t*)msg2, strlen(msg2), sig2);
    bool ok2 = ed25519_verify(pub2, (const uint8_t*)msg2, strlen(msg2), sig2);
    printf("  Self-consistency: %s\n", ok2 ? "PASS" : "FAIL");
    if (!ok2) fail++;

    // Test 3: Sign empty message with known seed and verify
    printf("\n=== Test 3: Sign with known seed ===\n");
    // We need to derive the public key from the seed
    // SHA-512(seed), clamp, then scalar mult base
    uint8_t h2[64];
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, h2);
    h2[0] &= 248;
    h2[31] &= 127;
    h2[31] |= 64;
    hexb("  clamped scalar", h2, 32);

    // Now sign with this seed: priv = seed (32 bytes) || pub (computed later)
    uint8_t priv3[64];
    memcpy(priv3, seed, 32);

    // Compute pub key and store in priv3+32
    // We need ge_scalarmult_base(h2) to get pub. But that's internal.
    // Instead, sign first (which stores pub in priv+32 during ed25519_sign)
    uint8_t sig3[64];
    ed25519_sign(priv3, (const uint8_t*)"", 0, sig3);

    // Extract pub from priv3+32
    hexb("  derived pub", priv3 + 32, 32);
    hexb("  expected pub", expected_pub, 32);
    bool pub_ok = memcmp(priv3 + 32, expected_pub, 32) == 0;
    printf("  Public key match: %s\n", pub_ok ? "PASS" : "FAIL");
    if (!pub_ok) fail++;

    hexb("  signature", sig3, 64);
    hexb("  expected ", expected_sig, 64);
    bool sig_ok = memcmp(sig3, expected_sig, 64) == 0;
    printf("  Signature match: %s\n", sig_ok ? "PASS" : "FAIL");
    if (!sig_ok) fail++;

    // Test 4: Verify our own signature
    bool ok4 = ed25519_verify(priv3 + 32, (const uint8_t*)"", 0, sig3);
    printf("  Self-verify: %s\n", ok4 ? "PASS" : "FAIL");
    if (!ok4) fail++;

    printf("\n%s (%d failures)\n", fail ? "FAIL" : "PASS", fail);
    return fail;
}
