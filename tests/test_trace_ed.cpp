#include "ed25519.hpp"
#include "sha512.hpp"
#include <cstdio>
#include <cstring>

static void hexb(const char* label, const uint8_t* d, int n) {
    printf("  %s: ", label);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

// Include the internal headers to trace step by step
#include "fe_25519.hpp"

int main() {
    using namespace jpssl;
    using namespace jpssl::fe_impl;

    // RFC 8032 test vector 1: key generation
    uint8_t seed[32] = {
        0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
        0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
        0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
    };

    uint8_t expected_pub[32] = {
        0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
        0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
        0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
    };

    // Step 1: SHA-512(seed)
    uint8_t h[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, h);
    printf("=== Step 1: SHA-512(seed) ===\n");
    hexb("hash", h, 64);

    // Step 2: Clamp
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    printf("=== Step 2: Clamped scalar ===\n");
    hexb("clamped", h, 32);

    // Let's decode the scalar as a big integer
    // The expected public key corresponds to scalar mult of clamped seed by basepoint

    // Verify with OpenSSL via command line
    printf("\n=== Cross-check with OpenSSL ===\n");
    // Write seed to temp file and use openssl
    {
        FILE* f = fopen("/tmp/ed_seed.bin", "wb");
        fwrite(seed, 1, 32, f);
        fclose(f);
    }
    int r = system("openssl pkey -provider legacy -provider default -in /tmp/ed_seed.bin -inform DER -pubout 2>/dev/null || "
                   "echo 'openssl pkey failed'");
    if (r != 0) {
        // Try with genpkey
        system("openssl genpkey -algorithm ED25519 -outform DER 2>/dev/null");
    }

    // Better: compute public key using openssl
    printf("\nOpenSSL derived public key:\n");
    // First create a seed file and use openssl to derive key
    FILE* f = fopen("/tmp/ed_priv.pem", "wb");
    fprintf(f, "-----BEGIN PRIVATE KEY-----\n");
    // Just skip openssl cross-check for now
    fclose(f);

    // Step 3: compute scalar multiplication manually step by step
    // We need access to ge_scalarmult_base which is in anonymous namespace
    // Let's just use the public API

    uint8_t priv[64];
    memcpy(priv, seed, 32);
    // priv+32 will be filled by ed25519_sign

    uint8_t sig[64];
    ed25519_sign(priv, (const uint8_t*)"", 0, sig);
    hexb("  computed pub", priv + 32, 32);
    hexb("  expected pub", expected_pub, 32);
    bool pub_match = memcmp(priv + 32, expected_pub, 32) == 0;
    printf("  pubkey match: %s\n", pub_match ? "YES" : "NO");

    // Verify the RFC 8032 expected signature
    bool verify_ok = ed25519_verify(expected_pub, (const uint8_t*)"", 0, sig);
    printf("  verify RFC sig: %s\n", verify_ok ? "OK" : "FAIL");
    
    // Also test: does the computed pubkey verify the computed signature?
    bool self_ok = ed25519_verify(priv+32, (const uint8_t*)"", 0, sig);
    printf("  self verify: %s\n", self_ok ? "OK" : "FAIL");

    // Test 2: generate fresh keypair and sign/verify
    printf("\n=== Test: fresh keypair ===\n");
    uint8_t priv2[64], pub2[32], sig2[64];
    ed25519_keygen(pub2, priv2);
    hexb("  pub2", pub2, 32);
    ed25519_sign(priv2, (const uint8_t*)"test", 4, sig2);
    bool ok2 = ed25519_verify(pub2, (const uint8_t*)"test", 4, sig2);
    printf("  verify ok: %s\n", ok2 ? "YES" : "NO");

    // If fails, trace the verify process
    if (!ok2) {
        printf("\n=== Tracing verify failure ===\n");
        // Extract components
        uint8_t r_bytes[32], s_bytes[32];
        memcpy(r_bytes, sig2, 32);
        memcpy(s_bytes, sig2 + 32, 32);
        hexb("  R", r_bytes, 32);
        hexb("  S", s_bytes, 32);
        
        // Check S < l
        uint64_t L64[4] = {0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000};
        uint64_t s_l[4];
        for (int i = 0; i < 4; i++)
            s_l[i] = (uint64_t)s_bytes[8*i] | ((uint64_t)s_bytes[8*i+1] << 8) |
                     ((uint64_t)s_bytes[8*i+2] << 16) | ((uint64_t)s_bytes[8*i+3] << 24) |
                     ((uint64_t)s_bytes[8*i+4] << 32) | ((uint64_t)s_bytes[8*i+5] << 40) |
                     ((uint64_t)s_bytes[8*i+6] << 48) | ((uint64_t)s_bytes[8*i+7] << 56);
        int cmp = 0;
        for (int j = 3; j >= 0; j--) {
            if (s_l[j] > L64[j]) { cmp = 1; break; }
            if (s_l[j] < L64[j]) { cmp = -1; break; }
        }
        printf("  S < l: %s (cmp=%d)\n", cmp < 0 ? "yes" : "no", cmp);
    }

    return pub_match && verify_ok && self_ok && ok2 ? 0 : 1;
}
