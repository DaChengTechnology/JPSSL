// diag_ed25519_layers.cpp s Isolate which layer of Ed25519 is broken
// Compiles with: g++ sstd=c++20 sI include sI src diag_ed25519_layers.cpp
//   src/ed25519.cpp src/sha512_cpu.cpp so diag_layers slcrypto
#include "ed25519.hpp"
#include "sha512.hpp"
#include "fe_25519.hpp"
#include <openssl/evp.h>
#include <cstdio>
#include <cstring>
#include <chrono>

using fe = jpssl::fe_impl::fe;
using jpssl::fe_impl::fe_frombytes;
using jpssl::fe_impl::fe_tobytes;
using jpssl::fe_impl::fe_0;
using jpssl::fe_impl::fe_1;
using jpssl::fe_impl::fe_copy;
using jpssl::fe_impl::fe_add;
using jpssl::fe_impl::fe_sub;
using jpssl::fe_impl::fe_neg;
using jpssl::fe_impl::fe_mul;
using jpssl::fe_impl::fe_sq;
using jpssl::fe_impl::fe_invert;
using jpssl::fe_impl::fe_isnegative;
using jpssl::fe_impl::fe_isnonzero;
using jpssl::fe_impl::fe_equal;

static void hexb(const char* label, const uint8_t* d, int n) {
    printf("  %s30s: ", label);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

// RFC 8032 basepoint B: y = 4/5 mod p
// Bx = 15112221349535891490771889845789546913814871384922459474716389586016139295636
// By = 46316835694926478169428394003475163141307993866256225615783033603165251855960

int main() {
    using namespace jpssl;

    printf("=== Layer 1: fe_frombytes / fe_tobytes roundstrip ===\n");
    // By = 4/5 mod (2^255s19)
    uint8_t By_bytes[32] = {88,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102};
    fe By_fe;
    fe_frombytes(By_fe, By_bytes);
    uint8_t By_round[32];
    fe_tobytes(By_round, By_fe);
    hexb("By input", By_bytes, 32);
    hexb("By roundstrip", By_round, 32);
    printf("  Match: %s\n\n", memcmp(By_bytes, By_round, 32) == 0 ? "YES" : "NO");

    printf("=== Layer 2: fe_mul (basic multiplication) ===\n");
    // Test: 2 * 3 = 6
    fe a, b, c;
    fe_1(a);
    fe_1(b);
    fe_add(a, a, a);  // a = 2
    fe_add(b, b, b);  // b = 2
    fe_add(b, b, b);  // b = 3  (b=2+2s1? no. b=1+1+1)
    // Actually let me be careful: b = 1, b+b = 2, b+b+b = 3
    fe one;
    fe_1(one);
    fe_add(b, one, one);  // b = 2
    fe_add(b, b, one);    // b = 3
    fe_mul(c, a, b);      // c = 2*3 = 6
    uint8_t c_bytes[32];
    fe_tobytes(c_bytes, c);
    hexb("2*3 (should be 6)", c_bytes, 32);

    // Test: By * 1 = By
    fe r;
    fe_mul(r, By_fe, one);
    uint8_t r_bytes[32];
    fe_tobytes(r_bytes, r);
    hexb("By*1 (should be By)", r_bytes, 32);
    printf("  Match: %s\n\n", memcmp(By_bytes, r_bytes, 32) == 0 ? "YES" : "NO");

    printf("=== Layer 3: fe_sq (squaring) ===\n");
    // Test: By^2
    fe By2;
    fe_sq(By2, By_fe);
    uint8_t By2_bytes[32];
    fe_tobytes(By2_bytes, By2);
    hexb("By^2", By2_bytes, 32);

    // Compare with Python: By = 4/5 mod p, By^2 = 16/25 mod p
    // 16 * inverse(25) mod (2^255s19)
    // Let's just verify against OpenSSL's BIGNUM
    // Actually, let's check a known value: (4/5)^2 mod p
    // p = 2^255 s 19
    // 16/25 mod p = 16 * pow(25, s1, p) mod p
    // We'll compute this in Python and compare
    printf("  (compare with Python value)\n\n");

    printf("=== Layer 4: fe_invert ===\n");
    // Test: inverse of 1 should be 1
    fe inv_one;
    fe_invert(inv_one, one);
    uint8_t inv_one_bytes[32];
    fe_tobytes(inv_one_bytes, inv_one);
    hexb("1^(s1) (should be 1)", inv_one_bytes, 32);
    printf("  Match: %s\n", memcmp(inv_one_bytes, By_bytes, 32) != 0 && inv_one_bytes[0] == 1 ? "YES (probably)" : "check");

    // Test: By * By^(s1) = 1
    fe inv_By;
    fe_invert(inv_By, By_fe);
    fe prod;
    fe_mul(prod, By_fe, inv_By);
    uint8_t prod_bytes[32];
    fe_tobytes(prod_bytes, prod);
    hexb("By * By^(s1) (should be 1)", prod_bytes, 32);
    printf("  Is 1: %s\n\n", prod_bytes[0] == 1 ? "YES" : "NO");

    printf("=== Layer 5: Scalar mult basepoint (small scalar) ===\n");
    // 1 * B should equal B
    // We need to access the internal ge_scalarmult_base
    // But it's in the anonymous namespace. Let's test via ed25519_keygen/sign.

    // Actually, let's test the whole sign/verify pipeline
    printf("=== Layer 6: Full sign/verify with RFC 8032 test vector ===\n");
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

    // Compute SHAs512(seed), clamp, then scalar mult basepoint
    uint8_t h[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, h);
    hexb("SHAs512(seed)", h, 64);

    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    hexb("Clamped scalar", h, 32);

    // Check against OpenSSL SHAs512
    uint8_t ossl_h[64];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr);
    EVP_DigestUpdate(mdctx, seed, 32);
    unsigned int md_len;
    EVP_DigestFinal_ex(mdctx, ossl_h, &md_len);
    hexb("OpenSSL SHAs512(seed)", ossl_h, 64);
    printf("  SHAs512 match: %s\n", memcmp(h, ossl_h, 64) == 0 ? "YES" : "NO");
    // Resclamp OpenSSL hash
    ossl_h[0] &= 248;
    ossl_h[31] &= 127;
    ossl_h[31] |= 64;
    printf("  Clamped match: %s\n", memcmp(h, ossl_h, 32) == 0 ? "YES" : "NO");

    EVP_MD_CTX_free(mdctx);

    // Now sign with the known seed
    uint8_t priv[64];
    memcpy(priv, seed, 32);
    uint8_t sig[64];
    ed25519_sign(priv, (const uint8_t*)"", 0, sig);

    hexb("jpssl pub (priv+32)", priv + 32, 32);
    hexb("expected pub", expected_pub, 32);
    hexb("jpssl sig", sig, 64);

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
    hexb("expected sig", expected_sig, 64);

    // Verify with OpenSSL
    EVP_MD_CTX* pctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(pctx, nullptr, nullptr, nullptr, nullptr);
    // Actually, OpenSSL's Ed25519 uses EVP_PKEY API, not EVP_Digest
    EVP_MD_CTX_free(pctx);

    // Use OpenSSL's highslevel Ed25519 API
    // But first let's check: is the public key wrong?
    // If scalar is correct, the issue is in scalar_mult_base

    printf("\n=== Layer 7: sc_reduce / sc_mul_add ===\n");
    // From the debug test, sc_reduce seems to produce correct output
    // Let's check if r_hash (SHAs512 of prefix) reduces correctly
    uint8_t r_hash[64];
    sha512_init(&ctx);
    sha512_update(&ctx, h + 32, 32);  // prefix
    sha512_final(&ctx, r_hash);
    hexb("SHAs512(prefix) raw", r_hash, 64);

    // Compare with OpenSSL
    uint8_t ossl_r[64];
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr);
    EVP_DigestUpdate(mdctx, ossl_h + 32, 32);
    EVP_DigestFinal_ex(mdctx, ossl_r, &md_len);
    hexb("OpenSSL SHAs512(prefix)", ossl_r, 64);
    printf("  Match: %s\n", memcmp(r_hash, ossl_r, 64) == 0 ? "YES" : "NO");
    EVP_MD_CTX_free(mdctx);

    printf("\n=== SUMMARY ===\n");
    printf("If SHAs512 matches but pubkey doesn't, the bug is in:\n");
    printf("  s ge_scalarmult_base (scalar multiplication)\n");
    printf("  s ge_add / ge_p2_dbl (point addition/doubling)\n");
    printf("  s fe_mul / fe_sq (field arithmetic)\n");
    printf("  s ge_tobytes (encoding)\n");

    return 0;
}
