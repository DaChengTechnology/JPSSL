#include "x25519.hpp"
#include <cstdio>
#include <cstring>

static void hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main() {
    // RFC 7748 Section 6.1 Test Vector 1
    uint8_t alice_priv[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
        0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
        0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    };
    uint8_t alice_pub_expected[32] = {
        0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,
        0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
        0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,
        0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
    };
    uint8_t bob_priv[32] = {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
    };
    uint8_t bob_pub_expected[32] = {
        0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
        0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
        0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
        0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
    };
    uint8_t shared_expected[32] = {
        0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,
        0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
        0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,
        0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
    };

    bool all_pass = true;

    // Test 1: Generate Alice's public key from private
    uint8_t alice_pub[32];
    jpssl::x25519_scalar_mult(alice_pub, alice_priv, nullptr);
    bool t1 = memcmp(alice_pub, alice_pub_expected, 32) == 0;
    printf("Test 1 - Alice pubkey: %s\n", t1 ? "PASS" : "FAIL");
    if (!t1) { hex("  Got     ", alice_pub, 32); hex("  Expected", alice_pub_expected, 32); all_pass = false; }

    // Test 2: Generate Bob's public key
    uint8_t bob_pub[32];
    jpssl::x25519_scalar_mult(bob_pub, bob_priv, nullptr);
    bool t2 = memcmp(bob_pub, bob_pub_expected, 32) == 0;
    printf("Test 2 - Bob pubkey:   %s\n", t2 ? "PASS" : "FAIL");
    if (!t2) { hex("  Got     ", bob_pub, 32); hex("  Expected", bob_pub_expected, 32); all_pass = false; }

    // Test 3: Shared secret (Alice's side)
    uint8_t shared_a[32];
    jpssl::x25519_scalar_mult(shared_a, alice_priv, bob_pub_expected);
    bool t3 = memcmp(shared_a, shared_expected, 32) == 0;
    printf("Test 3 - Alice shared: %s\n", t3 ? "PASS" : "FAIL");
    if (!t3) { hex("  Got     ", shared_a, 32); hex("  Expected", shared_expected, 32); all_pass = false; }

    // Test 4: Shared secret (Bob's side)
    uint8_t shared_b[32];
    jpssl::x25519_scalar_mult(shared_b, bob_priv, alice_pub_expected);
    bool t4 = memcmp(shared_b, shared_expected, 32) == 0;
    printf("Test 4 - Bob shared:   %s\n", t4 ? "PASS" : "FAIL");
    if (!t4) { hex("  Got     ", shared_b, 32); hex("  Expected", shared_expected, 32); all_pass = false; }

    // Test 5: Both sides agree
    bool t5 = memcmp(shared_a, shared_b, 32) == 0;
    printf("Test 5 - Both agree:   %s\n", t5 ? "PASS" : "FAIL");
    if (!t5) all_pass = false;

    printf("\n%s\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return all_pass ? 0 : 1;
}
