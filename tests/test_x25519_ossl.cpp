// Compare jpssl X25519 vs OpenSSL X25519  
#include "x25519.hpp"
#include <cstdio>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>

void hex(const char* label, const uint8_t* d, int n) {
    printf("%s: ", label);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

int main() {
    // RFC 7748 test vector
    uint8_t priv[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
        0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
        0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    };
    uint8_t pub_expected[32] = {
        0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,
        0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
        0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,
        0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
    };

    // jpssl
    uint8_t jp_pub[32];
    jpssl::x25519_scalar_mult(jp_pub, priv, nullptr);

    // OpenSSL
    uint8_t ossl_pub[32];
    // EVP_PKEY with X25519
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, ossl_pub, &pub_len);
    EVP_PKEY_free(pkey);

    printf("jpssl:  "); hex("", jp_pub, 32);
    printf("ossl:   "); hex("", ossl_pub, 32);
    printf("expect: "); hex("", pub_expected, 32);

    bool jp_ok = memcmp(jp_pub, pub_expected, 32) == 0;
    bool ossl_ok = memcmp(ossl_pub, pub_expected, 32) == 0;
    printf("jpssl correct:  %s\n", jp_ok ? "PASS" : "FAIL");
    printf("ossl correct:   %s\n", ossl_ok ? "PASS" : "FAIL");

    // Also check if jpssl and ossl agree
    bool agree = memcmp(jp_pub, ossl_pub, 32) == 0;
    printf("jpssl == ossl:  %s\n", agree ? "PASS" : "FAIL");

    // Quick random test
    printf("\n--- Random keypair test ---\n");
    for (int t = 0; t < 3; t++) {
        uint8_t rand_priv[32], rand_pub_jp[32], rand_pub_ossl[32];
        RAND_bytes(rand_priv, 32);
        rand_priv[0] &= 248; rand_priv[31] &= 127; rand_priv[31] |= 64;

        jpssl::x25519_scalar_mult(rand_pub_jp, rand_priv, nullptr);

        EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, rand_priv, 32);
        size_t plen = 32;
        EVP_PKEY_get_raw_public_key(pk, rand_pub_ossl, &plen);
        EVP_PKEY_free(pk);

        bool match = memcmp(rand_pub_jp, rand_pub_ossl, 32) == 0;
        printf("Test %d: %s\n", t+1, match ? "PASS" : "FAIL");
        if (!match) {
            hex("  jpssl priv", rand_priv, 32);
            hex("  jpssl pub ", rand_pub_jp, 32);
            hex("  ossl  pub ", rand_pub_ossl, 32);
        }
    }
    return 0;
}
