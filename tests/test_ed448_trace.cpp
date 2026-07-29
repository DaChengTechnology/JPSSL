#include "ed448.hpp"
#include "sha3.hpp"
#include "rsa.hpp"
#include "fe_448.hpp"
#include <cstdio>
#include <cstring>
#include <openssl/evp.h>

using namespace jpssl;
using namespace jpssl::fe448_impl;

static void print_hex(const char* label, const uint8_t* data, size_t n) {
    printf("%s: ", label);
    for (size_t i = 0; i < n; ++i) printf("%02x", data[i]);
    printf("\n");
}

int main() {
    // d = p - 39081, from RFC
    fe448 d_val;
    static const uint8_t D_BYTES[56] = {
        0x56,0x67,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };
    fe448_frombytes(d_val, D_BYTES);

    // fe448_one: just h[0]=1
    fe448 one_val;
    fe448_1(one_val);

    // 1. Decode base point
    static const uint8_t B_ENC[57] = {
        0x14,0xfa,0x30,0xf2,0x5b,0x79,0x08,0x98,0xad,0xc8,0xd7,0x4e,
        0x2c,0x13,0xbd,0xfd,0xc4,0x39,0x7c,0xe6,0x1c,0xff,0xd3,0x3a,
        0xd7,0xc2,0xa0,0x05,0x1e,0x9c,0x78,0x87,0x40,0x98,0xa3,0x6c,
        0x73,0x73,0xea,0x4b,0x62,0xc7,0xc9,0x56,0x37,0x20,0x76,0x88,
        0x24,0xbc,0xb6,0x6e,0x71,0x46,0x3f,0x69,0x00
    };
    jpssl::ed448_point BP;
    bool bok = jpssl::ed448_debug_decode(BP, B_ENC);
    printf("Base point decode: %s\n", bok ? "OK" : "FAIL");

    // Get affine coordinates
    fe448 z_inv, x_aff, y_aff;
    fe448_invert(z_inv, BP.Z);
    fe448_mul(x_aff, BP.X, z_inv);
    fe448_mul(y_aff, BP.Y, z_inv);
    uint8_t xb[56], yb[56];
    fe448_tobytes(xb, x_aff);
    fe448_tobytes(yb, y_aff);
    print_hex("  base x", xb, 56);
    print_hex("  base y", yb, 56);

    // Compute 2/3 mod p using rsa_bignum
    static const uint8_t p_bytes[56] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };
    uint8_t p_be[56];
    for (int i = 0; i < 56; ++i) p_be[i] = p_bytes[55 - i];
    rsa_bignum P = rsa_bignum::from_bytes(p_be, 56);

    rsa_bignum two_p;
    bn_add(two_p, P, P);
    bn_add(two_p, two_p, rsa_bignum::from_uint64(1));
    rsa_bignum three = rsa_bignum::from_uint64(3);
    rsa_bignum inv3, rem;
    bn_divmod(inv3, rem, two_p, three);

    rsa_bignum y_bn;
    bn_mul(y_bn, rsa_bignum::from_uint64(2), inv3);
    rsa_bignum y_mod;
    bn_mod(y_mod, y_bn, P);

    uint8_t y_be[256] = {0};
    y_mod.to_bytes(y_be);
    uint8_t y_expected[56];
    for (int i = 0; i < 56; ++i) y_expected[i] = y_be[255 - i];
    print_hex("  expected y (2/3)", y_expected, 56);
    printf("  our y matches 2/3: %s\n", memcmp(yb, y_expected, 56) == 0 ? "YES" : "NO");

    // 2. Verify curve equation: x^2 + y^2 = 1 + d*x^2*y^2
    fe448 X2, Y2, x2_plus_y2, rhs_tmp, rhs;
    fe448_sq(X2, x_aff);
    fe448_sq(Y2, y_aff);
    fe448_add(x2_plus_y2, X2, Y2);
    fe448_mul(rhs_tmp, X2, Y2);
    fe448_mul(rhs, rhs_tmp, d_val);
    fe448_add(rhs, rhs, one_val);

    uint8_t lhs_b[56], rhs_b[56];
    fe448_tobytes(lhs_b, x2_plus_y2);
    fe448_tobytes(rhs_b, rhs);
    printf("Curve eq x^2+y^2=1+d*x^2*y^2: %s\n", memcmp(lhs_b, rhs_b, 56) == 0 ? "YES" : "NO");
    if (memcmp(lhs_b, rhs_b, 56) != 0) {
        print_hex("  lhs", lhs_b, 56);
        print_hex("  rhs", rhs_b, 56);
    }

    // Roundtrip
    uint8_t re_enc[57];
    jpssl::ed448_debug_encode(BP, re_enc);
    printf("Base point roundtrip: %s\n", memcmp(B_ENC, re_enc, 57) == 0 ? "OK" : "FAIL");

    // 3. Build pow2B chain and check curve equation
    jpssl::ed448_point pow2B[448];
    jpssl::ed448_debug_decode(pow2B[0], B_ENC);
    for (int k = 1; k < 448; ++k)
        jpssl::ed448_debug_point_double(pow2B[k], pow2B[k-1]);
    printf("\npow2B curve equation check:\n");
    bool all_ok = true;
    for (int k = 0; k < 448 && all_ok; ++k) {
        fe448_invert(z_inv, pow2B[k].Z);
        fe448_mul(x_aff, pow2B[k].X, z_inv);
        fe448_mul(y_aff, pow2B[k].Y, z_inv);
        fe448_sq(X2, x_aff);
        fe448_sq(Y2, y_aff);
        fe448_add(x2_plus_y2, X2, Y2);
        fe448_mul(rhs_tmp, X2, Y2);
        fe448_mul(rhs, rhs_tmp, d_val);
        fe448_add(rhs, rhs, one_val);
        fe448_tobytes(lhs_b, x2_plus_y2);
        fe448_tobytes(rhs_b, rhs);
        if (memcmp(lhs_b, rhs_b, 56) != 0) {
            printf("  pow2B[%d] curve eq FAILED\n", k);
            all_ok = false;
        }
    }
    if (all_ok) printf("  [PASS] all pow2B points on curve\n");

    // 4. Check point_add results stay on curve
    printf("\npoint_add curve equation check:\n");
    all_ok = true;
    for (int s = 0; s < 50 && all_ok; ++s) {
        int a = (s * 9) % 448;
        int b = (s * 9 + 5) % 448;
        if (a == b) continue;
        jpssl::ed448_point sum;
        jpssl::ed448_debug_point_add(sum, pow2B[a], pow2B[b]);
        fe448_invert(z_inv, sum.Z);
        fe448_mul(x_aff, sum.X, z_inv);
        fe448_mul(y_aff, sum.Y, z_inv);
        fe448_sq(X2, x_aff);
        fe448_sq(Y2, y_aff);
        fe448_add(x2_plus_y2, X2, Y2);
        fe448_mul(rhs_tmp, X2, Y2);
        fe448_mul(rhs, rhs_tmp, d_val);
        fe448_add(rhs, rhs, one_val);
        fe448_tobytes(lhs_b, x2_plus_y2);
        fe448_tobytes(rhs_b, rhs);
        if (memcmp(lhs_b, rhs_b, 56) != 0) {
            printf("  sum(pow2B[%d], pow2B[%d]) curve FAILED\n", a, b);
            all_ok = false;
        }
    }
    if (all_ok) printf("  [PASS] all point_add results on curve\n");

    // 5. Compare keygen with OpenSSL for RFC seed
    const char* priv_hex = "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
    uint8_t priv[57];
    for (int i = 0; i < 57; ++i) {
        int hi = (priv_hex[i*2] >= 'a') ? (priv_hex[i*2] - 'a' + 10) : (priv_hex[i*2] - '0');
        int lo = (priv_hex[i*2+1] >= 'a') ? (priv_hex[i*2+1] - 'a' + 10) : (priv_hex[i*2+1] - '0');
        priv[i] = (uint8_t)((hi << 4) | lo);
    }

    uint8_t our_pub[57];
    ed448_keygen(our_pub, priv);
    uint8_t ossl_pub[57];
    {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, nullptr, priv, 57);
        size_t pub_len = 57;
        EVP_PKEY_get_raw_public_key(pkey, ossl_pub, &pub_len);
        EVP_PKEY_free(pkey);
    }
    printf("\nOur keygen pub:  ");
    print_hex("", our_pub, 57);
    printf("OpenSSL keygen: ");
    print_hex("", ossl_pub, 57);
    printf("Match: %s\n", memcmp(our_pub, ossl_pub, 57) == 0 ? "YES" : "NO");

    return 0;
}
