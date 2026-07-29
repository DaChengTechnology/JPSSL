#include "ed448.hpp"
#include "sha3.hpp"
#include "fe_448.hpp"
#include "rsa.hpp"
#include <cstdio>
#include <cstring>

using namespace jpssl;
using namespace jpssl::fe448_impl;

static void print_hex(const char* label, const uint8_t* data, size_t n) {
    printf("%s: ", label);
    for (size_t i = 0; i < n; ++i) printf("%02x", data[i]);
    printf("\n");
}

static bool check_eq(const char* name, const uint8_t* got, const uint8_t* exp, size_t n) {
    bool ok = (memcmp(got, exp, n) == 0);
    printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        print_hex("  Got     ", got, n);
        print_hex("  Expected", exp, n);
    }
    return ok;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static bool hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

int main() {
    const char* priv_hex = "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
    uint8_t seed[57];
    hex_to_bytes(priv_hex, seed, 57);

    // Step 1: SHAKE256(seed, 114)
    uint8_t h[114];
    {
        sha3_ctx ctx;
        shake256_init(&ctx);
        shake_update(&ctx, seed, 57);
        shake_squeeze(&ctx, h, 114);
    }
    print_hex("h[0:57]", h, 57);
    print_hex("h[57:114]", h+57, 57);

    // Expected from Python
    uint8_t exp_h57[57], exp_h57_114[57];
    hex_to_bytes("eb3930a0cea0808ec7ed6667f472a588b411f0545ba4f3ee75025e1d38519cb905c036d81eeed17483f9f56615ceee4fa70501a71fc0bbb778", exp_h57, 57);
    hex_to_bytes("2f1b36f96b3e2ef921d6119ae189bb3e07f68a293b92d1e8d8e6b0bbf5186c92dad552a03a1b171abc1fb37954a66d15d8fb74f17d4cbb1e29", exp_h57_114, 57);
    
    bool ok = true;
    ok &= check_eq("SHAKE256(seed,114)[0:57]", h, exp_h57, 57);
    ok &= check_eq("SHAKE256(seed,114)[57:114]", h+57, exp_h57_114, 57);

    // Step 2: prune
    uint8_t s[57];
    memcpy(s, h, 57);
    s[0] &= 0xFC;
    s[55] |= 0x80;
    s[56] = 0x00;
    print_hex("s pruned", s, 57);
    
    uint8_t exp_s_pruned[57];
    hex_to_bytes("e83930a0cea0808ec7ed6667f472a588b411f0545ba4f3ee75025e1d38519cb905c036d81eeed17483f9f56615ceee4fa70501a71fc0bbb700", exp_s_pruned, 57);
    ok &= check_eq("prune_scalar", s, exp_s_pruned, 57);

    // Step 3: reduce mod L
    printf("\n--- Mod L reduction ---\n");
    {
        auto bytes_le_to_bn = [](const uint8_t* le, size_t n) -> rsa_bignum {
            uint8_t be[256] = {0};
            for (size_t i = 0; i < n; ++i) be[i] = le[n - 1 - i];
            return rsa_bignum::from_bytes(be, n);
        };
        auto bn_to_bytes_le = [](const rsa_bignum& v, uint8_t* out, size_t n) {
            uint8_t be[256] = {0};
            v.to_bytes(be);
            for (size_t i = 0; i < n; ++i) out[i] = be[255 - i];
        };
        
        // L from ed448.cpp
        uint8_t L_BYTES[57] = {
            0xdf,0xe3,0x7f,0x76,0x58,0x4c,0x8f,0x68,0x19,0x85,0xa5,0x61,0x0c,0x09,0x6e,0x78,
            0x07,0xd6,0x8c,0x34,0xcc,0x22,0x1d,0xbb,0x77,0x2b,0xf2,0x45,0xad,0x57,0x33,0xaa,
            0x88,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x3f,0x00
        };
        rsa_bignum L = bytes_le_to_bn(L_BYTES, 57);
        
        rsa_bignum s_bn = bytes_le_to_bn(s, 57);
        rsa_bignum s_mod;
        bn_mod(s_mod, s_bn, L);
        
        uint8_t s_le[57];
        bn_to_bytes_le(s_mod, s_le, 57);
        print_hex("s mod L", s_le, 57);
        
        uint8_t exp_s_mod[57];
        hex_to_bytes("2a7230b31d0862bd94e31ba4db60c997a565d6ebc25eb97886ab7991dda13565f4c036d81eeed17483f9f56615ceee4fa70501a71fc0bb3700", exp_s_mod, 57);
        ok &= check_eq("mod L", s_le, exp_s_mod, 57);
    }

    printf("\n%s\n", ok ? "ALL HASH/PRUNE/MODL CHECKS PASSED" : "SOME CHECKS FAILED");
    return ok ? 0 : 1;
}
