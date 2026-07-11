#include "ed25519.hpp"
#include "sha512.hpp"
#include <cstdio>
#include <cstring>

static void hexb(const char* label, const uint8_t* d, int n) {
    printf("  %s: ", label);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

static constexpr uint64_t L64[4] = {
    0x5812631a5cf5d3ed, 0x14def9dea2f79cd6,
    0x0000000000000000, 0x1000000000000000
};
static constexpr uint64_t S64[4] = {
    0xd6ec31748d98951d, 0xc6ef5bf4737dcf70,
    0xfffffffffffffffe, 0x0fffffffffffffff
};

static void sc_load_64(uint64_t r[4], const uint8_t* b) {
    for (int i = 0; i < 4; i++)
        r[i] = (uint64_t)b[8*i] | ((uint64_t)b[8*i+1] << 8) |
               ((uint64_t)b[8*i+2] << 16) | ((uint64_t)b[8*i+3] << 24) |
               ((uint64_t)b[8*i+4] << 32) | ((uint64_t)b[8*i+5] << 40) |
               ((uint64_t)b[8*i+6] << 48) | ((uint64_t)b[8*i+7] << 56);
}
static void sc_store_64(uint8_t* b, const uint64_t r[4]) {
    for (int i = 0; i < 4; i++) {
        b[8*i] = r[i] & 0xFF;
        b[8*i+1] = (r[i] >> 8) & 0xFF;
        b[8*i+2] = (r[i] >> 16) & 0xFF;
        b[8*i+3] = (r[i] >> 24) & 0xFF;
        b[8*i+4] = (r[i] >> 32) & 0xFF;
        b[8*i+5] = (r[i] >> 40) & 0xFF;
        b[8*i+6] = (r[i] >> 48) & 0xFF;
        b[8*i+7] = (r[i] >> 56) & 0xFF;
    }
}

int main() {
    using namespace jpssl;
    int fail = 0;

    uint8_t seed[32] = {
        0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
        0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
        0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
        0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
    };
    uint8_t h[64];
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, h);
    uint8_t r_hash[64];
    sha512_init(&ctx);
    sha512_update(&ctx, h + 32, 32);
    sha512_final(&ctx, r_hash);
    hexb("SHA512(prefix)", r_hash, 64);

    uint64_t t[8];
    sc_load_64(t, r_hash);
    sc_load_64(t + 4, r_hash + 32);

    int passes = 0;
    for (int pass = 0; pass < 200; pass++) {
        if ((t[4] | t[5] | t[6] | t[7]) == 0) { passes = pass; break; }
        uint64_t hi[4] = {t[4], t[5], t[6], t[7]};
        t[4] = t[5] = t[6] = t[7] = 0;
        for (int pos = 0; pos < 4; pos++) {
            if (hi[pos] == 0) continue;
            uint64_t p[5] = {0,0,0,0,0};
            unsigned __int128 carry = 0;
            for (int j = 0; j < 4; j++) {
                carry += (unsigned __int128)hi[pos] * S64[j] + p[j];
                p[j] = (uint64_t)carry;
                carry >>= 64;
            }
            p[4] = (uint64_t)carry;
            carry = 0;
            for (int j = 0; j < 5; j++) {
                carry += (unsigned __int128)t[j + pos] + p[j];
                t[j + pos] = (uint64_t)carry;
                carry >>= 64;
            }
            for (int j = 5 + pos; carry && j < 8; j++) {
                carry += t[j];
                t[j] = (uint64_t)carry;
                carry >>= 64;
            }
        }
    }
    printf("  converged in %d passes\n", passes);
    printf("  t after iterative: ");
    for (int i = 0; i < 8; i++) printf("%016lx ", t[i]);
    printf("\n");

    for (int i = 0; i < 10; i++) {
        int cmp = 0;
        for (int j = 3; j >= 0; j--) {
            if (t[j] > L64[j]) { cmp = 1; break; }
            if (t[j] < L64[j]) { cmp = -1; break; }
        }
        if (cmp < 0) break;
        uint64_t borrow = 0;
        for (int j = 0; j < 4; j++) {
            unsigned __int128 r = (unsigned __int128)t[j] - L64[j] - borrow;
            t[j] = (uint64_t)r;
            borrow = (uint64_t)(r >> 64) & 1;
        }
    }
    uint8_t result[32];
    sc_store_64(result, t);
    hexb("result", result, 32);

    uint8_t exp[32] = {
        0xf3,0x89,0x07,0x30,0x8c,0x89,0x3d,0xea,
        0xf2,0x44,0x78,0x7d,0xb4,0xaf,0x53,0x68,
        0x22,0x49,0x10,0x74,0x18,0xaf,0xc2,0xed,
        0xc5,0x8f,0x75,0xac,0x58,0xa0,0x74,0x04
    };
    hexb("expected", exp, 32);
    bool ok = memcmp(result, exp, 32) == 0;
    printf("  match: %s\n", ok ? "YES" : "NO");
    if (!ok) fail++;

    printf("\n%s\n", fail ? "FAIL" : "PASS");
    return fail;
}
