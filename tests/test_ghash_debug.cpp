#include "aes.hpp"
#include <cstdio>
#include <cstring>
#include <vector>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wdeprecated"

static void hexdump(const char* label, const uint8_t* data, size_t len) {
    std::printf("  %s: ", label);
    for (size_t i = 0; i < len; ++i) std::printf("%02x", data[i]);
    std::printf("\n");
}

using namespace jpssl;

// Compute GHASH(H, X) where X is a single block, using OpenSSL as oracle
// OpenSSL tag = GHASH(AAD || CT || len_block) XOR E(K,J0)
// If we pass no AAD + CT=16 bytes + extract tag, then:
//   S = tag XOR E(K,J0) = GHASH(H, [X] || len_block)
// We want just X * H = GHASH(H, [X])
// We can compute: process X as AAD, then...
//   S = tag XOR E(K,J0) = GHASH(H, X || 0^pad || [len(X)*8]_64 || [0]_64)
// For a single full block X (16 bytes), pad = 0:
//   S = GHASH(H, [X] || len_block)
//     = X * H^2 + len_block * H
// So X * H = (S + len_block * H) * H^{-1}  ← complicated
//
// Simpler: use different API that gives us just the raw GHASH
// Actually, GCM128_CONTEXT internally stores the GHASH state in Xi.
// We can access it via gcm->Xi after processing.
// But it's in internal format. Let's just use setiv + aad in a specific way.

// Approach: pass X as AAD + no encrypt. Get tag = GHASH(H, X||pad||len_block) XOR E(K,J0)
// For len(X) = 16, pad = 0, len_block = [128]_64 || [0]_64
// ossl_ghash = tag XOR E(K,J0) = X*H^2 + len_block*H
//
// We want jpssl_ghash = GHASH(H, X) = X*H (single block, no len_block)
// These are not directly comparable for multiple blocks.
//
// Instead: test gf128_mul directly. GHASH(H, [X]) with 1 block = X*H.
// Compare jp's gf128_mul(X, H) vs relying on GHASH machinery.

int main() {
    const uint8_t key[] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    // Compute H = AES_encrypt(K, 0^128)
    uint8_t H[16], zero[16] = {};
    aes_encrypt_block(ctx, zero, H);
    hexdump("H", H, 16);

    // Test multiplicative identity: 1 * H == H
    uint8_t one[16] = {};
    one[15] = 0x01;  // x^0 coefficient = 1
    uint8_t one_mul_H[16];
    gf128_mul(one, H, one_mul_H);
    hexdump("1 * H", one_mul_H, 16);

    uint8_t H_mul_one[16];
    gf128_mul(H, one, H_mul_one);
    hexdump("H * 1", H_mul_one, 16);

    bool identity_ok = std::memcmp(one_mul_H, H, 16) == 0 && std::memcmp(H_mul_one, H, 16) == 0;
    std::printf("  GF(2^128) identity: %s\n", identity_ok ? "PASS" : "FAIL");

    // Test: compute E(K, J0) — needed for tag extraction
    uint8_t J0[16] = {};
    const uint8_t iv12[] = {0x99,0xaa,0xbb,0xcc,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    std::memcpy(J0, iv12, 12);
    J0[15] = 0x01;
    uint8_t E_J0[16];
    aes_encrypt_block(ctx, J0, E_J0);
    hexdump("E(K,J0)", E_J0, 16);

    AES_KEY ossl_key;
    AES_set_encrypt_key(key, 128, &ossl_key);

    // 1) Test GHASH on a SINGLE block: X = all-zeros
    //    jpssl: ghash(H, [0^16]) should give 0
    {
        uint8_t single_zero[16] = {};
        uint8_t jp_out[16];
        ghash(H, single_zero, jp_out);
        // Also test directly via gf128_mul: 0 * H = 0
        uint8_t zero_mul_H[16];
        gf128_mul(single_zero, H, zero_mul_H);

        hexdump("jp ghash([0])", jp_out, 16);
        hexdump("jp gf128_mul(0,H)", zero_mul_H, 16);

        bool ok = true;
        for (int i = 0; i < 16; ++i) if (jp_out[i] != 0) ok = false;
        std::printf("  GHASH([0]) == 0: %s\n", ok ? "PASS" : "FAIL");
        bool mul_ok = true;
        for (int i = 0; i < 16; ++i) if (zero_mul_H[i] != 0) mul_ok = false;
        std::printf("  gf128_mul(0,H) == 0: %s\n", mul_ok ? "PASS" : "FAIL");
    }

    // 2) Test GHASH on SINGLE block: X = 1 (identity), GHASH(H, [1]) = H
    {
        uint8_t block_one[16] = {};
        block_one[15] = 0x01;
        uint8_t jp_out[16];
        ghash(H, block_one, jp_out);

        hexdump("jp ghash([1])", jp_out, 16);
        bool ok = std::memcmp(jp_out, H, 16) == 0;
        std::printf("  GHASH([1]) == H: %s\n", ok ? "PASS" : "FAIL");
    }

    // 3) Test the actual GCM input: compare FULL GHASH (including len_block) with OpenSSL
    //    Build the full GHASH input as aes_gcm_encrypt does
    const uint8_t pt[] = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
        0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
        0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
        0xb1,0x6a,0xed,0xb5,0xb0,0x8d,0xaa,0x90,0x31,0xa7,0x59,0x09,0xc6,0x71,0x66,0x29
    };
    const uint8_t aad[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13
    };
    size_t pt_len = sizeof(pt);
    size_t aad_len = sizeof(aad);

    // Get OpenSSL ciphertext
    uint8_t ossl_ct[64];
    {
        GCM128_CONTEXT *gcm = CRYPTO_gcm128_new(&ossl_key, (block128_f)AES_encrypt);
        CRYPTO_gcm128_setiv(gcm, iv12, 12);
        CRYPTO_gcm128_aad(gcm, aad, aad_len);
        CRYPTO_gcm128_encrypt(gcm, pt, ossl_ct, pt_len);
        CRYPTO_gcm128_release(gcm);
    }

    // Build GHASH input exactly as aes_gcm_encrypt does
    std::vector<uint8_t> gi;
    gi.insert(gi.end(), aad, aad + aad_len);
    gi.insert(gi.end(), (16 - (aad_len % 16)) % 16, 0);
    gi.insert(gi.end(), ossl_ct, ossl_ct + pt_len);
    gi.insert(gi.end(), (16 - (pt_len % 16)) % 16, 0);
    auto store_be64 = [](uint8_t* buf, uint64_t val) {
        for (int i = 7; i >= 0; --i) { buf[i] = val & 0xFF; val >>= 8; }
    };
    uint8_t len_block[16] = {};
    store_be64(len_block, aad_len * 8);
    store_be64(len_block + 8, pt_len * 8);
    gi.insert(gi.end(), len_block, len_block + 16);

    // jpssl GHASH (full, including len_block)
    uint8_t jp_S[16];
    ghash(H, gi, jp_S);
    hexdump("jp GHASH(full)", jp_S, 16);

    // OpenSSL GHASH: extract from proper GCM tag
    {
        GCM128_CONTEXT *gcm = CRYPTO_gcm128_new(&ossl_key, (block128_f)AES_encrypt);
        CRYPTO_gcm128_setiv(gcm, iv12, 12);
        CRYPTO_gcm128_aad(gcm, aad, aad_len);
        CRYPTO_gcm128_encrypt(gcm, pt, ossl_ct, pt_len);
        uint8_t ossl_tag[16];
        CRYPTO_gcm128_tag(gcm, ossl_tag, 16);
        CRYPTO_gcm128_release(gcm);

        uint8_t ossl_S[16];
        for (int i = 0; i < 16; ++i) ossl_S[i] = ossl_tag[i] ^ E_J0[i];
        hexdump("ossl GHASH(full)", ossl_S, 16);
        bool ghash_ok = std::memcmp(jp_S, ossl_S, 16) == 0;
        std::printf("  GHASH(full) match: %s\n", ghash_ok ? "PASS" : "FAIL");
    }

    // 4) Debug: trace GHASH block by block
    // Rebuild the GHASH input blocks
    // Input has 7 blocks:
    //   [0] = aad[0..15]: 000102030405060708090a0b0c0d0e0f
    //   [1] = aad[16..18] + pad: 10111213000000000000000000000000
    //   [2..5] = ciphertext (4 blocks)
    //   [6] = len_block: 00000000000000a00000000000000200
    {
        std::vector<uint8_t> blocks = gi;  // 112 bytes = 7 * 16
        size_t num_blocks = blocks.size() / 16;

        // Compute GHASH step by step with jpssl
        for (size_t step = 1; step <= num_blocks; ++step) {
            std::vector<uint8_t> partial(blocks.data(), blocks.data() + step * 16);
            uint8_t jp_partial[16];
            ghash(H, partial, jp_partial);
            std::printf("  Step %zu: GHASH up to block %zu\n", step, step);
            hexdump("    jp partial", jp_partial, 16);

            // OpenSSL oracle: process the exact same partial input
            // We do this by passing as AAD (no CT) and extracting tag
            uint8_t dummy_ct[1] = {};
            GCM128_CONTEXT *gcm = CRYPTO_gcm128_new(&ossl_key, (block128_f)AES_encrypt);
            CRYPTO_gcm128_setiv(gcm, iv12, 12);
            // We can't directly pass the partial as AAD because OpenSSL
            // appends len_block. But we CAN compute the correct GHASH:
            // For partial ending at a block boundary:
            //   pass partial as AAD, no CT → tag = GHASH(H, partial || len(partial)||0) XOR E(K,J0)
            //   So ossl_GHASH_partial = tag XOR E(J0)
            //                  = GHASH(H, partial || [len(partial)*8]_64 || [0]_64)
            //   But jp_partial = GHASH(H, partial) WITHOUT len_block
            //   
            // So these won't match for step < num_blocks (when partial doesn't include len_block yet)
            //
            // Alternative: compute jp also WITH len_block and compare
            if (step <= 2) {
                // For early steps, don't compare (len_block mismatch)
                std::printf("    (skip ossl compare — len_block mismatch)\n");
            } else if (step == num_blocks) {
                // Final step already compared above
                std::printf("    (compare in final step above)\n");
            }
            CRYPTO_gcm128_release(gcm);
        }
    }

    // 5) Direct multiplication test: jpssl gf128_mul vs OpenSSL
    //    Use the known H and specific blocks
    {
        // Extract individual blocks from the GHASH input
        auto get_block = [&](size_t idx) -> const uint8_t* {
            return gi.data() + idx * 16;
        };
        size_t nb = gi.size() / 16;

        // Compute Y[1] = X[0] * H via jpssl gf128_mul
        uint8_t Y1_mul[16];
        gf128_mul(get_block(0), H, Y1_mul);
        hexdump("X[0] * H (gf128_mul)", Y1_mul, 16);

        // Same via ghash
        uint8_t Y1_gh[16];
        ghash(H, std::vector<uint8_t>(get_block(0), get_block(0) + 16), Y1_gh);
        hexdump("X[0] * H (ghash)", Y1_gh, 16);

        bool mul_vs_gh = std::memcmp(Y1_mul, Y1_gh, 16) == 0;
        std::printf("  gf128_mul vs ghash(single): %s\n", mul_vs_gh ? "PASS" : "FAIL");

        // Compare Y[2] = (Y[1] + X[1]) * H
        uint8_t Y2_mul[16];
        {
            uint8_t tmp[16];
            for (int i = 0; i < 16; ++i) tmp[i] = Y1_mul[i] ^ get_block(1)[i];
            gf128_mul(tmp, H, Y2_mul);
        }
        hexdump("(XOR[0,1])*H (gf128_mul)", Y2_mul, 16);

        // via ghash (2 blocks)
        uint8_t Y2_gh[16];
        ghash(H, std::vector<uint8_t>(gi.data(), gi.data() + 32), Y2_gh);
        hexdump("(XOR[0,1])*H (ghash)", Y2_gh, 16);

        mul_vs_gh = std::memcmp(Y2_mul, Y2_gh, 16) == 0;
        std::printf("  gf128_mul vs ghash(2 blocks): %s\n", mul_vs_gh ? "PASS" : "FAIL");
    }

    std::printf("\n  Note: test_ghash_debug is for diagnostics only.\n");
    return 0;
}
#pragma GCC diagnostic pop
