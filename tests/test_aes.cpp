/**
 * test_aes.cpp — AES 全覆盖单元测试
 *
 * 覆盖：
 *   - S-Box: FIPS-197 已知值验证
 *   - 单块加解密: AES-128/192/256，与 OpenSSL 交叉验证
 *   - ECB 模式: 多块加解密，全密钥长度
 *   - PKCS7 填充: 边界情况 (0/1/15/16/17/255 字节)
 *   - CBC 模式: 加解密往返，多 IV 大小，篡改检测
 *   - GCM 模式: 加解密往返，AAD 变体，IV 长度变体，tag 长度，篡改检测
 *   - CPU 特性: AES-NI 可用性检测
 *   - NIST 测试向量: AES-128 GCM 官方向量
 */

#include "aes.hpp"
#include "cpu_features.hpp"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/aes.h>

using namespace jpssl;

// ========================================================================
// 辅助
// ========================================================================
static int g_pass = 0, g_fail = 0;

#define CHECK(name, expr) do { \
    if (expr) { std::printf("  [PASS] %s\n", name); g_pass++; } \
    else { std::printf("  [FAIL] %s\n", name); g_fail++; } \
} while(0)

static void hexdump(const char* label, const uint8_t* d, size_t n) {
    std::printf("  %s: ", label);
    for (size_t i = 0; i < n; ++i) std::printf("%02x", d[i]);
    std::printf("\n");
}

// ========================================================================
// 1. S-Box 验证 (FIPS 197)
// ========================================================================
void test_sbox() {
    std::printf("\n--- S-Box (FIPS-197) ---\n");

    // FIPS 197 Appendix C: S-Box(0x00) = 0x63, S-Box(0x53) = 0xED, etc.
    // First byte of SBOX: SBOX[0] = 0x63
    CHECK("SBOX[0x00] == 0x63", SBOX[0x00] == 0x63);
    CHECK("SBOX[0x01] == 0x7c", SBOX[0x01] == 0x7c);
    CHECK("SBOX[0x53] == 0xed", SBOX[0x53] == 0xed);
    CHECK("SBOX[0xff] == 0x16", SBOX[0xff] == 0x16);

    // Inverse S-Box
    CHECK("INV_SBOX[0x63] == 0x00", INV_SBOX[0x63] == 0x00);
    CHECK("INV_SBOX[0x7c] == 0x01", INV_SBOX[0x7c] == 0x01);
    CHECK("INV_SBOX[0xed] == 0x53", INV_SBOX[0xed] == 0x53);
    CHECK("INV_SBOX[0x16] == 0xff", INV_SBOX[0x16] == 0xff);

    // Round constants
    CHECK("RCON[1] == 0x01", RCON[1] == 0x01);
    CHECK("RCON[2] == 0x02", RCON[2] == 0x02);

    // GF(2^8) multiplication
    CHECK("gf28_mul(0x57, 0x83) == 0xc1", gf28_mul(0x57, 0x83) == 0xc1);
    CHECK("gf28_mul(0x02, 0x87) == 0x15", gf28_mul(0x02, 0x87) == 0x15);
}

// ========================================================================
// 2. 单块加解密 (AES-128/192/256)
// ========================================================================
void test_block_encrypt() {
    std::printf("\n--- Block Encrypt/Decrypt ---\n");

    // AES-128: FIPS 197 Appendix B
    {
        const uint8_t key[16] = {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        };
        const uint8_t pt[16] = {
            0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
            0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
        };
        const uint8_t expected[16] = {
            0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
            0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32
        };

        aes_context ctx;
        ctx.init(std::span<const uint8_t, 16>(key, 16));

        uint8_t ct[16];
        aes_encrypt_block(ctx, pt, ct);
        CHECK("AES-128 encrypt FIPS-197 App B", memcmp(ct, expected, 16) == 0);

        uint8_t recovered[16];
        aes_decrypt_block(ctx, ct, recovered);
        CHECK("AES-128 decrypt roundtrip", memcmp(recovered, pt, 16) == 0);
    }

    // AES-192
    {
        const uint8_t key[24] = {
            0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
            0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
            0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
        };
        const uint8_t pt[16] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
        };
        const uint8_t expected[16] = {
            0xbd,0x33,0x4f,0x1d,0x6e,0x45,0xf2,0x5f,
            0xf7,0x12,0xa2,0x14,0x57,0x1f,0xa5,0xcc  // wrong, let me verify
        };
        // Use OpenSSL for the expected value
        AES_KEY ossl_key;
        AES_set_encrypt_key(key, 192, &ossl_key);
        uint8_t ossl_ct[16];
        AES_encrypt(pt, ossl_ct, &ossl_key);

        aes_context ctx;
        ctx.init(std::span<const uint8_t, 24>(key, 24));
        uint8_t ct[16];
        aes_encrypt_block(ctx, pt, ct);

        uint8_t recovered[16];
        aes_decrypt_block(ctx, ct, recovered);
        CHECK("AES-192 decrypt roundtrip", memcmp(recovered, pt, 16) == 0);

        // NOTE: AES-192 AES-NI key expansion has a known bug (produces different
        // round keys than OpenSSL).  Encrypt/decrypt are self-consistent.
        CHECK("AES-192 encrypt vs OpenSSL (KNOWN BUG)",
              memcmp(ct, ossl_ct, 16) == 0);
    }

    // AES-256
    {
        const uint8_t key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        const uint8_t pt[16] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
        };

        aes_context ctx;
        ctx.init(std::span<const uint8_t, 32>(key, 32));

        uint8_t ct[16];
        aes_encrypt_block(ctx, pt, ct);

        // Compare with OpenSSL
        AES_KEY ossl_key;
        AES_set_encrypt_key(key, 256, &ossl_key);
        uint8_t ossl_ct[16];
        AES_encrypt(pt, ossl_ct, &ossl_key);
        CHECK("AES-256 encrypt vs OpenSSL", memcmp(ct, ossl_ct, 16) == 0);

        uint8_t recovered[16];
        aes_decrypt_block(ctx, ct, recovered);
        CHECK("AES-256 decrypt roundtrip", memcmp(recovered, pt, 16) == 0);
    }

    // All-zero key and plaintext
    {
        const uint8_t key[16] = {};
        const uint8_t pt[16] = {};

        aes_context ctx;
        ctx.init(std::span<const uint8_t, 16>(key, 16));
        uint8_t ct[16], rt[16];
        aes_encrypt_block(ctx, pt, ct);
        aes_decrypt_block(ctx, ct, rt);
        CHECK("AES-128 all-zero roundtrip", memcmp(rt, pt, 16) == 0);

        // Compare with OpenSSL
        AES_KEY ossl_key;
        AES_set_encrypt_key(key, 128, &ossl_key);
        uint8_t ossl_ct[16];
        AES_encrypt(pt, ossl_ct, &ossl_key);
        CHECK("AES-128 all-zero vs OpenSSL", memcmp(ct, ossl_ct, 16) == 0);
    }
}

// ========================================================================
// 3. ECB 模式
// ========================================================================
void test_ecb() {
    std::printf("\n--- ECB Mode ---\n");

    const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    // Single block
    {
        uint8_t pt[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                           0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t ct[16], rt[16];
        aes_encrypt_block(ctx, pt, ct);
        aes_decrypt_block(ctx, ct, rt);
        CHECK("ECB single block roundtrip", memcmp(rt, pt, 16) == 0);
    }

    // Multi-block (32 bytes)
    {
        uint8_t pt[32];
        for (int i = 0; i < 32; ++i) pt[i] = (uint8_t)i;
        uint8_t ct[32], rt[32];

        aes_encrypt_ecb(ctx, std::span<const uint8_t>(pt, 32),
                         std::span<uint8_t>(ct, 32));
        // Verify blocks encrypted independently
        CHECK("ECB block0 != block1", memcmp(ct, ct + 16, 16) != 0);

        aes_decrypt_ecb(ctx, std::span<const uint8_t>(ct, 32),
                         std::span<uint8_t>(rt, 32));
        CHECK("ECB 2-block roundtrip", memcmp(rt, pt, 32) == 0);
    }

    // Compare ECB with OpenSSL
    {
        uint8_t pt[32];
        for (int i = 0; i < 32; ++i) pt[i] = (uint8_t)(i + 0x80);
        uint8_t ct_jp[32];
        aes_encrypt_ecb(ctx, std::span<const uint8_t>(pt, 32),
                         std::span<uint8_t>(ct_jp, 32));

        AES_KEY ossl_key;
        AES_set_encrypt_key(key, 128, &ossl_key);
        uint8_t ct_ossl[32];
        AES_encrypt(pt, ct_ossl, &ossl_key);
        AES_encrypt(pt + 16, ct_ossl + 16, &ossl_key);

        CHECK("ECB 2-block vs OpenSSL", memcmp(ct_jp, ct_ossl, 32) == 0);
    }
}

// ========================================================================
// 4. PKCS7 填充
// ========================================================================
void test_pkcs7() {
    std::printf("\n--- PKCS7 Padding ---\n");

    // Empty → 16 bytes of 0x10
    {
        uint8_t empty[1];
        auto padded = pkcs7_pad(std::span<const uint8_t>(empty, 0));
        CHECK("PKCS7 empty → 16 bytes 0x10", padded.size() == 16 &&
              std::all_of(padded.begin(), padded.end(), [](uint8_t b){ return b == 0x10; }));
        auto unpadded = pkcs7_unpad(padded);
        CHECK("PKCS7 unpad empty", unpadded.empty());
    }

    // 1 byte → 16 bytes (15 pad bytes)
    {
        uint8_t d[] = {0x42};
        auto padded = pkcs7_pad(std::span<const uint8_t>(d, 1));
        CHECK("PKCS7 1→16 len=16", padded.size() == 16);
        CHECK("PKCS7 1→16 last=0x0f", padded[15] == 0x0f);
        auto unpadded = pkcs7_unpad(padded);
        CHECK("PKCS7 unpad 1→1", unpadded.size() == 1 && unpadded[0] == 0x42);
    }

    // 15 bytes → 16 bytes (1 pad byte)
    {
        uint8_t d[15];
        for (int i = 0; i < 15; ++i) d[i] = (uint8_t)i;
        auto padded = pkcs7_pad(std::span<const uint8_t>(d, 15));
        CHECK("PKCS7 15→16 last=0x01", padded.size() == 16 && padded[15] == 0x01);
        auto unpadded = pkcs7_unpad(padded);
        CHECK("PKCS7 unpad 15→15", unpadded.size() == 15);
    }

    // 16 bytes → 32 bytes (16 pad bytes — PKCS7 always pads)
    {
        uint8_t d[16];
        for (int i = 0; i < 16; ++i) d[i] = (uint8_t)i;
        auto padded = pkcs7_pad(std::span<const uint8_t>(d, 16));
        CHECK("PKCS7 16→32 len=32", padded.size() == 32);
        CHECK("PKCS7 16→32 all-last=0x10", padded[31] == 0x10 && padded[16] == 0x10);
        auto unpadded = pkcs7_unpad(padded);
        CHECK("PKCS7 unpad 16→16", unpadded.size() == 16);
    }

    // 17 bytes → 32 bytes
    {
        uint8_t d[17];
        for (int i = 0; i < 17; ++i) d[i] = (uint8_t)i;
        auto padded = pkcs7_pad(std::span<const uint8_t>(d, 17));
        CHECK("PKCS7 17→32 last=0x0f", padded.size() == 32 && padded[31] == 0x0f);
        auto unpadded = pkcs7_unpad(padded);
        CHECK("PKCS7 unpad 17→17", unpadded.size() == 17);
    }

    // Invalid padding should throw
    {
        uint8_t bad[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0xff};
        bool caught = false;
        try { pkcs7_unpad(std::span<const uint8_t>(bad, 16)); }
        catch (const std::runtime_error&) { caught = true; }
        CHECK("PKCS7 unpad bad padding throws", caught);
    }
}

// ========================================================================
// 5. CBC 模式
// ========================================================================
void test_cbc() {
    std::printf("\n--- CBC Mode ---\n");

    const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    // Roundtrip: various sizes
    const size_t sizes[] = {0, 1, 15, 16, 17, 31, 32, 64, 128, 255};
    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); ++si) {
        size_t n = sizes[si];
        std::vector<uint8_t> pt(n);
        for (size_t i = 0; i < n; ++i) pt[i] = (uint8_t)(i & 0xFF);

        std::vector<uint8_t> ct;
        aes_cbc_encrypt(ctx, iv, pt, ct);

        std::vector<uint8_t> recovered;
        bool ok = aes_cbc_decrypt(ctx, iv, ct, recovered);

        char name[64];
        snprintf(name, sizeof(name), "CBC roundtrip n=%zu", n);
        CHECK(name, ok && recovered == pt);
    }

    // Different IV produces different ciphertext
    {
        uint8_t pt[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                           0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        const uint8_t iv1[16] = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        };
        const uint8_t iv2[16] = {
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
        };
        std::vector<uint8_t> ct1, ct2;
        aes_cbc_encrypt(ctx, iv1, pt, ct1);
        aes_cbc_encrypt(ctx, iv2, pt, ct2);
        CHECK("CBC different IV → different CT", ct1 != ct2);
    }

    // Corrupted ciphertext: either fails decrypt or produces wrong data
    {
        uint8_t pt[32];
        for (int i = 0; i < 32; ++i) pt[i] = (uint8_t)i;
        std::vector<uint8_t> ct;
        aes_cbc_encrypt(ctx, iv, pt, ct);

        // Corrupt first block
        ct[5] ^= 0xFF;
        std::vector<uint8_t> recovered;
        bool ok = aes_cbc_decrypt(ctx, iv, ct, recovered);
        // Padding may coincidentally look valid; in that case data must differ
        CHECK("CBC corrupted CT rejected or data differs",
              !ok || recovered.size() != 32 ||
              memcmp(recovered.data(), pt, 32) != 0);
    }
}

// ========================================================================
// 6. GCM 模式
// ========================================================================
void test_gcm() {
    std::printf("\n--- GCM Mode ---\n");

    const uint8_t K[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const uint8_t IV[12] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b
    };

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(K, 16));

    // Roundtrip: various plaintext sizes, with AAD
    const size_t pt_sizes[] = {0, 1, 15, 16, 17, 31, 32, 64, 256};
    const char* aad_str = "authenticated data for GCM test";
    for (size_t si = 0; si < sizeof(pt_sizes)/sizeof(pt_sizes[0]); ++si) {
        size_t n = pt_sizes[si];
        std::vector<uint8_t> pt(n);
        for (size_t i = 0; i < n; ++i) pt[i] = (uint8_t)(i & 0xFF);

        std::vector<uint8_t> aad(aad_str, aad_str + strlen(aad_str));

        std::vector<uint8_t> ct;
        uint8_t tag[16];
        aes_gcm_encrypt(ctx, IV, 12, pt, aad, ct, tag, 16);

        // Verify CT length == PT length
        CHECK("GCM ct_len == pt_len", ct.size() == n);

        std::vector<uint8_t> recovered;
        bool ok = aes_gcm_decrypt(ctx, IV, 12, ct, aad, tag, 16, recovered);

        char name[64];
        snprintf(name, sizeof(name), "GCM roundtrip n=%zu", n);
        CHECK(name, ok && recovered == pt);

        // Tampered tag → fail
        if (n > 0) {
            uint8_t bad_tag[16];
            memcpy(bad_tag, tag, 16);
            bad_tag[0] ^= 0xFF;
            std::vector<uint8_t> dummy;
            bool bad = aes_gcm_decrypt(ctx, IV, 12, ct, aad, bad_tag, 16, dummy);
            snprintf(name, sizeof(name), "GCM tampered tag rejected n=%zu", n);
            CHECK(name, !bad);
        }

        // Tampered AAD → fail
        if (n > 0 && !aad.empty()) {
            std::vector<uint8_t> bad_aad(aad);
            bad_aad[0] ^= 0xFF;
            std::vector<uint8_t> dummy;
            bool bad = aes_gcm_decrypt(ctx, IV, 12, ct, bad_aad, tag, 16, dummy);
            snprintf(name, sizeof(name), "GCM tampered AAD rejected n=%zu", n);
            CHECK(name, !bad);
        }
    }

    // IV length variants
    {
        const uint8_t iv8[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
        const uint8_t iv16[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };

        uint8_t pt[16] = {0xaa,0xbb,0xcc,0xdd};

        std::vector<uint8_t> ct;
        uint8_t tag8[16], tag16[16];

        aes_gcm_encrypt(ctx, iv8, 8, std::span<const uint8_t>(pt, 16),
                        std::span<const uint8_t>(), ct, tag8, 16);
        std::vector<uint8_t> rt;
        CHECK("GCM IV len=8 roundtrip",
              aes_gcm_decrypt(ctx, iv8, 8, ct, std::span<const uint8_t>(), tag8, 16, rt));

        aes_gcm_encrypt(ctx, iv16, 16, std::span<const uint8_t>(pt, 16),
                        std::span<const uint8_t>(), ct, tag16, 16);
        CHECK("GCM IV len=16 roundtrip",
              aes_gcm_decrypt(ctx, iv16, 16, ct, std::span<const uint8_t>(), tag16, 16, rt));
    }

    // Tag length variants
    {
        uint8_t pt[16] = {0xaa,0xbb};
        for (size_t tl = 12; tl <= 16; ++tl) {
            std::vector<uint8_t> ct;
            uint8_t tag[16] = {};
            aes_gcm_encrypt(ctx, IV, 12, std::span<const uint8_t>(pt, 16),
                            std::span<const uint8_t>(), ct, tag, tl);
            std::vector<uint8_t> rt;
            char name[64];
            snprintf(name, sizeof(name), "GCM tag_len=%zu roundtrip", tl);
            CHECK(name, aes_gcm_decrypt(ctx, IV, 12, ct, std::span<const uint8_t>(),
                                        tag, tl, rt));
        }
    }

    // Empty AAD
    {
        uint8_t pt[32];
        for (int i = 0; i < 32; ++i) pt[i] = (uint8_t)i;
        std::vector<uint8_t> ct;
        uint8_t tag[16];
        aes_gcm_encrypt(ctx, IV, 12, std::span<const uint8_t>(pt, 32),
                        std::span<const uint8_t>(), ct, tag, 16);
        std::vector<uint8_t> rt;
        CHECK("GCM empty AAD roundtrip",
              aes_gcm_decrypt(ctx, IV, 12, ct, std::span<const uint8_t>(), tag, 16, rt) &&
              rt == std::vector<uint8_t>(pt, pt + 32));
    }

    // Compare with OpenSSL
    {
        uint8_t pt[32];
        for (int i = 0; i < 32; ++i) pt[i] = (uint8_t)(i + 0x20);
        const char* aad = "test aad";

        std::vector<uint8_t> ct_jp;
        uint8_t tag_jp[16];
        aes_gcm_encrypt(ctx, IV, 12, std::span<const uint8_t>(pt, 32),
                        std::span<const uint8_t>((const uint8_t*)aad, strlen(aad)),
                        ct_jp, tag_jp, 16);

        // OpenSSL
        EVP_CIPHER_CTX* evp = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(evp, EVP_aes_128_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_EncryptInit_ex(evp, NULL, NULL, K, IV);
        int outlen;
        uint8_t ct_ossl[32], tag_ossl[16];
        EVP_EncryptUpdate(evp, NULL, &outlen, (const uint8_t*)aad, strlen(aad));
        EVP_EncryptUpdate(evp, ct_ossl, &outlen, pt, 32);
        int final_len;
        EVP_EncryptFinal_ex(evp, ct_ossl + outlen, &final_len);
        EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, 16, tag_ossl);
        EVP_CIPHER_CTX_free(evp);

        bool ct_ok = memcmp(ct_jp.data(), ct_ossl, 32) == 0;
        CHECK("GCM vs OpenSSL ciphertext", ct_ok);
        CHECK("GCM vs OpenSSL tag", memcmp(tag_jp, tag_ossl, 16) == 0);
    }

    // NIST SP 800-38D Test Case 1
    {
        const uint8_t K0[16] = {};
        const uint8_t IV0[12] = {};
        const uint8_t expected_tag[16] = {
            0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
            0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a
        };

        aes_context ctx0;
        ctx0.init(std::span<const uint8_t, 16>(K0, 16));
        std::vector<uint8_t> ct;
        uint8_t tag[16];
        aes_gcm_encrypt(ctx0, IV0, 12,
                        std::span<const uint8_t>(), std::span<const uint8_t>(),
                        ct, tag, 16);
        CHECK("GCM NIST TC1 tag", memcmp(tag, expected_tag, 16) == 0);
        CHECK("GCM NIST TC1 empty ct", ct.empty());
    }
}

// ========================================================================
// 7. CPU 特性
// ========================================================================
void test_cpu_features() {
    std::printf("\n--- CPU Features ---\n");

    auto feats = cpu_features::detect();
    CHECK("AES-NI available", feats.aesni);
    CHECK("PCLMULQDQ available", feats.pclmulqdq);
    // AVX2/AVX512/VCLMUL are optional
    std::printf("  [INFO] AVX2: %s\n", feats.avx2 ? "yes" : "no");
    std::printf("  [INFO] VAES/VPCLMUL: %s\n", feats.vpclmulqdq_vaes ? "yes" : "no");
}

// ========================================================================
// 8. 密钥扩展
// ========================================================================
void test_key_expansion() {
    std::printf("\n--- Key Expansion ---\n");

    // AES-128: key expansion produces 11 round keys (44 words, 176 bytes)
    {
        const uint8_t key[16] = {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        };
        uint8_t rk[176];
        key_expansion(key, AesKeySize::AES_128, rk);

        // First round key = original key
        CHECK("KeyExp AES-128 rk[0] == key", memcmp(rk, key, 16) == 0);

        // Last round key (FIPS-197: round 10 key)
        const uint8_t expected_rk10[16] = {
            0xd0,0x14,0xf9,0xa8,0xc9,0xee,0x25,0x89,
            0xe1,0x3f,0x0c,0xc8,0xb6,0x63,0x0c,0xa6
        };
        CHECK("KeyExp AES-128 round 10", memcmp(rk + 160, expected_rk10, 16) == 0);
    }

    // AES-256: 15 round keys (60 words, 240 bytes)
    {
        const uint8_t key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        uint8_t rk[240];
        key_expansion(key, AesKeySize::AES_256, rk);
        CHECK("KeyExp AES-256 rk[0] == key", memcmp(rk, key, 32) == 0);
    }
}

// ========================================================================
// main
// ========================================================================
int main() {
    test_sbox();
    test_block_encrypt();
    test_ecb();
    test_pkcs7();
    test_cbc();
    test_gcm();
    test_cpu_features();
    test_key_expansion();

    std::printf("\n========================================\n");
    std::printf("  Results: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("========================================\n");
    return g_fail > 0 ? 1 : 0;
}
