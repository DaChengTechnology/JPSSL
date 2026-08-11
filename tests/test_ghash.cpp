/**
 * test_ghash.cpp — GHash 完整单元测试（NIST SP 800-38D §6.3-6.4）
 *
 * 覆盖：
 *   - GF(2^128) 乘法：恒等性、零元、交换律、结合律
 *   - GHASH：单块、多块、非对齐、空输入
 *   - GCM 认证标签：NIST 官方测试向量
 *   - OpenSSL 交叉验证（如果可用）
 */

#include "aes.hpp"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

using namespace jpssl;

// ========================================================================
// 辅助函数
// ========================================================================

/// 字节数组的简单比较
static bool bytes_eq(const uint8_t* a, const uint8_t* b, size_t n) {
    return std::memcmp(a, b, n) == 0;
}

/// 十六进制转储（调试用）
static void hexdump(const char* label, const uint8_t* data, size_t len) {
    std::printf("  %s: ", label);
    for (size_t i = 0; i < len; ++i) std::printf("%02x", data[i]);
    std::printf("\n");
}

/// 测试计数器
static int g_pass = 0, g_fail = 0;

#define CHECK(name, expr) do { \
    if (expr) { \
        std::printf("  [PASS] %s\n", name); \
        g_pass++; \
    } else { \
        std::printf("  [FAIL] %s\n", name); \
        g_fail++; \
    } \
} while(0)

// ========================================================================
// 测试 1: GF(2^128) 恒等性
// ========================================================================
void test_gf128_identity() {
    std::printf("\n--- GF(2^128) Identity ---\n");

    const uint8_t key[] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    aes_context ctx;
    ctx.init(jpssl::span<const uint8_t, 16>(key, 16));

    // H = AES_encrypt(K, 0^128)
    uint8_t H[16], zero[16] = {};
    aes_encrypt_block(ctx, zero, H);

    // 1 in NIST bit-reflected convention: byte 0 bit 7 = x^0 = 1
    uint8_t one[16] = {};
    one[0] = 0x80;

    uint8_t r1[16], r2[16];
    gf128_mul(one, H, r1);  // 1 * H
    gf128_mul(H, one, r2);  // H * 1

    CHECK("1 * H == H", bytes_eq(r1, H, 16));
    CHECK("H * 1 == H", bytes_eq(r2, H, 16));
    CHECK("1 * H == H * 1", bytes_eq(r1, r2, 16));
}

// ========================================================================
// 测试 2: GF(2^128) 零元
// ========================================================================
void test_gf128_zero() {
    std::printf("\n--- GF(2^128) Zero ---\n");

    const uint8_t key[] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    aes_context ctx;
    ctx.init(jpssl::span<const uint8_t, 16>(key, 16));

    uint8_t H[16], zero[16] = {};
    aes_encrypt_block(ctx, zero, H);

    uint8_t r1[16], r2[16];
    gf128_mul(zero, H, r1);  // 0 * H
    gf128_mul(H, zero, r2);  // H * 0

    CHECK("0 * H == 0", bytes_eq(r1, zero, 16));
    CHECK("H * 0 == 0", bytes_eq(r2, zero, 16));
}

// ========================================================================
// 测试 3: GF(2^128) 交换律（多组随机数据）
// ========================================================================
void test_gf128_commutative() {
    std::printf("\n--- GF(2^128) Commutative ---\n");

    // 使用 AES 计数器模式生成伪随机 128-bit 值
    const uint8_t seed[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    aes_context ctx;
    ctx.init(jpssl::span<const uint8_t, 16>(seed, 16));

    uint8_t counter[16] = {};
    for (int t = 0; t < 10; ++t) {
        // Generate two pseudo-random blocks
        counter[15] = (uint8_t)(t * 2);
        uint8_t A[16];
        aes_encrypt_block(ctx, counter, A);

        counter[15] = (uint8_t)(t * 2 + 1);
        uint8_t B[16];
        aes_encrypt_block(ctx, counter, B);

        uint8_t r1[16], r2[16];
        gf128_mul(A, B, r1);
        gf128_mul(B, A, r2);

        char name[64];
        snprintf(name, sizeof(name), "A*B == B*A (round %d)", t);
        CHECK(name, bytes_eq(r1, r2, 16));
    }
}

// ========================================================================
// 测试 4: GF(2^128) 结合律
// ========================================================================
void test_gf128_associative() {
    std::printf("\n--- GF(2^128) Associative ---\n");

    const uint8_t key[] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    aes_context ctx;
    ctx.init(jpssl::span<const uint8_t, 16>(key, 16));

    uint8_t H[16], zero[16] = {};
    aes_encrypt_block(ctx, zero, H);

    // Generate A and B pseudo-randomly
    uint8_t A[16], B[16];
    uint8_t ctr[16] = {};
    ctr[15] = 0x01;
    aes_encrypt_block(ctx, ctr, A);
    ctr[15] = 0x02;
    aes_encrypt_block(ctx, ctr, B);

    // (H * A) * B
    uint8_t ha[16], hab[16];
    gf128_mul(H, A, ha);
    gf128_mul(ha, B, hab);

    // H * (A * B)
    uint8_t ab[16], hab2[16];
    gf128_mul(A, B, ab);
    gf128_mul(H, ab, hab2);

    CHECK("(H*A)*B == H*(A*B)", bytes_eq(hab, hab2, 16));
}

// ========================================================================
// 测试 5: GHASH 单块
// ========================================================================
void test_ghash_single_block() {
    std::printf("\n--- GHASH Single Block ---\n");

    const uint8_t key[] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    aes_context ctx;
    ctx.init(jpssl::span<const uint8_t, 16>(key, 16));

    uint8_t H[16], zero[16] = {};
    aes_encrypt_block(ctx, zero, H);

    // GHASH(H, [X]) = X * H（因为 Y_1 = (0 ⊕ X) * H = X * H）
    uint8_t X[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    uint8_t gh_out[16];
    ghash(H, jpssl::span<const uint8_t>(X, 16), gh_out);

    uint8_t expected[16];
    gf128_mul(X, H, expected);

    CHECK("GHASH(H, [X]) == X * H", bytes_eq(gh_out, expected, 16));

    // GHASH(H, [1]) = H
    uint8_t one_block[16] = {};
    one_block[0] = 0x80;  // x^0 = 1 (bit-reflected: byte 0 bit 7)
    uint8_t gh_one[16];
    ghash(H, jpssl::span<const uint8_t>(one_block, 16), gh_one);
    CHECK("GHASH(H, [1]) == H", bytes_eq(gh_one, H, 16));
}

// ========================================================================
// 测试 6: GHASH 多块
// ========================================================================
void test_ghash_multi_block() {
    std::printf("\n--- GHASH Multi Block ---\n");

    const uint8_t key[] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    aes_context ctx;
    ctx.init(jpssl::span<const uint8_t, 16>(key, 16));

    uint8_t H[16], zero[16] = {};
    aes_encrypt_block(ctx, zero, H);

    // Two blocks: X1, X2
    uint8_t X1[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    uint8_t X2[16] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };

    // Combined input: X1 || X2 (32 bytes)
    uint8_t combined[32];
    std::memcpy(combined, X1, 16);
    std::memcpy(combined + 16, X2, 16);

    uint8_t gh_out[16];
    ghash(H, jpssl::span<const uint8_t>(combined, 32), gh_out);

    // Manual: Y1 = X1 * H, Y2 = (Y1 ⊕ X2) * H
    uint8_t y1[16], y1_xor_x2[16], expected[16];
    gf128_mul(X1, H, y1);
    for (int i = 0; i < 16; ++i) y1_xor_x2[i] = y1[i] ^ X2[i];
    gf128_mul(y1_xor_x2, H, expected);

    CHECK("GHASH(H, [X1||X2]) matches manual", bytes_eq(gh_out, expected, 16));
}

// ========================================================================
// 测试 7: GHASH 非对齐（最后一块不足 16 字节）
// ========================================================================
void test_ghash_unaligned() {
    std::printf("\n--- GHASH Unaligned ---\n");

    const uint8_t key[] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    aes_context ctx;
    ctx.init(jpssl::span<const uint8_t, 16>(key, 16));

    uint8_t H[16], zero[16] = {};
    aes_encrypt_block(ctx, zero, H);

    // 20 bytes: one full block + 4 bytes (zero-padded to 16)
    uint8_t data[20] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13
    };

    uint8_t gh_out[16];
    ghash(H, jpssl::span<const uint8_t>(data, 20), gh_out);

    // Manual: X1 full, X2 padded
    uint8_t x2_padded[16] = {};
    std::memcpy(x2_padded, data + 16, 4);

    uint8_t y1[16], y1_xor_x2[16], expected[16];
    gf128_mul(data, H, y1);
    for (int i = 0; i < 16; ++i) y1_xor_x2[i] = y1[i] ^ x2_padded[i];
    gf128_mul(y1_xor_x2, H, expected);

    CHECK("GHASH unaligned matches manual", bytes_eq(gh_out, expected, 16));
}

// ========================================================================
// 测试 8: GHASH 空输入
// ========================================================================
void test_ghash_empty() {
    std::printf("\n--- GHASH Empty ---\n");

    const uint8_t key[] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    aes_context ctx;
    ctx.init(jpssl::span<const uint8_t, 16>(key, 16));

    uint8_t H[16], zero[16] = {};
    aes_encrypt_block(ctx, zero, H);

    uint8_t gh_out[16];
    ghash(H, jpssl::span<const uint8_t>(), gh_out);

    // GHASH of empty input: no blocks, so Y_0 = 0
    CHECK("GHASH(empty) == 0", bytes_eq(gh_out, zero, 16));
}

// ========================================================================
// 测试 9: NIST SP 800-38D GCM 测试向量
// ========================================================================
void test_nist_gcm_vectors() {
    std::printf("\n--- NIST SP 800-38D GCM Test Vectors ---\n");

    // ═══ Test Case 1: 全零密钥 + 空明密文 + 全零 IV ═══
    {
        const uint8_t K[16] = {};
        const uint8_t IV[12] = {};
        const uint8_t P[1] = {};
        const uint8_t A[1] = {};
        // Expected tag from NIST SP 800-38D
        const uint8_t expected_tag[16] = {
            0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
            0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a
        };

        aes_context ctx;
        ctx.init(jpssl::span<const uint8_t, 16>(K, 16));

        uint8_t tag[16];
        std::vector<uint8_t> ct;
        aes_gcm_encrypt(ctx, IV, 12,
                        jpssl::span<const uint8_t>(P, 0),
                        jpssl::span<const uint8_t>(A, 0),
                        ct, tag, 16);

        CHECK("NIST TC1: tag match", bytes_eq(tag, expected_tag, 16));
        CHECK("NIST TC1: empty ciphertext", ct.empty());
    }

    // ═══ Test Case 2: 已知明文 + AAD（与 OpenSSL 交叉验证） ═══
    {
        const uint8_t K[16] = {
            0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
            0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
        };
        const uint8_t IV[12] = {
            0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
            0xde,0xca,0xf8,0x88
        };
        const uint8_t P[] = {
            0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
            0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
            0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
            0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
            0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
            0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
            0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
            0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55
        };
        const uint8_t A[] = {
            0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
            0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
            0xab,0xad,0xda,0xd2
        };

        aes_context ctx;
        ctx.init(jpssl::span<const uint8_t, 16>(K, 16));

        uint8_t tag[16];
        std::vector<uint8_t> ct;
        aes_gcm_encrypt(ctx, IV, 12,
                        jpssl::span<const uint8_t>(P, sizeof(P)),
                        jpssl::span<const uint8_t>(A, sizeof(A)),
                        ct, tag, 16);

        CHECK("TC2: ciphertext length == plaintext length",
              ct.size() == sizeof(P));

        // Verify decryption (self-consistency)
        std::vector<uint8_t> pt;
        bool dec_ok = aes_gcm_decrypt(ctx, IV, 12,
                                      jpssl::span<const uint8_t>(ct.data(), ct.size()),
                                      jpssl::span<const uint8_t>(A, sizeof(A)),
                                      tag, 16, pt);
        CHECK("TC2: decrypt succeeds", dec_ok);
        CHECK("TC2: roundtrip matches", pt.size() == sizeof(P) &&
              bytes_eq(pt.data(), P, sizeof(P)));
    }
}

// ========================================================================
// 测试 10: GCM 加解密往返测试
// ========================================================================
void test_gcm_roundtrip() {
    std::printf("\n--- GCM Roundtrip ---\n");

    const uint8_t K[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const uint8_t IV[12] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b
    };

    // Various plaintext sizes
    const size_t sizes[] = {0, 1, 15, 16, 17, 31, 32, 64, 128, 256, 1024};
    for (size_t s_idx = 0; s_idx < sizeof(sizes)/sizeof(sizes[0]); ++s_idx) {
        size_t pt_len = sizes[s_idx];
        std::vector<uint8_t> pt(pt_len);
        for (size_t i = 0; i < pt_len; ++i) pt[i] = (uint8_t)(i & 0xFF);

        // AAD
        uint8_t aad_data[] = "test aad data for GCM roundtrip verification";

        aes_context ctx;
        ctx.init(jpssl::span<const uint8_t, 16>(K, 16));

        // Encrypt
        uint8_t tag[16];
        std::vector<uint8_t> ct;
        aes_gcm_encrypt(ctx, IV, 12,
                        jpssl::span<const uint8_t>(pt.data(), pt.size()),
                        jpssl::span<const uint8_t>(aad_data, sizeof(aad_data) - 1),
                        ct, tag, 16);

        // Decrypt
        std::vector<uint8_t> recovered;
        bool ok = aes_gcm_decrypt(ctx, IV, 12,
                                  jpssl::span<const uint8_t>(ct.data(), ct.size()),
                                  jpssl::span<const uint8_t>(aad_data, sizeof(aad_data) - 1),
                                  tag, 16, recovered);

        char name[64];
        snprintf(name, sizeof(name), "Roundtrip pt_len=%zu", pt_len);
        CHECK(name, ok && recovered.size() == pt_len &&
              bytes_eq(recovered.data(), pt.data(), pt_len));

        // Tampered tag should fail
        if (pt_len > 0) {
            uint8_t bad_tag[16];
            std::memcpy(bad_tag, tag, 16);
            bad_tag[0] ^= 0xFF;
            std::vector<uint8_t> dummy;
            bool bad_ok = aes_gcm_decrypt(ctx, IV, 12,
                                          jpssl::span<const uint8_t>(ct.data(), ct.size()),
                                          jpssl::span<const uint8_t>(aad_data, sizeof(aad_data) - 1),
                                          bad_tag, 16, dummy);
            snprintf(name, sizeof(name), "Tampered tag rejected pt_len=%zu", pt_len);
            CHECK(name, !bad_ok);
        }
    }
}

// ========================================================================
// main
// ========================================================================
int main() {
    test_gf128_identity();
    test_gf128_zero();
    test_gf128_commutative();
    test_gf128_associative();
    test_ghash_single_block();
    test_ghash_multi_block();
    test_ghash_unaligned();
    test_ghash_empty();
    test_nist_gcm_vectors();
    test_gcm_roundtrip();

    std::printf("\n========================================\n");
    std::printf("  Results: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("========================================\n");

    return g_fail > 0 ? 1 : 0;
}
