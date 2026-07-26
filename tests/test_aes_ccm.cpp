#include "aes.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <span>
using namespace jpssl;

static int g_pass = 0, g_fail = 0;

#define CHECK(name, expr) do { \
    if (expr) { std::printf("  [PASS] %s\n", name); g_pass++; } \
    else { std::printf("  [FAIL] %s\n", name); g_fail++; } \
} while(0)

static bool hex_eq(const uint8_t* a, const uint8_t* b, size_t n) {
    return std::memcmp(a, b, n) == 0;
}

static void hexdump(const char* label, const uint8_t* d, size_t n) {
    std::printf("  %s: ", label);
    for (size_t i = 0; i < n; ++i) std::printf("%02x", d[i]);
    std::printf("\n");
}

// NIST SP 800-38C C.1: AES-128, nonce=12, tag=4, AAD=none, PT=empty
void test_nist_empty_pt() {
    std::printf("\n--- NIST SP 800-38C C.1 (empty plaintext) ---\n");
    uint8_t key[16] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
    };
    uint8_t nonce[12] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b
    };
    uint8_t expected_tag[4] = {0xd2,0xca,0x88,0x61};
    size_t tag_len = 4;

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    std::vector<uint8_t> ct;
    uint8_t tag[16] = {};
    aes_ccm_encrypt(ctx, nonce, 12,
                    std::span<const uint8_t>(),
                    std::span<const uint8_t>(),
                    ct, tag, tag_len);

    CHECK("Empty PT: CT is empty", ct.empty());
    CHECK("Empty PT: Tag matches expected", hex_eq(tag, expected_tag, tag_len));

    std::vector<uint8_t> pt_out;
    bool ok = aes_ccm_decrypt(ctx, nonce, 12,
                              std::span<const uint8_t>(ct.data(), ct.size()),
                              std::span<const uint8_t>(),
                              tag, tag_len, pt_out);
    CHECK("Empty PT: decrypt returns true", ok);
    CHECK("Empty PT: decrypted PT is empty", pt_out.empty());
}

// Encrypt/decrypt roundtrip with various key sizes and configurations
void test_roundtrip() {
    std::printf("\n--- Roundtrip tests ---\n");

    // AES-128, nonce=12, tag=16, with AAD
    {
        uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
        uint8_t nonce[12] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b};
        const char* pt_str = "Hello AES-CCM World! Test message.";
        const char* aad_str = "Associated data";
        size_t tag_len = 16;

        aes_context ctx;
        ctx.init(std::span<const uint8_t, 16>(key, 16));

        std::vector<uint8_t> ct;
        uint8_t tag[16];
        aes_ccm_encrypt(ctx, nonce, 12,
                        std::span<const uint8_t>((const uint8_t*)pt_str, strlen(pt_str)),
                        std::span<const uint8_t>((const uint8_t*)aad_str, strlen(aad_str)),
                        ct, tag, tag_len);

        std::vector<uint8_t> pt_out;
        bool ok = aes_ccm_decrypt(ctx, nonce, 12,
                                  std::span<const uint8_t>(ct.data(), ct.size()),
                                  std::span<const uint8_t>((const uint8_t*)aad_str, strlen(aad_str)),
                                  tag, tag_len, pt_out);
        CHECK("AES-128 roundtrip", ok && pt_out.size() == strlen(pt_str) && std::memcmp(pt_out.data(), pt_str, pt_out.size()) == 0);
    }

    // AES-256, nonce=11, tag=8, empty AAD
    {
        uint8_t key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        uint8_t nonce[11] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a};
        const char* pt_str = "AES-256 CCM test";
        size_t tag_len = 8;

        aes_context ctx;
        ctx.init(std::span<const uint8_t, 32>(key, 32));

        std::vector<uint8_t> ct;
        uint8_t tag[16];
        aes_ccm_encrypt(ctx, nonce, 11,
                        std::span<const uint8_t>((const uint8_t*)pt_str, strlen(pt_str)),
                        std::span<const uint8_t>(),
                        ct, tag, tag_len);

        std::vector<uint8_t> pt_out;
        bool ok = aes_ccm_decrypt(ctx, nonce, 11,
                                  std::span<const uint8_t>(ct.data(), ct.size()),
                                  std::span<const uint8_t>(),
                                  tag, tag_len, pt_out);
        CHECK("AES-256 roundtrip", ok && pt_out.size() == strlen(pt_str) && std::memcmp(pt_out.data(), pt_str, pt_out.size()) == 0);
    }

    // Empty plaintext
    {
        uint8_t key[16] = {0};
        uint8_t nonce[12] = {0};
        size_t tag_len = 8;

        aes_context ctx;
        ctx.init(std::span<const uint8_t, 16>(key, 16));

        std::vector<uint8_t> ct;
        uint8_t tag[16];
        aes_ccm_encrypt(ctx, nonce, 12,
                        std::span<const uint8_t>(),
                        std::span<const uint8_t>(),
                        ct, tag, tag_len);

        CHECK("Empty plaintext CT is empty", ct.empty());

        std::vector<uint8_t> pt_out;
        bool ok = aes_ccm_decrypt(ctx, nonce, 12,
                                  std::span<const uint8_t>(ct.data(), ct.size()),
                                  std::span<const uint8_t>(),
                                  tag, tag_len, pt_out);
        CHECK("Empty plaintext roundtrip", ok && pt_out.empty());
    }

    // Non-block-aligned plaintext (17 bytes)
    {
        uint8_t key[16] = {0};
        uint8_t nonce[13] = {0};
        uint8_t pt[17] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17};
        size_t tag_len = 4;

        aes_context ctx;
        ctx.init(std::span<const uint8_t, 16>(key, 16));

        std::vector<uint8_t> ct;
        uint8_t tag[16];
        aes_ccm_encrypt(ctx, nonce, 13,
                        std::span<const uint8_t>(pt, 17),
                        std::span<const uint8_t>(),
                        ct, tag, tag_len);

        CHECK("17-byte PT produces 17-byte CT", ct.size() == 17);

        std::vector<uint8_t> pt_out;
        bool ok = aes_ccm_decrypt(ctx, nonce, 13,
                                  std::span<const uint8_t>(ct.data(), ct.size()),
                                  std::span<const uint8_t>(),
                                  tag, tag_len, pt_out);
        CHECK("17-byte roundtrip", ok && pt_out.size() == 17 && std::memcmp(pt_out.data(), pt, 17) == 0);
    }
}

// Test decryption rejects tampered data
void test_tamper_detection() {
    std::printf("\n--- Tamper detection ---\n");

    uint8_t key[16] = {0};
    uint8_t nonce[12] = {0};
    const char* pt = "Tamper test message";
    const char* aad = "AAD data";
    size_t tag_len = 8;

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    std::vector<uint8_t> ct;
    uint8_t tag[16];
    aes_ccm_encrypt(ctx, nonce, 12,
                    std::span<const uint8_t>((const uint8_t*)pt, strlen(pt)),
                    std::span<const uint8_t>((const uint8_t*)aad, strlen(aad)),
                    ct, tag, tag_len);

    // Tamper ciphertext
    std::vector<uint8_t> ct2 = ct;
    ct2[0] ^= 1;
    std::vector<uint8_t> pt_out;
    bool ok = aes_ccm_decrypt(ctx, nonce, 12,
                              std::span<const uint8_t>(ct2.data(), ct2.size()),
                              std::span<const uint8_t>((const uint8_t*)aad, strlen(aad)),
                              tag, tag_len, pt_out);
    CHECK("Tampered CT rejected", !ok);

    // Tamper AAD
    std::string aad2 = aad;
    aad2[0] ^= 1;
    ok = aes_ccm_decrypt(ctx, nonce, 12,
                         std::span<const uint8_t>(ct.data(), ct.size()),
                         std::span<const uint8_t>((const uint8_t*)aad2.data(), aad2.size()),
                         tag, tag_len, pt_out);
    CHECK("Tampered AAD rejected", !ok);

    // Wrong nonce
    uint8_t nonce2[12] = {1,0,0,0,0,0,0,0,0,0,0,0};
    ok = aes_ccm_decrypt(ctx, nonce2, 12,
                         std::span<const uint8_t>(ct.data(), ct.size()),
                         std::span<const uint8_t>((const uint8_t*)aad, strlen(aad)),
                         tag, tag_len, pt_out);
    CHECK("Wrong nonce rejected", !ok);
}

// Test invalid parameters return false (not throw) on decrypt
void test_invalid_params() {
    std::printf("\n--- Invalid parameter handling ---\n");

    aes_context ctx;
    uint8_t key[16] = {0};
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    uint8_t nonce[12] = {0};
    uint8_t tag[4] = {0};
    std::vector<uint8_t> pt_out;

    bool ok = aes_ccm_decrypt(ctx, nonce, 12,
                              std::span<const uint8_t>(),
                              std::span<const uint8_t>(),
                              tag, 3, pt_out);
    CHECK("Invalid tag_len returns false", !ok);

    ok = aes_ccm_decrypt(ctx, nonce, 12,
                         std::span<const uint8_t>(),
                         std::span<const uint8_t>(),
                         tag, 5, pt_out);
    CHECK("Odd tag_len returns false", !ok);

    ok = aes_ccm_decrypt(ctx, nonce, 6,
                         std::span<const uint8_t>(),
                         std::span<const uint8_t>(),
                         tag, 4, pt_out);
    CHECK("Invalid nonce_len returns false", !ok);
}

int main() {
    std::printf("=== AES-CCM Tests ===\n");

    test_nist_empty_pt();
    test_roundtrip();
    test_tamper_detection();
    test_invalid_params();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
