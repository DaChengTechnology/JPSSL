#include "jptest/jptest/test_utils.hpp"
#include "sha3.hpp"
#include <openssl/evp.h>
#include <cstring>
#include <cstdio>
#include <vector>

using namespace jpssl;
using namespace jptest;

static void ossl_sha3(const uint8_t* data, size_t len,
                       uint8_t* hash, size_t hash_len, int nid) {
    (void)hash_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = nullptr;
    switch (nid) {
        case 256: md = EVP_sha3_256(); break;
        case 384: md = EVP_sha3_384(); break;
        case 512: md = EVP_sha3_512(); break;
    }
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int out_len;
    EVP_DigestFinal_ex(ctx, hash, &out_len);
    EVP_MD_CTX_free(ctx);
}

static void test_sha3_256() {
    const char* test_cases[] = {"", "Hello, world!", "The quick brown fox jumps over the lazy dog",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", nullptr};

    for (int i = 0; test_cases[i] != nullptr; ++i) {
        const char* msg = test_cases[i];
        size_t len = std::strlen(msg);

        uint8_t jp_hash[32];
        sha3_ctx ctx;
        sha3_256_init(&ctx);
        sha3_update(&ctx, (const uint8_t*)msg, len);
        sha3_final(&ctx, jp_hash);

        uint8_t ossl_hash[32];
        ossl_sha3((const uint8_t*)msg, len, ossl_hash, 32, 256);

        TEST_MSG("SHA3-256 length " + std::to_string(len),
                 std::memcmp(jp_hash, ossl_hash, 32) == 0,
                 "jpssl and OpenSSL outputs differ");
    }
}

static void test_sha3_384() {
    const char* test_cases[] = {"", "Hello, world!", "The quick brown fox jumps over the lazy dog",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", nullptr};

    for (int i = 0; test_cases[i] != nullptr; ++i) {
        const char* msg = test_cases[i];
        size_t len = std::strlen(msg);

        uint8_t jp_hash[48];
        sha3_ctx ctx;
        sha3_384_init(&ctx);
        sha3_update(&ctx, (const uint8_t*)msg, len);
        sha3_final(&ctx, jp_hash);

        uint8_t ossl_hash[48];
        ossl_sha3((const uint8_t*)msg, len, ossl_hash, 48, 384);

        TEST_MSG("SHA3-384 length " + std::to_string(len),
                 std::memcmp(jp_hash, ossl_hash, 48) == 0,
                 "jpssl and OpenSSL outputs differ");
    }
}

static void test_sha3_512() {
    const char* test_cases[] = {"", "Hello, world!", "The quick brown fox jumps over the lazy dog",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", nullptr};

    for (int i = 0; test_cases[i] != nullptr; ++i) {
        const char* msg = test_cases[i];
        size_t len = std::strlen(msg);

        uint8_t jp_hash[64];
        sha3_ctx ctx;
        sha3_512_init(&ctx);
        sha3_update(&ctx, (const uint8_t*)msg, len);
        sha3_final(&ctx, jp_hash);

        uint8_t ossl_hash[64];
        ossl_sha3((const uint8_t*)msg, len, ossl_hash, 64, 512);

        TEST_MSG("SHA3-512 length " + std::to_string(len),
                 std::memcmp(jp_hash, ossl_hash, 64) == 0,
                 "jpssl and OpenSSL outputs differ");
    }
}

static void test_sha3_multi_part() {
    const char* parts[] = {"Hello, ", "world!", nullptr};
    const char* full = "Hello, world!";

    for (int bits : {256, 384, 512}) {
        size_t hash_len = bits / 8;

        uint8_t jp_hash[64];
        sha3_ctx ctx;
        if (bits == 256) sha3_256_init(&ctx);
        else if (bits == 384) sha3_384_init(&ctx);
        else sha3_512_init(&ctx);

        for (int i = 0; parts[i] != nullptr; ++i)
            sha3_update(&ctx, (const uint8_t*)parts[i], std::strlen(parts[i]));
        sha3_final(&ctx, jp_hash);

        uint8_t ossl_hash[64];
        ossl_sha3((const uint8_t*)full, std::strlen(full), ossl_hash, hash_len, bits);

        TEST_MSG("SHA3-" + std::to_string(bits) + " multi-part",
                 std::memcmp(jp_hash, ossl_hash, hash_len) == 0,
                 "multi-part update differs from single-shot");
    }
}

static void test_sha3_large_input() {
    std::vector<uint8_t> data(100000);
    for (size_t i = 0; i < data.size(); ++i) data[i] = (uint8_t)(i & 0xFF);

    for (int bits : {256, 384, 512}) {
        size_t hash_len = bits / 8;

        uint8_t jp_hash[64];
        sha3_ctx ctx;
        if (bits == 256) sha3_256_init(&ctx);
        else if (bits == 384) sha3_384_init(&ctx);
        else sha3_512_init(&ctx);
        sha3_update(&ctx, data.data(), data.size());
        sha3_final(&ctx, jp_hash);

        uint8_t ossl_hash[64];
        ossl_sha3(data.data(), data.size(), ossl_hash, hash_len, bits);

        TEST_MSG("SHA3-" + std::to_string(bits) + " large input",
                 std::memcmp(jp_hash, ossl_hash, hash_len) == 0,
                 "100000-byte input differs from OpenSSL");
    }
}

int main() {
    std::cout << "Running SHA-3 tests" << std::endl;
    RUN_TEST(test_sha3_256);
    RUN_TEST(test_sha3_384);
    RUN_TEST(test_sha3_512);
    RUN_TEST(test_sha3_multi_part);
    RUN_TEST(test_sha3_large_input);
    return test_summary();
}
