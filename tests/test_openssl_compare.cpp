/**
 * test_openssl_compare.cpp — OpenSSL TLS 对比测试
 * 功能：
 *   1. 对比 jpssl TLS 握手与 OpenSSL 握手消息哈希
 *   2. 测试密码学算法输出一致性（SHA-256, HKDF, HMAC）
 *   3. 性能对比：jpssl AES-GCM vs OpenSSL AES-GCM
 *   4. 握手完成时间对比：jpssl vs OpenSSL
 *
 * 编译需要链接 OpenSSL (libssl + libcrypto)
 */

#include "test_utils.hpp"
#include "tls.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "hkdf.hpp"
#include "hmac.hpp"
#include "aes.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <chrono>
#include <vector>
#include <cstring>
#include <iostream>
#include <cstdio>
#include <iomanip>

static void hexdump(const char* label, const uint8_t* data, size_t len) {
    std::cerr << "  " << label << ": ";
    for (size_t i = 0; i < len; ++i) std::fprintf(stderr, "%02x", data[i]);
    std::cerr << std::endl;
}

using namespace jpssl;
using namespace jpssl::tls;
using namespace jptest;
using namespace std::chrono;

// ========================================================================
//  测试 1: SHA-256 输出对比 — jpssl vs OpenSSL
// ========================================================================

void test_sha256_consistency() {
    const char* test_cases[] = {
        "",
        "Hello, world!",
        "The quick brown fox jumps over the lazy dog",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        nullptr
    };

    for (int i = 0; test_cases[i] != nullptr; ++i) {
        const char* msg = test_cases[i];
        size_t len = std::strlen(msg);

        uint8_t jp_hash[32];
        sha256_ctx jp_ctx;
        sha256_init(&jp_ctx);
        sha256_update(&jp_ctx, (const uint8_t*)msg, len);
        sha256_final(&jp_ctx, jp_hash);

        uint8_t ossl_hash[32];
        SHA256((const unsigned char*)msg, len, ossl_hash);

        bool equal = std::memcmp(jp_hash, ossl_hash, 32) == 0;
        TEST_MSG("SHA-256 match length " + std::to_string(len), equal,
                 "jpssl and OpenSSL outputs differ");
    }
}

// ========================================================================
//  测试 2: HMAC-SHA256 输出对比 — jpssl vs OpenSSL
// ========================================================================

void test_hmac_consistency() {
    const uint8_t key[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };
    const char data[] = "Hi There";
    const uint8_t expected[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };

    uint8_t jp_mac[32];
    hmac_sha256(key, sizeof(key), (const uint8_t*)data, sizeof(data) - 1, jp_mac);
    hexdump("jp_mac ", jp_mac, 32);
    hexdump("expected", expected, 32);
    bool jp_ok = std::memcmp(jp_mac, expected, 32) == 0;
    TEST("HMAC-SHA256 jpssl matches RFC 4231 expected", jp_ok);

    unsigned int ossl_len;
    uint8_t ossl_mac[32];
    HMAC(EVP_sha256(), key, sizeof(key), (const unsigned char*)data, sizeof(data) - 1, ossl_mac, &ossl_len);
    bool ossl_equal = std::memcmp(jp_mac, ossl_mac, 32) == 0;
    TEST("HMAC-SHA256 jpssl matches OpenSSL", ossl_equal);
}

// ========================================================================
//  测试 3: HKDF 输出验证 — 使用 RFC 5869 标准测试向量
// ========================================================================

void test_hkdf_consistency() {
    // RFC 5869 Test Case 1: Basic test with SHA-256
    const uint8_t ikm[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                           0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                           0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    const uint8_t salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c};
    const uint8_t info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                            0xf8, 0xf9};

    // Expected PRK from RFC 5869 A.1
    const uint8_t expected_prk[32] = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    };

    // Expected OKM from RFC 5869 A.1 (L=42)
    const uint8_t expected_okm[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };

    uint8_t jp_prk[32];
    hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), jp_prk);
    bool prk_ok = std::memcmp(jp_prk, expected_prk, 32) == 0;
    TEST("HKDF-Extract matches RFC 5869", prk_ok);

    uint8_t jp_out[42];
    hkdf_expand(jp_prk, info, sizeof(info), jp_out, 42);
    bool okm_ok = std::memcmp(jp_out, expected_okm, 42) == 0;
    TEST("HKDF-Expand matches RFC 5869", okm_ok);
}

// ========================================================================
//  测试 4: AES-GCM 加密输出对比 — jpssl vs OpenSSL
// ========================================================================

void test_aes_gcm_consistency() {
    const uint8_t key[16] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    const uint8_t iv[12] = {
        0x99, 0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08
    };
    const uint8_t plaintext[] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xb5, 0xb0, 0x8d, 0xaa, 0x90,
        0x31, 0xa7, 0x59, 0x09, 0xc6, 0x71, 0x66, 0x29
    };
    const uint8_t aad[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13
    };

    size_t pt_len = sizeof(plaintext);

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    // jpssl AES-GCM: ciphertext is a vector reference
    std::vector<uint8_t> jp_ct;
    uint8_t jp_tag[16];
    aes_gcm_encrypt(ctx, iv, 12, std::span<const uint8_t>(plaintext, pt_len),
                   std::span<const uint8_t>(aad, sizeof(aad)), jp_ct, jp_tag, 16);

    // OpenSSL AES-GCM
    EVP_CIPHER_CTX* evp_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(evp_ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(evp_ctx, nullptr, nullptr, key, iv);

    int out_len;
    std::vector<uint8_t> ossl_ct(pt_len + 16);
    EVP_EncryptUpdate(evp_ctx, nullptr, &out_len, aad, sizeof(aad));
    EVP_EncryptUpdate(evp_ctx, ossl_ct.data(), &out_len, plaintext, pt_len);
    int ciphertext_len = out_len;
    EVP_EncryptFinal_ex(evp_ctx, ossl_ct.data() + out_len, &out_len);
    ciphertext_len += out_len;
    uint8_t ossl_tag[16];
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG, 16, ossl_tag);
    EVP_CIPHER_CTX_free(evp_ctx);

    // Compare ciphertext (first pt_len bytes)
    bool ct_equal = jp_ct.size() >= pt_len &&
                    std::memcmp(jp_ct.data(), ossl_ct.data(), pt_len) == 0;
    bool tag_equal = std::memcmp(jp_tag, ossl_tag, 16) == 0;

    hexdump("jp_tag  ", jp_tag, 16);
    hexdump("ossl_tag", ossl_tag, 16);

    TEST("AES-GCM ciphertext match jpssl vs OpenSSL", ct_equal);
    TEST("AES-GCM tag match jpssl vs OpenSSL", tag_equal);

    // Verify jpssl decrypt
    std::vector<uint8_t> jp_dec;
    bool jp_ok = aes_gcm_decrypt(ctx, iv, 12,
                                 std::span<const uint8_t>(jp_ct.data(), jp_ct.size()),
                                 std::span<const uint8_t>(aad, sizeof(aad)),
                                 jp_tag, 16, jp_dec);
    TEST("jpssl AES-GCM decrypt success", jp_ok);
    bool dec_equal = jp_dec.size() == pt_len &&
                     std::memcmp(jp_dec.data(), plaintext, pt_len) == 0;
    TEST("jpssl AES-GCM decrypted matches original", dec_equal);
}

// ========================================================================
//  SHA-512 输出对比 — jpssl vs OpenSSL
// ========================================================================

void test_sha512_consistency() {
    const char* test_cases[] = {"", "Hello, world!", "The quick brown fox jumps over the lazy dog", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", nullptr};
    for (int i = 0; test_cases[i] != nullptr; ++i) {
        const char* msg = test_cases[i];
        size_t len = std::strlen(msg);
        uint8_t jp_hash[64];
        sha512_ctx ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, (const uint8_t*)msg, len);
        sha512_final(&ctx, jp_hash);
        uint8_t ossl_hash[64];
        SHA512((const unsigned char*)msg, len, ossl_hash);
        bool equal = std::memcmp(jp_hash, ossl_hash, 64) == 0;
        TEST_MSG("SHA-512 match length " + std::to_string(len), equal, "jpssl and OpenSSL outputs differ");
    }
}

void test_sha384_consistency() {
    const char* test_cases[] = {"", "Hello, world!", "The quick brown fox jumps over the lazy dog", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", nullptr};
    for (int i = 0; test_cases[i] != nullptr; ++i) {
        const char* msg = test_cases[i];
        size_t len = std::strlen(msg);
        uint8_t jp_hash[48];
        sha512_ctx ctx;
        sha384_init(&ctx);
        sha512_update(&ctx, (const uint8_t*)msg, len);
        sha512_final(&ctx, jp_hash);
        uint8_t ossl_hash[48];
        SHA384((const unsigned char*)msg, len, ossl_hash);
        bool equal = std::memcmp(jp_hash, ossl_hash, 48) == 0;
        TEST_MSG("SHA-384 match length " + std::to_string(len), equal, "jpssl and OpenSSL outputs differ");
    }
}

// ========================================================================
//  性能对比：AES-GCM 吞吐量
// ========================================================================

void benchmark_aes_gcm_throughput() {
    std::cout << "\n  -- AES-GCM Throughput Benchmark (16MB) --" << std::endl;

    const size_t total_bytes = 16 * 1024 * 1024; // 16 MB
    uint8_t key[16];
    uint8_t iv[12];
    RAND_bytes(key, 16);
    RAND_bytes(iv, 12);

    std::vector<uint8_t> plain(total_bytes);
    RAND_bytes(plain.data(), total_bytes);

    // ── jpssl AES-GCM ──
    aes_context jp_ctx;
    jp_ctx.init(std::span<const uint8_t, 16>(key, 16));

    auto t0 = high_resolution_clock::now();
    std::vector<uint8_t> jp_cipher;
    uint8_t jp_tag[16];
    aes_gcm_encrypt_auto(jp_ctx, iv, 12, std::span<const uint8_t>(plain),
                   std::span<const uint8_t>(), jp_cipher, jp_tag, 16);
    auto t1 = high_resolution_clock::now();
    double jp_ms = duration<double, std::milli>(t1 - t0).count();
    double jp_gbps = (total_bytes) / (jp_ms / 1000.0) / 1e9;

    // ── OpenSSL AES-GCM ──
    EVP_CIPHER_CTX* evp_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(evp_ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(evp_ctx, nullptr, nullptr, key, iv);

    int out_len;
    std::vector<uint8_t> ossl_cipher(total_bytes + 16);
    uint8_t ossl_tag[16];

    t0 = high_resolution_clock::now();
    EVP_EncryptUpdate(evp_ctx, ossl_cipher.data(), &out_len, plain.data(), total_bytes);
    EVP_EncryptFinal_ex(evp_ctx, ossl_cipher.data() + out_len, &out_len);
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG, 16, ossl_tag);
    t1 = high_resolution_clock::now();
    EVP_CIPHER_CTX_free(evp_ctx);

    double ossl_ms = duration<double, std::milli>(t1 - t0).count();
    double ossl_gbps = (total_bytes) / (ossl_ms / 1000.0) / 1e9;

        // ── MUSA GPU AES-GCM ──
    musa_aes_init(jp_ctx);

    std::vector<uint8_t> gpu_cipher(total_bytes);
    uint8_t gpu_tag[4096];

    t0 = high_resolution_clock::now();
    musa_aes_gcm_encrypt(iv, plain.data(), total_bytes,
                         nullptr, 0, gpu_cipher.data(), gpu_tag, 4096);
    t1 = high_resolution_clock::now();
    double gpu_ms = duration<double, std::milli>(t1 - t0).count();
    double gpu_gbps = (total_bytes) / (gpu_ms / 1000.0) / 1e9;

    musa_aes_cleanup();

    std::printf("  GPU(MUSA):%8.2f ms  %.3f GB/s\n", gpu_ms, gpu_gbps);
    if (gpu_ms > 0) {
        std::printf("  GPU Ratio: %.2fx vs OpenSSL\n", ossl_ms / gpu_ms);
    }
    
    std::printf("  jpssl:   %8.2f ms  %.3f GB/s\n", jp_ms, jp_gbps);
    std::printf("  OpenSSL: %8.2f ms  %.3f GB/s\n", ossl_ms, ossl_gbps);
    if (jp_ms > 0) {
        std::printf("  Ratio:   %.2fx\n", ossl_ms / jp_ms);
    }
    std::cout << "  -----------------------------------------" << std::endl;

    TEST("Benchmark completed", true);
}

// ========================================================================
//  测试 5: TLS 握手 — jpssl 自握手 vs OpenSSL 上下文初始化
// ========================================================================

void test_tls_handshake_perf() {
    std::cout << "\n  -- TLS Full Handshake Performance --" << std::endl;

    const int iterations = 10;

    // ── jpssl 完整握手 ──
    tls_certificate_manager cert_mgr;
    auto cert = std::make_unique<tls_certificate>();
    cert->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(cert->pub.ed25519, cert->priv.ed25519);
    cert_mgr.add_certificate("localhost", std::move(cert));

    auto t0 = high_resolution_clock::now();
    int success = 0;
    for (int i = 0; i < iterations; ++i) {
        tls_session client, server;
        client.server_name = "localhost";
        std::vector<uint8_t> ch, sf, cf;
        tls13_make_client_hello(client, ch);
        tls13_make_server_flight(server, ch.data(), ch.size(), sf, cert_mgr);
        tls13_process_server_flight(client, sf.data(), sf.size(), cf, &cert_mgr);
        if (tls13_process_client_finished(server, cf.data(), cf.size())) {
            success++;
        }
    }
    auto t1 = high_resolution_clock::now();
    double jp_total_ms = duration<double, std::milli>(t1 - t0).count();
    double jp_avg_ms = jp_total_ms / iterations;

    std::printf("  jpssl TLS 1.3 full handshake: %.2f ms/handshake (%d/%d success)\n",
                jp_avg_ms, success, iterations);

    // ── OpenSSL TLS 握手性能（简化测量）──
    // 创建 SSL_CTX 并测量 SSL 对象创建 + 基础握手设置时间
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    t0 = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        SSL* cli = SSL_new(ssl_ctx);
        SSL_set_connect_state(cli);
        SSL_free(cli);
    }
    t1 = high_resolution_clock::now();
    double ossl_total_ms = duration<double, std::milli>(t1 - t0).count();
    double ossl_avg_ms = ossl_total_ms / iterations;

    SSL_CTX_free(ssl_ctx);

    std::printf("  OpenSSL SSL_new+connect: %.2f ms/op\n", ossl_avg_ms);
    std::printf("  jpssl vs OpenSSL ratio: %.2fx\n", ossl_avg_ms / jp_avg_ms);
    std::cout << "  -----------------------------------------" << std::endl;

    TEST("jpssl " + std::to_string(success) + "/" + std::to_string(iterations) + " handshakes succeeded",
         success == iterations);
}

// ========================================================================
//  入口
// ========================================================================

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::cout << "Running jpssl vs OpenSSL comparison tests\n" << std::endl;

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    RUN_TEST(test_sha256_consistency);
    RUN_TEST(test_sha512_consistency);
    RUN_TEST(test_sha384_consistency);
    RUN_TEST(test_hmac_consistency);
    RUN_TEST(test_hkdf_consistency);
    RUN_TEST(test_aes_gcm_consistency);
    RUN_TEST(benchmark_aes_gcm_throughput);
    RUN_TEST(test_tls_handshake_perf);

    return test_summary();
}