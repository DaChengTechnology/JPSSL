/**
 * bench_cipher_suites.cpp — 密码套件吞吐量测试 & OpenSSL 对比
 *
 * 覆盖以下 11 个密码套件：
 *
 *   TLS 1.3:
 *     TLS_AES_128_GCM_SHA256          (0x1301) — AES-128-GCM + SHA-256
 *     TLS_AES_256_GCM_SHA384          (0x1302) — AES-256-GCM + SHA-384
 *     TLS_CHACHA20_POLY1305_SHA256    (0x1303) — ChaCha20-Poly1305 + SHA-256
 *     TLS_AES_128_CCM_SHA256          (0x1304) — AES-128-CCM + SHA-256
 *     TLS_AES_128_CCM_8_SHA256        (0x1305) — AES-128-CCM-8 + SHA-256
 *
 *   TLS 1.2:
 *     TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256          (0xC02B)
 *     TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384          (0xC02C)
 *     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256             (0xC02F)
 *     TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384             (0xC030)
 *     TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256       (0xCCA8)
 *     TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256     (0xCCA9)
 *
 * 对于每个套件，测试：
 *   1. 正确性（加密-解密往返 + 完整性校验）
 *   2. 吞吐量（jpssl vs OpenSSL）
 *
 * 编译：需要链接 OpenSSL (libssl + libcrypto)
 */

#include "test_utils.hpp"
#include "tls.hpp"
#include "aes.hpp"
#include "chacha20_poly1305.hpp"
#include "sha256.hpp"
#include "sha512.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <chrono>
#include <vector>
#include <cstring>
#include <iostream>
#include <cstdio>
#include <iomanip>
#include <string>
#include <map>

using namespace jpssl;
using namespace jpssl::tls;
using namespace jptest;
using namespace std::chrono;

static const size_t DATA_SIZE = 16ULL * 1024 * 1024; // 16 MB
// CCM with 12-byte nonce: max plaintext = 2^24 - 1 = 16777215 bytes
static const size_t CCM_DATA_SIZE = 16ULL * 1024 * 1024 - 1;

static double to_gbps(size_t bytes, double ms) {
    return (bytes / 1e9) / (ms / 1000.0);
}

static const char* suites_tls13_aes128_gcm[] = {
    "TLS_AES_128_GCM_SHA256 (0x1301)", nullptr
};
static const char* suites_tls13_aes256_gcm[] = {
    "TLS_AES_256_GCM_SHA384 (0x1302)", nullptr
};
static const char* suites_tls13_chacha[] = {
    "TLS_CHACHA20_POLY1305_SHA256 (0x1303)", nullptr
};
static const char* suites_tls13_ccm[] = {
    "TLS_AES_128_CCM_SHA256 (0x1304)", nullptr
};
static const char* suites_tls13_ccm8[] = {
    "TLS_AES_128_CCM_8_SHA256 (0x1305)", nullptr
};
static const char* suites_tls12_aes128_gcm[] = {
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)",
    nullptr
};
static const char* suites_tls12_aes256_gcm[] = {
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C)",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)",
    nullptr
};
static const char* suites_tls12_chacha[] = {
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9)",
    nullptr
};

static void print_suite_header(const char* title, const char** suites) {
    std::printf("\n  ── %s ──\n", title);
    for (int i = 0; suites[i]; ++i)
        std::printf("    %s\n", suites[i]);
}

// ========================================================================
//  Benchmark 1: AES-128-GCM  (TLS_AES_128_GCM_SHA256 & TLS 1.2 ECDHE_*_AES_128_GCM)
// ========================================================================

static void benchmark_aes128_gcm() {
    print_suite_header("AES-128-GCM Record Layer Encryption",
                       suites_tls13_aes128_gcm);
    std::printf("  Shared by TLS 1.2: ");
    for (int i = 0; suites_tls12_aes128_gcm[i]; ++i)
        std::printf("%s ", suites_tls12_aes128_gcm[i]);
    std::printf("\n");

    uint8_t key[16], iv[12];
    RAND_bytes(key, 16);
    RAND_bytes(iv, 12);
    std::vector<uint8_t> plain(DATA_SIZE);
    RAND_bytes(plain.data(), DATA_SIZE);

    // ── jpssl AES-128-GCM ──
    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    auto t0 = high_resolution_clock::now();
    std::vector<uint8_t> ct;
    uint8_t tag[16];
    aes_gcm_encrypt_auto(ctx, iv, 12, std::span<const uint8_t>(plain),
                         std::span<const uint8_t>(), ct, tag, 16);
    auto t1 = high_resolution_clock::now();
    double jp_enc_ms = duration<double, std::milli>(t1 - t0).count();

    t0 = high_resolution_clock::now();
    std::vector<uint8_t> pt;
    bool dec_ok = aes_gcm_decrypt_auto(ctx, iv, 12, std::span<const uint8_t>(ct),
                                       std::span<const uint8_t>(), tag, 16, pt);
    t1 = high_resolution_clock::now();
    double jp_dec_ms = duration<double, std::milli>(t1 - t0).count();

    bool correct = dec_ok && pt.size() == DATA_SIZE &&
                   memcmp(pt.data(), plain.data(), DATA_SIZE) == 0;
    TEST("jpssl AES-128-GCM round-trip correct", correct);

    // ── OpenSSL AES-128-GCM ──
    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ectx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ectx, nullptr, nullptr, key, iv);

    int out_len;
    std::vector<uint8_t> ossl_ct(DATA_SIZE + 16);
    uint8_t ossl_tag[16];

    t0 = high_resolution_clock::now();
    EVP_EncryptUpdate(ectx, ossl_ct.data(), &out_len, plain.data(), DATA_SIZE);
    EVP_EncryptFinal_ex(ectx, ossl_ct.data() + out_len, &out_len);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, ossl_tag);
    t1 = high_resolution_clock::now();
    double ossl_enc_ms = duration<double, std::milli>(t1 - t0).count();
    EVP_CIPHER_CTX_free(ectx);

    // OpenSSL decrypt
    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(dctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(dctx, nullptr, nullptr, key, iv);
    EVP_DecryptUpdate(dctx, nullptr, &out_len, nullptr, 0); // no AAD

    t0 = high_resolution_clock::now();
    std::vector<uint8_t> ossl_pt(DATA_SIZE);
    EVP_DecryptUpdate(dctx, ossl_pt.data(), &out_len, ossl_ct.data(), DATA_SIZE);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, 16, ossl_tag);
    int ret = EVP_DecryptFinal_ex(dctx, ossl_pt.data() + out_len, &out_len);
    t1 = high_resolution_clock::now();
    double ossl_dec_ms = duration<double, std::milli>(t1 - t0).count();
    EVP_CIPHER_CTX_free(dctx);

    TEST("OpenSSL AES-128-GCM decrypt OK", ret > 0);

    double jp_enc_gbps = to_gbps(DATA_SIZE, jp_enc_ms);
    double jp_dec_gbps = to_gbps(DATA_SIZE, jp_dec_ms);
    double ossl_enc_gbps = to_gbps(DATA_SIZE, ossl_enc_ms);
    double ossl_dec_gbps = to_gbps(DATA_SIZE, ossl_dec_ms);

    std::printf("  %-12s %12s %12s %12s %12s\n",
                "", "jpssl(ms)", "jpssl(GB/s)", "OpenSSL(ms)", "OpenSSL(GB/s)");
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "Encrypt", jp_enc_ms, jp_enc_gbps, ossl_enc_ms, ossl_enc_gbps);
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "Decrypt", jp_dec_ms, jp_dec_gbps, ossl_dec_ms, ossl_dec_gbps);
    if (ossl_enc_ms > 0)
        std::printf("  Encrypt ratio: %.2fx (jpssl/OpenSSL)\n",
                    ossl_enc_ms / jp_enc_ms);
    if (ossl_dec_ms > 0)
        std::printf("  Decrypt ratio: %.2fx (jpssl/OpenSSL)\n",
                    ossl_dec_ms / jp_dec_ms);
}

// ========================================================================
//  Benchmark 2: AES-256-GCM  (TLS_AES_256_GCM_SHA384 & TLS 1.2 ECDHE_*_AES_256_GCM)
// ========================================================================

static void benchmark_aes256_gcm() {
    print_suite_header("AES-256-GCM Record Layer Encryption",
                       suites_tls13_aes256_gcm);
    std::printf("  Shared by TLS 1.2: ");
    for (int i = 0; suites_tls12_aes256_gcm[i]; ++i)
        std::printf("%s ", suites_tls12_aes256_gcm[i]);
    std::printf("\n");

    uint8_t key[32], iv[12];
    RAND_bytes(key, 32);
    RAND_bytes(iv, 12);
    std::vector<uint8_t> plain(DATA_SIZE);
    RAND_bytes(plain.data(), DATA_SIZE);

    // ── jpssl AES-256-GCM ──
    aes_context ctx;
    ctx.init(std::span<const uint8_t, 32>(key, 32));

    auto t0 = high_resolution_clock::now();
    std::vector<uint8_t> ct;
    uint8_t tag[16];
    aes_gcm_encrypt_auto(ctx, iv, 12, std::span<const uint8_t>(plain),
                         std::span<const uint8_t>(), ct, tag, 16);
    auto t1 = high_resolution_clock::now();
    double jp_enc_ms = duration<double, std::milli>(t1 - t0).count();

    t0 = high_resolution_clock::now();
    std::vector<uint8_t> pt;
    bool dec_ok = aes_gcm_decrypt_auto(ctx, iv, 12, std::span<const uint8_t>(ct),
                                       std::span<const uint8_t>(), tag, 16, pt);
    t1 = high_resolution_clock::now();
    double jp_dec_ms = duration<double, std::milli>(t1 - t0).count();

    bool correct = dec_ok && pt.size() == DATA_SIZE &&
                   memcmp(pt.data(), plain.data(), DATA_SIZE) == 0;
    TEST("jpssl AES-256-GCM round-trip correct", correct);

    // ── OpenSSL AES-256-GCM ──
    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ectx, nullptr, nullptr, key, iv);

    int out_len;
    std::vector<uint8_t> ossl_ct(DATA_SIZE + 16);
    uint8_t ossl_tag[16];

    t0 = high_resolution_clock::now();
    EVP_EncryptUpdate(ectx, ossl_ct.data(), &out_len, plain.data(), DATA_SIZE);
    EVP_EncryptFinal_ex(ectx, ossl_ct.data() + out_len, &out_len);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, ossl_tag);
    t1 = high_resolution_clock::now();
    double ossl_enc_ms = duration<double, std::milli>(t1 - t0).count();
    EVP_CIPHER_CTX_free(ectx);

    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(dctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(dctx, nullptr, nullptr, key, iv);

    t0 = high_resolution_clock::now();
    std::vector<uint8_t> ossl_pt(DATA_SIZE);
    EVP_DecryptUpdate(dctx, ossl_pt.data(), &out_len, ossl_ct.data(), DATA_SIZE);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, 16, ossl_tag);
    int ret = EVP_DecryptFinal_ex(dctx, ossl_pt.data() + out_len, &out_len);
    t1 = high_resolution_clock::now();
    double ossl_dec_ms = duration<double, std::milli>(t1 - t0).count();
    EVP_CIPHER_CTX_free(dctx);

    TEST("OpenSSL AES-256-GCM decrypt OK", ret > 0);

    double jp_enc_gbps = to_gbps(DATA_SIZE, jp_enc_ms);
    double jp_dec_gbps = to_gbps(DATA_SIZE, jp_dec_ms);
    double ossl_enc_gbps = to_gbps(DATA_SIZE, ossl_enc_ms);
    double ossl_dec_gbps = to_gbps(DATA_SIZE, ossl_dec_ms);

    std::printf("  %-12s %12s %12s %12s %12s\n",
                "", "jpssl(ms)", "jpssl(GB/s)", "OpenSSL(ms)", "OpenSSL(GB/s)");
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "Encrypt", jp_enc_ms, jp_enc_gbps, ossl_enc_ms, ossl_enc_gbps);
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "Decrypt", jp_dec_ms, jp_dec_gbps, ossl_dec_ms, ossl_dec_gbps);
    if (ossl_enc_ms > 0)
        std::printf("  Encrypt ratio: %.2fx (jpssl/OpenSSL)\n",
                    ossl_enc_ms / jp_enc_ms);
    if (ossl_dec_ms > 0)
        std::printf("  Decrypt ratio: %.2fx (jpssl/OpenSSL)\n",
                    ossl_dec_ms / jp_dec_ms);
}

// ========================================================================
//  Benchmark 3: ChaCha20-Poly1305
//  (TLS_CHACHA20_POLY1305_SHA256 & TLS 1.2 ECDHE_*_CHACHA20_POLY1305)
// ========================================================================

static void benchmark_chacha20_poly1305() {
    print_suite_header("ChaCha20-Poly1305 Record Layer Encryption",
                       suites_tls13_chacha);
    std::printf("  Shared by TLS 1.2: ");
    for (int i = 0; suites_tls12_chacha[i]; ++i)
        std::printf("%s ", suites_tls12_chacha[i]);
    std::printf("\n");

    uint8_t key[32], nonce[12];
    RAND_bytes(key, 32);
    RAND_bytes(nonce, 12);
    std::vector<uint8_t> plain(DATA_SIZE);
    RAND_bytes(plain.data(), DATA_SIZE);

    // ── jpssl ChaCha20-Poly1305 ──
    auto t0 = high_resolution_clock::now();
    std::vector<uint8_t> ct;
    uint8_t tag[16];
    chacha20_poly1305_encrypt(key, nonce, std::span<const uint8_t>(plain),
                              std::span<const uint8_t>(), ct, tag);
    auto t1 = high_resolution_clock::now();
    double jp_enc_ms = duration<double, std::milli>(t1 - t0).count();

    t0 = high_resolution_clock::now();
    std::vector<uint8_t> pt;
    bool dec_ok = chacha20_poly1305_decrypt(key, nonce, std::span<const uint8_t>(ct),
                                            std::span<const uint8_t>(), tag, pt);
    t1 = high_resolution_clock::now();
    double jp_dec_ms = duration<double, std::milli>(t1 - t0).count();

    bool correct = dec_ok && pt.size() == DATA_SIZE &&
                   memcmp(pt.data(), plain.data(), DATA_SIZE) == 0;
    TEST("jpssl ChaCha20-Poly1305 round-trip correct", correct);

    // ── OpenSSL ChaCha20-Poly1305 ──
    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ectx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ectx, nullptr, nullptr, key, nonce);

    int out_len;
    std::vector<uint8_t> ossl_ct(DATA_SIZE + 16);
    uint8_t ossl_tag[16];

    t0 = high_resolution_clock::now();
    EVP_EncryptUpdate(ectx, ossl_ct.data(), &out_len, plain.data(), DATA_SIZE);
    EVP_EncryptFinal_ex(ectx, ossl_ct.data() + out_len, &out_len);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_GET_TAG, 16, ossl_tag);
    t1 = high_resolution_clock::now();
    double ossl_enc_ms = duration<double, std::milli>(t1 - t0).count();
    EVP_CIPHER_CTX_free(ectx);

    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(dctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(dctx, nullptr, nullptr, key, nonce);

    t0 = high_resolution_clock::now();
    std::vector<uint8_t> ossl_pt(DATA_SIZE);
    EVP_DecryptUpdate(dctx, ossl_pt.data(), &out_len, ossl_ct.data(), DATA_SIZE);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, ossl_tag);
    int ret = EVP_DecryptFinal_ex(dctx, ossl_pt.data() + out_len, &out_len);
    t1 = high_resolution_clock::now();
    double ossl_dec_ms = duration<double, std::milli>(t1 - t0).count();
    EVP_CIPHER_CTX_free(dctx);

    TEST("OpenSSL ChaCha20-Poly1305 decrypt OK", ret > 0);

    double jp_enc_gbps = to_gbps(DATA_SIZE, jp_enc_ms);
    double jp_dec_gbps = to_gbps(DATA_SIZE, jp_dec_ms);
    double ossl_enc_gbps = to_gbps(DATA_SIZE, ossl_enc_ms);
    double ossl_dec_gbps = to_gbps(DATA_SIZE, ossl_dec_ms);

    std::printf("  %-12s %12s %12s %12s %12s\n",
                "", "jpssl(ms)", "jpssl(GB/s)", "OpenSSL(ms)", "OpenSSL(GB/s)");
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "Encrypt", jp_enc_ms, jp_enc_gbps, ossl_enc_ms, ossl_enc_gbps);
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "Decrypt", jp_dec_ms, jp_dec_gbps, ossl_dec_ms, ossl_dec_gbps);
    if (ossl_enc_ms > 0)
        std::printf("  Encrypt ratio: %.2fx (jpssl/OpenSSL)\n",
                    ossl_enc_ms / jp_enc_ms);
    if (ossl_dec_ms > 0)
        std::printf("  Decrypt ratio: %.2fx (jpssl/OpenSSL)\n",
                    ossl_dec_ms / jp_dec_ms);
}

// ========================================================================
//  Benchmark 4: AES-128-CCM  (TLS_AES_128_CCM_SHA256)
// ========================================================================

static void benchmark_aes128_ccm() {
    print_suite_header("AES-128-CCM Record Layer Encryption (tag=16)",
                       suites_tls13_ccm);

    uint8_t key[16], nonce[12];
    RAND_bytes(key, 16);
    RAND_bytes(nonce, 12);
    std::vector<uint8_t> plain(CCM_DATA_SIZE);
    RAND_bytes(plain.data(), CCM_DATA_SIZE);

    // ── jpssl AES-128-CCM ──
    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    auto t0 = high_resolution_clock::now();
    std::vector<uint8_t> ct;
    uint8_t tag[16];
    aes_ccm_encrypt(ctx, nonce, 12, std::span<const uint8_t>(plain),
                    std::span<const uint8_t>(), ct, tag, 16);
    auto t1 = high_resolution_clock::now();
    double jp_enc_ms = duration<double, std::milli>(t1 - t0).count();

    t0 = high_resolution_clock::now();
    std::vector<uint8_t> pt;
    bool dec_ok = aes_ccm_decrypt(ctx, nonce, 12, std::span<const uint8_t>(ct),
                                  std::span<const uint8_t>(), tag, 16, pt);
    t1 = high_resolution_clock::now();
    double jp_dec_ms = duration<double, std::milli>(t1 - t0).count();

    bool correct = dec_ok && pt.size() == CCM_DATA_SIZE &&
                   memcmp(pt.data(), plain.data(), CCM_DATA_SIZE) == 0;
    TEST("jpssl AES-128-CCM round-trip correct", correct);

    // ── OpenSSL AES-128-CCM ──
    // CCM 需要先设置 tag 长度和明文长度
    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ectx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_SET_TAG, 16, nullptr);
    EVP_EncryptInit_ex(ectx, nullptr, nullptr, key, nonce);

    int out_len;
    EVP_EncryptUpdate(ectx, nullptr, &out_len, nullptr, CCM_DATA_SIZE);
    std::vector<uint8_t> ossl_ct(CCM_DATA_SIZE + 16);
    uint8_t ossl_tag[16];

    t0 = high_resolution_clock::now();
    EVP_EncryptUpdate(ectx, ossl_ct.data(), &out_len, plain.data(), CCM_DATA_SIZE);
    EVP_EncryptFinal_ex(ectx, ossl_ct.data() + out_len, &out_len);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_GET_TAG, 16, ossl_tag);
    t1 = high_resolution_clock::now();
    double ossl_enc_ms = duration<double, std::milli>(t1 - t0).count();
    EVP_CIPHER_CTX_free(ectx);

    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(dctx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, nullptr);
    EVP_DecryptInit_ex(dctx, nullptr, nullptr, key, nonce);
    EVP_DecryptUpdate(dctx, nullptr, &out_len, nullptr, CCM_DATA_SIZE);

    t0 = high_resolution_clock::now();
    std::vector<uint8_t> ossl_pt(CCM_DATA_SIZE);
    EVP_DecryptUpdate(dctx, ossl_pt.data(), &out_len, ossl_ct.data(), CCM_DATA_SIZE);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, ossl_tag);
    int ret = EVP_DecryptFinal_ex(dctx, ossl_pt.data() + out_len, &out_len);
    t1 = high_resolution_clock::now();
    double ossl_dec_ms = duration<double, std::milli>(t1 - t0).count();
    EVP_CIPHER_CTX_free(dctx);

    TEST("OpenSSL AES-128-CCM decrypt OK", ret > 0);

    double jp_enc_gbps = to_gbps(CCM_DATA_SIZE, jp_enc_ms);
    double jp_dec_gbps = to_gbps(CCM_DATA_SIZE, jp_dec_ms);
    double ossl_enc_gbps = to_gbps(CCM_DATA_SIZE, ossl_enc_ms);
    double ossl_dec_gbps = to_gbps(CCM_DATA_SIZE, ossl_dec_ms);

    std::printf("  %-12s %12s %12s %12s %12s\n",
                "", "jpssl(ms)", "jpssl(GB/s)", "OpenSSL(ms)", "OpenSSL(GB/s)");
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "Encrypt", jp_enc_ms, jp_enc_gbps, ossl_enc_ms, ossl_enc_gbps);
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "Decrypt", jp_dec_ms, jp_dec_gbps, ossl_dec_ms, ossl_dec_gbps);
    if (ossl_enc_ms > 0)
        std::printf("  Encrypt ratio: %.2fx (jpssl/OpenSSL)\n",
                    ossl_enc_ms / jp_enc_ms);
    if (ossl_dec_ms > 0)
        std::printf("  Decrypt ratio: %.2fx (jpssl/OpenSSL)\n",
                    ossl_dec_ms / jp_dec_ms);
}

// ========================================================================
//  Benchmark 5: AES-128-CCM-8  (TLS_AES_128_CCM_8_SHA256)
// ========================================================================

static void benchmark_aes128_ccm8() {
    print_suite_header("AES-128-CCM-8 Record Layer Encryption (tag=8)",
                       suites_tls13_ccm8);

    uint8_t key[16], nonce[12];
    RAND_bytes(key, 16);
    RAND_bytes(nonce, 12);
    std::vector<uint8_t> plain(CCM_DATA_SIZE);
    RAND_bytes(plain.data(), CCM_DATA_SIZE);

    // ── jpssl AES-128-CCM-8 ──
    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    auto t0 = high_resolution_clock::now();
    std::vector<uint8_t> ct;
    uint8_t tag[8];
    aes_ccm_encrypt(ctx, nonce, 12, std::span<const uint8_t>(plain),
                    std::span<const uint8_t>(), ct, tag, 8);
    auto t1 = high_resolution_clock::now();
    double jp_enc_ms = duration<double, std::milli>(t1 - t0).count();

    t0 = high_resolution_clock::now();
    std::vector<uint8_t> pt;
    bool dec_ok = aes_ccm_decrypt(ctx, nonce, 12, std::span<const uint8_t>(ct),
                                  std::span<const uint8_t>(), tag, 8, pt);
    t1 = high_resolution_clock::now();
    double jp_dec_ms = duration<double, std::milli>(t1 - t0).count();

    bool correct = dec_ok && pt.size() == CCM_DATA_SIZE &&
                   memcmp(pt.data(), plain.data(), CCM_DATA_SIZE) == 0;
    TEST("jpssl AES-128-CCM-8 round-trip correct", correct);

    // ── OpenSSL AES-128-CCM-8 ──
    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ectx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_SET_TAG, 8, nullptr);
    EVP_EncryptInit_ex(ectx, nullptr, nullptr, key, nonce);

    int out_len;
    EVP_EncryptUpdate(ectx, nullptr, &out_len, nullptr, CCM_DATA_SIZE);
    std::vector<uint8_t> ossl_ct(CCM_DATA_SIZE + 16);
    uint8_t ossl_tag[8];

    t0 = high_resolution_clock::now();
    EVP_EncryptUpdate(ectx, ossl_ct.data(), &out_len, plain.data(), CCM_DATA_SIZE);
    EVP_EncryptFinal_ex(ectx, ossl_ct.data() + out_len, &out_len);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_GET_TAG, 8, ossl_tag);
    t1 = high_resolution_clock::now();
    double ossl_enc_ms = duration<double, std::milli>(t1 - t0).count();
    EVP_CIPHER_CTX_free(ectx);

    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(dctx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 8, nullptr);
    EVP_DecryptInit_ex(dctx, nullptr, nullptr, key, nonce);
    EVP_DecryptUpdate(dctx, nullptr, &out_len, nullptr, CCM_DATA_SIZE);

    t0 = high_resolution_clock::now();
    std::vector<uint8_t> ossl_pt(CCM_DATA_SIZE);
    EVP_DecryptUpdate(dctx, ossl_pt.data(), &out_len, ossl_ct.data(), CCM_DATA_SIZE);
    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 8, ossl_tag);
    int ret = EVP_DecryptFinal_ex(dctx, ossl_pt.data() + out_len, &out_len);
    t1 = high_resolution_clock::now();
    double ossl_dec_ms = duration<double, std::milli>(t1 - t0).count();
    EVP_CIPHER_CTX_free(dctx);

    TEST("OpenSSL AES-128-CCM-8 decrypt OK", ret > 0);

    double jp_enc_gbps = to_gbps(CCM_DATA_SIZE, jp_enc_ms);
    double jp_dec_gbps = to_gbps(CCM_DATA_SIZE, jp_dec_ms);
    double ossl_enc_gbps = to_gbps(CCM_DATA_SIZE, ossl_enc_ms);
    double ossl_dec_gbps = to_gbps(CCM_DATA_SIZE, ossl_dec_ms);

    std::printf("  %-12s %12s %12s %12s %12s\n",
                "", "jpssl(ms)", "jpssl(GB/s)", "OpenSSL(ms)", "OpenSSL(GB/s)");
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "Encrypt", jp_enc_ms, jp_enc_gbps, ossl_enc_ms, ossl_enc_gbps);
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "Decrypt", jp_dec_ms, jp_dec_gbps, ossl_dec_ms, ossl_dec_gbps);
    if (ossl_enc_ms > 0)
        std::printf("  Encrypt ratio: %.2fx (jpssl/OpenSSL)\n",
                    ossl_enc_ms / jp_enc_ms);
    if (ossl_dec_ms > 0)
        std::printf("  Decrypt ratio: %.2fx (jpssl/OpenSSL)\n",
                    ossl_dec_ms / jp_dec_ms);
}

// ========================================================================
//  Benchmark 6: SHA-256 吞吐量 (用于 TLS 1.3 transcript + HKDF)
// ========================================================================

static void benchmark_sha256_throughput() {
    std::printf("\n  ── SHA-256 Hash Throughput ──\n");
    std::printf("    Used by: all TLS 1.3 suites, TLS 1.2 ECDHE_*_AES_128_GCM,\n");
    std::printf("             TLS 1.2 ECDHE_*_CHACHA20_POLY1305\n");

    std::vector<uint8_t> data(DATA_SIZE);
    RAND_bytes(data.data(), DATA_SIZE);

    // jpssl SHA-256
    uint8_t jp_hash[32];
    sha256_ctx ctx;
    auto t0 = high_resolution_clock::now();
    sha256_init(&ctx);
    sha256_update(&ctx, data.data(), data.size());
    sha256_final(&ctx, jp_hash);
    auto t1 = high_resolution_clock::now();
    double jp_ms = duration<double, std::milli>(t1 - t0).count();
    double jp_gbps = to_gbps(DATA_SIZE, jp_ms);

    // OpenSSL SHA-256
    t0 = high_resolution_clock::now();
    uint8_t ossl_hash[32];
    SHA256(data.data(), data.size(), ossl_hash);
    t1 = high_resolution_clock::now();
    double ossl_ms = duration<double, std::milli>(t1 - t0).count();
    double ossl_gbps = to_gbps(DATA_SIZE, ossl_ms);

    bool match = memcmp(jp_hash, ossl_hash, 32) == 0;
    TEST("SHA-256 jpssl matches OpenSSL", match);

    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "jpssl", jp_ms, jp_gbps, ossl_ms, ossl_gbps);
    if (ossl_ms > 0)
        std::printf("  Ratio: %.2fx (jpssl/OpenSSL)\n", ossl_ms / jp_ms);
}

// ========================================================================
//  Benchmark 7: SHA-384 吞吐量 (用于 TLS_AES_256_GCM_SHA384)
// ========================================================================

static void benchmark_sha384_throughput() {
    std::printf("\n  ── SHA-384 Hash Throughput ──\n");
    std::printf("    Used by: TLS_AES_256_GCM_SHA384,\n");
    std::printf("             TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,\n");
    std::printf("             TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n");

    std::vector<uint8_t> data(DATA_SIZE);
    RAND_bytes(data.data(), DATA_SIZE);

    // jpssl SHA-384
    uint8_t jp_hash[48];
    sha512_ctx ctx;
    auto t0 = high_resolution_clock::now();
    sha384_init(&ctx);
    sha512_update(&ctx, data.data(), data.size());
    sha512_final(&ctx, jp_hash);
    auto t1 = high_resolution_clock::now();
    double jp_ms = duration<double, std::milli>(t1 - t0).count();
    double jp_gbps = to_gbps(DATA_SIZE, jp_ms);

    // OpenSSL SHA-384
    t0 = high_resolution_clock::now();
    uint8_t ossl_hash[48];
    SHA384(data.data(), data.size(), ossl_hash);
    t1 = high_resolution_clock::now();
    double ossl_ms = duration<double, std::milli>(t1 - t0).count();
    double ossl_gbps = to_gbps(DATA_SIZE, ossl_ms);

    bool match = memcmp(jp_hash, ossl_hash, 48) == 0;
    TEST("SHA-384 jpssl matches OpenSSL", match);

    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s\n",
                "jpssl", jp_ms, jp_gbps, ossl_ms, ossl_gbps);
    if (ossl_ms > 0)
        std::printf("  Ratio: %.2fx (jpssl/OpenSSL)\n", ossl_ms / jp_ms);
}

// ========================================================================
//  入口
// ========================================================================

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::cout << "jpssl Cipher Suite Benchmark & OpenSSL Comparison\n";
    std::cout << "Data size: " << (DATA_SIZE / (1024*1024)) << " MB per test\n";

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    RUN_TEST(benchmark_aes128_gcm);
    RUN_TEST(benchmark_aes256_gcm);
    RUN_TEST(benchmark_chacha20_poly1305);
    RUN_TEST(benchmark_aes128_ccm);
    RUN_TEST(benchmark_aes128_ccm8);
    RUN_TEST(benchmark_sha256_throughput);
    RUN_TEST(benchmark_sha384_throughput);

    // ── 汇总表 ──
    std::cout << "\n\n=== Summary: Cipher Suite → AEAD Primitive Mapping ===\n";
    std::cout << "  TLS 1.3 Suites:\n";
    std::cout << "    TLS_AES_128_GCM_SHA256        → AES-128-GCM\n";
    std::cout << "    TLS_AES_256_GCM_SHA384        → AES-256-GCM\n";
    std::cout << "    TLS_CHACHA20_POLY1305_SHA256  → ChaCha20-Poly1305\n";
    std::cout << "    TLS_AES_128_CCM_SHA256        → AES-128-CCM\n";
    std::cout << "    TLS_AES_128_CCM_8_SHA256      → AES-128-CCM-8\n";
    std::cout << "  TLS 1.2 Suites:\n";
    std::cout << "    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256        → AES-128-GCM\n";
    std::cout << "    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384        → AES-256-GCM\n";
    std::cout << "    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256           → AES-128-GCM\n";
    std::cout << "    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384           → AES-256-GCM\n";
    std::cout << "    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256     → ChaCha20-Poly1305\n";
    std::cout << "    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256   → ChaCha20-Poly1305\n";
    std::cout << std::endl;

    return test_summary();
}
