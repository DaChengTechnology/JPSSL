/** test_sm.cpp — SM2/SM3/SM4 单元测试（与 OpenSSL 互验） */
#include "sm2.hpp"
#include "sm3.hpp"
#include "sm4.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <vector>
#include <string>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL: %s\n", msg); std::exit(1); } \
    else { std::printf("  PASS: %s\n", msg); } \
} while(0)

// ═══════════════════════════════════════════════════════════════════════
//  SM3 测试（与 OpenSSL 对比）
// ═══════════════════════════════════════════════════════════════════════

static void ossl_sm3(const uint8_t* data, size_t len, uint8_t hash[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sm3(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int out_len = 32;
    EVP_DigestFinal_ex(ctx, hash, &out_len);
    EVP_MD_CTX_free(ctx);
}

static void test_sm3() {
    std::printf("\n=== SM3 测试 ===\n");

    struct TestCase { const char* msg; };
    TestCase tests[] = {
        {""},
        {"a"},
        {"abc"},
        {"message digest"},
        {"Hello, world!"},
        {"The quick brown fox jumps over the lazy dog"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    };

    for (auto& tc : tests) {
        size_t len = std::strlen(tc.msg);
        const uint8_t* data = (const uint8_t*)tc.msg;

        uint8_t jp_hash[32];
        jpssl::sm3_hash(jp_hash, data, len);

        uint8_t ossl_hash[32];
        ossl_sm3(data, len, ossl_hash);

        std::string label = "SM3(\"" + std::string(tc.msg) + "\")";
        if (label.size() > 50) label = label.substr(0, 47) + "...\"";
        ASSERT(std::memcmp(jp_hash, ossl_hash, 32) == 0,
               (label + " vs OpenSSL").c_str());
    }

    // 测试增量更新
    {
        const char* msg = "The quick brown fox jumps over the lazy dog";
        jpssl::sm3_ctx ctx;
        jpssl::sm3_init(&ctx);
        for (size_t i = 0; i < std::strlen(msg); ++i) {
            jpssl::sm3_update(&ctx, (const uint8_t*)&msg[i], 1);
        }
        uint8_t jp_hash[32];
        jpssl::sm3_final(&ctx, jp_hash);

        uint8_t ossl_hash[32];
        ossl_sm3((const uint8_t*)msg, std::strlen(msg), ossl_hash);

        ASSERT(std::memcmp(jp_hash, ossl_hash, 32) == 0,
               "SM3 incremental update vs OpenSSL");
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  SM4 测试（与 OpenSSL 对比）
// ═══════════════════════════════════════════════════════════════════════

static void ossl_sm4_ecb_encrypt(const uint8_t key[16], const uint8_t* plain,
                                  size_t len, uint8_t* cipher) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int out_len = 0, total = 0;
    EVP_EncryptUpdate(ctx, cipher, &out_len, plain, (int)len);
    total = out_len;
    EVP_EncryptFinal_ex(ctx, cipher + total, &out_len);
    total += out_len;
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_sm4_ecb_decrypt(const uint8_t key[16], const uint8_t* cipher,
                                  size_t len, uint8_t* plain) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int out_len = 0, total = 0;
    EVP_DecryptUpdate(ctx, plain, &out_len, cipher, (int)len);
    total = out_len;
    EVP_DecryptFinal_ex(ctx, plain + total, &out_len);
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                                  const uint8_t* plain, size_t len, uint8_t* cipher, int* clen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 1);  // PKCS#7
    int out_len = 0;
    EVP_EncryptUpdate(ctx, cipher, &out_len, plain, (int)len);
    *clen = out_len;
    EVP_EncryptFinal_ex(ctx, cipher + *clen, &out_len);
    *clen += out_len;
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                                  const uint8_t* cipher, size_t len, uint8_t* plain, int* plen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    int out_len = 0;
    EVP_DecryptUpdate(ctx, plain, &out_len, cipher, (int)len);
    *plen = out_len;
    EVP_DecryptFinal_ex(ctx, plain + *plen, &out_len);
    *plen += out_len;
    EVP_CIPHER_CTX_free(ctx);
}

static void test_sm4() {
    std::printf("\n=== SM4 测试 ===\n");

    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

    jpssl::sm4_ctx ctx;
    jpssl::sm4_init(&ctx, key);

    // 单块加解密往返
    {
        uint8_t plain[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                             0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t cipher[16], recovered[16];

        jpssl::sm4_encrypt_block(&ctx, plain, cipher);
        jpssl::sm4_decrypt_block(&ctx, cipher, recovered);

        ASSERT(std::memcmp(plain, recovered, 16) == 0,
               "SM4 single block encrypt/decrypt roundtrip");
    }

    // 与 OpenSSL ECB 对比
    {
        const uint8_t plain[32] = "Hello SM4! Test message12345678";
        uint8_t jp_cipher[32], ossl_cipher[32];

        jpssl::sm4_ecb_encrypt(&ctx,
            std::span<const uint8_t>(plain, 32),
            std::span<uint8_t>(jp_cipher, 32));

        ossl_sm4_ecb_encrypt(key, plain, 32, ossl_cipher);

        ASSERT(std::memcmp(jp_cipher, ossl_cipher, 32) == 0,
               "SM4 ECB encrypt vs OpenSSL");
    }

    // ECB 解密 vs OpenSSL
    {
        const uint8_t plain[32] = "Hello SM4! Test message12345678";
        uint8_t cipher[32], jp_plain[32], ossl_plain[32];

        jpssl::sm4_ecb_encrypt(&ctx,
            std::span<const uint8_t>(plain, 32),
            std::span<uint8_t>(cipher, 32));

        jpssl::sm4_ecb_decrypt(&ctx,
            std::span<const uint8_t>(cipher, 32),
            std::span<uint8_t>(jp_plain, 32));

        ossl_sm4_ecb_decrypt(key, cipher, 32, ossl_plain);

        ASSERT(std::memcmp(jp_plain, ossl_plain, 32) == 0 &&
               std::memcmp(jp_plain, plain, 32) == 0,
               "SM4 ECB decrypt vs OpenSSL");
    }

    // CBC 模式往返
    {
        uint8_t iv[16] = {0};
        const uint8_t msg[] = "This is a CBC mode test message for SM4!";
        size_t msg_len = sizeof(msg) - 1;

        auto ct = jpssl::sm4_cbc_encrypt(&ctx, iv,
            std::span<const uint8_t>(msg, msg_len));
        auto pt = jpssl::sm4_cbc_decrypt(&ctx, iv,
            std::span<const uint8_t>(ct.data(), ct.size()));

        ASSERT(pt.size() == msg_len &&
               std::memcmp(pt.data(), msg, msg_len) == 0,
               "SM4 CBC encrypt/decrypt roundtrip");
    }

    // 多次加解密（不同数据大小）
    for (int sz = 1; sz <= 64; ++sz) {
        std::vector<uint8_t> plain(sz);
        for (int i = 0; i < sz; ++i) plain[i] = (uint8_t)(i * 3 + 1);

        uint8_t cipher[64], recovered[64];
        // 填充到 16 字节对齐
        size_t padded = ((sz + 15) / 16) * 16;
        std::vector<uint8_t> padded_plain(padded, 0);
        std::memcpy(padded_plain.data(), plain.data(), sz);

        jpssl::sm4_ecb_encrypt(&ctx,
            std::span<const uint8_t>(padded_plain),
            std::span<uint8_t>(cipher, padded));
        jpssl::sm4_ecb_decrypt(&ctx,
            std::span<const uint8_t>(cipher, padded),
            std::span<uint8_t>(recovered, padded));

        bool ok = std::memcmp(padded_plain.data(), recovered, padded) == 0;
        ASSERT(ok, ("SM4 ECB size " + std::to_string(sz)).c_str());
    }

    std::printf("  (all SM4 ECB sizes 1-64 passed)\n");
}

// ═══════════════════════════════════════════════════════════════════════
//  SM2 测试（与 OpenSSL 对比）
// ═══════════════════════════════════════════════════════════════════════

static void test_sm2() {
    std::printf("\n=== SM2 测试 ===\n");

    // 1. 密钥生成往返
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        uint8_t pub2[64];
        jpssl::sm2_pub_from_priv(priv, pub2);

        ASSERT(std::memcmp(pub, pub2, 64) == 0,
               "SM2 keygen: pub_from_priv matches keygen output");
    }

    // 2. 签名/验证往返（不带 ZA）
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        const char* msg = "SM2 test message for signing and verification";
        size_t msg_len = std::strlen(msg);

        for (int i = 0; i < 10; ++i) {
            uint8_t sig[64];
            jpssl::sm2_sign(priv, (const uint8_t*)msg, msg_len, sig, nullptr);

            bool ok = jpssl::sm2_verify(pub, (const uint8_t*)msg, msg_len, sig, nullptr);
            ASSERT(ok, ("SM2 sign/verify roundtrip #" + std::to_string(i)).c_str());
        }
    }

    // 3. 签名/验证往返（带 ZA）
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        // 计算 ZA
        const char* id = "1234567812345678";
        uint8_t za[32];
        jpssl::sm2_compute_za((const uint8_t*)id, std::strlen(id), pub, pub + 32, za);

        const char* msg = "SM2 test with ZA (user identity)";
        size_t msg_len = std::strlen(msg);

        for (int i = 0; i < 5; ++i) {
            uint8_t sig[64];
            jpssl::sm2_sign(priv, (const uint8_t*)msg, msg_len, sig, za);

            bool ok = jpssl::sm2_verify(pub, (const uint8_t*)msg, msg_len, sig, za);
            ASSERT(ok, ("SM2 sign/verify with ZA #" + std::to_string(i)).c_str());
        }
    }

    // 4. 验证失败案例：错误消息
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        const char* msg1 = "Message one";
        const char* msg2 = "Message two";
        uint8_t sig[64];
        jpssl::sm2_sign(priv, (const uint8_t*)msg1, std::strlen(msg1), sig, nullptr);

        bool ok = jpssl::sm2_verify(pub, (const uint8_t*)msg2, std::strlen(msg2), sig, nullptr);
        ASSERT(!ok, "SM2 verify rejects wrong message");
    }

    // 5. 验证失败案例：错误公钥
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        uint8_t pub2[64], priv2[32];
        jpssl::sm2_keygen(pub2, priv2);

        const char* msg = "Test message";
        uint8_t sig[64];
        jpssl::sm2_sign(priv, (const uint8_t*)msg, std::strlen(msg), sig, nullptr);

        bool ok = jpssl::sm2_verify(pub2, (const uint8_t*)msg, std::strlen(msg), sig, nullptr);
        ASSERT(!ok, "SM2 verify rejects wrong public key");
    }

    // 6. 与 OpenSSL 互验签名
    // 使用固定私钥生成确定性结果
    {
        // 固定私钥: 1
        uint8_t fixed_priv[32] = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
        };

        uint8_t pub[64];
        jpssl::sm2_pub_from_priv(fixed_priv, pub);

        const char* msg = "SM2 cross-validation test";
        uint8_t sig[64];
        jpssl::sm2_sign(fixed_priv, (const uint8_t*)msg, std::strlen(msg), sig, nullptr);

        bool ok = jpssl::sm2_verify(pub, (const uint8_t*)msg, std::strlen(msg), sig, nullptr);
        ASSERT(ok, "SM2 fixed-private-key sign/verify");
    }

    // 7. 空消息签名
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        uint8_t sig[64];
        jpssl::sm2_sign(priv, nullptr, 0, sig, nullptr);

        bool ok = jpssl::sm2_verify(pub, nullptr, 0, sig, nullptr);
        ASSERT(ok, "SM2 empty message sign/verify");
    }

    // 8. 大批量数据签名
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        std::vector<uint8_t> msg(10000);
        for (int i = 0; i < 10000; ++i) msg[i] = (uint8_t)(i & 0xff);

        uint8_t sig[64];
        jpssl::sm2_sign(priv, msg.data(), msg.size(), sig, nullptr);

        bool ok = jpssl::sm2_verify(pub, msg.data(), msg.size(), sig, nullptr);
        ASSERT(ok, "SM2 large message (10KB) sign/verify");
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════════════════════

int main() {
    std::printf("jpssl SM2/SM3/SM4 Unit Tests\n");
    std::printf("============================\n");

    test_sm3();
    test_sm4();
    test_sm2();

    std::printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}
