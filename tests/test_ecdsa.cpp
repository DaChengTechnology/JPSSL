// ECDSA P-256/P-384 测试：与 OpenSSL 互验
#include "ecdsa.hpp"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <cstdio>
#include <cstring>
#include <vector>

static void hex(const char* label, const uint8_t* d, int n) {
    printf("  %s: ", label);
    for (int i = 0; i < n; ++i) printf("%02x", d[i]);
    printf("\n");
}

// OpenSSL: 用私钥派生公钥，并验证我们的公钥是否一致
static bool ossl_pub_from_priv(const uint8_t priv_be[32], uint8_t pub_be[64]) {
    BIGNUM* d = BN_bin2bn(priv_be, 32, nullptr);
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT* Q = EC_POINT_new(grp);
    EC_POINT_mul(grp, Q, d, nullptr, nullptr, nullptr);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* x = BN_new(); BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(grp, Q, x, y, ctx);
    int xl = BN_num_bytes(x), yl = BN_num_bytes(y);
    memset(pub_be, 0, 64);
    BN_bn2bin(x, pub_be + (32 - xl));
    BN_bn2bin(y, pub_be + 32 + (32 - yl));
    BN_free(x); BN_free(y); BN_free(d);
    BN_CTX_free(ctx); EC_POINT_free(Q); EC_GROUP_free(grp);
    return true;
}

// OpenSSL 签名 (SHA-256)
static bool ossl_sign(const uint8_t priv_be[32], const uint8_t* msg, size_t len,
                      uint8_t* sig, size_t* siglen) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIGNUM* d = BN_bin2bn(priv_be, 32, nullptr);
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY* eck = EC_KEY_new();
    EC_KEY_set_group(eck, grp);
    EC_KEY_set_private_key(eck, d);
    EC_POINT* Q = EC_POINT_new(grp);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_mul(grp, Q, d, nullptr, nullptr, ctx);
    EC_KEY_set_public_key(eck, Q);
    EVP_PKEY_assign_EC_KEY(pkey, eck);

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(mctx, msg, len);
    EVP_DigestSignFinal(mctx, nullptr, siglen);
    EVP_DigestSignFinal(mctx, sig, siglen);

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    BN_free(d); EC_POINT_free(Q); BN_CTX_free(ctx); EC_GROUP_free(grp);
    return true;
}

// OpenSSL 验证 (raw r||s 64 字节)
// ECDSA_do_verify 期望 dgst 参数是已哈希的 digest, 不是原始消息
static bool ossl_verify(const uint8_t pub_be[64], const uint8_t* msg, size_t len,
                        const uint8_t sig_rs[64]) {
    uint8_t digest[32];
    SHA256(msg, len, digest);

    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY* eck = EC_KEY_new();
    EC_KEY_set_group(eck, grp);
    BIGNUM* x = BN_bin2bn(pub_be, 32, nullptr);
    BIGNUM* y = BN_bin2bn(pub_be + 32, 32, nullptr);
    EC_POINT* Q = EC_POINT_new(grp);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_set_affine_coordinates(grp, Q, x, y, ctx);
    EC_KEY_set_public_key(eck, Q);

    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(sig_rs, 32, nullptr);
    BIGNUM* s = BN_bin2bn(sig_rs + 32, 32, nullptr);
    ECDSA_SIG_set0(sig, r, s);

    int ok = ECDSA_do_verify(digest, 32, sig, eck);

    ECDSA_SIG_free(sig);
    EC_KEY_free(eck); EC_POINT_free(Q); EC_GROUP_free(grp);
    BN_free(x); BN_free(y); BN_CTX_free(ctx);
    return ok == 1;
}

// OpenSSL DER -> raw r||s
static bool der_to_rs(const uint8_t* der, size_t derlen, uint8_t rs[64]) {
    const unsigned char* p = der;
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, (long)derlen);
    if (!sig) return false;
    const BIGNUM *r = ECDSA_SIG_get0_r(sig);
    const BIGNUM *s = ECDSA_SIG_get0_s(sig);
    memset(rs, 0, 64);
    int rl = BN_num_bytes(r), sl = BN_num_bytes(s);
    BN_bn2bin(r, rs + (32 - rl));
    BN_bn2bin(s, rs + 32 + (32 - sl));
    ECDSA_SIG_free(sig);
    return true;
}

int main() {
    int fails = 0;

    // ── 测试 1：本库 keygen -> 本库 sign -> 本库 verify ──
    printf("=== Test 1: self keygen/sign/verify ===\n");
    for (int i = 0; i < 5; ++i) {
        uint8_t priv[32], pub[64], sig[64];
        const char* msg = "hello ec p256";
        jpssl::ecdsa_p256_keygen(pub, priv);
        jpssl::ecdsa_p256_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        bool ok = jpssl::ecdsa_p256_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) ++fails;
    }

    // ── 测试 2：本库 keygen，与 OpenSSL 派生的公钥对比 ──
    printf("=== Test 2: pubkey matches OpenSSL ===\n");
    for (int i = 0; i < 3; ++i) {
        uint8_t priv[32], pub[64];
        jpssl::ecdsa_p256_keygen(pub, priv);
        uint8_t ossl_pub[64];
        ossl_pub_from_priv(priv, ossl_pub);
        bool ok = memcmp(pub, ossl_pub, 64) == 0;
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) {
            hex("priv", priv, 32);
            hex("ours", pub, 64);
            hex("ossl", ossl_pub, 64);
            ++fails;
        }
    }

    // ── 测试 3：本库 sign -> OpenSSL verify ──
    printf("=== Test 3: our sign -> OpenSSL verify ===\n");
    for (int i = 0; i < 3; ++i) {
        uint8_t priv[32], pub[64], sig[64];
        jpssl::ecdsa_p256_keygen(pub, priv);
        const char* msg = "cross verify ossl";
        jpssl::ecdsa_p256_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        bool ok = ossl_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) {
            hex("priv", priv, 32);
            hex("sig ", sig, 64);
            ++fails;
        }
    }

    // ── 测试 4：OpenSSL sign -> 本库 verify ──
    printf("=== Test 4: OpenSSL sign -> our verify ===\n");
    for (int i = 0; i < 3; ++i) {
        uint8_t priv[32], pub[64];
        jpssl::ecdsa_p256_keygen(pub, priv);
        const char* msg = "ossl sign our verify";
        uint8_t der[256];
        size_t derlen = sizeof(der);
        ossl_sign(priv, (const uint8_t*)msg, strlen(msg), der, &derlen);
        uint8_t sig[64];
        der_to_rs(der, derlen, sig);
        bool ok = jpssl::ecdsa_p256_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) {
            hex("priv", priv, 32);
            hex("sig ", sig, 64);
            ++fails;
        }
    }

    // ── 测试 5：篡改消息必须失败 ──
    printf("=== Test 5: tamper detection ===\n");
    {
        uint8_t priv[32], pub[64], sig[64];
        jpssl::ecdsa_p256_keygen(pub, priv);
        const char* msg = "original message";
        jpssl::ecdsa_p256_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        const char* bad = "modified message";
        bool ok = jpssl::ecdsa_p256_verify(pub, (const uint8_t*)bad, strlen(bad), sig);
        printf("  tampered msg rejected: %s\n", !ok ? "PASS" : "FAIL");
        if (ok) ++fails;
    }

    // ── 测试 6：篡改签名必须失败 ──
    printf("=== Test 6: bad sig rejected ===\n");
    {
        uint8_t priv[32], pub[64], sig[64];
        jpssl::ecdsa_p256_keygen(pub, priv);
        const char* msg = "another test";
        jpssl::ecdsa_p256_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        sig[0] ^= 0xff;
        bool ok = jpssl::ecdsa_p256_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  bad sig rejected: %s\n", !ok ? "PASS" : "FAIL");
        if (ok) ++fails;
    }

    // ════════════════════════════════════════════════════════════
    //  P-384 测试
    // ════════════════════════════════════════════════════════════

    // ── P-384 OpenSSL 辅助函数 ──

    auto ossl384_pub_from_priv = [](const uint8_t priv_be[48], uint8_t pub_be[96]) -> bool {
        BIGNUM* d = BN_bin2bn(priv_be, 48, nullptr);
        EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_secp384r1);
        EC_POINT* Q = EC_POINT_new(grp);
        EC_POINT_mul(grp, Q, d, nullptr, nullptr, nullptr);
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* x = BN_new(); BIGNUM* y = BN_new();
        EC_POINT_get_affine_coordinates(grp, Q, x, y, ctx);
        int xl = BN_num_bytes(x), yl = BN_num_bytes(y);
        memset(pub_be, 0, 96);
        BN_bn2bin(x, pub_be + (48 - xl));
        BN_bn2bin(y, pub_be + 48 + (48 - yl));
        BN_free(x); BN_free(y); BN_free(d);
        BN_CTX_free(ctx); EC_POINT_free(Q); EC_GROUP_free(grp);
        return true;
    };

    auto ossl384_sign = [](const uint8_t priv_be[48], const uint8_t* msg, size_t len,
                           uint8_t* sig, size_t* siglen) -> bool {
        EVP_PKEY* pkey = EVP_PKEY_new();
        BIGNUM* d = BN_bin2bn(priv_be, 48, nullptr);
        EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_secp384r1);
        EC_KEY* eck = EC_KEY_new();
        EC_KEY_set_group(eck, grp);
        EC_KEY_set_private_key(eck, d);
        EC_POINT* Q = EC_POINT_new(grp);
        BN_CTX* ctx = BN_CTX_new();
        EC_POINT_mul(grp, Q, d, nullptr, nullptr, ctx);
        EC_KEY_set_public_key(eck, Q);
        EVP_PKEY_assign_EC_KEY(pkey, eck);
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mctx, nullptr, EVP_sha384(), nullptr, pkey);
        EVP_DigestSignUpdate(mctx, msg, len);
        EVP_DigestSignFinal(mctx, nullptr, siglen);
        EVP_DigestSignFinal(mctx, sig, siglen);
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        BN_free(d); EC_POINT_free(Q); BN_CTX_free(ctx); EC_GROUP_free(grp);
        return true;
    };

    auto ossl384_verify = [](const uint8_t pub_be[96], const uint8_t* msg, size_t len,
                             const uint8_t sig_rs[96]) -> bool {
        uint8_t digest[48];
        // SHA-384
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha384(), nullptr);
        EVP_DigestUpdate(mdctx, msg, len);
        unsigned int dlen;
        EVP_DigestFinal_ex(mdctx, digest, &dlen);
        EVP_MD_CTX_free(mdctx);

        EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_secp384r1);
        EC_KEY* eck = EC_KEY_new();
        EC_KEY_set_group(eck, grp);
        BIGNUM* x = BN_bin2bn(pub_be, 48, nullptr);
        BIGNUM* y = BN_bin2bn(pub_be + 48, 48, nullptr);
        EC_POINT* Q = EC_POINT_new(grp);
        BN_CTX* ctx = BN_CTX_new();
        EC_POINT_set_affine_coordinates(grp, Q, x, y, ctx);
        EC_KEY_set_public_key(eck, Q);
        ECDSA_SIG* sig = ECDSA_SIG_new();
        BIGNUM* r = BN_bin2bn(sig_rs, 48, nullptr);
        BIGNUM* s = BN_bin2bn(sig_rs + 48, 48, nullptr);
        ECDSA_SIG_set0(sig, r, s);
        int ok = ECDSA_do_verify(digest, 48, sig, eck);
        ECDSA_SIG_free(sig);
        EC_KEY_free(eck); EC_POINT_free(Q); EC_GROUP_free(grp);
        BN_free(x); BN_free(y); BN_CTX_free(ctx);
        return ok == 1;
    };

    auto der384_to_rs = [](const uint8_t* der, size_t derlen, uint8_t rs[96]) -> bool {
        const unsigned char* p = der;
        ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, (long)derlen);
        if (!sig) return false;
        const BIGNUM* r = ECDSA_SIG_get0_r(sig);
        const BIGNUM* s = ECDSA_SIG_get0_s(sig);
        memset(rs, 0, 96);
        int rl = BN_num_bytes(r), sl = BN_num_bytes(s);
        BN_bn2bin(r, rs + (48 - rl));
        BN_bn2bin(s, rs + 48 + (48 - sl));
        ECDSA_SIG_free(sig);
        return true;
    };

    // ── 测试 7：P-384 本库 keygen -> sign -> verify ──
    printf("=== Test 7: P-384 self keygen/sign/verify ===\n");
    for (int i = 0; i < 5; ++i) {
        uint8_t priv[48], pub[96], sig[96];
        const char* msg = "hello ec p384";
        jpssl::ecdsa_p384_keygen(pub, priv);
        jpssl::ecdsa_p384_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        bool ok = jpssl::ecdsa_p384_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) ++fails;
    }

    // ── 测试 8：P-384 本库 keygen，与 OpenSSL 派生的公钥对比 ──
    printf("=== Test 8: P-384 pubkey matches OpenSSL ===\n");
    for (int i = 0; i < 3; ++i) {
        uint8_t priv[48], pub[96];
        jpssl::ecdsa_p384_keygen(pub, priv);
        uint8_t ossl_pub[96];
        ossl384_pub_from_priv(priv, ossl_pub);
        bool ok = memcmp(pub, ossl_pub, 96) == 0;
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) {
            hex("priv", priv, 48);
            hex("ours", pub, 96);
            hex("ossl", ossl_pub, 96);
            ++fails;
        }
    }

    // ── 测试 9：P-384 本库 sign -> OpenSSL verify ──
    printf("=== Test 9: P-384 our sign -> OpenSSL verify ===\n");
    for (int i = 0; i < 3; ++i) {
        uint8_t priv[48], pub[96], sig[96];
        jpssl::ecdsa_p384_keygen(pub, priv);
        const char* msg = "cross verify p384";
        jpssl::ecdsa_p384_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        bool ok = ossl384_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) {
            hex("priv", priv, 48);
            hex("sig ", sig, 96);
            ++fails;
        }
    }

    // ── 测试 10：P-384 OpenSSL sign -> 本库 verify ──
    printf("=== Test 10: P-384 OpenSSL sign -> our verify ===\n");
    for (int i = 0; i < 3; ++i) {
        uint8_t priv[48], pub[96];
        jpssl::ecdsa_p384_keygen(pub, priv);
        const char* msg = "ossl sign p384 our verify";
        uint8_t der[256];
        size_t derlen = sizeof(der);
        ossl384_sign(priv, (const uint8_t*)msg, strlen(msg), der, &derlen);
        uint8_t sig[96];
        der384_to_rs(der, derlen, sig);
        bool ok = jpssl::ecdsa_p384_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) {
            hex("priv", priv, 48);
            hex("sig ", sig, 96);
            ++fails;
        }
    }

    // ── 测试 11：P-384 篡改消息必须失败 ──
    printf("=== Test 11: P-384 tamper detection ===\n");
    {
        uint8_t priv[48], pub[96], sig[96];
        jpssl::ecdsa_p384_keygen(pub, priv);
        const char* msg = "original message p384";
        jpssl::ecdsa_p384_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        const char* bad = "modified message p384";
        bool ok = jpssl::ecdsa_p384_verify(pub, (const uint8_t*)bad, strlen(bad), sig);
        printf("  tampered msg rejected: %s\n", !ok ? "PASS" : "FAIL");
        if (ok) ++fails;
    }

    // ── 测试 12：P-384 篡改签名必须失败 ──
    printf("=== Test 12: P-384 bad sig rejected ===\n");
    {
        uint8_t priv[48], pub[96], sig[96];
        jpssl::ecdsa_p384_keygen(pub, priv);
        const char* msg = "another p384 test";
        jpssl::ecdsa_p384_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        sig[0] ^= 0xff;
        bool ok = jpssl::ecdsa_p384_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  bad sig rejected: %s\n", !ok ? "PASS" : "FAIL");
        if (ok) ++fails;
    }

    // ── P-521 tests ──

    auto ossl521_pub_from_priv = [](const uint8_t priv_be[66], uint8_t pub_be[132]) -> bool {
        BIGNUM* d = BN_bin2bn(priv_be, 66, nullptr);
        EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_secp521r1);
        EC_POINT* Q = EC_POINT_new(grp);
        EC_POINT_mul(grp, Q, d, nullptr, nullptr, nullptr);
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* x = BN_new(); BIGNUM* y = BN_new();
        EC_POINT_get_affine_coordinates(grp, Q, x, y, ctx);
        int xl = BN_num_bytes(x), yl = BN_num_bytes(y);
        memset(pub_be, 0, 132);
        BN_bn2bin(x, pub_be + (66 - xl));
        BN_bn2bin(y, pub_be + 66 + (66 - yl));
        BN_free(x); BN_free(y); BN_free(d);
        BN_CTX_free(ctx); EC_POINT_free(Q); EC_GROUP_free(grp);
        return true;
    };

    auto ossl521_sign = [](const uint8_t priv_be[66], const uint8_t* msg, size_t len,
                           uint8_t* sig, size_t* siglen) -> bool {
        EVP_PKEY* pkey = EVP_PKEY_new();
        BIGNUM* d = BN_bin2bn(priv_be, 66, nullptr);
        EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_secp521r1);
        EC_KEY* eck = EC_KEY_new();
        EC_KEY_set_group(eck, grp);
        EC_KEY_set_private_key(eck, d);
        EC_POINT* Q = EC_POINT_new(grp);
        BN_CTX* ctx = BN_CTX_new();
        EC_POINT_mul(grp, Q, d, nullptr, nullptr, ctx);
        EC_KEY_set_public_key(eck, Q);
        EVP_PKEY_assign_EC_KEY(pkey, eck);
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mctx, nullptr, EVP_sha512(), nullptr, pkey);
        EVP_DigestSignUpdate(mctx, msg, len);
        EVP_DigestSignFinal(mctx, nullptr, siglen);
        EVP_DigestSignFinal(mctx, sig, siglen);
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_free(pkey);
        BN_free(d); EC_POINT_free(Q); BN_CTX_free(ctx); EC_GROUP_free(grp);
        return true;
    };

    auto ossl521_verify = [](const uint8_t pub_be[132], const uint8_t* msg, size_t len,
                             const uint8_t sig_rs[132]) -> bool {
        uint8_t digest[64];
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr);
        EVP_DigestUpdate(mdctx, msg, len);
        unsigned int dlen;
        EVP_DigestFinal_ex(mdctx, digest, &dlen);
        EVP_MD_CTX_free(mdctx);

        EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_secp521r1);
        EC_KEY* eck = EC_KEY_new();
        EC_KEY_set_group(eck, grp);
        BIGNUM* x = BN_bin2bn(pub_be, 66, nullptr);
        BIGNUM* y = BN_bin2bn(pub_be + 66, 66, nullptr);
        EC_POINT* Q = EC_POINT_new(grp);
        BN_CTX* ctx = BN_CTX_new();
        EC_POINT_set_affine_coordinates(grp, Q, x, y, ctx);
        EC_KEY_set_public_key(eck, Q);
        ECDSA_SIG* sig = ECDSA_SIG_new();
        BIGNUM* r = BN_bin2bn(sig_rs, 66, nullptr);
        BIGNUM* s = BN_bin2bn(sig_rs + 66, 66, nullptr);
        ECDSA_SIG_set0(sig, r, s);
        int ok = ECDSA_do_verify(digest, 64, sig, eck);
        ECDSA_SIG_free(sig);
        EC_KEY_free(eck); EC_POINT_free(Q); EC_GROUP_free(grp);
        BN_free(x); BN_free(y); BN_CTX_free(ctx);
        return ok == 1;
    };

    auto der521_to_rs = [](const uint8_t* der, size_t derlen, uint8_t rs[132]) -> bool {
        const unsigned char* p = der;
        ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, (long)derlen);
        if (!sig) return false;
        const BIGNUM* r = ECDSA_SIG_get0_r(sig);
        const BIGNUM* s = ECDSA_SIG_get0_s(sig);
        memset(rs, 0, 132);
        int rl = BN_num_bytes(r), sl = BN_num_bytes(s);
        BN_bn2bin(r, rs + (66 - rl));
        BN_bn2bin(s, rs + 66 + (66 - sl));
        ECDSA_SIG_free(sig);
        return true;
    };

    // Test 13: P-521 self keygen/sign/verify
    printf("=== Test 13: P-521 self keygen/sign/verify ===\n");
    for (int i = 0; i < 3; ++i) {
        uint8_t priv[66], pub[132], sig[132];
        const char* msg = "hello ec p521";
        jpssl::ecdsa_p521_keygen(pub, priv);
        jpssl::ecdsa_p521_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        bool ok = jpssl::ecdsa_p521_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) ++fails;
    }

    // Test 14: P-521 pubkey matches OpenSSL
    printf("=== Test 14: P-521 pubkey matches OpenSSL ===\n");
    for (int i = 0; i < 3; ++i) {
        uint8_t priv[66], pub[132];
        jpssl::ecdsa_p521_keygen(pub, priv);
        uint8_t ossl_pub[132];
        ossl521_pub_from_priv(priv, ossl_pub);
        bool ok = memcmp(pub, ossl_pub, 132) == 0;
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) {
            hex("priv", priv, 66);
            hex("ours", pub, 132);
            hex("ossl", ossl_pub, 132);
            ++fails;
        }
    }

    // Test 15: P-521 our sign -> OpenSSL verify
    printf("=== Test 15: P-521 our sign -> OpenSSL verify ===\n");
    for (int i = 0; i < 3; ++i) {
        uint8_t priv[66], pub[132], sig[132];
        jpssl::ecdsa_p521_keygen(pub, priv);
        const char* msg = "cross verify p521";
        jpssl::ecdsa_p521_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        bool ok = ossl521_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) {
            hex("priv", priv, 66);
            hex("sig ", sig, 132);
            ++fails;
        }
    }

    // Test 16: P-521 OpenSSL sign -> our verify
    printf("=== Test 16: P-521 OpenSSL sign -> our verify ===\n");
    for (int i = 0; i < 3; ++i) {
        uint8_t priv[66], pub[132];
        jpssl::ecdsa_p521_keygen(pub, priv);
        const char* msg = "ossl sign p521 our verify";
        uint8_t der[512];
        size_t derlen = sizeof(der);
        ossl521_sign(priv, (const uint8_t*)msg, strlen(msg), der, &derlen);
        uint8_t sig[132];
        der521_to_rs(der, derlen, sig);
        bool ok = jpssl::ecdsa_p521_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  iter %d: %s\n", i, ok ? "PASS" : "FAIL");
        if (!ok) {
            hex("priv", priv, 66);
            hex("sig ", sig, 132);
            ++fails;
        }
    }

    // Test 17: P-521 tamper detection
    printf("=== Test 17: P-521 tamper detection ===\n");
    {
        uint8_t priv[66], pub[132], sig[132];
        jpssl::ecdsa_p521_keygen(pub, priv);
        const char* msg = "original message p521";
        jpssl::ecdsa_p521_sign(priv, (const uint8_t*)msg, strlen(msg), sig);
        const char* bad = "modified message p521";
        bool ok = jpssl::ecdsa_p521_verify(pub, (const uint8_t*)bad, strlen(bad), sig);
        printf("  tampered msg rejected: %s\n", !ok ? "PASS" : "FAIL");
        if (ok) ++fails;
        sig[0] ^= 0xff;
        ok = jpssl::ecdsa_p521_verify(pub, (const uint8_t*)msg, strlen(msg), sig);
        printf("  bad sig rejected: %s\n", !ok ? "PASS" : "FAIL");
        if (ok) ++fails;
    }

    printf("\n=== Result: %d failures ===\n", fails);
    return fails ? 1 : 0;
}
