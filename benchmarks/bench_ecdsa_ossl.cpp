// bench_ecdsa_ossl.cpp - jpssl ECDSA (P-256/384/521) vs OpenSSL 微基准
//
// 覆盖: 密钥生成 / 签名 / 验签（三条曲线）。
// 编译需链接 OpenSSL libcrypto（仅测试端对照，jpssl 库本身不依赖 OpenSSL）。

#include "ecdsa.hpp"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>

using Clock = std::chrono::steady_clock;

static volatile int g_sink = 0;

static const uint8_t g_msg[256] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static constexpr size_t g_msglen = sizeof(g_msg);

// 自适应迭代次数的微基准：每轮跑约 target_ms，取 3 轮中最小值。
template <typename F>
static double auto_bench(const char* name, F&& f, double target_ms = 250.0, int rounds = 3) {
    f();
    const int est_n = 8;
    auto t0 = Clock::now();
    for (int i = 0; i < est_n; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / est_n;
    if (est_ns < 1000.0) {
        const int est_n2 = 2000;
        t0 = Clock::now();
        for (int i = 0; i < est_n2; ++i) f();
        t1 = Clock::now();
        est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / est_n2;
    }
    long long iters = 1;
    if (est_ns > 0.0) {
        iters = static_cast<long long>(target_ms * 1e6 / est_ns);
        if (iters < 1) iters = 1;
        if (iters > 2000000) iters = 2000000;
    }

    double best = 1e300;
    for (int r = 0; r < rounds; ++r) {
        auto s = Clock::now();
        for (long long i = 0; i < iters; ++i) f();
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / iters;
        if (ns < best) best = ns;
    }
    printf("%-34s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    return best;
}

// OpenSSL：由私钥派生公钥并签名（digest = SHA-256(msg)），返回 r||s 大端
static bool ossl_sign_rs(int nid, const uint8_t* priv, int key_len,
                         const EVP_MD* md, int digest_len,
                         const uint8_t* msg, size_t msg_len,
                         uint8_t* rs, int* rs_len) {
    BIGNUM* d = BN_bin2bn(priv, key_len, nullptr);
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(nid);
    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, grp);
    EC_KEY_set_private_key(key, d);
    EC_POINT* Q = EC_POINT_new(grp);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_mul(grp, Q, d, nullptr, nullptr, ctx);
    EC_KEY_set_public_key(key, Q);

    uint8_t digest[SHA512_DIGEST_LENGTH];
    unsigned int dlen = 0;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, md, nullptr);
    EVP_DigestUpdate(mctx, msg, msg_len);
    EVP_DigestFinal_ex(mctx, digest, &dlen);
    ECDSA_SIG* sig = ECDSA_do_sign(digest, dlen, key);

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    int rl = BN_num_bytes(r), sl = BN_num_bytes(s);
    memset(rs, 0, (size_t)(*rs_len));
    BN_bn2bin(r, rs + (*rs_len / 2 - rl));
    BN_bn2bin(s, rs + *rs_len - sl);

    ECDSA_SIG_free(sig);
    EVP_MD_CTX_free(mctx);
    BN_CTX_free(ctx);
    EC_POINT_free(Q);
    EC_KEY_free(key);
    EC_GROUP_free(grp);
    BN_free(d);
    return true;
}

// OpenSSL verify（digest = SHA-256(msg)，r||s）
static bool ossl_verify_rs(int nid, const uint8_t* pub, int pub_len,
                           const EVP_MD* md, int digest_len,
                           const uint8_t* msg, size_t msg_len,
                           const uint8_t* rs, int rs_len) {
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(nid);
    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, grp);
    BIGNUM* x = BN_bin2bn(pub, pub_len / 2, nullptr);
    BIGNUM* y = BN_bin2bn(pub + pub_len / 2, pub_len / 2, nullptr);
    EC_POINT* Q = EC_POINT_new(grp);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_set_affine_coordinates(grp, Q, x, y, ctx);
    EC_KEY_set_public_key(key, Q);

    uint8_t digest[SHA512_DIGEST_LENGTH];
    unsigned int dlen = 0;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, md, nullptr);
    EVP_DigestUpdate(mctx, msg, msg_len);
    EVP_DigestFinal_ex(mctx, digest, &dlen);
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(rs, rs_len / 2, nullptr);
    BIGNUM* s = BN_bin2bn(rs + rs_len / 2, rs_len / 2, nullptr);
    ECDSA_SIG_set0(sig, r, s);
    int ok = ECDSA_do_verify(digest, dlen, sig, key);

    ECDSA_SIG_free(sig);
    EVP_MD_CTX_free(mctx);
    BN_CTX_free(ctx);
    EC_POINT_free(Q);
    EC_KEY_free(key);
    EC_GROUP_free(grp);
    BN_free(x);
    BN_free(y);
    return ok == 1;
}

template <typename Keygen, typename Sign, typename Verify>
static void bench_jpssl(const char* label, Keygen kg, Sign sg, Verify vf) {
    char kname[64], sname[64], vname[64];
    std::snprintf(kname, sizeof kname, "%s keygen (jpssl)", label);
    std::snprintf(sname, sizeof sname, "%s sign   (jpssl)", label);
    std::snprintf(vname, sizeof vname, "%s verify (jpssl)", label);
    auto a = auto_bench(kname, kg, 150.0);
    auto b = auto_bench(sname, sg, 150.0);
    auto c = auto_bench(vname, vf, 150.0);
    g_sink ^= (int)a ^ (int)b ^ (int)c;
}

int main() {
    printf("=== ECDSA: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);

    uint8_t digest[SHA512_DIGEST_LENGTH];
    unsigned int dlen = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, g_msg, g_msglen);
    EVP_DigestFinal_ex(md, digest, &dlen);

    // ---- P-256 ----
    {
        uint8_t pub[64], priv[32], sig[64];
        bench_jpssl(
            "P-256",
            [&]{ jpssl::ecdsa_p256_keygen(pub, priv); },
            [&]{ jpssl::ecdsa_p256_sign(priv, g_msg, g_msglen, sig); },
            [&]{ jpssl::ecdsa_p256_verify(pub, g_msg, g_msglen, sig); });

        EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        auto o_kg = auto_bench("P-256 keygen (OpenSSL)", [&]{ EC_KEY_generate_key(key); }, 150.0);
        ECDSA_SIG* s = ECDSA_do_sign(digest, dlen, key);
        auto o_sg = auto_bench("P-256 sign   (OpenSSL)", [&]{ ECDSA_SIG_free(ECDSA_do_sign(digest, dlen, key)); }, 150.0);
        auto o_vf = auto_bench("P-256 verify (OpenSSL)", [&]{ ECDSA_do_verify(digest, dlen, s, key); }, 150.0);
        g_sink ^= (int)o_kg ^ (int)o_sg ^ (int)o_vf;

        jpssl::ecdsa_p256_keygen(pub, priv);
        jpssl::ecdsa_p256_sign(priv, g_msg, g_msglen, sig);
        bool cross = ossl_verify_rs(NID_X9_62_prime256v1, pub, 64, EVP_sha256(), 32,
                                    g_msg, g_msglen, sig, 64);
        bool cross2 = false;
        uint8_t osig[64];
        int osiglen = 64;
        ossl_sign_rs(NID_X9_62_prime256v1, priv, 32, EVP_sha256(), 32,
                     g_msg, g_msglen, osig, &osiglen);
        cross2 = jpssl::ecdsa_p256_verify(pub, g_msg, g_msglen, osig);
        printf("  interop: jpssl->OpenSSL %s | OpenSSL->jpssl %s\n",
               cross ? "PASS" : "FAIL", cross2 ? "PASS" : "FAIL");
        ECDSA_SIG_free(s);
        EC_KEY_free(key);
    }

    // ---- P-384 ----
    {
        uint8_t pub[96], priv[48], sig[96];
        bench_jpssl(
            "P-384",
            [&]{ jpssl::ecdsa_p384_keygen(pub, priv); },
            [&]{ jpssl::ecdsa_p384_sign(priv, g_msg, g_msglen, sig); },
            [&]{ jpssl::ecdsa_p384_verify(pub, g_msg, g_msglen, sig); });

        uint8_t d384[48];
        unsigned int l384 = 0;
        EVP_MD_CTX* m384 = EVP_MD_CTX_new();
        EVP_DigestInit_ex(m384, EVP_sha384(), nullptr);
        EVP_DigestUpdate(m384, g_msg, g_msglen);
        EVP_DigestFinal_ex(m384, d384, &l384);

        EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp384r1);
        auto o_kg = auto_bench("P-384 keygen (OpenSSL)", [&]{ EC_KEY_generate_key(key); }, 150.0);
        ECDSA_SIG* s = ECDSA_do_sign(d384, l384, key);
        auto o_sg = auto_bench("P-384 sign   (OpenSSL)", [&]{ ECDSA_SIG_free(ECDSA_do_sign(d384, l384, key)); }, 150.0);
        auto o_vf = auto_bench("P-384 verify (OpenSSL)", [&]{ ECDSA_do_verify(d384, l384, s, key); }, 150.0);
        g_sink ^= (int)o_kg ^ (int)o_sg ^ (int)o_vf;

        jpssl::ecdsa_p384_keygen(pub, priv);
        jpssl::ecdsa_p384_sign(priv, g_msg, g_msglen, sig);
        bool cross = ossl_verify_rs(NID_secp384r1, pub, 96, EVP_sha384(), 48,
                                    g_msg, g_msglen, sig, 96);
        bool cross2 = false;
        uint8_t osig[96];
        int osiglen = 96;
        ossl_sign_rs(NID_secp384r1, priv, 48, EVP_sha384(), 48,
                     g_msg, g_msglen, osig, &osiglen);
        cross2 = jpssl::ecdsa_p384_verify(pub, g_msg, g_msglen, osig);
        printf("  interop: jpssl->OpenSSL %s | OpenSSL->jpssl %s\n",
               cross ? "PASS" : "FAIL", cross2 ? "PASS" : "FAIL");
        ECDSA_SIG_free(s);
        EC_KEY_free(key);
        EVP_MD_CTX_free(m384);
    }

    // ---- P-521 ----
    {
        uint8_t pub[132], priv[66], sig[132];
        bench_jpssl(
            "P-521",
            [&]{ jpssl::ecdsa_p521_keygen(pub, priv); },
            [&]{ jpssl::ecdsa_p521_sign(priv, g_msg, g_msglen, sig); },
            [&]{ jpssl::ecdsa_p521_verify(pub, g_msg, g_msglen, sig); });

        uint8_t d521[64];
        unsigned int l521 = 0;
        EVP_MD_CTX* m521 = EVP_MD_CTX_new();
        EVP_DigestInit_ex(m521, EVP_sha512(), nullptr);
        EVP_DigestUpdate(m521, g_msg, g_msglen);
        EVP_DigestFinal_ex(m521, d521, &l521);

        EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp521r1);
        auto o_kg = auto_bench("P-521 keygen (OpenSSL)", [&]{ EC_KEY_generate_key(key); }, 150.0);
        ECDSA_SIG* s = ECDSA_do_sign(d521, l521, key);
        auto o_sg = auto_bench("P-521 sign   (OpenSSL)", [&]{ ECDSA_SIG_free(ECDSA_do_sign(d521, l521, key)); }, 150.0);
        auto o_vf = auto_bench("P-521 verify (OpenSSL)", [&]{ ECDSA_do_verify(d521, l521, s, key); }, 150.0);
        g_sink ^= (int)o_kg ^ (int)o_sg ^ (int)o_vf;

        jpssl::ecdsa_p521_keygen(pub, priv);
        jpssl::ecdsa_p521_sign(priv, g_msg, g_msglen, sig);
        bool cross = ossl_verify_rs(NID_secp521r1, pub, 132, EVP_sha512(), 64,
                                    g_msg, g_msglen, sig, 132);
        bool cross2 = false;
        uint8_t osig[132];
        int osiglen = 132;
        ossl_sign_rs(NID_secp521r1, priv, 66, EVP_sha512(), 64,
                     g_msg, g_msglen, osig, &osiglen);
        cross2 = jpssl::ecdsa_p521_verify(pub, g_msg, g_msglen, osig);
        printf("  interop: jpssl->OpenSSL %s | OpenSSL->jpssl %s\n",
               cross ? "PASS" : "FAIL", cross2 ? "PASS" : "FAIL");
        ECDSA_SIG_free(s);
        EC_KEY_free(key);
        EVP_MD_CTX_free(m521);
    }

    EVP_MD_CTX_free(md);
    printf("\n(sink=%d)\n", g_sink);
    return 0;
}
