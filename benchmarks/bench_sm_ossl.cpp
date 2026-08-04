// bench_sm_ossl.cpp - jpssl SM3/SM2 vs OpenSSL 微基准
//
// 覆盖: SM3 哈希吞吐 / SM2 密钥生成 / 签名 / 验签
// 说明: OpenSSL 的 SM2 签名经 EVP 输出 DER, 这里与 jpssl 的
//       原始 64 字节 r||s 互转后互操作自检, 再分别计时。
// 编译需链接 OpenSSL libcrypto (仅测试端对照, jpssl 库本身不依赖)。
#include "sm2.hpp"
#include "sm3.hpp"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using Clock = std::chrono::steady_clock;

static volatile int g_sink = 0;

template <typename F>
static double auto_bench(const char* name, F&& f, double target_ms = 250.0,
                         int rounds = 3) {
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
    printf("%-32s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    return best;
}

static const char* ID = "1234567812345678";

static EVP_PKEY* ossl_sm2_key(const uint8_t priv[32], const uint8_t pub[64]) {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_sm2);
    if (!ec) return nullptr;
    BIGNUM* x = BN_bin2bn(pub, 32, nullptr);
    BIGNUM* y = BN_bin2bn(pub + 32, 32, nullptr);
    EC_POINT* P = EC_POINT_new(EC_KEY_get0_group(ec));
    bool ok = x && y && P
           && EC_POINT_set_affine_coordinates(EC_KEY_get0_group(ec), P, x, y, nullptr) == 1
           && EC_KEY_set_public_key(ec, P) == 1;
    if (ok && priv) {
        BIGNUM* d = BN_bin2bn(priv, 32, nullptr);
        ok = d && EC_KEY_set_private_key(ec, d) == 1;
        BN_free(d);
    }
    EC_POINT_free(P); BN_free(x); BN_free(y);
    if (!ok) { EC_KEY_free(ec); return nullptr; }
    EVP_PKEY* k = EVP_PKEY_new();
    if (!k) { EC_KEY_free(ec); return nullptr; }
    if (EVP_PKEY_assign_EC_KEY(k, ec) != 1) {
        EVP_PKEY_free(k); EC_KEY_free(ec); return nullptr;
    }
    return k;
}

// OpenSSL 签名（DER -> 原始 r||s）
static bool ossl_sm2_sign(const uint8_t priv[32], const uint8_t pub[64],
                          const uint8_t* msg, size_t mlen, uint8_t sig[64]) {
    EVP_PKEY* k = ossl_sm2_key(priv, pub);
    if (!k) return false;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = EVP_DigestSignInit(mctx, &pctx, EVP_sm3(), nullptr, k) == 1
           && EVP_PKEY_CTX_set1_id(pctx, (const uint8_t*)ID, (int)std::strlen(ID)) == 1;
    uint8_t der[80];
    size_t dlen = sizeof(der);
    if (ok) ok = EVP_DigestSign(mctx, der, &dlen, msg, mlen) == 1;
    if (ok) {
        const unsigned char* p = der;
        ECDSA_SIG* es = d2i_ECDSA_SIG(nullptr, &p, (long)dlen);
        ok = es != nullptr;
        if (ok) {
            const BIGNUM *r = nullptr, *s = nullptr;
            ECDSA_SIG_get0(es, &r, &s);
            ok = BN_bn2binpad(r, sig, 32) == 32 && BN_bn2binpad(s, sig + 32, 32) == 32;
            ECDSA_SIG_free(es);
        }
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(k);
    return ok;
}

// OpenSSL 验签（原始 r||s -> DER）
static bool ossl_sm2_verify(const uint8_t pub[64],
                            const uint8_t* msg, size_t mlen, const uint8_t sig[64]) {
    EVP_PKEY* k = ossl_sm2_key(nullptr, pub);
    if (!k) return false;
    ECDSA_SIG* es = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(sig, 32, nullptr);
    BIGNUM* s = BN_bin2bn(sig + 32, 32, nullptr);
    bool der_ok = es && r && s && ECDSA_SIG_set0(es, r, s) == 1;
    uint8_t der[80];
    unsigned char* p = der;
    int dlen = der_ok ? i2d_ECDSA_SIG(es, &p) : 0;
    if (es) ECDSA_SIG_free(es);
    if (!der_ok || dlen <= 0) { BN_free(r); BN_free(s); EVP_PKEY_free(k); return false; }
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = EVP_DigestVerifyInit(mctx, &pctx, EVP_sm3(), nullptr, k) == 1
           && EVP_PKEY_CTX_set1_id(pctx, (const uint8_t*)ID, (int)std::strlen(ID)) == 1;
    if (ok) ok = EVP_DigestVerify(mctx, der, (size_t)dlen, msg, mlen) == 1;
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(k);
    return ok;
}

int main() {
    printf("=== SM3/SM2: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);

    static const uint8_t g_msg[256] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    constexpr size_t g_msglen = sizeof(g_msg);

    // ---- 互操作自检 ----
    uint8_t pub[64], priv[32];
    jpssl::sm2_keygen(pub, priv);
    uint8_t za[32];
    jpssl::sm2_compute_za((const uint8_t*)ID, std::strlen(ID), pub, pub + 32, za);
    uint8_t sig[64];
    jpssl::sm2_sign(priv, g_msg, g_msglen, sig, za);
    bool ok1 = ossl_sm2_verify(pub, g_msg, g_msglen, sig);
    uint8_t osig[64];
    bool ok2 = ossl_sm2_sign(priv, pub, g_msg, g_msglen, osig);
    ok2 = ok2 && jpssl::sm2_verify(pub, g_msg, g_msglen, osig, za);
    printf("OpenSSL verifies jpssl signature : %s\n", ok1 ? "PASS" : "FAIL");
    printf("jpssl verifies OpenSSL signature : %s\n", ok2 ? "PASS" : "FAIL");
    if (!ok1 || !ok2) {
        printf("interop FAILED, abort\n");
        return 1;
    }

    // ---- SM3 吞吐 ----
    {
        std::vector<uint8_t> buf(8 * 1024, 0x5a);
        uint8_t d[32];
        double jp_ns = auto_bench("jpssl sm3 (8 KiB)", [&] {
            jpssl::sm3_hash(d, buf.data(), buf.size());
            g_sink ^= d[0];
        });
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        double os_ns = auto_bench("openssl sm3 (8 KiB)", [&] {
            unsigned int ol = 32;
            EVP_DigestInit_ex(mctx, EVP_sm3(), nullptr);
            EVP_DigestUpdate(mctx, buf.data(), buf.size());
            EVP_DigestFinal_ex(mctx, d, &ol);
            g_sink ^= d[0];
        });
        EVP_MD_CTX_free(mctx);
        double jp_mb = 8192.0 / jp_ns * 1e3;
        double os_mb = 8192.0 / os_ns * 1e3;
        printf("sm3: jpssl %8.1f MB/s   openssl %8.1f MB/s   x%.2f\n",
               jp_mb, os_mb, jp_mb / os_mb);
    }

    printf("\n%-32s %12s %14s\n", "case", "ns/op", "Kops/s");

    // ---- SM2 密钥生成 ----
    auto_bench("jpssl sm2 keygen", [] {
        uint8_t p[64], k[32];
        jpssl::sm2_keygen(p, k);
        g_sink ^= p[0] ^ k[0];
    });
    auto_bench("openssl sm2 keygen", [] {
        EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "SM2");
        if (k) EVP_PKEY_free(k);
        g_sink ^= (k != nullptr);
    });

    // ---- SM2 签名 ----
    auto_bench("jpssl sm2 sign", [&] {
        uint8_t s[64];
        jpssl::sm2_sign(priv, g_msg, g_msglen, s, za);
        g_sink ^= s[0];
    });
    auto_bench("openssl sm2 sign", [&] {
        uint8_t s[64];
        ossl_sm2_sign(priv, pub, g_msg, g_msglen, s);
        g_sink ^= s[0];
    });

    // ---- SM2 验签 ----
    auto_bench("jpssl sm2 verify", [&] {
        volatile bool ok = jpssl::sm2_verify(pub, g_msg, g_msglen, sig, za);
        g_sink ^= (int)ok;
    });
    auto_bench("openssl sm2 verify", [&] {
        volatile bool ok = ossl_sm2_verify(pub, g_msg, g_msglen, sig);
        g_sink ^= (int)ok;
    });

    return 0;
}
