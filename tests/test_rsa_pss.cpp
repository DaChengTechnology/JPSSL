// test_rsa_pss.cpp - RSASSA-PSS (RFC 8017) 测试
//   覆盖: RSA-2048 / RSA-4096 × SHA-256 / SHA-384 / SHA-512
//   验证: 本库自洽 + 与 OpenSSL 双向交叉验证 + 篡改检测
#include "rsa.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <cstdio>
#include <cstring>

static BIGNUM* bn_from(const uint8_t* be, size_t len) {
    return BN_bin2bn(be, (int)len, nullptr);
}

// 用 jpssl 的 CRT 私钥构造 OpenSSL RSA* (含 p/q/dP/dQ/qInv)
static RSA* ossl_rsa_from_crt(const jpssl::rsa_crt_key& k) {
    uint8_t n[256], e[256], d[256], p[256], q[256], dP[256], dQ[256], qInv[256];
    k.n.to_bytes(n); k.e.to_bytes(e); k.d.to_bytes(d);
    k.p.to_bytes(p); k.q.to_bytes(q); k.dP.to_bytes(dP); k.dQ.to_bytes(dQ); k.qInv.to_bytes(qInv);
    RSA* rsa = RSA_new();
    RSA_set0_key(rsa, bn_from(n, 256), bn_from(e, 256), bn_from(d, 256));
    RSA_set0_factors(rsa, bn_from(p, 256), bn_from(q, 256));
    RSA_set0_crt_params(rsa, bn_from(dP, 256), bn_from(dQ, 256), bn_from(qInv, 256));
    return rsa;
}

static RSA* ossl_rsa_from_crt4096(const jpssl::rsa4096_crt_key& k) {
    uint8_t n[512], e[512], d[512], p[512], q[512], dP[512], dQ[512], qInv[512];
    k.n.to_bytes(n); k.e.to_bytes(e); k.d.to_bytes(d);
    k.p.to_bytes(p); k.q.to_bytes(q); k.dP.to_bytes(dP); k.dQ.to_bytes(dQ); k.qInv.to_bytes(qInv);
    RSA* rsa = RSA_new();
    RSA_set0_key(rsa, bn_from(n, 512), bn_from(e, 512), bn_from(d, 512));
    RSA_set0_factors(rsa, bn_from(p, 512), bn_from(q, 512));
    RSA_set0_crt_params(rsa, bn_from(dP, 512), bn_from(dQ, 512), bn_from(qInv, 512));
    return rsa;
}

static EVP_PKEY* ossl_pub_evp(const jpssl::rsa_public_key& k) {
    uint8_t n[256], e[256];
    k.n.to_bytes(n); k.e.to_bytes(e);
    RSA* rsa = RSA_new();
    RSA_set0_key(rsa, bn_from(n, 256), bn_from(e, 256), nullptr);
    EVP_PKEY* pk = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pk, rsa);
    return pk;
}

static EVP_PKEY* ossl_pub_evp4096(const jpssl::rsa4096_public_key& k) {
    uint8_t n[512], e[512];
    k.n.to_bytes(n); k.e.to_bytes(e);
    RSA* rsa = RSA_new();
    RSA_set0_key(rsa, bn_from(n, 512), bn_from(e, 512), nullptr);
    EVP_PKEY* pk = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pk, rsa);
    return pk;
}

static bool ossl_pss_sign(RSA* rsa, const EVP_MD* md, const uint8_t* msg, size_t len,
                          uint8_t* sig, size_t* siglen) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);   // 转移所有权
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestSignInit(mctx, &pctx, md, nullptr, pkey) <= 0) { EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); return false; }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) { EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); return false; }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) { EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); return false; }
    if (EVP_DigestSignUpdate(mctx, msg, len) <= 0) { EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); return false; }
    if (EVP_DigestSignFinal(mctx, nullptr, siglen) <= 0) { EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); return false; }
    if (EVP_DigestSignFinal(mctx, sig, siglen) <= 0) { EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); return false; }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return true;
}

static bool ossl_pss_verify(EVP_PKEY* pkey, const EVP_MD* md, const uint8_t* msg, size_t len,
                            const uint8_t* sig, size_t siglen) {
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestVerifyInit(mctx, &pctx, md, nullptr, pkey) <= 0) { EVP_MD_CTX_free(mctx); return false; }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) { EVP_MD_CTX_free(mctx); return false; }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) { EVP_MD_CTX_free(mctx); return false; }
    if (EVP_DigestVerifyUpdate(mctx, msg, len) <= 0) { EVP_MD_CTX_free(mctx); return false; }
    int r = EVP_DigestVerifyFinal(mctx, sig, siglen);
    EVP_MD_CTX_free(mctx);
    return r == 1;
}

int main() {
    int fails = 0;
    const char* msg = "RSASSA-PSS test message for jpssl";
    const EVP_MD* mds[3] = { EVP_sha256(), EVP_sha384(), EVP_sha512() };
    jpssl::PssHash hashes[3] = { jpssl::PssHash::SHA256, jpssl::PssHash::SHA384, jpssl::PssHash::SHA512 };
    const char* names[3] = { "SHA-256", "SHA-384", "SHA-512" };
    size_t sig_sizes[3] = { 256, 256, 256 };
    (void)sig_sizes;

    // ── RSA-2048 ──
    printf("generating RSA-2048 key...\n");
    jpssl::rsa_public_key pub;
    jpssl::rsa_crt_key crt;
    if (!jpssl::rsa_keygen_crt(pub, crt)) { printf("RSA-2048 keygen failed\n"); return 1; }
    for (int h = 0; h < 3; ++h) {
        printf("=== RSA-2048 PSS %s ===\n", names[h]);
        uint8_t sig[256];
        bool ok = jpssl::rsassa_pss_sign(crt, (const uint8_t*)msg, strlen(msg), sig, 0, hashes[h]);
        printf("  our sign: %s\n", ok ? "PASS" : "FAIL");
        if (!ok) { ++fails; continue; }

        bool self_ok = jpssl::rsassa_pss_verify(pub, (const uint8_t*)msg, strlen(msg), sig, 0, hashes[h]);
        printf("  our verify (self): %s\n", self_ok ? "PASS" : "FAIL");
        if (!self_ok) ++fails;

        EVP_PKEY* pk = ossl_pub_evp(pub);
        bool ov = ossl_pss_verify(pk, mds[h], (const uint8_t*)msg, strlen(msg), sig, 256);
        printf("  our sign -> ossl verify: %s\n", ov ? "PASS" : "FAIL");
        if (!ov) ++fails;
        EVP_PKEY_free(pk);

        uint8_t ossig[256];
        size_t oslen = sizeof(ossig);
        RSA* rsa = ossl_rsa_from_crt(crt);
        bool os = ossl_pss_sign(rsa, mds[h], (const uint8_t*)msg, strlen(msg), ossig, &oslen);
        printf("  ossl sign: %s\n", os ? "PASS" : "FAIL");
        if (!os) { ++fails; continue; }
        bool our_ok = jpssl::rsassa_pss_verify(pub, (const uint8_t*)msg, strlen(msg), ossig, 0, hashes[h]);
        printf("  ossl sign -> our verify: %s\n", our_ok ? "PASS" : "FAIL");
        if (!our_ok) ++fails;

        sig[10] ^= 0x01;
        bool tamper_ok = jpssl::rsassa_pss_verify(pub, (const uint8_t*)msg, strlen(msg), sig, 0, hashes[h]);
        printf("  tampered sig rejected: %s\n", !tamper_ok ? "PASS" : "FAIL");
        if (tamper_ok) ++fails;
    }

    // ── RSA-4096 ──
    printf("generating RSA-4096 key...\n");
    jpssl::rsa4096_public_key pub4;
    jpssl::rsa4096_crt_key crt4;
    if (!jpssl::rsa4096_keygen_crt(pub4, crt4)) { printf("RSA-4096 keygen failed\n"); return 1; }
    for (int h = 0; h < 3; ++h) {
        printf("=== RSA-4096 PSS %s ===\n", names[h]);
        uint8_t sig[512];
        bool ok = jpssl::rsassa_pss_sign4096(crt4, (const uint8_t*)msg, strlen(msg), sig, 0, hashes[h]);
        printf("  our sign: %s\n", ok ? "PASS" : "FAIL");
        if (!ok) { ++fails; continue; }

        bool self_ok = jpssl::rsassa_pss_verify4096(pub4, (const uint8_t*)msg, strlen(msg), sig, 0, hashes[h]);
        printf("  our verify (self): %s\n", self_ok ? "PASS" : "FAIL");
        if (!self_ok) ++fails;

        EVP_PKEY* pk = ossl_pub_evp4096(pub4);
        bool ov = ossl_pss_verify(pk, mds[h], (const uint8_t*)msg, strlen(msg), sig, 512);
        printf("  our sign -> ossl verify: %s\n", ov ? "PASS" : "FAIL");
        if (!ov) ++fails;
        EVP_PKEY_free(pk);

        uint8_t ossig[512];
        size_t oslen = sizeof(ossig);
        RSA* rsa = ossl_rsa_from_crt4096(crt4);
        bool os = ossl_pss_sign(rsa, mds[h], (const uint8_t*)msg, strlen(msg), ossig, &oslen);
        printf("  ossl sign: %s\n", os ? "PASS" : "FAIL");
        if (!os) { ++fails; continue; }
        bool our_ok = jpssl::rsassa_pss_verify4096(pub4, (const uint8_t*)msg, strlen(msg), ossig, 0, hashes[h]);
        printf("  ossl sign -> our verify: %s\n", our_ok ? "PASS" : "FAIL");
        if (!our_ok) ++fails;

        sig[10] ^= 0x01;
        bool tamper_ok = jpssl::rsassa_pss_verify4096(pub4, (const uint8_t*)msg, strlen(msg), sig, 0, hashes[h]);
        printf("  tampered sig rejected: %s\n", !tamper_ok ? "PASS" : "FAIL");
        if (tamper_ok) ++fails;
    }

    printf("\n=== Result: %d failures ===\n", fails);
    return fails ? 1 : 0;
}
