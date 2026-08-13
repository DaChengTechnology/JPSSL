// bench_sig_multi.cpp — 公钥签名算法 多实现 × 多消息长度 × OpenSSL 对比基准
//
// 覆盖矩阵:
//   RSA-2048 / RSA-4096 : keygen / sign (PKCS#1 v1.5 + SHA-256) / verify
//   ECDSA P-256 / P-384 : keygen / sign / verify
//   Ed25519             : keygen / sign / verify (scalar=ref10, r51) + batch verify N=64/256
//   Ed448               : keygen / sign / verify (scalar) + batch verify N=64/256
//
// 消息长度矩阵: 32 / 256 / 1024 / 65536 字节 (签名/验签); keygen 与消息无关, size_bytes=0。
//
// 正确性自检: 每算法 jpssl <-> OpenSSL 互验签名, 任一 FAIL 则非零退出且不输出 CSV。
// 输出: stdout 人类可读表格 + benchmarks/results/bench_sig_multi.csv
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -Iinclude benchmarks/bench_sig_multi.cpp
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto
//       -o /tmp/bench_sig_multi

#include "rsa.hpp"
#include "rsa_mont_asm.hpp"
#include "ecdsa.hpp"
#include "ed25519.hpp"
#include "ed25519_batch.hpp"
#include "ed448.hpp"
#include "ed448_batch.hpp"
#include "cpu_features.hpp"
#include "sha256.hpp"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

// ─────────────────────────────────────────────────────────────────────
// 头文件未声明、但静态库已导出 (T 符号) 的后端实现声明
// （ed25519.hpp 只暴露 r51 公共 API；ref10 scalar 与 avx512 后端以
//   库符号为准手动声明，avx512 仅在 cpu_has_avx512() 时调用）
// ─────────────────────────────────────────────────────────────────────
namespace jpssl {
namespace ed25519_ref10_impl {
void ed25519_keygen(uint8_t pub[32], uint8_t priv[64]);
void ed25519_sign(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]);
bool ed25519_verify(const uint8_t pub[32], const uint8_t* msg, size_t msg_len,
                    const uint8_t sig[64]);
}
namespace avx512_impl {
void ed25519_keygen(uint8_t pub[32], uint8_t priv[64]);
void ed25519_sign(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]);
bool ed25519_verify(const uint8_t pub[32], const uint8_t* msg, size_t msg_len,
                    const uint8_t sig[64]);
}
namespace detail {
bool ed448_batch_verify_avx2(const uint8_t* const* pubs, const uint8_t* const* msgs,
                             const size_t* msg_lens, const uint8_t* const* sigs, int count);
bool ed448_batch_verify_avx512(const uint8_t* const* pubs, const uint8_t* const* msgs,
                               const size_t* msg_lens, const uint8_t* const* sigs, int count);
}
} // namespace jpssl

static volatile int g_sink = 0;

// ─────────────────────────────────────────────────────────────────────
// SHA-256 DigestInfo DER 前缀 (RFC 8017 §9.2 / RFC 3447)
// ─────────────────────────────────────────────────────────────────────
static const uint8_t kSha256DerPrefix[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};
static constexpr size_t kSha256PrefixLen = 19;

// ─────────────────────────────────────────────────────────────────────
// 消息长度矩阵 + 确定性消息数据
// ─────────────────────────────────────────────────────────────────────
static const std::array<size_t, 4> kSizes = {32, 256, 1024, 65536};

static std::vector<uint8_t> g_msg(size_t n) {
    std::vector<uint8_t> m(n);
    uint64_t x = 0x9e3779b97f4a7c15ull;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        m[i] = static_cast<uint8_t>(x);
    }
    return m;
}

// ─────────────────────────────────────────────────────────────────────
// CSV 行记录
// ─────────────────────────────────────────────────────────────────────
struct Row {
    std::string algo, impl;
    size_t size;
    double ns;
};
static std::vector<Row> g_rows;

static void emit_row(const char* algo, const char* impl, size_t size, double ns) {
    g_rows.push_back({algo, impl, size, ns});
    printf("  %-22s %-18s %6zu %13.1f ns/op %12.2f ops/s\n",
           algo, impl, size, ns, 1e9 / ns);
}

static int g_skip_count = 0;
static void skip(const char* msg) {
    ++g_skip_count;
    printf("  SKIP %s\n", msg);
}

// ─────────────────────────────────────────────────────────────────────
// 自适应迭代微基准: 每轮约 target_ms, rounds 轮取最小值 (参考 bench_ed25519_ossl.cpp)
// est_n: 首次耗时估计的调用次数 (keygen 等慢操作传 1)
// ─────────────────────────────────────────────────────────────────────
template <typename F>
static double auto_bench(const char* name, F&& f, double target_ms = 150.0,
                         int rounds = 3, int est_n = 8) {
    f(); // 预热
    auto t0 = Clock::now();
    for (int i = 0; i < est_n; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / est_n;
    if (est_ns < 1000.0) {  // 太快, 重新用更多次估计
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
    printf("  %-22s %-18s %6s %13.1f ns/op %12.2f ops/s   (iters=%lld)\n",
           name, "", "", best, 1e9 / best, iters);
    return best;
}

// ═════════════════════════════════════════════════════════════════════
//  OpenSSL 侧辅助
// ═════════════════════════════════════════════════════════════════════

// jpssl RSA 公钥 (n, e) → OpenSSL EVP_PKEY (public)
static EVP_PKEY* ossl_rsa_pub_from_n(const uint8_t* n_bytes, size_t n_len,
                                     const uint8_t* e_bytes, size_t e_len) {
    BIGNUM* bn_n = BN_bin2bn(n_bytes, (int)n_len, nullptr);
    BIGNUM* bn_e = BN_bin2bn(e_bytes, (int)e_len, nullptr);
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_fromdata_init(pctx);
    int ok = EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(pctx);
    BN_free(bn_n);
    BN_free(bn_e);
    return ok == 1 ? pkey : nullptr;
}

// OpenSSL 私钥 n/e 提取 → 大端字节
static bool ossl_rsa_get_n_e(EVP_PKEY* pkey, std::vector<uint8_t>& n, std::vector<uint8_t>& e) {
    BIGNUM *bn_n = nullptr, *bn_e = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n) != 1) return false;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn_e) != 1) { BN_free(bn_n); return false; }
    int nn = BN_num_bytes(bn_n), ne = BN_num_bytes(bn_e);
    n.assign((size_t)nn, 0);
    e.assign((size_t)ne, 0);
    BN_bn2bin(bn_n, n.data());
    BN_bn2bin(bn_e, e.data());
    BN_free(bn_n);
    BN_free(bn_e);
    return true;
}

// OpenSSL ECDSA: 从私钥派生 EC_KEY 并签 SHA-256/SHA-384 摘要, 输出固定 r||s
static bool ossl_ecdsa_sign_rs(int nid, const uint8_t* priv, int key_len,
                               const EVP_MD* md, int rs_len,
                               const uint8_t* msg, size_t msg_len, uint8_t* rs) {
    BIGNUM* d = BN_bin2bn(priv, key_len, nullptr);
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(nid);
    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, grp);
    EC_KEY_set_private_key(key, d);
    EC_POINT* Q = EC_POINT_new(grp);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_mul(grp, Q, d, nullptr, nullptr, ctx);
    EC_KEY_set_public_key(key, Q);

    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, md, nullptr);
    EVP_DigestUpdate(mctx, msg, msg_len);
    EVP_DigestFinal_ex(mctx, digest, &dlen);
    ECDSA_SIG* sig = ECDSA_do_sign(digest, dlen, key);

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    int rl = BN_num_bytes(r), sl = BN_num_bytes(s);
    memset(rs, 0, (size_t)rs_len);
    BN_bn2bin(r, rs + (rs_len / 2 - rl));
    BN_bn2bin(s, rs + rs_len - sl);

    ECDSA_SIG_free(sig);
    EVP_MD_CTX_free(mctx);
    BN_CTX_free(ctx);
    EC_POINT_free(Q);
    EC_KEY_free(key);
    EC_GROUP_free(grp);
    BN_free(d);
    return true;
}

// OpenSSL ECDSA 验签 (固定 r||s)
static bool ossl_ecdsa_verify_rs(int nid, const uint8_t* pub, int pub_len,
                                 const EVP_MD* md, int rs_len,
                                 const uint8_t* msg, size_t msg_len, const uint8_t* rs) {
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(nid);
    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, grp);
    BIGNUM* x = BN_bin2bn(pub, pub_len / 2, nullptr);
    BIGNUM* y = BN_bin2bn(pub + pub_len / 2, pub_len / 2, nullptr);
    EC_POINT* Q = EC_POINT_new(grp);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_set_affine_coordinates(grp, Q, x, y, ctx);
    EC_KEY_set_public_key(key, Q);

    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, md, nullptr);
    EVP_DigestUpdate(mctx, msg, msg_len);
    EVP_DigestFinal_ex(mctx, digest, &dlen);
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(rs, (int)(rs_len / 2), nullptr);
    BIGNUM* s = BN_bin2bn(rs + rs_len / 2, (int)(rs_len / 2), nullptr);
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

// ═════════════════════════════════════════════════════════════════════
//  jpssl RSA-4096 PKCS#1 v1.5 (头文件仅暴露 2048 的 rsassa 包装器,
//  4096 用公开原语 RSASP14096/RSAVP14096 复刻同一 EMSA 流程)
// ═════════════════════════════════════════════════════════════════════
static bool jpssl_rsa4096_pkcs1v15_sign(const jpssl::rsa4096_crt_key& key,
                                         const uint8_t* msg, size_t msgLen,
                                         const uint8_t* digestPrefix, size_t prefixLen,
                                         uint8_t sig[512]) {
    constexpr size_t k = 512;
    uint8_t digest[32];
    jpssl::sha256(msg, msgLen, digest);
    size_t hLen = 32;
    std::vector<uint8_t> T(prefixLen + hLen);
    memcpy(T.data(), digestPrefix, prefixLen);
    memcpy(T.data() + prefixLen, digest, hLen);
    size_t psLen = k - prefixLen - hLen - 3;
    if (psLen < 8) return false;
    uint8_t EM[512];
    EM[0] = 0x00; EM[1] = 0x01;
    memset(EM + 2, 0xFF, psLen);
    EM[2 + psLen] = 0x00;
    memcpy(EM + 2 + psLen + 1, T.data(), T.size());
    jpssl::rsa4096_bignum m = jpssl::rsa4096_bignum::from_bytes(EM, 512);
    jpssl::rsa4096_bignum s;
    jpssl::RSASP14096(key, m, s);
    s.to_bytes(sig);
    return true;
}

static bool jpssl_rsa4096_pkcs1v15_verify(const jpssl::rsa4096_public_key& pub,
                                          const uint8_t* msg, size_t msgLen,
                                          const uint8_t* digestPrefix, size_t prefixLen,
                                          const uint8_t sig[512]) {
    constexpr size_t k = 512;
    jpssl::rsa4096_bignum sbn = jpssl::rsa4096_bignum::from_bytes(sig, 512);
    jpssl::rsa4096_bignum mbn;
    jpssl::RSAVP14096(pub, sbn, mbn);
    uint8_t EM[512];
    mbn.to_bytes(EM);
    if (EM[0] != 0x00 || EM[1] != 0x01) return false;
    size_t pos = 2;
    while (pos < k && EM[pos] == 0xFF) ++pos;
    if (pos == k || EM[pos] != 0x00) return false;
    if (pos - 2 < 8) return false;
    ++pos;
    size_t tLen = prefixLen + 32;
    if (k - pos < tLen) return false;
    if (memcmp(EM + pos, digestPrefix, prefixLen) != 0) return false;
    uint8_t digest[32];
    jpssl::sha256(msg, msgLen, digest);
    return memcmp(EM + pos + prefixLen, digest, 32) == 0;
}

// ═════════════════════════════════════════════════════════════════════
//  互操作自检
// ═════════════════════════════════════════════════════════════════════
static int g_fail = 0;
static void selfcheck(const char* algo, bool jp2os, bool os2jp) {
    const char* j = jp2os ? "PASS" : "FAIL";
    const char* o = os2jp ? "PASS" : "FAIL";
    printf("  interop %-28s jpssl->openssl %-4s  openssl->jpssl %s\n", algo, j, o);
    if (!jp2os || !os2jp) ++g_fail;
}

// ── RSA ──────────────────────────────────────────────────────────────
struct RsaCtx2048 {
    jpssl::rsa_public_key pub;
    jpssl::rsa_crt_key crt;
    uint8_t sig[256];
    EVP_PKEY* ossl_key = nullptr;   // OpenSSL 自生成密钥 (keygen 基准 + 互操作)
    uint8_t ossl_sig[256];
};
struct RsaCtx4096 {
    jpssl::rsa4096_public_key pub;
    jpssl::rsa4096_crt_key crt;
    uint8_t sig[512];
    EVP_PKEY* ossl_key = nullptr;
    uint8_t ossl_sig[512];
};

static bool rsa2048_selfcheck(RsaCtx2048& c, const uint8_t* msg, size_t msglen) {
    bool ok = jpssl::rsa_keygen_crt(c.pub, c.crt);
    if (!ok) { printf("  rsa2048 keygen failed\n"); return false; }

    // jpssl 签 → OpenSSL 验
    jpssl::rsassa_pkcs1v15_sign(c.crt, msg, msglen, kSha256DerPrefix, kSha256PrefixLen, c.sig);
    uint8_t nbuf[256], ebuf[256];
    c.pub.n.to_bytes(nbuf);
    c.pub.e.to_bytes(ebuf);
    EVP_PKEY* jp_pub = ossl_rsa_pub_from_n(nbuf, 256, ebuf, 256);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool jp2os = jp_pub != nullptr
        && EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, jp_pub) == 1
        && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mctx), RSA_PKCS1_PADDING) == 1
        && EVP_DigestVerify(mctx, c.sig, 256, msg, msglen) == 1;

    // OpenSSL keygen + 签 → jpssl 验
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    bool kg = EVP_PKEY_keygen(kctx, &c.ossl_key) == 1;
    EVP_PKEY_CTX_free(kctx);
    size_t slen = 256;
    bool sgn = false;
    if (kg) {
        EVP_MD_CTX* sm = EVP_MD_CTX_new();
        EVP_PKEY_CTX* spctx = nullptr;
        sgn = EVP_DigestSignInit(sm, &spctx, EVP_sha256(), nullptr, c.ossl_key) == 1
            && EVP_PKEY_CTX_set_rsa_padding(spctx, RSA_PKCS1_PADDING) == 1
            && EVP_DigestSign(sm, c.ossl_sig, &slen, msg, msglen) == 1;
        EVP_MD_CTX_free(sm);
    }
    bool os2jp = false;
    if (sgn) {
        std::vector<uint8_t> n, e;
        if (ossl_rsa_get_n_e(c.ossl_key, n, e)) {
            jpssl::rsa_public_key pub;
            pub.n = jpssl::rsa_bignum::from_bytes(n.data(), 256);
            pub.e = jpssl::rsa_bignum::from_bytes(e.data(), e.size());
            os2jp = jpssl::rsassa_pkcs1v15_verify(pub, msg, msglen,
                                                  kSha256DerPrefix, kSha256PrefixLen, c.ossl_sig);
        }
    }
    selfcheck("rsa2048 PKCS1+SHA256", jp2os, os2jp);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(jp_pub);
    return jp2os && os2jp;
}

static bool rsa4096_selfcheck(RsaCtx4096& c, const uint8_t* msg, size_t msglen) {
    bool ok = jpssl::rsa4096_keygen_crt(c.pub, c.crt);
    if (!ok) { printf("  rsa4096 keygen failed\n"); return false; }

    jpssl_rsa4096_pkcs1v15_sign(c.crt, msg, msglen, kSha256DerPrefix, kSha256PrefixLen, c.sig);
    uint8_t nbuf[512], ebuf[512];
    c.pub.n.to_bytes(nbuf);
    c.pub.e.to_bytes(ebuf);
    EVP_PKEY* jp_pub = ossl_rsa_pub_from_n(nbuf, 512, ebuf, 512);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool jp2os = jp_pub != nullptr
        && EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, jp_pub) == 1
        && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mctx), RSA_PKCS1_PADDING) == 1
        && EVP_DigestVerify(mctx, c.sig, 512, msg, msglen) == 1;

    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 4096);
    bool kg = EVP_PKEY_keygen(kctx, &c.ossl_key) == 1;
    EVP_PKEY_CTX_free(kctx);
    size_t slen = 512;
    bool sgn = false;
    if (kg) {
        EVP_MD_CTX* sm = EVP_MD_CTX_new();
        EVP_PKEY_CTX* spctx = nullptr;
        sgn = EVP_DigestSignInit(sm, &spctx, EVP_sha256(), nullptr, c.ossl_key) == 1
            && EVP_PKEY_CTX_set_rsa_padding(spctx, RSA_PKCS1_PADDING) == 1
            && EVP_DigestSign(sm, c.ossl_sig, &slen, msg, msglen) == 1;
        EVP_MD_CTX_free(sm);
    }
    bool os2jp = false;
    if (sgn) {
        std::vector<uint8_t> n, e;
        if (ossl_rsa_get_n_e(c.ossl_key, n, e)) {
            jpssl::rsa4096_public_key pub;
            pub.n = jpssl::rsa4096_bignum::from_bytes(n.data(), 512);
            pub.e = jpssl::rsa4096_bignum::from_bytes(e.data(), e.size());
            os2jp = jpssl_rsa4096_pkcs1v15_verify(pub, msg, msglen,
                                                  kSha256DerPrefix, kSha256PrefixLen, c.ossl_sig);
        }
    }
    selfcheck("rsa4096 PKCS1+SHA256", jp2os, os2jp);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(jp_pub);
    return jp2os && os2jp;
}

// ── ECDSA ────────────────────────────────────────────────────────────
struct EcdsaCtx {
    int nid;
    const EVP_MD* md;
    int key_len, pub_len, sig_len;
    uint8_t pub[96], priv[48], sig[96];
};

static bool ecdsa_selfcheck(EcdsaCtx& c, const uint8_t* msg, size_t msglen) {
    if (c.key_len == 32) jpssl::ecdsa_p256_keygen(c.pub, c.priv);
    else                 jpssl::ecdsa_p384_keygen(c.pub, c.priv);
    if (c.key_len == 32) jpssl::ecdsa_p256_sign(c.priv, msg, msglen, c.sig);
    else                 jpssl::ecdsa_p384_sign(c.priv, msg, msglen, c.sig);

    bool jp2os = ossl_ecdsa_verify_rs(c.nid, c.pub, c.pub_len, c.md, c.sig_len,
                                      msg, msglen, c.sig);
    uint8_t osig[96];
    ossl_ecdsa_sign_rs(c.nid, c.priv, c.key_len, c.md, c.sig_len, msg, msglen, osig);
    bool os2jp = (c.key_len == 32) ? jpssl::ecdsa_p256_verify(c.pub, msg, msglen, osig)
                                   : jpssl::ecdsa_p384_verify(c.pub, msg, msglen, osig);
    selfcheck(c.key_len == 32 ? "ecdsa-p256 SHA-256" : "ecdsa-p384 SHA-384", jp2os, os2jp);
    return jp2os && os2jp;
}

// ── Ed25519 ──────────────────────────────────────────────────────────
struct Ed25519Ctx {
    uint8_t pub[32], priv[64], sig[64];
    uint8_t ossl_pub[32], ossl_sig[64];
    EVP_PKEY* ossl_key = nullptr;
    EVP_PKEY* ossl_pubkey = nullptr;
    std::vector<std::array<uint8_t, 32>> bpubs;
    std::vector<std::array<uint8_t, 64>> bprivs;
    std::vector<std::array<uint8_t, 64>> bsigs;
    std::vector<EVP_PKEY*> ovpubs;
};

static bool ed25519_selfcheck(Ed25519Ctx& c, const uint8_t* msg, size_t msglen) {
    jpssl::ed25519_keygen(c.pub, c.priv);
    jpssl::ed25519_sign(c.priv, msg, msglen, c.sig);

    c.ossl_pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, c.pub, 32);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool jp2os = c.ossl_pubkey != nullptr
        && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, c.ossl_pubkey) == 1
        && EVP_DigestVerify(mctx, c.sig, 64, msg, msglen) == 1;

    c.ossl_key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    size_t plen = 32;
    EVP_PKEY_get_raw_public_key(c.ossl_key, c.ossl_pub, &plen);
    size_t slen = 64;
    bool sgn = c.ossl_key != nullptr
        && EVP_MD_CTX_reset(mctx) == 1
        && EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, c.ossl_key) == 1
        && EVP_DigestSign(mctx, c.ossl_sig, &slen, msg, msglen) == 1;
    bool os2jp_r51 = sgn && jpssl::ed25519_verify_r51(c.ossl_pub, msg, msglen, c.ossl_sig);
    bool os2jp_scalar = sgn && jpssl::ed25519_ref10_impl::ed25519_verify(c.ossl_pub, msg, msglen, c.ossl_sig);
    selfcheck("ed25519 (r51+scalar)", jp2os, os2jp_r51 && os2jp_scalar);
    EVP_MD_CTX_free(mctx);

    // 批量验签数据集 (256 组)
    constexpr int BN = 256;
    c.bpubs.resize(BN); c.bprivs.resize(BN); c.bsigs.resize(BN);
    for (int i = 0; i < BN; ++i) {
        jpssl::ed25519_keygen(c.bpubs[i].data(), c.bprivs[i].data());
        jpssl::ed25519_sign(c.bprivs[i].data(), msg, msglen, c.bsigs[i].data());
        c.ovpubs.push_back(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                       c.bpubs[i].data(), 32));
    }
    return jp2os && os2jp_r51 && os2jp_scalar;
}

// ── Ed448 ────────────────────────────────────────────────────────────
struct Ed448Ctx {
    uint8_t pub[57], priv[114], sig[114];
    uint8_t ossl_pub[57], ossl_sig[114];
    EVP_PKEY* ossl_key = nullptr;
    EVP_PKEY* ossl_pubkey = nullptr;
    std::vector<std::array<uint8_t, 57>> bpubs;
    std::vector<std::array<uint8_t, 114>> bprivs, bsigs;
    std::vector<EVP_PKEY*> ovpubs;
};

static bool ed448_selfcheck(Ed448Ctx& c, const uint8_t* msg, size_t msglen) {
    jpssl::ed448_generate_keypair(c.pub, c.priv);
    jpssl::ed448_sign(c.priv, msg, msglen, c.sig);

    c.ossl_pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr, c.pub, 57);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool jp2os = c.ossl_pubkey != nullptr
        && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, c.ossl_pubkey) == 1
        && EVP_DigestVerify(mctx, c.sig, 114, msg, msglen) == 1;

    c.ossl_key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED448");
    size_t plen = 57;
    EVP_PKEY_get_raw_public_key(c.ossl_key, c.ossl_pub, &plen);
    size_t slen = 114;
    bool sgn = c.ossl_key != nullptr
        && EVP_MD_CTX_reset(mctx) == 1
        && EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, c.ossl_key) == 1
        && EVP_DigestSign(mctx, c.ossl_sig, &slen, msg, msglen) == 1;
    bool os2jp = sgn && jpssl::ed448_verify(c.ossl_pub, msg, msglen, c.ossl_sig);
    selfcheck("ed448", jp2os, os2jp);
    EVP_MD_CTX_free(mctx);

    constexpr int BN = 256;
    c.bpubs.resize(BN); c.bprivs.resize(BN); c.bsigs.resize(BN);
    for (int i = 0; i < BN; ++i) {
        jpssl::ed448_keygen(c.bpubs[i].data(), c.bprivs[i].data());
        jpssl::ed448_sign(c.bprivs[i].data(), msg, msglen, c.bsigs[i].data());
        c.ovpubs.push_back(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr,
                                                       c.bpubs[i].data(), 57));
    }
    return jp2os && os2jp;
}

// ═════════════════════════════════════════════════════════════════════
//  main
// ═════════════════════════════════════════════════════════════════════
int main() {
    const auto feats = jpssl::cpu_features::detect();
    printf("=== bench_sig_multi: jpssl vs OpenSSL ===\n");
    printf("OpenSSL : %s\n", OPENSSL_VERSION_TEXT);
    printf("CPU     : x86_64  AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES=%d SHA-NI=%d ADX=%d\n",
           feats.aesni ? 1 : 0, feats.avx2 ? 1 : 0, feats.pclmulqdq ? 1 : 0,
           feats.avx512 ? 1 : 0, feats.vpclmulqdq_vaes ? 1 : 0,
           feats.sha_ni ? 1 : 0, jpssl::cpu_has_adx() ? 1 : 0);
    printf("Montgomery asm (MULX+ADX) available : %s\n",
           jpssl::mont_mul_asm_available() ? "yes" : "no");

    std::vector<std::vector<uint8_t>> msgs;
    for (size_t s : kSizes) msgs.push_back(g_msg(s));
    const uint8_t* m32 = msgs[0].data();   // 32B 消息 (自检/批量统一用)
    const size_t m32len = msgs[0].size();

    // ── 1. 互操作自检 ────────────────────────────────────────────────
    printf("\n=== interop self-tests ===\n");
    RsaCtx2048 rsa2048;
    RsaCtx4096 rsa4096;
    EcdsaCtx ec_p256{NID_X9_62_prime256v1, EVP_sha256(), 32, 64, 64, {}, {}, {}};
    EcdsaCtx ec_p384{NID_secp384r1, EVP_sha384(), 48, 96, 96, {}, {}, {}};
    Ed25519Ctx ed25519;
    Ed448Ctx ed448;

    if (!rsa2048_selfcheck(rsa2048, m32, m32len)) ++g_fail;
    if (!rsa4096_selfcheck(rsa4096, m32, m32len)) ++g_fail;
    if (!ecdsa_selfcheck(ec_p256, m32, m32len)) ++g_fail;
    if (!ecdsa_selfcheck(ec_p384, m32, m32len)) ++g_fail;
    if (!ed25519_selfcheck(ed25519, m32, m32len)) ++g_fail;
    if (!ed448_selfcheck(ed448, m32, m32len)) ++g_fail;

    // 批量 API 自检
    {
        std::vector<const uint8_t*> pubp, sigp, msgp;
        std::vector<size_t> lens;
        for (int i = 0; i < 256; ++i) {
            pubp.push_back(ed25519.bpubs[i].data());
            sigp.push_back(ed25519.bsigs[i].data());
            msgp.push_back(m32);
            lens.push_back(m32len);
        }
        bool ok25519 = jpssl::ed25519_batch_verify(pubp.data(), msgp.data(), lens.data(),
                                                   sigp.data(), 256);
        printf("  batch selfcheck ed25519_batch_verify x256 : %s\n", ok25519 ? "PASS" : "FAIL");
        if (!ok25519) ++g_fail;
    }
    {
        std::vector<const uint8_t*> pubp, sigp, msgp;
        std::vector<size_t> lens;
        for (int i = 0; i < 256; ++i) {
            pubp.push_back(ed448.bpubs[i].data());
            sigp.push_back(ed448.bsigs[i].data());
            msgp.push_back(m32);
            lens.push_back(m32len);
        }
        bool ok448 = jpssl::ed448_batch_verify(pubp.data(), msgp.data(), lens.data(),
                                               sigp.data(), 256);
        printf("  batch selfcheck ed448_batch_verify x256   : %s\n", ok448 ? "PASS" : "FAIL");
        if (!ok448) ++g_fail;
    }

    if (g_fail) {
        printf("\ninterop FAILED (%d), abort without CSV\n", g_fail);
        return 1;
    }
    printf("all interop self-tests PASS\n");

    // ── 2. 多实现 SKIP 说明 ──────────────────────────────────────────
    printf("\n=== SKIPs (不支持的实现, 绝不被调用) ===\n");
    if (!feats.avx512) {
        skip("ed25519-avx512 keygen/sign/verify : cpu_has_avx512()=false (本机无 AVX512, 调用会 SIGILL)");
        skip("ed448-batch-avx512 : cpu_has_avx512()=false");
    }
    skip("ed448-avx2-sign / ed448-avx512-sign : 头文件与库均未导出 Ed448 SIMD 签名变体 (仅批量验签后端存在, 见下)");
    printf("  note: ed448_batch_verify 在本机自动分派到 AVX2 后端 (batch_size=%d)\n",
           jpssl::ed448_batch_size());

    // ── 3. 基准测量 ──────────────────────────────────────────────────
    printf("\n=== RSA-2048 ===\n");
    printf("  --- keygen (size=0) ---\n");
    auto rsa2048_kg_jp = auto_bench("rsa2048-keygen", [&] {
        jpssl::rsa_public_key pub; jpssl::rsa_crt_key crt;
        jpssl::rsa_keygen_crt(pub, crt);
        g_sink ^= pub.n.d[0];
    }, 200.0, 3, 1);
    emit_row("rsa2048-keygen", "jpssl", 0, rsa2048_kg_jp);

    auto rsa2048_kg_os = auto_bench("rsa2048-keygen", [&] {
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(kctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
        EVP_PKEY* k = nullptr;
        EVP_PKEY_keygen(kctx, &k);
        EVP_PKEY_CTX_free(kctx);
        if (k) EVP_PKEY_free(k);
    }, 200.0, 3, 1);
    emit_row("rsa2048-keygen", "openssl", 0, rsa2048_kg_os);

    printf("  --- sign / verify (size=32,256,1024,65536) ---\n");
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    for (size_t size : kSizes) {
        const uint8_t* m = msgs[std::distance(kSizes.begin(), std::find(kSizes.begin(), kSizes.end(), size))].data();
        uint8_t sigbuf[256];

        double s_jp = auto_bench("rsa2048-sign", [&] {
            jpssl::rsassa_pkcs1v15_sign(rsa2048.crt, m, size, kSha256DerPrefix, kSha256PrefixLen, sigbuf);
            g_sink ^= sigbuf[0];
        });
        emit_row("rsa2048-sign", "jpssl", size, s_jp);

        double s_os = auto_bench("rsa2048-sign", [&] {
            EVP_PKEY_CTX* pctx = nullptr;
            size_t sl = 256;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), nullptr, rsa2048.ossl_key);
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
            EVP_DigestSign(mctx, sigbuf, &sl, m, size);
            g_sink ^= sigbuf[0];
        });
        emit_row("rsa2048-sign", "openssl", size, s_os);

        double v_jp = auto_bench("rsa2048-verify", [&] {
            g_sink ^= jpssl::rsassa_pkcs1v15_verify(rsa2048.pub, m, size,
                                                    kSha256DerPrefix, kSha256PrefixLen, rsa2048.sig) ? 1 : 0;
        });
        emit_row("rsa2048-verify", "jpssl", size, v_jp);

        double v_os = auto_bench("rsa2048-verify", [&] {
            EVP_PKEY_CTX* pctx = nullptr;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestVerifyInit(mctx, &pctx, EVP_sha256(), nullptr, rsa2048.ossl_key);
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
            int r = EVP_DigestVerify(mctx, rsa2048.ossl_sig, 256, m, size);
            g_sink ^= r;
        });
        emit_row("rsa2048-verify", "openssl", size, v_os);
    }

    printf("  --- Montgomery modpow 多实现对比 (d 指数, size=0) ---\n");
    {
        jpssl::mont_ctx mc = jpssl::rsa_mont_init(rsa2048.pub.n);
        jpssl::rsa_bignum base = jpssl::rsa_bignum::from_bytes(m32, 256);
        jpssl::rsa_bignum out;
        double m1 = auto_bench("rsa2048-modpow", [&] {
            jpssl::rsa_mont_modpow(out, base, rsa2048.crt.d, mc, rsa2048.pub.n);
            g_sink ^= out.d[0];
        }, 150.0, 3, 1);
        emit_row("rsa2048-modpow", "jpssl-mont", 0, m1);
        double m2 = auto_bench("rsa2048-modpow", [&] {
            jpssl::rsa_mont_modpow_win(out, base, rsa2048.crt.d, mc, rsa2048.pub.n);
            g_sink ^= out.d[0];
        }, 150.0, 3, 1);
        emit_row("rsa2048-modpow", "jpssl-montwin", 0, m2);
    }

    printf("\n=== RSA-4096 ===\n");
    printf("  --- keygen (size=0) ---\n");
    auto rsa4096_kg_jp = auto_bench("rsa4096-keygen", [&] {
        jpssl::rsa4096_public_key pub; jpssl::rsa4096_crt_key crt;
        jpssl::rsa4096_keygen_crt(pub, crt);
        g_sink ^= pub.n.d[0];
    }, 300.0, 3, 1);
    emit_row("rsa4096-keygen", "jpssl", 0, rsa4096_kg_jp);

    auto rsa4096_kg_os = auto_bench("rsa4096-keygen", [&] {
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(kctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 4096);
        EVP_PKEY* k = nullptr;
        EVP_PKEY_keygen(kctx, &k);
        EVP_PKEY_CTX_free(kctx);
        if (k) EVP_PKEY_free(k);
    }, 300.0, 3, 1);
    emit_row("rsa4096-keygen", "openssl", 0, rsa4096_kg_os);

    printf("  --- sign / verify (size=32,256,1024,65536) ---\n");
    for (size_t size : kSizes) {
        const uint8_t* m = msgs[std::distance(kSizes.begin(), std::find(kSizes.begin(), kSizes.end(), size))].data();
        uint8_t sigbuf[512];

        double s_jp = auto_bench("rsa4096-sign", [&] {
            jpssl_rsa4096_pkcs1v15_sign(rsa4096.crt, m, size, kSha256DerPrefix, kSha256PrefixLen, sigbuf);
            g_sink ^= sigbuf[0];
        });
        emit_row("rsa4096-sign", "jpssl", size, s_jp);

        double s_os = auto_bench("rsa4096-sign", [&] {
            EVP_PKEY_CTX* pctx = nullptr;
            size_t sl = 512;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), nullptr, rsa4096.ossl_key);
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
            EVP_DigestSign(mctx, sigbuf, &sl, m, size);
            g_sink ^= sigbuf[0];
        });
        emit_row("rsa4096-sign", "openssl", size, s_os);

        double v_jp = auto_bench("rsa4096-verify", [&] {
            g_sink ^= jpssl_rsa4096_pkcs1v15_verify(rsa4096.pub, m, size,
                                                    kSha256DerPrefix, kSha256PrefixLen, rsa4096.sig) ? 1 : 0;
        });
        emit_row("rsa4096-verify", "jpssl", size, v_jp);

        double v_os = auto_bench("rsa4096-verify", [&] {
            EVP_PKEY_CTX* pctx = nullptr;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestVerifyInit(mctx, &pctx, EVP_sha256(), nullptr, rsa4096.ossl_key);
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
            int r = EVP_DigestVerify(mctx, rsa4096.ossl_sig, 512, m, size);
            g_sink ^= r;
        });
        emit_row("rsa4096-verify", "openssl", size, v_os);
    }

    printf("  --- Montgomery modpow 多实现对比 (d 指数, size=0) ---\n");
    {
        jpssl::mont_ctx4096 mc = jpssl::rsa4096_mont_init(rsa4096.pub.n);
        jpssl::rsa4096_bignum base = jpssl::rsa4096_bignum::from_bytes(m32, 512);
        jpssl::rsa4096_bignum out;
        double m1 = auto_bench("rsa4096-modpow", [&] {
            jpssl::rsa4096_mont_modpow(out, base, rsa4096.crt.d, mc, rsa4096.pub.n);
            g_sink ^= out.d[0];
        }, 150.0, 3, 1);
        emit_row("rsa4096-modpow", "jpssl-mont", 0, m1);
        double m2 = auto_bench("rsa4096-modpow", [&] {
            jpssl::rsa4096_mont_modpow_win(out, base, rsa4096.crt.d, mc, rsa4096.pub.n);
            g_sink ^= out.d[0];
        }, 150.0, 3, 1);
        emit_row("rsa4096-modpow", "jpssl-montwin", 0, m2);
    }

    printf("\n=== ECDSA ===\n");
    // P-256
    {
        uint8_t pub[64], priv[32], sig[64];
        printf("  --- P-256 keygen / sign / verify ---\n");
        auto kg = auto_bench("ecdsa-p256-keygen", [&] { jpssl::ecdsa_p256_keygen(pub, priv); });
        emit_row("ecdsa-p256-keygen", "jpssl", 0, kg);
        EC_KEY* eck = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        auto kg_os = auto_bench("ecdsa-p256-keygen", [&] { EC_KEY_generate_key(eck); });
        emit_row("ecdsa-p256-keygen", "openssl", 0, kg_os);

        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int dlen = 0;
        EVP_MD_CTX* dctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(dctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(dctx, m32, m32len);
        EVP_DigestFinal_ex(dctx, digest, &dlen);
        ECDSA_SIG* sig_os = ECDSA_do_sign(digest, dlen, eck);
        for (size_t size : kSizes) {
            const uint8_t* m = msgs[std::distance(kSizes.begin(), std::find(kSizes.begin(), kSizes.end(), size))].data();
            double sj = auto_bench("ecdsa-p256-sign", [&] { jpssl::ecdsa_p256_sign(priv, m, size, sig); g_sink ^= sig[0]; });
            emit_row("ecdsa-p256-sign", "jpssl", size, sj);
            double so = auto_bench("ecdsa-p256-sign", [&] { ECDSA_SIG_free(ECDSA_do_sign(digest, dlen, eck)); });
            emit_row("ecdsa-p256-sign", "openssl", size, so);
            double vj = auto_bench("ecdsa-p256-verify", [&] { g_sink ^= jpssl::ecdsa_p256_verify(pub, m, size, sig) ? 1 : 0; });
            emit_row("ecdsa-p256-verify", "jpssl", size, vj);
            double vo = auto_bench("ecdsa-p256-verify", [&] { ECDSA_do_verify(digest, dlen, sig_os, eck); });
            emit_row("ecdsa-p256-verify", "openssl", size, vo);
        }
        ECDSA_SIG_free(sig_os);
        EC_KEY_free(eck);
        EVP_MD_CTX_free(dctx);
    }
    // P-384
    {
        uint8_t pub[96], priv[48], sig[96];
        printf("  --- P-384 keygen / sign / verify ---\n");
        auto kg = auto_bench("ecdsa-p384-keygen", [&] { jpssl::ecdsa_p384_keygen(pub, priv); });
        emit_row("ecdsa-p384-keygen", "jpssl", 0, kg);
        EC_KEY* eck = EC_KEY_new_by_curve_name(NID_secp384r1);
        auto kg_os = auto_bench("ecdsa-p384-keygen", [&] { EC_KEY_generate_key(eck); });
        emit_row("ecdsa-p384-keygen", "openssl", 0, kg_os);

        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int dlen = 0;
        EVP_MD_CTX* dctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(dctx, EVP_sha384(), nullptr);
        EVP_DigestUpdate(dctx, m32, m32len);
        EVP_DigestFinal_ex(dctx, digest, &dlen);
        ECDSA_SIG* sig_os = ECDSA_do_sign(digest, dlen, eck);
        for (size_t size : kSizes) {
            const uint8_t* m = msgs[std::distance(kSizes.begin(), std::find(kSizes.begin(), kSizes.end(), size))].data();
            double sj = auto_bench("ecdsa-p384-sign", [&] { jpssl::ecdsa_p384_sign(priv, m, size, sig); g_sink ^= sig[0]; });
            emit_row("ecdsa-p384-sign", "jpssl", size, sj);
            double so = auto_bench("ecdsa-p384-sign", [&] { ECDSA_SIG_free(ECDSA_do_sign(digest, dlen, eck)); });
            emit_row("ecdsa-p384-sign", "openssl", size, so);
            double vj = auto_bench("ecdsa-p384-verify", [&] { g_sink ^= jpssl::ecdsa_p384_verify(pub, m, size, sig) ? 1 : 0; });
            emit_row("ecdsa-p384-verify", "jpssl", size, vj);
            double vo = auto_bench("ecdsa-p384-verify", [&] { ECDSA_do_verify(digest, dlen, sig_os, eck); });
            emit_row("ecdsa-p384-verify", "openssl", size, vo);
        }
        ECDSA_SIG_free(sig_os);
        EC_KEY_free(eck);
        EVP_MD_CTX_free(dctx);
    }

    printf("\n=== Ed25519 ===\n");
    printf("  --- keygen (size=0) ---\n");
    {
        auto k1 = auto_bench("ed25519-keygen", [] {
            uint8_t pub[32], priv[64];
            jpssl::ed25519_ref10_impl::ed25519_keygen(pub, priv);
            g_sink ^= pub[0] ^ priv[0];
        });
        emit_row("ed25519-keygen", "jpssl-scalar", 0, k1);
        auto k2 = auto_bench("ed25519-keygen", [] {
            uint8_t pub[32], priv[64];
            jpssl::ed25519_keygen_r51(pub, priv);
            g_sink ^= pub[0] ^ priv[0];
        });
        emit_row("ed25519-keygen", "jpssl-r51", 0, k2);
        auto k3 = auto_bench("ed25519-keygen", [] {
            EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
            if (k) EVP_PKEY_free(k);
        });
        emit_row("ed25519-keygen", "openssl", 0, k3);
        if (feats.avx512) {
            auto k4 = auto_bench("ed25519-keygen", [] {
                uint8_t pub[32], priv[64];
                jpssl::avx512_impl::ed25519_keygen(pub, priv);
                g_sink ^= pub[0] ^ priv[0];
            });
            emit_row("ed25519-keygen", "jpssl-avx512", 0, k4);
        }
    }
    printf("  --- sign / verify (size=32,256,1024,65536) ---\n");
    for (size_t size : kSizes) {
        const uint8_t* m = msgs[std::distance(kSizes.begin(), std::find(kSizes.begin(), kSizes.end(), size))].data();
        uint8_t sig[64];

        double s1 = auto_bench("ed25519-sign", [&] {
            jpssl::ed25519_ref10_impl::ed25519_sign(ed25519.priv, m, size, sig);
            g_sink ^= sig[0];
        });
        emit_row("ed25519-sign", "jpssl-scalar", size, s1);

        double s2 = auto_bench("ed25519-sign", [&] {
            jpssl::ed25519_sign_r51(ed25519.priv, m, size, sig);
            g_sink ^= sig[0];
        });
        emit_row("ed25519-sign", "jpssl-r51", size, s2);

        double s3 = auto_bench("ed25519-sign", [&] {
            size_t sl = 64;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ed25519.ossl_key);
            EVP_DigestSign(mctx, sig, &sl, m, size);
            g_sink ^= sig[0];
        });
        emit_row("ed25519-sign", "openssl", size, s3);

        if (feats.avx512) {
            double s4 = auto_bench("ed25519-sign", [&] {
                jpssl::avx512_impl::ed25519_sign(ed25519.priv, m, size, sig);
                g_sink ^= sig[0];
            });
            emit_row("ed25519-sign", "jpssl-avx512", size, s4);
        }

        double v1 = auto_bench("ed25519-verify", [&] {
            g_sink ^= jpssl::ed25519_ref10_impl::ed25519_verify(ed25519.pub, m, size, ed25519.sig) ? 1 : 0;
        });
        emit_row("ed25519-verify", "jpssl-scalar", size, v1);

        double v2 = auto_bench("ed25519-verify", [&] {
            g_sink ^= jpssl::ed25519_verify_r51(ed25519.pub, m, size, ed25519.sig) ? 1 : 0;
        });
        emit_row("ed25519-verify", "jpssl-r51", size, v2);

        double v3 = auto_bench("ed25519-verify", [&] {
            EVP_MD_CTX_reset(mctx);
            EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ed25519.ossl_pubkey);
            int r = EVP_DigestVerify(mctx, ed25519.sig, 64, m, size);
            g_sink ^= r;
        });
        emit_row("ed25519-verify", "openssl", size, v3);
    }
    printf("  --- batch verify (size=32, N=64/256) ---\n");
    {
        std::vector<const uint8_t*> pubp, sigp, msgp;
        std::vector<size_t> lens;
        for (int i = 0; i < 256; ++i) {
            pubp.push_back(ed25519.bpubs[i].data());
            sigp.push_back(ed25519.bsigs[i].data());
            msgp.push_back(m32);
            lens.push_back(m32len);
        }
        for (int n : {64, 256}) {
            double b = auto_bench("ed25519-batch", [&] {
                g_sink ^= jpssl::ed25519_batch_verify(pubp.data(), msgp.data(), lens.data(),
                                                      sigp.data(), n) ? 1 : 0;
            });
            char impl[32];
            std::snprintf(impl, sizeof impl, "jpssl-batch%d", n);
            emit_row("ed25519-batch", impl, m32len, b);

            double o = auto_bench("ed25519-batch", [&] {
                int r = 0;
                for (int i = 0; i < n; ++i) {
                    EVP_MD_CTX_reset(mctx);
                    EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ed25519.ovpubs[i]);
                    r ^= EVP_DigestVerify(mctx, ed25519.bsigs[i].data(), 64, m32, m32len);
                }
                g_sink ^= r;
            });
            emit_row("ed25519-batch", "openssl", m32len, o);
        }
    }

    printf("\n=== Ed448 ===\n");
    printf("  --- keygen (size=0) ---\n");
    {
        auto k1 = auto_bench("ed448-keygen", [] {
            uint8_t pub[57], priv[114];
            jpssl::ed448_generate_keypair(pub, priv);
            g_sink ^= pub[0] ^ priv[0];
        });
        emit_row("ed448-keygen", "jpssl-scalar", 0, k1);
        auto k2 = auto_bench("ed448-keygen", [] {
            EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED448");
            if (k) EVP_PKEY_free(k);
        });
        emit_row("ed448-keygen", "openssl", 0, k2);
    }
    printf("  --- sign / verify (size=32,256,1024,65536) ---\n");
    for (size_t size : kSizes) {
        const uint8_t* m = msgs[std::distance(kSizes.begin(), std::find(kSizes.begin(), kSizes.end(), size))].data();
        uint8_t sig[114];

        double s1 = auto_bench("ed448-sign", [&] {
            jpssl::ed448_sign(ed448.priv, m, size, sig);
            g_sink ^= sig[0];
        });
        emit_row("ed448-sign", "jpssl-scalar", size, s1);

        double s2 = auto_bench("ed448-sign", [&] {
            size_t sl = 114;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ed448.ossl_key);
            EVP_DigestSign(mctx, sig, &sl, m, size);
            g_sink ^= sig[0];
        });
        emit_row("ed448-sign", "openssl", size, s2);

        double v1 = auto_bench("ed448-verify", [&] {
            g_sink ^= jpssl::ed448_verify(ed448.pub, m, size, ed448.sig) ? 1 : 0;
        });
        emit_row("ed448-verify", "jpssl-scalar", size, v1);

        double v2 = auto_bench("ed448-verify", [&] {
            EVP_MD_CTX_reset(mctx);
            EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ed448.ossl_pubkey);
            int r = EVP_DigestVerify(mctx, ed448.sig, 114, m, size);
            g_sink ^= r;
        });
        emit_row("ed448-verify", "openssl", size, v2);
    }
    printf("  --- batch verify (size=32, N=64/256) ---\n");
    {
        std::vector<const uint8_t*> pubp, sigp, msgp;
        std::vector<size_t> lens;
        for (int i = 0; i < 256; ++i) {
            pubp.push_back(ed448.bpubs[i].data());
            sigp.push_back(ed448.bsigs[i].data());
            msgp.push_back(m32);
            lens.push_back(m32len);
        }
        for (int n : {64, 256}) {
            double b = auto_bench("ed448-batch", [&] {
                g_sink ^= jpssl::ed448_batch_verify(pubp.data(), msgp.data(), lens.data(),
                                                    sigp.data(), n) ? 1 : 0;
            });
            char impl[32];
            std::snprintf(impl, sizeof impl, "jpssl-batch%d", n);
            emit_row("ed448-batch", impl, m32len, b);

            double o = auto_bench("ed448-batch", [&] {
                int r = 0;
                for (int i = 0; i < n; ++i) {
                    EVP_MD_CTX_reset(mctx);
                    EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ed448.ovpubs[i]);
                    r ^= EVP_DigestVerify(mctx, ed448.bsigs[i].data(), 114, m32, m32len);
                }
                g_sink ^= r;
            });
            emit_row("ed448-batch", "openssl", m32len, o);
        }
    }

    // ── 4. CSV 输出 ──────────────────────────────────────────────────
    std::filesystem::create_directories("benchmarks/results");
    const char* csv_path = "benchmarks/results/bench_sig_multi.csv";
    FILE* csv = std::fopen(csv_path, "w");
    if (!csv) {
        printf("ERROR: cannot open %s\n", csv_path);
        return 2;
    }
    std::fprintf(csv, "algo,impl,size_bytes,ns_per_op,ops_per_sec\n");
    for (const Row& r : g_rows) {
        std::fprintf(csv, "%s,%s,%zu,%.2f,%.2f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.ns, 1e9 / r.ns);
    }
    std::fclose(csv);
    printf("\nCSV written: %s (%zu rows)\n", csv_path, g_rows.size());

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(rsa2048.ossl_key);
    EVP_PKEY_free(rsa4096.ossl_key);
    EVP_PKEY_free(ed25519.ossl_key);
    EVP_PKEY_free(ed25519.ossl_pubkey);
    EVP_PKEY_free(ed448.ossl_key);
    EVP_PKEY_free(ed448.ossl_pubkey);
    for (EVP_PKEY* k : ed25519.ovpubs) EVP_PKEY_free(k);
    for (EVP_PKEY* k : ed448.ovpubs) EVP_PKEY_free(k);
    printf("(sink=%d, skips=%d)\n", g_sink, g_skip_count);
    return 0;
}
