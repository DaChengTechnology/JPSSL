// bench_rsa.cpp — RSA 全量测试基准: keygen / sign (PKCS#1 v1.5 + SHA-256) / verify
//
// 覆盖矩阵 (RSA-2048 / RSA-4096):
//   keygen : jpssl (rsa_keygen_crt / rsa4096_keygen_crt) vs openssl (EVP_PKEY keygen)
//   sign   : jpssl (rsassa_pkcs1v15_sign / RSASP14096 复刻 EMSA-PKCS1-v1_5)
//            vs openssl (EVP_DigestSign, RSA_PKCS1_PADDING + EVP_sha256)
//   verify : jpssl (rsassa_pkcs1v15_verify / RSAVP14096)
//            vs openssl (EVP_DigestVerify, RSA_PKCS1_PADDING + EVP_sha256)
//   消息长度矩阵: 32 / 256 / 1024 / 65536 字节 (RSA 先哈希, 长度无关, 仍按矩阵覆盖)
//
// 正确性自检 (始终执行, 32B 消息): jpssl 签 → OpenSSL 验 + OpenSSL 签 → jpssl 验,
//   外加各实现内部自洽 (签→验); 任一 FAIL → 非零退出且不写 CSV。
//
// BENCH_SMOKE=1 : 仅 32B 一档, keygen 1 次, sign/verify 目标 ~80ms, 1 轮
// 未设置        : 4 档长度, 目标 ~150ms, keygen 3 次取最小, 3 轮取最小
//
// 注意: jpssl keygen 素数搜索带看门狗 (2048=500ms/素数, 4096=1000ms/素数),
//   超时回退预置素数表, keygen 必完成; CSV 照实记录该有界搜索耗时。
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_rsa.csv
// CSV 列: algo,impl,size_bytes,ns_per_op,ops_per_sec
//   algo: rsa2048-keygen/rsa2048-sign/rsa2048-verify/rsa4096-*
//   impl: jpssl/openssl; keygen 行 size_bytes=0
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_rsa.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_rsa

#include "rsa.hpp"
#include "rsa_mont_asm.hpp"
#include "cpu_features.hpp"
#include "sha256.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

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
// 全量消息长度矩阵 (smoke 时截取为 {32})
// ─────────────────────────────────────────────────────────────────────
static const std::array<size_t, 4> kAllSizes = {32, 256, 1024, 65536};

static bool g_smoke = false;
static double g_target_ms = 150.0;   // 每轮目标时长 (sign/verify)
static int g_rounds = 3;             // 轮数 (取最小)
static std::vector<size_t> g_sizes;  // 本次实际测试的消息长度

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

// ─────────────────────────────────────────────────────────────────────
// 自适应迭代微基准 (sign/verify): 每轮约 g_target_ms, g_rounds 轮取最小
// est_n: 首次耗时估计的调用次数
// ─────────────────────────────────────────────────────────────────────
template <typename F>
static double auto_bench(const char* name, F&& f, int est_n = 8) {
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
        iters = static_cast<long long>(g_target_ms * 1e6 / est_ns);
        if (iters < 1) iters = 1;
        if (iters > 2000000) iters = 2000000;
    }

    double best = 1e300;
    for (int r = 0; r < g_rounds; ++r) {
        auto s = Clock::now();
        for (long long i = 0; i < iters; ++i) f();
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / iters;
        if (ns < best) best = ns;
    }
    printf("  %-22s %-18s %6s %13.1f ns/op %12.2f ops/s   (iters=%lld, rounds=%d)\n",
           name, "", "", best, 1e9 / best, iters, g_rounds);
    return best;
}

// ─────────────────────────────────────────────────────────────────────
// keygen 单测: 每轮恰好 1 次 (迭代数下限=1), g_rounds 轮取最小
// (看门狗保证 jpssl keygen 必完成; OpenSSL keygen 同样逐次计时)
// ─────────────────────────────────────────────────────────────────────
template <typename F>
static double auto_bench_keygen(const char* name, F&& f) {
    f(); // 预热 1 次
    double best = 1e300;
    for (int r = 0; r < g_rounds; ++r) {
        auto s = Clock::now();
        f();
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count();
        if (ns < best) best = ns;
    }
    printf("  %-22s %-18s %6s %13.1f ns/op %12.2f ops/s   (keygen/round, rounds=%d)\n",
           name, "", "", best, 1e9 / best, g_rounds);
    return best;
}

// ═════════════════════════════════════════════════════════════════════
//  OpenSSL 侧辅助
// ═════════════════════════════════════════════════════════════════════

// jpssl RSA 公钥 (n, e) → OpenSSL EVP_PKEY (public, OSSL_PARAM 构造)
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

// OpenSSL 私钥 n/e 提取 → 大端字节 (长度 = BN_num_bytes, 实际字节数)
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
static int g_check_count = 0;
static void selfcheck(const char* algo, bool jp2os, bool os2jp, bool jp_intra, bool os_intra) {
    ++g_check_count;
    const char* j = jp2os ? "PASS" : "FAIL";
    const char* o = os2jp ? "PASS" : "FAIL";
    const char* ji = jp_intra ? "PASS" : "FAIL";
    const char* oi = os_intra ? "PASS" : "FAIL";
    printf("  interop %-26s jpssl->openssl %-4s openssl->jpssl %-4s"
           " | intra jpssl %s / openssl %s\n",
           algo, j, o, ji, oi);
    if (!jp2os || !os2jp || !jp_intra || !os_intra) ++g_fail;
}

// ── RSA 上下文 ────────────────────────────────────────────────────────
struct RsaCtx2048 {
    jpssl::rsa_public_key pub;
    jpssl::rsa_crt_key crt;
    uint8_t sig[256];          // jpssl 签名 (自检时生成)
    uint8_t ossl_sig[256];     // OpenSSL 签名 (自检时生成)
    EVP_PKEY* ossl_key = nullptr;
    EVP_PKEY* ossl_pubkey = nullptr;   // 由 jpssl pub(n,e) 构造的 OpenSSL 公钥
};

static bool rsa2048_selfcheck(RsaCtx2048& c, const uint8_t* msg, size_t msglen) {
    bool ok = jpssl::rsa_keygen_crt(c.pub, c.crt);
    if (!ok) { printf("  rsa2048 keygen failed\n"); return false; }

    // jpssl 签 → OpenSSL 验 (+ jpssl 自身验)
    jpssl::rsassa_pkcs1v15_sign(c.crt, msg, msglen, kSha256DerPrefix, kSha256PrefixLen, c.sig);
    bool jp_intra = jpssl::rsassa_pkcs1v15_verify(c.pub, msg, msglen,
                                                  kSha256DerPrefix, kSha256PrefixLen, c.sig);
    uint8_t nbuf[256], ebuf[256];
    c.pub.n.to_bytes(nbuf);
    c.pub.e.to_bytes(ebuf);
    c.ossl_pubkey = ossl_rsa_pub_from_n(nbuf, 256, ebuf, 256);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool jp2os = c.ossl_pubkey != nullptr
        && EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, c.ossl_pubkey) == 1
        && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mctx), RSA_PKCS1_PADDING) == 1
        && EVP_DigestVerify(mctx, c.sig, 256, msg, msglen) == 1;

    // OpenSSL keygen + 签 → jpssl 验 (+ OpenSSL 自身验)
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    bool kg = EVP_PKEY_keygen(kctx, &c.ossl_key) == 1;
    EVP_PKEY_CTX_free(kctx);
    bool sgn = false, os_intra = false;
    if (kg) {
        EVP_MD_CTX* sm = EVP_MD_CTX_new();
        EVP_PKEY_CTX* spctx = nullptr;
        size_t slen = 256;
        sgn = EVP_DigestSignInit(sm, &spctx, EVP_sha256(), nullptr, c.ossl_key) == 1
            && EVP_PKEY_CTX_set_rsa_padding(spctx, RSA_PKCS1_PADDING) == 1
            && EVP_DigestSign(sm, c.ossl_sig, &slen, msg, msglen) == 1;
        if (sgn) {
            EVP_MD_CTX_reset(mctx);
            os_intra = EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, c.ossl_key) == 1
                && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mctx), RSA_PKCS1_PADDING) == 1
                && EVP_DigestVerify(mctx, c.ossl_sig, 256, msg, msglen) == 1;
        }
        EVP_MD_CTX_free(sm);
    }
    bool os2jp = false;
    if (sgn) {
        std::vector<uint8_t> n, e;
        if (ossl_rsa_get_n_e(c.ossl_key, n, e)) {
            jpssl::rsa_public_key pub;
            pub.n = jpssl::rsa_bignum::from_bytes(n.data(), n.size());
            pub.e = jpssl::rsa_bignum::from_bytes(e.data(), e.size());
            os2jp = jpssl::rsassa_pkcs1v15_verify(pub, msg, msglen,
                                                  kSha256DerPrefix, kSha256PrefixLen, c.ossl_sig);
        }
    }
    selfcheck("rsa2048 PKCS1+SHA256", jp2os, os2jp, jp_intra, os_intra);
    EVP_MD_CTX_free(mctx);
    return jp2os && os2jp && jp_intra && os_intra;
}

struct RsaCtx4096 {
    jpssl::rsa4096_public_key pub;
    jpssl::rsa4096_crt_key crt;
    uint8_t sig[512];
    uint8_t ossl_sig[512];
    EVP_PKEY* ossl_key = nullptr;
    EVP_PKEY* ossl_pubkey = nullptr;
};

static bool rsa4096_selfcheck(RsaCtx4096& c, const uint8_t* msg, size_t msglen) {
    bool ok = jpssl::rsa4096_keygen_crt(c.pub, c.crt);
    if (!ok) { printf("  rsa4096 keygen failed\n"); return false; }

    jpssl_rsa4096_pkcs1v15_sign(c.crt, msg, msglen, kSha256DerPrefix, kSha256PrefixLen, c.sig);
    bool jp_intra = jpssl_rsa4096_pkcs1v15_verify(c.pub, msg, msglen,
                                                  kSha256DerPrefix, kSha256PrefixLen, c.sig);
    uint8_t nbuf[512], ebuf[512];
    c.pub.n.to_bytes(nbuf);
    c.pub.e.to_bytes(ebuf);
    c.ossl_pubkey = ossl_rsa_pub_from_n(nbuf, 512, ebuf, 512);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool jp2os = c.ossl_pubkey != nullptr
        && EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, c.ossl_pubkey) == 1
        && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mctx), RSA_PKCS1_PADDING) == 1
        && EVP_DigestVerify(mctx, c.sig, 512, msg, msglen) == 1;

    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 4096);
    bool kg = EVP_PKEY_keygen(kctx, &c.ossl_key) == 1;
    EVP_PKEY_CTX_free(kctx);
    bool sgn = false, os_intra = false;
    if (kg) {
        EVP_MD_CTX* sm = EVP_MD_CTX_new();
        EVP_PKEY_CTX* spctx = nullptr;
        size_t slen = 512;
        sgn = EVP_DigestSignInit(sm, &spctx, EVP_sha256(), nullptr, c.ossl_key) == 1
            && EVP_PKEY_CTX_set_rsa_padding(spctx, RSA_PKCS1_PADDING) == 1
            && EVP_DigestSign(sm, c.ossl_sig, &slen, msg, msglen) == 1;
        if (sgn) {
            EVP_MD_CTX_reset(mctx);
            os_intra = EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, c.ossl_key) == 1
                && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mctx), RSA_PKCS1_PADDING) == 1
                && EVP_DigestVerify(mctx, c.ossl_sig, 512, msg, msglen) == 1;
        }
        EVP_MD_CTX_free(sm);
    }
    bool os2jp = false;
    if (sgn) {
        std::vector<uint8_t> n, e;
        if (ossl_rsa_get_n_e(c.ossl_key, n, e)) {
            jpssl::rsa4096_public_key pub;
            pub.n = jpssl::rsa4096_bignum::from_bytes(n.data(), n.size());
            pub.e = jpssl::rsa4096_bignum::from_bytes(e.data(), e.size());
            os2jp = jpssl_rsa4096_pkcs1v15_verify(pub, msg, msglen,
                                                  kSha256DerPrefix, kSha256PrefixLen, c.ossl_sig);
        }
    }
    selfcheck("rsa4096 PKCS1+SHA256", jp2os, os2jp, jp_intra, os_intra);
    EVP_MD_CTX_free(mctx);
    return jp2os && os2jp && jp_intra && os_intra;
}

// ═════════════════════════════════════════════════════════════════════
//  main
// ═════════════════════════════════════════════════════════════════════
int main() {
    const char* smoke_env = std::getenv("BENCH_SMOKE");
    g_smoke = smoke_env && *smoke_env == '1';
    g_target_ms = g_smoke ? 80.0 : 150.0;
    g_rounds = g_smoke ? 1 : 3;
    g_sizes.assign(kAllSizes.begin(), kAllSizes.end());
    if (g_smoke) g_sizes = {32};

    const auto feats = jpssl::cpu_features::detect();
    printf("=== bench_rsa: jpssl vs OpenSSL (mode: %s) ===\n", g_smoke ? "SMOKE" : "FULL");
    printf("OpenSSL : %s\n", OPENSSL_VERSION_TEXT);
    printf("CPU     : x86_64 AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES=%d SHA-NI=%d ADX=%d\n",
           feats.aesni ? 1 : 0, feats.avx2 ? 1 : 0, feats.pclmulqdq ? 1 : 0,
           feats.avx512 ? 1 : 0, feats.vpclmulqdq_vaes ? 1 : 0,
           feats.sha_ni ? 1 : 0, jpssl::cpu_has_adx() ? 1 : 0);
    printf("note    : jpssl keygen 素数搜索带看门狗 (2048=500ms/素数, 4096=1000ms/素数), "
           "超时回退预置素数表; CSV 照实记录\n");

    std::vector<std::vector<uint8_t>> msgs;
    for (size_t s : g_sizes) msgs.push_back(g_msg(s));
    const uint8_t* m32 = msgs[0].data();
    const size_t m32len = msgs[0].size();

    // ── 1. 互操作自检 (始终执行, 32B) ────────────────────────────────
    printf("\n=== interop self-tests (32B message) ===\n");
    RsaCtx2048 rsa2048;
    RsaCtx4096 rsa4096;
    bool ok2048 = rsa2048_selfcheck(rsa2048, m32, m32len);
    bool ok4096 = rsa4096_selfcheck(rsa4096, m32, m32len);
    if (!ok2048) ++g_fail;
    if (!ok4096) ++g_fail;

    if (g_fail) {
        printf("\ninterop FAILED (%d), abort without CSV\n", g_fail);
        return 1;
    }
    printf("all interop self-tests PASS (%d check(s))\n", g_check_count);

    // ── 2. 基准测量 ──────────────────────────────────────────────────
    printf("\n=== RSA-2048 ===\n");
    printf("  --- keygen (size=0) ---\n");
    emit_row("rsa2048-keygen", "jpssl", 0, auto_bench_keygen("rsa2048-keygen", [&] {
        jpssl::rsa_public_key pub; jpssl::rsa_crt_key crt;
        jpssl::rsa_keygen_crt(pub, crt);
        g_sink ^= pub.n.d[0];
    }));
    emit_row("rsa2048-keygen", "openssl", 0, auto_bench_keygen("rsa2048-keygen", [&] {
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(kctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
        EVP_PKEY* k = nullptr;
        EVP_PKEY_keygen(kctx, &k);
        EVP_PKEY_CTX_free(kctx);
        if (k) EVP_PKEY_free(k);
    }));

    printf("  --- sign / verify (size=%s) ---\n", g_smoke ? "32" : "32,256,1024,65536");
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    for (size_t idx = 0; idx < g_sizes.size(); ++idx) {
        const size_t size = g_sizes[idx];
        const uint8_t* m = msgs[idx].data();
        uint8_t sigbuf[256];

        emit_row("rsa2048-sign", "jpssl", size, auto_bench("rsa2048-sign", [&] {
            jpssl::rsassa_pkcs1v15_sign(rsa2048.crt, m, size,
                                        kSha256DerPrefix, kSha256PrefixLen, sigbuf);
            g_sink ^= sigbuf[0];
        }));
        emit_row("rsa2048-sign", "openssl", size, auto_bench("rsa2048-sign", [&] {
            EVP_PKEY_CTX* pctx = nullptr;
            size_t sl = 256;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), nullptr, rsa2048.ossl_key);
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
            EVP_DigestSign(mctx, sigbuf, &sl, m, size);
            g_sink ^= sigbuf[0];
        }));
        emit_row("rsa2048-verify", "jpssl", size, auto_bench("rsa2048-verify", [&] {
            g_sink ^= jpssl::rsassa_pkcs1v15_verify(rsa2048.pub, m, size,
                                                    kSha256DerPrefix, kSha256PrefixLen,
                                                    rsa2048.sig) ? 1 : 0;
        }));
        emit_row("rsa2048-verify", "openssl", size, auto_bench("rsa2048-verify", [&] {
            EVP_PKEY_CTX* pctx = nullptr;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestVerifyInit(mctx, &pctx, EVP_sha256(), nullptr, rsa2048.ossl_key);
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
            int r = EVP_DigestVerify(mctx, rsa2048.ossl_sig, 256, m, size);
            g_sink ^= r;
        }));
    }

    printf("\n=== RSA-4096 ===\n");
    printf("  --- keygen (size=0) ---\n");
    emit_row("rsa4096-keygen", "jpssl", 0, auto_bench_keygen("rsa4096-keygen", [&] {
        jpssl::rsa4096_public_key pub; jpssl::rsa4096_crt_key crt;
        jpssl::rsa4096_keygen_crt(pub, crt);
        g_sink ^= pub.n.d[0];
    }));
    emit_row("rsa4096-keygen", "openssl", 0, auto_bench_keygen("rsa4096-keygen", [&] {
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY_keygen_init(kctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 4096);
        EVP_PKEY* k = nullptr;
        EVP_PKEY_keygen(kctx, &k);
        EVP_PKEY_CTX_free(kctx);
        if (k) EVP_PKEY_free(k);
    }));

    printf("  --- sign / verify (size=%s) ---\n", g_smoke ? "32" : "32,256,1024,65536");
    for (size_t idx = 0; idx < g_sizes.size(); ++idx) {
        const size_t size = g_sizes[idx];
        const uint8_t* m = msgs[idx].data();
        uint8_t sigbuf[512];

        emit_row("rsa4096-sign", "jpssl", size, auto_bench("rsa4096-sign", [&] {
            jpssl_rsa4096_pkcs1v15_sign(rsa4096.crt, m, size,
                                        kSha256DerPrefix, kSha256PrefixLen, sigbuf);
            g_sink ^= sigbuf[0];
        }));
        emit_row("rsa4096-sign", "openssl", size, auto_bench("rsa4096-sign", [&] {
            EVP_PKEY_CTX* pctx = nullptr;
            size_t sl = 512;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), nullptr, rsa4096.ossl_key);
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
            EVP_DigestSign(mctx, sigbuf, &sl, m, size);
            g_sink ^= sigbuf[0];
        }));
        emit_row("rsa4096-verify", "jpssl", size, auto_bench("rsa4096-verify", [&] {
            g_sink ^= jpssl_rsa4096_pkcs1v15_verify(rsa4096.pub, m, size,
                                                    kSha256DerPrefix, kSha256PrefixLen,
                                                    rsa4096.sig) ? 1 : 0;
        }));
        emit_row("rsa4096-verify", "openssl", size, auto_bench("rsa4096-verify", [&] {
            EVP_PKEY_CTX* pctx = nullptr;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestVerifyInit(mctx, &pctx, EVP_sha256(), nullptr, rsa4096.ossl_key);
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
            int r = EVP_DigestVerify(mctx, rsa4096.ossl_sig, 512, m, size);
            g_sink ^= r;
        }));
    }

    // ── 3. CSV 输出 ──────────────────────────────────────────────────
    std::filesystem::create_directories("benchmarks/results");
    const char* csv_path = "benchmarks/results/bench_rsa.csv";
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
    std::filesystem::path abs_csv = std::filesystem::absolute(csv_path);
    printf("\nCSV written: %s (%zu rows)\n", abs_csv.c_str(), g_rows.size());

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(rsa2048.ossl_key);
    EVP_PKEY_free(rsa2048.ossl_pubkey);
    EVP_PKEY_free(rsa4096.ossl_key);
    EVP_PKEY_free(rsa4096.ossl_pubkey);
    printf("(sink=%d)\n", g_sink);
    return 0;
}
