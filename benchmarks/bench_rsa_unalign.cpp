// bench_rsa_unalign.cpp — RSA 非对齐测试对比组 (jpssl vs OpenSSL)
//
// 假设: RSA 签名先哈希, 理论上消息长度 / 指针对齐不影响结果与性能。
// 本程序验证该假设并记录数据: 非对齐消息长度 + 非对齐指针偏移。
//
// 覆盖矩阵 (RSA-2048 / RSA-4096, PKCS#1 v1.5 + SHA-256):
//   非对齐消息长度 : 3 / 999 / 32761 (自检组含对齐长度 32 作对照)
//   非对齐指针偏移 : 消息起始与签名缓冲均偏移 offset 字节
//      自检 offset = {1,3,7}; 性能 offset = {0,3}
//   实现          : jpssl (rsassa_pkcs1v15_* / RSASP14096+RSAVP14096 复刻 EMSA)
//                   vs openssl (EVP_DigestSign/Verify, RSA_PKCS1_PADDING + SHA-256)
//
// 正确性自检 (始终执行): 非对齐下两方向互验 (jpssl签→openssl验、
//   openssl签→jpssl验) + 各实现内部签验自洽; 任意消息长度签验自洽;
//   任一 FAIL → 非零退出且不写 CSV。
// keygen 不在非对齐组重复 (无意义): 每密钥位宽仅各生成一次密钥供签名/验证复用。
//
// BENCH_SMOKE=1 : 消息长度 {3} × offset {0,3}, 目标 ~80ms, 1 轮
// 未设置        : 消息长度 {3,999,32761} × offset {0,3}, 目标 ~150ms, 3 轮取最小
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_rsa_unalign.csv
// CSV 列: algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec
//   algo: rsa2048-sign-unalign/rsa2048-verify-unalign/rsa4096-*
//   impl: jpssl/openssl
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_rsa_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_rsa_unalign

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
// 非对齐覆盖矩阵
// ─────────────────────────────────────────────────────────────────────
static const std::array<size_t, 4> kSelfCheckSizes = {3, 999, 32761, 32};   // 32 = 对齐对照
static const std::array<size_t, 3> kSelfCheckOffsets = {1, 3, 7};
static const std::array<size_t, 6> kSweepSizes = {1, 64, 1000, 32768, 65536, 100000};
static const std::vector<size_t> kPerfSizesFull = {3, 999, 32761};
static const std::vector<size_t> kPerfSizesSmoke = {3};
static const std::array<size_t, 2> kPerfOffsets = {0, 3};

static bool g_smoke = false;
static double g_target_ms = 150.0;   // 每轮目标时长 (sign/verify)
static int g_rounds = 3;             // 轮数 (取最小)
static const std::vector<size_t>* g_perf_sizes = nullptr;

// 消息缓冲: 最大长度 + 最大偏移 + 余量, 确定性 PRNG 填充
static std::vector<uint8_t> g_msg_buf;

static std::vector<uint8_t> g_msg_buf_make(size_t cap) {
    std::vector<uint8_t> m(cap);
    uint64_t x = 0x9e3779b97f4a7c15ull;
    for (size_t i = 0; i < cap; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        m[i] = static_cast<uint8_t>(x);
    }
    return m;
}

// ─────────────────────────────────────────────────────────────────────
// CSV 行记录 (含 offset 列)
// ─────────────────────────────────────────────────────────────────────
struct Row {
    std::string algo, impl;
    size_t size;
    size_t offset;
    double ns;
};
static std::vector<Row> g_rows;

static void emit_row(const char* algo, const char* impl, size_t size, size_t offset, double ns) {
    g_rows.push_back({algo, impl, size, offset, ns});
    printf("  %-26s %-8s %6zu %6zu %13.1f ns/op %12.2f ops/s\n",
           algo, impl, size, offset, ns, 1e9 / ns);
}

// ─────────────────────────────────────────────────────────────────────
// 自适应迭代微基准 (sign/verify): 每轮约 g_target_ms, g_rounds 轮取最小
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
    printf("  %-26s %-8s %6s %6s %13.1f ns/op %12.2f ops/s   (iters=%lld, rounds=%d)\n",
           name, "", "", "", best, 1e9 / best, iters, g_rounds);
    return best;
}

// ─────────────────────────────────────────────────────────────────────
//  OpenSSL 侧辅助
// ─────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────
//  jpssl RSA-4096 PKCS#1 v1.5 (头文件仅暴露 2048 的 rsassa 包装器,
//  4096 用公开原语 RSASP14096/RSAVP14096 复刻同一 EMSA 流程)
// ─────────────────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────────────────
//  互操作自检
// ─────────────────────────────────────────────────────────────────────
static int g_fail = 0;
static int g_check_count = 0;
static void selfcheck(const char* algo, bool jp2os, bool os2jp, bool jp_intra, bool os_intra) {
    ++g_check_count;
    const char* j = jp2os ? "PASS" : "FAIL";
    const char* o = os2jp ? "PASS" : "FAIL";
    const char* ji = jp_intra ? "PASS" : "FAIL";
    const char* oi = os_intra ? "PASS" : "FAIL";
    printf("  interop %-30s jpssl->openssl %-4s openssl->jpssl %-4s"
           " | intra jpssl %s / openssl %s\n",
           algo, j, o, ji, oi);
    if (!jp2os || !os2jp || !jp_intra || !os_intra) ++g_fail;
}

// ─────────────────────────────────────────────────────────────────────
//  密钥上下文 (每密钥位宽各一次 keygen, 供自检与性能复用)
// ─────────────────────────────────────────────────────────────────────
struct RsaCtx2048 {
    jpssl::rsa_public_key pub;
    jpssl::rsa_crt_key crt;
    EVP_PKEY* ossl_key = nullptr;      // OpenSSL 私钥 (openssl 签/验)
    EVP_PKEY* ossl_pubkey = nullptr;   // 由 jpssl pub(n,e) 构造的 OpenSSL 公钥
};

static bool rsa2048_setup(RsaCtx2048& c) {
    if (!jpssl::rsa_keygen_crt(c.pub, c.crt)) return false;
    uint8_t nbuf[256], ebuf[256];
    c.pub.n.to_bytes(nbuf);
    c.pub.e.to_bytes(ebuf);
    c.ossl_pubkey = ossl_rsa_pub_from_n(nbuf, 256, ebuf, 256);
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    bool kg = EVP_PKEY_keygen(kctx, &c.ossl_key) == 1;
    EVP_PKEY_CTX_free(kctx);
    return c.ossl_pubkey != nullptr && kg;
}

// 单点非对齐互操作自检: 消息 msg+off (len 字节), 签名缓冲 jp_sig+off / os_sig+off
static void rsa2048_interop_check(RsaCtx2048& c, const uint8_t* msg, size_t len, size_t off,
                                  uint8_t* jp_sig, uint8_t* os_sig) {
    // jpssl 签 → OpenSSL 验 (+ jpssl 自身验)
    jpssl::rsassa_pkcs1v15_sign(c.crt, msg + off, len,
                                kSha256DerPrefix, kSha256PrefixLen, jp_sig + off);
    bool jp_intra = jpssl::rsassa_pkcs1v15_verify(c.pub, msg + off, len,
                                                  kSha256DerPrefix, kSha256PrefixLen, jp_sig + off);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool jp2os = c.ossl_pubkey != nullptr
        && EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, c.ossl_pubkey) == 1
        && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mctx), RSA_PKCS1_PADDING) == 1
        && EVP_DigestVerify(mctx, jp_sig + off, 256, msg + off, len) == 1;

    // OpenSSL 签 → jpssl 验 (+ OpenSSL 自身验)
    EVP_MD_CTX* sm = EVP_MD_CTX_new();
    EVP_PKEY_CTX* spctx = nullptr;
    size_t slen = 256;
    bool sgn = EVP_DigestSignInit(sm, &spctx, EVP_sha256(), nullptr, c.ossl_key) == 1
        && EVP_PKEY_CTX_set_rsa_padding(spctx, RSA_PKCS1_PADDING) == 1
        && EVP_DigestSign(sm, os_sig + off, &slen, msg + off, len) == 1;
    bool os_intra = false;
    if (sgn) {
        EVP_MD_CTX_reset(mctx);
        os_intra = EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, c.ossl_key) == 1
            && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mctx), RSA_PKCS1_PADDING) == 1
            && EVP_DigestVerify(mctx, os_sig + off, 256, msg + off, len) == 1;
    }
    bool os2jp = false;
    if (sgn) {
        std::vector<uint8_t> n, e;
        if (ossl_rsa_get_n_e(c.ossl_key, n, e)) {
            jpssl::rsa_public_key pub;
            pub.n = jpssl::rsa_bignum::from_bytes(n.data(), n.size());
            pub.e = jpssl::rsa_bignum::from_bytes(e.data(), e.size());
            os2jp = jpssl::rsassa_pkcs1v15_verify(pub, msg + off, len,
                                                  kSha256DerPrefix, kSha256PrefixLen, os_sig + off);
        }
    }
    EVP_MD_CTX_free(sm);
    EVP_MD_CTX_free(mctx);
    char name[96];
    std::snprintf(name, sizeof(name), "rsa2048 len=%zu off=%zu", len, off);
    selfcheck(name, jp2os, os2jp, jp_intra, os_intra);
}

struct RsaCtx4096 {
    jpssl::rsa4096_public_key pub;
    jpssl::rsa4096_crt_key crt;
    EVP_PKEY* ossl_key = nullptr;
    EVP_PKEY* ossl_pubkey = nullptr;
};

static bool rsa4096_setup(RsaCtx4096& c) {
    if (!jpssl::rsa4096_keygen_crt(c.pub, c.crt)) return false;
    uint8_t nbuf[512], ebuf[512];
    c.pub.n.to_bytes(nbuf);
    c.pub.e.to_bytes(ebuf);
    c.ossl_pubkey = ossl_rsa_pub_from_n(nbuf, 512, ebuf, 512);
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 4096);
    bool kg = EVP_PKEY_keygen(kctx, &c.ossl_key) == 1;
    EVP_PKEY_CTX_free(kctx);
    return c.ossl_pubkey != nullptr && kg;
}

static void rsa4096_interop_check(RsaCtx4096& c, const uint8_t* msg, size_t len, size_t off,
                                  uint8_t* jp_sig, uint8_t* os_sig) {
    jpssl_rsa4096_pkcs1v15_sign(c.crt, msg + off, len,
                                kSha256DerPrefix, kSha256PrefixLen, jp_sig + off);
    bool jp_intra = jpssl_rsa4096_pkcs1v15_verify(c.pub, msg + off, len,
                                                  kSha256DerPrefix, kSha256PrefixLen, jp_sig + off);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool jp2os = c.ossl_pubkey != nullptr
        && EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, c.ossl_pubkey) == 1
        && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mctx), RSA_PKCS1_PADDING) == 1
        && EVP_DigestVerify(mctx, jp_sig + off, 512, msg + off, len) == 1;

    EVP_MD_CTX* sm = EVP_MD_CTX_new();
    EVP_PKEY_CTX* spctx = nullptr;
    size_t slen = 512;
    bool sgn = EVP_DigestSignInit(sm, &spctx, EVP_sha256(), nullptr, c.ossl_key) == 1
        && EVP_PKEY_CTX_set_rsa_padding(spctx, RSA_PKCS1_PADDING) == 1
        && EVP_DigestSign(sm, os_sig + off, &slen, msg + off, len) == 1;
    bool os_intra = false;
    if (sgn) {
        EVP_MD_CTX_reset(mctx);
        os_intra = EVP_DigestVerifyInit(mctx, nullptr, EVP_sha256(), nullptr, c.ossl_key) == 1
            && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mctx), RSA_PKCS1_PADDING) == 1
            && EVP_DigestVerify(mctx, os_sig + off, 512, msg + off, len) == 1;
    }
    bool os2jp = false;
    if (sgn) {
        std::vector<uint8_t> n, e;
        if (ossl_rsa_get_n_e(c.ossl_key, n, e)) {
            jpssl::rsa4096_public_key pub;
            pub.n = jpssl::rsa4096_bignum::from_bytes(n.data(), n.size());
            pub.e = jpssl::rsa4096_bignum::from_bytes(e.data(), e.size());
            os2jp = jpssl_rsa4096_pkcs1v15_verify(pub, msg + off, len,
                                                  kSha256DerPrefix, kSha256PrefixLen, os_sig + off);
        }
    }
    EVP_MD_CTX_free(sm);
    EVP_MD_CTX_free(mctx);
    char name[96];
    std::snprintf(name, sizeof(name), "rsa4096 len=%zu off=%zu", len, off);
    selfcheck(name, jp2os, os2jp, jp_intra, os_intra);
}

// 单实现内部签验自洽 (任意长度): jpssl intra + openssl intra, offset=1
static void length_sweep_check2048(RsaCtx2048& c, const uint8_t* msg, size_t len,
                                   uint8_t* jp_sig, uint8_t* os_sig) {
    const size_t off = 1;
    jpssl::rsassa_pkcs1v15_sign(c.crt, msg + off, len,
                                kSha256DerPrefix, kSha256PrefixLen, jp_sig + off);
    bool jp_intra = jpssl::rsassa_pkcs1v15_verify(c.pub, msg + off, len,
                                                  kSha256DerPrefix, kSha256PrefixLen, jp_sig + off);
    EVP_MD_CTX* sm = EVP_MD_CTX_new();
    EVP_PKEY_CTX* spctx = nullptr;
    size_t slen = 256;
    bool sgn = EVP_DigestSignInit(sm, &spctx, EVP_sha256(), nullptr, c.ossl_key) == 1
        && EVP_PKEY_CTX_set_rsa_padding(spctx, RSA_PKCS1_PADDING) == 1
        && EVP_DigestSign(sm, os_sig + off, &slen, msg + off, len) == 1;
    bool os_intra = false;
    if (sgn) {
        EVP_MD_CTX_reset(sm);
        os_intra = EVP_DigestVerifyInit(sm, nullptr, EVP_sha256(), nullptr, c.ossl_key) == 1
            && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(sm), RSA_PKCS1_PADDING) == 1
            && EVP_DigestVerify(sm, os_sig + off, 256, msg + off, len) == 1;
    }
    EVP_MD_CTX_free(sm);
    char name[96];
    std::snprintf(name, sizeof(name), "rsa2048 sweep len=%zu off=1", len);
    selfcheck(name, true, true, jp_intra, os_intra);
}

static void length_sweep_check4096(RsaCtx4096& c, const uint8_t* msg, size_t len,
                                   uint8_t* jp_sig, uint8_t* os_sig) {
    const size_t off = 1;
    jpssl_rsa4096_pkcs1v15_sign(c.crt, msg + off, len,
                                kSha256DerPrefix, kSha256PrefixLen, jp_sig + off);
    bool jp_intra = jpssl_rsa4096_pkcs1v15_verify(c.pub, msg + off, len,
                                                  kSha256DerPrefix, kSha256PrefixLen, jp_sig + off);
    EVP_MD_CTX* sm = EVP_MD_CTX_new();
    EVP_PKEY_CTX* spctx = nullptr;
    size_t slen = 512;
    bool sgn = EVP_DigestSignInit(sm, &spctx, EVP_sha256(), nullptr, c.ossl_key) == 1
        && EVP_PKEY_CTX_set_rsa_padding(spctx, RSA_PKCS1_PADDING) == 1
        && EVP_DigestSign(sm, os_sig + off, &slen, msg + off, len) == 1;
    bool os_intra = false;
    if (sgn) {
        EVP_MD_CTX_reset(sm);
        os_intra = EVP_DigestVerifyInit(sm, nullptr, EVP_sha256(), nullptr, c.ossl_key) == 1
            && EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(sm), RSA_PKCS1_PADDING) == 1
            && EVP_DigestVerify(sm, os_sig + off, 512, msg + off, len) == 1;
    }
    EVP_MD_CTX_free(sm);
    char name[96];
    std::snprintf(name, sizeof(name), "rsa4096 sweep len=%zu off=1", len);
    selfcheck(name, true, true, jp_intra, os_intra);
}

// ═════════════════════════════════════════════════════════════════════
//  main
// ═════════════════════════════════════════════════════════════════════
int main() {
    const char* smoke_env = std::getenv("BENCH_SMOKE");
    g_smoke = smoke_env && *smoke_env == '1';
    g_target_ms = g_smoke ? 80.0 : 150.0;
    g_rounds = g_smoke ? 1 : 3;
    g_perf_sizes = g_smoke ? &kPerfSizesSmoke : &kPerfSizesFull;

    const auto feats = jpssl::cpu_features::detect();
    printf("=== bench_rsa_unalign: jpssl vs OpenSSL (mode: %s) ===\n",
           g_smoke ? "SMOKE" : "FULL");
    printf("OpenSSL : %s\n", OPENSSL_VERSION_TEXT);
    printf("CPU     : x86_64 AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES=%d SHA-NI=%d ADX=%d\n",
           feats.aesni ? 1 : 0, feats.avx2 ? 1 : 0, feats.pclmulqdq ? 1 : 0,
           feats.avx512 ? 1 : 0, feats.vpclmulqdq_vaes ? 1 : 0,
           feats.sha_ni ? 1 : 0, jpssl::cpu_has_adx() ? 1 : 0);
    printf("note    : RSA 先哈希, 理论长度/对齐无关; 本程序验证该假设并记录数据\n");
    printf("note    : keygen 每密钥位宽各 1 次 (供签名/验证复用), 不计入 CSV\n");

    // 消息缓冲: 覆盖最大长度 100000 + 最大偏移 7
    const size_t kMsgCap = 100000 + 16;
    g_msg_buf = g_msg_buf_make(kMsgCap);

    // 签名缓冲: 密钥字节宽 + 最大偏移 + 余量
    uint8_t jp_sig2048[256 + 16], os_sig2048[256 + 16];
    uint8_t jp_sig4096[512 + 16], os_sig4096[512 + 16];

    // ── 1. 密钥生成 (每密钥位宽一次) ────────────────────────────────
    printf("\n=== key setup (1x per key size, not benchmarked) ===\n");
    RsaCtx2048 rsa2048;
    RsaCtx4096 rsa4096;
    if (!rsa2048_setup(rsa2048)) { printf("rsa2048 key setup FAILED\n"); return 1; }
    printf("  rsa2048 keys ready (jpssl + openssl)\n");
    if (!rsa4096_setup(rsa4096)) { printf("rsa4096 key setup FAILED\n"); return 1; }
    printf("  rsa4096 keys ready (jpssl + openssl)\n");

    // ── 2. 互操作自检: 非对齐长度 {3,999,32761} × 偏移 {1,3,7}, 含对齐对照 32 ──
    printf("\n=== interop self-tests (unaligned len x offset, 32 = aligned control) ===\n");
    for (size_t len : kSelfCheckSizes) {
        for (size_t off : kSelfCheckOffsets) {
            rsa2048_interop_check(rsa2048, g_msg_buf.data(), len, off, jp_sig2048, os_sig2048);
            rsa4096_interop_check(rsa4096, g_msg_buf.data(), len, off, jp_sig4096, os_sig4096);
        }
    }

    // ── 3. 任意消息长度签验自洽 (offset=1) ──────────────────────────
    printf("\n=== arbitrary-length sign/verify self-consistency (offset=1) ===\n");
    for (size_t len : kSweepSizes) {
        length_sweep_check2048(rsa2048, g_msg_buf.data(), len, jp_sig2048, os_sig2048);
        length_sweep_check4096(rsa4096, g_msg_buf.data(), len, jp_sig4096, os_sig4096);
    }

    if (g_fail) {
        printf("\ninterop FAILED (%d), abort without CSV\n", g_fail);
        return 1;
    }
    printf("all unalign self-tests PASS (%d check(s))\n", g_check_count);

    // ── 4. 性能基准: 长度 {3,999,32761} × offset {0,3} (sign+verify) ──
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    printf("\n=== RSA-2048 (unalign perf) ===\n");
    for (size_t size : *g_perf_sizes) {
        for (size_t off : kPerfOffsets) {
            printf("  --- sign / verify size=%zu offset=%zu ---\n", size, off);
            // 生成有效签名并互验 (该组合同时计入自检)
            rsa2048_interop_check(rsa2048, g_msg_buf.data(), size, off, jp_sig2048, os_sig2048);

            emit_row("rsa2048-sign-unalign", "jpssl", size, off, auto_bench("rsa2048-sign-unalign", [&] {
                jpssl::rsassa_pkcs1v15_sign(rsa2048.crt, g_msg_buf.data() + off, size,
                                            kSha256DerPrefix, kSha256PrefixLen, jp_sig2048 + off);
                g_sink ^= jp_sig2048[off];
            }));
            emit_row("rsa2048-sign-unalign", "openssl", size, off, auto_bench("rsa2048-sign-unalign", [&] {
                EVP_PKEY_CTX* pctx = nullptr;
                size_t sl = 256;
                EVP_MD_CTX_reset(mctx);
                EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), nullptr, rsa2048.ossl_key);
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
                EVP_DigestSign(mctx, os_sig2048 + off, &sl, g_msg_buf.data() + off, size);
                g_sink ^= os_sig2048[off];
            }));
            emit_row("rsa2048-verify-unalign", "jpssl", size, off, auto_bench("rsa2048-verify-unalign", [&] {
                g_sink ^= jpssl::rsassa_pkcs1v15_verify(rsa2048.pub, g_msg_buf.data() + off, size,
                                                        kSha256DerPrefix, kSha256PrefixLen,
                                                        jp_sig2048 + off) ? 1 : 0;
            }));
            emit_row("rsa2048-verify-unalign", "openssl", size, off, auto_bench("rsa2048-verify-unalign", [&] {
                EVP_PKEY_CTX* pctx = nullptr;
                EVP_MD_CTX_reset(mctx);
                EVP_DigestVerifyInit(mctx, &pctx, EVP_sha256(), nullptr, rsa2048.ossl_key);
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
                int r = EVP_DigestVerify(mctx, jp_sig2048 + off, 256, g_msg_buf.data() + off, size);
                g_sink ^= r;
            }));
        }
    }

    printf("\n=== RSA-4096 (unalign perf) ===\n");
    for (size_t size : *g_perf_sizes) {
        for (size_t off : kPerfOffsets) {
            printf("  --- sign / verify size=%zu offset=%zu ---\n", size, off);
            rsa4096_interop_check(rsa4096, g_msg_buf.data(), size, off, jp_sig4096, os_sig4096);

            emit_row("rsa4096-sign-unalign", "jpssl", size, off, auto_bench("rsa4096-sign-unalign", [&] {
                jpssl_rsa4096_pkcs1v15_sign(rsa4096.crt, g_msg_buf.data() + off, size,
                                            kSha256DerPrefix, kSha256PrefixLen, jp_sig4096 + off);
                g_sink ^= jp_sig4096[off];
            }));
            emit_row("rsa4096-sign-unalign", "openssl", size, off, auto_bench("rsa4096-sign-unalign", [&] {
                EVP_PKEY_CTX* pctx = nullptr;
                size_t sl = 512;
                EVP_MD_CTX_reset(mctx);
                EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), nullptr, rsa4096.ossl_key);
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
                EVP_DigestSign(mctx, os_sig4096 + off, &sl, g_msg_buf.data() + off, size);
                g_sink ^= os_sig4096[off];
            }));
            emit_row("rsa4096-verify-unalign", "jpssl", size, off, auto_bench("rsa4096-verify-unalign", [&] {
                g_sink ^= jpssl_rsa4096_pkcs1v15_verify(rsa4096.pub, g_msg_buf.data() + off, size,
                                                        kSha256DerPrefix, kSha256PrefixLen,
                                                        jp_sig4096 + off) ? 1 : 0;
            }));
            emit_row("rsa4096-verify-unalign", "openssl", size, off, auto_bench("rsa4096-verify-unalign", [&] {
                EVP_PKEY_CTX* pctx = nullptr;
                EVP_MD_CTX_reset(mctx);
                EVP_DigestVerifyInit(mctx, &pctx, EVP_sha256(), nullptr, rsa4096.ossl_key);
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
                int r = EVP_DigestVerify(mctx, jp_sig4096 + off, 512, g_msg_buf.data() + off, size);
                g_sink ^= r;
            }));
        }
    }

    if (g_fail) {
        printf("\nperf-phase self-checks FAILED (%d), abort without CSV\n", g_fail);
        EVP_MD_CTX_free(mctx);
        return 1;
    }

    // ── 5. CSV 输出 ──────────────────────────────────────────────────
    std::filesystem::create_directories("benchmarks/results");
    const char* csv_path = "benchmarks/results/bench_rsa_unalign.csv";
    FILE* csv = std::fopen(csv_path, "w");
    if (!csv) {
        printf("ERROR: cannot open %s\n", csv_path);
        EVP_MD_CTX_free(mctx);
        return 2;
    }
    std::fprintf(csv, "algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec\n");
    for (const Row& r : g_rows) {
        std::fprintf(csv, "%s,%s,%zu,%zu,%.2f,%.2f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.offset, r.ns, 1e9 / r.ns);
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
