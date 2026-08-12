// bench_ed25519.cpp — Ed25519 全量测试: 全部实现路径 × 多消息长度 × OpenSSL 对比
//
// 覆盖矩阵:
//   实现路径  : jpssl 默认 (ed25519_keygen/sign/verify, 内部派发 r51)
//              jpssl r51 显式 (ed25519_*_r51)
//              jpssl ref10 scalar (ed25519_ref10_impl::*, 头文件未暴露, 本文件 extern 声明)
//              jpssl avx512 (avx512_impl::*, 仅 cpu_has_avx512() 时调用; 本机无 AVX512 → SKIP,
//                            调用会 SIGILL, 绝不调用)
//              jpssl 批量验签 (ed25519_batch_verify, N=64/256, 32B 消息)
//              OpenSSL (EVP_PKEY ED25519)
//   消息长度  : 32 / 256 / 1024 / 65536 字节 (keygen 与消息无关, size_bytes=0)
//
// 正确性自检 (始终执行, 消息 32B):
//   - 每个单条路径与 OpenSSL 两方向互验: jpssl 签 → OpenSSL 验, OpenSSL 签 → jpssl 验
//     (外加自身签名自验)
//   - 批量验签 N=64/256 与 OpenSSL 逐条循环验签结果一致, 并做负例 (破坏一条签名必须拒绝)
//   - 任一 FAIL → 非零退出且不写 CSV
//   (注意: 批量私钥缓冲为 64B — ed25519_keygen 写 pub[32] + priv[64]; 先例文件曾因 32B 越界崩溃)
//
// 性能基准: keygen / sign / verify × 消息长度矩阵; 批量 N=64/256 (32B 消息)
//   BENCH_SMOKE=1: 只测 32B 一档, ~80ms/轮, 1 轮 (批量仅 N=64 一次)
//   默认全量     : 4 档, ~150ms/轮, 3 轮取最小
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_ed25519.csv
//   CSV 列: algo,impl,size_bytes,ns_per_op,ops_per_sec
//   algo: ed25519-keygen / ed25519-sign / ed25519-verify / ed25519-batch
//   impl: jpssl / jpssl-r51 / jpssl-scalar / jpssl-avx512 /
//         jpssl-batch64 / jpssl-batch256 / openssl
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES \
//       -Iinclude -Isrc benchmarks/bench_ed25519.cpp \
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto \
//       -o /tmp/bench_ed25519

#include "ed25519.hpp"
#include "ed25519_batch.hpp"
#include "cpu_features.hpp"

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

// ─────────────────────────────────────────────────────────────────────
// 头文件未声明、但静态库已导出 (T 符号) 的后端实现声明
// （ed25519.hpp 只暴露 r51 公共 API 与默认接口；ref10 scalar 与 avx512
//   后端以库符号为准手动声明，avx512 仅在 cpu_has_avx512() 时调用）
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
} // namespace jpssl

static volatile int g_sink = 0;

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
    printf("  %-20s %-18s %6zu %13.1f ns/op %12.2f ops/s\n",
           algo, impl, size, ns, 1e9 / ns);
}

static int g_skip_count = 0;
static void skip(const char* msg) {
    ++g_skip_count;
    printf("  SKIP %s\n", msg);
}

// ─────────────────────────────────────────────────────────────────────
// 自适应迭代微基准: 每轮约 target_ms, rounds 轮取最小值 (参考 bench_ed25519_ossl.cpp)
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
    printf("  %-20s %-18s %6s %13.1f ns/op %12.2f ops/s   (iters=%lld)\n",
           name, "", "", best, 1e9 / best, iters);
    return best;
}

// ─────────────────────────────────────────────────────────────────────
// 单条实现路径描述 (keygen/sign/verify 三者一致)
// ─────────────────────────────────────────────────────────────────────
struct SigImpl {
    const char* name;
    void (*keygen)(uint8_t pub[32], uint8_t priv[64]);
    void (*sign)(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]);
    bool (*verify)(const uint8_t pub[32], const uint8_t* msg, size_t msg_len,
                   const uint8_t sig[64]);
};

static const SigImpl kImpls[] = {
    {"jpssl",        jpssl::ed25519_keygen,
                      jpssl::ed25519_sign,
                      jpssl::ed25519_verify},
    {"jpssl-r51",    jpssl::ed25519_keygen_r51,
                      jpssl::ed25519_sign_r51,
                      jpssl::ed25519_verify_r51},
    {"jpssl-scalar", jpssl::ed25519_ref10_impl::ed25519_keygen,
                      jpssl::ed25519_ref10_impl::ed25519_sign,
                      jpssl::ed25519_ref10_impl::ed25519_verify},
    {"jpssl-avx512", jpssl::avx512_impl::ed25519_keygen,
                      jpssl::avx512_impl::ed25519_sign,
                      jpssl::avx512_impl::ed25519_verify},
};

static bool is_avx512(const SigImpl& im) {
    return std::strcmp(im.name, "jpssl-avx512") == 0;
}

// ─────────────────────────────────────────────────────────────────────
// 互操作自检
// ─────────────────────────────────────────────────────────────────────
static int g_fail = 0;
static int g_pass = 0;

static void selfcheck(const char* what, bool ok) {
    printf("  selfcheck %-44s : %s\n", what, ok ? "PASS" : "FAIL");
    if (ok) ++g_pass; else ++g_fail;
}

// 单条路径 × OpenSSL 两方向互验 (jpssl 签→openssl 验, openssl 签→jpssl 验) + 自验
static void single_path_selfchecks(const uint8_t* msg, size_t msglen) {
    const bool have_avx512 = jpssl::cpu_has_avx512();

    EVP_PKEY* ossl_key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    if (!ossl_key) { selfcheck("openssl keygen", false); return; }
    uint8_t ossl_pub[32];
    size_t plen = 32;
    EVP_PKEY_get_raw_public_key(ossl_key, ossl_pub, &plen);
    uint8_t ossl_sig[64];
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    size_t slen = 64;
    bool ossl_sign_ok = EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ossl_key) == 1
        && EVP_DigestSign(mctx, ossl_sig, &slen, msg, msglen) == 1 && slen == 64;
    selfcheck("openssl ED25519 keygen+sign", ossl_sign_ok);

    for (const SigImpl& im : kImpls) {
        if (is_avx512(im) && !have_avx512) {
            skip("interop jpssl-avx512 : cpu_has_avx512()=false (本机无 AVX512, 调用会 SIGILL, 绝不调用)");
            continue;
        }
        uint8_t pub[32], priv[64], sig[64];
        im.keygen(pub, priv);
        im.sign(priv, msg, msglen, sig);

        // jpssl 签 → OpenSSL 验
        EVP_PKEY* jp_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub, 32);
        bool jp2os = jp_pub != nullptr
            && EVP_MD_CTX_reset(mctx) == 1
            && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, jp_pub) == 1
            && EVP_DigestVerify(mctx, sig, 64, msg, msglen) == 1;
        EVP_PKEY_free(jp_pub);

        // OpenSSL 签 → jpssl 验
        bool os2jp = ossl_sign_ok && im.verify(ossl_pub, msg, msglen, ossl_sig);

        // 自验: 自身签名 → 自身验
        bool self = im.verify(pub, msg, msglen, sig);

        char what[96];
        std::snprintf(what, sizeof what, "%s jpssl->openssl", im.name);
        selfcheck(what, jp2os);
        std::snprintf(what, sizeof what, "%s openssl->jpssl", im.name);
        selfcheck(what, os2jp);
        std::snprintf(what, sizeof what, "%s self-roundtrip", im.name);
        selfcheck(what, self);
    }

    EVP_PKEY_free(ossl_key);
    EVP_MD_CTX_free(mctx);
}

// 批量验签自检: N=64/256 与 OpenSSL 逐条循环验签一致 + 负例
static constexpr int kBatchN = 256;

struct BatchCtx {
    std::vector<std::array<uint8_t, 32>> pubs;
    std::vector<std::array<uint8_t, 64>> privs;   // 64B! ed25519_keygen 写 pub[32]+priv[64]
    std::vector<std::array<uint8_t, 64>> sigs;
    std::vector<const uint8_t*> pub_ptrs, msg_ptrs, sig_ptrs;
    std::vector<size_t> lens;
    std::vector<EVP_PKEY*> ovpubs;
};

static void batch_build(BatchCtx& c, const uint8_t* msg, size_t msglen) {
    c.pubs.resize(kBatchN);
    c.privs.resize(kBatchN);
    c.sigs.resize(kBatchN);
    c.pub_ptrs.resize(kBatchN);
    c.msg_ptrs.resize(kBatchN, msg);
    c.sig_ptrs.resize(kBatchN);
    c.lens.resize(kBatchN, msglen);
    for (int i = 0; i < kBatchN; ++i) {
        jpssl::ed25519_keygen(c.pubs[i].data(), c.privs[i].data());
        jpssl::ed25519_sign(c.privs[i].data(), msg, msglen, c.sigs[i].data());
        c.pub_ptrs[i] = c.pubs[i].data();
        c.sig_ptrs[i] = c.sigs[i].data();
        c.ovpubs.push_back(
            EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, c.pubs[i].data(), 32));
    }
}

static void batch_selfchecks(BatchCtx& c, const uint8_t* msg, size_t msglen) {
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    for (int n : {64, 256}) {
        bool jp_ok = jpssl::ed25519_batch_verify(
            c.pub_ptrs.data(), c.msg_ptrs.data(), c.lens.data(), c.sig_ptrs.data(), n);
        bool os_ok = true;
        for (int i = 0; i < n; ++i) {
            if (EVP_MD_CTX_reset(mctx) != 1
                || EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, c.ovpubs[i]) != 1
                || EVP_DigestVerify(mctx, c.sigs[i].data(), 64, msg, msglen) != 1) {
                os_ok = false;
                break;
            }
        }
        char what[96];
        std::snprintf(what, sizeof what, "batch x%d jpssl==openssl-loop", n);
        selfcheck(what, jp_ok && os_ok);
    }

    // 负例: 破坏第 4 条签名 → 批量必须拒绝 (随机盲化下确定性失败)
    {
        uint8_t corrupt[64];
        memcpy(corrupt, c.sigs[3].data(), 64);
        corrupt[0] ^= 0x01;
        const uint8_t* saved = c.sig_ptrs[3];
        c.sig_ptrs[3] = corrupt;
        bool neg = !jpssl::ed25519_batch_verify(
            c.pub_ptrs.data(), c.msg_ptrs.data(), c.lens.data(), c.sig_ptrs.data(), 64);
        c.sig_ptrs[3] = saved;
        selfcheck("batch x64 negative (corrupt 1 sig)", neg);
    }
    EVP_MD_CTX_free(mctx);
}

// ─────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────
int main() {
    const bool smoke = std::getenv("BENCH_SMOKE") != nullptr;
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;

    const auto feats = jpssl::cpu_features::detect();
    printf("=== bench_ed25519: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("mode    : %s\n", smoke ? "SMOKE (32B only, 1 round, ~80ms)" : "FULL (4 sizes, 3 rounds, ~150ms)");
    printf("CPU     : x86_64  AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES=%d SHA-NI=%d\n",
           feats.aesni ? 1 : 0, feats.avx2 ? 1 : 0, feats.pclmulqdq ? 1 : 0,
           feats.avx512 ? 1 : 0, feats.vpclmulqdq_vaes ? 1 : 0, feats.sha_ni ? 1 : 0);
    printf("batch backend size (ed25519_batch_size): %d\n", jpssl::ed25519_batch_size());

    // 消息矩阵: smoke 只 32B 一档
    std::vector<size_t> sizes;
    if (smoke) sizes.push_back(32);
    else for (size_t s : kSizes) sizes.push_back(s);
    std::vector<std::vector<uint8_t>> msgs;
    for (size_t s : sizes) msgs.push_back(g_msg(s));
    const uint8_t* m32 = msgs[0].data();
    const size_t m32len = msgs[0].size();

    // ── 1. 互操作自检 (始终执行) ────────────────────────────────────
    printf("\n=== interop self-tests (msg 32B) ===\n");
    single_path_selfchecks(m32, m32len);

    BatchCtx batch;
    batch_build(batch, m32, m32len);
    batch_selfchecks(batch, m32, m32len);

    if (g_fail) {
        printf("\nself-tests FAILED (%d), abort without CSV\n", g_fail);
        for (EVP_PKEY* k : batch.ovpubs) EVP_PKEY_free(k);
        return 1;
    }
    printf("all self-tests PASS (%d checks)\n", g_pass);

    // ── 2. SKIP 说明 ────────────────────────────────────────────────
    printf("\n=== SKIPs (不支持的实现, 绝不被调用) ===\n");
    if (!feats.avx512) {
        skip("ed25519-avx512 keygen/sign/verify (+interop) : cpu_has_avx512()=false (本机调用会 SIGILL)");
    }
    if (g_skip_count == 0) printf("  (none)\n");

    // 供基准使用的 jpssl 默认密钥与 OpenSSL 密钥 (来自自检)
    uint8_t pub[32], priv[64], sig[64];
    jpssl::ed25519_keygen(pub, priv);
    jpssl::ed25519_sign(priv, m32, m32len, sig);

    EVP_PKEY* ossl_pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub, 32);
    EVP_PKEY* ossl_key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    uint8_t ossl_pub[32], ossl_sig[64];
    size_t plen = 32;
    EVP_PKEY_get_raw_public_key(ossl_key, ossl_pub, &plen);

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();

    // ── 3. 基准测量 ──────────────────────────────────────────────────
    printf("\n=== Ed25519 keygen (size=0) ===\n");
    for (const SigImpl& im : kImpls) {
        if (is_avx512(im) && !feats.avx512) continue;
        double ns = auto_bench("ed25519-keygen", [im] {
            uint8_t p[32], k[64];
            im.keygen(p, k);
            g_sink ^= p[0] ^ k[0];
        }, target_ms, rounds);
        emit_row("ed25519-keygen", im.name, 0, ns);
    }
    {
        double ns = auto_bench("ed25519-keygen", [] {
            EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
            if (k) EVP_PKEY_free(k);
        }, target_ms, rounds);
        emit_row("ed25519-keygen", "openssl", 0, ns);
    }

    printf("\n=== Ed25519 sign / verify (size=%s) ===\n", smoke ? "32" : "32,256,1024,65536");
    for (size_t idx = 0; idx < sizes.size(); ++idx) {
        const size_t size = sizes[idx];
        const uint8_t* m = msgs[idx].data();

        // 该长度下由 jpssl 默认路径生成一份基准签名 (所有验签用例共用)
        uint8_t sig_for_size[64];
        jpssl::ed25519_sign(priv, m, size, sig_for_size);

        for (const SigImpl& im : kImpls) {
            if (is_avx512(im) && !feats.avx512) continue;
            uint8_t sbuf[64];
            double s = auto_bench("ed25519-sign", [im, priv, m, size, &sbuf] {
                im.sign(priv, m, size, sbuf);
                g_sink ^= sbuf[0];
            }, target_ms, rounds);
            emit_row("ed25519-sign", im.name, size, s);
        }
        {
            double s = auto_bench("ed25519-sign", [&, m, size] {
                size_t sl = 64;
                EVP_MD_CTX_reset(mctx);
                EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ossl_key);
                EVP_DigestSign(mctx, ossl_sig, &sl, m, size);
                g_sink ^= ossl_sig[0];
            }, target_ms, rounds);
            emit_row("ed25519-sign", "openssl", size, s);
        }

        for (const SigImpl& im : kImpls) {
            if (is_avx512(im) && !feats.avx512) continue;
            double v = auto_bench("ed25519-verify", [im, pub, m, size, &sig_for_size] {
                g_sink ^= im.verify(pub, m, size, sig_for_size) ? 1 : 0;
            }, target_ms, rounds);
            emit_row("ed25519-verify", im.name, size, v);
        }
        {
            double v = auto_bench("ed25519-verify", [&, m, size] {
                EVP_MD_CTX_reset(mctx);
                EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ossl_pubkey);
                int r = EVP_DigestVerify(mctx, sig_for_size, 64, m, size);
                g_sink ^= r;
            }, target_ms, rounds);
            emit_row("ed25519-verify", "openssl", size, v);
        }
    }

    printf("\n=== Ed25519 batch verify (msg 32B, N=%s) ===\n", smoke ? "64" : "64/256");
    {
        std::vector<int> ns;
        if (smoke) ns.push_back(64);
        else { ns.push_back(64); ns.push_back(256); }
        for (int n : ns) {
            double b = auto_bench("ed25519-batch", [&, n] {
                g_sink ^= jpssl::ed25519_batch_verify(
                    batch.pub_ptrs.data(), batch.msg_ptrs.data(), batch.lens.data(),
                    batch.sig_ptrs.data(), n) ? 1 : 0;
            }, target_ms, rounds, 1);
            char impl[32];
            std::snprintf(impl, sizeof impl, "jpssl-batch%d", n);
            emit_row("ed25519-batch", impl, m32len, b);

            double o = auto_bench("ed25519-batch", [&, n] {
                int r = 0;
                for (int i = 0; i < n; ++i) {
                    EVP_MD_CTX_reset(mctx);
                    EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, batch.ovpubs[i]);
                    r ^= EVP_DigestVerify(mctx, batch.sigs[i].data(), 64, m32, m32len);
                }
                g_sink ^= r;
            }, target_ms, rounds, 1);
            emit_row("ed25519-batch", "openssl", m32len, o);
        }
    }

    // ── 4. CSV 输出 ──────────────────────────────────────────────────
    std::filesystem::create_directories("benchmarks/results");
    const char* csv_path = "benchmarks/results/bench_ed25519.csv";
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
    EVP_PKEY_free(ossl_pubkey);
    EVP_PKEY_free(ossl_key);
    for (EVP_PKEY* k : batch.ovpubs) EVP_PKEY_free(k);
    printf("(sink=%d, self-test PASS=%d, skips=%d)\n", g_sink, g_pass, g_skip_count);
    return 0;
}
