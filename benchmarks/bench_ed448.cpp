// bench_ed448.cpp — Ed448 全量测试/基准: jpssl 全部实现路径 × 多消息长度 × OpenSSL 对比
//
// 覆盖矩阵:
//   keygen              : jpssl (ed448_generate_keypair) vs OpenSSL (EVP_PKEY ED448)
//   sign / verify       : jpssl (ed448_sign / ed448_verify) vs OpenSSL (EVP_DigestSign/Verify)
//                         消息长度 32 / 256 / 1024 / 65536 字节 (BENCH_SMOKE=1 时仅 32)
//   batch verify        : N=64 / N=256, 32B 消息
//                         - jpssl::ed448_batch_verify (默认派发: AVX512>AVX2>scalar)
//                         - jpssl::detail::ed448_batch_verify_avx2  (显式 AVX2, cpu_has_avx2 时才调用)
//                         - jpssl::detail::ed448_batch_verify_avx512 (显式 AVX512, cpu_has_avx512 时才调用)
//                         - OpenSSL 逐条循环验签
//
// 正确性自检 (始终执行, 任一 FAIL 非零退出且不输出 CSV):
//   S1. jpssl 密钥生成+签名 → OpenSSL 验签 (32B)
//   S2. OpenSSL 密钥生成+签名 → jpssl 验签 (32B)
//   S3. 篡改签名被 jpssl 与 OpenSSL 同时拒绝
//   S4. jpssl 批量验签 x256 (默认派发) 与 OpenSSL 逐条循环验签结果一致
//   S5. 显式 AVX2 批量后端 x256 与默认派发一致 (cpu_has_avx2 时)
//   S6. 显式 AVX512 批量后端 x256 与默认派发一致 (cpu_has_avx512 时)
//
// 基准模式:
//   BENCH_SMOKE=1: 仅 32B 一档, ~80ms/轮, 1 轮 (不取最小)
//   未设置      :  4 档, ~150ms/轮, 3 轮取最小
//
// 输出: benchmarks/results/bench_ed448.csv
//   列头: algo,impl,size_bytes,ns_per_op,ops_per_sec
//   algo: ed448-keygen / ed448-sign / ed448-verify / ed448-batch
//   impl: jpssl / jpssl-avx2 / jpssl-avx512 / jpssl-batch64 / jpssl-batch256 / openssl
//   (batch 行 size_bytes = 消息长度 32B; N 编码在 impl 名 jpssl-batch64/jpssl-batch256;
//    显式后端行 jpssl-avx2/jpssl-avx512 在 N=256 记录)
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_ed448.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_ed448

#include "ed448.hpp"
#include "ed448_batch.hpp"
#include "cpu_features.hpp"

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <algorithm>
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
// 消息长度矩阵 + 确定性消息数据
// ─────────────────────────────────────────────────────────────────────
static const std::array<size_t, 4> kAllSizes = {32, 256, 1024, 65536};

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
    std::printf("  %-22s %-18s %6zu %13.1f ns/op %12.2f ops/s\n",
                algo, impl, size, ns, 1e9 / ns);
}

static int g_skip_count = 0;
static void skip(const char* msg) {
    ++g_skip_count;
    std::printf("  SKIP %s\n", msg);
}

static int g_pass = 0, g_fail = 0;
static void selfcheck(const char* name, bool ok) {
    if (ok) { ++g_pass; std::printf("  selfcheck %-46s : PASS\n", name); }
    else    { ++g_fail; std::printf("  selfcheck %-46s : FAIL\n", name); }
}

// ─────────────────────────────────────────────────────────────────────
// 自适应迭代微基准: 每轮约 target_ms, rounds 轮取最小值
// ─────────────────────────────────────────────────────────────────────
template <typename F>
static double auto_bench(const char* name, F&& f, double target_ms, int rounds) {
    f(); // 预热
    auto t0 = Clock::now();
    for (int i = 0; i < 8; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / 8;
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
    std::printf("  %-22s %-18s %6s %13.1f ns/op %12.2f ops/s   (iters=%lld)\n",
                name, "", "", best, 1e9 / best, iters);
    return best;
}

// ─────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────
int main() {
    const bool smoke = (std::getenv("BENCH_SMOKE") != nullptr);
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds       = smoke ? 1 : 3;

    const auto feats = jpssl::cpu_features::detect();
    std::printf("=== bench_ed448: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    std::printf("CPU : x86_64 AVX2=%d AVX512=%d NEON=%d\n",
                feats.avx2 ? 1 : 0, feats.avx512 ? 1 : 0, feats.neon ? 1 : 0);
    std::printf("mode: %s (target_ms=%.0f, rounds=%d)\n",
                smoke ? "SMOKE" : "FULL", target_ms, rounds);
    std::printf("jpssl ed448_batch_size() = %d (%s)\n", jpssl::ed448_batch_size(),
                jpssl::ed448_batch_size() == 8 ? "AVX512" :
                (jpssl::ed448_batch_size() == 4 ? "AVX2" : "scalar"));

    std::vector<size_t> sizes;
    if (smoke) sizes.push_back(32);
    else sizes.assign(kAllSizes.begin(), kAllSizes.end());
    std::vector<std::vector<uint8_t>> msgs;
    for (size_t s : sizes) msgs.push_back(g_msg(s));
    const std::vector<uint8_t> m32 = g_msg(32);

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY* ossl_key = nullptr;
    EVP_PKEY* ossl_pubkey = nullptr;

    // ── 1. 正确性自检 (始终执行) ────────────────────────────────────
    std::printf("\n=== interop self-tests ===\n");
    uint8_t pub[57], priv[114], sig[114];
    uint8_t ossl_pub[57], ossl_sig[114];

    // S1. jpssl → OpenSSL (32B)
    jpssl::ed448_generate_keypair(pub, priv);
    jpssl::ed448_sign(priv, m32.data(), m32.size(), sig);
    ossl_pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr, pub, 57);
    bool jp2os = ossl_pubkey != nullptr
        && EVP_MD_CTX_reset(mctx) == 1
        && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ossl_pubkey) == 1
        && EVP_DigestVerify(mctx, sig, 114, m32.data(), m32.size()) == 1;
    selfcheck("ed448 jpssl->ossl (keygen+sign, 32B)", jp2os);

    // S2. OpenSSL → jpssl (32B)
    ossl_key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED448");
    size_t plen = 57;
    EVP_PKEY_get_raw_public_key(ossl_key, ossl_pub, &plen);
    size_t slen = 114;
    bool sgn = ossl_key != nullptr
        && EVP_MD_CTX_reset(mctx) == 1
        && EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ossl_key) == 1
        && EVP_DigestSign(mctx, ossl_sig, &slen, m32.data(), m32.size()) == 1
        && slen == 114;
    bool os2jp = sgn && jpssl::ed448_verify(ossl_pub, m32.data(), m32.size(), ossl_sig);
    selfcheck("ed448 ossl->jpssl (ossl keygen+sign, 32B)", os2jp);

    // S3. 篡改签名拒绝 (jpssl + OpenSSL 都必须拒绝)
    {
        uint8_t bad_sig[114];
        std::memcpy(bad_sig, sig, 114);
        bad_sig[57] ^= 0x01;
        bool jp_reject = !jpssl::ed448_verify(pub, m32.data(), m32.size(), bad_sig);
        bool os_reject = ossl_pubkey != nullptr
            && EVP_MD_CTX_reset(mctx) == 1
            && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ossl_pubkey) == 1
            && EVP_DigestVerify(mctx, bad_sig, 114, m32.data(), m32.size()) <= 0;
        selfcheck("ed448 tampered sig rejected (jpssl+ossl)", jp_reject && os_reject);
    }

    // 批量验签数据集 (256 组, 32B 消息)
    constexpr int BN = 256;
    std::vector<std::array<uint8_t, 57>>  bpubs(BN);
    std::vector<std::array<uint8_t, 114>> bprivs(BN), bsigs(BN);
    std::vector<const uint8_t*> pubp(BN), msgp(BN, m32.data()), sigp(BN);
    std::vector<size_t> lens(BN, m32.size());
    std::vector<EVP_PKEY*> ovpubs(BN);
    for (int i = 0; i < BN; ++i) {
        jpssl::ed448_keygen(bpubs[i].data(), bprivs[i].data());
        jpssl::ed448_sign(bprivs[i].data(), m32.data(), m32.size(), bsigs[i].data());
        pubp[i] = bpubs[i].data();
        sigp[i] = bsigs[i].data();
        ovpubs[i] = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr, bpubs[i].data(), 57);
    }

    // S4. jpssl 默认批量派发 x256 == OpenSSL 逐条循环 x256
    {
        bool batch_ok = jpssl::ed448_batch_verify(pubp.data(), msgp.data(), lens.data(),
                                                  sigp.data(), BN);
        bool loop_ok = true;
        for (int i = 0; i < BN; ++i) {
            if (ovpubs[i] == nullptr) { loop_ok = false; continue; }
            EVP_MD_CTX_reset(mctx);
            EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ovpubs[i]);
            loop_ok = loop_ok && (EVP_DigestVerify(mctx, bsigs[i].data(), 114,
                                                   m32.data(), m32.size()) == 1);
        }
        selfcheck("ed448 batch x256 == ossl loop x256", batch_ok && loop_ok);
    }

    // S5. 显式 AVX2 批量后端 x256 (cpu_has_avx2 时)
    if (feats.avx2) {
        bool ok = jpssl::detail::ed448_batch_verify_avx2(pubp.data(), msgp.data(), lens.data(),
                                                         sigp.data(), BN);
        selfcheck("ed448 batch x256 explicit avx2", ok);
    } else {
        skip("ed448-batch-avx2 : cpu_has_avx2()=false (不调用 AVX2 代码)");
    }

    // S6. 显式 AVX512 批量后端 x256 (cpu_has_avx512 时)
    if (feats.avx512) {
#if defined(JP_AVX512)
        bool ok = jpssl::detail::ed448_batch_verify_avx512(pubp.data(), msgp.data(), lens.data(),
                                                           sigp.data(), BN);
        selfcheck("ed448 batch x256 explicit avx512", ok);
#endif
    } else {
        skip("ed448-batch-avx512 : cpu_has_avx512()=false (本机无 AVX512, 调用会 SIGILL)");
    }

    if (g_fail) {
        std::printf("\ninterop FAILED (%d FAIL / %d PASS), abort without CSV\n", g_fail, g_pass);
        return 1;
    }
    std::printf("all self-tests PASS (%d)\n", g_pass);

    // ── 2. SKIP 说明 (不支持的实现, 绝不被调用) ─────────────────────
    std::printf("\n=== SKIPs (不支持的实现, 绝不被调用) ===\n");
    skip("ed448-sign/verify jpssl-avx2 : 头文件与库均未导出 Ed448 单条 SIMD 签名/验签变体 (仅批量验签后端存在)");
    skip("ed448-sign/verify jpssl-avx512 : 头文件与库均未导出 Ed448 单条 SIMD 签名/验签变体");
    if (!feats.avx512)
        skip("ed448-batch jpssl-avx512 : cpu_has_avx512()=false (本机无 AVX512, 调用会 SIGILL)");
    if (!feats.avx2)
        skip("ed448-batch jpssl-avx2 : cpu_has_avx2()=false (不调用 AVX2 代码)");
    if (!feats.neon)
        skip("ed448 NEON : 本机为 x86_64, NEON 不可用");

    // ── 3. 基准测量 ──────────────────────────────────────────────────
    std::printf("\n=== Ed448 keygen (size=0) ===\n");
    {
        double k1 = auto_bench("ed448-keygen", [] {
            uint8_t p[57], pk[114];
            jpssl::ed448_generate_keypair(p, pk);
            g_sink ^= p[0] ^ pk[0];
        }, target_ms, rounds);
        emit_row("ed448-keygen", "jpssl", 0, k1);

        double k2 = auto_bench("ed448-keygen", [] {
            EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED448");
            if (k) EVP_PKEY_free(k);
        }, target_ms, rounds);
        emit_row("ed448-keygen", "openssl", 0, k2);
    }

    std::printf("\n=== Ed448 sign / verify (size=%s) ===\n",
                smoke ? "32" : "32,256,1024,65536");
    for (size_t size : sizes) {
        const uint8_t* m = msgs[std::distance(sizes.begin(),
                                              std::find(sizes.begin(), sizes.end(), size))].data();
        uint8_t sbuf[114];

        double s1 = auto_bench("ed448-sign", [&] {
            jpssl::ed448_sign(priv, m, size, sbuf);
            g_sink ^= sbuf[0];
        }, target_ms, rounds);
        emit_row("ed448-sign", "jpssl", size, s1);

        double s2 = auto_bench("ed448-sign", [&] {
            size_t sl = 114;
            EVP_MD_CTX_reset(mctx);
            EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ossl_key);
            EVP_DigestSign(mctx, sbuf, &sl, m, size);
            g_sink ^= sbuf[0];
        }, target_ms, rounds);
        emit_row("ed448-sign", "openssl", size, s2);

        // 验签基准用当前消息长度的有效签名 (jpssl 私钥签发), 保证 jpssl 与
        // OpenSSL 两条验签路径都运行在"有效签名"路径上
        uint8_t vfysig[114];
        jpssl::ed448_sign(priv, m, size, vfysig);

        double v1 = auto_bench("ed448-verify", [&] {
            g_sink ^= jpssl::ed448_verify(pub, m, size, vfysig) ? 1 : 0;
        }, target_ms, rounds);
        emit_row("ed448-verify", "jpssl", size, v1);

        double v2 = auto_bench("ed448-verify", [&] {
            EVP_MD_CTX_reset(mctx);
            EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ossl_pubkey);
            int r = EVP_DigestVerify(mctx, vfysig, 114, m, size);
            g_sink ^= r;
        }, target_ms, rounds);
        emit_row("ed448-verify", "openssl", size, v2);
    }

    std::printf("\n=== Ed448 batch verify (size=32, N=64/256) ===\n");
    for (int n : {64, 256}) {
        const char* impl_def = (n == 64) ? "jpssl-batch64" : "jpssl-batch256";
        double b_def = auto_bench("ed448-batch", [&] {
            g_sink ^= jpssl::ed448_batch_verify(pubp.data(), msgp.data(), lens.data(),
                                                sigp.data(), n) ? 1 : 0;
        }, target_ms, rounds);
        emit_row("ed448-batch", impl_def, m32.size(), b_def);

        double o_loop = auto_bench("ed448-batch", [&] {
            int r = 0;
            for (int i = 0; i < n; ++i) {
                EVP_MD_CTX_reset(mctx);
                EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ovpubs[i]);
                r ^= EVP_DigestVerify(mctx, bsigs[i].data(), 114, m32.data(), m32.size());
            }
            g_sink ^= r;
        }, target_ms, rounds);
        emit_row("ed448-batch", "openssl", m32.size(), o_loop);

        if (n == 256) { // 显式后端 (N=256)
            if (feats.avx2) {
                double b_a2 = auto_bench("ed448-batch", [&] {
                    g_sink ^= jpssl::detail::ed448_batch_verify_avx2(
                        pubp.data(), msgp.data(), lens.data(), sigp.data(), n) ? 1 : 0;
                }, target_ms, rounds);
                emit_row("ed448-batch", "jpssl-avx2", m32.size(), b_a2);
            }
#if defined(JP_AVX512)
            if (feats.avx512) {
                double b_a5 = auto_bench("ed448-batch", [&] {
                    g_sink ^= jpssl::detail::ed448_batch_verify_avx512(
                        pubp.data(), msgp.data(), lens.data(), sigp.data(), n) ? 1 : 0;
                }, target_ms, rounds);
                emit_row("ed448-batch", "jpssl-avx512", m32.size(), b_a5);
            }
#endif
        }
    }

    // ── 4. CSV 输出 ──────────────────────────────────────────────────
    std::filesystem::create_directories("benchmarks/results");
    const char* csv_path = "benchmarks/results/bench_ed448.csv";
    FILE* csv = std::fopen(csv_path, "w");
    if (!csv) {
        // 兜底: 从仓库根以外的目录运行时写绝对路径
        csv_path = "/home/jp/jpssl/benchmarks/results/bench_ed448.csv";
        std::filesystem::create_directories("/home/jp/jpssl/benchmarks/results");
        csv = std::fopen(csv_path, "w");
    }
    if (!csv) {
        std::printf("ERROR: cannot open %s\n", csv_path);
        return 2;
    }
    std::fprintf(csv, "algo,impl,size_bytes,ns_per_op,ops_per_sec\n");
    for (const Row& r : g_rows) {
        std::fprintf(csv, "%s,%s,%zu,%.2f,%.2f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.ns, 1e9 / r.ns);
    }
    std::fclose(csv);
    std::printf("\nCSV written: %s (%zu rows)\n", csv_path, g_rows.size());

    for (EVP_PKEY* k : ovpubs) EVP_PKEY_free(k);
    EVP_PKEY_free(ossl_key);
    EVP_PKEY_free(ossl_pubkey);
    EVP_MD_CTX_free(mctx);
    std::printf("(sink=%d, passes=%d, skips=%d)\n", g_sink, g_pass, g_skip_count);
    return 0;
}
