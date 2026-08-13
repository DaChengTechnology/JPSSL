// bench_sha3.cpp — SHA3 家族 (SHA3-256/384/512) 多长度 × 实现 × OpenSSL 对比微基准
//
// 覆盖矩阵:
//   SHA3-256 : jpssl scalar (sha3_256_init/update/final) vs OpenSSL EVP_sha3_256
//   SHA3-384 : jpssl scalar (sha3_384_init/update/final) vs OpenSSL EVP_sha3_384
//   SHA3-512 : jpssl scalar (sha3_512_init/update/final) vs OpenSSL EVP_sha3_512
//   (SHA3 在 jpssl 中为纯 C 标量实现, 无 SIMD 变体, 故实现路径 = 标量 + OpenSSL)
//
// 性能长度: 16 / 256 / 4096 / 65536 / 1048576 (全量)
//           16 / 256                                (BENCH_SMOKE=1, 约 80ms/项, 1 轮)
//
// 正确性: 各变体与 OpenSSL 在 256B 与 1MB 两档逐字节比对;
//   任一 FAIL 打印后立即非零退出, 全部 PASS 才进行基准并写 CSV。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_sha3.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_sha3
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_sha3.csv
//   CSV 列: algo,impl,size_bytes,ns_per_op,throughput_mbps
//   algo = sha3-256 / sha3-384 / sha3-512; impl = jpssl-scalar / openssl
//
// 环境变量: BENCH_SMOKE=1  → smoke 模式 (长度 16/256, ~80ms, 1 轮取最小)
//           未设置          → 全量模式 (5 档长度, ~150ms, 3 轮取最小)

#include "sha3.hpp"

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

static volatile uint8_t g_sink = 0;  // 阻止编译器把纯计算优化掉

// ── 自适应迭代微基准: 每轮跑约 target_ms, rounds 轮取最小值 ──
template <typename F>
static double auto_bench(F&& f, double target_ms = 150.0, int rounds = 3) {
    f();  // 预热
    int est_n = 8;
    auto t0 = Clock::now();
    for (int i = 0; i < est_n; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / est_n;
    if (est_ns < 1000.0) {  // 太快, 加大估计样本
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
    return best;
}

// ── 结果收集 ──
struct Row {
    std::string algo;
    std::string impl;
    size_t size;
    double ns;
    double bytes_per_op;
};
static std::vector<Row> g_rows;

template <typename F>
static void bench_case(const char* algo, const char* impl, size_t size,
                       double bytes_per_op, double target_ms, int rounds, F&& f) {
    double ns = auto_bench(std::forward<F>(f), target_ms, rounds);
    g_rows.push_back({algo, impl, size, ns, bytes_per_op});
    std::printf("%-10s %-14s %10zu %12.0f %12.1f\n",
                algo, impl, size, ns, bytes_per_op * 1000.0 / ns);
}

static std::string to_hex(const uint8_t* d, size_t n) {
    static const char* hexd = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s += hexd[d[i] >> 4];
        s += hexd[d[i] & 0xf];
    }
    return s;
}

// ── 数据 ──
static constexpr size_t kMax = 1048576 + 128;
static uint8_t g_data[kMax];

static void fill_deterministic(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        p[i] = (uint8_t)(x >> 24);
    }
}

static constexpr size_t kBenchSizesFull[]  = {16, 256, 4096, 65536, 1048576};
static constexpr size_t kBenchSizesSmoke[] = {16, 256};
static constexpr size_t kCheckSizes[]      = {256, 1048576};  // 自检档位 (始终全跑)

// ── jpssl SHA3 封装 (streaming, 与 OpenSSL streaming 对齐) ──
static void jp_sha3(const uint8_t* d, size_t n, uint8_t out[64], int bits) {
    jpssl::sha3_ctx c;
    if (bits == 256) jpssl::sha3_256_init(&c);
    else if (bits == 384) jpssl::sha3_384_init(&c);
    else jpssl::sha3_512_init(&c);
    if (n) jpssl::sha3_update(&c, d, n);
    jpssl::sha3_final(&c, out);
}

// ── OpenSSL 哈希 (复用 ctx, 每次 op 重新 Init) ──
struct OsslDigest {
    const EVP_MD* md;
    EVP_MD_CTX* ctx;
    uint8_t out[64];
    unsigned int out_len = 0;
    explicit OsslDigest(const EVP_MD* m) : md(m), ctx(EVP_MD_CTX_new()) {}
    ~OsslDigest() { EVP_MD_CTX_free(ctx); }
    void op(const uint8_t* data, size_t len) {
        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, data, len);
        EVP_DigestFinal_ex(ctx, out, &out_len);
    }
};

int main() {
    std::printf("=== jpssl SHA3 (256/384/512) vs OpenSSL 微基准 ===\n");
    std::printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);

    const char* smoke_env = std::getenv("BENCH_SMOKE");
    const bool smoke = (smoke_env != nullptr && std::strcmp(smoke_env, "0") != 0);
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;
    const size_t* bench_sizes = smoke ? kBenchSizesSmoke : kBenchSizesFull;
    const size_t n_bench_sizes = smoke ? 2 : 5;
    std::printf("mode        : %s (target=%.0fms, rounds=%d, bench_len=%zu)\n",
                smoke ? "SMOKE" : "FULL", target_ms, rounds, n_bench_sizes);

    // ── 数据准备 (确定性内容) ──
    fill_deterministic(g_data, kMax, 0x12345678u);

    OsslDigest od_sha3_256(EVP_sha3_256()), od_sha3_384(EVP_sha3_384()), od_sha3_512(EVP_sha3_512());

    // ── 正确性自检 (jpssl scalar vs OpenSSL, 逐字节) ──
    std::printf("\n--- 正确性自检 (jpssl scalar vs OpenSSL, 逐字节) ---\n");
    bool all_pass = true;
    int pass_count = 0, fail_count = 0;
    auto check = [&](const char* what, const std::string& got, const std::string& want) {
        bool ok = (got == want);
        all_pass = all_pass && ok;
        if (ok) ++pass_count; else ++fail_count;
        std::printf("  check %-40s : %s\n", what, ok ? "PASS" : "FAIL");
        if (!ok) {
            std::printf("        jpssl   = %s\n", got.c_str());
            std::printf("        openssl = %s\n", want.c_str());
        }
    };

    for (size_t s : kCheckSizes) {
        char tag[64];
        uint8_t a[64];
        // SHA3-256 (32B 摘要)
        jp_sha3(g_data, s, a, 256); od_sha3_256.op(g_data, s);
        std::snprintf(tag, sizeof(tag), "sha3-256 scalar len=%zu", s);
        check(tag, to_hex(a, 32), to_hex(od_sha3_256.out, od_sha3_256.out_len));
        // SHA3-384 (48B 摘要)
        jp_sha3(g_data, s, a, 384); od_sha3_384.op(g_data, s);
        std::snprintf(tag, sizeof(tag), "sha3-384 scalar len=%zu", s);
        check(tag, to_hex(a, 48), to_hex(od_sha3_384.out, od_sha3_384.out_len));
        // SHA3-512 (64B 摘要)
        jp_sha3(g_data, s, a, 512); od_sha3_512.op(g_data, s);
        std::snprintf(tag, sizeof(tag), "sha3-512 scalar len=%zu", s);
        check(tag, to_hex(a, 64), to_hex(od_sha3_512.out, od_sha3_512.out_len));
    }

    std::printf("\n自检汇总: PASS=%d FAIL=%d\n", pass_count, fail_count);
    if (!all_pass) {
        std::printf("自检失败, 退出 (非零)\n");
        return 1;
    }

    // ── 性能基准 ──
    std::printf("\n%-10s %-14s %10s %12s %12s\n", "algo", "impl", "size", "ns/op", "MB/s");
    for (size_t i = 0; i < n_bench_sizes; ++i) {
        size_t s = bench_sizes[i];
        uint8_t out[64];
        bench_case("sha3-256", "jpssl-scalar", s, (double)s, target_ms, rounds,
                   [&] { jp_sha3(g_data, s, out, 256); g_sink ^= out[0]; });
        bench_case("sha3-256", "openssl", s, (double)s, target_ms, rounds,
                   [&] { od_sha3_256.op(g_data, s); g_sink ^= od_sha3_256.out[0]; });
        bench_case("sha3-384", "jpssl-scalar", s, (double)s, target_ms, rounds,
                   [&] { jp_sha3(g_data, s, out, 384); g_sink ^= out[0]; });
        bench_case("sha3-384", "openssl", s, (double)s, target_ms, rounds,
                   [&] { od_sha3_384.op(g_data, s); g_sink ^= od_sha3_384.out[0]; });
        bench_case("sha3-512", "jpssl-scalar", s, (double)s, target_ms, rounds,
                   [&] { jp_sha3(g_data, s, out, 512); g_sink ^= out[0]; });
        bench_case("sha3-512", "openssl", s, (double)s, target_ms, rounds,
                   [&] { od_sha3_512.op(g_data, s); g_sink ^= od_sha3_512.out[0]; });
    }

    // ── 写 CSV ──
    int mkrc = std::system("mkdir -p benchmarks/results");
    (void)mkrc;  // 目录已存在时 mkdir 返回非零, 忽略
    std::FILE* fp = std::fopen("benchmarks/results/bench_sha3.csv", "w");
    if (!fp) {
        std::printf("ERROR: 无法写 CSV 文件\n");
        return 1;
    }
    std::fprintf(fp, "algo,impl,size_bytes,ns_per_op,throughput_mbps\n");
    for (const Row& r : g_rows) {
        double mbps = r.bytes_per_op * 1000.0 / r.ns;
        std::fprintf(fp, "%s,%s,%zu,%.1f,%.3f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.ns, mbps);
    }
    std::fclose(fp);
    std::printf("\nCSV 已写入 benchmarks/results/bench_sha3.csv (%zu 数据行)\n", g_rows.size());
    return 0;
}
