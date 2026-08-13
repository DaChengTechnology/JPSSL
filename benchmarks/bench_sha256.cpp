// bench_sha256.cpp — SHA-256 全量微基准 + 正确性自检 (jpssl scalar / sha_ni vs OpenSSL)
//
// 覆盖矩阵:
//   SHA-256 : jpssl scalar (sha256_init/update/final)
//             jpssl sha_ni  (sha256_sha_ni, cpu_has_sha_ni 守卫)
//             OpenSSL EVP_sha256
//   (SHA-224 不在覆盖范围: include/sha256.hpp 与 src/ 均未提供 sha224 API)
//
// 正确性自检: 全部 5 档长度 × 每个 jpssl 路径 与 OpenSSL 摘要逐字节比对,
//   另加空串/"abc" 已知答案向量 (KAT); 任一 FAIL 立即非零退出。
//   自检不依赖 BENCH_SMOKE, 始终跑全部档位。
//
// 性能基准: BENCH_SMOKE=1 -> 长度 {16,256}, ~80ms/轮, 1 轮;
//           未设置      -> 5 档 {16,256,4096,65536,1048576}, ~150ms/轮, 3 轮取最小。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_sha256.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_sha256
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_sha256.csv
//   CSV 列: algo,impl,size_bytes,ns_per_op,throughput_mbps

#include "sha256.hpp"
#include "cpu_features.hpp"

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
static double auto_bench(F&& f, double target_ms, int rounds) {
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

static double g_target_ms = 150.0;
static int g_rounds = 3;

template <typename F>
static void bench_case(const char* algo, const char* impl, size_t size,
                       double bytes_per_op, F&& f) {
    double ns = auto_bench(std::forward<F>(f), g_target_ms, g_rounds);
    g_rows.push_back({algo, impl, size, ns, bytes_per_op});
    std::printf("%-13s %-18s %10zu %12.0f %12.1f\n",
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

static constexpr size_t kSizes[] = {16, 256, 4096, 65536, 1048576};

// ── jpssl scalar 封装 (streaming, 与 OpenSSL streaming 对齐) ──
static void jp_sha256_scalar(const uint8_t* d, size_t n, uint8_t out[32]) {
    jpssl::sha256_ctx c; jpssl::sha256_init(&c);
    if (n) jpssl::sha256_update(&c, d, n);
    jpssl::sha256_final(&c, out);
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
    std::printf("=== jpssl SHA-256 vs OpenSSL 微基准 ===\n");
    std::printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    std::printf("CPU features   : AES-NI=%d AVX2=%d PCLMULQDQ=%d VAES=%d SHA-NI=%d ADX=%d AVX512=%d NEON=%d\n",
                (int)jpssl::cpu_has_aesni(), (int)jpssl::cpu_has_avx2(),
                (int)jpssl::cpu_has_pclmulqdq(), (int)jpssl::cpu_has_vpclmulqdq_vaes(),
                (int)jpssl::cpu_has_sha_ni(), (int)jpssl::cpu_has_adx(),
                (int)jpssl::cpu_has_avx512(), (int)jpssl::cpu_has_neon());

    // ── 运行模式 ──
    const bool smoke = (std::getenv("BENCH_SMOKE") != nullptr);
    if (smoke) {
        g_target_ms = 80.0;
        g_rounds = 1;
        std::printf("Mode         : SMOKE (BENCH_SMOKE=1, sizes={16,256}, ~80ms, 1 round)\n");
    } else {
        std::printf("Mode         : FULL (5 sizes, ~150ms, 3 rounds, min)\n");
    }

    fill_deterministic(g_data, kMax, 0x12345678u);
    const bool has_sha_ni = jpssl::cpu_has_sha_ni();

    // ── 正确性自检 (jpssl 各实现 vs OpenSSL; 始终全部档位) ──
    std::printf("\n--- 正确性自检 (jpssl 各实现 vs OpenSSL) ---\n");
    bool all_pass = true;
    auto check = [&](const char* what, const std::string& got, const std::string& want) {
        bool ok = (got == want);
        all_pass = all_pass && ok;
        std::printf("  check %-38s : %s\n", what, ok ? "PASS" : "FAIL");
        if (!ok) {
            std::printf("        jpssl   = %s\n", got.c_str());
            std::printf("        openssl = %s\n", want.c_str());
        }
    };

    OsslDigest od_sha256(EVP_sha256());

    // KAT: 空串与 "abc" 的已知答案向量 (FIPS 180-4)
    {
        uint8_t a[32];
        jp_sha256_scalar(nullptr, 0, a);
        check("sha256 KAT empty (scalar)", to_hex(a, 32),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        if (has_sha_ni) {
            jpssl::sha256_sha_ni(a, nullptr, 0);
            check("sha256 KAT empty (sha_ni)", to_hex(a, 32),
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        }
        const char* abc = "abc";
        jp_sha256_scalar((const uint8_t*)abc, 3, a);
        check("sha256 KAT abc (scalar)", to_hex(a, 32),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        if (has_sha_ni) {
            jpssl::sha256_sha_ni(a, (const uint8_t*)abc, 3);
            check("sha256 KAT abc (sha_ni)", to_hex(a, 32),
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }
    }

    for (size_t s : kSizes) {
        char tag[64];
        {
            uint8_t a[32];
            jp_sha256_scalar(g_data, s, a); od_sha256.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha256 scalar  len=%zu", s);
            check(tag, to_hex(a, 32), to_hex(od_sha256.out, 32));
        }
        if (has_sha_ni) {
            uint8_t a[32];
            jpssl::sha256_sha_ni(a, g_data, s); od_sha256.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha256 sha_ni  len=%zu", s);
            check(tag, to_hex(a, 32), to_hex(od_sha256.out, 32));
        }
    }

    if (!all_pass) {
        std::printf("\n正确性自检存在 FAIL, 退出(1)\n");
        return 1;
    }
    std::printf("\n正确性自检: 全部 PASS\n");

    // ── 性能基准 ──
    std::printf("\n--- 性能 (ns/op, MB/s) ---\n");
    std::printf("%-13s %-18s %10s %12s %12s\n",
                "algo", "impl", "size_bytes", "ns_per_op", "MB/s");

    const size_t* bench_sizes = kSizes;
    size_t bench_count = sizeof(kSizes) / sizeof(kSizes[0]);
    if (smoke) {
        static constexpr size_t kSmokeSizes[] = {16, 256};
        bench_sizes = kSmokeSizes;
        bench_count = 2;
    }

    for (size_t i = 0; i < bench_count; ++i) {
        const size_t s = bench_sizes[i];
        uint8_t out[32];
        bench_case("sha256", "jpssl-scalar", s, (double)s,
                   [&] { jp_sha256_scalar(g_data, s, out); g_sink ^= out[0]; });
        if (has_sha_ni) {
            bench_case("sha256", "jpssl-sha_ni", s, (double)s,
                       [&] { jpssl::sha256_sha_ni(out, g_data, s); g_sink ^= out[0]; });
        } else {
            std::printf("SKIP sha256 jpssl-sha_ni (cpu_has_sha_ni()=false)\n");
        }
        bench_case("sha256", "openssl", s, (double)s,
                   [&] { od_sha256.op(g_data, s); g_sink ^= od_sha256.out[0]; });
    }

    // ── 写 CSV ──
    if (std::system("mkdir -p benchmarks/results") != 0) {
        std::printf("ERROR: mkdir benchmarks/results 失败\n");
        return 1;
    }
    std::FILE* fp = std::fopen("benchmarks/results/bench_sha256.csv", "w");
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
    std::printf("\nCSV 已写入 benchmarks/results/bench_sha256.csv (%zu 行)\n", g_rows.size());
    std::printf("sink=%u\n", (unsigned)g_sink);  // 用掉 sink, 避免未使用告警
    return 0;
}
