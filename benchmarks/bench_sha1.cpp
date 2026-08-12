// bench_sha1.cpp — SHA-1 全量测试: 全部实现路径 × 多长度 × OpenSSL 对比
//
// 覆盖矩阵 (消息长度: 16 / 256 / 4096 / 65536 / 1048576 字节):
//   jpssl-scalar      : sha1_init/update/final (streaming)
//   jpssl-avx2-batch  : sha1_multi_avx2  (8 条独立等长消息批量, cpu_has_avx2() 守卫)
//   jpssl-avx512-batch: sha1_multi_avx512 (16 条独立等长消息批量, cpu_has_avx512() 守卫;
//                        本机不支持则打印 SKIP 绝不调用, 避免 SIGILL)
//   openssl           : EVP_sha1
//
// 正确性自检: 每个可用实现 × 全部档位, 摘要与 OpenSSL 逐字节比对;
//   任一 FAIL 立即非零退出。自检始终跑全部档位, 与 BENCH_SMOKE 无关。
// 性能基准:
//   全量          : 5 档长度, 每实现每档 ~150ms, 3 轮取最小值
//   BENCH_SMOKE=1 : 只测 16 / 256, ~80ms, 1 轮
//
// CSV 输出: benchmarks/results/bench_sha1.csv
//   列头: algo,impl,size_bytes,ns_per_op,throughput_mbps
//   algo=sha1; impl ∈ {jpssl-scalar, jpssl-avx2-batch, jpssl-avx512-batch, openssl}
//   avx2/avx512 批量行的 ns_per_op 折算为单条消息 (整批耗时 ÷ 8 或 ÷ 16),
//   吞吐按单条消息长度计算。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_sha1.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_sha1

#include "sha1.hpp"
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

// ── 结果收集 (CSV 每行按单条消息折算) ──
struct Row {
    std::string algo;
    std::string impl;
    size_t size;       // 单条消息长度 (字节)
    double ns_per_op;  // 折算后的单条消息耗时 (ns)
    double mbps;       // 吞吐 (MB/s), 按单条消息长度计算
};
static std::vector<Row> g_rows;

// batch_n: 批量实现的并行消息数 (scalar/openssl=1, avx2=8, avx512=16)
template <typename F>
static void bench_case(const char* algo, const char* impl, size_t size,
                       int batch_n, double target_ms, int rounds, F&& f) {
    double ns_batch = auto_bench(std::forward<F>(f), target_ms, rounds);
    double ns_single = ns_batch / (double)batch_n;
    double mbps = (double)size * 1000.0 / ns_single;
    g_rows.push_back({algo, impl, size, ns_single, mbps});
    std::printf("%-13s %-18s %10zu %12.0f %12.1f\n",
                algo, impl, size, ns_single, mbps);
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

// ── 数据 (全局, 64B 对齐; 16 条批量消息各自独立内容) ──
static constexpr size_t kMax = 1048576 + 128;
alignas(64) static uint8_t g_data[kMax];
alignas(64) static uint8_t g_batch[16][kMax];

static void fill_deterministic(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        p[i] = (uint8_t)(x >> 24);
    }
}

// ── jpssl 标量封装 (streaming, 与 OpenSSL streaming 对齐) ──
static void jp_sha1(const uint8_t* d, size_t n, uint8_t out[20]) {
    jpssl::sha1_ctx c; jpssl::sha1_init(&c);
    if (n) jpssl::sha1_update(&c, d, n);
    jpssl::sha1_final(&c, out);
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
    std::printf("=== jpssl SHA-1 全量测试 vs OpenSSL ===\n");
    std::printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    std::printf("CPU features   : AVX2=%d AVX512=%d AES-NI=%d PCLMULQDQ=%d VAES=%d SHA-NI=%d ADX=%d NEON=%d\n",
                (int)jpssl::cpu_has_avx2(), (int)jpssl::cpu_has_avx512(),
                (int)jpssl::cpu_has_aesni(), (int)jpssl::cpu_has_pclmulqdq(),
                (int)jpssl::cpu_has_vpclmulqdq_vaes(), (int)jpssl::cpu_has_sha_ni(),
                (int)jpssl::cpu_has_adx(), (int)jpssl::cpu_has_neon());

    const bool smoke = [] {
        const char* e = std::getenv("BENCH_SMOKE");
        return e && std::strcmp(e, "1") == 0;
    }();

    const size_t kAllSizes[] = {16, 256, 4096, 65536, 1048576};
    constexpr int kAllCount = 5;
    // smoke: 只测前两档 16 / 256; 全量: 5 档
    const int bench_count = smoke ? 2 : kAllCount;
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;

    // ── 数据准备 (确定性内容) ──
    fill_deterministic(g_data, kMax, 0x12345678u);
    for (int i = 0; i < 16; ++i) fill_deterministic(g_batch[i], kMax, 0x1000 + (uint32_t)i);

    OsslDigest od_sha1(EVP_sha1());
    const bool has_avx2 = jpssl::cpu_has_avx2();
    const bool has_avx512 = jpssl::cpu_has_avx512();

    // ── 正确性自检 (jpssl 各实现 vs OpenSSL), 始终全部档位 ──
    std::printf("\n--- 正确性自检 (jpssl 各实现 vs OpenSSL, 全部档位) ---\n");
    bool all_pass = true;
    size_t pass_count = 0, fail_count = 0;
    auto check = [&](const char* what, const std::string& got, const std::string& want) {
        bool ok = (got == want);
        all_pass = all_pass && ok;
        ++(ok ? pass_count : fail_count);
        std::printf("  check %-40s : %s\n", what, ok ? "PASS" : "FAIL");
        if (!ok) {
            std::printf("        jpssl   = %s\n", got.c_str());
            std::printf("        openssl = %s\n", want.c_str());
        }
    };

    for (size_t ci = 0; ci < kAllCount; ++ci) {
        const size_t s = kAllSizes[ci];
        char tag[80];
        // scalar
        {
            uint8_t a[20];
            jp_sha1(g_data, s, a); od_sha1.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha1 jpssl-scalar  len=%zu", s);
            check(tag, to_hex(a, 20), to_hex(od_sha1.out, od_sha1.out_len));
        }
        if (has_avx2) {
            const uint8_t* m[8];
            for (int i = 0; i < 8; ++i) m[i] = g_batch[i];
            uint8_t out8[8][20];
            jpssl::sha1_multi_avx2(m, s, out8);
            std::string jh, oh;
            for (int i = 0; i < 8; ++i) {
                od_sha1.op(g_batch[i], s);
                jh += to_hex(out8[i], 20);
                oh += to_hex(od_sha1.out, od_sha1.out_len);
            }
            std::snprintf(tag, sizeof(tag), "sha1 jpssl-avx2-batch x8   len=%zu", s);
            check(tag, jh, oh);
        }
        if (has_avx512) {
            const uint8_t* m[16];
            for (int i = 0; i < 16; ++i) m[i] = g_batch[i];
            uint8_t out16[16][20];
            jpssl::sha1_multi_avx512(m, s, out16);
            std::string jh, oh;
            for (int i = 0; i < 16; ++i) {
                od_sha1.op(g_batch[i], s);
                jh += to_hex(out16[i], 20);
                oh += to_hex(od_sha1.out, od_sha1.out_len);
            }
            std::snprintf(tag, sizeof(tag), "sha1 jpssl-avx512-batch x16 len=%zu", s);
            check(tag, jh, oh);
        }
    }

    if (!all_pass) {
        std::printf("\n正确性自检存在 FAIL (%zu 项), 放弃基准并退出(1)\n", fail_count);
        return 1;
    }
    std::printf("\n正确性自检: 全部 PASS (%zu 项)\n", pass_count);

    // ── 性能基准 ──
    std::printf("\n--- 基准 (BENCH_SMOKE=%d, 每轮约 %.0fms, %d 轮%s) ---\n",
                (int)smoke, target_ms, rounds, smoke ? "" : ", 取最小值");
    std::printf("%-13s %-18s %10s %12s %12s\n", "algo", "impl", "size_bytes", "ns/op", "MB/s");

    for (int bi = 0; bi < bench_count; ++bi) {
        const size_t s = kAllSizes[(size_t)bi];
        uint8_t out[20];
        bench_case("sha1", "jpssl-scalar", s, 1, target_ms, rounds,
                   [&] { jp_sha1(g_data, s, out); g_sink ^= out[0]; });
        if (has_avx2) {
            const uint8_t* m[8];
            for (int i = 0; i < 8; ++i) m[i] = g_batch[i];
            uint8_t out8[8][20];
            bench_case("sha1", "jpssl-avx2-batch", s, 8, target_ms, rounds,
                       [&] { jpssl::sha1_multi_avx2(m, s, out8); g_sink ^= out8[0][0]; });
        } else {
            std::printf("SKIP sha1 jpssl-avx2-batch (cpu_has_avx2()=false)\n");
        }
        if (has_avx512) {
            const uint8_t* m[16];
            for (int i = 0; i < 16; ++i) m[i] = g_batch[i];
            uint8_t out16[16][20];
            bench_case("sha1", "jpssl-avx512-batch", s, 16, target_ms, rounds,
                       [&] { jpssl::sha1_multi_avx512(m, s, out16); g_sink ^= out16[0][0]; });
        } else {
            std::printf("SKIP sha1 jpssl-avx512-batch (cpu_has_avx512()=false, 本机不支持, 不调用避免 SIGILL)\n");
        }
        bench_case("sha1", "openssl", s, 1, target_ms, rounds,
                   [&] { od_sha1.op(g_data, s); g_sink ^= od_sha1.out[0]; });
    }

    // ── 写 CSV ──
    if (std::system("mkdir -p benchmarks/results") != 0) {
        /* mkdir 失败会由下方 fopen 报错; 目录已存在时返回 0 */
    }
    std::FILE* fp = std::fopen("benchmarks/results/bench_sha1.csv", "w");
    if (!fp) {
        std::printf("ERROR: 无法写 CSV 文件 benchmarks/results/bench_sha1.csv\n");
        return 1;
    }
    std::fprintf(fp, "algo,impl,size_bytes,ns_per_op,throughput_mbps\n");
    for (const Row& r : g_rows) {
        std::fprintf(fp, "%s,%s,%zu,%.1f,%.3f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.ns_per_op, r.mbps);
    }
    std::fclose(fp);
    std::printf("\nCSV 已写入 benchmarks/results/bench_sha1.csv (%zu 数据行)\n", g_rows.size());
    return 0;
}
