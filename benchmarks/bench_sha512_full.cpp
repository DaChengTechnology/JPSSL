// bench_sha512.cpp — SHA-512 / SHA-384 全量测试: 全部实现路径 × 多长度 × OpenSSL 对比
//
// 覆盖矩阵 (消息长度: 16 / 256 / 4096 / 65536 / 1048576 字节):
//   SHA-512 : jpssl scalar (sha512 流式 API, transform 指针切 sha512_transform_cpu)
//             jpssl opt    (transform 指针切 sha512_transform_opt, 本机 = SSE4.1 SIMD)
//             OpenSSL EVP_sha512
//   SHA-384 : jpssl scalar / jpssl opt (sha384_init + 同一 transform 指针机制, 头文件提供)
//             OpenSSL EVP_sha384
//
// 实现路径切换: 库内全局函数指针 jpssl::sha512_transform_ptr 被 sha512_update/final 调用,
//   通过替换指针在 scalar (cpu) 与 opt (SSE4.1) 两条路径间切换 (参考 bench_hash_multi.cpp)。
//   注意: 库构建时 JP_AVX2=ON, sha512_opt.cpp 的静态初始化默认把指针指向 opt,
//   因此 "scalar" 用例必须显式换回 cpu 指针。
//
// 正确性: 每个 算法×实现×长度 与 OpenSSL 摘要逐字节比对 (自检始终覆盖全部 5 档长度);
//   任一 FAIL 立即非零退出, 全部 PASS 才进行基准并写 CSV。
// 性能: 全量 5 档长度 × ~150ms/轮 × 3 轮取最小;
//       环境变量 BENCH_SMOKE=1 时只测 16 与 256 两档 × ~80ms × 1 轮。
// 输出: stdout 人类可读表格 + benchmarks/results/bench_sha512_full.csv
//   CSV 列: algo,impl,size_bytes,ns_per_op,throughput_mbps
//   algo  = sha512 | sha384; impl = jpssl-scalar | jpssl-opt | openssl
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_sha512.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_sha512

#include "sha512.hpp"

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// 库内符号 (sha512_cpu.cpp / sha512_opt.cpp), 用于切换 SHA-512/SHA-384 实现路径
namespace jpssl {
extern void (*sha512_transform_ptr)(uint64_t[8], const uint8_t[128]);
extern void sha512_transform_cpu(uint64_t[8], const uint8_t[128]);
extern void sha512_transform_opt(uint64_t[8], const uint8_t[128]);
}  // namespace jpssl

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
                       double bytes_per_op, F&& f) {
    double ns = auto_bench(std::forward<F>(f));
    g_rows.push_back({algo, impl, size, ns, bytes_per_op});
    std::printf("%-8s %-14s %10zu %12.0f %12.1f\n",
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

// 自检/全量基准共用长度矩阵
static constexpr size_t kSizes[] = {16, 256, 4096, 65536, 1048576};
static constexpr int kNumSizes = (int)(sizeof(kSizes) / sizeof(kSizes[0]));

// ── jpssl 哈希封装 (流式 API, 内部走全局 transform 指针) ──
static void jp_sha512_impl(const uint8_t* d, size_t n, uint8_t out[64]) {
    jpssl::sha512_ctx c; jpssl::sha512_init(&c);
    if (n) jpssl::sha512_update(&c, d, n);
    jpssl::sha512_final(&c, out);
}
static void jp_sha384_impl(const uint8_t* d, size_t n, uint8_t out[48]) {
    jpssl::sha512_ctx c; jpssl::sha384_init(&c);
    if (n) jpssl::sha512_update(&c, d, n);
    jpssl::sha512_final(&c, out);
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

// 单条逐字节比对; 返回是否一致
static bool digest_eq(const char* tag, const uint8_t* got, const uint8_t* want, size_t n) {
    if (std::memcmp(got, want, n) == 0) return true;
    std::printf("  check %-42s : FAIL\n", tag);
    std::printf("        jpssl   = %s\n", to_hex(got, n).c_str());
    std::printf("        openssl = %s\n", to_hex(want, n).c_str());
    for (size_t i = 0; i < n; ++i) {
        if (got[i] != want[i]) { std::printf("        first diff at byte %zu\n", i); break; }
    }
    return false;
}

int main() {
    std::printf("=== jpssl SHA-512 / SHA-384 全量测试 (scalar / opt vs OpenSSL) ===\n");
    std::printf("OpenSSL: %s\n", OPENSSL_VERSION_TEXT);
    std::printf("模式    : %s\n", std::getenv("BENCH_SMOKE") ? "SMOKE (16/256, ~80ms, 1轮)" : "全量 (5档, ~150ms, 3轮取最小)");

    const bool smoke = (std::getenv("BENCH_SMOKE") != nullptr);
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;

    // ── 数据准备 (确定性内容, 自检与基准共用同一份) ──
    fill_deterministic(g_data, kMax, 0x12345678u);

    OsslDigest od512(EVP_sha512()), od384(EVP_sha384());

    // 实现路径: 算法 {sha512, sha384} × 实现 {jpssl-scalar, jpssl-opt, openssl}
    struct Impl {
        const char* name;
        void (*transform)(uint64_t[8], const uint8_t[128]);  // nullptr => openssl
        bool is_openssl;
    };
    const Impl impls[] = {
        {"jpssl-scalar", jpssl::sha512_transform_cpu, false},
        {"jpssl-opt",    jpssl::sha512_transform_opt, false},
        {"openssl",      nullptr,                     true},
    };
    constexpr int kNumImpls = (int)(sizeof(impls) / sizeof(impls[0]));

    // ── 正确性自检 (jpssl 各路径 vs OpenSSL, 始终覆盖全部 5 档长度) ──
    std::printf("\n--- 正确性自检 (jpssl 各实现 vs OpenSSL 逐字节比对) ---\n");
    int total_checks = 0, pass_checks = 0;
    for (int is384 = 0; is384 <= 1; ++is384) {
        const char* algo = is384 ? "sha384" : "sha512";
        const size_t dlen = is384 ? 48 : 64;
        for (size_t s : kSizes) {
            for (const Impl& im : impls) {
                char tag[96];
                std::snprintf(tag, sizeof(tag), "%s %-11s len=%zu", algo, im.name, s);
                uint8_t want[64];
                (is384 ? od384 : od512).op(g_data, s);
                std::memcpy(want, (is384 ? od384 : od512).out, dlen);
                uint8_t got[64];
                bool ok;
                if (im.is_openssl) {
                    std::memcpy(got, want, dlen);
                    ok = true;  // openssl vs openssl 恒等, 仅统计
                } else {
                    jpssl::sha512_transform_ptr = im.transform;
                    if (is384) jp_sha384_impl(g_data, s, got);
                    else       jp_sha512_impl(g_data, s, got);
                    ok = digest_eq(tag, got, want, dlen);
                }
                ++total_checks;
                if (ok) {
                    ++pass_checks;
                    std::printf("  check %-42s : PASS\n", tag);
                } else {
                    std::printf("  check %-42s : FAIL\n", tag);
                }
            }
        }
    }
    jpssl::sha512_transform_ptr = jpssl::sha512_transform_opt;  // 恢复默认
    if (pass_checks != total_checks) {
        std::printf("\n正确性自检失败: %d/%d PASS, 非零退出\n", pass_checks, total_checks);
        return 1;
    }
    std::printf("正确性自检全部通过: %d/%d PASS\n", pass_checks, total_checks);

    // ── 性能基准 ──
    std::printf("\n--- 性能基准 (ns/op, MB/s=bytes*1000/ns) ---\n");
    std::printf("%-8s %-14s %10s %12s %12s\n", "algo", "impl", "size_bytes", "ns_per_op", "MB/s");
    const int num_bench = smoke ? 2 : kNumSizes;
    for (int i = 0; i < num_bench; ++i) {
        const size_t s = kSizes[i];
        for (int is384 = 0; is384 <= 1; ++is384) {
            const char* algo = is384 ? "sha384" : "sha512";
            {
                jpssl::sha512_transform_ptr = impls[0].transform;
                bench_case(algo, impls[0].name, s, (double)s,
                           [&, is384, s] {
                               uint8_t out[64];
                               if (is384) jp_sha384_impl(g_data, s, out);
                               else       jp_sha512_impl(g_data, s, out);
                               g_sink ^= out[0];
                           });
            }
            {
                jpssl::sha512_transform_ptr = impls[1].transform;
                bench_case(algo, impls[1].name, s, (double)s,
                           [&, is384, s] {
                               uint8_t out[64];
                               if (is384) jp_sha384_impl(g_data, s, out);
                               else       jp_sha512_impl(g_data, s, out);
                               g_sink ^= out[0];
                           });
            }
            {
                OsslDigest& od = (is384 ? od384 : od512);
                bench_case(algo, impls[2].name, s, (double)s,
                           [&od, s] { od.op(g_data, s); g_sink ^= od.out[0]; });
            }
        }
    }
    jpssl::sha512_transform_ptr = jpssl::sha512_transform_opt;  // 恢复默认
    std::printf("sink=%u\n", (unsigned)g_sink);

    // ── 写 CSV ──
    std::system("mkdir -p benchmarks/results");
    std::FILE* fp = std::fopen("benchmarks/results/bench_sha512_full.csv", "w");
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
    std::printf("\nCSV 已写入 benchmarks/results/bench_sha512_full.csv (%zu 行)\n", g_rows.size());
    return 0;
}
