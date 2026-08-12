// bench_sha256_unalign.cpp — SHA-256 非对齐测试对比组 (jpssl scalar / sha_ni vs OpenSSL)
//
// 与 bench_sha256.cpp 同款写法的独立程序: 自检 + 自适应微基准 + 独立 CSV。
// 本程序聚焦【非对齐】场景:
//
//   非对齐长度   : {17, 1001, 32767, 100003}
//   非对齐 offset : 自检 {1,3,7,13} 全覆盖 + offset=0 基准;
//                  性能 {0,3}。
//
// 正确性自检 (始终执行, 不依赖 BENCH_SMOKE):
//   - 每个 (len, offset) 组合: jpssl scalar / jpssl sha_ni 摘要与 OpenSSL 逐字节一致;
//   - 非零 offset 的摘要与 offset=0 (同一内容) 一致;
//   - sha_ni 与 scalar 摘要一致;
//   任一 FAIL 立即非零退出。
//
// 性能基准: BENCH_SMOKE=1 -> 长度 {17,1001} × offset {0,3}, ~80ms/轮, 1 轮;
//           未设置      -> 长度 {17,1001,32767,100003} × offset {0,3},
//                          ~150ms/轮, 3 轮取最小。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_sha256_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_sha256_unalign
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_sha256_unalign.csv
//   CSV 列: algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps

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
    size_t offset;
    double ns;
    double bytes_per_op;
};
static std::vector<Row> g_rows;

static double g_target_ms = 150.0;
static int g_rounds = 3;

template <typename F>
static void bench_case(const char* algo, const char* impl, size_t size,
                       size_t offset, double bytes_per_op, F&& f) {
    double ns = auto_bench(std::forward<F>(f), g_target_ms, g_rounds);
    g_rows.push_back({algo, impl, size, offset, ns, bytes_per_op});
    std::printf("%-16s %-13s %10zu %6zu %12.0f %12.1f\n",
                algo, impl, size, offset, ns, bytes_per_op * 1000.0 / ns);
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
// 最大长度 100003 + offset 13 + 冗余; g_msg 为对齐基准内容, g_buf 承载各 offset 副本。
static constexpr size_t kMaxMsg = 100003;
static constexpr size_t kMaxBuf = kMaxMsg + 64;
static uint8_t g_msg[kMaxBuf];
static uint8_t g_buf[kMaxBuf];

static void fill_deterministic(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        p[i] = (uint8_t)(x >> 24);
    }
}

static constexpr size_t kSizes[] = {17, 1001, 32767, 100003};
static constexpr size_t kSmokeSizes[] = {17, 1001};
// 自检 offsets 全覆盖; 性能 offset 至少 {0,3}
static constexpr size_t kCheckOffsets[] = {1, 3, 7, 13};
static constexpr size_t kPerfOffsets[] = {0, 3};

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
    std::printf("=== jpssl SHA-256 非对齐测试对比组 (vs OpenSSL) ===\n");
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
        std::printf("Mode         : SMOKE (BENCH_SMOKE=1, sizes={17,1001} x offset{0,3}, ~80ms, 1 round)\n");
    } else {
        std::printf("Mode         : FULL (sizes={17,1001,32767,100003} x offset{0,3}, ~150ms, 3 rounds, min)\n");
    }

    fill_deterministic(g_msg, kMaxMsg, 0x13572468u);
    const bool has_sha_ni = jpssl::cpu_has_sha_ni();
    if (has_sha_ni) std::printf("SHA-NI        : 可用 (sha_ni 路径将参与自检与基准)\n");
    else            std::printf("SHA-NI        : 不可用 (跳过 jpssl-sha_ni)\n");

    // ── 正确性自检 (始终全部档位) ──
    std::printf("\n--- 正确性自检 (非对齐, jpssl 各实现 vs OpenSSL) ---\n");
    bool all_pass = true;
    int pass_count = 0;
    auto check = [&](const char* what, const std::string& got, const std::string& want) {
        bool ok = (got == want);
        all_pass = all_pass && ok;
        if (ok) ++pass_count;
        std::printf("  check %-44s : %s\n", what, ok ? "PASS" : "FAIL");
        if (!ok) {
            std::printf("        jpssl   = %s\n", got.c_str());
            std::printf("        openssl = %s\n", want.c_str());
        }
    };

    OsslDigest od_sha256(EVP_sha256());

    for (size_t s : kSizes) {
        char tag[96];
        // offset=0 基准摘要 (同一内容)
        uint8_t a0[32], n0[32];
        std::string scalar0, sha0;
        {
            jp_sha256_scalar(g_msg, s, a0);
            od_sha256.op(g_msg, s);
            scalar0 = to_hex(a0, 32);
            std::snprintf(tag, sizeof(tag), "sha256 scalar  len=%zu off=0 vs ossl", s);
            check(tag, scalar0, to_hex(od_sha256.out, 32));
            if (has_sha_ni) {
                jpssl::sha256_sha_ni(n0, g_msg, s);
                sha0 = to_hex(n0, 32);
                std::snprintf(tag, sizeof(tag), "sha256 sha_ni  len=%zu off=0 vs ossl", s);
                check(tag, sha0, to_hex(od_sha256.out, 32));
                std::snprintf(tag, sizeof(tag), "sha256 sha_ni  len=%zu off=0 vs scalar", s);
                check(tag, sha0, scalar0);
            }
        }
        // 非对齐 offsets 全覆盖
        for (size_t off : kCheckOffsets) {
            const uint8_t* p = g_buf + off;
            std::memcpy(g_buf + off, g_msg, s);  // 与 offset=0 完全同一内容
            uint8_t a[32], n[32];
            jp_sha256_scalar(p, s, a);
            od_sha256.op(p, s);
            std::string sh = to_hex(a, 32);
            std::snprintf(tag, sizeof(tag), "sha256 scalar  len=%zu off=%zu vs ossl", s, off);
            check(tag, sh, to_hex(od_sha256.out, 32));
            std::snprintf(tag, sizeof(tag), "sha256 scalar  len=%zu off=%zu vs off=0", s, off);
            check(tag, sh, scalar0);
            if (has_sha_ni) {
                jpssl::sha256_sha_ni(n, p, s);
                std::string sn = to_hex(n, 32);
                std::snprintf(tag, sizeof(tag), "sha256 sha_ni  len=%zu off=%zu vs ossl", s, off);
                check(tag, sn, to_hex(od_sha256.out, 32));
                std::snprintf(tag, sizeof(tag), "sha256 sha_ni  len=%zu off=%zu vs off=0", s, off);
                check(tag, sn, sha0);
                std::snprintf(tag, sizeof(tag), "sha256 sha_ni  len=%zu off=%zu vs scalar", s, off);
                check(tag, sn, sh);
            }
        }
    }

    if (!all_pass) {
        std::printf("\n正确性自检存在 FAIL, 退出(1)\n");
        return 1;
    }
    std::printf("\n正确性自检: 全部 PASS (%d 项)\n", pass_count);

    // ── 性能基准 ──
    std::printf("\n--- 性能 (ns/op, MB/s) ---\n");
    std::printf("%-16s %-13s %10s %6s %12s %12s\n",
                "algo", "impl", "size_bytes", "off", "ns_per_op", "MB/s");

    const size_t* bench_sizes = kSizes;
    size_t bench_count = sizeof(kSizes) / sizeof(kSizes[0]);
    if (smoke) {
        bench_sizes = kSmokeSizes;
        bench_count = sizeof(kSmokeSizes) / sizeof(kSmokeSizes[0]);
    }

    for (size_t i = 0; i < bench_count; ++i) {
        const size_t s = bench_sizes[i];
        for (size_t off : kPerfOffsets) {
            const uint8_t* p = (off == 0) ? g_msg : g_buf + off;
            if (off != 0) std::memcpy(g_buf + off, g_msg, s);
            uint8_t out[32];
            char algo[32];
            std::snprintf(algo, sizeof(algo), "sha256-unalign");
            bench_case(algo, "jpssl-scalar", s, off, (double)s,
                       [&] { jp_sha256_scalar(p, s, out); g_sink ^= out[0]; });
            if (has_sha_ni) {
                bench_case(algo, "jpssl-sha_ni", s, off, (double)s,
                           [&] { jpssl::sha256_sha_ni(out, p, s); g_sink ^= out[0]; });
            } else {
                std::printf("SKIP sha256-unalign jpssl-sha_ni (cpu_has_sha_ni()=false)\n");
            }
            bench_case(algo, "openssl", s, off, (double)s,
                       [&] { od_sha256.op(p, s); g_sink ^= od_sha256.out[0]; });
        }
    }

    // ── 写 CSV ──
    if (std::system("mkdir -p benchmarks/results") != 0) {
        std::printf("ERROR: mkdir benchmarks/results 失败\n");
        return 1;
    }
    std::FILE* fp = std::fopen("benchmarks/results/bench_sha256_unalign.csv", "w");
    if (!fp) {
        std::printf("ERROR: 无法写 CSV 文件\n");
        return 1;
    }
    std::fprintf(fp, "algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps\n");
    for (const Row& r : g_rows) {
        double mbps = r.bytes_per_op * 1000.0 / r.ns;
        std::fprintf(fp, "%s,%s,%zu,%zu,%.1f,%.3f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.offset, r.ns, mbps);
    }
    std::fclose(fp);
    std::printf("\nCSV 已写入 benchmarks/results/bench_sha256_unalign.csv (%zu 行)\n", g_rows.size());
    std::printf("sink=%u\n", (unsigned)g_sink);  // 用掉 sink, 避免未使用告警
    return 0;
}
