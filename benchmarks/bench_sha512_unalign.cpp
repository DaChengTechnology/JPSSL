// bench_sha512_unalign.cpp — SHA-512 / SHA-384 非对齐测试对比组 (scalar / opt vs OpenSSL)
//
// 非对齐矩阵:
//   长度  : 17 / 1001 / 32767 / 100003 字节 (SHA-512 块 = 128B, 均非块对齐)
//   offset: 消息起始指针偏移 1 / 3 / 7 / 13 字节 (自检全覆盖);
//           性能只测 offset {0, 3}
//   数据  : 同一份规范消息 g_msg 复制到每个 offset 的独立 lane 中
//           (lane 基址 + offset 处起始), 保证 "同消息不同指针偏移" 可比。
//   实现  : jpssl scalar (transform 指针切 sha512_transform_cpu)
//           jpssl opt    (transform 指针切 sha512_transform_opt, 本机 = SSE4.1 SIMD)
//           OpenSSL EVP_sha512 / EVP_sha384
//
// 实现路径切换: 库内全局函数指针 jpssl::sha512_transform_ptr 被 sha512_update/final 调用,
//   通过替换指针在 scalar (cpu) 与 opt (SSE4.1) 两条路径间切换 (参考 bench_sha512_full.cpp)。
//   库构建时 JP_AVX2=ON, sha512_opt.cpp 静态初始化默认把指针指向 opt,
//   因此 "scalar" 用例必须显式换回 cpu 指针; 每次替换后均恢复默认指针。
//
// 正确性自检 (始终执行, 覆盖 全部长度 × offset {0,1,3,7,13} × 全部实现):
//   1) 非对齐下 jpssl 各实现与 OpenSSL 逐字节一致;
//   2) offset != 0 的摘要与 offset = 0 的摘要一致;
//   3) opt 与 scalar 一致;
//   任一 FAIL 立即非零退出, 全部 PASS 才进行基准并写 CSV。
// 性能: 长度 {17,1001,32767,100003} × offset {0,3} × ~150ms/轮 × 3 轮取最小;
//       环境变量 BENCH_SMOKE=1 时只测 长度 {17,1001} × offset {0,3} × ~80ms × 1 轮。
// 输出: stdout 人类可读表格 + benchmarks/results/bench_sha512_unalign.csv
//   CSV 列: algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps
//   algo = sha512-unalign | sha384-unalign; impl = jpssl-scalar | jpssl-opt | openssl
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_sha512_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_sha512_unalign

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
    size_t offset;
    double ns;
    double bytes_per_op;
};
static std::vector<Row> g_rows;

template <typename F>
static void bench_case(const char* algo, const char* impl, size_t size, size_t offset,
                       double bytes_per_op, F&& f) {
    double ns = auto_bench(std::forward<F>(f));
    g_rows.push_back({algo, impl, size, offset, ns, bytes_per_op});
    std::printf("%-14s %-14s %10zu %10zu %12.0f %12.1f\n",
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

// 非对齐长度矩阵 (SHA-512 块 128B)
static constexpr size_t kSizes[] = {17, 1001, 32767, 100003};
static constexpr int kNumSizes = (int)(sizeof(kSizes) / sizeof(kSizes[0]));

// 自检 offset 全覆盖; 性能只测 {0, 3}
static constexpr size_t kSelfOffsets[] = {0, 1, 3, 7, 13};
static constexpr int kNumSelfOffsets = (int)(sizeof(kSelfOffsets) / sizeof(kSelfOffsets[0]));
static constexpr size_t kBenchOffsets[] = {0, 3};
static constexpr int kNumBenchOffsets = (int)(sizeof(kBenchOffsets) / sizeof(kBenchOffsets[0]));

// ── 数据 ──
// 最大消息长度 100003 (SHA-512 块 128B, 均非块对齐)
static constexpr size_t kMaxMsg = 100003;
// 每个测试 offset 一条独立 lane: lane 内 [o, o + kMaxMsg) 保存同一份规范消息 g_msg,
// 保证 "同一条消息、不同起始指针偏移" 的语义 (offset 与 offset=0 一致性自检才有意义)。
static constexpr size_t kLaneSize = kMaxMsg + 64;
static uint8_t g_msg[kMaxMsg];                       // 规范消息 (确定性内容)
static uint8_t g_data[kNumSelfOffsets * kLaneSize];  // 每 offset 一条 lane

static void fill_deterministic(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        p[i] = (uint8_t)(x >> 24);
    }
}

// offset -> 该 offset 的消息起始指针 (lane 基址 + offset)
static const uint8_t* lane_ptr(size_t off) {
    for (int oi = 0; oi < kNumSelfOffsets; ++oi) {
        if (kSelfOffsets[oi] == off)
            return g_data + (size_t)oi * kLaneSize + off;
    }
    return nullptr;
}

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
    std::printf("  check %-56s : FAIL\n", tag);
    std::printf("        jpssl   = %s\n", to_hex(got, n).c_str());
    std::printf("        openssl = %s\n", to_hex(want, n).c_str());
    for (size_t i = 0; i < n; ++i) {
        if (got[i] != want[i]) { std::printf("        first diff at byte %zu\n", i); break; }
    }
    return false;
}

int main() {
    std::printf("=== jpssl SHA-512 / SHA-384 非对齐测试 (scalar / opt vs OpenSSL) ===\n");
    std::printf("OpenSSL: %s\n", OPENSSL_VERSION_TEXT);
    std::printf("模式    : %s\n", std::getenv("BENCH_SMOKE") ? "SMOKE (len{17,1001} x offset{0,3}, ~80ms, 1轮)" : "全量 (len{17,1001,32767,100003} x offset{0,3}, ~150ms, 3轮取最小)");

    const bool smoke = (std::getenv("BENCH_SMOKE") != nullptr);
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;

    // ── 数据准备 (确定性内容, 自检与基准共用同一份) ──
    fill_deterministic(g_msg, kMaxMsg, 0x12345678u);
    for (int oi = 0; oi < kNumSelfOffsets; ++oi) {
        const size_t off = kSelfOffsets[oi];
        std::memcpy(g_data + (size_t)oi * kLaneSize + off, g_msg, kMaxMsg);
    }

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

    // ── 正确性自检 ──
    // 每个 (algo, size, offset): 计算 openssl / jpssl-scalar / jpssl-opt 摘要,
    // 检查: jpssl 与 OpenSSL 一致; opt 与 scalar 一致;
    //       offset != 0 的摘要与 offset = 0 的摘要一致。
    std::printf("\n--- 正确性自检 (非对齐: jpssl 各实现 vs OpenSSL 逐字节比对) ---\n");
    int total_checks = 0, pass_checks = 0;
    for (int is384 = 0; is384 <= 1; ++is384) {
        const char* algo = is384 ? "sha384" : "sha512";
        const size_t dlen = is384 ? 48 : 64;
        OsslDigest& od = (is384 ? od384 : od512);
        for (size_t s : kSizes) {
            // 各 offset 的摘要 (scalar/opt 需先切指针, 测后恢复)
            uint8_t dig_ossl[5][64];
            uint8_t dig_scalar[5][64];
            uint8_t dig_opt[5][64];
            for (int oi = 0; oi < kNumSelfOffsets; ++oi) {
                const size_t off = kSelfOffsets[oi];
                const uint8_t* msg = lane_ptr(off);
                od.op(msg, s);
                std::memcpy(dig_ossl[oi], od.out, dlen);
                jpssl::sha512_transform_ptr = jpssl::sha512_transform_cpu;
                if (is384) jp_sha384_impl(msg, s, dig_scalar[oi]);
                else       jp_sha512_impl(msg, s, dig_scalar[oi]);
                jpssl::sha512_transform_ptr = jpssl::sha512_transform_opt;
                if (is384) jp_sha384_impl(msg, s, dig_opt[oi]);
                else       jp_sha512_impl(msg, s, dig_opt[oi]);
            }
            jpssl::sha512_transform_ptr = jpssl::sha512_transform_opt;  // 恢复默认

            for (int oi = 0; oi < kNumSelfOffsets; ++oi) {
                const size_t off = kSelfOffsets[oi];
                char tag[128];
                // 1) jpssl-scalar == OpenSSL
                std::snprintf(tag, sizeof(tag), "%s scalar len=%zu off=%zu == openssl", algo, s, off);
                bool ok = digest_eq(tag, dig_scalar[oi], dig_ossl[oi], dlen);
                ++total_checks; if (ok) ++pass_checks;
                std::printf("  check %-56s : %s\n", tag, ok ? "PASS" : "FAIL");
                // 2) jpssl-opt == OpenSSL
                std::snprintf(tag, sizeof(tag), "%s opt    len=%zu off=%zu == openssl", algo, s, off);
                ok = digest_eq(tag, dig_opt[oi], dig_ossl[oi], dlen);
                ++total_checks; if (ok) ++pass_checks;
                std::printf("  check %-56s : %s\n", tag, ok ? "PASS" : "FAIL");
                // 3) opt == scalar
                std::snprintf(tag, sizeof(tag), "%s opt    len=%zu off=%zu == scalar", algo, s, off);
                ok = digest_eq(tag, dig_opt[oi], dig_scalar[oi], dlen);
                ++total_checks; if (ok) ++pass_checks;
                std::printf("  check %-56s : %s\n", tag, ok ? "PASS" : "FAIL");
                // 4) offset != 0 与 offset = 0 一致 (三实现分别比对)
                if (oi != 0) {
                    std::snprintf(tag, sizeof(tag), "%s scalar len=%zu off=%zu == off=0", algo, s, off);
                    ok = digest_eq(tag, dig_scalar[oi], dig_scalar[0], dlen);
                    ++total_checks; if (ok) ++pass_checks;
                    std::printf("  check %-56s : %s\n", tag, ok ? "PASS" : "FAIL");
                    std::snprintf(tag, sizeof(tag), "%s opt    len=%zu off=%zu == off=0", algo, s, off);
                    ok = digest_eq(tag, dig_opt[oi], dig_opt[0], dlen);
                    ++total_checks; if (ok) ++pass_checks;
                    std::printf("  check %-56s : %s\n", tag, ok ? "PASS" : "FAIL");
                    std::snprintf(tag, sizeof(tag), "%s openssl len=%zu off=%zu == off=0", algo, s, off);
                    ok = digest_eq(tag, dig_ossl[oi], dig_ossl[0], dlen);
                    ++total_checks; if (ok) ++pass_checks;
                    std::printf("  check %-56s : %s\n", tag, ok ? "PASS" : "FAIL");
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
    std::printf("\n--- 性能基准 (非对齐, ns/op, MB/s=bytes*1000/ns) ---\n");
    std::printf("%-14s %-14s %10s %10s %12s %12s\n",
                "algo", "impl", "size_bytes", "offset_bytes", "ns_per_op", "MB/s");
    const int num_sizes = smoke ? 2 : kNumSizes;
    for (int i = 0; i < num_sizes; ++i) {
        const size_t s = kSizes[i];
        for (int is384 = 0; is384 <= 1; ++is384) {
            const char* algo = is384 ? "sha384-unalign" : "sha512-unalign";
            OsslDigest& od = (is384 ? od384 : od512);
            for (int oi = 0; oi < kNumBenchOffsets; ++oi) {
                const size_t off = kBenchOffsets[oi];
                const uint8_t* msg = lane_ptr(off);
                {
                    jpssl::sha512_transform_ptr = impls[0].transform;
                    bench_case(algo, impls[0].name, s, off, (double)s,
                               [&, is384, s, msg] {
                                   uint8_t out[64];
                                   if (is384) jp_sha384_impl(msg, s, out);
                                   else       jp_sha512_impl(msg, s, out);
                                   g_sink ^= out[0];
                               });
                }
                {
                    jpssl::sha512_transform_ptr = impls[1].transform;
                    bench_case(algo, impls[1].name, s, off, (double)s,
                               [&, is384, s, msg] {
                                   uint8_t out[64];
                                   if (is384) jp_sha384_impl(msg, s, out);
                                   else       jp_sha512_impl(msg, s, out);
                                   g_sink ^= out[0];
                               });
                }
                {
                    bench_case(algo, impls[2].name, s, off, (double)s,
                               [&od, s, msg] { od.op(msg, s); g_sink ^= od.out[0]; });
                }
            }
        }
    }
    jpssl::sha512_transform_ptr = jpssl::sha512_transform_opt;  // 恢复默认
    std::printf("sink=%u\n", (unsigned)g_sink);

    // ── 写 CSV ──
    std::system("mkdir -p benchmarks/results");
    std::FILE* fp = std::fopen("benchmarks/results/bench_sha512_unalign.csv", "w");
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
    std::printf("\nCSV 已写入 benchmarks/results/bench_sha512_unalign.csv (%zu 行)\n", g_rows.size());
    return 0;
}
