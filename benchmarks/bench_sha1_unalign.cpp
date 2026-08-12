// bench_sha1_unalign.cpp — SHA-1 非对齐(unaligned)测试对比组: 任意长度 × 非对齐偏移 vs OpenSSL
//
// 非对齐组的定义 (对本算法):
//   非对齐长度: 17 / 1001 / 32767 / 100003 字节 (任意长度, 覆盖块边界余数)
//   非对齐指针 offset: 消息起始偏移 1 / 3 / 7 / 13 字节
//   覆盖实现:
//     jpssl-scalar      : sha1_init/update/final (streaming, 非对齐指针)
//     jpssl-avx2-batch  : sha1_multi_avx2  (8 条同长非对齐消息批量, cpu_has_avx2() 守卫)
//     jpssl-avx512-batch: sha1_multi_avx512 (16 条, cpu_has_avx512() 守卫;
//                          本机不支持则打印 SKIP 绝不调用, 避免 SIGILL)
//     openssl           : EVP_sha1
//
// 正确性自检 (始终执行, 与 BENCH_SMOKE 无关):
//   非对齐长度 × 偏移 {1,3,7,13} 下, jpssl 各实现摘要与 OpenSSL 逐字节一致;
//   偏移指针结果与 offset=0 一致; avx2-batch 与 scalar 一致;
//   任一 FAIL 立即非零退出。
// 性能基准:
//   长度 {17,1001,32767,100003} × offset {0,3}
//   BENCH_SMOKE=1 : 长度 {17,1001} × offset {0,3}, 每轮约 80ms, 1 轮
//   未设置(全量)  : 全部长度 × offset {0,3}, 每轮约 150ms, 3 轮取最小值
//
// CSV 输出: benchmarks/results/bench_sha1_unalign.csv
//   列头: algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps
//   algo=sha1-unalign; impl ∈ {jpssl-scalar, jpssl-avx2-batch, openssl}
//   avx2 批量行的 ns_per_op 折算为单条消息 (整批耗时 ÷ 8), 吞吐按单条消息长度计算。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_sha1_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_sha1_unalign

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
    size_t size;        // 单条消息长度 (字节)
    size_t offset;      // 消息起始偏移 (字节)
    double ns_per_op;   // 折算后的单条消息耗时 (ns)
    double mbps;        // 吞吐 (MB/s), 按单条消息长度计算
};
static std::vector<Row> g_rows;

// batch_n: 批量实现的并行消息数 (scalar/openssl=1, avx2=8, avx512=16)
template <typename F>
static void bench_case(const char* algo, const char* impl, size_t size, size_t offset,
                       int batch_n, double target_ms, int rounds, F&& f) {
    double ns_batch = auto_bench(std::forward<F>(f), target_ms, rounds);
    double ns_single = ns_batch / (double)batch_n;
    double mbps = (double)size * 1000.0 / ns_single;
    g_rows.push_back({algo, impl, size, offset, ns_single, mbps});
    std::printf("%-13s %-18s %10zu %8zu %12.0f %12.1f\n",
                algo, impl, size, offset, ns_single, mbps);
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

// ── 数据 (全局, 64B 对齐; 16 条批量消息各自独立内容; 留足非对齐偏移余量) ──
// 每个非对齐偏移各有一份"同内容"副本: 内容原样放在 buf+off 处,
// 使 buf+off 与 offset=0 的 g_data / g_batch 内容逐字节一致, 仅指针对齐不同。
static constexpr size_t kMaxSize = 100003;
static constexpr size_t kMax = kMaxSize + 64;  // 偏移余量
alignas(64) static uint8_t g_data[kMax];
alignas(64) static uint8_t g_batch[16][kMax];
alignas(64) static uint8_t g_shift[4][kMax];       // 标量/openssl: 同内容非对齐副本 (offsets {1,3,7,13})
alignas(64) static uint8_t g_bshift[4][16][kMax];  // 批量: 同内容非对齐副本

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
    std::printf("=== jpssl SHA-1 非对齐测试对比组 vs OpenSSL ===\n");
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

    // 非对齐长度: 任意长度, 覆盖块边界余数 (64B 块)
    const size_t kAllSizes[] = {17, 1001, 32767, 100003};
    constexpr int kAllCount = 4;
    // smoke: 只测前两档 17 / 1001; 全量: 4 档
    const int bench_count = smoke ? 2 : kAllCount;
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;

    // 自检偏移全覆盖 {1,3,7,13}; 性能偏移 {0,3}
    const size_t kSelfOffsets[] = {1, 3, 7, 13};
    constexpr int kSelfOffsetCount = 4;
    const size_t kBenchOffsets[] = {0, 3};
    constexpr int kBenchOffsetCount = 2;

    // ── 数据准备 (确定性内容; 各偏移生成同内容非对齐副本) ──
    fill_deterministic(g_data, kMax, 0x12345678u);
    for (int i = 0; i < 16; ++i) fill_deterministic(g_batch[i], kMax, 0x1000 + (uint32_t)i);
    for (int oi = 0; oi < kSelfOffsetCount; ++oi) {
        const size_t off = kSelfOffsets[oi];
        std::memcpy(g_shift[oi] + off, g_data, kMaxSize);
        for (int i = 0; i < 16; ++i) {
            std::memcpy(g_bshift[oi][i] + off, g_batch[i], kMaxSize);
        }
    }

    OsslDigest od_sha1(EVP_sha1());
    const bool has_avx2 = jpssl::cpu_has_avx2();
    const bool has_avx512 = jpssl::cpu_has_avx512();

    // ── 正确性自检 (始终全部档位) ──
    //   1) jpssl 各实现摘要与 OpenSSL 逐字节一致 (非对齐长度 × 偏移 {1,3,7,13})
    //   2) 偏移指针结果与 offset=0 一致
    //   3) avx2-batch 与 scalar 一致
    std::printf("\n--- 正确性自检 (非对齐长度 × 偏移, 始终执行) ---\n");
    bool all_pass = true;
    size_t pass_count = 0, fail_count = 0;
    auto check = [&](const char* what, const std::string& got, const std::string& want) {
        bool ok = (got == want);
        all_pass = all_pass && ok;
        ++(ok ? pass_count : fail_count);
        std::printf("  check %-44s : %s\n", what, ok ? "PASS" : "FAIL");
        if (!ok) {
            std::printf("        got  = %s\n", got.c_str());
            std::printf("        want = %s\n", want.c_str());
        }
    };

    for (size_t ci = 0; ci < kAllCount; ++ci) {
        const size_t s = kAllSizes[ci];
        char tag[96];

        // 基线: offset=0 的 jpssl-scalar / avx2-batch (逐条)
        uint8_t scalar0[20];
        jp_sha1(g_data, s, scalar0);
        uint8_t batch0[8][20];
        if (has_avx2) {
            const uint8_t* m0[8];
            for (int i = 0; i < 8; ++i) m0[i] = g_batch[i];
            jpssl::sha1_multi_avx2(m0, s, batch0);
        }

        for (int oi = 0; oi < kSelfOffsetCount; ++oi) {
            const size_t off = kSelfOffsets[oi];
            // 非对齐指针指向同内容副本 (与 g_data / g_batch[i] 内容一致, 仅指针对齐不同)
            const uint8_t* p_scalar = g_shift[oi] + off;
            const uint8_t* p_batch[8];
            for (int i = 0; i < 8; ++i) p_batch[i] = g_bshift[oi][i] + off;

            // 1) jpssl-scalar(非对齐指针) vs OpenSSL
            {
                uint8_t a[20];
                jp_sha1(p_scalar, s, a); od_sha1.op(p_scalar, s);
                std::snprintf(tag, sizeof(tag), "sha1-unalign scalar off=%zu len=%zu vs ossl", off, s);
                check(tag, to_hex(a, 20), to_hex(od_sha1.out, od_sha1.out_len));
            }
            // 2) 偏移指针与 offset=0 一致 (scalar): 同内容, 对齐不同
            {
                uint8_t a[20];
                jp_sha1(p_scalar, s, a);
                std::snprintf(tag, sizeof(tag), "sha1-unalign scalar off=%zu len=%zu vs off=0", off, s);
                check(tag, to_hex(a, 20), to_hex(scalar0, 20));
            }
            if (has_avx2) {
                uint8_t out8[8][20];
                jpssl::sha1_multi_avx2(p_batch, s, out8);
                // 1) avx2-batch(非对齐) vs OpenSSL (逐条)
                {
                    std::string jh, oh;
                    for (int i = 0; i < 8; ++i) {
                        od_sha1.op(p_batch[i], s);
                        jh += to_hex(out8[i], 20);
                        oh += to_hex(od_sha1.out, od_sha1.out_len);
                    }
                    std::snprintf(tag, sizeof(tag), "sha1-unalign avx2-batch x8 off=%zu len=%zu vs ossl", off, s);
                    check(tag, jh, oh);
                }
                // 3) avx2-batch 与 scalar 一致 (逐条, 同为非对齐指针)
                {
                    std::string jh, sh;
                    for (int i = 0; i < 8; ++i) {
                        uint8_t sa[20];
                        jp_sha1(p_batch[i], s, sa);
                        jh += to_hex(out8[i], 20);
                        sh += to_hex(sa, 20);
                    }
                    std::snprintf(tag, sizeof(tag), "sha1-unalign avx2-batch x8 off=%zu len=%zu vs scalar", off, s);
                    check(tag, jh, sh);
                }
                // 2) 偏移指针与 offset=0 一致 (avx2-batch): 同内容, 对齐不同
                {
                    std::string jh, bh;
                    for (int i = 0; i < 8; ++i) {
                        jh += to_hex(out8[i], 20);
                        bh += to_hex(batch0[i], 20);
                    }
                    std::snprintf(tag, sizeof(tag), "sha1-unalign avx2-batch x8 off=%zu len=%zu vs off=0", off, s);
                    check(tag, jh, bh);
                }
            } else {
                std::snprintf(tag, sizeof(tag), "sha1-unalign avx2-batch x8 off=%zu len=%zu", off, s);
                std::printf("  SKIP %-42s : cpu_has_avx2()=false\n", tag);
            }
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
            std::snprintf(tag, sizeof(tag), "sha1-unalign avx512-batch x16 len=%zu vs ossl", s);
            check(tag, jh, oh);
        } else {
            std::snprintf(tag, sizeof(tag), "sha1-unalign avx512-batch x16 len=%zu", s);
            std::printf("  SKIP %-42s : cpu_has_avx512()=false (本机不支持, 不调用避免 SIGILL)\n", tag);
        }
    }

    if (!all_pass) {
        std::printf("\n正确性自检存在 FAIL (%zu 项), 放弃基准并退出(1)\n", fail_count);
        return 1;
    }
    std::printf("\n正确性自检: 全部 PASS (%zu 项)\n", pass_count);

    // ── 性能基准: 长度 {17,1001,32767,100003} × offset {0,3} ──
    std::printf("\n--- 基准 (BENCH_SMOKE=%d, 长度前 %d 档, 每轮约 %.0fms, %d 轮%s) ---\n",
                (int)smoke, bench_count, target_ms, rounds, smoke ? "" : ", 取最小值");
    std::printf("%-13s %-18s %10s %8s %12s %12s\n",
                "algo", "impl", "size_bytes", "offset", "ns/op", "MB/s");

    // 性能偏移 {0,3}: 均使用同内容数据 (offset=3 指向 g_shift/g_bshift 中同内容非对齐副本)
    const int kOffIdx[] = {0, 1};  // 对应 kSelfOffsets 下标: 0→偏移0(g_data), 1→偏移3(g_shift[1])
    for (int bi = 0; bi < bench_count; ++bi) {
        const size_t s = kAllSizes[(size_t)bi];
        for (int oi = 0; oi < kBenchOffsetCount; ++oi) {
            const size_t off = kBenchOffsets[oi];
            const int sfi = kOffIdx[oi];
            const uint8_t* p_scalar = (sfi == 0) ? g_data : g_shift[sfi] + off;
            uint8_t out[20];
            bench_case("sha1-unalign", "jpssl-scalar", s, off, 1, target_ms, rounds,
                       [&] { jp_sha1(p_scalar, s, out); g_sink ^= out[0]; });
            if (has_avx2) {
                const uint8_t* m[8];
                for (int i = 0; i < 8; ++i)
                    m[i] = (sfi == 0) ? g_batch[i] : g_bshift[sfi][i] + off;
                uint8_t out8[8][20];
                bench_case("sha1-unalign", "jpssl-avx2-batch", s, off, 8, target_ms, rounds,
                           [&] { jpssl::sha1_multi_avx2(m, s, out8); g_sink ^= out8[0][0]; });
            } else {
                std::printf("SKIP sha1-unalign jpssl-avx2-batch (cpu_has_avx2()=false)\n");
            }
            if (has_avx512) {
                const uint8_t* m[16];
                for (int i = 0; i < 16; ++i)
                    m[i] = (sfi == 0) ? g_batch[i] : g_bshift[sfi][i] + off;
                uint8_t out16[16][20];
                bench_case("sha1-unalign", "jpssl-avx512-batch", s, off, 16, target_ms, rounds,
                           [&] { jpssl::sha1_multi_avx512(m, s, out16); g_sink ^= out16[0][0]; });
            } else {
                std::printf("SKIP sha1-unalign jpssl-avx512-batch (cpu_has_avx512()=false, 不调用避免 SIGILL)\n");
            }
            bench_case("sha1-unalign", "openssl", s, off, 1, target_ms, rounds,
                       [&] { od_sha1.op(p_scalar, s); g_sink ^= od_sha1.out[0]; });
        }
    }

    // ── 写 CSV ──
    if (std::system("mkdir -p benchmarks/results") != 0) {
        /* mkdir 失败会由下方 fopen 报错; 目录已存在时返回 0 */
    }
    std::FILE* fp = std::fopen("benchmarks/results/bench_sha1_unalign.csv", "w");
    if (!fp) {
        std::printf("ERROR: 无法写 CSV 文件 benchmarks/results/bench_sha1_unalign.csv\n");
        return 1;
    }
    std::fprintf(fp, "algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps\n");
    for (const Row& r : g_rows) {
        std::fprintf(fp, "%s,%s,%zu,%zu,%.1f,%.3f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.offset, r.ns_per_op, r.mbps);
    }
    std::fclose(fp);
    std::printf("\nCSV 已写入 benchmarks/results/bench_sha1_unalign.csv (%zu 数据行)\n", g_rows.size());
    return 0;
}
