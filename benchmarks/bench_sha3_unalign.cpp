// bench_sha3_unalign.cpp — SHA3 家族 (256/384/512) 非对齐指针测试对比组 (vs OpenSSL)
//
// 本程序与 bench_sha3.cpp 同源 (scalar + OpenSSL 自检、auto_bench、CSV 写法),
// 增加【非对齐】维度: 消息起始指针偏移 (offset_bytes ∈ {1,3,7,13} 自检全跑;
// 性能档 offset ∈ {0,3})。SHA3 在 jpssl 中为纯 C 标量实现, 无 SIMD 变体。
//
// 覆盖矩阵:
//   SHA3-256 : jpssl scalar (sha3_256_init/update/final) vs OpenSSL EVP_sha3_256
//   SHA3-384 : jpssl scalar (sha3_384_init/update/final) vs OpenSSL EVP_sha3_384
//   SHA3-512 : jpssl scalar (sha3_512_init/update/final) vs OpenSSL EVP_sha3_512
//
// 非对齐长度 (SHA3 块 72/104/136B): 17 / 1001 / 32767 / 100003
// 性能 offset: {0, 3}; 自检 offset: {1, 3, 7, 13} (+ offset=0 基线)
//
// 非对齐数据保证: 每个 (len, offset) 单元基准/自检前, 将同一份伪随机消息
// 重新拷入 scratch+offset, 因此各 offset 下哈希内容逐字节一致 (内容相同),
// 仅起始指针偏移不同。拷贝在计时循环之外, 不污染基准。
//
// 正确性自检 (始终执行):
//   1) 非对齐下 jpssl 与 OpenSSL 逐字节一致 (offset ∈ {1,3,7,13});
//   2) 各 offset 摘要与 offset=0 摘要逐字节一致 (jpssl 与 openssl 各自验证);
//   任一 FAIL 打印后立即非零退出, 全部 PASS 才进行基准并写 CSV。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_sha3_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_sha3_unalign
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_sha3_unalign.csv
//   CSV 列: algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps
//   algo = sha3-256-unalign / sha3-384-unalign / sha3-512-unalign
//   impl = jpssl-scalar / openssl
//
// 环境变量: BENCH_SMOKE=1 → smoke (长度 17/1001, ~80ms, 1 轮)
//           未设置          → 全量 (4 档长度, ~150ms, 3 轮取最小)

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
    size_t offset;
    double ns;
    double bytes_per_op;
};
static std::vector<Row> g_rows;

template <typename F>
static void bench_case(const char* algo, const char* impl, size_t size, size_t offset,
                       double bytes_per_op, double target_ms, int rounds, F&& f) {
    double ns = auto_bench(std::forward<F>(f), target_ms, rounds);
    g_rows.push_back({algo, impl, size, offset, ns, bytes_per_op});
    std::printf("%-16s %-12s %10zu %6zu %12.0f %12.1f\n",
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
// g_msg: 规范伪随机消息; scratch: 每 (len, offset) 单元重新拷入 g_msg[0..len),
// 使 scratch[off..off+len) == g_msg[0..len) (内容逐字节一致, 仅指针偏移不同)。
static constexpr size_t kMaxMsg      = 100003;   // 最大基准长度
static constexpr size_t kMaxOff      = 13;       // 最大指针偏移
static constexpr size_t kScratchSize = kMaxMsg + kMaxOff + 32;  // 收尾余量
static uint8_t g_msg[kMaxMsg];
static uint8_t g_scratch[kScratchSize];

static void fill_deterministic(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        p[i] = (uint8_t)(x >> 24);
    }
}

// 将规范消息前 n 字节拷入 scratch+off (内容与 off=0 完全一致)
static void prep_input(size_t off, size_t n) {
    std::memcpy(g_scratch + off, g_msg, n);
}

static constexpr size_t kBenchSizesFull[]  = {17, 1001, 32767, 100003};
static constexpr size_t kBenchSizesSmoke[] = {17, 1001};
static constexpr size_t kCheckOffsets[]    = {1, 3, 7, 13};   // 自检 offset 全覆盖
static constexpr size_t kBenchOffsets[]    = {0, 3};          // 性能至少 offset=0 与 3

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
    std::printf("=== jpssl SHA3 (256/384/512) 非对齐对比 vs OpenSSL 微基准 ===\n");
    std::printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);

    const char* smoke_env = std::getenv("BENCH_SMOKE");
    const bool smoke = (smoke_env != nullptr && std::strcmp(smoke_env, "0") != 0);
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;
    const size_t* bench_sizes = smoke ? kBenchSizesSmoke : kBenchSizesFull;
    const size_t n_bench_sizes = smoke ? 2 : 4;
    std::printf("mode        : %s (target=%.0fms, rounds=%d, bench_len=%zu, bench_off={0,3})\n",
                smoke ? "SMOKE" : "FULL", target_ms, rounds, n_bench_sizes);

    // ── 数据准备 (规范消息) ──
    fill_deterministic(g_msg, kMaxMsg, 0x12345678u);

    OsslDigest od_sha3_256(EVP_sha3_256()), od_sha3_384(EVP_sha3_384()), od_sha3_512(EVP_sha3_512());

    // ── 正确性自检 (非对齐: jpssl vs OpenSSL 逐字节; offset vs offset=0) ──
    std::printf("\n--- 正确性自检 (非对齐: jpssl vs OpenSSL 逐字节; offset vs offset=0) ---\n");
    bool all_pass = true;
    int pass_count = 0, fail_count = 0;
    auto check = [&](const char* what, const std::string& got, const std::string& want) {
        bool ok = (got == want);
        all_pass = all_pass && ok;
        if (ok) ++pass_count; else ++fail_count;
        std::printf("  check %-56s : %s\n", what, ok ? "PASS" : "FAIL");
        if (!ok) {
            std::printf("        got  = %s\n", got.c_str());
            std::printf("        want = %s\n", want.c_str());
        }
    };

    for (size_t s : kBenchSizesFull) {
        for (int bits = 256; bits <= 512; bits += 128) {
            const int dlen = bits / 8;  // 32/48/64
            char algo[32];
            std::snprintf(algo, sizeof(algo), "sha3-%d", bits);

            // offset=0 基线 (jpssl vs openssl)
            prep_input(0, s);
            uint8_t a0[64];
            jp_sha3(g_scratch, s, a0, bits);
            if (bits == 256) od_sha3_256.op(g_scratch, s);
            else if (bits == 384) od_sha3_384.op(g_scratch, s);
            else od_sha3_512.op(g_scratch, s);
            const uint8_t* o0p = (bits == 256) ? od_sha3_256.out :
                                 (bits == 384) ? od_sha3_384.out : od_sha3_512.out;
            char tag[96];
            std::snprintf(tag, sizeof(tag), "%s scalar vs openssl len=%zu off=0", algo, s);
            check(tag, to_hex(a0, dlen), to_hex(o0p, dlen));

            for (size_t off : kCheckOffsets) {
                prep_input(off, s);   // scratch[off..off+s) == g_msg[0..s)
                uint8_t ao[64];
                jp_sha3(g_scratch + off, s, ao, bits);
                if (bits == 256) od_sha3_256.op(g_scratch + off, s);
                else if (bits == 384) od_sha3_384.op(g_scratch + off, s);
                else od_sha3_512.op(g_scratch + off, s);
                const uint8_t* oop = (bits == 256) ? od_sha3_256.out :
                                     (bits == 384) ? od_sha3_384.out : od_sha3_512.out;
                // 1) 非对齐下 jpssl 与 OpenSSL 逐字节一致
                std::snprintf(tag, sizeof(tag), "%s scalar vs openssl len=%zu off=%zu", algo, s, off);
                check(tag, to_hex(ao, dlen), to_hex(oop, dlen));
                // 2) offset 与 offset=0 逐字节一致 (jpssl 与 openssl 各自验证)
                std::snprintf(tag, sizeof(tag), "%s jpssl off=%zu vs off=0 len=%zu", algo, off, s);
                check(tag, to_hex(ao, dlen), to_hex(a0, dlen));
                std::snprintf(tag, sizeof(tag), "%s openssl off=%zu vs off=0 len=%zu", algo, off, s);
                check(tag, to_hex(oop, dlen), to_hex(o0p, dlen));
            }
        }
    }

    std::printf("\n自检汇总: PASS=%d FAIL=%d\n", pass_count, fail_count);
    if (!all_pass) {
        std::printf("自检失败, 退出 (非零)\n");
        return 1;
    }

    // ── 性能基准 ──
    std::printf("\n%-16s %-12s %10s %6s %12s %12s\n", "algo", "impl", "size", "off", "ns/op", "MB/s");
    for (size_t i = 0; i < n_bench_sizes; ++i) {
        size_t s = bench_sizes[i];
        for (size_t off : kBenchOffsets) {
            prep_input(off, s);   // 计时循环之外, 不污染基准
            const uint8_t* p = g_scratch + off;
            uint8_t out[64];
            bench_case("sha3-256-unalign", "jpssl-scalar", s, off, (double)s, target_ms, rounds,
                       [&] { jp_sha3(p, s, out, 256); g_sink ^= out[0]; });
            bench_case("sha3-256-unalign", "openssl", s, off, (double)s, target_ms, rounds,
                       [&] { od_sha3_256.op(p, s); g_sink ^= od_sha3_256.out[0]; });
            bench_case("sha3-384-unalign", "jpssl-scalar", s, off, (double)s, target_ms, rounds,
                       [&] { jp_sha3(p, s, out, 384); g_sink ^= out[0]; });
            bench_case("sha3-384-unalign", "openssl", s, off, (double)s, target_ms, rounds,
                       [&] { od_sha3_384.op(p, s); g_sink ^= od_sha3_384.out[0]; });
            bench_case("sha3-512-unalign", "jpssl-scalar", s, off, (double)s, target_ms, rounds,
                       [&] { jp_sha3(p, s, out, 512); g_sink ^= out[0]; });
            bench_case("sha3-512-unalign", "openssl", s, off, (double)s, target_ms, rounds,
                       [&] { od_sha3_512.op(p, s); g_sink ^= od_sha3_512.out[0]; });
        }
    }

    // ── 写 CSV ──
    int mkrc = std::system("mkdir -p benchmarks/results");
    (void)mkrc;  // 目录已存在时 mkdir 返回非零, 忽略
    std::FILE* fp = std::fopen("benchmarks/results/bench_sha3_unalign.csv", "w");
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
    std::printf("\nCSV 已写入 benchmarks/results/bench_sha3_unalign.csv (%zu 数据行)\n", g_rows.size());
    return 0;
}
