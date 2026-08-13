// bench_hmac.cpp — HMAC-SHA256/384/512 多长度 × jpssl/OpenSSL 对比微基准
//
// 覆盖矩阵 (消息长度: 16 / 256 / 4096 / 65536 / 1048576 字节, 固定 32B 密钥):
//   HMAC-SHA256 : jpssl hmac.hpp (hmac_sha256)      / OpenSSL HMAC(EVP_sha256)
//   HMAC-SHA384 : jpssl hmac.hpp (hmac_sha384)      / OpenSSL HMAC(EVP_sha384)
//   HMAC-SHA512 : 文件内 RFC 2104 实现 (见下)        / OpenSSL HMAC(EVP_sha512)
//
// API 适配说明:
//   - hmac.hpp 只提供 SHA-256 与 SHA-384 变体, 没有 SHA-512 变体;
//     HMAC-SHA512 依据 RFC 2104 在本文件内用 include/sha512.hpp 的
//     sha512_init/update/final 原语实现 (与主仓库 bench_hash_multi.cpp 同做法),
//     正确性用 OpenSSL 交叉验证。
//
// 全量 vs smoke:
//   BENCH_SMOKE=1 : 长度只测 16 与 256, 每轮约 80ms, 1 轮
//   未设置         : 5 档长度, 每轮约 150ms, 3 轮取最小值
//   正确性自检始终在全部 5 档长度上执行, 任一 FAIL 非零退出。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_hmac.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_hmac
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_hmac.csv
//   CSV 列: algo,impl,size_bytes,ns_per_op,throughput_mbps
//   algo = hmac-sha256 | hmac-sha384 | hmac-sha512 ; impl = jpssl | openssl

#include "hmac.hpp"
#include "sha512.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
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

template <typename F>
static void bench_case(const char* algo, const char* impl, size_t size,
                       double bytes_per_op, double target_ms, int rounds, F&& f) {
    double ns = auto_bench(std::forward<F>(f), target_ms, rounds);
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

static constexpr size_t kSizesFull[] = {16, 256, 4096, 65536, 1048576};
static constexpr size_t kSizesSmoke[] = {16, 256};

// ── jpssl HMAC 封装 (固定 32B 密钥) ──
static void jp_hmac_sha256(const uint8_t* key, const uint8_t* msg, size_t n, uint8_t mac[32]) {
    jpssl::hmac_sha256(key, 32, msg, n, mac);
}
static void jp_hmac_sha384(const uint8_t* key, const uint8_t* msg, size_t n, uint8_t mac[48]) {
    jpssl::hmac_sha384(key, 32, msg, n, mac);
}

// HMAC-SHA512 (RFC 2104, 用 jpssl sha512 原语实现; 库内无 hmac_sha512)
static void hmac_sha512_local(const uint8_t* key, size_t key_len,
                              const uint8_t* msg, size_t msg_len, uint8_t mac[64]) {
    uint8_t ikey[128], okey[128], tk[64];
    jpssl::sha512_ctx ctx;
    if (key_len > 128) {
        jpssl::sha512_init(&ctx);
        jpssl::sha512_update(&ctx, key, key_len);
        jpssl::sha512_final(&ctx, tk);
        key = tk; key_len = 64;
    }
    std::memset(ikey, 0, 128); std::memset(okey, 0, 128);
    std::memcpy(ikey, key, key_len); std::memcpy(okey, key, key_len);
    for (int i = 0; i < 128; ++i) { ikey[i] ^= 0x36; okey[i] ^= 0x5c; }
    jpssl::sha512_init(&ctx);
    jpssl::sha512_update(&ctx, ikey, 128);
    jpssl::sha512_update(&ctx, msg, msg_len);
    jpssl::sha512_final(&ctx, tk);
    jpssl::sha512_init(&ctx);
    jpssl::sha512_update(&ctx, okey, 128);
    jpssl::sha512_update(&ctx, tk, 64);
    jpssl::sha512_final(&ctx, mac);
}

// ── OpenSSL HMAC (固定 32B 密钥) ──
static void ossl_hmac(const EVP_MD* md, const uint8_t* key, const uint8_t* msg,
                      size_t n, uint8_t* mac, size_t mac_len) {
    unsigned int l = 0;
    HMAC(md, key, 32, msg, n, mac, &l);
    if (l != mac_len) std::memset(mac, 0, mac_len);
}

int main() {
    const bool smoke = (std::getenv("BENCH_SMOKE") != nullptr);
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;
    const size_t* sizes = smoke ? kSizesSmoke : kSizesFull;
    const size_t n_sizes = smoke ? 2 : 5;

    std::printf("=== jpssl HMAC (SHA256/384/512) vs OpenSSL 微基准 ===\n");
    std::printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    std::printf("Mode: %s (target_ms=%.0f rounds=%d)\n", smoke ? "SMOKE" : "FULL", target_ms, rounds);

    // ── 数据准备 (确定性内容, 固定 32B 密钥) ──
    fill_deterministic(g_data, kMax, 0x12345678u);
    uint8_t key32[32];
    for (int i = 0; i < 32; ++i) key32[i] = (uint8_t)(0x01 + i);

    // ── 正确性自检 (jpssl vs OpenSSL, 始终全部 5 档长度) ──
    std::printf("\n--- 正确性自检 (jpssl vs OpenSSL, 全部长度档) ---\n");
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

    for (size_t k = 0; k < 5; ++k) {
        size_t s = kSizesFull[k];
        char tag[64];
        // HMAC-SHA256 (32B 摘要)
        {
            uint8_t m1[32], m2[32];
            jp_hmac_sha256(key32, g_data, s, m1);
            ossl_hmac(EVP_sha256(), key32, g_data, s, m2, 32);
            std::snprintf(tag, sizeof(tag), "hmac-sha256    len=%zu", s);
            check(tag, to_hex(m1, 32), to_hex(m2, 32));
        }
        // HMAC-SHA384 (48B 摘要)
        {
            uint8_t m1[48], m2[48];
            jp_hmac_sha384(key32, g_data, s, m1);
            ossl_hmac(EVP_sha384(), key32, g_data, s, m2, 48);
            std::snprintf(tag, sizeof(tag), "hmac-sha384    len=%zu", s);
            check(tag, to_hex(m1, 48), to_hex(m2, 48));
        }
        // HMAC-SHA512 (64B 摘要, 文件内 RFC 2104 实现)
        {
            uint8_t m1[64], m2[64];
            hmac_sha512_local(key32, 32, g_data, s, m1);
            ossl_hmac(EVP_sha512(), key32, g_data, s, m2, 64);
            std::snprintf(tag, sizeof(tag), "hmac-sha512    len=%zu", s);
            check(tag, to_hex(m1, 64), to_hex(m2, 64));
        }
    }

    if (!all_pass) {
        std::printf("\n正确性自检存在 FAIL, 放弃基准并退出(1)\n");
        return 1;
    }
    std::printf("\n正确性自检: 全部 PASS\n");

    // ── 性能基准 ──
    std::printf("\n--- 基准 (每轮约 %.0fms, %d 轮%s) ---\n", target_ms, rounds,
                rounds > 1 ? "取最小值" : "");
    std::printf("%-13s %-18s %10s %12s %12s\n", "algo", "impl", "size_bytes", "ns/op", "MB/s");

    for (size_t k = 0; k < n_sizes; ++k) {
        size_t s = sizes[k];
        uint8_t m256[32], m384[48], m512[64];
        // HMAC-SHA256
        bench_case("hmac-sha256", "jpssl", s, (double)s, target_ms, rounds,
                   [&] { jp_hmac_sha256(key32, g_data, s, m256); g_sink ^= m256[0]; });
        bench_case("hmac-sha256", "openssl", s, (double)s, target_ms, rounds,
                   [&] { ossl_hmac(EVP_sha256(), key32, g_data, s, m256, 32); g_sink ^= m256[0]; });
        // HMAC-SHA384
        bench_case("hmac-sha384", "jpssl", s, (double)s, target_ms, rounds,
                   [&] { jp_hmac_sha384(key32, g_data, s, m384); g_sink ^= m384[0]; });
        bench_case("hmac-sha384", "openssl", s, (double)s, target_ms, rounds,
                   [&] { ossl_hmac(EVP_sha384(), key32, g_data, s, m384, 48); g_sink ^= m384[0]; });
        // HMAC-SHA512
        bench_case("hmac-sha512", "jpssl", s, (double)s, target_ms, rounds,
                   [&] { hmac_sha512_local(key32, 32, g_data, s, m512); g_sink ^= m512[0]; });
        bench_case("hmac-sha512", "openssl", s, (double)s, target_ms, rounds,
                   [&] { ossl_hmac(EVP_sha512(), key32, g_data, s, m512, 64); g_sink ^= m512[0]; });
    }

    // ── 写 CSV ──
    std::system("mkdir -p benchmarks/results");
    std::FILE* fp = std::fopen("benchmarks/results/bench_hmac.csv", "w");
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
    std::printf("\nCSV 已写入 benchmarks/results/bench_hmac.csv (%zu 行)\n", g_rows.size());
    return 0;
}
