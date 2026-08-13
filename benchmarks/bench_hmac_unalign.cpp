// bench_hmac_unalign.cpp — HMAC-SHA256/384/512 非对齐微基准（jpssl vs OpenSSL）
//
// 覆盖矩阵:
//   非对齐长度  : 17 / 1001 / 32767 / 100003 字节（固定 32B 密钥）
//   非对齐偏移  : 消息起始指针偏移 1 / 3 / 7 / 13 字节
//   算法        : HMAC-SHA256 / HMAC-SHA384 / HMAC-SHA512
//   实现        : jpssl (libjpssl_cpu.a) vs OpenSSL (libcrypto, HMAC API)
//
// API 适配说明:
//   - hmac.hpp 只提供 SHA-256 与 SHA-384 变体, 没有 SHA-512 变体;
//     HMAC-SHA512 依据 RFC 2104 在本文件内用 include/sha512.hpp 的
//     sha512_init/update/final 原语实现 (与 bench_hmac.cpp / bench_hash_multi.cpp 同做法),
//     正确性用 OpenSSL 交叉验证。SHA-256 / SHA-384 使用库内 hmac_sha256 / hmac_sha384。
//
// 自检 (始终执行, 任一 FAIL 非零退出):
//   - 长度 {17,1001,32767,100003} × 偏移 {0,1,3,7,13} × 3 算法:
//        a) 非对齐下 jpssl 与 OpenSSL MAC 逐字节一致
//        b) 各偏移结果与 offset=0 结果一致
//   - 额外: 非对齐密钥 (key 起始偏移 1/3/7/13, 消息长度 1001) jpssl vs OpenSSL 一致
//
// 性能基准:
//   BENCH_SMOKE=1 : 长度 {17,1001} × 偏移 {0,3}, 每轮约 80ms, 1 轮
//   未设置         : 长度 {17,1001,32767,100003} × 偏移 {0,3}, 每轮约 150ms, 3 轮取最小
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_hmac_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_hmac_unalign
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_hmac_unalign.csv
//   CSV 列: algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps
//   algo = hmac-sha256-unalign | hmac-sha384-unalign | hmac-sha512-unalign ; impl = jpssl | openssl

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
    std::printf("%-20s %-8s %10zu %5zu %12.0f %12.1f\n",
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
// 每个偏移位点一个独立槽位 (行间互不重叠): 各槽位存放同一份规范消息/密钥,
// 测试指针 = 槽位基址 + 偏移, 因此各偏移位点内容完全相同、仅指针对齐不同,
// 这样 "offset == offset=0" 的比较才有意义 (若用重叠区域, 大消息下各偏移内容无法同时一致)。
static constexpr size_t kMaxMsg = 100003;      // 最大消息长度
static uint8_t g_slots[5][kMaxMsg + 16];       // 消息槽位: 行 r 对应偏移 kCheckOffsets[r]
static uint8_t g_kslots[5][64];                // 密钥槽位: 行 r 对应偏移 kCheckOffsets[r]
static uint8_t g_canon[kMaxMsg];               // 规范消息 (永不被修改)

// 偏移 → 槽位行号 (kCheckOffsets: {0,1,3,7,13})
static size_t row_of(size_t off) {
    switch (off) {
        case 0:  return 0;
        case 1:  return 1;
        case 3:  return 2;
        case 7:  return 3;
        case 13: return 4;
        default: return 0;
    }
}

static void fill_deterministic(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        p[i] = (uint8_t)(x >> 24);
    }
}

static constexpr size_t kSizesFull[] = {17, 1001, 32767, 100003};
static constexpr size_t kSizesSmoke[] = {17, 1001};
static constexpr size_t kCheckOffsets[] = {0, 1, 3, 7, 13};
static constexpr size_t kPerfOffsets[] = {0, 3};

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
    const size_t n_sizes = smoke ? 2 : 4;

    std::printf("=== jpssl HMAC (SHA256/384/512) 非对齐 vs OpenSSL 微基准 ===\n");
    std::printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    std::printf("Mode: %s (target_ms=%.0f rounds=%d)\n", smoke ? "SMOKE" : "FULL", target_ms, rounds);

    // ── 数据准备 ──
    // 规范内容放在独立的 g_canon 中 (永不被修改)。对每个测试长度 s, prepare(s)
    // 把 canon[0..s) 拷贝到各槽位的 基址+偏移 处, 使每个偏移位点的指针内容
    // 都是同一段 canon[0..s) (各槽位互不重叠, 不会互相破坏), 仅指针对齐不同。
    fill_deterministic(g_canon, kMaxMsg, 0x12345678u);
    uint8_t key32[32];
    for (int i = 0; i < 32; ++i) key32[i] = (uint8_t)(0x01 + i);
    auto prepare = [&](size_t s) {
        for (int r = 0; r < 5; ++r) {
            size_t off = kCheckOffsets[r];
            std::memcpy(g_slots[r] + off, g_canon, s);
            std::memcpy(g_kslots[r] + off, key32, 32);
        }
    };

    // ── 正确性自检 ──
    std::printf("\n--- 正确性自检 (jpssl vs OpenSSL, 非对齐全覆盖) ---\n");
    bool all_pass = true;
    int n_pass = 0, n_fail = 0;
    auto check = [&](const char* what, const std::string& got, const std::string& want) {
        bool ok = (got == want);
        all_pass = all_pass && ok;
        if (ok) ++n_pass; else ++n_fail;
        std::printf("  check %-52s : %s\n", what, ok ? "PASS" : "FAIL");
        if (!ok) {
            std::printf("        jpssl   = %s\n", got.c_str());
            std::printf("        openssl = %s\n", want.c_str());
        }
    };

    for (size_t k = 0; k < 4; ++k) {
        size_t s = kSizesFull[k];
        prepare(s);
        for (size_t off : kCheckOffsets) {
            char tag[96];
            // 消息指针 = 槽位基址 + 偏移: 各偏移位点内容与 offset=0 完全一致, 仅对齐不同
            const uint8_t* msg = g_slots[row_of(off)] + off;
            const uint8_t* msg0 = g_slots[0];          // offset=0 基准 (对齐指针, 同一内容)
            const uint8_t* key = g_kslots[0];          // 消息偏移自检用对齐密钥
            // HMAC-SHA256 (32B 摘要)
            {
                uint8_t r0[32], m1[32], m2[32];
                jp_hmac_sha256(key, msg0, s, r0);
                jp_hmac_sha256(key, msg, s, m1);
                ossl_hmac(EVP_sha256(), key, msg, s, m2, 32);
                std::snprintf(tag, sizeof(tag), "hmac-sha256    len=%-6zu off=%zu jpssl==ossl", s, off);
                check(tag, to_hex(m1, 32), to_hex(m2, 32));
                if (off) {
                    std::snprintf(tag, sizeof(tag), "hmac-sha256    len=%-6zu off=%zu == off=0", s, off);
                    check(tag, to_hex(m1, 32), to_hex(r0, 32));
                }
            }
            // HMAC-SHA384 (48B 摘要)
            {
                uint8_t r0[48], m1[48], m2[48];
                jp_hmac_sha384(key, msg0, s, r0);
                jp_hmac_sha384(key, msg, s, m1);
                ossl_hmac(EVP_sha384(), key, msg, s, m2, 48);
                std::snprintf(tag, sizeof(tag), "hmac-sha384    len=%-6zu off=%zu jpssl==ossl", s, off);
                check(tag, to_hex(m1, 48), to_hex(m2, 48));
                if (off) {
                    std::snprintf(tag, sizeof(tag), "hmac-sha384    len=%-6zu off=%zu == off=0", s, off);
                    check(tag, to_hex(m1, 48), to_hex(r0, 48));
                }
            }
            // HMAC-SHA512 (64B 摘要, 文件内 RFC 2104 实现)
            {
                uint8_t r0[64], m1[64], m2[64];
                hmac_sha512_local(key, 32, msg0, s, r0);
                hmac_sha512_local(key, 32, msg, s, m1);
                ossl_hmac(EVP_sha512(), key, msg, s, m2, 64);
                std::snprintf(tag, sizeof(tag), "hmac-sha512    len=%-6zu off=%zu jpssl==ossl", s, off);
                check(tag, to_hex(m1, 64), to_hex(m2, 64));
                if (off) {
                    std::snprintf(tag, sizeof(tag), "hmac-sha512    len=%-6zu off=%zu == off=0", s, off);
                    check(tag, to_hex(m1, 64), to_hex(r0, 64));
                }
            }
        }
    }
    // 非对齐密钥自检 (key 起始偏移 1/3/7/13, 消息长度 1001)
    prepare(1001);
    for (size_t off : kCheckOffsets) {
        if (!off) continue;
        char tag[96];
        // 密钥指针 = 密钥槽位基址 + 偏移: 各偏移位点密钥字节与 keyoff=0 完全一致, 仅对齐不同
        const uint8_t* key = g_kslots[row_of(off)] + off;
        const uint8_t* key0 = g_kslots[0];     // keyoff=0 基准
        const uint8_t* msg = g_slots[0];
        {
            uint8_t k0[32], m1[32], m2[32];
            jp_hmac_sha256(key0, msg, 1001, k0);
            jp_hmac_sha256(key, msg, 1001, m1);
            ossl_hmac(EVP_sha256(), key, msg, 1001, m2, 32);
            std::snprintf(tag, sizeof(tag), "hmac-sha256    keyoff=%zu jpssl==ossl", off);
            check(tag, to_hex(m1, 32), to_hex(m2, 32));
            std::snprintf(tag, sizeof(tag), "hmac-sha256    keyoff=%zu == keyoff=0", off);
            check(tag, to_hex(m1, 32), to_hex(k0, 32));
        }
        {
            uint8_t k0[48], m1[48], m2[48];
            jp_hmac_sha384(key0, msg, 1001, k0);
            jp_hmac_sha384(key, msg, 1001, m1);
            ossl_hmac(EVP_sha384(), key, msg, 1001, m2, 48);
            std::snprintf(tag, sizeof(tag), "hmac-sha384    keyoff=%zu jpssl==ossl", off);
            check(tag, to_hex(m1, 48), to_hex(m2, 48));
            std::snprintf(tag, sizeof(tag), "hmac-sha384    keyoff=%zu == keyoff=0", off);
            check(tag, to_hex(m1, 48), to_hex(k0, 48));
        }
        {
            uint8_t k0[64], m1[64], m2[64];
            hmac_sha512_local(key0, 32, msg, 1001, k0);
            hmac_sha512_local(key, 32, msg, 1001, m1);
            ossl_hmac(EVP_sha512(), key, msg, 1001, m2, 64);
            std::snprintf(tag, sizeof(tag), "hmac-sha512    keyoff=%zu jpssl==ossl", off);
            check(tag, to_hex(m1, 64), to_hex(m2, 64));
            std::snprintf(tag, sizeof(tag), "hmac-sha512    keyoff=%zu == keyoff=0", off);
            check(tag, to_hex(m1, 64), to_hex(k0, 64));
        }
    }

    if (!all_pass) {
        std::printf("\n正确性自检存在 %d FAIL (PASS=%d FAIL=%d), 放弃基准并退出(1)\n",
                    n_fail, n_pass, n_fail);
        return 1;
    }
    std::printf("\n正确性自检: 全部 PASS (%d 项)\n", n_pass);

    // ── 性能基准 ──
    std::printf("\n--- 基准 (每轮约 %.0fms, %d 轮%s) ---\n", target_ms, rounds,
                rounds > 1 ? "取最小值" : "");
    std::printf("%-20s %-8s %10s %5s %12s %12s\n",
                "algo", "impl", "size_bytes", "off", "ns/op", "MB/s");

    for (size_t k = 0; k < n_sizes; ++k) {
        size_t s = sizes[k];
        prepare(s);
        for (size_t off : kPerfOffsets) {
            // 与自检同语义: 槽位基址 + 偏移, 各偏移位点内容一致、仅对齐不同
            const uint8_t* msg = g_slots[row_of(off)] + off;
            const uint8_t* key = g_kslots[0];
            uint8_t m256[32], m384[48], m512[64];
            // HMAC-SHA256
            bench_case("hmac-sha256-unalign", "jpssl", s, off, (double)s, target_ms, rounds,
                       [&] { jp_hmac_sha256(key, msg, s, m256); g_sink ^= m256[0]; });
            bench_case("hmac-sha256-unalign", "openssl", s, off, (double)s, target_ms, rounds,
                       [&] { ossl_hmac(EVP_sha256(), key, msg, s, m256, 32); g_sink ^= m256[0]; });
            // HMAC-SHA384
            bench_case("hmac-sha384-unalign", "jpssl", s, off, (double)s, target_ms, rounds,
                       [&] { jp_hmac_sha384(key, msg, s, m384); g_sink ^= m384[0]; });
            bench_case("hmac-sha384-unalign", "openssl", s, off, (double)s, target_ms, rounds,
                       [&] { ossl_hmac(EVP_sha384(), key, msg, s, m384, 48); g_sink ^= m384[0]; });
            // HMAC-SHA512
            bench_case("hmac-sha512-unalign", "jpssl", s, off, (double)s, target_ms, rounds,
                       [&] { hmac_sha512_local(key, 32, msg, s, m512); g_sink ^= m512[0]; });
            bench_case("hmac-sha512-unalign", "openssl", s, off, (double)s, target_ms, rounds,
                       [&] { ossl_hmac(EVP_sha512(), key, msg, s, m512, 64); g_sink ^= m512[0]; });
        }
    }

    // ── 写 CSV ──
    std::system("mkdir -p benchmarks/results");
    std::FILE* fp = std::fopen("benchmarks/results/bench_hmac_unalign.csv", "w");
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
    std::printf("\nCSV 已写入 benchmarks/results/bench_hmac_unalign.csv (%zu 行)\n", g_rows.size());
    return 0;
}
