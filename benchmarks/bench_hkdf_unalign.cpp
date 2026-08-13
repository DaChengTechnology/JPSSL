// bench_hkdf_unalign.cpp — HKDF (RFC 5869) 非对齐测试对比组 (与 OpenSSL 对比)
//
// 覆盖: HKDF-SHA256 / HKDF-SHA384 / HKDF-SHA512 (非对齐变体)
//   jpssl  : hkdf.hpp 公开 API (hkdf_extract/hkdf_expand 与
//            hkdf_extract_sha384/hkdf_expand_sha384)
//   openssl: EVP_KDF("HKDF") + EVP_KDF_derive
//
// 变体说明:
//   - hkdf.hpp 只提供 SHA-256 与 SHA-384 变体, 没有 SHA-512 变体;
//     因此 HKDF-SHA512 依据 RFC 5869 在本文件内用 include/sha512.hpp 的
//     init/update/final 原语实现 (HMAC-SHA512 按 RFC 2104 文件内实现),
//     正确性用 OpenSSL 交叉验证。
//
// 非对齐组定义:
//   1. 非对齐长度: IKM 17/1001/32767/100003 (固定 salt 16B, info 16B,
//      OKM 按变体 = 32B(sha256)/48B(sha384)/64B(sha512))。
//   2. 非对齐指针 offset: IKM 起始偏移 1/3/7/13; 自检 1/3/7/13 全覆盖
//      (salt/info 也以非对齐偏移放置参与自检); 性能至少测 offset {0,3}。
//   3. 自检 (始终执行, 不受 BENCH_SMOKE 影响):
//      - 非对齐下 jpssl 与 OpenSSL 的 OKM 逐字节一致;
//      - 同一消息在 offset X 与 offset=0 下的 OKM 一致;
//      - 任一 FAIL 立即非零退出。
//   4. 性能基准: 长度 {17,1001,32767,100003} x offset {0,3};
//      BENCH_SMOKE=1: 长度 {17,1001} x offset {0,3}, 每轮约 80ms, 1 轮;
//      未设置: 全量 4 档长度, 每轮约 150ms, 3 轮取最小。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_hkdf_unalign.cpp
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_hkdf_unalign
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_hkdf_unalign.csv
//   CSV 列: algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps
//   algo 取 hkdf-sha256-unalign / hkdf-sha384-unalign / hkdf-sha512-unalign;
//   impl 取 jpssl / openssl

#include "hkdf.hpp"
#include "sha512.hpp"
#include "cpu_features.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/opensslv.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
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

static void bench_case(const char* algo, const char* impl, size_t size, size_t offset,
                       double bytes_per_op, double target_ms, int rounds, auto&& f) {
    double ns = auto_bench(f, target_ms, rounds);
    g_rows.push_back({algo, impl, size, offset, ns, bytes_per_op});
    std::printf("%-17s %-9s %8zu %6zu %12.0f %12.1f\n",
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
static constexpr size_t kMax = 100003 + 128;          // 最大 IKM + 最大 offset + 余量
static uint8_t g_msg[kMax];                           // 规范消息 (IKM 内容)
static uint8_t g_work[kMax + 32];                     // 工作缓冲 (offset 放置副本用)
static uint8_t g_salt_a[16], g_salt_u[16 + 8];   // 对齐 salt / 非对齐 salt (+3 处放副本)
static uint8_t g_info_a[16], g_info_u[16 + 8];   // 对齐 info / 非对齐 info (+7 处放副本)

static void fill_deterministic(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        p[i] = (uint8_t)(x >> 24);
    }
}

// ── 测试矩阵 ──
static constexpr size_t kSizesAll[] = {17, 1001, 32767, 100003};
static constexpr size_t kSizesSmoke[] = {17, 1001};
static constexpr size_t kCheckOffsets[] = {1, 3, 7, 13};  // 自检全覆盖
static constexpr size_t kBenchOffsets[] = {0, 3};         // 性能 offset

// ── HMAC-SHA512 (RFC 2104, 用 jpssl sha512 原语实现; 库内无 hmac_sha512) ──
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

// ── jpssl HKDF 封装 ──
static void jp_hkdf_sha256(const uint8_t* salt, size_t salt_len,
                           const uint8_t* ikm, size_t ikm_len,
                           const uint8_t* info, size_t info_len,
                           uint8_t* out, size_t out_len) {
    uint8_t prk[32];
    jpssl::hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    jpssl::hkdf_expand(prk, info, info_len, out, out_len);
}

static void jp_hkdf_sha384(const uint8_t* salt, size_t salt_len,
                           const uint8_t* ikm, size_t ikm_len,
                           const uint8_t* info, size_t info_len,
                           uint8_t* out, size_t out_len) {
    uint8_t prk[48];
    jpssl::hkdf_extract_sha384(salt, salt_len, ikm, ikm_len, prk);
    jpssl::hkdf_expand_sha384(prk, info, info_len, out, out_len);
}

// HKDF-SHA512 (RFC 5869, 用上面的 HMAC-SHA512; 库内无 hkdf_sha512) —— 文件内 RFC 实现
static void jp_hkdf_sha512(const uint8_t* salt, size_t salt_len,
                           const uint8_t* ikm, size_t ikm_len,
                           const uint8_t* info, size_t info_len,
                           uint8_t* out, size_t out_len) {
    uint8_t prk[64];
    if (!salt || salt_len == 0) {
        uint8_t z[64] = {};
        hmac_sha512_local(z, 64, ikm, ikm_len, prk);
    } else {
        hmac_sha512_local(salt, salt_len, ikm, ikm_len, prk);
    }
    uint8_t t[64];
    size_t t_len = 0;
    uint8_t counter = 1;
    uint8_t hmac_in[64 + 64 + 1];  // Tprev(≤64) || info(≤64) || counter
    while (out_len > 0) {
        size_t p = 0;
        if (t_len) { std::memcpy(hmac_in + p, t, t_len); p += t_len; }
        std::memcpy(hmac_in + p, info, info_len); p += info_len;
        hmac_in[p++] = counter;
        hmac_sha512_local(prk, 64, hmac_in, p, t);
        size_t n = (out_len < 64) ? out_len : 64;
        std::memcpy(out, t, n); out += n; out_len -= n;
        t_len = 64; ++counter;
    }
}

// OpenSSL EVP_KDF("HKDF") 封装
struct OsslKdf {
    EVP_KDF* kdf = nullptr;
    EVP_KDF_CTX* kctx = nullptr;
    const char* digest = nullptr;
    const uint8_t* salt = nullptr; size_t salt_len = 0;
    const uint8_t* info = nullptr; size_t info_len = 0;
    bool ok = false;
    explicit OsslKdf(const char* d) : digest(d) {
        kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
        if (kdf) kctx = EVP_KDF_CTX_new(kdf);
        ok = (kctx != nullptr);
    }
    ~OsslKdf() {
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
    }
    bool derive(const uint8_t* ikm, size_t ikm_len, uint8_t* out, size_t out_len) {
        OSSL_PARAM params[5];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest), 0);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(ikm), ikm_len);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt), salt_len);
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info), info_len);
        params[4] = OSSL_PARAM_construct_end();
        return EVP_KDF_derive(kctx, out, out_len, params) == 1;
    }
};

// ── 变体描述 ──
struct Variant {
    const char* algo;
    const char* digest;   // OpenSSL 摘要名
    size_t okm_len;       // OKM 长度 (32 / 48 / 64)
    void (*jp)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t);
};

static const Variant kVariants[] = {
    {"hkdf-sha256-unalign", "SHA256", 32, jp_hkdf_sha256},
    {"hkdf-sha384-unalign", "SHA384", 48, jp_hkdf_sha384},
    {"hkdf-sha512-unalign", "SHA512", 64, jp_hkdf_sha512},
};

int main() {
    const bool smoke = (std::getenv("BENCH_SMOKE") != nullptr);
    const size_t* bench_sizes = smoke ? kSizesSmoke : kSizesAll;
    const size_t bench_n = smoke ? (sizeof(kSizesSmoke) / sizeof(kSizesSmoke[0]))
                                 : (sizeof(kSizesAll) / sizeof(kSizesAll[0]));
    const size_t bench_off_n = sizeof(kBenchOffsets) / sizeof(kBenchOffsets[0]);
    const size_t check_off_n = sizeof(kCheckOffsets) / sizeof(kCheckOffsets[0]);
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;

    std::printf("=== jpssl HKDF (RFC 5869) 非对齐对比组 vs OpenSSL 微基准 ===\n");
    std::printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    std::printf("BENCH_SMOKE     : %s (bench 档位=%zu x offset=%zu, ~%.0fms/轮, %d 轮)\n",
                smoke ? "on" : "off", bench_n, bench_off_n, target_ms, rounds);
    std::printf("CPU features    : AES-NI=%d AVX2=%d PCLMULQDQ=%d VAES=%d SHA-NI=%d ADX=%d AVX512=%d NEON=%d\n",
                (int)jpssl::cpu_has_aesni(), (int)jpssl::cpu_has_avx2(),
                (int)jpssl::cpu_has_pclmulqdq(), (int)jpssl::cpu_has_vpclmulqdq_vaes(),
                (int)jpssl::cpu_has_sha_ni(), (int)jpssl::cpu_has_adx(),
                (int)jpssl::cpu_has_avx512(), (int)jpssl::cpu_has_neon());

    // ── 数据准备 (确定性内容) ──
    fill_deterministic(g_msg, kMax, 0x12345678u);
    // salt/info 在独立缓冲: 对齐份与在 +3/+7 偏移处的非对齐副本, 字节完全一致
    for (int i = 0; i < 16; ++i) {
        g_salt_a[i] = (uint8_t)(0x40 + i);
        g_info_a[i] = (uint8_t)(0x80 + i);
    }
    std::memcpy(g_salt_u + 3, g_salt_a, 16);  // 非对齐 salt 副本 (相同字节)
    std::memcpy(g_info_u + 7, g_info_a, 16);  // 非对齐 info 副本 (相同字节)

    const uint8_t* salt_a = g_salt_a;        // 对齐 salt (offset 0)
    const uint8_t* info_a = g_info_a;        // 对齐 info (offset 0)
    const uint8_t* salt_u = g_salt_u + 3;    // 非对齐 salt (offset 3)
    const uint8_t* info_u = g_info_u + 7;    // 非对齐 info (offset 7)

    // ── 正确性自检 (始终全部档位/全部 offset) ──
    std::printf("\n--- 正确性自检 (非对齐 jpssl vs OpenSSL 逐字节比对; offset vs offset=0) ---\n");
    bool all_pass = true;
    size_t pass_cnt = 0;
    auto check = [&](const char* what, const std::string& got, const std::string& want) {
        bool ok = (got == want);
        all_pass = all_pass && ok;
        std::printf("  check %-46s : %s\n", what, ok ? "PASS" : "FAIL");
        if (ok) ++pass_cnt;
        if (!ok) {
            std::printf("        jpssl   = %s\n", got.c_str());
            std::printf("        openssl = %s\n", want.c_str());
        }
    };

    OsslKdf kd256("SHA256"), kd384("SHA384"), kd512("SHA512");
    kd256.salt = salt_a; kd256.salt_len = 16; kd256.info = info_a; kd256.info_len = 16;
    kd384.salt = salt_a; kd384.salt_len = 16; kd384.info = info_a; kd384.info_len = 16;
    kd512.salt = salt_a; kd512.salt_len = 16; kd512.info = info_a; kd512.info_len = 16;
    if (!kd256.ok || !kd384.ok || !kd512.ok)
        std::printf("WARN: OpenSSL EVP_KDF 初始化失败 (ok=%d/%d/%d)\n",
                    (int)kd256.ok, (int)kd384.ok, (int)kd512.ok);

    // 把同一段消息分别放到 offset=0 与 offset=X (字节相同, 地址不同), 再比较 OKM
    // 注意: 每次变体重新放置 offset=0 副本, 避免前面 offset 副本覆盖其尾部字节
    for (size_t s : kSizesAll) {
        for (const Variant& v : kVariants) {
            std::memcpy(g_work + 0, g_msg, s);      // 对齐放置
            OsslKdf* kd = (v.algo == std::string("hkdf-sha256-unalign")) ? &kd256
                         : (v.algo == std::string("hkdf-sha384-unalign")) ? &kd384 : &kd512;
            uint8_t oa[64], oa2[64];                // offset=0 基线 (jpssl / openssl)
            v.jp(salt_a, 16, g_work + 0, s, info_a, 16, oa, v.okm_len);
            if (!kd->ok || !kd->derive(g_work + 0, s, oa2, v.okm_len)) {
                char tag[96];
                std::snprintf(tag, sizeof(tag), "%s len=%zu off=0 (ossl kdf)", v.algo, s);
                check(tag, "kdf-error", "ok");
            } else {
                char tag[96];
                std::snprintf(tag, sizeof(tag), "%s len=%zu off=0 jpssl==openssl", v.algo, s);
                check(tag, to_hex(oa, v.okm_len), to_hex(oa2, v.okm_len));
            }
            for (size_t oi = 0; oi < check_off_n; ++oi) {
                size_t off = kCheckOffsets[oi];
                std::memcpy(g_work + off, g_msg, s);   // 同一消息, 非对齐地址
                uint8_t o1[64], o2[64], o3[64], o4[64];
                char tag[96];
                // 1) 非对齐下 jpssl vs OpenSSL 逐字节一致
                v.jp(salt_a, 16, g_work + off, s, info_a, 16, o1, v.okm_len);
                bool d1 = kd->ok && kd->derive(g_work + off, s, o2, v.okm_len);
                if (!d1) {
                    std::snprintf(tag, sizeof(tag), "%s len=%zu off=%zu jpssl==openssl (ossl kdf)", v.algo, s, off);
                    check(tag, "kdf-error", "ok");
                } else {
                    std::snprintf(tag, sizeof(tag), "%s len=%zu off=%zu jpssl==openssl", v.algo, s, off);
                    check(tag, to_hex(o1, v.okm_len), to_hex(o2, v.okm_len));
                }
                // 2) offset vs offset=0 一致 (jpssl / openssl 各自)
                std::snprintf(tag, sizeof(tag), "%s len=%zu off=%zu==off=0 jpssl", v.algo, s, off);
                check(tag, to_hex(o1, v.okm_len), to_hex(oa, v.okm_len));
                std::snprintf(tag, sizeof(tag), "%s len=%zu off=%zu==off=0 openssl", v.algo, s, off);
                check(tag, to_hex(o2, v.okm_len), to_hex(oa2, v.okm_len));
                // 3) salt/info 也非对齐: jpssl vs OpenSSL 一致, 且与对齐 salt/info 一致
                kd->salt = salt_u; kd->info = info_u;
                v.jp(salt_u, 16, g_work + off, s, info_u, 16, o3, v.okm_len);
                bool d3 = kd->ok && kd->derive(g_work + off, s, o4, v.okm_len);
                std::snprintf(tag, sizeof(tag), "%s len=%zu off=%zu salt/info-unalign jpssl==openssl", v.algo, s, off);
                if (!d3) check(tag, "kdf-error", "ok");
                else       check(tag, to_hex(o3, v.okm_len), to_hex(o4, v.okm_len));
                std::snprintf(tag, sizeof(tag), "%s len=%zu off=%zu salt/info-unalign==aligned jpssl", v.algo, s, off);
                check(tag, to_hex(o3, v.okm_len), to_hex(o1, v.okm_len));
                kd->salt = salt_a; kd->info = info_a;
            }
        }
    }

    if (!all_pass) {
        std::printf("\n正确性自检存在 FAIL, 放弃基准并退出(1)\n");
        return 1;
    }
    std::printf("\n正确性自检: 全部 PASS (%zu 项)\n", pass_cnt);

    // ── 基准 ──
    std::printf("\n--- 基准 (长度 x offset, 每轮约 %.0fms, %d 轮取最小) ---\n", target_ms, rounds);
    std::printf("%-17s %-9s %8s %6s %12s %12s\n", "algo", "impl", "size_bytes", "off", "ns/op", "MB/s");

    for (size_t i = 0; i < bench_n; ++i) {
        size_t s = bench_sizes[i];
        for (size_t oj = 0; oj < bench_off_n; ++oj) {
            size_t off = kBenchOffsets[oj];
            std::memcpy(g_work + off, g_msg, s);   // 非对齐副本 (含 off=0 即对齐)
            for (const Variant& v : kVariants) {
                OsslKdf* kd = (v.algo == std::string("hkdf-sha256-unalign")) ? &kd256
                             : (v.algo == std::string("hkdf-sha384-unalign")) ? &kd384 : &kd512;
                uint8_t o[64];
                bench_case(v.algo, "jpssl", s, off, (double)s, target_ms, rounds,
                           [&] { v.jp(salt_a, 16, g_work + off, s, info_a, 16, o, v.okm_len); g_sink ^= o[0]; });
                bench_case(v.algo, "openssl", s, off, (double)s, target_ms, rounds,
                           [&] { kd->derive(g_work + off, s, o, v.okm_len); g_sink ^= o[0]; });
            }
        }
    }

    // ── 写 CSV ──
    std::error_code ec;
    std::filesystem::create_directories("benchmarks/results", ec);
    std::FILE* fp = std::fopen("benchmarks/results/bench_hkdf_unalign.csv", "w");
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
    std::printf("\nCSV 已写入 benchmarks/results/bench_hkdf_unalign.csv (%zu 数据行)\n", g_rows.size());
    return 0;
}
