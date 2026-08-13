// bench_aes_ecb_unalign.cpp — AES-ECB 非对齐测试对比组 (与 OpenSSL 对比) 微基准
//
// 本文件是 benchmarks/bench_aes_ecb.cpp 的补充测试: 不改动任何现有文件,
// 只新增【非对齐长度 + 非对齐指针】两个维度, 输出独立 CSV。
//
// 覆盖:
//   AES-128/256-ECB (非 16 倍数长度, PKCS7 填充路径):
//     jpssl sw / aesni / auto (pkcs7 三入口) vs OpenSSL (padding=1, 同条件)
//
// 非对齐组的定义:
//   1. 非对齐长度: {17, 1001, 32767, 100003} 字节 (非 16 的倍数)。
//      ECB/CBC 走 PKCS7 填充路径: 密文 = ceil(n/16)*16 字节。
//   2. 非对齐指针 (offset): 分配 buf = alloc(size + max_offset + 16),
//      数据起始地址使用 buf + offset; offset ∈ {1, 3, 7, 13} 全覆盖自检,
//      性能档至少测 offset=0 (基线) 与 offset=3。
//   3. 自检 (始终执行全部档位): 非对齐长度+偏移下 jpssl 各实现输出与
//      OpenSSL 逐字节一致; 任一 FAIL 以非零码退出且不写 CSV。
//   4. 性能基准: 长度 {17, 1001, 32767, 100003} × offset {0, 3},
//      加密/解密分别记录, 与 OpenSSL 同条件对比;
//      BENCH_SMOKE=1 时只测长度 {17, 1001} × offset {0,3}, ~80ms, 1 轮;
//      未设置时全量、~150ms、3 轮取最小。
//
// 关于 OpenSSL 对照的说明 (与参考文件的差异):
//   - 参考文件 (bench_aes_ecb.cpp) 用 padding=0 + "前 n 字节" 比较, 其长度
//     均为 16 的倍数。实测 OpenSSL ECB 在 padding=0 且长度非 16 倍数时会
//     丢弃尾部不完整块 (17 字节 → 仅输出 16 字节), 因此对非对齐长度必须
//     使用 OpenSSL padding=1 (PKCS7), 与 jpssl 的 PKCS7 填充路径逐字节一致
//     (密文长度同为 ceil(n/16)*16, 直接整体比较, 不再需要"前 n 字节"技巧)。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_aes_ecb_unalign.cpp
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_aes_ecb_unalign

#include "aes.hpp"
#include "cpu_features.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

using jpssl::aes_context;

using Clock = std::chrono::steady_clock;

// 阻止编译器把输出缓冲区相关调用折叠/消除
static volatile int g_sink = 0;

// ── 固定测试数据 ────────────────────────────────────────────────
static const std::array<uint8_t, 16> K16 = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const std::array<uint8_t, 32> K32 = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

// 非对齐长度矩阵 (均非 16 的倍数)
static const std::vector<size_t> g_sizes_full = {17, 1001, 32767, 100003};
static const std::vector<size_t> g_sizes_smoke = {17, 1001};

// 非对齐指针偏移
static constexpr size_t kMaxOffset = 13;                             // 分配冗余
static const std::vector<size_t> g_offsets_check = {0, 1, 3, 7, 13}; // 自检全覆盖
static const std::vector<size_t> g_offsets_perf = {0, 3};            // 性能档

// 确定性伪随机填充
static void fill_test(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed * 2654435761u + 12345u;
    for (size_t i = 0; i < n; ++i) {
        x = x * 1664525u + 1013904223u;
        p[i] = static_cast<uint8_t>(x >> 24);
    }
}

// PKCS7 填充后密文长度 (ECB 块 16)
static size_t padded_len(size_t n) { return ((n + 15) / 16) * 16; }

// ── 自适应微基准: 每轮约 target_ms, 取 rounds 轮中最小值 ────────
template <typename F>
static double auto_bench(F&& f, double target_ms, int rounds) {
    f();  // 预热
    const int est_n = 8;
    auto t0 = Clock::now();
    for (int i = 0; i < est_n; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / est_n;
    if (est_ns < 1000.0) {
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

// ── 结果收集 (含 offset 列) ─────────────────────────────────────
struct Row {
    std::string algo;
    std::string impl;
    size_t size;
    size_t offset;
    double ns;
    double mbps;
};
static std::vector<Row> g_rows;
static bool g_all_pass = true;

static void record(const char* algo, const char* impl, size_t size, size_t offset, double ns) {
    double mbps = size / ns * 1000.0;  // bytes/ns * 1000 = MB/s
    g_rows.push_back({algo, impl, size, offset, ns, mbps});
    printf("%-30s %-12s %9zu %7zu %12.1f %12.1f\n", algo, impl, size, offset, ns, mbps);
}

// ── OpenSSL 基础封装 (padding 可配; EVP_EncryptInit_ex 可能重置 padding, 每 op 强制) ──
// 非对齐长度必须用 padding=1 (PKCS7): padding=0 会丢弃尾部不完整块 (实测)。
static void ossl_cipher_enc(const EVP_CIPHER* ciph, const uint8_t* key,
                            const uint8_t* in, size_t n, uint8_t* out, int pad,
                            EVP_CIPHER_CTX* ctx, size_t* out_total) {
    EVP_EncryptInit_ex(ctx, ciph, nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, pad);
    int outl = 0, fin = 0;
    EVP_EncryptUpdate(ctx, out, &outl, in, static_cast<int>(n));
    EVP_EncryptFinal_ex(ctx, out + outl, &fin);
    *out_total = static_cast<size_t>(outl) + static_cast<size_t>(fin);
}

static void ossl_cipher_dec(const EVP_CIPHER* ciph, const uint8_t* key,
                            const uint8_t* in, size_t n, uint8_t* out, int pad,
                            EVP_CIPHER_CTX* ctx, size_t* out_total) {
    EVP_DecryptInit_ex(ctx, ciph, nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, pad);
    int outl = 0, fin = 0;
    EVP_DecryptUpdate(ctx, out, &outl, in, static_cast<int>(n));
    EVP_DecryptFinal_ex(ctx, out + outl, &fin);
    *out_total = static_cast<size_t>(outl) + static_cast<size_t>(fin);
}

// ── 自检辅助 ────────────────────────────────────────────────────
static int g_checks = 0;

static bool check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) g_all_pass = false;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    return ok;
}

// ── 非对齐自检: jpssl(PKCS7) vs OpenSSL(padding=1), 整体逐字节一致 ──
//   buf: 分配基址 (容量 ≥ offset + n + 冗余); 数据起始地址 = buf + offset
//   返回 jpssl 密文/明文, 供 offset 与 offset=0 的一致性比较
template <typename EncFn, typename DecFn>
static void validate_unalign(const char* name, size_t n, size_t offset,
                             const uint8_t* buf,
                             EncFn jenc, DecFn jdec,
                             const EVP_CIPHER* ciph, const uint8_t* key,
                             std::vector<uint8_t>* ct_out,
                             std::vector<uint8_t>* pt_out) {
    const uint8_t* in = buf + offset;
    const size_t plen = padded_len(n);

    // jpssl 加密 (PKCS7): 密文 plen 字节
    std::vector<uint8_t> jct;
    jenc(std::span<const uint8_t>(in, n), jct);

    // OpenSSL padding=1 对照
    EVP_CIPHER_CTX* enc = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> oct(plen);
    size_t olen = 0;
    ossl_cipher_enc(ciph, key, in, n, oct.data(), 1, enc, &olen);
    EVP_CIPHER_CTX_free(enc);
    bool ok = jct.size() == plen && olen == plen && std::equal(oct.begin(), oct.end(), jct.begin());
    check(ok, (std::string(name) + " ct == OpenSSL (PKCS7)").c_str());

    // jpssl 解密回原文
    std::vector<uint8_t> jpt;
    bool d1 = jdec(jct, jpt);
    ok = d1 && jpt.size() == n && std::equal(jpt.begin(), jpt.end(), in);
    check(ok, (std::string(name) + " jpssl decrypt roundtrip").c_str());

    // OpenSSL 解密 jpssl 密文 (padding=1) → 原文
    EVP_CIPHER_CTX* dec = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> opt(plen);
    size_t dlen = 0;
    ossl_cipher_dec(ciph, key, jct.data(), jct.size(), opt.data(), 1, dec, &dlen);
    EVP_CIPHER_CTX_free(dec);
    ok = dlen == n && std::equal(opt.begin(), opt.begin() + n, in);
    check(ok, (std::string(name) + " OpenSSL decrypts jpssl ct").c_str());

    if (ct_out) *ct_out = std::move(jct);
    if (pt_out) *pt_out = std::move(jpt);
}

// ── 非对齐基准入口: 单实现 × 单长度 × 单偏移 ────────────────────
// jpssl sw/aesni/auto 均走 PKCS7 填充接口 (密文 plen); OpenSSL 用 padding=1 同条件
template <typename E, typename D>
static void bench_unalign(const char* algo, size_t size, size_t offset,
                          const EVP_CIPHER* ciph, const uint8_t* key,
                          E&& jenc, D&& jdec, const char* impl,
                          double target_ms, int rounds) {
    const size_t plen = padded_len(size);

    // 输入明文: 起始地址 pt_buf.data() + offset
    std::vector<uint8_t> pt_buf(size + kMaxOffset + 16);
    fill_test(pt_buf.data() + offset, size, 0x00B100C);

    // 预计算密文 (供解密基准): 加密输出写入 ct_buf + offset
    std::vector<uint8_t> ct_vec, pt_vec;
    jenc(std::span<const uint8_t>(pt_buf.data() + offset, size), ct_vec);
    std::vector<uint8_t> ct_buf(plen + kMaxOffset + 16);
    std::memcpy(ct_buf.data() + offset, ct_vec.data(), ct_vec.size());

    char algo_e[96], algo_d[96];
    std::snprintf(algo_e, sizeof(algo_e), "%s-enc-unalign", algo);
    std::snprintf(algo_d, sizeof(algo_d), "%s-dec-unalign", algo);

    double nse = auto_bench([&] {
        jenc(std::span<const uint8_t>(pt_buf.data() + offset, size), ct_vec);
        g_sink ^= ct_vec[0];
    }, target_ms, rounds);
    record(algo_e, impl, size, offset, nse);

    double nsd = auto_bench([&] {
        jdec(std::span<const uint8_t>(ct_buf.data() + offset, ct_vec.size()), pt_vec);
        g_sink ^= pt_vec[0];
    }, target_ms, rounds);
    record(algo_d, impl, size, offset, nsd);

    // OpenSSL 同条件对照 (padding=1, 同 offset)
    EVP_CIPHER_CTX* c_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(c_enc, 1);
    EVP_CIPHER_CTX* c_dec = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(c_dec, 1);
    std::vector<uint8_t> oct(plen + kMaxOffset + 16), opt(size + kMaxOffset + 16);
    size_t olen = 0, dlen = 0;
    nse = auto_bench([&] {
        ossl_cipher_enc(ciph, key, pt_buf.data() + offset, size, oct.data() + offset, 1, c_enc, &olen);
        g_sink ^= oct[offset];
    }, target_ms, rounds);
    record(algo_e, "openssl", size, offset, nse);
    nsd = auto_bench([&] {
        ossl_cipher_dec(ciph, key, oct.data() + offset, plen, opt.data() + offset, 1, c_dec, &dlen);
        g_sink ^= opt[offset];
    }, target_ms, rounds);
    record(algo_d, "openssl", size, offset, nsd);
    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// ── main ────────────────────────────────────────────────────────
int main() {
    auto feats = jpssl::cpu_features::detect();
    printf("=== bench_aes_ecb_unalign: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("CPU features: AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES+VPCLMULQDQ=%d SHA-NI=%d\n",
           (int)feats.aesni, (int)feats.avx2, (int)feats.pclmulqdq,
           (int)feats.avx512, (int)feats.vpclmulqdq_vaes, (int)feats.sha_ni);

    // 确保 OpenSSL 库初始化
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    bool smoke = [] {
        const char* e = std::getenv("BENCH_SMOKE");
        return e && *e && std::string(e) != "0";
    }();

    aes_context ctx128, ctx256;
    ctx128.init(K16);
    ctx256.init(K32);

    // ── 自检 (始终执行全部档位: 4 长度 × 5 偏移 × 3 实现 × 2 密钥) ──
    printf("\n=== Correctness self-checks (unalign: jpssl <-> OpenSSL, PKCS7) ===\n");
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
        const char* kn = keysz ? "aes-256-ecb" : "aes-128-ecb";

        for (size_t n : g_sizes_full) {
            // 分配偏移缓冲: 容量 offset + n + 冗余, 数据从 buf+offset 起。
            // 同一份明文复制到各偏移位置 (与 buf+0 处完全一致), 以验证
            // "同输入、不同对齐地址" 下输出一致。
            std::vector<uint8_t> buf(n + kMaxOffset + 16);
            fill_test(buf.data(), n, 0xA11CE ^ static_cast<uint32_t>(n));

            // 每个实现存 offset=0 的密文/明文, 供 offset 一致性比较
            std::vector<uint8_t> ct0_sw, pt0_sw, ct0_ni, pt0_ni, ct0_au, pt0_au;

            for (size_t off : g_offsets_check) {
                // 确定性填充: 同一份明文出现在 buf+0 与 buf+off (逐字节一致),
                // 验证 "同输入、不同对齐地址" 下输出一致
                fill_test(buf.data() + off, n, 0xA11CE ^ static_cast<uint32_t>(n));
                char nm[96];
                std::vector<uint8_t> jct, jpt;
                std::snprintf(nm, sizeof(nm), "%s/sw@%zu+off%zu", kn, n, off);
                validate_unalign(nm, n, off, buf.data(),
                                 [&](std::span<const uint8_t> p, std::vector<uint8_t>& c) {
                                     jpssl::aes_encrypt_ecb_pkcs7_sw(ctx, p, c);
                                 },
                                 [&](std::span<const uint8_t> c, std::vector<uint8_t>& p) {
                                     return jpssl::aes_decrypt_ecb_pkcs7_sw(ctx, c, p);
                                 },
                                 ciph, key, &jct, &jpt);
                if (off == 0) { ct0_sw = jct; pt0_sw = jpt; }
                else {
                    check(jct == ct0_sw, (std::string(nm) + " ct == ct@offset0").c_str());
                    check(jpt == pt0_sw, (std::string(nm) + " pt == pt@offset0").c_str());
                }

                std::snprintf(nm, sizeof(nm), "%s/aesni@%zu+off%zu", kn, n, off);
                validate_unalign(nm, n, off, buf.data(),
                                 [&](std::span<const uint8_t> p, std::vector<uint8_t>& c) {
                                     jpssl::aes_encrypt_ecb_pkcs7_aesni(ctx, p, c);
                                 },
                                 [&](std::span<const uint8_t> c, std::vector<uint8_t>& p) {
                                     return jpssl::aes_decrypt_ecb_pkcs7_aesni(ctx, c, p);
                                 },
                                 ciph, key, &jct, &jpt);
                if (off == 0) { ct0_ni = jct; pt0_ni = jpt; }
                else {
                    check(jct == ct0_ni, (std::string(nm) + " ct == ct@offset0").c_str());
                    check(jpt == pt0_ni, (std::string(nm) + " pt == pt@offset0").c_str());
                }

                std::snprintf(nm, sizeof(nm), "%s/auto@%zu+off%zu", kn, n, off);
                validate_unalign(nm, n, off, buf.data(),
                                 [&](std::span<const uint8_t> p, std::vector<uint8_t>& c) {
                                     jpssl::aes_encrypt_ecb_pkcs7(ctx, p, c);
                                 },
                                 [&](std::span<const uint8_t> c, std::vector<uint8_t>& p) {
                                     return jpssl::aes_decrypt_ecb_pkcs7(ctx, c, p);
                                 },
                                 ciph, key, &jct, &jpt);
                if (off == 0) { ct0_au = jct; pt0_au = jpt; }
                else {
                    check(jct == ct0_au, (std::string(nm) + " ct == ct@offset0").c_str());
                    check(jpt == pt0_au, (std::string(nm) + " pt == pt@offset0").c_str());
                }
            }
        }
    }

    if (!g_all_pass) {
        printf("\nSelf-check FAILED — aborting benchmark (exit 1), no CSV written\n");
        return 1;
    }
    printf("All self-checks passed (%d checks)\n", g_checks);

    // ── 基准 ──
    double target_ms = smoke ? 80.0 : 150.0;
    int rounds = smoke ? 1 : 3;
    printf("\n=== Benchmarks (%s: min of %d rounds, ~%.0fms/round) ===\n",
           smoke ? "smoke" : "full", rounds, target_ms);
    printf("%-30s %-12s %9s %7s %12s %12s\n", "algo", "impl", "size", "offset", "ns/op", "MB/s");

    const std::vector<size_t> sizes = smoke ? g_sizes_smoke : g_sizes_full;
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
        char algo[64];
        std::snprintf(algo, sizeof(algo), "%s", keysz ? "aes-256-ecb" : "aes-128-ecb");
        for (size_t s : sizes) {
            for (size_t off : g_offsets_perf) {
                bench_unalign(algo, s, off, ciph, key,
                              [&](std::span<const uint8_t> p, std::vector<uint8_t>& c) {
                                  jpssl::aes_encrypt_ecb_pkcs7_sw(ctx, p, c);
                              },
                              [&](std::span<const uint8_t> c, std::vector<uint8_t>& p) {
                                  return jpssl::aes_decrypt_ecb_pkcs7_sw(ctx, c, p);
                              },
                              "jpssl-sw", target_ms, rounds);
                bench_unalign(algo, s, off, ciph, key,
                              [&](std::span<const uint8_t> p, std::vector<uint8_t>& c) {
                                  jpssl::aes_encrypt_ecb_pkcs7_aesni(ctx, p, c);
                              },
                              [&](std::span<const uint8_t> c, std::vector<uint8_t>& p) {
                                  return jpssl::aes_decrypt_ecb_pkcs7_aesni(ctx, c, p);
                              },
                              "jpssl-aesni", target_ms, rounds);
                bench_unalign(algo, s, off, ciph, key,
                              [&](std::span<const uint8_t> p, std::vector<uint8_t>& c) {
                                  jpssl::aes_encrypt_ecb_pkcs7(ctx, p, c);
                              },
                              [&](std::span<const uint8_t> c, std::vector<uint8_t>& p) {
                                  return jpssl::aes_decrypt_ecb_pkcs7(ctx, c, p);
                              },
                              "jpssl-auto", target_ms, rounds);
            }
        }
    }

    // ── 写 CSV ──
    std::filesystem::path csv_dir = std::filesystem::path("benchmarks") / "results";
    std::error_code ec;
    std::filesystem::create_directories(csv_dir, ec);
    std::string csv_path = (csv_dir / "bench_aes_ecb_unalign.csv").string();
    {
        std::ofstream f(csv_path);
        f << "algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps\n";
        for (const auto& r : g_rows) {
            f << r.algo << ',' << r.impl << ',' << r.size << ',' << r.offset << ','
              << r.ns << ',' << r.mbps << '\n';
        }
    }
    printf("\nCSV written to %s\n", csv_path.c_str());
    printf("Done. All self-checks passed, exit 0.\n");
    return 0;
}
