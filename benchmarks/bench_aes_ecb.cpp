// bench_aes_ecb.cpp — AES-ECB (AES-128/256, 无填充整块) 多实现 × 多长度 × OpenSSL 对比微基准
//
// 覆盖:
//   AES-128/256-ECB (无填充): jpssl sw / aesni / auto vs OpenSSL (padding=0)
//
// 说明:
//   - jpssl 的 ECB 无填充标量/AES-NI 入口为 PKCS7 自动填充接口
//     (aes_encrypt_ecb_pkcs7_sw / aes_encrypt_ecb_pkcs7_aesni): 长度须为 16 的倍数,
//     密文比明文多一块填充; 与 OpenSSL (padding=0) 交叉验证时比较密文前 n 字节。
//   - jpssl auto (aes_encrypt_ecb / aes_decrypt_ecb) 为无填充接口, 密文逐字节一致。
//   - OpenSSL 对照: EVP_aes_128_ecb / EVP_aes_256_ecb + EVP_CIPHER_CTX_set_padding(0)。
//   - 微基准: 先估时再自适应迭代使每轮约 target_ms, 取 rounds 轮最小值。
//   - 正确性: 每个 (算法,实现) 与 OpenSSL 在 256B 与 1MB 两档交叉验证, 任一 FAIL
//     以非零码退出; 自检始终执行全部档位。
//   - BENCH_SMOKE=1: 长度只测 16/256, 自适应目标 ~80ms, 1 轮; 未设置时全量 5 档、
//     目标 ~150ms、3 轮取最小。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_aes_ecb.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_aes_ecb

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

// 消息长度矩阵 (均为 16 的倍数)
static const std::vector<size_t> g_sizes_full = {16, 256, 4096, 65536, 1048576};
static const std::vector<size_t> g_sizes_smoke = {16, 256};

// 测试明文填充 (确定性伪随机)
static void fill_test(std::vector<uint8_t>& v, size_t n, uint32_t seed) {
    v.resize(n);
    uint32_t x = seed * 2654435761u + 12345u;
    for (size_t i = 0; i < n; ++i) {
        x = x * 1664525u + 1013904223u;
        v[i] = static_cast<uint8_t>(x >> 24);
    }
}

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

// ── 结果收集 ────────────────────────────────────────────────────
struct Row {
    std::string algo;
    std::string impl;
    size_t size;
    double ns;
    double mbps;
    bool skipped;
};
static std::vector<Row> g_rows;
static bool g_all_pass = true;

static void record(const char* algo, const char* impl, size_t size, double ns) {
    double mbps = size / ns * 1000.0;  // bytes/ns * 1000 = MB/s
    g_rows.push_back({algo, impl, size, ns, mbps, false});
    printf("%-26s %-12s %9zu %12.1f %12.1f\n", algo, impl, size, ns, mbps);
}

// ── OpenSSL 基础封装 ────────────────────────────────────────────
// ECB 无 IV; 每个操作强制 padding=0 (EVP_EncryptInit_ex 可能重置 padding)

static void ossl_cipher_enc(const EVP_CIPHER* ciph, const uint8_t* key,
                            const uint8_t* in, size_t n, uint8_t* out,
                            EVP_CIPHER_CTX* ctx) {
    EVP_EncryptInit_ex(ctx, ciph, nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int outl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, in, static_cast<int>(n));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, out + outl, &fin);
}

static void ossl_cipher_dec(const EVP_CIPHER* ciph, const uint8_t* key,
                            const uint8_t* in, size_t n, uint8_t* out,
                            EVP_CIPHER_CTX* ctx) {
    EVP_DecryptInit_ex(ctx, ciph, nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int outl = 0;
    EVP_DecryptUpdate(ctx, out, &outl, in, static_cast<int>(n));
    int fin = 0;
    EVP_DecryptFinal_ex(ctx, out + outl, &fin);
}

// ── 自检辅助 ────────────────────────────────────────────────────
static int g_checks = 0;

static bool check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) g_all_pass = false;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    return ok;
}

// ── 块密码 (ECB) 交叉验证: jpssl(自动 PKCS7 填充) vs OpenSSL(padding=0) ──
// jpssl 密文 = n+16 字节, 前 n 字节应等于 OpenSSL 无填充密文
template <typename EncFn, typename DecFn>
static void validate_block_padded(const char* name, size_t n,
                                  EncFn jenc, DecFn jdec,
                                  const EVP_CIPHER* ciph, const uint8_t* key) {
    std::vector<uint8_t> pt, jct, jpt, oct, opt;
    fill_test(pt, n, 0xA11CE);
    jenc(pt, jct);  // jpssl 加密 (n+16)
    EVP_CIPHER_CTX* enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(enc, 0);
    oct.resize(n);
    ossl_cipher_enc(ciph, key, pt.data(), n, oct.data(), enc);
    EVP_CIPHER_CTX_free(enc);

    bool ok = jct.size() == n + 16 && std::equal(oct.begin(), oct.end(), jct.begin());
    check(ok, (std::string(name) + " ct prefix == OpenSSL (padding=0)").c_str());

    bool d1 = jdec(jct, jpt);
    ok = d1 && jpt == pt;
    check(ok, (std::string(name) + " jpssl decrypt roundtrip").c_str());

    // OpenSSL 解密 jpssl 密文前 n 字节
    EVP_CIPHER_CTX* dec2 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(dec2, 0);
    opt.resize(n);
    ossl_cipher_dec(ciph, key, jct.data(), n, opt.data(), dec2);
    EVP_CIPHER_CTX_free(dec2);
    ok = opt == pt;
    check(ok, (std::string(name) + " OpenSSL decrypts jpssl ct").c_str());
}

// 无填充块密码 (jpssl aes_encrypt_ecb): 密文逐字节一致
template <typename EncFn, typename DecFn>
static void validate_block_nopad(const char* name, size_t n,
                                 EncFn jenc, DecFn jdec,
                                 const EVP_CIPHER* ciph, const uint8_t* key) {
    std::vector<uint8_t> pt, jct, oct, opt;
    fill_test(pt, n, 0xBADC0DE);
    jct.resize(n);
    jenc(pt, jct);
    EVP_CIPHER_CTX* enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(enc, 0);
    oct.resize(n);
    ossl_cipher_enc(ciph, key, pt.data(), n, oct.data(), enc);
    EVP_CIPHER_CTX_free(enc);

    bool ok = jct == oct;
    check(ok, (std::string(name) + " ct == OpenSSL (padding=0)").c_str());

    std::vector<uint8_t> jpt(n);
    jdec(jct, jpt);
    ok = jpt == pt;
    check(ok, (std::string(name) + " jpssl decrypt roundtrip").c_str());

    EVP_CIPHER_CTX* dec = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(dec, 0);
    opt.resize(n);
    ossl_cipher_dec(ciph, key, oct.data(), n, opt.data(), dec);
    EVP_CIPHER_CTX_free(dec);
    ok = opt == pt;
    check(ok, (std::string(name) + " OpenSSL decrypt roundtrip").c_str());
}

// ── ECB 基准入口: 单实现 × 单长度 ───────────────────────────────
// jpssl sw/aesni 走 PKCS7 填充接口 (密文 n+16); auto 与 openssl 为无填充 (n)
template <typename E, typename D>
static void bench_block(const char* algo, size_t size,
                        const aes_context& ctx,
                        const EVP_CIPHER* ciph, const uint8_t* key,
                        E&& jenc, D&& jdec, const char* impl,
                        double target_ms, int rounds) {
    // 准备密文 (供解密基准)
    std::vector<uint8_t> pt, jct, jpt;
    fill_test(pt, size, 0x00B100C);
    jenc(pt, jct);

    char algo_e[64], algo_d[64];
    std::snprintf(algo_e, sizeof(algo_e), "%s-enc", algo);
    std::snprintf(algo_d, sizeof(algo_d), "%s-dec", algo);

    double nse = auto_bench([&] {
        jenc(pt, jct);
        g_sink ^= jct[0];
    }, target_ms, rounds);
    record(algo_e, impl, size, nse);

    double nsd = auto_bench([&] {
        jdec(jct, jpt);
        g_sink ^= jpt[0];
    }, target_ms, rounds);
    record(algo_d, impl, size, nsd);

    // OpenSSL 对照
    EVP_CIPHER_CTX* c_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(c_enc, 0);
    EVP_CIPHER_CTX* c_dec = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(c_dec, 0);
    std::vector<uint8_t> oct(size), opt(size);
    nse = auto_bench([&] {
        ossl_cipher_enc(ciph, key, pt.data(), size, oct.data(), c_enc);
        g_sink ^= oct[0];
    }, target_ms, rounds);
    record(algo_e, "openssl", size, nse);
    nsd = auto_bench([&] {
        ossl_cipher_dec(ciph, key, oct.data(), size, opt.data(), c_dec);
        g_sink ^= opt[0];
    }, target_ms, rounds);
    record(algo_d, "openssl", size, nsd);
    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// ── main ────────────────────────────────────────────────────────
int main() {
    auto feats = jpssl::cpu_features::detect();
    printf("=== bench_aes_ecb: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
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

    const std::vector<size_t> sizes = smoke ? g_sizes_smoke : g_sizes_full;

    // ── 自检 (先于基准, 全 PASS 才继续; 始终执行全部档位) ──
    printf("\n=== Correctness self-checks (jpssl <-> OpenSSL) ===\n");
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
        const char* kn = keysz ? "aes-256-ecb" : "aes-128-ecb";

        for (size_t n : {size_t(256), size_t(1048576)}) {
            char nm[80];
            std::snprintf(nm, sizeof(nm), "%s/sw@%zu", kn, n);
            validate_block_padded(nm, n,
                                  [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                                      jpssl::aes_encrypt_ecb_pkcs7_sw(ctx, p, c);
                                  },
                                  [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                                      return jpssl::aes_decrypt_ecb_pkcs7_sw(ctx, c, p);
                                  },
                                  ciph, key);
            std::snprintf(nm, sizeof(nm), "%s/aesni@%zu", kn, n);
            validate_block_padded(nm, n,
                                  [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                                      jpssl::aes_encrypt_ecb_pkcs7_aesni(ctx, p, c);
                                  },
                                  [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                                      return jpssl::aes_decrypt_ecb_pkcs7_aesni(ctx, c, p);
                                  },
                                  ciph, key);
            std::snprintf(nm, sizeof(nm), "%s/auto@%zu", kn, n);
            validate_block_nopad(nm, n,
                                 [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                                     jpssl::aes_encrypt_ecb(ctx, p, c);
                                 },
                                 [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                                     jpssl::aes_decrypt_ecb(ctx, c, p);
                                 },
                                 ciph, key);
        }
    }

    if (!g_all_pass) {
        printf("\nSelf-check FAILED — aborting benchmark (exit 1)\n");
        return 1;
    }
    printf("All self-checks passed (%d checks)\n", g_checks);

    // ── 基准 ──
    double target_ms = smoke ? 80.0 : 150.0;
    int rounds = smoke ? 1 : 3;
    printf("\n=== Benchmarks (%s: min of %d rounds, ~%.0fms/round) ===\n",
           smoke ? "smoke" : "full", rounds, target_ms);
    printf("%-26s %-12s %9s %12s %12s\n", "algo", "impl", "size", "ns/op", "MB/s");

    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
        char algo[64];
        std::snprintf(algo, sizeof(algo), "%s", keysz ? "aes-256-ecb" : "aes-128-ecb");
        for (size_t s : sizes) {
            bench_block(algo, s, ctx, ciph, key,
                        [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                            jpssl::aes_encrypt_ecb_pkcs7_sw(ctx, p, c);
                        },
                        [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                            return jpssl::aes_decrypt_ecb_pkcs7_sw(ctx, c, p);
                        },
                        "jpssl-sw", target_ms, rounds);
            bench_block(algo, s, ctx, ciph, key,
                        [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                            jpssl::aes_encrypt_ecb_pkcs7_aesni(ctx, p, c);
                        },
                        [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                            return jpssl::aes_decrypt_ecb_pkcs7_aesni(ctx, c, p);
                        },
                        "jpssl-aesni", target_ms, rounds);
            bench_block(algo, s, ctx, ciph, key,
                        [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                            c.resize(p.size());
                            jpssl::aes_encrypt_ecb(ctx, p, c);
                        },
                        [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                            p.resize(c.size());
                            jpssl::aes_decrypt_ecb(ctx, c, p);
                        },
                        "jpssl-auto", target_ms, rounds);
        }
    }

    // ── 写 CSV ──
    std::filesystem::path csv_dir = std::filesystem::path("benchmarks") / "results";
    std::error_code ec;
    std::filesystem::create_directories(csv_dir, ec);
    std::string csv_path = (csv_dir / "bench_aes_ecb.csv").string();
    {
        std::ofstream f(csv_path);
        f << "algo,impl,size_bytes,ns_per_op,throughput_mbps\n";
        for (const auto& r : g_rows) {
            if (r.skipped) continue;
            f << r.algo << ',' << r.impl << ',' << r.size << ','
              << r.ns << ',' << r.mbps << '\n';
        }
    }
    printf("\nCSV written to %s\n", csv_path.c_str());
    printf("Done. All self-checks passed, exit 0.\n");
    return 0;
}
