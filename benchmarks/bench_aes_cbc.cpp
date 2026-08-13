// bench_aes_cbc.cpp — AES-CBC (AES-128/256, 自动 PKCS7 填充) 全量微基准
//
// 覆盖:
//   AES-128/256-CBC 加密/解密 : jpssl sw / aesni (自动 PKCS7 填充) vs OpenSSL (padding=0)
//
// 说明:
//   - jpssl 的 CBC 走 PKCS7 自动填充接口: 密文 = n+16 字节, 前 n 字节与
//     OpenSSL (padding=0) 逐字节一致, 随后附一个完整填充块。
//   - 正确性自检: 每个 (算法,实现) 在全部长度档位与 OpenSSL 交叉验证
//     (ct 前缀 == OpenSSL / jpssl roundtrip / OpenSSL roundtrip /
//     OpenSSL 解密 jpssl 密文前 n 字节), 任一 FAIL 以非零码退出。
//   - 微基准: 先估时再自适应迭代, 每轮约 target_ms, 取 rounds 轮最小值。
//     BENCH_SMOKE=1 时只测 {16,256}、~80ms、1 轮; 否则全量 5 档、~150ms、3 轮。
//     自检始终覆盖全部 5 档长度。
//   - 输出 CSV: benchmarks/results/bench_aes_cbc.csv
//     列头: algo,impl,size_bytes,ns_per_op,throughput_mbps
//     algo 形如 aes-128-cbc-enc; impl 为 jpssl-sw / jpssl-aesni / openssl。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_aes_cbc.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_aes_cbc

#include "aes.hpp"
#include "cpu_features.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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
static const std::array<uint8_t, 16> IV16 = {
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

// 消息长度矩阵 (均为 16 的倍数)
static const std::vector<size_t> g_sizes = {16, 256, 4096, 65536, 1048576};

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

static void record_skip(const char* algo, const char* impl, size_t size, const char* why) {
    g_rows.push_back({algo, impl, size, 0.0, 0.0, true});
    printf("%-26s %-12s %9zu SKIP (%s)\n", algo, impl, size, why);
}

// ── OpenSSL 基础封装 (padding 恒为 0; EVP_EncryptInit_ex 可能重置 padding, 每 op 强制) ──
static void ossl_cipher_enc(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                            const uint8_t* in, size_t n, uint8_t* out,
                            EVP_CIPHER_CTX* ctx) {
    EVP_EncryptInit_ex(ctx, ciph, nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int outl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, in, static_cast<int>(n));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, out + outl, &fin);
}

static void ossl_cipher_dec(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                            const uint8_t* in, size_t n, uint8_t* out,
                            EVP_CIPHER_CTX* ctx) {
    EVP_DecryptInit_ex(ctx, ciph, nullptr, key, iv);
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

// ── CBC 交叉验证: jpssl(自动 PKCS7 填充) vs OpenSSL(padding=0) ──
// jpssl 密文 = n+16 字节, 前 n 字节应等于 OpenSSL 无填充密文
template <typename EncFn, typename DecFn>
static bool validate_block_padded(const char* name, size_t n,
                                  EncFn jenc, DecFn jdec,
                                  const EVP_CIPHER* ciph, const uint8_t* key,
                                  const uint8_t* iv) {
    std::vector<uint8_t> pt, jct, jpt, oct, opt;
    fill_test(pt, n, 0xA11CE);
    jenc(pt, jct);  // jpssl 加密 (n+16)
    EVP_CIPHER_CTX* enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(enc, 0);
    oct.resize(n);
    ossl_cipher_enc(ciph, key, iv, pt.data(), n, oct.data(), enc);
    EVP_CIPHER_CTX_free(enc);

    bool ok = jct.size() == n + 16 && std::equal(oct.begin(), oct.end(), jct.begin());
    check(ok, (std::string(name) + " ct prefix == OpenSSL (padding=0)").c_str());

    bool d1 = jdec(jct, jpt);
    ok = d1 && jpt == pt;
    check(ok, (std::string(name) + " jpssl decrypt roundtrip").c_str());

    EVP_CIPHER_CTX* dec = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(dec, 0);
    opt.resize(n);
    ossl_cipher_dec(ciph, key, iv, oct.data(), n, opt.data(), dec);
    EVP_CIPHER_CTX_free(dec);
    ok = opt == pt;
    check(ok, (std::string(name) + " OpenSSL decrypt roundtrip").c_str());

    // OpenSSL 解密 jpssl 密文前 n 字节
    EVP_CIPHER_CTX* dec2 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(dec2, 0);
    std::vector<uint8_t> opt2(n);
    ossl_cipher_dec(ciph, key, iv, jct.data(), n, opt2.data(), dec2);
    EVP_CIPHER_CTX_free(dec2);
    ok = opt2 == pt;
    check(ok, (std::string(name) + " OpenSSL decrypts jpssl ct").c_str());
    return ok;
}

// ── CBC 基准: jpssl sw/aesni (PKCS7 填充) vs OpenSSL (padding=0) ──
template <typename E, typename D>
static void bench_block(const char* algo, size_t size,
                        const aes_context& ctx,
                        const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
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
        ossl_cipher_enc(ciph, key, iv, pt.data(), size, oct.data(), c_enc);
        g_sink ^= oct[0];
    }, target_ms, rounds);
    record(algo_e, "openssl", size, nse);
    nsd = auto_bench([&] {
        ossl_cipher_dec(ciph, key, iv, oct.data(), size, opt.data(), c_dec);
        g_sink ^= opt[0];
    }, target_ms, rounds);
    record(algo_d, "openssl", size, nsd);
    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// ── main ────────────────────────────────────────────────────────
int main() {
    auto feats = jpssl::cpu_features::detect();
    printf("=== bench_aes_cbc: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("CPU features: AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES+VPCLMULQDQ=%d SHA-NI=%d\n",
           (int)feats.aesni, (int)feats.avx2, (int)feats.pclmulqdq,
           (int)feats.avx512, (int)feats.vpclmulqdq_vaes, (int)feats.sha_ni);
    if (feats.avx512) printf("  WARNING: AVX512 available on this host\n");

    // 准备 OpenSSL 上下文 (仅确保 OpenSSL 库初始化)
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    const bool smoke = [] {
        const char* e = std::getenv("BENCH_SMOKE");
        return e != nullptr && std::string(e) == "1";
    }();
    std::vector<size_t> sizes = smoke ? std::vector<size_t>{16, 256} : g_sizes;
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;
    printf("Mode: %s (%zu sizes, %.0fms/round, %d round%s)\n",
           smoke ? "SMOKE" : "FULL", sizes.size(), target_ms, rounds,
           rounds > 1 ? "s" : "");

    aes_context ctx128, ctx256;
    ctx128.init(K16);
    ctx256.init(K32);

    // ── 自检 (先于基准, 始终覆盖全部长度档位, 全 PASS 才继续) ──
    printf("\n=== Correctness self-checks (jpssl <-> OpenSSL) ===\n");
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_cbc() : EVP_aes_128_cbc();
        const char* kn = keysz ? "aes-256-cbc" : "aes-128-cbc";

        for (size_t n : g_sizes) {
            char nm[80];
            std::snprintf(nm, sizeof(nm), "%s/sw@%zu", kn, n);
            validate_block_padded(nm, n,
                                  [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                                      jpssl::aes_cbc_encrypt_sw(ctx, IV16.data(), p, c);
                                  },
                                  [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                                      return jpssl::aes_cbc_decrypt_sw(ctx, IV16.data(), c, p);
                                  },
                                  ciph, key, IV16.data());
            std::snprintf(nm, sizeof(nm), "%s/aesni@%zu", kn, n);
            validate_block_padded(nm, n,
                                  [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                                      jpssl::aes_cbc_encrypt_aesni(ctx, IV16.data(), p, c);
                                  },
                                  [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                                      return jpssl::aes_cbc_decrypt_aesni(ctx, IV16.data(), c, p);
                                  },
                                  ciph, key, IV16.data());
        }
    }

    if (!g_all_pass) {
        printf("\nSelf-check FAILED — aborting benchmark (exit 1)\n");
        return 1;
    }
    printf("All self-checks passed (%d checks)\n", g_checks);

    // ── 基准 ──
    printf("\n=== Benchmarks (%s: %.0fms/round, %d round%s) ===\n",
           smoke ? "SMOKE" : "FULL", target_ms, rounds, rounds > 1 ? "s" : "");
    printf("%-26s %-12s %9s %12s %12s\n", "algo", "impl", "size", "ns/op", "MB/s");

    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_cbc() : EVP_aes_128_cbc();
        char algo[64];
        std::snprintf(algo, sizeof(algo), "%s", keysz ? "aes-256-cbc" : "aes-128-cbc");
        for (size_t s : sizes) {
            bench_block(algo, s, ctx, ciph, key, IV16.data(),
                        [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                            jpssl::aes_cbc_encrypt_sw(ctx, IV16.data(), p, c);
                        },
                        [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                            return jpssl::aes_cbc_decrypt_sw(ctx, IV16.data(), c, p);
                        },
                        "jpssl-sw", target_ms, rounds);
            bench_block(algo, s, ctx, ciph, key, IV16.data(),
                        [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                            jpssl::aes_cbc_encrypt_aesni(ctx, IV16.data(), p, c);
                        },
                        [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                            return jpssl::aes_cbc_decrypt_aesni(ctx, IV16.data(), c, p);
                        },
                        "jpssl-aesni", target_ms, rounds);
        }
    }

    // ── 写 CSV ──
    std::filesystem::path csv_dir = std::filesystem::path("benchmarks") / "results";
    std::error_code ec;
    std::filesystem::create_directories(csv_dir, ec);
    std::string csv_path = (csv_dir / "bench_aes_cbc.csv").string();
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
