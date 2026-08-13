// bench_aes_gcm.cpp — AES-GCM (AES-128/256, AEAD, IV 12B, tag 16B) 全量微基准
//
// 覆盖:
//   AES-128/256-GCM 加密/解密 : jpssl sw / aesni / avx2 / vaes / avx512 / auto
//                               vs OpenSSL (EVP_aes_128_gcm / EVP_aes_256_gcm, IV 12B)
//
// 结构复用自 benchmarks/bench_sym_multi.cpp 的 GCM 部分 (GcmImpl 表、
// validate_gcm_impl 交叉验证含篡改检测、bench_gcm、auto_bench、CSV record),
// 拆出 GCM 细化:
//   - 正确性自检固定 256B 与 1MB 两档 (自检始终全档位, 与 smoke 无关)。
//   - 性能基准: 默认 5 档长度 {16,256,4096,65536,1048576}、~150ms、3 轮取最小;
//     BENCH_SMOKE=1 时只测 {16,256}、~80ms、1 轮。
//   - 运行时 CPU 特性检测; 不支持的实现仅打印 SKIP, 绝不调用
//     (本机无 AVX512, 直接调用 avx512 变体会 SIGILL)。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_aes_gcm.cpp
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto -o /tmp/bench_aes_gcm
//
// 运行:
//   BENCH_SMOKE=1 /tmp/bench_aes_gcm    # smoke: 2 档长度, 快速
//   /tmp/bench_aes_gcm                  # 全量: 5 档长度
//
// 输出:
//   benchmarks/results/bench_aes_gcm.csv (列头 algo,impl,size_bytes,ns_per_op,throughput_mbps)

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
#include <cstdlib>
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
// IV 12B (GCM 推荐)
static const std::array<uint8_t, 12> IV12 = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b};

// 消息长度矩阵 (均为 16 的倍数)
static const std::vector<size_t> g_sizes_full = {16, 256, 4096, 65536, 1048576};
static const std::vector<size_t> g_sizes_smoke = {16, 256};
static const std::vector<size_t> g_sizes_check = {256, 1048576};

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
static double auto_bench(F&& f, double target_ms = 150.0, int rounds = 3) {
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
};
static std::vector<Row> g_rows;
static bool g_all_pass = true;

static void record(const char* algo, const char* impl, size_t size, double ns) {
    double mbps = size / ns * 1000.0;  // bytes/ns * 1000 = MB/s
    g_rows.push_back({algo, impl, size, ns, mbps});
    printf("%-26s %-12s %9zu %12.1f %12.1f\n", algo, impl, size, ns, mbps);
}

static void record_skip(const char* algo, const char* impl, size_t size, const char* why) {
    printf("%-26s %-12s %9zu SKIP (%s)\n", algo, impl, size, why);
}

// ── 自检辅助 ────────────────────────────────────────────────────
static int g_checks = 0;

static bool check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) g_all_pass = false;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    return ok;
}

// ── OpenSSL GCM 封装 ────────────────────────────────────────────

// GCM 加密 (AAD 可为空), tag 16B
static void ossl_gcm_enc(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                         const std::vector<uint8_t>& pt, const std::vector<uint8_t>& aad,
                         std::vector<uint8_t>& ct, uint8_t tag[16], EVP_CIPHER_CTX* ctx) {
    EVP_EncryptInit_ex(ctx, ciph, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    int outl = 0;
    if (!aad.empty())
        EVP_EncryptUpdate(ctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size()));
    ct.resize(pt.size());
    EVP_EncryptUpdate(ctx, ct.data(), &outl, pt.data(), static_cast<int>(pt.size()));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, ct.data() + outl, &fin);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
}

// GCM 解密; 返回 tag 是否通过
static bool ossl_gcm_dec(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                         const std::vector<uint8_t>& ct, const std::vector<uint8_t>& aad,
                         const uint8_t tag[16], std::vector<uint8_t>& pt,
                         EVP_CIPHER_CTX* ctx) {
    EVP_DecryptInit_ex(ctx, ciph, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag));
    int outl = 0;
    if (!aad.empty())
        EVP_DecryptUpdate(ctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size()));
    pt.resize(ct.size());
    EVP_DecryptUpdate(ctx, pt.data(), &outl, ct.data(), static_cast<int>(ct.size()));
    int fin = 0;
    return EVP_DecryptFinal_ex(ctx, pt.data() + outl, &fin) == 1;
}

// ── GCM 专用交叉验证 (含 OpenSSL 字节级对比) ────────────────────
struct GcmImpl {
    const char* impl;
    void (*enc)(const aes_context&, const uint8_t*, size_t, std::span<const uint8_t>,
                std::span<const uint8_t>, std::vector<uint8_t>&, uint8_t*, size_t);
    bool (*dec)(const aes_context&, const uint8_t*, size_t, std::span<const uint8_t>,
                std::span<const uint8_t>, const uint8_t*, size_t, std::vector<uint8_t>&);
};

static bool validate_gcm_impl(const char* name, const aes_context& ctx, const EVP_CIPHER* ciph,
                              const uint8_t* key, size_t n, const GcmImpl& gi) {
    std::vector<uint8_t> pt, aad, jct, oct, p2, p3, bct;
    uint8_t jtag[16] = {0}, otag[16] = {0};
    fill_test(pt, n, 0x0A55C0DE);

    gi.enc(ctx, IV12.data(), IV12.size(), pt, aad, jct, jtag, 16);

    EVP_CIPHER_CTX* ctxo = EVP_CIPHER_CTX_new();
    ossl_gcm_enc(ciph, key, IV12.data(), pt, aad, oct, otag, ctxo);

    bool ok = jct == oct && std::memcmp(jtag, otag, 16) == 0;
    check(ok, (std::string(name) + " ct+tag == OpenSSL").c_str());

    // jpssl 解密 OpenSSL 密文
    bool d1 = gi.dec(ctx, IV12.data(), IV12.size(), oct, aad, otag, 16, p2);
    ok = d1 && p2 == pt;
    check(ok, (std::string(name) + " jpssl decrypts OpenSSL ct").c_str());

    // OpenSSL 解密 jpssl 密文
    bool o1 = ossl_gcm_dec(ciph, key, IV12.data(), jct, aad, jtag, p3, ctxo);
    ok = o1 && p3 == pt;
    check(ok, (std::string(name) + " OpenSSL decrypts jpssl ct").c_str());

    // 篡改 tag → jpssl 拒绝
    uint8_t bad_tag[16];
    std::memcpy(bad_tag, jtag, 16);
    bad_tag[5] ^= 0x80;
    std::vector<uint8_t> p4;
    ok = !gi.dec(ctx, IV12.data(), IV12.size(), jct, aad, bad_tag, 16, p4);
    check(ok, (std::string(name) + " rejects tampered tag").c_str());

    // 篡改密文 → OpenSSL 拒绝
    bct = jct;
    bct[0] ^= 0x40;
    std::vector<uint8_t> p5;
    ok = !ossl_gcm_dec(ciph, key, IV12.data(), bct, aad, jtag, p5, ctxo);
    check(ok, (std::string(name) + " OpenSSL rejects tampered ct").c_str());
    EVP_CIPHER_CTX_free(ctxo);
    return ok;
}

// ── GCM 基准入口 ────────────────────────────────────────────────
static void bench_gcm(const char* algo, size_t size,
                      const aes_context& ctx, const EVP_CIPHER* ciph, const uint8_t* key,
                      const jpssl::cpu_features& feats,
                      double target_ms, int rounds) {
    std::vector<uint8_t> pt, aad, jct, jpt;
    uint8_t jtag[16] = {0};
    fill_test(pt, size, 0x6C0C);

    char algo_e[64], algo_d[64];
    std::snprintf(algo_e, sizeof(algo_e), "%s-enc", algo);
    std::snprintf(algo_d, sizeof(algo_d), "%s-dec", algo);

    struct GcmRow {
        const char* impl;
        void (*enc)(const aes_context&, const uint8_t*, size_t, std::span<const uint8_t>,
                    std::span<const uint8_t>, std::vector<uint8_t>&, uint8_t*, size_t);
        bool (*dec)(const aes_context&, const uint8_t*, size_t, std::span<const uint8_t>,
                    std::span<const uint8_t>, const uint8_t*, size_t, std::vector<uint8_t>&);
        bool gate;
        const char* skip_why;
    };
    const std::vector<GcmRow> rows = {
        {"jpssl-sw", jpssl::aes_gcm_encrypt_sw, jpssl::aes_gcm_decrypt_sw, true, ""},
        {"jpssl-aesni", jpssl::aes_gcm_encrypt_aesni, jpssl::aes_gcm_decrypt_aesni, true, ""},
        {"jpssl-avx2", jpssl::aes_gcm_encrypt_avx2, jpssl::aes_gcm_decrypt_avx2, feats.avx2, "no AVX2"},
#if defined(__x86_64__) && defined(JP_VAES)
        {"jpssl-vaes", jpssl::aes_gcm_encrypt_vaes, jpssl::aes_gcm_decrypt_vaes, feats.vpclmulqdq_vaes, "no VAES/VPCLMULQDQ"},
#endif
#if defined(JP_AVX512)
        {"jpssl-avx512", jpssl::aes_gcm_encrypt_avx512, jpssl::aes_gcm_decrypt_avx512, feats.avx512, "no AVX512 (SIGILL if called; never called)"},
#endif
        {"jpssl-auto", jpssl::aes_gcm_encrypt_auto, jpssl::aes_gcm_decrypt_auto, true, ""},
    };

    for (const auto& r : rows) {
        if (!r.gate) {
            record_skip(algo_e, r.impl, size, r.skip_why);
            record_skip(algo_d, r.impl, size, r.skip_why);
            continue;
        }
        jct.clear();
        r.enc(ctx, IV12.data(), IV12.size(), pt, aad, jct, jtag, 16);
        double nse = auto_bench([&] {
            r.enc(ctx, IV12.data(), IV12.size(), pt, aad, jct, jtag, 16);
            g_sink ^= jct[0] ^ jtag[0];
        }, target_ms, rounds);
        record(algo_e, r.impl, size, nse);

        double nsd = auto_bench([&] {
            bool ok2 = r.dec(ctx, IV12.data(), IV12.size(), jct, aad, jtag, 16, jpt);
            g_sink ^= (int)ok2 ^ jpt[0];
        }, target_ms, rounds);
        record(algo_d, r.impl, size, nsd);
    }

    // OpenSSL 对照
    EVP_CIPHER_CTX* c_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* c_dec = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> oct, opt;
    uint8_t otag[16] = {0};
    ossl_gcm_enc(ciph, key, IV12.data(), pt, aad, oct, otag, c_enc);
    double nse = auto_bench([&] {
        ossl_gcm_enc(ciph, key, IV12.data(), pt, aad, oct, otag, c_enc);
        g_sink ^= oct[0] ^ otag[0];
    }, target_ms, rounds);
    record(algo_e, "openssl", size, nse);

    double nsd = auto_bench([&] {
        bool ok2 = ossl_gcm_dec(ciph, key, IV12.data(), oct, aad, otag, opt, c_dec);
        g_sink ^= (int)ok2 ^ opt[0];
    }, target_ms, rounds);
    record(algo_d, "openssl", size, nsd);
    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// ── main ────────────────────────────────────────────────────────
int main() {
    const bool smoke = std::getenv("BENCH_SMOKE") != nullptr;
    const std::vector<size_t> sizes = smoke ? g_sizes_smoke : g_sizes_full;
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;

    auto feats = jpssl::cpu_features::detect();
    printf("=== bench_aes_gcm: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("mode=%s sizes=%zu target_ms=%.0f rounds=%d\n",
           smoke ? "SMOKE" : "FULL", sizes.size(), target_ms, rounds);
    printf("CPU features: AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES+VPCLMULQDQ=%d SHA-NI=%d\n",
           (int)feats.aesni, (int)feats.avx2, (int)feats.pclmulqdq,
           (int)feats.avx512, (int)feats.vpclmulqdq_vaes, (int)feats.sha_ni);
    if (!feats.avx512) printf("  NOTE: AVX512 unavailable on this host — jpssl-avx512 will SKIP (never called)\n");

    // 准备 OpenSSL 上下文 (仅确保 OpenSSL 库初始化)
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    aes_context ctx128, ctx256;
    ctx128.init(K16);
    ctx256.init(K32);

    // ── 自检 (先于基准, 始终全档位 256B 与 1MB, 全 PASS 才继续) ──
    printf("\n=== Correctness self-checks (jpssl <-> OpenSSL, tag 16B, AAD empty) ===\n");
    const GcmImpl gcm_impls[] = {
        {"sw", jpssl::aes_gcm_encrypt_sw, jpssl::aes_gcm_decrypt_sw},
        {"aesni", jpssl::aes_gcm_encrypt_aesni, jpssl::aes_gcm_decrypt_aesni},
        {"avx2", jpssl::aes_gcm_encrypt_avx2, jpssl::aes_gcm_decrypt_avx2},
#if defined(__x86_64__) && defined(JP_VAES)
        {"vaes", jpssl::aes_gcm_encrypt_vaes, jpssl::aes_gcm_decrypt_vaes},
#endif
#if defined(JP_AVX512)
        {"avx512", jpssl::aes_gcm_encrypt_avx512, jpssl::aes_gcm_decrypt_avx512},
#endif
        {"auto", jpssl::aes_gcm_encrypt_auto, jpssl::aes_gcm_decrypt_auto},
    };
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
        const char* kn = keysz ? "aes-256-gcm" : "aes-128-gcm";
        for (const auto& gi : gcm_impls) {
            if (std::string(gi.impl) == "avx2" && !feats.avx2) {
                printf("  [SKIP] %s/%s: no AVX2\n", kn, gi.impl);
                continue;
            }
            if (std::string(gi.impl) == "vaes" && !feats.vpclmulqdq_vaes) {
                printf("  [SKIP] %s/%s: no VAES/VPCLMULQDQ\n", kn, gi.impl);
                continue;
            }
            if (std::string(gi.impl) == "avx512" && !feats.avx512) {
                printf("  [SKIP] %s/%s: no AVX512 (never called)\n", kn, gi.impl);
                continue;
            }
            for (size_t n : g_sizes_check) {
                char nm[80];
                std::snprintf(nm, sizeof(nm), "%s/%s@%zu", kn, gi.impl, n);
                validate_gcm_impl(nm, ctx, ciph, key, n, gi);
            }
        }
    }

    if (!g_all_pass) {
        printf("\nSelf-checks FAILED (%d checks, some FAIL). Aborting before benchmark.\n", g_checks);
        return 1;
    }
    printf("Self-checks: %d checks, all PASS.\n", g_checks);

    // ── 性能基准 ────────────────────────────────────────────────
    printf("\n=== Benchmark (ns/op, MB/s) ===\n");
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
        char algo[64];
        std::snprintf(algo, sizeof(algo), "%s", keysz ? "aes-256-gcm" : "aes-128-gcm");
        for (size_t s : sizes) bench_gcm(algo, s, ctx, ciph, key, feats, target_ms, rounds);
    }

    // ── 写 CSV (SKIP 的实现不入 CSV) ────────────────────────────
    std::filesystem::path csv_dir = std::filesystem::path("benchmarks") / "results";
    std::error_code ec;
    std::filesystem::create_directories(csv_dir, ec);
    std::string csv_path = (csv_dir / "bench_aes_gcm.csv").string();
    {
        std::ofstream f(csv_path);
        f << "algo,impl,size_bytes,ns_per_op,throughput_mbps\n";
        for (const auto& r : g_rows) {
            f << r.algo << ',' << r.impl << ',' << r.size << ','
              << r.ns << ',' << r.mbps << '\n';
        }
    }
    printf("\nCSV written to %s (%zu data rows)\n", csv_path.c_str(), g_rows.size());
    printf("Done. All self-checks passed, exit 0.\n");
    (void)g_sink;
    return 0;
}
