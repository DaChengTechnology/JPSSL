// bench_chacha20.cpp — ChaCha20-Poly1305 (AEAD) 全量测试: 实现路径 × 多长度 × OpenSSL 对比
//
// 覆盖:
//   AEAD (key 32B / nonce 12B / tag 16B / AAD 空):
//     jpssl  chacha20_poly1305_encrypt / decrypt  (公开接口, 内部自动分派 SIMD)
//     openssl EVP_chacha20_poly1305
//   流加密 (非 AEAD, 对称 XOR):
//     jpssl      chacha20_crypt          (公开默认入口; 内部运行时检测自动分派
//                                          AVX512→AVX2→NEON→标量; 本机无 AVX512,
//                                         故执行 AVX2 路径 — 见下方语义注记)
//     jpssl-avx2 chacha20_crypt_avx2     (强制 AVX2 实现)
//     jpssl-avx512 chacha20_crypt_avx512 (仅 cpu_has_avx512() 时调用, 否则 SKIP)
//     openssl    EVP_chacha20            (16B IV = [LE32(counter)||nonce12],
//                                         与 jpssl counter+nonce12 布局对齐)
//
// 语义注记: 库内 chacha20_poly1305_encrypt/decrypt 直接调用 chacha20_crypt_feed_poly
//   (AEAD 路径), 内部再按运行时 CPU 特性分派 chacha20_crypt_avx512/avx2/neon/标量,
//   公开 API 无法强制指定某个流实现; 因此流加密按"公开入口 + 直接调用各 SIMD 实现"
//   分别测量: impl jpssl = chacha20_crypt (自动分派), jpssl-avx2 / jpssl-avx512 为
//   强制实现。标量实现是 chacha20_crypt 的回退路径, 无独立公开符号, 故不单独成行。
//
// 正确性自检 (始终覆盖全部 5 档长度, 与 BENCH_SMOKE 无关):
//   - AEAD: jpssl 与 OpenSSL 交叉验证 (ct+tag 逐字节一致 / 双向解密往返 /
//     篡改 tag 与篡改 ct 均被拒绝); 任一 FAIL → 非零退出
//   - 流加密: chacha20_crypt 与 avx2/avx512 输出互比一致, 并与 OpenSSL chacha20 流对齐
// 性能基准:
//   全量: 16/256/4096/65536/1048576, ~150ms/轮, 3 轮取最小
//   BENCH_SMOKE=1: 仅 16/256, ~80ms/轮, 1 轮
// 输出: benchmarks/results/bench_chacha20.csv (algo,impl,size_bytes,ns_per_op,throughput_mbps)
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_chacha20.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_chacha20

#include "chacha20_poly1305.hpp"
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

using Clock = std::chrono::steady_clock;

// 阻止编译器把输出缓冲区相关调用折叠/消除
static volatile int g_sink = 0;

// ── 固定测试数据 ────────────────────────────────────────────────
static const std::array<uint8_t, 32> K32 = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
static const std::array<uint8_t, 12> IV12 = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b};

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

// ── OpenSSL 基础封装 ────────────────────────────────────────────

// ChaCha20-Poly1305 加密 (AAD 可为空)
static void ossl_ccp_enc(const uint8_t key[32], const uint8_t nonce[12],
                         const std::vector<uint8_t>& pt, const std::vector<uint8_t>& aad,
                         std::vector<uint8_t>& ct, uint8_t tag[16], EVP_CIPHER_CTX* ctx) {
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce);
    int outl = 0;
    if (!aad.empty())
        EVP_EncryptUpdate(ctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size()));
    ct.resize(pt.size());
    EVP_EncryptUpdate(ctx, ct.data(), &outl, pt.data(), static_cast<int>(pt.size()));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, ct.data() + outl, &fin);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
}

// ChaCha20-Poly1305 解密; 返回 tag 是否通过
static bool ossl_ccp_dec(const uint8_t key[32], const uint8_t nonce[12],
                         const std::vector<uint8_t>& ct, const std::vector<uint8_t>& aad,
                         const uint8_t tag[16], std::vector<uint8_t>& pt,
                         EVP_CIPHER_CTX* ctx) {
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag));
    int outl = 0;
    if (!aad.empty())
        EVP_DecryptUpdate(ctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size()));
    pt.resize(ct.size());
    EVP_DecryptUpdate(ctx, pt.data(), &outl, ct.data(), static_cast<int>(ct.size()));
    int fin = 0;
    return EVP_DecryptFinal_ex(ctx, pt.data() + outl, &fin) == 1;
}

// ChaCha20 流加密 (OpenSSL): 16B IV = [LE32(counter) || nonce12],
// 与 jpssl chacha20_crypt(key, counter, nonce12) 的 keystream 布局逐字节对齐
// (已验证: 该构造对 RFC 8439 §2.3.2 测试向量与 jpssl 输出一致)
static void ossl_chacha20_stream(const uint8_t key[32], uint32_t counter,
                                 const uint8_t nonce[12],
                                 std::span<const uint8_t> in, std::span<uint8_t> out,
                                 EVP_CIPHER_CTX* ctx) {
    uint8_t ivec[16];
    ivec[0] = static_cast<uint8_t>(counter & 0xff);
    ivec[1] = static_cast<uint8_t>((counter >> 8) & 0xff);
    ivec[2] = static_cast<uint8_t>((counter >> 16) & 0xff);
    ivec[3] = static_cast<uint8_t>((counter >> 24) & 0xff);
    std::memcpy(ivec + 4, nonce, 12);
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key, ivec);
    int outl = 0;
    EVP_EncryptUpdate(ctx, out.data(), &outl, in.data(), static_cast<int>(in.size()));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, out.data() + outl, &fin);
}

// ── 自检辅助 ────────────────────────────────────────────────────
static int g_checks = 0;
static int g_pass = 0;

static bool check(bool ok, const char* what) {
    ++g_checks;
    if (ok) ++g_pass; else g_all_pass = false;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    return ok;
}

// ── 正确性自检: AEAD (jpssl 公开接口) × OpenSSL, 单档位 ──────────
static void validate_ccp(size_t n) {
    std::vector<uint8_t> pt, aad, jct, oct, p2, p3, bct;
    uint8_t jtag[16] = {0}, otag[16] = {0};
    fill_test(pt, n, 0xC1A0520);
    char nm[96];
    std::snprintf(nm, sizeof(nm), "chacha20-poly1305/jpssl@%zu", n);

    jpssl::chacha20_poly1305_encrypt(K32.data(), IV12.data(), pt, aad, jct, jtag);

    EVP_CIPHER_CTX* ctxo = EVP_CIPHER_CTX_new();
    ossl_ccp_enc(K32.data(), IV12.data(), pt, aad, oct, otag, ctxo);

    bool ok = jct == oct && std::memcmp(jtag, otag, 16) == 0;
    check(ok, (std::string(nm) + " ct+tag == OpenSSL").c_str());

    // jpssl 解密 OpenSSL 密文
    bool d1 = jpssl::chacha20_poly1305_decrypt(K32.data(), IV12.data(), oct, aad, otag, p2);
    ok = d1 && p2 == pt;
    check(ok, (std::string(nm) + " jpssl decrypts OpenSSL ct").c_str());

    // OpenSSL 解密 jpssl 密文
    bool o1 = ossl_ccp_dec(K32.data(), IV12.data(), jct, aad, jtag, p3, ctxo);
    ok = o1 && p3 == pt;
    check(ok, (std::string(nm) + " OpenSSL decrypts jpssl ct").c_str());

    // 篡改 tag → jpssl 拒绝
    uint8_t bad_tag[16];
    std::memcpy(bad_tag, jtag, 16);
    bad_tag[7] ^= 0x02;
    std::vector<uint8_t> p4;
    ok = !jpssl::chacha20_poly1305_decrypt(K32.data(), IV12.data(), jct, aad, bad_tag, p4);
    check(ok, (std::string(nm) + " jpssl rejects tampered tag").c_str());

    // 篡改密文 → OpenSSL 拒绝
    bct = jct;
    bct[0] ^= 0x08;
    std::vector<uint8_t> p5;
    ok = !ossl_ccp_dec(K32.data(), IV12.data(), bct, aad, jtag, p5, ctxo);
    check(ok, (std::string(nm) + " OpenSSL rejects tampered ct").c_str());
    EVP_CIPHER_CTX_free(ctxo);
}

// ── 正确性自检: 流加密多实现互比 + OpenSSL 对齐, 单档位 ─────────
// 加密与解密同为 XOR, 语义对称; 此处统一以 counter=1 (AEAD 实际使用值) 加密明文
static void validate_stream(size_t n) {
    std::vector<uint8_t> pt, o0, o1, o2, o3;
    fill_test(pt, n, 0xC1A0521);
    char nm[96];
    std::snprintf(nm, sizeof(nm), "chacha20-stream/jpssl@%zu", n);
    bool ok;

    o0.resize(n);
    jpssl::chacha20_crypt(K32.data(), 1, IV12.data(), pt, o0);  // 公开默认入口

    if (jpssl::cpu_has_avx2()) {
        o1.resize(n);
        jpssl::chacha20_crypt_avx2(K32.data(), 1, IV12.data(), pt, o1);
        ok = o0 == o1;
        check(ok, (std::string(nm) + " avx2 == default").c_str());
    } else {
        printf("  [SKIP] %s avx2 (no AVX2)\n", nm);
    }

    if (jpssl::cpu_has_avx512()) {
        o2.resize(n);
        jpssl::chacha20_crypt_avx512(K32.data(), 1, IV12.data(), pt, o2);
        ok = o0 == o2;
        check(ok, (std::string(nm) + " avx512 == default").c_str());
    } else {
        printf("  [SKIP] %s avx512 (no AVX512, never called)\n", nm);
    }

    // 与 OpenSSL chacha20 流对齐 (16B IV = [LE32(counter)||nonce12])
    o3.resize(n);
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    ossl_chacha20_stream(K32.data(), 1, IV12.data(), pt, o3, c);
    ok = o0 == o3;
    check(ok, (std::string(nm) + " == OpenSSL chacha20 stream").c_str());
    EVP_CIPHER_CTX_free(c);
}

// ── 性能基准: 单档位, 全部实现路径 ──────────────────────────────
static void bench_ccp(size_t size, double target_ms, int rounds) {
    std::vector<uint8_t> pt, aad, jct, jpt, oct, opt, stream_out;
    uint8_t jtag[16] = {0}, otag[16] = {0};
    fill_test(pt, size, 0xC1C1A);
    stream_out.resize(size);
    const char* algo_e = "chacha20-poly1305-enc";
    const char* algo_d = "chacha20-poly1305-dec";
    const char* algo_s = "chacha20-stream";

    // ── AEAD: jpssl 公开接口 (内部自动分派) ──
    jpssl::chacha20_poly1305_encrypt(K32.data(), IV12.data(), pt, aad, jct, jtag);
    double nse = auto_bench(
        [&] { jpssl::chacha20_poly1305_encrypt(K32.data(), IV12.data(), pt, aad, jct, jtag);
              g_sink ^= jct[0] ^ jtag[0]; }, target_ms, rounds);
    record(algo_e, "jpssl", size, nse);
    double nsd = auto_bench(
        [&] { bool ok2 = jpssl::chacha20_poly1305_decrypt(K32.data(), IV12.data(), jct, aad, jtag, jpt);
              g_sink ^= (int)ok2 ^ jpt[0]; }, target_ms, rounds);
    record(algo_d, "jpssl", size, nsd);

    // ── 流加密: jpssl 公开默认入口 chacha20_crypt (自动分派; 本机=AVX2) ──
    nse = auto_bench(
        [&] { jpssl::chacha20_crypt(K32.data(), 1, IV12.data(), pt, stream_out);
              g_sink ^= stream_out[0]; }, target_ms, rounds);
    record(algo_s, "jpssl", size, nse);

    // ── 流加密: jpssl AVX2 强制实现 ──
    if (jpssl::cpu_has_avx2()) {
        nse = auto_bench(
            [&] { jpssl::chacha20_crypt_avx2(K32.data(), 1, IV12.data(), pt, stream_out);
                  g_sink ^= stream_out[0]; }, target_ms, rounds);
        record(algo_s, "jpssl-avx2", size, nse);
    } else {
        record_skip(algo_s, "jpssl-avx2", size, "no AVX2");
    }

    // ── 流加密: jpssl AVX512 强制实现 (不支持 → SKIP, 绝不调用) ──
    if (jpssl::cpu_has_avx512()) {
        nse = auto_bench(
            [&] { jpssl::chacha20_crypt_avx512(K32.data(), 1, IV12.data(), pt, stream_out);
                  g_sink ^= stream_out[0]; }, target_ms, rounds);
        record(algo_s, "jpssl-avx512", size, nse);
    } else {
        record_skip(algo_s, "jpssl-avx512", size, "no AVX512");
    }

    // ── AEAD: OpenSSL 对照 ──
    EVP_CIPHER_CTX* c_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* c_dec = EVP_CIPHER_CTX_new();
    ossl_ccp_enc(K32.data(), IV12.data(), pt, aad, oct, otag, c_enc);
    nse = auto_bench(
        [&] { ossl_ccp_enc(K32.data(), IV12.data(), pt, aad, oct, otag, c_enc);
              g_sink ^= oct[0] ^ otag[0]; }, target_ms, rounds);
    record(algo_e, "openssl", size, nse);
    nsd = auto_bench(
        [&] { bool ok2 = ossl_ccp_dec(K32.data(), IV12.data(), oct, aad, otag, opt, c_dec);
              g_sink ^= (int)ok2 ^ opt[0]; }, target_ms, rounds);
    record(algo_d, "openssl", size, nsd);

    // ── 流加密: OpenSSL chacha20 对照 ──
    nse = auto_bench(
        [&] { ossl_chacha20_stream(K32.data(), 1, IV12.data(), pt, stream_out, c_enc);
              g_sink ^= stream_out[0]; }, target_ms, rounds);
    record(algo_s, "openssl", size, nse);

    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// ── main ────────────────────────────────────────────────────────
int main() {
    const bool smoke = [] {
        const char* e = std::getenv("BENCH_SMOKE");
        return e != nullptr && *e != '\0' && std::string(e) != "0";
    }();

    auto feats = jpssl::cpu_features::detect();
    const bool have_avx2 = jpssl::cpu_has_avx2();
    const bool have_avx512 = jpssl::cpu_has_avx512();

    printf("=== bench_chacha20: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("CPU features: AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES+VPCLMULQDQ=%d SHA-NI=%d\n",
           (int)feats.aesni, (int)feats.avx2, (int)feats.pclmulqdq,
           (int)feats.avx512, (int)feats.vpclmulqdq_vaes, (int)feats.sha_ni);
    printf("mode: %s (BENCH_SMOKE=%d), avx2=%d avx512=%d\n",
           smoke ? "smoke" : "full", (int)smoke, (int)have_avx2, (int)have_avx512);
    if (have_avx512) printf("  WARNING: AVX512 available on this host\n");

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    // ── 正确性自检 (始终全部 5 档, 与 smoke 无关) ──
    printf("\n=== Correctness self-checks (jpssl <-> OpenSSL, all sizes) ===\n");
    for (size_t n : g_sizes) validate_ccp(n);
    for (size_t n : g_sizes) validate_stream(n);

    if (!g_all_pass) {
        printf("\nSelf-check FAILED (%d/%d checks passed) — aborting benchmark (exit 1)\n",
               g_pass, g_checks);
        return 1;
    }
    printf("All self-checks passed (%d checks)\n", g_checks);

    // ── 性能基准 ──
    const std::vector<size_t> sizes = smoke ? std::vector<size_t>{16, 256} : g_sizes;
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;
    printf("\n=== Benchmarks (mode=%s, %.0fms/round, %d round(s), min) ===\n",
           smoke ? "smoke" : "full", target_ms, rounds);
    printf("%-26s %-12s %9s %12s %12s\n", "algo", "impl", "size", "ns/op", "MB/s");

    for (size_t s : sizes) bench_ccp(s, target_ms, rounds);

    // ── 写 CSV ──
    std::filesystem::path csv_dir = std::filesystem::path("benchmarks") / "results";
    std::error_code ec;
    std::filesystem::create_directories(csv_dir, ec);
    std::string csv_path = (csv_dir / "bench_chacha20.csv").string();
    size_t csv_rows = 0;
    {
        std::ofstream f(csv_path);
        if (!f) {
            printf("\nERROR: cannot write %s\n", csv_path.c_str());
            return 1;
        }
        f << "algo,impl,size_bytes,ns_per_op,throughput_mbps\n";
        for (const auto& r : g_rows) {
            if (r.skipped) continue;
            f << r.algo << ',' << r.impl << ',' << r.size << ','
              << r.ns << ',' << r.mbps << '\n';
            ++csv_rows;
        }
    }
    size_t skip_count = 0;
    for (const auto& r : g_rows) if (r.skipped) ++skip_count;
    printf("\nCSV written to %s (%zu data rows, %zu SKIP rows)\n",
           csv_path.c_str(), csv_rows, skip_count);
    if (!have_avx512) printf("AVX512: not supported on this host — SKIP (never called)\n");
    printf("Done. All self-checks passed (%d), exit 0.\n", g_pass);
    return 0;
}
