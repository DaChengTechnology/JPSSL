// bench_x448.cpp - X448 ECDH 全量微基准: keygen / derive / full handshake / batch N=1000
//
// 多实现 × OpenSSL 对比:
//   jpssl              单次公开 API (x448_generate_keypair / x448_scalar_mult)
//   jpssl-batch        x448_scalar_mult_batch (运行时自动派发: AVX512=8 / AVX2=4 / scalar=1)
//   jpssl-batch-avx2   显式 AVX2 变体 (CPU 无 AVX2 → SKIP, 绝不调用)
//   jpssl-batch-avx512 显式 AVX512 变体 (CPU 无 AVX512 → SKIP, 用 jpssl::cpu_has_avx512()
//                      检测, 不支持打印 SKIP 绝不调用——本机调用会 SIGILL)
//   openssl           EVP_PKEY raw keygen + derive
//
// 正确性自检 (始终执行, 任一 FAIL 非零退出):
//   * jpssl × openssl 交叉验证共享密钥一致 (双向: 各自 priv × 对方 pub)
//   * 批量每 op 与单次一致 (dispatch / avx2 / avx512 变体分别逐字节核对)
//
// 全量 vs smoke: 环境变量 BENCH_SMOKE=1 → 每 op 目标迭代减半 (75ms/轮) + 1 轮;
//                未设置               → ~150ms/轮, 3 轮取最小。自检不受影响, 始终执行。
//
// 编译 (worktree 根执行):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES \
//       -Iinclude -Isrc benchmarks/bench_x448.cpp \
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto \
//       -o /tmp/bench_x448
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_x448.csv
//       CSV 列头固定: algo,impl,size_bytes,ns_per_op,ops_per_sec
//       (algo 含操作种类: x448-keygen / x448-derive / x448-full / x448-batch;
//        size_bytes = 56, X448 共享密钥/私钥字节数)

#include "cpu_features.hpp"
#include "x448.hpp"

#include <openssl/evp.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <vector>

using Clock = std::chrono::steady_clock;

// 阻止编译器把纯函数调用优化掉
static volatile int g_sink = 0;
static FILE* g_csv = nullptr;
static bool g_smoke = false;
static int g_selfcheck_pass = 0;
static int g_selfcheck_fail = 0;

static void csv_row(const char* algo, const char* impl, int size_bytes, double ns) {
    if (g_csv) fprintf(g_csv, "%s,%s,%d,%.1f,%.1f\n", algo, impl, size_bytes, ns, 1e9 / ns);
}

// 自适应微基准: 每轮约 target_ms, rounds 轮取最小 (参考 bench_ecdh_multi.cpp 风格;
// smoke 模式 target_ms 减半 → 迭代减半, 且只跑 1 轮)。
template <typename F>
static double auto_bench(const char* name, const char* algo, const char* impl, int size_bytes,
                         F&& f) {
    const double target_ms = g_smoke ? 75.0 : 150.0;
    const int rounds = g_smoke ? 1 : 3;
    f();
    int est_n = 8;
    auto t0 = Clock::now();
    for (int i = 0; i < est_n; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / est_n;
    if (est_ns < 1000.0) {
        int est_n2 = 2000;
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
    printf("%-36s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    csv_row(algo, impl, size_bytes, best);
    return best;
}

// 批量基准: 每次调用处理 items_per_call 条, 返回平均单条 ns。
template <typename F>
static double auto_bench_batch(const char* name, const char* algo, const char* impl,
                               int size_bytes, F&& f, int items_per_call) {
    const double target_ms = g_smoke ? 75.0 : 150.0;
    const int rounds = g_smoke ? 1 : 3;
    f();
    auto t0 = Clock::now();
    for (int i = 0; i < 8; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / 8.0;
    long long iters = 1;
    if (est_ns > 0.0) {
        iters = static_cast<long long>(target_ms * 1e6 / est_ns);
        if (iters < 1) iters = 1;
        if (iters > 200000) iters = 200000;
    }
    double best = 1e300;
    for (int r = 0; r < rounds; ++r) {
        auto s = Clock::now();
        for (long long i = 0; i < iters; ++i) f();
        auto e = Clock::now();
        double per = std::chrono::duration<double, std::nano>(e - s).count() / iters / items_per_call;
        if (per < best) best = per;
    }
    printf("%-36s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    csv_row(algo, impl, size_bytes, best);
    return best;
}

// ───────────────────────── OpenSSL raw (X448) ─────────────────────────

static EVP_PKEY* ossl_raw_priv(int evp_type, const uint8_t* priv, size_t len) {
    return EVP_PKEY_new_raw_private_key(evp_type, nullptr, priv, len);
}
static EVP_PKEY* ossl_raw_pub(int evp_type, const uint8_t* pub, size_t len) {
    return EVP_PKEY_new_raw_public_key(evp_type, nullptr, pub, len);
}

static bool ossl_raw_keygen(int evp_type, const char* name, uint8_t* priv, uint8_t* pub,
                            size_t len) {
    EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, name);
    if (!k) return false;
    size_t plen = len, slen = len;
    EVP_PKEY_get_raw_private_key(k, priv, &slen);
    EVP_PKEY_get_raw_public_key(k, pub, &plen);
    EVP_PKEY_free(k);
    return slen == len && plen == len;
}

// 使用已构造的 pkey 完成一次 derive (含 ctx 新建/初始化/设置 peer/derive)
static bool ossl_raw_derive_keys(EVP_PKEY* ours, EVP_PKEY* peer, size_t len, uint8_t* out) {
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new(ours, nullptr);
    bool ok = c && EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, peer) == 1;
    size_t olen = len;
    ok = ok && EVP_PKEY_derive(c, out, &olen) == 1 && olen == len;
    EVP_PKEY_CTX_free(c);
    return ok;
}

static bool ossl_raw_derive(int evp_type, const uint8_t* my_priv, const uint8_t* peer_pub,
                            size_t len, uint8_t* out) {
    EVP_PKEY* ours = ossl_raw_priv(evp_type, my_priv, len);
    EVP_PKEY* peer = ossl_raw_pub(evp_type, peer_pub, len);
    bool ok = ours && peer && ossl_raw_derive_keys(ours, peer, len, out);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(ours);
    return ok;
}

// ───────────────────────── 正确性自检 ─────────────────────────

static void record_check(const char* what, bool ok) {
    printf("%s: %s\n", what, ok ? "PASS" : "FAIL");
    if (ok) ++g_selfcheck_pass; else ++g_selfcheck_fail;
    if (!ok) g_sink ^= 0x448;
}

// 交叉验证: jpssl 私钥 × openssl 公钥, 双向同密钥
static bool selfcheck_x448() {
    uint8_t ja_priv[56], ja_pub[56], bo_priv[56], bo_pub[56];
    jpssl::x448_generate_keypair(ja_pub, ja_priv);
    bool ok = ossl_raw_keygen(EVP_PKEY_X448, "X448", bo_priv, bo_pub, 56);
    uint8_t ss_jp[56], ss_ossl[56], ss_jp2[56];
    jpssl::x448_scalar_mult(ss_jp, ja_priv, bo_pub);
    ok = ok && ossl_raw_derive(EVP_PKEY_X448, bo_priv, ja_pub, 56, ss_ossl);
    jpssl::x448_scalar_mult(ss_jp2, bo_priv, ja_pub);
    ok = ok && memcmp(ss_jp, ss_ossl, 56) == 0 && memcmp(ss_jp, ss_jp2, 56) == 0;
    record_check("X448 cross-check (jpssl priv × openssl pub, 双向同密钥)", ok);
    return ok;
}

// 批量正确性: dispatch / avx2 / avx512 变体逐字节 == 单次逐条结果
// (outs2d 为输出缓冲, 批量 API 需要非 const 写指针)
static bool selfcheck_x448_batch(uint8_t (*outs2d)[56],
                                 const std::vector<const uint8_t*>& sc,
                                 const std::vector<const uint8_t*>& pt, int bn) {
    std::vector<uint8_t> ref((size_t)bn * 56);
    for (int i = 0; i < bn; ++i)
        jpssl::x448_scalar_mult(ref.data() + (size_t)i * 56, sc[(size_t)i], pt[(size_t)i]);
    bool all = true;

    jpssl::x448_scalar_mult_batch(outs2d, sc.data(), pt.data(), bn);
    bool ok = memcmp(ref.data(), outs2d, (size_t)bn * 56) == 0;
    record_check("x448 batch(dispatch) == per-op", ok);
    all = all && ok;

    if (jpssl::cpu_has_avx2()) {
#if defined(JP_AVX2)
        jpssl::x448_scalar_mult_batch_avx2(outs2d, sc.data(), pt.data(), bn);
        ok = memcmp(ref.data(), outs2d, (size_t)bn * 56) == 0;
        record_check("x448 batch(avx2 显式) == per-op", ok);
        all = all && ok;
#else
        record_check("x448 batch(avx2 显式) == per-op", false);
        all = false;
#endif
    } else {
        printf("SKIP x448 batch avx2 显式变体自检: CPU 无 AVX2\n");
    }

    if (jpssl::cpu_has_avx512()) {
#if defined(JP_AVX512)
        jpssl::x448_scalar_mult_batch_avx512(outs2d, sc.data(), pt.data(), bn);
        ok = memcmp(ref.data(), outs2d, (size_t)bn * 56) == 0;
        record_check("x448 batch(avx512 显式) == per-op", ok);
        all = all && ok;
#else
        record_check("x448 batch(avx512 显式) == per-op", false);
        all = false;
#endif
    } else {
        printf("SKIP x448 batch avx512 显式变体自检: CPU 无 AVX512 (绝不调用 avx512 路径)\n");
    }
    return all;
}

// ───────────────────────── X448 基准 ─────────────────────────

static void bench_x448() {
    printf("\n--- X448 ---\n");
    uint8_t a_priv[56], a_pub[56], b_priv[56], b_pub[56], ss[56];
    jpssl::x448_generate_keypair(a_pub, a_priv);
    jpssl::x448_generate_keypair(b_pub, b_priv);

    double jp_kg = auto_bench("x448 keygen jpssl", "x448-keygen", "jpssl", 56, [&] {
        uint8_t p[56], s[56];
        jpssl::x448_generate_keypair(p, s);
        g_sink ^= p[0] ^ s[0];
    });
    double os_kg = auto_bench("x448 keygen openssl", "x448-keygen", "openssl", 56, [&] {
        uint8_t p[56], s[56];
        if (!ossl_raw_keygen(EVP_PKEY_X448, "X448", s, p, 56)) g_sink ^= 1;
        g_sink ^= p[0] ^ s[0];
    });

    double jp_dv = auto_bench("x448 derive jpssl", "x448-derive", "jpssl", 56, [&] {
        jpssl::x448_scalar_mult(ss, a_priv, b_pub);
        g_sink ^= ss[0];
    });
    EVP_PKEY* os_ours = ossl_raw_priv(EVP_PKEY_X448, a_priv, 56);
    EVP_PKEY* os_peer = ossl_raw_pub(EVP_PKEY_X448, b_pub, 56);
    double os_dv = auto_bench("x448 derive openssl", "x448-derive", "openssl", 56, [&] {
        ossl_raw_derive_keys(os_ours, os_peer, 56, ss);
        g_sink ^= ss[0];
    });

    double jp_full = auto_bench("x448 full handshake jpssl", "x448-full", "jpssl", 56, [&] {
        uint8_t pa[56], sa[56], pb[56], sb[56], s1[56], s2[56];
        jpssl::x448_generate_keypair(pa, sa);
        jpssl::x448_generate_keypair(pb, sb);
        jpssl::x448_scalar_mult(s1, sa, pb);
        jpssl::x448_scalar_mult(s2, sb, pa);
        g_sink ^= s1[0] ^ s2[0];
    });
    double os_full = auto_bench("x448 full handshake openssl", "x448-full", "openssl", 56, [&] {
        uint8_t sa[56], pa[56], sb[56], pb[56], s1[56], s2[56];
        EVP_PKEY* ka = EVP_PKEY_Q_keygen(nullptr, nullptr, "X448");
        EVP_PKEY* kb = EVP_PKEY_Q_keygen(nullptr, nullptr, "X448");
        size_t l;
        l = 56; EVP_PKEY_get_raw_private_key(ka, sa, &l);
        l = 56; EVP_PKEY_get_raw_public_key(ka, pa, &l);
        l = 56; EVP_PKEY_get_raw_private_key(kb, sb, &l);
        l = 56; EVP_PKEY_get_raw_public_key(kb, pb, &l);
        EVP_PKEY* oa = ossl_raw_priv(EVP_PKEY_X448, sa, 56);
        EVP_PKEY* oap = ossl_raw_pub(EVP_PKEY_X448, pb, 56);
        EVP_PKEY* ob = ossl_raw_priv(EVP_PKEY_X448, sb, 56);
        EVP_PKEY* obp = ossl_raw_pub(EVP_PKEY_X448, pa, 56);
        ossl_raw_derive_keys(oa, oap, 56, s1);
        ossl_raw_derive_keys(ob, obp, 56, s2);
        EVP_PKEY_free(oa); EVP_PKEY_free(oap);
        EVP_PKEY_free(ob); EVP_PKEY_free(obp);
        EVP_PKEY_free(ka); EVP_PKEY_free(kb);
        g_sink ^= s1[0] ^ s2[0];
    });

    // 批量 N=1000: jpssl 批量 API (内部运行时派发) + 显式 avx2/avx512 变体 + openssl 循环
    constexpr int BN = 1000;
    std::vector<uint8_t> outs((size_t)BN * 56);
    std::vector<const uint8_t*> sc((size_t)BN, a_priv), pt((size_t)BN, b_pub);
    uint8_t(*outs2d)[56] = reinterpret_cast<uint8_t(*)[56]>(outs.data());

    // 正确性: 批量 == 逐条 (dispatch + 可用显式变体)
    if (!selfcheck_x448_batch(outs2d, sc, pt, BN)) { g_sink ^= 0x448; }

    double jp_bat = auto_bench_batch("x448 batch N=1000 jpssl (dispatch)",
                                     "x448-batch", "jpssl-batch", 56, [&] {
        jpssl::x448_scalar_mult_batch(outs2d, sc.data(), pt.data(), BN);
        g_sink ^= outs[0];
    }, BN);

    if (jpssl::cpu_has_avx2()) {
        double jp_bat_avx2 = auto_bench_batch("x448 batch N=1000 jpssl (avx2 显式)",
                                              "x448-batch", "jpssl-batch-avx2", 56, [&] {
#if defined(JP_AVX2)
            jpssl::x448_scalar_mult_batch_avx2(outs2d, sc.data(), pt.data(), BN);
#else
            jpssl::x448_scalar_mult_batch(outs2d, sc.data(), pt.data(), BN);
#endif
            g_sink ^= outs[0];
        }, BN);
        (void)jp_bat_avx2;
    } else {
        printf("SKIP x448 batch avx2 变体: CPU 无 AVX2\n");
    }

    if (jpssl::cpu_has_avx512()) {
#if defined(JP_AVX512)
        double jp_bat_avx512 = auto_bench_batch("x448 batch N=1000 jpssl (avx512 显式)",
                                                "x448-batch", "jpssl-batch-avx512", 56, [&] {
            jpssl::x448_scalar_mult_batch_avx512(outs2d, sc.data(), pt.data(), BN);
            g_sink ^= outs[0];
        }, BN);
        (void)jp_bat_avx512;
#endif
    } else {
        printf("SKIP x448 batch avx512 变体: CPU 无 AVX512 (batch 自动派发走 AVX2)\n");
    }

    double os_bat = auto_bench_batch("x448 batch N=1000 openssl (loop)",
                                     "x448-batch", "openssl", 56, [&] {
        for (int i = 0; i < BN; ++i)
            ossl_raw_derive_keys(os_ours, os_peer, 56, outs.data() + (size_t)i * 56);
        g_sink ^= outs[0];
    }, BN);

    printf("x448 ratios (openssl/jpssl, >1 = jpssl 快): keygen %.2fx  derive %.2fx  "
           "full %.2fx  batch(dispatch) %.2fx\n",
           os_kg / jp_kg, os_dv / jp_dv, os_full / jp_full, os_bat / jp_bat);

    EVP_PKEY_free(os_ours);
    EVP_PKEY_free(os_peer);
}

// ───────────────────────── main ─────────────────────────

int main() {
    g_smoke = std::getenv("BENCH_SMOKE") != nullptr;
    printf("=== X448 ECDH: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("mode: %s\n", g_smoke ? "SMOKE (迭代减半, 1 轮)" : "full (~150ms/轮, 3 轮取最小)");
    printf("CPU: AVX2=%d AVX512=%d\n", jpssl::cpu_has_avx2() ? 1 : 0,
           jpssl::cpu_has_avx512() ? 1 : 0);

    // SKIP 说明 (本机特性不支持的多实现变体, 绝不调用)
    if (!jpssl::cpu_has_avx512()) {
        printf("SKIP x448 batch avx512  : CPU 无 AVX512 (x448_scalar_mult_batch 自动派发到 AVX2; "
               "显式 avx512 调用会 SIGILL, 故不调用)\n");
    }
    if (!jpssl::cpu_has_avx2()) {
        printf("SKIP x448 batch avx2    : CPU 无 AVX2\n");
    }

    std::filesystem::create_directories("benchmarks/results");
    g_csv = fopen("benchmarks/results/bench_x448.csv", "w");
    if (g_csv) fprintf(g_csv, "algo,impl,size_bytes,ns_per_op,ops_per_sec\n");
    else printf("WARNING: 无法打开 CSV 输出文件\n");

    // 正确性自检 (始终执行, FAIL 非零退出)
    bool all_ok = true;
    printf("\n--- 交叉验证自检 ---\n");
    all_ok = selfcheck_x448() && all_ok;
    if (!all_ok) {
        printf("SELF-CHECK FAILED — 共享密钥不一致, 基准结果不可信 (PASS=%d FAIL=%d)\n",
               g_selfcheck_pass, g_selfcheck_fail);
        if (g_csv) fclose(g_csv);
        return 1;
    }

    printf("\n%-36s %12s %14s\n", "case", "ns/op", "Kops/s");
    bench_x448();

    if (g_csv) {
        fclose(g_csv);
        g_csv = nullptr;
        printf("\nCSV 已写入: benchmarks/results/bench_x448.csv\n");
    }
    printf("SELF-CHECK PASS=%d FAIL=%d (sink=%d)\n", g_selfcheck_pass, g_selfcheck_fail, g_sink);
    return (g_selfcheck_fail != 0) ? 1 : 0;
}
