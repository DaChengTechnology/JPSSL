// bench_x25519.cpp - X25519 ECDH 全量测试: keygen / derive / full / batch × jpssl/OpenSSL 对比
//
// 覆盖:
//   a) keygen          - 密钥对生成 (jpssl: x25519_generate_keypair; openssl: EVP raw keygen)
//   b) derive          - 共享密钥派生, 固定对端公钥 (jpssl: x25519_scalar_mult; openssl: EVP derive)
//   c) full            - 完整协商 (双方 keygen + 双向 derive)
//   d) batch N=1000    - 批量派生 (双方均为循环派生接口, 单条平均)
//
// 正确性自检 (始终执行, FAIL 非零退出):
//   - RFC 7748 §6.1 已知答案向量 (jpssl 侧固定向量派生 == 官方共享密钥)
//   - jpssl × OpenSSL 交叉验证: jpssl 私钥+openssl 公钥 vs openssl 私钥+jpssl 公钥 -> 相同共享密钥
//   - keygen 一致性: keygen 公钥 == scalar_mult(私钥, 基点)
//   - 批量 == 逐条
//
// 全量 vs smoke: 环境变量 BENCH_SMOKE=1 -> 每 op 迭代次数减半、1 轮;
//   未设置 -> 每轮约 150ms、3 轮取最小。自检始终执行。
//
// 编译 (worktree 根执行):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_x25519.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_x25519
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_x25519.csv
//       CSV 列头固定: algo,impl,size_bytes,ns_per_op,ops_per_sec
//       algo: x25519-keygen / x25519-derive / x25519-full / x25519-batch
//       impl: jpssl / openssl; size_bytes = 32 (共享密钥长度)

#include "cpu_features.hpp"
#include "x25519.hpp"

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

static void csv_row(const char* algo, const char* impl, int size_bytes, double ns) {
    if (g_csv) fprintf(g_csv, "%s,%s,%d,%.1f,%.1f\n", algo, impl, size_bytes, ns, 1e9 / ns);
}

// ───────────────────────── smoke / 全量 控制 ─────────────────────────

static bool g_smoke = false;

// 每轮约 target_ms (全量默认 150ms), 3 轮取最小; smoke 模式: 迭代减半、1 轮
template <typename F>
static double auto_bench(const char* name, const char* algo, const char* impl, int size_bytes,
                         F&& f, double target_ms = 150.0, int rounds = 3) {
    if (g_smoke) rounds = 1;
    f();
    int est_n = 8;
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
    if (g_smoke) {
        iters = iters / 2;
        if (iters < 1) iters = 1;
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

// 批量基准: 每次调用处理 items_per_call 条, 3 轮取最小, 返回平均单条 ns (smoke: 迭代减半、1 轮)
template <typename F>
static double auto_bench_batch(const char* name, const char* algo, const char* impl,
                               int size_bytes, F&& f, int items_per_call,
                               double target_ms = 150.0) {
    int rounds = g_smoke ? 1 : 3;
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
    if (g_smoke) {
        iters = iters / 2;
        if (iters < 1) iters = 1;
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

// ───────────────────────── OpenSSL raw (X25519) ─────────────────────────

static EVP_PKEY* ossl_raw_priv(const uint8_t* priv, size_t len) {
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, len);
}
static EVP_PKEY* ossl_raw_pub(const uint8_t* pub, size_t len) {
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pub, len);
}

static bool ossl_raw_keygen(uint8_t* priv, uint8_t* pub, size_t len) {
    EVP_PKEY* k = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    if (!k) return false;
    size_t plen = len, slen = len;
    bool ok = EVP_PKEY_get_raw_private_key(k, priv, &slen) == 1
           && EVP_PKEY_get_raw_public_key(k, pub, &plen) == 1
           && slen == len && plen == len;
    EVP_PKEY_free(k);
    return ok;
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

static bool ossl_raw_derive(const uint8_t* my_priv, const uint8_t* peer_pub,
                            size_t len, uint8_t* out) {
    EVP_PKEY* ours = ossl_raw_priv(my_priv, len);
    EVP_PKEY* peer = ossl_raw_pub(peer_pub, len);
    bool ok = ours && peer && ossl_raw_derive_keys(ours, peer, len, out);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(ours);
    return ok;
}

// ───────────────────────── 正确性自检 ─────────────────────────

static int g_pass = 0, g_fail = 0;

static void check(const char* name, bool ok) {
    printf("%-40s: %s\n", name, ok ? "PASS" : "FAIL");
    if (ok) ++g_pass; else ++g_fail;
}

// RFC 7748 §6.1 固定向量: Alice 私钥 × Bob 公钥 = 官方共享密钥
static bool selfcheck_rfc7748() {
    static const uint8_t alice_priv[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
        0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
        0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a};
    static const uint8_t bob_pub[32] = {
        0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
        0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
        0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
        0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f};
    static const uint8_t expected_ss[32] = {
        0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,
        0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
        0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,
        0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42};
    uint8_t ss[32];
    jpssl::x25519_scalar_mult(ss, alice_priv, bob_pub);
    bool ok = memcmp(ss, expected_ss, 32) == 0;
    check("RFC 7748 §6.1 已知答案 (jpssl)", ok);
    // 交叉: OpenSSL 对同一固定向量
    uint8_t ss_o[32];
    ok = ok && ossl_raw_derive(alice_priv, bob_pub, 32, ss_o)
           && memcmp(ss, ss_o, 32) == 0;
    check("RFC 7748 §6.1 已知答案 (jpssl == openssl)", ok);
    return ok;
}

// jpssl × OpenSSL 交叉验证: jpssl 私钥+openssl 公钥 vs openssl 私钥+jpssl 公钥 -> 相同共享密钥
static bool selfcheck_cross() {
    uint8_t ja_priv[32], ja_pub[32], bo_priv[32], bo_pub[32];
    jpssl::x25519_generate_keypair(ja_pub, ja_priv);
    bool ok = ossl_raw_keygen(bo_priv, bo_pub, 32);
    uint8_t ss_jp[32], ss_ossl[32], ss_jp2[32];
    jpssl::x25519_scalar_mult(ss_jp, ja_priv, bo_pub);
    ok = ok && ossl_raw_derive(bo_priv, ja_pub, 32, ss_ossl);
    jpssl::x25519_scalar_mult(ss_jp2, bo_priv, ja_pub);   // 反向同密钥
    ok = ok && memcmp(ss_jp, ss_ossl, 32) == 0 && memcmp(ss_jp, ss_jp2, 32) == 0;
    check("交叉验证 jpssl×openssl 双向同密钥", ok);
    return ok;
}

// keygen 一致性: keygen 公钥 == scalar_mult(私钥, 基点); 并与 OpenSSL 派生互证
static bool selfcheck_keygen() {
    uint8_t pub[32], priv[32], pub2[32];
    jpssl::x25519_generate_keypair(pub, priv);
    jpssl::x25519_scalar_mult(pub2, priv, nullptr);       // nullptr = 基点
    bool ok = memcmp(pub, pub2, 32) == 0;
    check("keygen 一致性 jpssl 公钥==标量×基点", ok);

    uint8_t bo_priv[32], bo_pub[32], ss_jp[32], ss_ossl[32];
    ok = ok && ossl_raw_keygen(bo_priv, bo_pub, 32);
    jpssl::x25519_scalar_mult(ss_jp, priv, bo_pub);
    ok = ok && ossl_raw_derive(bo_priv, pub, 32, ss_ossl)
           && memcmp(ss_jp, ss_ossl, 32) == 0;
    check("keygen 互证 jpssl 新密钥对 × openssl 派生", ok);
    return ok;
}

// ───────────────────────── X25519 基准 ─────────────────────────

static void bench_x25519() {
    printf("\n--- X25519 ---\n");
    uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32], ss[32];
    jpssl::x25519_generate_keypair(a_pub, a_priv);
    jpssl::x25519_generate_keypair(b_pub, b_priv);

    double jp_kg = auto_bench("x25519 keygen jpssl", "x25519-keygen", "jpssl", 32, [&] {
        uint8_t p[32], s[32];
        jpssl::x25519_generate_keypair(p, s);
        g_sink ^= p[0] ^ s[0];
    });
    double os_kg = auto_bench("x25519 keygen openssl", "x25519-keygen", "openssl", 32, [&] {
        uint8_t p[32], s[32];
        if (!ossl_raw_keygen(s, p, 32)) g_sink ^= 1;
        g_sink ^= p[0] ^ s[0];
    });

    double jp_dv = auto_bench("x25519 derive jpssl", "x25519-derive", "jpssl", 32, [&] {
        jpssl::x25519_scalar_mult(ss, a_priv, b_pub);
        g_sink ^= ss[0];
    });
    EVP_PKEY* os_ours = ossl_raw_priv(a_priv, 32);
    EVP_PKEY* os_peer = ossl_raw_pub(b_pub, 32);
    double os_dv = auto_bench("x25519 derive openssl", "x25519-derive", "openssl", 32, [&] {
        ossl_raw_derive_keys(os_ours, os_peer, 32, ss);
        g_sink ^= ss[0];
    });

    double jp_full = auto_bench("x25519 full handshake jpssl", "x25519-full", "jpssl", 32, [&] {
        uint8_t pa[32], sa[32], pb[32], sb[32], s1[32], s2[32];
        jpssl::x25519_generate_keypair(pa, sa);
        jpssl::x25519_generate_keypair(pb, sb);
        jpssl::x25519_scalar_mult(s1, sa, pb);
        jpssl::x25519_scalar_mult(s2, sb, pa);
        g_sink ^= s1[0] ^ s2[0];
    });
    double os_full = auto_bench("x25519 full handshake openssl", "x25519-full", "openssl", 32, [&] {
        uint8_t sa[32], pa[32], sb[32], pb[32], s1[32], s2[32];
        EVP_PKEY* ka = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        EVP_PKEY* kb = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        size_t l;
        l = 32; EVP_PKEY_get_raw_private_key(ka, sa, &l);
        l = 32; EVP_PKEY_get_raw_public_key(ka, pa, &l);
        l = 32; EVP_PKEY_get_raw_private_key(kb, sb, &l);
        l = 32; EVP_PKEY_get_raw_public_key(kb, pb, &l);
        EVP_PKEY* oa = ossl_raw_priv(sa, 32);
        EVP_PKEY* oap = ossl_raw_pub(pb, 32);
        EVP_PKEY* ob = ossl_raw_priv(sb, 32);
        EVP_PKEY* obp = ossl_raw_pub(pa, 32);
        ossl_raw_derive_keys(oa, oap, 32, s1);
        ossl_raw_derive_keys(ob, obp, 32, s2);
        EVP_PKEY_free(oa); EVP_PKEY_free(oap);
        EVP_PKEY_free(ob); EVP_PKEY_free(obp);
        EVP_PKEY_free(ka); EVP_PKEY_free(kb);
        g_sink ^= s1[0] ^ s2[0];
    });

    // 批量 N=1000 (X25519 无批量 API → 双方均循环派生)
    constexpr int BN = 1000;
    std::vector<uint8_t> bsh(BN * 32);
    // 正确性: 批量 == 逐条 (两实现分别对拍)
    bool batch_ok = true;
    for (int i = 0; i < BN; ++i) {
        jpssl::x25519_scalar_mult(bsh.data() + (size_t)i * 32, a_priv, b_pub);
    }
    for (int i = 0; i < BN; ++i) {
        uint8_t ref[32];
        jpssl::x25519_scalar_mult(ref, a_priv, b_pub);
        batch_ok = batch_ok && memcmp(bsh.data() + (size_t)i * 32, ref, 32) == 0;
    }
    for (int i = 0; i < BN; ++i) {
        batch_ok = batch_ok && ossl_raw_derive_keys(os_ours, os_peer, 32,
                                                    bsh.data() + (size_t)i * 32);
    }
    for (int i = 0; i < BN; ++i) {
        uint8_t ref[32];
        jpssl::x25519_scalar_mult(ref, a_priv, b_pub);
        batch_ok = batch_ok && memcmp(bsh.data() + (size_t)i * 32, ref, 32) == 0;
    }
    check("batch N=1000 批量==逐条 (jpssl/openssl 同输出)", batch_ok);
    if (!batch_ok) g_sink ^= 0x25519;

    double jp_bat = auto_bench_batch("x25519 batch N=1000 jpssl (loop)",
                                     "x25519-batch", "jpssl", 32, [&] {
        for (int i = 0; i < BN; ++i)
            jpssl::x25519_scalar_mult(bsh.data() + (size_t)i * 32, a_priv, b_pub);
        g_sink ^= bsh[0];
    }, BN);
    double os_bat = auto_bench_batch("x25519 batch N=1000 openssl (loop)",
                                     "x25519-batch", "openssl", 32, [&] {
        for (int i = 0; i < BN; ++i)
            ossl_raw_derive_keys(os_ours, os_peer, 32, bsh.data() + (size_t)i * 32);
        g_sink ^= bsh[0];
    }, BN);

    printf("x25519 ratios (openssl/jpssl, >1 = jpssl 快): keygen %.2fx  derive %.2fx  "
           "full %.2fx  batch %.2fx\n",
           os_kg / jp_kg, os_dv / jp_dv, os_full / jp_full, os_bat / jp_bat);

    EVP_PKEY_free(os_ours);
    EVP_PKEY_free(os_peer);
}

// ───────────────────────── main ─────────────────────────

int main() {
    g_smoke = std::getenv("BENCH_SMOKE") != nullptr;
    auto feats = jpssl::cpu_features::detect();
    printf("=== X25519 ECDH: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("mode: %s\n", g_smoke ? "SMOKE (迭代减半, 1 轮)" : "full (每轮约 150ms, 3 轮取最小)");
    printf("CPU: AES-NI=%d AVX2=%d PCLMULQDQ=%d VAES=%d SHA-NI=%d ADX=%d AVX512=%d NEON=%d\n",
           feats.aesni, feats.avx2, feats.pclmulqdq, feats.vpclmulqdq_vaes, feats.sha_ni,
           jpssl::cpu_has_adx() ? 1 : 0, feats.avx512, feats.neon);
    if (!feats.avx512) {
        printf("SKIP x25519 avx512 后端: CPU 无 AVX512 (走标量+ADX 内联路径)\n");
    }

    std::filesystem::create_directories("benchmarks/results");
    g_csv = fopen("benchmarks/results/bench_x25519.csv", "w");
    if (g_csv) fprintf(g_csv, "algo,impl,size_bytes,ns_per_op,ops_per_sec\n");
    else printf("WARNING: 无法打开 CSV 输出文件\n");

    // 正确性自检 (FAIL 非零退出, 始终执行)
    printf("\n--- 交叉验证自检 (共享密钥一致性) ---\n");
    bool all_ok = selfcheck_rfc7748();
    all_ok = selfcheck_cross() && all_ok;
    all_ok = selfcheck_keygen() && all_ok;

    printf("\n--- 基准 ---\n");
    printf("%-36s %12s %14s\n", "case", "ns/op", "Kops/s");
    bench_x25519();   // 内含 batch==逐条 自检

    if (!all_ok || g_fail > 0) {
        printf("\nSELF-CHECK FAILED (%d FAIL) — 共享密钥不一致, 基准结果不可信\n", g_fail);
        if (g_csv) fclose(g_csv);
        return 1;
    }

    if (g_csv) {
        fclose(g_csv);
        printf("\nCSV 已写入: benchmarks/results/bench_x25519.csv\n");
    }
    printf("(sink=%d)\n", g_sink);
    return 0;
}
