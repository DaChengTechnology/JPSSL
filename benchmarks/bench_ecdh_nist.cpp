// bench_ecdh_nist.cpp - ECDH-NIST (P-256 / P-384) jpssl × OpenSSL 对比微基准
//
// 每条曲线覆盖 4 种操作:
//   keygen  : 单方密钥生成 (jpssl ecdsa_pXXX_keygen vs openssl EC keygen)
//   derive  : 固定密钥对的单边共享密钥派生 (jpssl ecdsa_pXXX_ecdh vs
//             OpenSSL EC_KEY + EVP_PKEY_derive; OpenSSL 侧从 jpssl 的 x||y
//             公钥构造 EC_KEY 再 derive)
//   full    : 完整协商 (双方 keygen + 双向 derive)
//   batch   : 批量 N=1000 (jpssl ecdsa_pXXX_ecdh_batch vs openssl 逐条循环),
//             CSV 记平均单条 ns/op
//
// 正确性自检 (始终执行, 任一 FAIL 非零退出):
//   - 每条曲线 jpssl / openssl 交叉验证共享密钥一致 (双向同密钥)
//   - batch 每 op 与单次 derive 一致
//
// 环境变量:
//   BENCH_SMOKE=1  → 每 op 迭代减半 (75ms/轮), 仅 1 轮
//   未设置         → ~150ms/轮, 3 轮取最小
//
// 编译 (worktree 根执行):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_ecdh_nist.cpp \
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto \
//       -o /tmp/bench_ecdh_nist
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_ecdh_nist.csv
//       CSV 列头固定: algo,impl,size_bytes,ns_per_op,ops_per_sec
//       (algo: p256-keygen / p256-derive / p256-full / p256-batch 及 p384-*;
//        impl: jpssl / jpssl-batch / openssl;
//        size_bytes: 32 (p256) / 48 (p384))
//
// 结构复用自 benchmarks/bench_ecdh_multi.cpp 的 P-256/P-384 部分
// (ecdh_keypair/ecdh_derive/ecdh_batch 与 OpenSSL EVP derive 对比、共享密钥
// 交叉验证), 拆出 ECDH-NIST 细化。

#include "cpu_features.hpp"
#include "ecdsa.hpp"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

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
static int g_self_pass = 0, g_self_fail = 0;

static void csv_row(const char* algo, const char* impl, int size_bytes, double ns) {
    if (g_csv) fprintf(g_csv, "%s,%s,%d,%.1f,%.1f\n", algo, impl, size_bytes, ns, 1e9 / ns);
}

// 自适应微基准: 每轮约 target_ms, rounds 轮取最小
template <typename F>
static double auto_bench(const char* name, const char* algo, const char* impl, int size_bytes,
                         F&& f, double target_ms, int rounds) {
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
    printf("%-34s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    csv_row(algo, impl, size_bytes, best);
    return best;
}

// 批量基准: 每次调用处理 items_per_call 条, 自适应调用次数使每轮约 target_ms,
// rounds 轮取最小, 返回平均单条 ns (CSV 也按单条记)。
template <typename F>
static double auto_bench_batch(const char* name, const char* algo, const char* impl,
                               int size_bytes, F&& f, int items_per_call,
                               double target_ms, int rounds) {
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
    printf("%-34s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    csv_row(algo, impl, size_bytes, best);
    return best;
}

// ───────────────────────── OpenSSL EC (P-256/P-384) ─────────────────────────

// 从原始字节构造 EC 密钥 (priv 可为 nullptr → 仅公钥, 作 peer 用)
static EVP_PKEY* ossl_ec_key_from_raw(int nid, const uint8_t* priv, int priv_len,
                                      const uint8_t* pub /* x||y */, int pub_len) {
    EC_KEY* ec = EC_KEY_new_by_curve_name(nid);
    if (!ec) return nullptr;
    if (priv) {
        BIGNUM* d = BN_bin2bn(priv, priv_len, nullptr);
        EC_KEY_set_private_key(ec, d);
        BN_free(d);
    }
    const EC_GROUP* grp = EC_KEY_get0_group(ec);
    EC_POINT* P = EC_POINT_new(grp);
    BIGNUM* x = BN_bin2bn(pub, pub_len / 2, nullptr);
    BIGNUM* y = BN_bin2bn(pub + pub_len / 2, pub_len / 2, nullptr);
    EC_POINT_set_affine_coordinates(grp, P, x, y, nullptr);
    BN_free(x);
    BN_free(y);
    EC_KEY_set_public_key(ec, P);
    EC_POINT_free(P);
    EVP_PKEY* pk = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pk, ec);  // 接管 ec
    return pk;
}

static bool ossl_ec_keygen(int nid, uint8_t* pub /* x||y */, uint8_t* priv, int nbytes) {
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!c) return false;
    bool ok = EVP_PKEY_keygen_init(c) == 1
           && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, nid) == 1;
    EVP_PKEY* k = nullptr;
    ok = ok && EVP_PKEY_keygen(c, &k) == 1;
    EVP_PKEY_CTX_free(c);
    if (ok) {
        EC_KEY* ec = EVP_PKEY_get1_EC_KEY(k);
        const BIGNUM* d = EC_KEY_get0_private_key(ec);
        const EC_GROUP* grp = EC_KEY_get0_group(ec);
        const EC_POINT* P = EC_KEY_get0_public_key(ec);
        uint8_t buf[1 + 2 * 66];
        size_t olen = EC_POINT_point2oct(grp, P, POINT_CONVERSION_UNCOMPRESSED, buf,
                                         sizeof buf, nullptr);
        ok = olen == static_cast<size_t>(1 + 2 * nbytes)
          && BN_bn2binpad(d, priv, nbytes) == nbytes;
        if (ok) memcpy(pub, buf + 1, 2 * nbytes);
        EC_KEY_free(ec);
    }
    EVP_PKEY_free(k);
    return ok;
}

// 使用已构造 pkey 完成一次 EC derive (ctx 新建/初始化/设 peer/derive)
static bool ossl_ec_derive_keys(EVP_PKEY* ours, EVP_PKEY* peer, int nbytes, uint8_t* out) {
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new(ours, nullptr);
    bool ok = c && EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, peer) == 1;
    size_t olen = nbytes;
    ok = ok && EVP_PKEY_derive(c, out, &olen) == 1 && olen == static_cast<size_t>(nbytes);
    EVP_PKEY_CTX_free(c);
    return ok;
}

// ───────────────────────── 正确性自检 (jpssl × OpenSSL 交叉验证) ─────────────────────────

template <int NBYTES>
static bool selfcheck_pXXX(int nid, const char* label) {
    constexpr int NPUB = 2 * NBYTES;
    bool ok = true;
    // 1) jpssl/openssl 交叉验证共享密钥一致 (双向)
    uint8_t ja_priv[NBYTES], ja_pub[NPUB], bo_priv[NBYTES], bo_pub[NPUB];
    if constexpr (NBYTES == 32) jpssl::ecdsa_p256_keygen(ja_pub, ja_priv);
    else                        jpssl::ecdsa_p384_keygen(ja_pub, ja_priv);
    ok = ok && ossl_ec_keygen(nid, bo_pub, bo_priv, NBYTES);
    uint8_t ss_jp[NBYTES], ss_ossl[NBYTES], ss_jp2[NBYTES];
    EVP_PKEY* bo_pk = ossl_ec_key_from_raw(nid, bo_priv, NBYTES, bo_pub, NPUB);
    EVP_PKEY* ja_pk = ossl_ec_key_from_raw(nid, nullptr, 0, ja_pub, NPUB);
    if constexpr (NBYTES == 32) {
        ok = ok && jpssl::ecdsa_p256_ecdh(ss_jp, ja_priv, bo_pub);
        ok = ok && ossl_ec_derive_keys(bo_pk, ja_pk, NBYTES, ss_ossl);
        ok = ok && jpssl::ecdsa_p256_ecdh(ss_jp2, bo_priv, ja_pub);
    } else {
        ok = ok && jpssl::ecdsa_p384_ecdh(ss_jp, ja_priv, bo_pub);
        ok = ok && ossl_ec_derive_keys(bo_pk, ja_pk, NBYTES, ss_ossl);
        ok = ok && jpssl::ecdsa_p384_ecdh(ss_jp2, bo_priv, ja_pub);
    }
    ok = ok && bo_pk && ja_pk && memcmp(ss_jp, ss_ossl, NBYTES) == 0
            && memcmp(ss_jp, ss_jp2, NBYTES) == 0;
    if (ok) ++g_self_pass; else ++g_self_fail;
    printf("%s cross-check (jpssl priv × openssl pub, 双向同密钥): %s\n",
           label, ok ? "PASS" : "FAIL");

    // 2) batch N=1000 每 op 与单次 derive 一致
    constexpr int BN = 1000;
    std::vector<uint8_t> bp_priv(BN * NBYTES), bp_pub(BN * NPUB), bp_sh(BN * NBYTES);
    std::vector<uint8_t> ref(BN * NBYTES);
    for (int i = 0; i < BN; ++i) {
        memcpy(bp_priv.data() + (size_t)i * NBYTES, ja_priv, NBYTES);
        memcpy(bp_pub.data() + (size_t)i * NPUB, bo_pub, NPUB);
        if constexpr (NBYTES == 32)
            jpssl::ecdsa_p256_ecdh(ref.data() + (size_t)i * NBYTES, ja_priv, bo_pub);
        else
            jpssl::ecdsa_p384_ecdh(ref.data() + (size_t)i * NBYTES, ja_priv, bo_pub);
    }
    bool batch_ok = true;
    if constexpr (NBYTES == 32)
        batch_ok = jpssl::ecdsa_p256_ecdh_batch(bp_sh.data(), bp_priv.data(), bp_pub.data(), BN);
    else
        batch_ok = jpssl::ecdsa_p384_ecdh_batch(bp_sh.data(), bp_priv.data(), bp_pub.data(), BN);
    batch_ok = batch_ok && memcmp(ref.data(), bp_sh.data(), BN * NBYTES) == 0;
    if (batch_ok) ++g_self_pass; else ++g_self_fail;
    printf("%s batch N=%d == per-op: %s\n", label, BN, batch_ok ? "PASS" : "FAIL");

    EVP_PKEY_free(bo_pk);
    EVP_PKEY_free(ja_pk);
    return ok && batch_ok;
}

// ───────────────────────── P-256 / P-384 基准 ─────────────────────────

template <int NBYTES>
static void bench_pXXX(int nid, const char* algo, const char* label,
                       double target_ms, int rounds) {
    constexpr int NPUB = 2 * NBYTES;
    printf("\n--- %s ---\n", label);
    uint8_t a_priv[NBYTES], a_pub[NPUB], b_priv[NBYTES], b_pub[NPUB], ss[NBYTES];
    if constexpr (NBYTES == 32) {
        jpssl::ecdsa_p256_keygen(a_pub, a_priv);
        jpssl::ecdsa_p256_keygen(b_pub, b_priv);
    } else {
        jpssl::ecdsa_p384_keygen(a_pub, a_priv);
        jpssl::ecdsa_p384_keygen(b_pub, b_priv);
    }

    char name[96];
    char algo_buf[64];
    double jp_kg, os_kg, jp_dv, os_dv, jp_full, os_full, jp_bat, os_bat;

    std::snprintf(name, sizeof name, "%s keygen jpssl", label);
    std::snprintf(algo_buf, sizeof algo_buf, "%s-keygen", algo);
    jp_kg = auto_bench(name, algo_buf, "jpssl", NBYTES, [&] {
        uint8_t p[NPUB], s[NBYTES];
        if constexpr (NBYTES == 32) jpssl::ecdsa_p256_keygen(p, s);
        else                        jpssl::ecdsa_p384_keygen(p, s);
        g_sink ^= p[0] ^ s[0];
    }, target_ms, rounds);
    std::snprintf(name, sizeof name, "%s keygen openssl", label);
    os_kg = auto_bench(name, algo_buf, "openssl", NBYTES, [&] {
        uint8_t p[NPUB], s[NBYTES];
        if (!ossl_ec_keygen(nid, p, s, NBYTES)) g_sink ^= 1;
        g_sink ^= p[0] ^ s[0];
    }, target_ms, rounds);

    EVP_PKEY* os_ours = ossl_ec_key_from_raw(nid, a_priv, NBYTES, a_pub, NPUB);
    EVP_PKEY* os_peer = ossl_ec_key_from_raw(nid, nullptr, 0, b_pub, NPUB);
    std::snprintf(name, sizeof name, "%s derive jpssl", label);
    std::snprintf(algo_buf, sizeof algo_buf, "%s-derive", algo);
    jp_dv = auto_bench(name, algo_buf, "jpssl", NBYTES, [&] {
        if constexpr (NBYTES == 32) jpssl::ecdsa_p256_ecdh(ss, a_priv, b_pub);
        else                        jpssl::ecdsa_p384_ecdh(ss, a_priv, b_pub);
        g_sink ^= ss[0];
    }, target_ms, rounds);
    std::snprintf(name, sizeof name, "%s derive openssl", label);
    os_dv = auto_bench(name, algo_buf, "openssl", NBYTES, [&] {
        ossl_ec_derive_keys(os_ours, os_peer, NBYTES, ss);
        g_sink ^= ss[0];
    }, target_ms, rounds);

    std::snprintf(name, sizeof name, "%s full handshake jpssl", label);
    std::snprintf(algo_buf, sizeof algo_buf, "%s-full", algo);
    jp_full = auto_bench(name, algo_buf, "jpssl", NBYTES, [&] {
        uint8_t pa[NPUB], sa[NBYTES], pb[NPUB], sb[NBYTES], s1[NBYTES], s2[NBYTES];
        if constexpr (NBYTES == 32) {
            jpssl::ecdsa_p256_keygen(pa, sa);
            jpssl::ecdsa_p256_keygen(pb, sb);
            jpssl::ecdsa_p256_ecdh(s1, sa, pb);
            jpssl::ecdsa_p256_ecdh(s2, sb, pa);
        } else {
            jpssl::ecdsa_p384_keygen(pa, sa);
            jpssl::ecdsa_p384_keygen(pb, sb);
            jpssl::ecdsa_p384_ecdh(s1, sa, pb);
            jpssl::ecdsa_p384_ecdh(s2, sb, pa);
        }
        g_sink ^= s1[0] ^ s2[0];
    }, target_ms, rounds);
    std::snprintf(name, sizeof name, "%s full handshake openssl", label);
    os_full = auto_bench(name, algo_buf, "openssl", NBYTES, [&] {
        uint8_t pa[NPUB], sa[NBYTES], pb[NPUB], sb[NBYTES], s1[NBYTES], s2[NBYTES];
        EVP_PKEY_CTX* ka = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        EVP_PKEY_CTX* kb = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        EVP_PKEY* pka = nullptr, *pkb = nullptr;
        if (ka && kb && EVP_PKEY_keygen_init(ka) == 1
            && EVP_PKEY_keygen_init(kb) == 1
            && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ka, nid) == 1
            && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kb, nid) == 1
            && EVP_PKEY_keygen(ka, &pka) == 1 && EVP_PKEY_keygen(kb, &pkb) == 1) {
            size_t l;
            l = NBYTES; EVP_PKEY_get_raw_private_key(pka, sa, &l);
            l = NBYTES; EVP_PKEY_get_raw_private_key(pkb, sb, &l);
            EC_KEY* eca = EVP_PKEY_get1_EC_KEY(pka);
            EC_KEY* ecb = EVP_PKEY_get1_EC_KEY(pkb);
            uint8_t buf[1 + 2 * 66];
            size_t o = EC_POINT_point2oct(EC_KEY_get0_group(eca), EC_KEY_get0_public_key(eca),
                                          POINT_CONVERSION_UNCOMPRESSED, buf, sizeof buf, nullptr);
            if (o == 1 + 2 * (size_t)NBYTES) memcpy(pa, buf + 1, 2 * NBYTES);
            o = EC_POINT_point2oct(EC_KEY_get0_group(ecb), EC_KEY_get0_public_key(ecb),
                                   POINT_CONVERSION_UNCOMPRESSED, buf, sizeof buf, nullptr);
            if (o == 1 + 2 * (size_t)NBYTES) memcpy(pb, buf + 1, 2 * NBYTES);
            EVP_PKEY* oa = ossl_ec_key_from_raw(nid, sa, NBYTES, pa, NPUB);
            EVP_PKEY* obp = ossl_ec_key_from_raw(nid, nullptr, 0, pb, NPUB);
            EVP_PKEY* ob = ossl_ec_key_from_raw(nid, sb, NBYTES, pb, NPUB);
            EVP_PKEY* oap = ossl_ec_key_from_raw(nid, nullptr, 0, pa, NPUB);
            ossl_ec_derive_keys(oa, obp, NBYTES, s1);
            ossl_ec_derive_keys(ob, oap, NBYTES, s2);
            EVP_PKEY_free(oa); EVP_PKEY_free(obp);
            EVP_PKEY_free(ob); EVP_PKEY_free(oap);
            EC_KEY_free(eca); EC_KEY_free(ecb);
        } else {
            g_sink ^= 1;
        }
        EVP_PKEY_free(pka); EVP_PKEY_free(pkb);
        EVP_PKEY_CTX_free(ka); EVP_PKEY_CTX_free(kb);
        g_sink ^= s1[0] ^ s2[0];
    }, target_ms, rounds);

    // 批量 N=1000: jpssl 批量 API vs openssl 循环
    constexpr int BN = 1000;
    std::vector<uint8_t> bp_priv(BN * NBYTES), bp_pub(BN * NPUB), bp_sh(BN * NBYTES);
    for (int i = 0; i < BN; ++i) {
        memcpy(bp_priv.data() + (size_t)i * NBYTES, a_priv, NBYTES);
        memcpy(bp_pub.data() + (size_t)i * NPUB, b_pub, NPUB);
    }
    std::snprintf(name, sizeof name, "%s batch N=%d jpssl (batch API)", label, BN);
    std::snprintf(algo_buf, sizeof algo_buf, "%s-batch", algo);
    jp_bat = auto_bench_batch(name, algo_buf, "jpssl-batch", NBYTES, [&] {
        if constexpr (NBYTES == 32)
            jpssl::ecdsa_p256_ecdh_batch(bp_sh.data(), bp_priv.data(), bp_pub.data(), BN);
        else
            jpssl::ecdsa_p384_ecdh_batch(bp_sh.data(), bp_priv.data(), bp_pub.data(), BN);
        g_sink ^= bp_sh[0];
    }, BN, target_ms, rounds);
    std::snprintf(name, sizeof name, "%s batch N=%d openssl (loop)", label, BN);
    os_bat = auto_bench_batch(name, algo_buf, "openssl", NBYTES, [&] {
        for (int i = 0; i < BN; ++i)
            ossl_ec_derive_keys(os_ours, os_peer, NBYTES, bp_sh.data() + (size_t)i * NBYTES);
        g_sink ^= bp_sh[0];
    }, BN, target_ms, rounds);

    printf("%s ratios (openssl/jpssl, >1 = jpssl 快): keygen %.2fx  derive %.2fx  "
           "full %.2fx  batch %.2fx\n",
           label, os_kg / jp_kg, os_dv / jp_dv, os_full / jp_full, os_bat / jp_bat);

    EVP_PKEY_free(os_ours);
    EVP_PKEY_free(os_peer);
}

// ───────────────────────── main ─────────────────────────

int main() {
    auto feats = jpssl::cpu_features::detect();
    const char* smoke_env = std::getenv("BENCH_SMOKE");
    bool smoke = smoke_env && std::strcmp(smoke_env, "1") == 0;
    const double target_ms = smoke ? 75.0 : 150.0;  // smoke: 每 op 迭代减半
    const int rounds = smoke ? 1 : 3;               // smoke: 1 轮; 全量: 3 轮取最小

    printf("=== ECDH-NIST (P-256/P-384): jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("CPU: AES-NI=%d AVX2=%d PCLMULQDQ=%d VAES=%d SHA-NI=%d ADX=%d AVX512=%d NEON=%d\n",
           feats.aesni, feats.avx2, feats.pclmulqdq, feats.vpclmulqdq_vaes, feats.sha_ni,
           jpssl::cpu_has_adx() ? 1 : 0, feats.avx512, feats.neon);
    printf("BENCH_SMOKE=%d  (target %.0f ms/round, %d round%s)\n",
           smoke ? 1 : 0, target_ms, rounds, rounds == 1 ? "" : "s");

    std::filesystem::create_directories("benchmarks/results");
    g_csv = fopen("benchmarks/results/bench_ecdh_nist.csv", "w");
    if (g_csv) fprintf(g_csv, "algo,impl,size_bytes,ns_per_op,ops_per_sec\n");
    else printf("WARNING: 无法打开 CSV 输出文件\n");

    // 正确性自检 (始终执行, FAIL 非零退出)
    printf("\n--- 交叉验证自检 (共享密钥一致性) ---\n");
    bool all_ok = true;
    all_ok = selfcheck_pXXX<32>(NID_X9_62_prime256v1, "P-256") && all_ok;
    all_ok = selfcheck_pXXX<48>(NID_secp384r1, "P-384") && all_ok;
    printf("self-check: %d PASS, %d FAIL\n", g_self_pass, g_self_fail);
    if (!all_ok) {
        printf("SELF-CHECK FAILED — 共享密钥不一致, 基准结果不可信\n");
        if (g_csv) fclose(g_csv);
        return 1;
    }

    printf("\n%-34s %12s %14s\n", "case", "ns/op", "Kops/s");
    bench_pXXX<32>(NID_X9_62_prime256v1, "p256", "P-256", target_ms, rounds);
    bench_pXXX<48>(NID_secp384r1, "p384", "P-384", target_ms, rounds);

    if (g_csv) {
        fclose(g_csv);
        printf("\nCSV 已写入: benchmarks/results/bench_ecdh_nist.csv\n");
    }
    printf("(sink=%d)\n", g_sink);
    return 0;
}
