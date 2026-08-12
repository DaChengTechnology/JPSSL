// bench_ecdh_multi.cpp - ECDH 密钥协商 多实现 × OpenSSL 对比微基准
//
// 覆盖: X25519 / X448 / ECDH P-256 / ECDH P-384
// 每个算法测:
//   a) 完整协商 (双方 keygen + 双向 derive) 单次 ns/op
//   另附 keygen 单次、derive 单次 (固定密钥对, 相同工作量)
//   b) 批量吞吐 N=1000 (jpssl 批量 API 或循环; OpenSSL 逐条循环)
// 多实现: X448 批量暴露 avx2/avx512 变体 (本机无 AVX512 → SKIP);
//         X25519/P-256/P-384 无公开多后端, 记 jpssl (内部运行时分派)。
//
// 编译 (worktree 根执行; -DJP_AVX2/-DJP_AVX512 仅取头文件声明, 调用处做运行时
// CPU 特性守卫, 不支持的路径绝不调用):
//   g++ -O2 -std=c++20 -DJP_AVX2 -DJP_AVX512 -DJP_VAES -maes -mavx2 -madx \
//       -Iinclude benchmarks/bench_ecdh_multi.cpp \
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto \
//       -o /tmp/bench_ecdh_multi
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_ecdh_multi.csv
//       CSV 列头固定: algo,impl,size_bytes,ns_per_op,ops_per_sec
//       (algo 含操作种类, 如 x25519-keygen / x25519-derive / x25519-full / x25519-batch;
//        size_bytes = 共享密钥/私钥字节数)

#include "cpu_features.hpp"
#include "x25519.hpp"
#include "x448.hpp"
#include "ecdsa.hpp"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
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

// 自适应微基准: 每轮约 target_ms, 3 轮取最小 (参考 bench_ed25519_ossl.cpp 风格)
template <typename F>
static double auto_bench(const char* name, const char* algo, const char* impl, int size_bytes,
                         F&& f, double target_ms = 250.0, int rounds = 3) {
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
// 3 轮取最小, 返回平均单条 ns。
template <typename F>
static double auto_bench_batch(const char* name, const char* algo, const char* impl,
                               int size_bytes, F&& f, int items_per_call,
                               double target_ms = 250.0) {
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
    for (int r = 0; r < 3; ++r) {
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

// ───────────────────────── OpenSSL raw (X25519/X448) ─────────────────────────

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

static bool selfcheck_x25519() {
    uint8_t ja_priv[32], ja_pub[32], bo_priv[32], bo_pub[32];
    jpssl::x25519_generate_keypair(ja_pub, ja_priv);
    bool ok = ossl_raw_keygen(EVP_PKEY_X25519, "X25519", bo_priv, bo_pub, 32);
    uint8_t ss_jp[32], ss_ossl[32], ss_jp2[32];
    jpssl::x25519_scalar_mult(ss_jp, ja_priv, bo_pub);
    ok = ok && ossl_raw_derive(EVP_PKEY_X25519, bo_priv, ja_pub, 32, ss_ossl);
    jpssl::x25519_scalar_mult(ss_jp2, bo_priv, ja_pub);
    ok = ok && memcmp(ss_jp, ss_ossl, 32) == 0 && memcmp(ss_jp, ss_jp2, 32) == 0;
    printf("X25519 cross-check (jpssl priv × openssl pub, 双向同密钥): %s\n",
           ok ? "PASS" : "FAIL");
    return ok;
}

static bool selfcheck_x448() {
    uint8_t ja_priv[56], ja_pub[56], bo_priv[56], bo_pub[56];
    jpssl::x448_generate_keypair(ja_pub, ja_priv);
    bool ok = ossl_raw_keygen(EVP_PKEY_X448, "X448", bo_priv, bo_pub, 56);
    uint8_t ss_jp[56], ss_ossl[56], ss_jp2[56];
    jpssl::x448_scalar_mult(ss_jp, ja_priv, bo_pub);
    ok = ok && ossl_raw_derive(EVP_PKEY_X448, bo_priv, ja_pub, 56, ss_ossl);
    jpssl::x448_scalar_mult(ss_jp2, bo_priv, ja_pub);
    ok = ok && memcmp(ss_jp, ss_ossl, 56) == 0 && memcmp(ss_jp, ss_jp2, 56) == 0;
    printf("X448   cross-check (jpssl priv × openssl pub, 双向同密钥): %s\n",
           ok ? "PASS" : "FAIL");
    return ok;
}

template <int NBYTES>
static bool selfcheck_pXXX(int nid, const char* label) {
    uint8_t ja_priv[NBYTES], ja_pub[2 * NBYTES], bo_priv[NBYTES], bo_pub[2 * NBYTES];
    if constexpr (NBYTES == 32) jpssl::ecdsa_p256_keygen(ja_pub, ja_priv);
    else                        jpssl::ecdsa_p384_keygen(ja_pub, ja_priv);
    bool ok = ossl_ec_keygen(nid, bo_pub, bo_priv, NBYTES);
    uint8_t ss_jp[NBYTES], ss_ossl[NBYTES], ss_jp2[NBYTES];
    EVP_PKEY* bo_pk = ossl_ec_key_from_raw(nid, bo_priv, NBYTES, bo_pub, 2 * NBYTES);
    EVP_PKEY* ja_pk = ossl_ec_key_from_raw(nid, nullptr, 0, ja_pub, 2 * NBYTES);
    if constexpr (NBYTES == 32) {
        ok = ok && jpssl::ecdsa_p256_ecdh(ss_jp, ja_priv, bo_pub);
        ok = ok && ossl_ec_derive_keys(bo_pk, ja_pk, NBYTES, ss_ossl);
        ok = ok && jpssl::ecdsa_p256_ecdh(ss_jp2, bo_priv, ja_pub);
    } else {
        ok = ok && jpssl::ecdsa_p384_ecdh(ss_jp, ja_priv, bo_pub);
        ok = ok && ossl_ec_derive_keys(bo_pk, ja_pk, NBYTES, ss_ossl);
        ok = ok && jpssl::ecdsa_p384_ecdh(ss_jp2, bo_priv, ja_pub);
    }
    ok = ok && memcmp(ss_jp, ss_ossl, NBYTES) == 0 && memcmp(ss_jp, ss_jp2, NBYTES) == 0;
    printf("%-5s cross-check (jpssl priv × openssl pub, 双向同密钥): %s\n",
           label, ok ? "PASS" : "FAIL");
    EVP_PKEY_free(bo_pk);
    EVP_PKEY_free(ja_pk);
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
        if (!ossl_raw_keygen(EVP_PKEY_X25519, "X25519", s, p, 32)) g_sink ^= 1;
        g_sink ^= p[0] ^ s[0];
    });

    double jp_dv = auto_bench("x25519 derive jpssl", "x25519-derive", "jpssl", 32, [&] {
        jpssl::x25519_scalar_mult(ss, a_priv, b_pub);
        g_sink ^= ss[0];
    });
    EVP_PKEY* os_ours = ossl_raw_priv(EVP_PKEY_X25519, a_priv, 32);
    EVP_PKEY* os_peer = ossl_raw_pub(EVP_PKEY_X25519, b_pub, 32);
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
        EVP_PKEY* oa = ossl_raw_priv(EVP_PKEY_X25519, sa, 32);
        EVP_PKEY* oap = ossl_raw_pub(EVP_PKEY_X25519, pb, 32);
        EVP_PKEY* ob = ossl_raw_priv(EVP_PKEY_X25519, sb, 32);
        EVP_PKEY* obp = ossl_raw_pub(EVP_PKEY_X25519, pa, 32);
        ossl_raw_derive_keys(oa, oap, 32, s1);
        ossl_raw_derive_keys(ob, obp, 32, s2);
        EVP_PKEY_free(oa); EVP_PKEY_free(oap);
        EVP_PKEY_free(ob); EVP_PKEY_free(obp);
        EVP_PKEY_free(ka); EVP_PKEY_free(kb);
        g_sink ^= s1[0] ^ s2[0];
    });

    // 批量 N=1000 (X25519 无批量 API → 双方均循环)
    constexpr int BN = 1000;
    std::vector<uint8_t> bsh(BN * 32);
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

// ───────────────────────── X448 基准 (多实现: scalar / batch dispatch→AVX2 / 显式 avx2 / avx512-SKIP) ─────────────────────────

static void bench_x448() {
    auto feats = jpssl::cpu_features::detect();
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

    double jp_dv = auto_bench("x448 derive jpssl (scalar)", "x448-derive", "jpssl-scalar", 56, [&] {
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

    // 批量 N=1000: jpssl 批量 API (内部运行时派发) + 显式 avx2 变体 + openssl 循环
    constexpr int BN = 1000;
    std::vector<uint8_t> outs(BN * 56);
    std::vector<const uint8_t*> sc(BN, a_priv), pt(BN, b_pub);
    uint8_t(*outs2d)[56] = reinterpret_cast<uint8_t(*)[56]>(outs.data());

    // 正确性: 批量 == 逐条
    std::vector<uint8_t> ref(BN * 56);
    for (int i = 0; i < BN; ++i)
        jpssl::x448_scalar_mult(ref.data() + (size_t)i * 56, a_priv, b_pub);
    jpssl::x448_scalar_mult_batch(outs2d, sc.data(), pt.data(), BN);
    bool batch_ok = memcmp(ref.data(), outs.data(), BN * 56) == 0;
#if defined(JP_AVX2)
    if (feats.avx2) {
        jpssl::x448_scalar_mult_batch_avx2(outs2d, sc.data(), pt.data(), BN);
        batch_ok = batch_ok && memcmp(ref.data(), outs.data(), BN * 56) == 0;
    }
#endif
    printf("x448 batch == per-op check: %s\n", batch_ok ? "PASS" : "FAIL");
    if (!batch_ok) { g_sink ^= 0x448; }

    double jp_bat = auto_bench_batch("x448 batch N=1000 jpssl (dispatch)",
                                     "x448-batch", "jpssl-batch", 56, [&] {
        jpssl::x448_scalar_mult_batch(outs2d, sc.data(), pt.data(), BN);
        g_sink ^= outs[0];
    }, BN);
    if (feats.avx2) {
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
#if defined(JP_AVX512)
    if (feats.avx512) {
        double jp_bat_avx512 = auto_bench_batch("x448 batch N=1000 jpssl (avx512 显式)",
                                                "x448-batch", "jpssl-batch-avx512", 56, [&] {
            jpssl::x448_scalar_mult_batch_avx512(outs2d, sc.data(), pt.data(), BN);
            g_sink ^= outs[0];
        }, BN);
        (void)jp_bat_avx512;
    }
#endif
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

// ───────────────────────── P-256 / P-384 基准 ─────────────────────────

template <int NBYTES>
static void bench_pXXX(int nid, const char* algo, const char* label) {
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
    });
    std::snprintf(name, sizeof name, "%s keygen openssl", label);
    os_kg = auto_bench(name, algo_buf, "openssl", NBYTES, [&] {
        uint8_t p[NPUB], s[NBYTES];
        if (!ossl_ec_keygen(nid, p, s, NBYTES)) g_sink ^= 1;
        g_sink ^= p[0] ^ s[0];
    });

    EVP_PKEY* os_ours = ossl_ec_key_from_raw(nid, a_priv, NBYTES, a_pub, NPUB);
    EVP_PKEY* os_peer = ossl_ec_key_from_raw(nid, nullptr, 0, b_pub, NPUB);
    std::snprintf(name, sizeof name, "%s derive jpssl", label);
    std::snprintf(algo_buf, sizeof algo_buf, "%s-derive", algo);
    jp_dv = auto_bench(name, algo_buf, "jpssl", NBYTES, [&] {
        if constexpr (NBYTES == 32) jpssl::ecdsa_p256_ecdh(ss, a_priv, b_pub);
        else                        jpssl::ecdsa_p384_ecdh(ss, a_priv, b_pub);
        g_sink ^= ss[0];
    });
    std::snprintf(name, sizeof name, "%s derive openssl", label);
    os_dv = auto_bench(name, algo_buf, "openssl", NBYTES, [&] {
        ossl_ec_derive_keys(os_ours, os_peer, NBYTES, ss);
        g_sink ^= ss[0];
    });

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
    });
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
    });

    // 批量 N=1000: jpssl 批量 API vs openssl 循环
    constexpr int BN = 1000;
    std::vector<uint8_t> bp_priv(BN * NBYTES), bp_pub(BN * NPUB), bp_sh(BN * NBYTES);
    for (int i = 0; i < BN; ++i) {
        memcpy(bp_priv.data() + (size_t)i * NBYTES, a_priv, NBYTES);
        memcpy(bp_pub.data() + (size_t)i * NPUB, b_pub, NPUB);
    }
    // 正确性: 批量 == 逐条
    std::vector<uint8_t> ref(BN * NBYTES);
    for (int i = 0; i < BN; ++i) {
        if constexpr (NBYTES == 32)
            jpssl::ecdsa_p256_ecdh(ref.data() + (size_t)i * NBYTES, a_priv, b_pub);
        else
            jpssl::ecdsa_p384_ecdh(ref.data() + (size_t)i * NBYTES, a_priv, b_pub);
    }
    if constexpr (NBYTES == 32)
        jpssl::ecdsa_p256_ecdh_batch(bp_sh.data(), bp_priv.data(), bp_pub.data(), BN);
    else
        jpssl::ecdsa_p384_ecdh_batch(bp_sh.data(), bp_priv.data(), bp_pub.data(), BN);
    bool batch_ok = memcmp(ref.data(), bp_sh.data(), BN * NBYTES) == 0;
    printf("%s batch == per-op check: %s\n", label, batch_ok ? "PASS" : "FAIL");
    if (!batch_ok) { g_sink ^= NBYTES; }

    std::snprintf(name, sizeof name, "%s batch N=1000 jpssl (batch API)", label);
    jp_bat = auto_bench_batch(name, algo, "jpssl-batch", NBYTES, [&] {
        if constexpr (NBYTES == 32)
            jpssl::ecdsa_p256_ecdh_batch(bp_sh.data(), bp_priv.data(), bp_pub.data(), BN);
        else
            jpssl::ecdsa_p384_ecdh_batch(bp_sh.data(), bp_priv.data(), bp_pub.data(), BN);
        g_sink ^= bp_sh[0];
    }, BN);
    std::snprintf(name, sizeof name, "%s batch N=1000 openssl (loop)", label);
    os_bat = auto_bench_batch(name, algo, "openssl", NBYTES, [&] {
        for (int i = 0; i < BN; ++i)
            ossl_ec_derive_keys(os_ours, os_peer, NBYTES, bp_sh.data() + (size_t)i * NBYTES);
        g_sink ^= bp_sh[0];
    }, BN);

    printf("%s ratios (openssl/jpssl, >1 = jpssl 快): keygen %.2fx  derive %.2fx  "
           "full %.2fx  batch %.2fx\n",
           label, os_kg / jp_kg, os_dv / jp_dv, os_full / jp_full, os_bat / jp_bat);

    EVP_PKEY_free(os_ours);
    EVP_PKEY_free(os_peer);
}

// ───────────────────────── main ─────────────────────────

int main() {
    auto feats = jpssl::cpu_features::detect();
    printf("=== ECDH 密钥协商: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("CPU: AES-NI=%d AVX2=%d PCLMULQDQ=%d VAES=%d SHA-NI=%d ADX=%d AVX512=%d NEON=%d\n",
           feats.aesni, feats.avx2, feats.pclmulqdq, feats.vpclmulqdq_vaes, feats.sha_ni,
           jpssl::cpu_has_adx() ? 1 : 0, feats.avx512, feats.neon);

    // SKIP 说明 (本机特性不支持的多实现变体, 绝不调用)
    if (!feats.avx512) {
        printf("SKIP x25519 avx512 后端 : CPU 无 AVX512 (x25519_scalar_mult 走标量+ADX 内联路径)\n");
        printf("SKIP x448 batch avx512  : CPU 无 AVX512 (x448_scalar_mult_batch 派发到 AVX2)\n");
    }
    if (!feats.avx2) {
        printf("SKIP x448 batch avx2    : CPU 无 AVX2\n");
    }
    if (!feats.neon) {
        printf("SKIP NEON 变体          : 非 aarch64 主机\n");
    }

    std::filesystem::create_directories("benchmarks/results");
    g_csv = fopen("benchmarks/results/bench_ecdh_multi.csv", "w");
    if (g_csv) fprintf(g_csv, "algo,impl,size_bytes,ns_per_op,ops_per_sec\n");
    else printf("WARNING: 无法打开 CSV 输出文件\n");

    // 正确性自检 (FAIL 非零退出)
    bool all_ok = true;
    printf("\n--- 交叉验证自检 (共享密钥一致性) ---\n");
    all_ok = selfcheck_x25519() && all_ok;
    all_ok = selfcheck_x448() && all_ok;
    all_ok = selfcheck_pXXX<32>(NID_X9_62_prime256v1, "P-256") && all_ok;
    all_ok = selfcheck_pXXX<48>(NID_secp384r1, "P-384") && all_ok;
    if (!all_ok) {
        printf("SELF-CHECK FAILED — 共享密钥不一致, 基准结果不可信\n");
        if (g_csv) fclose(g_csv);
        return 1;
    }

    printf("\n%-34s %12s %14s\n", "case", "ns/op", "Kops/s");
    bench_x25519();
    bench_x448();
    bench_pXXX<32>(NID_X9_62_prime256v1, "p256", "P-256");
    bench_pXXX<48>(NID_secp384r1, "p384", "P-384");

    if (g_csv) {
        fclose(g_csv);
        printf("\nCSV 已写入: benchmarks/results/bench_ecdh_multi.csv\n");
    }
    printf("(sink=%d)\n", g_sink);
    return 0;
}

