// bench_ecdh_nist_unalign.cpp - ECDH-NIST (P-256 / P-384) 非对齐缓冲对比微基准
//
// 本程序是 benchmarks/bench_ecdh_nist.cpp 的非对齐(unalign)对照版:
// ECDH 数据是固定小缓冲 (P-256 32B / P-384 48B), 无长度维度,
// 非对齐维度 = 指针偏移:
//   私钥 / 公钥(x||y, 64/96B) / 共享密钥缓冲起始偏移 1/3/7/13;
//   batch 输入的偏移也测 (整组缓冲起始偏移)。
//
// 每条曲线 4 种操作 (与参考版相同):
//   keygen  : 单方密钥生成 (jpssl ecdsa_pXXX_keygen vs openssl EC keygen)
//   derive  : 固定密钥对的单边共享密钥派生 (jpssl ecdsa_pXXX_ecdh vs
//             OpenSSL EC_KEY + EVP_PKEY_derive; OpenSSL 侧从 jpssl 的 x||y
//             公钥构造 EC_KEY 再 derive)
//   full    : 完整协商 (双方 keygen + 双向 derive)
//   batch   : 批量 N=1000 (jpssl ecdsa_pXXX_ecdh_batch vs openssl 逐条循环),
//             CSV 记平均单条 ns/op
// 性能维度: offset ∈ {0, 3} (两曲线都测)。
//
// 正确性自检 (始终执行, 任一 FAIL 非零退出):
//   - 偏移缓冲下 jpssl / OpenSSL 交叉共享密钥一致 (且与 offset=0 一致)
//   - batch 每 op 与单次 derive 一致 (偏移缓冲下)
//   - 偏移 0 与偏移缓冲一致
//   offset ∈ {1, 3, 7, 13} 全覆盖。
//
// 环境变量:
//   BENCH_SMOKE=1  → ~80ms/轮, 仅 1 轮 (offset 仍为 {0,3})
//   未设置         → ~150ms/轮, 3 轮取最小
//
// 编译 (worktree 根执行):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_ecdh_nist_unalign.cpp \
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto \
//       -o /tmp/bench_ecdh_nist_unalign
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_ecdh_nist_unalign.csv
//       CSV 列头固定: algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec
//       (algo: p256-keygen-unalign / p256-derive-unalign / p256-full-unalign /
//              p256-batch-unalign 及 p384-*;
//        impl: jpssl / jpssl-batch / openssl;
//        size_bytes: 32 (p256) / 48 (p384))
//
// 结构复用自 benchmarks/bench_ecdh_nist.cpp 的 keygen/derive/full/batch 与
// OpenSSL 交叉验证 (x||y 构造 EC_KEY) + auto_bench + CSV 写法, 增加 offset 维度。

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

// 非对齐缓冲的填充: 偏移上限 13 + 冗余
static constexpr int UNALIGN_MAX_OFF = 13;
static constexpr int UNALIGN_PAD = 16;

static void csv_row(const char* algo, const char* impl, int size_bytes, int offset_bytes,
                    double ns) {
    if (g_csv)
        fprintf(g_csv, "%s,%s,%d,%d,%.1f,%.1f\n", algo, impl, size_bytes, offset_bytes,
                ns, 1e9 / ns);
}

// 自适应微基准: 每轮约 target_ms, rounds 轮取最小
template <typename F>
static double auto_bench(const char* name, const char* algo, const char* impl, int size_bytes,
                         int offset_bytes, F&& f, double target_ms, int rounds) {
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
    printf("%-40s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    csv_row(algo, impl, size_bytes, offset_bytes, best);
    return best;
}

// 批量基准: 每次调用处理 items_per_call 条, 自适应调用次数使每轮约 target_ms,
// rounds 轮取最小, 返回平均单条 ns (CSV 也按单条记)。
template <typename F>
static double auto_bench_batch(const char* name, const char* algo, const char* impl,
                               int size_bytes, int offset_bytes, F&& f, int items_per_call,
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
    printf("%-40s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    csv_row(algo, impl, size_bytes, offset_bytes, best);
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

// ───────────────────────── 正确性自检 (偏移缓冲 × OpenSSL 交叉验证) ─────────────────────────
//
// 每组检查独立计数 PASS/FAIL (任一 FAIL → 非零退出):
//   1) offset=0 对齐基线: jpssl per-op × openssl derive 一致 (双向同密钥)
//   2) offset=0 对齐基线: batch N=1000 == per-op
//   3) offset ∈ {1,3,7,13}: 偏移缓冲下 jpssl/openssl 交叉共享密钥一致,
//      且与 offset=0 基线一致
//   4) offset ∈ {1,3,7,13}: 偏移缓冲下 batch N=1000 每 op == 单次 derive,
//      且与 offset=0 基线 batch 一致
template <int NBYTES>
static bool selfcheck_pXXX(int nid, const char* label) {
    constexpr int NPUB = 2 * NBYTES;
    constexpr int BN = 1000;
    constexpr int OFFSETS[4] = {1, 3, 7, 13};
    bool ok = true;

    // ── offset=0 对齐基线 ──
    uint8_t a_priv[NBYTES], a_pub[NPUB], b_priv[NBYTES], b_pub[NPUB];
    if constexpr (NBYTES == 32) jpssl::ecdsa_p256_keygen(a_pub, a_priv);
    else                        jpssl::ecdsa_p384_keygen(a_pub, a_priv);
    bool kg = ossl_ec_keygen(nid, b_pub, b_priv, NBYTES);  // 独立实现生成 B

    uint8_t ref_ss[NBYTES], ref_ossl[NBYTES];
    if constexpr (NBYTES == 32) jpssl::ecdsa_p256_ecdh(ref_ss, a_priv, b_pub);
    else                        jpssl::ecdsa_p384_ecdh(ref_ss, a_priv, b_pub);
    EVP_PKEY* os_b = ossl_ec_key_from_raw(nid, b_priv, NBYTES, b_pub, NPUB);
    EVP_PKEY* os_a = ossl_ec_key_from_raw(nid, nullptr, 0, a_pub, NPUB);
    bool der = os_b && os_a && ossl_ec_derive_keys(os_b, os_a, NBYTES, ref_ossl);

    // offset=0 per-op 参考 (逐条) 与 batch 参考
    std::vector<uint8_t> ref_per(BN * NBYTES), bp0_priv(BN * NBYTES), bp0_pub(BN * NPUB),
                         bp0_sh(BN * NBYTES);
    for (int i = 0; i < BN; ++i) {
        memcpy(bp0_priv.data() + (size_t)i * NBYTES, a_priv, NBYTES);
        memcpy(bp0_pub.data() + (size_t)i * NPUB, b_pub, NPUB);
        if constexpr (NBYTES == 32)
            jpssl::ecdsa_p256_ecdh(ref_per.data() + (size_t)i * NBYTES, a_priv, b_pub);
        else
            jpssl::ecdsa_p384_ecdh(ref_per.data() + (size_t)i * NBYTES, a_priv, b_pub);
    }
    bool b0 = false;
    if constexpr (NBYTES == 32)
        b0 = jpssl::ecdsa_p256_ecdh_batch(bp0_sh.data(), bp0_priv.data(), bp0_pub.data(), BN);
    else
        b0 = jpssl::ecdsa_p384_ecdh_batch(bp0_sh.data(), bp0_priv.data(), bp0_pub.data(), BN);
    b0 = b0 && memcmp(ref_per.data(), bp0_sh.data(), BN * NBYTES) == 0;

    bool c0 = kg && der && memcmp(ref_ss, ref_ossl, NBYTES) == 0;
    if (c0) ++g_self_pass; else ++g_self_fail;
    printf("%s offset=0 cross-check (jpssl per-op × openssl derive): %s\n",
           label, c0 ? "PASS" : "FAIL");
    if (b0) ++g_self_pass; else ++g_self_fail;
    printf("%s offset=0 batch N=%d == per-op: %s\n", label, BN, b0 ? "PASS" : "FAIL");
    ok = ok && c0 && b0;

    // ── 偏移缓冲 (1/3/7/13) ──
    std::vector<uint8_t> oa_priv(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES),
                         oa_pub(UNALIGN_MAX_OFF + UNALIGN_PAD + NPUB),
                         ob_priv(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES),
                         ob_pub(UNALIGN_MAX_OFF + UNALIGN_PAD + NPUB),
                         oss(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES),
                         oos(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES);
    std::vector<uint8_t> bp_priv(BN * NBYTES + UNALIGN_MAX_OFF + UNALIGN_PAD),
                         bp_pub(BN * NPUB + UNALIGN_MAX_OFF + UNALIGN_PAD),
                         bp_sh(BN * NBYTES + UNALIGN_MAX_OFF + UNALIGN_PAD),
                         per_off(BN * NBYTES);

    for (int off : OFFSETS) {
        uint8_t* aPriv = oa_priv.data() + off;
        uint8_t* aPub = oa_pub.data() + off;
        uint8_t* bPriv = ob_priv.data() + off;
        uint8_t* bPub = ob_pub.data() + off;
        memcpy(aPriv, a_priv, NBYTES);
        memcpy(aPub, a_pub, NPUB);
        memcpy(bPriv, b_priv, NBYTES);
        memcpy(bPub, b_pub, NPUB);

        // 3) 偏移缓冲下 jpssl/openssl 交叉一致, 且与 offset=0 一致
        bool e1 = false, e2 = false;
        if constexpr (NBYTES == 32) e1 = jpssl::ecdsa_p256_ecdh(oss.data() + off, aPriv, bPub);
        else                        e1 = jpssl::ecdsa_p384_ecdh(oss.data() + off, aPriv, bPub);
        EVP_PKEY* o_b = ossl_ec_key_from_raw(nid, bPriv, NBYTES, bPub, NPUB);
        EVP_PKEY* o_a = ossl_ec_key_from_raw(nid, nullptr, 0, aPub, NPUB);
        e2 = o_b && o_a && ossl_ec_derive_keys(o_b, o_a, NBYTES, oos.data() + off);
        bool cross = e1 && e2
                  && memcmp(oss.data() + off, oos.data() + off, NBYTES) == 0
                  && memcmp(oss.data() + off, ref_ss, NBYTES) == 0
                  && memcmp(oos.data() + off, ref_ossl, NBYTES) == 0;
        if (cross) ++g_self_pass; else ++g_self_fail;
        printf("%s offset=%d cross (jpssl × openssl, == offset=0): %s\n",
               label, off, cross ? "PASS" : "FAIL");

        // 4) 偏移缓冲下 batch N=1000 每 op == 单次 derive, 且 == offset=0 batch
        for (int i = 0; i < BN; ++i) {
            memcpy(bp_priv.data() + off + (size_t)i * NBYTES, a_priv, NBYTES);
            memcpy(bp_pub.data() + off + (size_t)i * NPUB, b_pub, NPUB);
            if constexpr (NBYTES == 32)
                jpssl::ecdsa_p256_ecdh(per_off.data() + (size_t)i * NBYTES, aPriv, bPub);
            else
                jpssl::ecdsa_p384_ecdh(per_off.data() + (size_t)i * NBYTES, aPriv, bPub);
        }
        bool bo = false;
        if constexpr (NBYTES == 32)
            bo = jpssl::ecdsa_p256_ecdh_batch(bp_sh.data() + off, bp_priv.data() + off,
                                              bp_pub.data() + off, BN);
        else
            bo = jpssl::ecdsa_p384_ecdh_batch(bp_sh.data() + off, bp_priv.data() + off,
                                              bp_pub.data() + off, BN);
        bo = bo && memcmp(per_off.data(), bp_sh.data() + off, BN * NBYTES) == 0
               && memcmp(bp0_sh.data(), bp_sh.data() + off, BN * NBYTES) == 0;
        if (bo) ++g_self_pass; else ++g_self_fail;
        printf("%s offset=%d batch N=%d == per-op 且 == offset=0: %s\n",
               label, off, BN, bo ? "PASS" : "FAIL");
        ok = ok && cross && bo;

        EVP_PKEY_free(o_b);
        EVP_PKEY_free(o_a);
    }

    EVP_PKEY_free(os_b);
    EVP_PKEY_free(os_a);
    return ok;
}

// ───────────────────────── P-256 / P-384 非对齐基准 ─────────────────────────
//
// 每条曲线测 offset ∈ {0, 3} × {keygen, derive, full, batch};
// 私钥/公钥(x||y)/共享密钥缓冲均置于填充缓冲的 offset 处。
template <int NBYTES>
static void bench_pXXX(int nid, const char* algo, const char* label,
                       double target_ms, int rounds) {
    constexpr int NPUB = 2 * NBYTES;
    constexpr int BN = 1000;
    const int OFFSETS[2] = {0, 3};

    printf("\n--- %s ---\n", label);

    // 固定密钥对: 独立对齐源数组 (永不重叠复制), 逐 offset 复制到填充缓冲偏移槽位
    uint8_t a_priv0[NBYTES], a_pub0[NPUB], b_priv0[NBYTES], b_pub0[NPUB];
    std::vector<uint8_t> a_priv(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES),
                         a_pub(UNALIGN_MAX_OFF + UNALIGN_PAD + NPUB),
                         b_priv(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES),
                         b_pub(UNALIGN_MAX_OFF + UNALIGN_PAD + NPUB),
                         ss(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES);
    if constexpr (NBYTES == 32) {
        jpssl::ecdsa_p256_keygen(a_pub0, a_priv0);
        jpssl::ecdsa_p256_keygen(b_pub0, b_priv0);
    } else {
        jpssl::ecdsa_p384_keygen(a_pub0, a_priv0);
        jpssl::ecdsa_p384_keygen(b_pub0, b_priv0);
    }

    // keygen 用独立填充缓冲 (不破坏固定密钥对)
    std::vector<uint8_t> kg_pub(UNALIGN_MAX_OFF + UNALIGN_PAD + NPUB),
                         kg_priv(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES);
    // full 用填充缓冲
    std::vector<uint8_t> fa_pub(UNALIGN_MAX_OFF + UNALIGN_PAD + NPUB),
                         fa_priv(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES),
                         fb_pub(UNALIGN_MAX_OFF + UNALIGN_PAD + NPUB),
                         fb_priv(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES),
                         fsh1(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES),
                         fsh2(UNALIGN_MAX_OFF + UNALIGN_PAD + NBYTES);
    // batch 用填充缓冲
    std::vector<uint8_t> bp_priv(BN * NBYTES + UNALIGN_MAX_OFF + UNALIGN_PAD),
                         bp_pub(BN * NPUB + UNALIGN_MAX_OFF + UNALIGN_PAD),
                         bp_sh(BN * NBYTES + UNALIGN_MAX_OFF + UNALIGN_PAD);

    char name[96];
    char algo_buf[64];

    for (int off : OFFSETS) {
        printf("\n--- %s offset=%d ---\n", label, off);
        uint8_t* aPriv = a_priv.data() + off;
        uint8_t* aPub = a_pub.data() + off;
        uint8_t* bPriv = b_priv.data() + off;
        uint8_t* bPub = b_pub.data() + off;
        uint8_t* ssOff = ss.data() + off;
        // 从独立对齐源数组复制 (源与目标不重叠)
        memcpy(aPriv, a_priv0, NBYTES);
        memcpy(aPub, a_pub0, NPUB);
        memcpy(bPriv, b_priv0, NBYTES);
        memcpy(bPub, b_pub0, NPUB);

        // keygen (输出到偏移缓冲)
        std::snprintf(name, sizeof name, "%s offset=%d keygen jpssl", label, off);
        std::snprintf(algo_buf, sizeof algo_buf, "%s-keygen-unalign", algo);
        auto_bench(name, algo_buf, "jpssl", NBYTES, off, [&] {
            uint8_t* p = kg_pub.data() + off;
            uint8_t* s = kg_priv.data() + off;
            if constexpr (NBYTES == 32) jpssl::ecdsa_p256_keygen(p, s);
            else                        jpssl::ecdsa_p384_keygen(p, s);
            g_sink ^= p[0] ^ s[0];
        }, target_ms, rounds);
        std::snprintf(name, sizeof name, "%s offset=%d keygen openssl", label, off);
        auto_bench(name, algo_buf, "openssl", NBYTES, off, [&] {
            uint8_t* p = kg_pub.data() + off;
            uint8_t* s = kg_priv.data() + off;
            if (!ossl_ec_keygen(nid, p, s, NBYTES)) g_sink ^= 1;
            g_sink ^= p[0] ^ s[0];
        }, target_ms, rounds);

        // derive: 偏移缓冲的固定密钥对
        EVP_PKEY* os_ours = ossl_ec_key_from_raw(nid, aPriv, NBYTES, aPub, NPUB);
        EVP_PKEY* os_peer = ossl_ec_key_from_raw(nid, nullptr, 0, bPub, NPUB);
        std::snprintf(name, sizeof name, "%s offset=%d derive jpssl", label, off);
        std::snprintf(algo_buf, sizeof algo_buf, "%s-derive-unalign", algo);
        auto_bench(name, algo_buf, "jpssl", NBYTES, off, [&] {
            if constexpr (NBYTES == 32) jpssl::ecdsa_p256_ecdh(ssOff, aPriv, bPub);
            else                        jpssl::ecdsa_p384_ecdh(ssOff, aPriv, bPub);
            g_sink ^= ssOff[0];
        }, target_ms, rounds);
        std::snprintf(name, sizeof name, "%s offset=%d derive openssl", label, off);
        auto_bench(name, algo_buf, "openssl", NBYTES, off, [&] {
            ossl_ec_derive_keys(os_ours, os_peer, NBYTES, ssOff);
            g_sink ^= ssOff[0];
        }, target_ms, rounds);

        // full: 双方 keygen + 双向 derive (偏移缓冲)
        std::snprintf(name, sizeof name, "%s offset=%d full handshake jpssl", label, off);
        std::snprintf(algo_buf, sizeof algo_buf, "%s-full-unalign", algo);
        auto_bench(name, algo_buf, "jpssl", NBYTES, off, [&] {
            uint8_t *pa = fa_pub.data() + off, *sa = fa_priv.data() + off;
            uint8_t *pb = fb_pub.data() + off, *sb = fb_priv.data() + off;
            uint8_t *s1 = fsh1.data() + off, *s2 = fsh2.data() + off;
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
        std::snprintf(name, sizeof name, "%s offset=%d full handshake openssl", label, off);
        auto_bench(name, algo_buf, "openssl", NBYTES, off, [&] {
            uint8_t pa[NPUB], sa[NBYTES], pb[NPUB], sb[NBYTES];
            uint8_t *s1 = fsh1.data() + off, *s2 = fsh2.data() + off;
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

        // batch N=1000: jpssl 批量 API vs openssl 循环 (偏移缓冲)
        for (int i = 0; i < BN; ++i) {
            memcpy(bp_priv.data() + off + (size_t)i * NBYTES, aPriv, NBYTES);
            memcpy(bp_pub.data() + off + (size_t)i * NPUB, bPub, NPUB);
        }
        std::snprintf(name, sizeof name, "%s offset=%d batch N=%d jpssl (batch API)",
                      label, off, BN);
        std::snprintf(algo_buf, sizeof algo_buf, "%s-batch-unalign", algo);
        auto_bench_batch(name, algo_buf, "jpssl-batch", NBYTES, off, [&] {
            if constexpr (NBYTES == 32)
                jpssl::ecdsa_p256_ecdh_batch(bp_sh.data() + off, bp_priv.data() + off,
                                             bp_pub.data() + off, BN);
            else
                jpssl::ecdsa_p384_ecdh_batch(bp_sh.data() + off, bp_priv.data() + off,
                                             bp_pub.data() + off, BN);
            g_sink ^= bp_sh[off];
        }, BN, target_ms, rounds);
        std::snprintf(name, sizeof name, "%s offset=%d batch N=%d openssl (loop)",
                      label, off, BN);
        auto_bench_batch(name, algo_buf, "openssl", NBYTES, off, [&] {
            for (int i = 0; i < BN; ++i)
                ossl_ec_derive_keys(os_ours, os_peer, NBYTES,
                                    bp_sh.data() + off + (size_t)i * NBYTES);
            g_sink ^= bp_sh[off];
        }, BN, target_ms, rounds);

        EVP_PKEY_free(os_ours);
        EVP_PKEY_free(os_peer);
    }
}

// ───────────────────────── main ─────────────────────────

int main() {
    auto feats = jpssl::cpu_features::detect();
    const char* smoke_env = std::getenv("BENCH_SMOKE");
    bool smoke = smoke_env && std::strcmp(smoke_env, "1") == 0;
    const double target_ms = smoke ? 80.0 : 150.0;  // smoke: ~80ms/轮
    const int rounds = smoke ? 1 : 3;               // smoke: 1 轮; 全量: 3 轮取最小

    printf("=== ECDH-NIST unalign (P-256/P-384): jpssl vs OpenSSL (%s) ===\n",
           OPENSSL_VERSION_TEXT);
    printf("CPU: AES-NI=%d AVX2=%d PCLMULQDQ=%d VAES=%d SHA-NI=%d ADX=%d AVX512=%d NEON=%d\n",
           feats.aesni, feats.avx2, feats.pclmulqdq, feats.vpclmulqdq_vaes, feats.sha_ni,
           jpssl::cpu_has_adx() ? 1 : 0, feats.avx512, feats.neon);
    printf("BENCH_SMOKE=%d  (target %.0f ms/round, %d round%s, offsets {0,3})\n",
           smoke ? 1 : 0, target_ms, rounds, rounds == 1 ? "" : "s");

    std::filesystem::create_directories("benchmarks/results");
    g_csv = fopen("benchmarks/results/bench_ecdh_nist_unalign.csv", "w");
    if (g_csv)
        fprintf(g_csv, "algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec\n");
    else
        printf("WARNING: 无法打开 CSV 输出文件\n");

    // 正确性自检 (始终执行, FAIL 非零退出)
    printf("\n--- 非对齐自检 (偏移 1/3/7/13 全覆盖, 交叉验证共享密钥一致性) ---\n");
    bool all_ok = true;
    all_ok = selfcheck_pXXX<32>(NID_X9_62_prime256v1, "P-256") && all_ok;
    all_ok = selfcheck_pXXX<48>(NID_secp384r1, "P-384") && all_ok;
    printf("self-check: %d PASS, %d FAIL\n", g_self_pass, g_self_fail);
    if (!all_ok) {
        printf("SELF-CHECK FAILED — 偏移缓冲下共享密钥不一致, 基准结果不可信\n");
        if (g_csv) fclose(g_csv);
        return 1;
    }

    printf("\n%-40s %12s %14s\n", "case", "ns/op", "Kops/s");
    bench_pXXX<32>(NID_X9_62_prime256v1, "p256", "P-256", target_ms, rounds);
    bench_pXXX<48>(NID_secp384r1, "p384", "P-384", target_ms, rounds);

    if (g_csv) {
        fclose(g_csv);
        printf("\nCSV 已写入: benchmarks/results/bench_ecdh_nist_unalign.csv\n");
    }
    printf("(sink=%d)\n", g_sink);
    return 0;
}
