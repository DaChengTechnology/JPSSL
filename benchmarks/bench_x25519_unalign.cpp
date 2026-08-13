// bench_x25519_unalign.cpp - X25519 ECDH 非对齐测试对比组 (与 OpenSSL 对比)
//
// 非对齐维度 (ECDH 为固定 32B 小缓冲, 无长度维度) = 输入/输出指针偏移 bufferoffset:
//   1. 偏移 bufferoffset: 私钥/公钥/共享密钥缓冲区起始偏移 1/3/7/13 (alloc size+offset+16)
//      性能测 offset=0 与 3 (keygen/derive/full/batch), 自检 1/3/7/13 全覆盖
//   2. 自检 (始终执行, FAIL 非零退出):
//      - RFC 7748 §6.1 已知向量在偏移 1/3/7/13 (及基线 0) 下仍 PASS (jpssl == openssl == 官方共享密钥)
//      - 偏移缓冲下 jpssl/OpenSSL 交叉共享密钥一致 (双向同密钥)
//      - 偏移 0 与偏移缓冲派生结果一致
//      - keygen 一致性: 偏移下 keygen 公钥 == scalar_mult(私钥, 基点)
//   3. 性能基准: op=keygen/derive/full/batch × offset {0,3} × impl {jpssl,openssl}
//      BENCH_SMOKE=1 -> 每 op 目标 ~80ms (160ms 目标再减半)、1 轮;
//      未设置 -> 每 op ~150ms、3 轮取最小。自检始终执行。
//
// CSV: benchmarks/results/bench_x25519_unalign.csv
//   列头: algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec
//   algo: x25519-keygen-unalign / x25519-derive-unalign / x25519-full-unalign / x25519-batch-unalign
//   impl: jpssl / openssl; size_bytes = 32 (共享密钥长度)
//
// 编译 (worktree 根执行):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_x25519_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_x25519_unalign
// 运行 (worktree 根执行):
//   BENCH_SMOKE=1 /tmp/bench_x25519_unalign

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

static void csv_row(const char* algo, const char* impl, int size_bytes, int offset_bytes, double ns) {
    if (g_csv) fprintf(g_csv, "%s,%s,%d,%d,%.1f,%.1f\n", algo, impl, size_bytes, offset_bytes, ns, 1e9 / ns);
}

// ───────────────────────── smoke / 全量 控制 ─────────────────────────

static bool g_smoke = false;

// 每轮约 target_ms (全量默认 150ms), 3 轮取最小; smoke 模式: 迭代减半、1 轮 (有效 ~target/2 ms)
template <typename F>
static double auto_bench(const char* name, const char* algo, const char* impl, int size_bytes,
                         int offset_bytes, F&& f, double target_ms, int rounds) {
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
    printf("%-40s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    csv_row(algo, impl, size_bytes, offset_bytes, best);
    return best;
}

// 批量基准: 每次调用处理 items_per_call 条, 3 轮取最小, 返回平均单条 ns (smoke: 迭代减半、1 轮)
template <typename F>
static double auto_bench_batch(const char* name, const char* algo, const char* impl,
                               int size_bytes, int offset_bytes, F&& f, int items_per_call,
                               double target_ms) {
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
    printf("%-40s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    csv_row(algo, impl, size_bytes, offset_bytes, best);
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
    printf("%-44s: %s\n", name, ok ? "PASS" : "FAIL");
    if (ok) ++g_pass; else ++g_fail;
}

// 把 32B 固定向量装入偏移缓冲 (alloc = size + offset + 16)
static void load_vec(uint8_t* buf, int ofs, const uint8_t v[32]) {
    memcpy(buf + ofs, v, 32);
}

// RFC 7748 §6.1 已知向量在偏移 {0,1,3,7,13} 下仍 PASS (jpssl == openssl == 官方共享密钥)
static bool selfcheck_rfc7748_unalign() {
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
    bool ok_all = true;
    const int offs[] = {0, 1, 3, 7, 13};
    for (int ofs : offs) {
        std::vector<uint8_t> ap_b(32 + ofs + 16), bp_b(32 + ofs + 16);
        std::vector<uint8_t> ss_b(32 + ofs + 16), ss_o_b(32 + ofs + 16);
        load_vec(ap_b.data(), ofs, alice_priv);
        load_vec(bp_b.data(), ofs, bob_pub);
        uint8_t* ss = ss_b.data() + ofs;
        uint8_t* ss_o = ss_o_b.data() + ofs;
        jpssl::x25519_scalar_mult(ss, ap_b.data() + ofs, bp_b.data() + ofs);
        bool ok = ossl_raw_derive(ap_b.data() + ofs, bp_b.data() + ofs, 32, ss_o)
               && memcmp(ss, ss_o, 32) == 0 && memcmp(ss, expected_ss, 32) == 0;
        char nm[80];
        snprintf(nm, sizeof nm, "RFC 7748 §6.1 @offset=%d (jpssl==openssl==官方)", ofs);
        check(nm, ok);
        ok_all = ok_all && ok;
    }
    return ok_all;
}

// 偏移 {1,3,7,13} 下:
//   a) jpssl/OpenSSL 交叉共享密钥一致 (双向同密钥)
//   b) keygen 一致性: 偏移下 keygen 公钥 == scalar_mult(私钥, 基点)
//   c) 偏移 0 与偏移缓冲派生结果一致 (同密钥对位对拍)
static bool selfcheck_cross_unalign() {
    bool ok_all = true;
    const int offs[] = {1, 3, 7, 13};
    for (int ofs : offs) {
        std::vector<uint8_t> ja_priv_b(32 + ofs + 16), ja_pub_b(32 + ofs + 16);
        std::vector<uint8_t> bo_priv_b(32 + ofs + 16), bo_pub_b(32 + ofs + 16);
        std::vector<uint8_t> ss_jp_b(32 + ofs + 16), ss_os_b(32 + ofs + 16), ss_rev_b(32 + ofs + 16);
        uint8_t* ja_priv = ja_priv_b.data() + ofs;
        uint8_t* ja_pub  = ja_pub_b.data() + ofs;
        uint8_t* bo_priv = bo_priv_b.data() + ofs;
        uint8_t* bo_pub  = bo_pub_b.data() + ofs;
        uint8_t* ss_jp  = ss_jp_b.data() + ofs;
        uint8_t* ss_os  = ss_os_b.data() + ofs;
        uint8_t* ss_rev = ss_rev_b.data() + ofs;
        char nm[80];

        // a) 交叉: jpssl 私钥+openssl 公钥 vs openssl 私钥+jpssl 公钥 -> 相同共享密钥
        jpssl::x25519_generate_keypair(ja_pub, ja_priv);
        bool ok = ossl_raw_keygen(bo_priv, bo_pub, 32);
        jpssl::x25519_scalar_mult(ss_jp, ja_priv, bo_pub);
        ok = ok && ossl_raw_derive(bo_priv, ja_pub, 32, ss_os);
        jpssl::x25519_scalar_mult(ss_rev, bo_priv, ja_pub);   // 反向同密钥
        ok = ok && memcmp(ss_jp, ss_os, 32) == 0 && memcmp(ss_jp, ss_rev, 32) == 0;
        snprintf(nm, sizeof nm, "交叉验证 jpssl×openssl @offset=%d 双向同密钥", ofs);
        check(nm, ok);
        ok_all = ok_all && ok;

        // b) keygen 一致性 @offset
        uint8_t pk[32];
        jpssl::x25519_scalar_mult(pk, ja_priv, nullptr);      // nullptr = 基点
        bool okk = memcmp(pk, ja_pub, 32) == 0;
        snprintf(nm, sizeof nm, "keygen 一致性 @offset=%d 公钥==标量×基点", ofs);
        check(nm, okk);
        ok_all = ok_all && okk;

        // c) 偏移 0 与偏移缓冲结果一致: 同私钥/对端公钥, offset0 派生 == offset 缓冲派生
        std::vector<uint8_t> jp0_b(32), bo0_b(32), ss0_b(32);
        memcpy(jp0_b.data(), ja_priv, 32);
        memcpy(bo0_b.data(), bo_pub, 32);
        jpssl::x25519_scalar_mult(ss0_b.data(), jp0_b.data(), bo0_b.data());
        bool ok0 = memcmp(ss0_b.data(), ss_jp, 32) == 0;
        snprintf(nm, sizeof nm, "偏移0 == 偏移%d 派生结果一致", ofs);
        check(nm, ok0);
        ok_all = ok_all && ok0;
    }
    return ok_all;
}

// ───────────────────────── 非对齐基准 ─────────────────────────

static void bench_unalign() {
    printf("\n--- X25519 非对齐 (offset {0,3}) ---\n");
    const int offs[] = {0, 3};
    for (int ofs : offs) {
        // 偏移缓冲 (alloc = size + offset + 16)
        std::vector<uint8_t> a_priv_b(32 + ofs + 16), a_pub_b(32 + ofs + 16);
        std::vector<uint8_t> b_priv_b(32 + ofs + 16), b_pub_b(32 + ofs + 16);
        std::vector<uint8_t> ss_b(32 + ofs + 16), ss2_b(32 + ofs + 16);
        uint8_t* a_priv = a_priv_b.data() + ofs;
        uint8_t* a_pub  = a_pub_b.data() + ofs;
        uint8_t* b_priv = b_priv_b.data() + ofs;
        uint8_t* b_pub  = b_pub_b.data() + ofs;
        uint8_t* ss  = ss_b.data() + ofs;
        uint8_t* ss2 = ss2_b.data() + ofs;
        jpssl::x25519_generate_keypair(a_pub, a_priv);
        jpssl::x25519_generate_keypair(b_pub, b_priv);

        char nm[96];
        // smoke: 目标 160ms 再减半 -> 有效 ~80ms/op、1 轮; 全量: ~150ms、3 轮取最小
        double target = g_smoke ? 160.0 : 150.0;

        // keygen
        snprintf(nm, sizeof nm, "x25519 keygen jpssl   @off=%d", ofs);
        double jp_kg = auto_bench(nm, "x25519-keygen-unalign", "jpssl", 32, ofs, [&] {
            jpssl::x25519_generate_keypair(a_pub, a_priv);   // 写入偏移缓冲
            g_sink ^= a_pub[0] ^ a_priv[0];
        }, target, 3);
        snprintf(nm, sizeof nm, "x25519 keygen openssl @off=%d", ofs);
        double os_kg = auto_bench(nm, "x25519-keygen-unalign", "openssl", 32, ofs, [&] {
            if (!ossl_raw_keygen(b_priv, b_pub, 32)) g_sink ^= 1;
            g_sink ^= b_pub[0] ^ b_priv[0];
        }, target, 3);

        // derive
        snprintf(nm, sizeof nm, "x25519 derive jpssl   @off=%d", ofs);
        double jp_dv = auto_bench(nm, "x25519-derive-unalign", "jpssl", 32, ofs, [&] {
            jpssl::x25519_scalar_mult(ss, a_priv, b_pub);
            g_sink ^= ss[0];
        }, target, 3);
        EVP_PKEY* os_ours = ossl_raw_priv(a_priv, 32);
        EVP_PKEY* os_peer = ossl_raw_pub(b_pub, 32);
        snprintf(nm, sizeof nm, "x25519 derive openssl @off=%d", ofs);
        double os_dv = auto_bench(nm, "x25519-derive-unalign", "openssl", 32, ofs, [&] {
            ossl_raw_derive_keys(os_ours, os_peer, 32, ss);
            g_sink ^= ss[0];
        }, target, 3);

        // full: 双方 keygen + 双向 derive (偏移缓冲)
        snprintf(nm, sizeof nm, "x25519 full jpssl     @off=%d", ofs);
        double jp_full = auto_bench(nm, "x25519-full-unalign", "jpssl", 32, ofs, [&] {
            jpssl::x25519_generate_keypair(a_pub, a_priv);
            jpssl::x25519_generate_keypair(b_pub, b_priv);
            jpssl::x25519_scalar_mult(ss, a_priv, b_pub);
            jpssl::x25519_scalar_mult(ss2, b_priv, a_pub);
            g_sink ^= ss[0] ^ ss2[0];
        }, target, 3);
        snprintf(nm, sizeof nm, "x25519 full openssl   @off=%d", ofs);
        double os_full = auto_bench(nm, "x25519-full-unalign", "openssl", 32, ofs, [&] {
            EVP_PKEY* ka = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
            EVP_PKEY* kb = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
            size_t l;
            l = 32; EVP_PKEY_get_raw_private_key(ka, a_priv, &l);
            l = 32; EVP_PKEY_get_raw_public_key(ka, a_pub, &l);
            l = 32; EVP_PKEY_get_raw_private_key(kb, b_priv, &l);
            l = 32; EVP_PKEY_get_raw_public_key(kb, b_pub, &l);
            EVP_PKEY* oa = ossl_raw_priv(a_priv, 32);
            EVP_PKEY* oap = ossl_raw_pub(b_pub, 32);
            EVP_PKEY* ob = ossl_raw_priv(b_priv, 32);
            EVP_PKEY* obp = ossl_raw_pub(a_pub, 32);
            ossl_raw_derive_keys(oa, oap, 32, ss);
            ossl_raw_derive_keys(ob, obp, 32, ss2);
            EVP_PKEY_free(oa); EVP_PKEY_free(oap);
            EVP_PKEY_free(ob); EVP_PKEY_free(obp);
            EVP_PKEY_free(ka); EVP_PKEY_free(kb);
            g_sink ^= ss[0] ^ ss2[0];
        }, target, 3);

        // 批量 N=1000 (X25519 无批量 API → 双方均循环派生, 单条平均)
        constexpr int BN = 1000;
        std::vector<uint8_t> bsh_b(BN * 32 + ofs + 16);
        uint8_t* bsh = bsh_b.data() + ofs;
        bool batch_ok = true;
        for (int i = 0; i < BN; ++i)
            jpssl::x25519_scalar_mult(bsh + (size_t)i * 32, a_priv, b_pub);
        for (int i = 0; i < BN; ++i) {
            uint8_t ref[32];
            jpssl::x25519_scalar_mult(ref, a_priv, b_pub);
            batch_ok = batch_ok && memcmp(bsh + (size_t)i * 32, ref, 32) == 0;
        }
        EVP_PKEY* os_bours = ossl_raw_priv(a_priv, 32);
        EVP_PKEY* os_bpeer = ossl_raw_pub(b_pub, 32);
        for (int i = 0; i < BN; ++i)
            batch_ok = batch_ok && ossl_raw_derive_keys(os_bours, os_bpeer, 32, bsh + (size_t)i * 32);
        for (int i = 0; i < BN; ++i) {
            uint8_t ref[32];
            jpssl::x25519_scalar_mult(ref, a_priv, b_pub);
            batch_ok = batch_ok && memcmp(bsh + (size_t)i * 32, ref, 32) == 0;
        }
        snprintf(nm, sizeof nm, "batch N=1000 批量==逐条 @off=%d (同输出)", ofs);
        check(nm, batch_ok);
        if (!batch_ok) g_sink ^= 0x25519;

        snprintf(nm, sizeof nm, "x25519 batch jpssl   @off=%d", ofs);
        double jp_bat = auto_bench_batch(nm, "x25519-batch-unalign", "jpssl", 32, ofs, [&] {
            for (int i = 0; i < BN; ++i)
                jpssl::x25519_scalar_mult(bsh + (size_t)i * 32, a_priv, b_pub);
            g_sink ^= bsh[0];
        }, BN, target);
        snprintf(nm, sizeof nm, "x25519 batch openssl @off=%d", ofs);
        double os_bat = auto_bench_batch(nm, "x25519-batch-unalign", "openssl", 32, ofs, [&] {
            for (int i = 0; i < BN; ++i)
                ossl_raw_derive_keys(os_bours, os_bpeer, 32, bsh + (size_t)i * 32);
            g_sink ^= bsh[0];
        }, BN, target);

        printf("offset=%d ratios (openssl/jpssl, >1 = jpssl 快): keygen %.2fx  derive %.2fx  "
               "full %.2fx  batch %.2fx\n",
               ofs, os_kg / jp_kg, os_dv / jp_dv, os_full / jp_full, os_bat / jp_bat);

        EVP_PKEY_free(os_ours);
        EVP_PKEY_free(os_peer);
        EVP_PKEY_free(os_bours);
        EVP_PKEY_free(os_bpeer);
    }
}

// ───────────────────────── main ─────────────────────────

int main() {
    g_smoke = std::getenv("BENCH_SMOKE") != nullptr;
    auto feats = jpssl::cpu_features::detect();
    printf("=== X25519 ECDH 非对齐对比: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("mode: %s\n", g_smoke ? "SMOKE (每 op ~80ms, 1 轮)" : "full (每 op ~150ms, 3 轮取最小)");
    printf("CPU: AES-NI=%d AVX2=%d PCLMULQDQ=%d VAES=%d SHA-NI=%d ADX=%d AVX512=%d NEON=%d\n",
           feats.aesni, feats.avx2, feats.pclmulqdq, feats.vpclmulqdq_vaes, feats.sha_ni,
           jpssl::cpu_has_adx() ? 1 : 0, feats.avx512, feats.neon);
    if (!feats.avx512) {
        printf("SKIP x25519 avx512 后端: CPU 无 AVX512 (走标量+ADX 内联路径)\n");
    }

    std::filesystem::create_directories("benchmarks/results");
    g_csv = fopen("benchmarks/results/bench_x25519_unalign.csv", "w");
    if (g_csv) fprintf(g_csv, "algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec\n");
    else printf("WARNING: 无法打开 CSV 输出文件\n");

    // 正确性自检 (FAIL 非零退出, 始终执行; 偏移 1/3/7/13 全覆盖 + 基线 0)
    printf("\n--- 非对齐自检 (偏移 1/3/7/13) ---\n");
    bool all_ok = selfcheck_rfc7748_unalign();
    all_ok = selfcheck_cross_unalign() && all_ok;

    printf("\n--- 基准: op × offset {0,3} ---\n");
    printf("%-40s %12s %14s\n", "case", "ns/op", "Kops/s");
    bench_unalign();   // 内含 batch==逐条 自检

    printf("\nself-check: %d PASS, %d FAIL\n", g_pass, g_fail);
    if (!all_ok || g_fail > 0) {
        printf("\nSELF-CHECK FAILED (%d FAIL) — 非对齐共享密钥不一致, 基准结果不可信\n", g_fail);
        if (g_csv) fclose(g_csv);
        return 1;
    }

    if (g_csv) {
        fclose(g_csv);
        printf("\nCSV 已写入: benchmarks/results/bench_x25519_unalign.csv\n");
    }
    printf("(sink=%d)\n", g_sink);
    return 0;
}
