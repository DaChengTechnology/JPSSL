// bench_x448_unalign.cpp - X448 ECDH 非对齐测试对比组 (与 OpenSSL 对比)
//
// 本文件是 bench_x448.cpp 的非对齐变体: ECDH 数据是固定 56B 小缓冲, 无长度维度,
// 非对齐维度 = 指针偏移。所有输入(私钥/公钥)与输出(共享密钥)缓冲起始偏移
// 1/3/7/13 字节, 检查 jpssl 与 OpenSSL 在偏移缓冲下行为是否一致。
//
// 多实现 × OpenSSL 对比 (每个 offset):
//   jpssl              单次公开 API (x448_generate_keypair / x448_scalar_mult)
//   jpssl-batch        x448_scalar_mult_batch (运行时自动派发: AVX512=8 / AVX2=4 / scalar=1)
//   jpssl-batch-avx2   显式 AVX2 变体 (CPU 无 AVX2 → SKIP, 绝不调用)
//   openssl            EVP_PKEY raw keygen + derive
//
// 自检 (始终执行, 任一 FAIL 非零退出):
//   * 偏移缓冲下 jpssl × OpenSSL 交叉共享密钥一致 (双向) 且与 offset=0 一致
//   * batch (dispatch 与 avx2 显式) 在偏移下与 per-op 逐字节一致, 且与 offset=0 一致
//   * 特别关注 AVX2 batch 对输入/输出对齐的要求: 每个偏移下的 batch 自检在
//     fork 的子进程中执行 —— 若 AVX2 batch 在非对齐输入下崩溃(SIGSEGV 等),
//     记录为 FAIL (CRASH) 而非使整个程序死亡, 照常以非零码退出 (有效发现, 不绕过)
//   * avx512 变体: CPU 无 AVX512 → SKIP, 绝不调用
//
// 性能基准: op=keygen/derive/full/batch × offset {0,3};
//   BENCH_SMOKE=1 → offset {0,3}, ~80ms/轮, 1 轮; 未设置 → ~150ms/轮, 3 轮取最小。
//   自检不受影响, 始终执行。
//
// 编译 (worktree 根执行):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES
//       -Iinclude -Isrc benchmarks/bench_x448_unalign.cpp
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto
//       -o /tmp/bench_x448_unalign
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_x448_unalign.csv
//       CSV 列头固定: algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec
//       algo: x448-keygen-unalign / x448-derive-unalign / x448-full-unalign /
//             x448-batch-unalign; size_bytes=56; offset_bytes=指针起始偏移

#include "cpu_features.hpp"
#include "x448.hpp"

#include <openssl/evp.h>

#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using Clock = std::chrono::steady_clock;

// 非对齐自检偏移集 (全覆盖) 与性能基准偏移集
static const int kSelfcheckOffsets[] = {0, 1, 3, 7, 13};
static const int kPerfOffsets[] = {0, 3};
static constexpr int kX448Len = 56;

// 阻止编译器把纯函数调用优化掉
static volatile int g_sink = 0;
static FILE* g_csv = nullptr;
static bool g_smoke = false;
static int g_selfcheck_pass = 0;
static int g_selfcheck_fail = 0;

static void csv_row(const char* algo, const char* impl, int size_bytes, int offset_bytes,
                    double ns) {
    if (g_csv) fprintf(g_csv, "%s,%s,%d,%d,%.1f,%.1f\n", algo, impl, size_bytes, offset_bytes, ns,
                       1e9 / ns);
}

// 自适应微基准: 每轮约 target_ms, rounds 轮取最小 (参考 bench_x448.cpp 写法;
// smoke 模式 target_ms 缩短 + 只跑 1 轮)。
template <typename F>
static double auto_bench(const char* name, const char* algo, const char* impl, int size_bytes,
                         int offset_bytes, F&& f) {
    const double target_ms = g_smoke ? 80.0 : 150.0;
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
    printf("%-44s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    csv_row(algo, impl, size_bytes, offset_bytes, best);
    return best;
}

// 批量基准: 每次调用处理 items_per_call 条, 返回平均单条 ns。
template <typename F>
static double auto_bench_batch(const char* name, const char* algo, const char* impl,
                               int size_bytes, int offset_bytes, F&& f, int items_per_call) {
    const double target_ms = g_smoke ? 80.0 : 150.0;
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
    printf("%-44s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    csv_row(algo, impl, size_bytes, offset_bytes, best);
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

// ───────────────────────── 自检 (含 fork 崩溃隔离) ─────────────────────────

static void record_check(const char* what, bool ok) {
    printf("%s: %s\n", what, ok ? "PASS" : "FAIL");
    if (ok) ++g_selfcheck_pass; else ++g_selfcheck_fail;
    if (!ok) g_sink ^= 0x448;
}

// 崩溃探针: 在 fork 的子进程中执行一次相同的非对齐调用, 仅检测该调用是否
// 因信号崩溃 (如 AVX2 batch 对非对齐缓冲使用对齐指令触发 SIGSEGV/SIGILL)。
// 探针存活只说明"不崩溃", 结果正确性由父进程真实执行 + 逐字节比对决定;
// 探针崩溃 → 该检查记 CRASH → FAIL, 父进程跳过真实执行 (同样的调用必然再崩),
// 整个程序照常继续并以非零码退出 —— 这是对"非对齐崩溃"关键发现的如实记录。
enum class IsoRes { PASS, FAIL, CRASH };

static IsoRes run_crash_probe(const std::function<void()>& fn) {
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        // fork 不可用: 假定不崩溃, 由父进程真实执行决定 PASS/FAIL
        return IsoRes::PASS;
    }
    if (pid == 0) {
        try {
            fn();
        } catch (...) {
        }
        _exit(0);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return IsoRes::PASS;
    if (WIFSIGNALED(st)) return IsoRes::CRASH;
    return IsoRes::PASS;
}

static void record_iso(const char* what, IsoRes r) {
    switch (r) {
        case IsoRes::PASS: record_check(what, true); break;
        case IsoRes::FAIL: record_check(what, false); break;
        case IsoRes::CRASH:
            printf("%s: FAIL (子进程崩溃于非对齐执行, 已隔离)\n", what);
            ++g_selfcheck_fail;
            g_sink ^= 0x448;
            break;
    }
}

// 非对齐自检主流程
static void selfcheck_unalign() {
    // 基准密钥对 (offset=0, 对齐)
    uint8_t ja_priv[kX448Len], ja_pub[kX448Len], bo_priv[kX448Len], bo_pub[kX448Len];
    jpssl::x448_generate_keypair(ja_pub, ja_priv);
    bool ok0 = ossl_raw_keygen(EVP_PKEY_X448, "X448", bo_priv, bo_pub, kX448Len);
    record_check("OpenSSL X448 keygen (baseline)", ok0);
    uint8_t ss0[kX448Len];
    jpssl::x448_scalar_mult(ss0, ja_priv, bo_pub);

    constexpr int BN = 1000;
    // 批量输出/参考块: 前 64B 用作偏移区, 行距 56B
    std::vector<uint8_t> outs((size_t)BN * kX448Len + 64);      // dispatch 结果
    std::vector<uint8_t> outs_avx2((size_t)BN * kX448Len + 64); // avx2 显式结果
    std::vector<uint8_t> refs((size_t)BN * kX448Len + 64);
    std::vector<uint8_t> outs0((size_t)BN * kX448Len + 64);   // dispatch offset=0 结果
    std::vector<uint8_t> outs0_avx2((size_t)BN * kX448Len + 64);  // avx2 offset=0 结果
    std::vector<const uint8_t*> sc((size_t)BN), pt((size_t)BN);

    for (int off : kSelfcheckOffsets) {
        printf("\n--- 非对齐自检 offset=%d ---\n", off);

        // 偏移缓冲 (alignas(64) 基址 + off → 非对齐指针)
        alignas(64) uint8_t ja_priv_b[kX448Len + 32], ja_pub_b[kX448Len + 32];
        alignas(64) uint8_t bo_priv_b[kX448Len + 32], bo_pub_b[kX448Len + 32];
        memcpy(ja_priv_b + off, ja_priv, kX448Len);
        memcpy(ja_pub_b + off, ja_pub, kX448Len);
        memcpy(bo_priv_b + off, bo_priv, kX448Len);
        memcpy(bo_pub_b + off, bo_pub, kX448Len);

        // 交叉共享密钥 (偏移缓冲): jpssl priv × openssl pub, 双向同密钥, 且 == offset 0
        alignas(64) uint8_t ss_jp[kX448Len + 32], ss_ossl[kX448Len + 32], ss_jp2[kX448Len + 32];
        uint8_t* ssj = ss_jp + off;
        uint8_t* sso = ss_ossl + off;
        uint8_t* ssj2 = ss_jp2 + off;
        jpssl::x448_scalar_mult(ssj, ja_priv_b + off, bo_pub_b + off);
        bool cross = ossl_raw_derive(EVP_PKEY_X448, bo_priv_b + off, ja_pub_b + off, kX448Len, sso);
        jpssl::x448_scalar_mult(ssj2, bo_priv_b + off, ja_pub_b + off);
        cross = cross && memcmp(ssj, sso, kX448Len) == 0 && memcmp(ssj, ssj2, kX448Len) == 0;
        record_iso(("X448 cross-check off=" + std::to_string(off) + " (jpssl×openssl 双向一致)").c_str(),
                   cross ? IsoRes::PASS : IsoRes::FAIL);
        bool same0 = memcmp(ssj, ss0, kX448Len) == 0;
        record_check(("X448 derive off=" + std::to_string(off) + " == off0").c_str(), same0);

        // 批量: per-op 参考 (偏移缓冲)
        for (int i = 0; i < BN; ++i) {
            sc[(size_t)i] = ja_priv_b + off;
            pt[(size_t)i] = bo_pub_b + off;
            jpssl::x448_scalar_mult(refs.data() + off + (size_t)i * kX448Len, sc[(size_t)i],
                                    pt[(size_t)i]);
        }
        uint8_t(*outs2d)[kX448Len] =
            reinterpret_cast<uint8_t(*)[kX448Len]>(outs.data() + off);
        uint8_t(*outs2d_avx2)[kX448Len] =
            reinterpret_cast<uint8_t(*)[kX448Len]>(outs_avx2.data() + off);

        // dispatch 变体: 子进程崩溃探针 (非对齐崩溃 → CRASH/FAIL), 然后父进程
        // 真实执行并逐字节比对 (子进程的写对父进程不可见, 必须父进程真跑)。
        std::function<void()> run_disp = [&]() {
            jpssl::x448_scalar_mult_batch(outs2d, sc.data(), pt.data(), BN);
        };
        IsoRes probe_disp = run_crash_probe(run_disp);
        if (probe_disp == IsoRes::CRASH) {
            record_iso(("X448 batch(dispatch) off=" + std::to_string(off) + " == per-op").c_str(),
                       IsoRes::CRASH);
        } else {
            run_disp();
            bool ok = memcmp(refs.data() + off, outs.data() + off, (size_t)BN * kX448Len) == 0;
            record_iso(("X448 batch(dispatch) off=" + std::to_string(off) + " == per-op").c_str(),
                       ok ? IsoRes::PASS : IsoRes::FAIL);
        }

        // avx2 显式变体 (CPU 无 AVX2 → SKIP; 同样探针 + 父进程真跑)
        if (jpssl::cpu_has_avx2()) {
            std::function<void()> run_avx2 = [&]() {
#if defined(JP_AVX2)
                jpssl::x448_scalar_mult_batch_avx2(outs2d_avx2, sc.data(), pt.data(), BN);
#else
                jpssl::x448_scalar_mult_batch(outs2d_avx2, sc.data(), pt.data(), BN);
#endif
            };
            IsoRes probe_avx2 = run_crash_probe(run_avx2);
            if (probe_avx2 == IsoRes::CRASH) {
                record_iso(("X448 batch(avx2 显式) off=" + std::to_string(off) + " == per-op").c_str(),
                           IsoRes::CRASH);
            } else {
                run_avx2();
                bool ok =
                    memcmp(refs.data() + off, outs_avx2.data() + off, (size_t)BN * kX448Len) == 0;
                record_iso(("X448 batch(avx2 显式) off=" + std::to_string(off) + " == per-op").c_str(),
                           ok ? IsoRes::PASS : IsoRes::FAIL);
            }
        } else {
            printf("SKIP x448 batch avx2 显式变体自检 (offset=%d): CPU 无 AVX2\n", off);
        }

        // 偏移 0 与偏移缓冲一致 (batch)
        if (off == 0) {
            // 保存 offset=0 的 dispatch/avx2 结果, 供后续偏移比对
            memcpy(outs0.data(), outs.data() + off, (size_t)BN * kX448Len);
            memcpy(outs0_avx2.data(), outs_avx2.data() + off, (size_t)BN * kX448Len);
        } else {
            bool same_disp = memcmp(outs.data() + off, outs0.data(), (size_t)BN * kX448Len) == 0;
            record_check(("X448 batch(dispatch) off=" + std::to_string(off) + " == off0").c_str(),
                         same_disp);
            if (jpssl::cpu_has_avx2()) {
                bool same_avx2 =
                    memcmp(outs_avx2.data() + off, outs0_avx2.data(), (size_t)BN * kX448Len) == 0;
                record_check(("X448 batch(avx2 显式) off=" + std::to_string(off) + " == off0").c_str(),
                             same_avx2);
            }
        }
    }
}

// ───────────────────────── X448 非对齐基准 ─────────────────────────

static void bench_unalign() {
    // 基准密钥对 (offset=0 生成, 复制到偏移缓冲使用)
    uint8_t a_priv[kX448Len], a_pub[kX448Len], b_priv[kX448Len], b_pub[kX448Len];
    jpssl::x448_generate_keypair(a_pub, a_priv);
    jpssl::x448_generate_keypair(b_pub, b_priv);

    for (int off : kPerfOffsets) {
        printf("\n--- X448 基准 offset=%d ---\n", off);
        alignas(64) uint8_t a_priv_b[kX448Len + 32], a_pub_b[kX448Len + 32];
        alignas(64) uint8_t b_priv_b[kX448Len + 32], b_pub_b[kX448Len + 32];
        memcpy(a_priv_b + off, a_priv, kX448Len);
        memcpy(a_pub_b + off, a_pub, kX448Len);
        memcpy(b_priv_b + off, b_priv, kX448Len);
        memcpy(b_pub_b + off, b_pub, kX448Len);
        alignas(64) uint8_t ss[kX448Len + 32];

        double jp_kg = auto_bench("x448 keygen jpssl off", "x448-keygen-unalign", "jpssl", 56, off,
                                  [&] {
            alignas(64) uint8_t p[kX448Len + 32], s[kX448Len + 32];
            jpssl::x448_generate_keypair(p + off, s + off);
            g_sink ^= p[off] ^ s[off];
        });
        double os_kg = auto_bench("x448 keygen openssl off", "x448-keygen-unalign", "openssl", 56,
                                  off, [&] {
            alignas(64) uint8_t p[kX448Len + 32], s[kX448Len + 32];
            if (!ossl_raw_keygen(EVP_PKEY_X448, "X448", s + off, p + off, 56)) g_sink ^= 1;
            g_sink ^= p[off] ^ s[off];
        });

        double jp_dv = auto_bench("x448 derive jpssl off", "x448-derive-unalign", "jpssl", 56, off,
                                  [&] {
            jpssl::x448_scalar_mult(ss + off, a_priv_b + off, b_pub_b + off);
            g_sink ^= ss[off];
        });
        EVP_PKEY* os_ours = ossl_raw_priv(EVP_PKEY_X448, a_priv_b + off, 56);
        EVP_PKEY* os_peer = ossl_raw_pub(EVP_PKEY_X448, b_pub_b + off, 56);
        double os_dv = auto_bench("x448 derive openssl off", "x448-derive-unalign", "openssl", 56,
                                  off, [&] {
            ossl_raw_derive_keys(os_ours, os_peer, 56, ss + off);
            g_sink ^= ss[off];
        });

        double jp_full = auto_bench("x448 full handshake jpssl off", "x448-full-unalign", "jpssl",
                                    56, off, [&] {
            alignas(64) uint8_t pa[kX448Len + 32], sa[kX448Len + 32];
            alignas(64) uint8_t pb[kX448Len + 32], sb[kX448Len + 32];
            alignas(64) uint8_t s1[kX448Len + 32], s2[kX448Len + 32];
            jpssl::x448_generate_keypair(pa + off, sa + off);
            jpssl::x448_generate_keypair(pb + off, sb + off);
            jpssl::x448_scalar_mult(s1 + off, sa + off, pb + off);
            jpssl::x448_scalar_mult(s2 + off, sb + off, pa + off);
            g_sink ^= s1[off] ^ s2[off];
        });
        double os_full = auto_bench("x448 full handshake openssl off", "x448-full-unalign",
                                    "openssl", 56, off, [&] {
            alignas(64) uint8_t sa[kX448Len + 32], pa[kX448Len + 32];
            alignas(64) uint8_t sb[kX448Len + 32], pb[kX448Len + 32];
            alignas(64) uint8_t s1[kX448Len + 32], s2[kX448Len + 32];
            EVP_PKEY* ka = EVP_PKEY_Q_keygen(nullptr, nullptr, "X448");
            EVP_PKEY* kb = EVP_PKEY_Q_keygen(nullptr, nullptr, "X448");
            size_t l;
            l = 56; EVP_PKEY_get_raw_private_key(ka, sa + off, &l);
            l = 56; EVP_PKEY_get_raw_public_key(ka, pa + off, &l);
            l = 56; EVP_PKEY_get_raw_private_key(kb, sb + off, &l);
            l = 56; EVP_PKEY_get_raw_public_key(kb, pb + off, &l);
            EVP_PKEY* oa = ossl_raw_priv(EVP_PKEY_X448, sa + off, 56);
            EVP_PKEY* oap = ossl_raw_pub(EVP_PKEY_X448, pb + off, 56);
            EVP_PKEY* ob = ossl_raw_priv(EVP_PKEY_X448, sb + off, 56);
            EVP_PKEY* obp = ossl_raw_pub(EVP_PKEY_X448, pa + off, 56);
            ossl_raw_derive_keys(oa, oap, 56, s1 + off);
            ossl_raw_derive_keys(ob, obp, 56, s2 + off);
            EVP_PKEY_free(oa); EVP_PKEY_free(oap);
            EVP_PKEY_free(ob); EVP_PKEY_free(obp);
            EVP_PKEY_free(ka); EVP_PKEY_free(kb);
            g_sink ^= s1[off] ^ s2[off];
        });

        // 批量 N=1000 (偏移缓冲): dispatch + avx2 显式 + openssl 循环
        constexpr int BN = 1000;
        std::vector<uint8_t> outs((size_t)BN * 56 + 64);
        uint8_t(*outs2d)[56] = reinterpret_cast<uint8_t(*)[56]>(outs.data() + off);
        std::vector<const uint8_t*> sc((size_t)BN, a_priv_b + off), pt((size_t)BN, b_pub_b + off);

        double jp_bat = auto_bench_batch("x448 batch N=1000 jpssl (dispatch) off",
                                         "x448-batch-unalign", "jpssl-batch", 56, off, [&] {
            jpssl::x448_scalar_mult_batch(outs2d, sc.data(), pt.data(), BN);
            g_sink ^= outs[off];
        }, BN);

        if (jpssl::cpu_has_avx2()) {
            double jp_bat_avx2 = auto_bench_batch("x448 batch N=1000 jpssl (avx2 显式) off",
                                                  "x448-batch-unalign", "jpssl-batch-avx2", 56, off,
                                                  [&] {
#if defined(JP_AVX2)
                jpssl::x448_scalar_mult_batch_avx2(outs2d, sc.data(), pt.data(), BN);
#else
                jpssl::x448_scalar_mult_batch(outs2d, sc.data(), pt.data(), BN);
#endif
                g_sink ^= outs[off];
            }, BN);
            (void)jp_bat_avx2;
        } else {
            printf("SKIP x448 batch avx2 变体: CPU 无 AVX2\n");
        }

        double os_bat = auto_bench_batch("x448 batch N=1000 openssl (loop) off",
                                         "x448-batch-unalign", "openssl", 56, off, [&] {
            for (int i = 0; i < BN; ++i)
                ossl_raw_derive_keys(os_ours, os_peer, 56, outs.data() + off + (size_t)i * 56);
            g_sink ^= outs[off];
        }, BN);

        printf("x448 offset=%d ratios (openssl/jpssl, >1 = jpssl 快): keygen %.2fx  derive %.2fx  "
               "full %.2fx  batch(dispatch) %.2fx\n",
               off, os_kg / jp_kg, os_dv / jp_dv, os_full / jp_full, os_bat / jp_bat);

        EVP_PKEY_free(os_ours);
        EVP_PKEY_free(os_peer);
    }
}

// ───────────────────────── main ─────────────────────────

int main() {
    g_smoke = std::getenv("BENCH_SMOKE") != nullptr;
    printf("=== X448 ECDH 非对齐对比组: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("mode: %s\n", g_smoke ? "SMOKE (offset {0,3}, ~80ms/轮, 1 轮)" : "full (~150ms/轮, 3 轮取最小)");
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
    g_csv = fopen("benchmarks/results/bench_x448_unalign.csv", "w");
    if (g_csv) fprintf(g_csv, "algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec\n");
    else printf("WARNING: 无法打开 CSV 输出文件\n");

    // 正确性自检 (始终执行, 任一 FAIL 非零退出)
    bool all_ok = true;
    printf("\n--- 非对齐自检 (offsets 0/1/3/7/13) ---\n");
    selfcheck_unalign();
    all_ok = g_selfcheck_fail == 0;
    if (!all_ok) {
        printf("SELF-CHECK FAILED — 非对齐下结果不一致/崩溃, 基准结果不可信 "
               "(PASS=%d FAIL=%d)\n", g_selfcheck_pass, g_selfcheck_fail);
        if (g_csv) fclose(g_csv);
        return 1;
    }

    printf("\n%-44s %12s %14s\n", "case", "ns/op", "Kops/s");
    bench_unalign();

    if (g_csv) {
        fclose(g_csv);
        g_csv = nullptr;
        printf("\nCSV 已写入: benchmarks/results/bench_x448_unalign.csv\n");
    }
    printf("SELF-CHECK PASS=%d FAIL=%d (sink=%d)\n", g_selfcheck_pass, g_selfcheck_fail, g_sink);
    return (g_selfcheck_fail != 0) ? 1 : 0;
}
