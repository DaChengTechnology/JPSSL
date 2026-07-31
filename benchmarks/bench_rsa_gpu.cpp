/**
 * bench_rsa_gpu.cpp — RSA 2048/4096 CPU vs MUSA GPU 性能对比
 *
 * 测试内容：
 *   1. RSA-2048: CPU 单次 / CPU 批量(AVX2) / MUSA GPU 批量
 *   2. RSA-4096: CPU 单次 / CPU 批量(AVX2) / MUSA GPU (CPU fallback)
 */

#include "rsa.hpp"
#include "rsa_simd.hpp"
#include "cpu_features.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

using namespace jpssl;
using namespace std::chrono;

// ═══════════════════════════════════════════════════════════════════════
//  工具
// ═══════════════════════════════════════════════════════════════════════

template<typename F>
static double measure_ms(F&& f, int repeats) {
    auto t0 = high_resolution_clock::now();
    for (int r = 0; r < repeats; ++r) f();
    auto t1 = high_resolution_clock::now();
    return duration<double, std::milli>(t1 - t0).count() / repeats;
}

static void random_bn(rsa_bignum& bn, std::mt19937_64& rng) {
    for (int i = 0; i < RSA_2048_WORDS; ++i) bn.d[i] = rng();
    bn.d[0] |= 1;
    bn.d[RSA_2048_WORDS - 1] |= (1ULL << 63);
}

static void random_bn4096(rsa4096_bignum& bn, std::mt19937_64& rng) {
    for (int i = 0; i < RSA_4096_WORDS; ++i) bn.d[i] = rng();
    bn.d[0] |= 1;
    bn.d[RSA_4096_WORDS - 1] |= (1ULL << 63);
}

// ═══════════════════════════════════════════════════════════════════════
//  RSA-2048
// ═══════════════════════════════════════════════════════════════════════

static void bench_rsa2048() {
    std::printf("\n");
    std::printf("╔══════════════════════════════════════════════════════════════╗\n");
    std::printf("║       RSA-2048: CPU vs MUSA GPU Performance                ║\n");
    std::printf("╚══════════════════════════════════════════════════════════════╝\n");

    std::mt19937_64 rng(42);

    rsa_bignum mod, exp;
    random_bn(mod, rng);
    random_bn(exp, rng);
    auto mctx = rsa_mont_init(mod);

    // ── 正确性：CPU single vs GPU batch ──
    {
        rsa_bignum base = rsa_bignum::from_uint64(12345);
        rsa_bignum expected;
        rsa_mont_modpow(expected, base, exp, mctx, mod);

        // GPU batch (4 ops, same base)
        std::vector<uint8_t> gpu_bases(4 * RSA_2048_BYTES);
        std::vector<uint8_t> gpu_results(4 * RSA_2048_BYTES);
        for (int i = 0; i < 4; ++i)
            base.to_bytes(gpu_bases.data() + i * RSA_2048_BYTES);

        musa_rsa_batch_modpow(mod, exp, mctx,
            gpu_bases.data(), gpu_results.data(), 4);

        rsa_bignum gpu0 = rsa_bignum::from_bytes(gpu_results.data(), RSA_2048_BYTES);
        bool gpu_ok = (gpu0 == expected);
        std::printf("  Correctness (GPU vs CPU single): %s\n",
                     gpu_ok ? "PASS" : "FAIL");
        if (!gpu_ok) {
            std::fprintf(stderr, "  ABORT: GPU correctness failed\n");
            return;
        }
    }

    auto feat = cpu_features::detect();
    std::printf("  CPU: AVX2=%s AVX-512=%s\n",
                feat.avx2 ? "YES" : "no",
                feat.avx512 ? "YES" : "no");

    // ── 准备 batch 数据 ──
    constexpr int MAX = 1024;
    std::vector<uint8_t> bases(MAX * RSA_2048_BYTES);
    std::vector<uint8_t> results(MAX * RSA_2048_BYTES);
    {
        rsa_bignum base = rsa_bignum::from_uint64(12345);
        for (int i = 0; i < MAX; ++i)
            base.to_bytes(bases.data() + i * RSA_2048_BYTES);
    }

    // ── CPU single ──
    double cpu1_ms = 0;
    {
        rsa_bignum base = rsa_bignum::from_uint64(12345), tmp;
        cpu1_ms = measure_ms([&]{ rsa_mont_modpow(tmp, base, exp, mctx, mod); }, 10);
        std::printf("\n  CPU single:         %9.3f ms  (%7.1f ops/sec)\n",
                    cpu1_ms, 1000.0 / cpu1_ms);
    }

    // ── Batch: different sizes ──
    struct { int n; int reps; } bs[] = {
        {1,100},{4,50},{8,30},{16,20},{32,10},{64,5},
        {128,3},{256,2},{512,1},{1024,1}
    };
    int nb = sizeof(bs) / sizeof(bs[0]);

    std::printf("\n  %-8s %14s %12s %14s %12s %10s\n",
                "Batch", "CPU(ms)", "CPU(ms/op)",
                "GPU(ms)", "GPU(ms/op)", "Speedup");
    std::printf("  %-8s %14s %12s %14s %12s %10s\n",
                "------", "-------", "---------",
                "-------", "---------", "-------");

    double best_cpu_ops = 0, best_gpu_ops = 0;

    for (int i = 0; i < nb; ++i) {
        // CPU batch
        double cpu_ms = measure_ms([&]{
            rsa_batch_decrypt_dispatch(mod.d, exp.d,
                mctx.R2_mod_m.d, mctx.R_mod_m.d, mctx.m_prime,
                bases.data(), results.data(), bs[i].n,
                RSA_2048_WORDS, 2048);
        }, bs[i].reps);

        // GPU batch
        double gpu_ms = measure_ms([&]{
            musa_rsa_batch_modpow(mod, exp, mctx,
                bases.data(), results.data(), bs[i].n);
        }, bs[i].reps);

        double cpu_ms_op = cpu_ms / bs[i].n;
        double gpu_ms_op = gpu_ms / bs[i].n;
        double speedup = cpu_ms / gpu_ms;

        std::printf("  %-8d %10.3f ms  %8.3f ms  %10.3f ms  %8.3f ms  %8.2fx\n",
                    bs[i].n, cpu_ms, cpu_ms_op, gpu_ms, gpu_ms_op, speedup);

        double cpu_ops = bs[i].n / cpu_ms * 1000.0;
        double gpu_ops = bs[i].n / gpu_ms * 1000.0;
        if (cpu_ops > best_cpu_ops) best_cpu_ops = cpu_ops;
        if (gpu_ops > best_gpu_ops) best_gpu_ops = gpu_ops;
    }

    std::printf("\n  ── Summary ──\n");
    std::printf("  CPU single:   %7.1f ops/sec\n", 1000.0 / cpu1_ms);
    std::printf("  CPU best:     %7.1f ops/sec  (batch)\n", best_cpu_ops);
    std::printf("  GPU best:     %7.1f ops/sec  (%.1fx vs CPU single, %.1fx vs CPU batch)\n",
                best_gpu_ops, best_gpu_ops / (1000.0 / cpu1_ms), best_gpu_ops / best_cpu_ops);
}

// ═══════════════════════════════════════════════════════════════════════
//  RSA-4096
// ═══════════════════════════════════════════════════════════════════════

static void bench_rsa4096() {
    std::printf("\n");
    std::printf("╔══════════════════════════════════════════════════════════════╗\n");
    std::printf("║       RSA-4096: CPU vs MUSA GPU Performance                ║\n");
    std::printf("║       (MUSA GPU 4096 kernel 已实现; S80 上慢于 CPU)        ║\n");
    std::printf("╚══════════════════════════════════════════════════════════════╝\n");

    std::mt19937_64 rng(99);

    rsa4096_bignum mod, exp;
    random_bn4096(mod, rng);
    random_bn4096(exp, rng);
    auto mctx = rsa4096_mont_init(mod);

    // ── 正确性 ──
    {
        rsa4096_bignum base = rsa4096_bignum::from_uint64(12345);
        rsa4096_bignum expected;
        rsa4096_mont_modpow(expected, base, exp, mctx, mod);

        std::vector<uint8_t> gpu_bases(4 * RSA_4096_BYTES);
        std::vector<uint8_t> gpu_results(4 * RSA_4096_BYTES);
        for (int i = 0; i < 4; ++i)
            base.to_bytes(gpu_bases.data() + i * RSA_4096_BYTES);

        musa4096_rsa_batch_modpow(mod, exp, mctx,
            gpu_bases.data(), gpu_results.data(), 4);
        rsa4096_bignum gpu0 = rsa4096_bignum::from_bytes(gpu_results.data(), RSA_4096_BYTES);
        std::printf("  Correctness (GPU vs CPU single): %s\n",
                     (gpu0 == expected) ? "PASS" : "FAIL");
    }

    // ── CPU single ──
    double cpu1_ms = 0;
    {
        rsa4096_bignum base = rsa4096_bignum::from_uint64(12345), tmp;
        cpu1_ms = measure_ms([&]{ rsa4096_mont_modpow(tmp, base, exp, mctx, mod); }, 5);
        std::printf("\n  CPU single:         %9.3f ms  (%7.2f ops/sec)\n",
                    cpu1_ms, 1000.0 / cpu1_ms);
    }

    constexpr int MAX = 512;
    std::vector<uint8_t> bases(MAX * RSA_4096_BYTES);
    std::vector<uint8_t> results(MAX * RSA_4096_BYTES);
    {
        rsa4096_bignum base = rsa4096_bignum::from_uint64(12345);
        for (int i = 0; i < MAX; ++i)
            base.to_bytes(bases.data() + i * RSA_4096_BYTES);
    }

    struct { int n; int reps; } bs[] = {
        {1,10},{4,5},{8,3},{16,2},{32,1},{64,1},{128,1},{256,1},{512,1}
    };
    int nb = sizeof(bs) / sizeof(bs[0]);

    std::printf("\n  %-8s %14s %12s %14s %12s %10s\n",
                "Batch", "CPU(ms)", "CPU(ms/op)",
                "GPU(ms)", "GPU(ms/op)", "Speedup");
    std::printf("  %-8s %14s %12s %14s %12s %10s\n",
                "------", "-------", "---------",
                "-------", "---------", "-------");

    double best_cpu_ops = 0;
    for (int i = 0; i < nb; ++i) {
        double cpu_ms = measure_ms([&]{
            rsa_batch_decrypt_dispatch(mod.d, exp.d,
                mctx.R2_mod_m.d, mctx.R_mod_m.d, mctx.m_prime,
                bases.data(), results.data(), bs[i].n,
                RSA_4096_WORDS, 4096);
        }, bs[i].reps);

        // GPU 4096 kernel 每 launch ~20s (S80 寄存器压力), 仅测 16/64/256 各 1 次
        double gpu_ms = 0;
        if (bs[i].n == 16 || bs[i].n == 64 || bs[i].n == 256) {
            gpu_ms = measure_ms([&]{
                musa4096_rsa_batch_modpow(mod, exp, mctx,
                    bases.data(), results.data(), bs[i].n);
            }, 1);
        }

        double cpu_ms_op = cpu_ms / bs[i].n;
        double gpu_ms_op = gpu_ms / bs[i].n;
        double speedup = cpu_ms / gpu_ms;

        std::printf("  %-8d %10.3f ms  %8.3f ms  %10.3f ms  %8.3f ms  %8.2fx\n",
                    bs[i].n, cpu_ms, cpu_ms_op, gpu_ms, gpu_ms_op, speedup);

        double ops = bs[i].n / cpu_ms * 1000.0;
        if (ops > best_cpu_ops) best_cpu_ops = ops;
    }

    std::printf("\n  ── Summary ──\n");
    std::printf("  CPU single:   %7.2f ops/sec\n", 1000.0 / cpu1_ms);
    std::printf("  CPU best:     %7.1f ops/sec  (batch)\n", best_cpu_ops);
    std::printf("  (GPU 4096 = CPU fallback — no GPU kernel for 4096-bit)\n");
}

// ═══════════════════════════════════════════════════════════════════════
//  main
// ═══════════════════════════════════════════════════════════════════════

int main() {
    std::printf("╔══════════════════════════════════════════════════════════════╗\n");
    std::printf("║   RSA Performance: CPU (scalar/AVX2) vs MUSA GPU            ║\n");
    std::printf("╚══════════════════════════════════════════════════════════════╝\n");

    auto feat = cpu_features::detect();
    std::printf("\n  CPU Features:\n");
    std::printf("    AVX2:              %s\n", feat.avx2 ? "YES" : "no");
    std::printf("    AVX-512:           %s\n", feat.avx512 ? "YES" : "no");
    std::printf("    SHA-NI:            %s\n", feat.sha_ni ? "YES" : "no");

    bench_rsa2048();
    bench_rsa4096();

    std::printf("\nDone.\n\n");
    return 0;
}
