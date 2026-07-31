#include "sha512.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

using namespace jpssl;
using namespace std::chrono;

// Internal transform functions (from sha512_cpu.cpp / sha512_opt.cpp)
namespace jpssl {
extern void (*sha512_transform_ptr)(uint64_t[8], const uint8_t[128]);
extern void sha512_transform_cpu(uint64_t[8], const uint8_t[128]);
#ifdef JP_AVX2
extern void sha512_transform_opt(uint64_t[8], const uint8_t[128]);
#endif
}

static std::vector<uint8_t> random_data(size_t n) {
    std::vector<uint8_t> d(n);
    std::mt19937 gen(42);
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& b : d) b = (uint8_t)dist(gen);
    return d;
}

// CPU: uses sha512_update/final (pure software transform)
static double bench_cpu(const uint8_t* data, size_t len, int repeats) {
    uint8_t digest[64];
    auto t0 = high_resolution_clock::now();
    for (int r = 0; r < repeats; ++r) {
        sha512_ctx ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, data, len);
        sha512_final(&ctx, digest);
    }
    auto t1 = high_resolution_clock::now();
    return duration<double, std::milli>(t1 - t0).count() / repeats;
}

// OPT: same API but forces SSE4.1 SIMD transform
static double bench_opt(const uint8_t* data, size_t len, int repeats) {
    auto saved = sha512_transform_ptr;
    sha512_transform_ptr = sha512_transform_opt;
    uint8_t digest[64];
    auto t0 = high_resolution_clock::now();
    for (int r = 0; r < repeats; ++r) {
        sha512_ctx ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, data, len);
        sha512_final(&ctx, digest);
    }
    auto t1 = high_resolution_clock::now();
    sha512_transform_ptr = saved;
    return duration<double, std::milli>(t1 - t0).count() / repeats;
}

// GPU single block (≤128 bytes)
static double bench_gpu_single(const uint8_t* data, size_t len, int repeats) {
    uint8_t digest[64];
    auto t0 = high_resolution_clock::now();
    for (int r = 0; r < repeats; ++r)
        musa_sha512_compute(data, len, digest, false);
    auto t1 = high_resolution_clock::now();
    return duration<double, std::milli>(t1 - t0).count() / repeats;
}

// GPU batch: N independent 128-byte messages
static double bench_gpu_batch(const uint8_t* data, int num_msgs, int repeats) {
    size_t out_size = 64;
    std::vector<uint8_t> outputs((size_t)num_msgs * out_size);
    auto t0 = high_resolution_clock::now();
    for (int r = 0; r < repeats; ++r)
        musa_sha512_batch(data, 128, outputs.data(), num_msgs, false);
    auto t1 = high_resolution_clock::now();
    return duration<double, std::milli>(t1 - t0).count() / repeats;
}

int main() {
    std::printf("╔══════════════════════════════════════════════════════════╗\n");
    std::printf("║     SHA-512 Performance: CPU vs OPT (SSE4.1) vs GPU     ║\n");
    std::printf("╚══════════════════════════════════════════════════════════╝\n\n");

    // ── CPU/OPT streaming tests (serial, any size) ──
    struct StreamTest { const char* label; size_t len; int repeats; };
    StreamTest stream_tests[] = {
        {"128 B   (1 block)",       128,      100000},
        {"1 KB    (8 blocks)",      1024,     10000},
        {"64 KB   (512 blocks)",    65536,    1000},
        {"1 MB    (8192 blocks)",   1048576,  100},
    };
    int num_stream = sizeof(stream_tests) / sizeof(stream_tests[0]);

    std::vector<uint8_t> data_1mb = random_data(1048576);

    // ── CPU ──
    std::printf("── CPU (pure software transform) ────────────────────\n");
    for (int i = 0; i < num_stream; ++i) {
        auto& t = stream_tests[i];
        double ms = bench_cpu(data_1mb.data(), t.len, t.repeats);
        double mbps = (t.len / (1024.0 * 1024.0)) / (ms / 1000.0);
        std::printf("  %-22s %9.3f ms  %8.2f MB/s\n", t.label, ms, mbps);
    }

    // ── OPT ──
#ifdef JP_AVX2
    std::printf("\n── OPT (SSE4.1 SIMD transform) ─────────────────────\n");
    for (int i = 0; i < num_stream; ++i) {
        auto& t = stream_tests[i];
        double ms = bench_opt(data_1mb.data(), t.len, t.repeats);
        double mbps = (t.len / (1024.0 * 1024.0)) / (ms / 1000.0);
        std::printf("  %-22s %9.3f ms  %8.2f MB/s\n", t.label, ms, mbps);
    }
#else
    std::printf("\n── OPT (SSE4.1 SIMD) — not compiled (JP_AVX2=OFF) ──\n");
#endif

    // ── GPU single-block + batch ──
    std::printf("\n── GPU (MUSA) ───────────────────────────────────────\n");
    musa_sha512_init();

    {
        auto& t = stream_tests[0];
        double ms = bench_gpu_single(data_1mb.data(), t.len, t.repeats);
        double mbps = (t.len / (1024.0 * 1024.0)) / (ms / 1000.0);
        std::printf("  %-22s %9.3f ms  %8.2f MB/s  (single-block)\n", t.label, ms, mbps);
    }

    struct BatchTest { const char* label; int num_msgs; int repeats; };
    BatchTest batch_tests[] = {
        {"Batch 10K×128B",           10000,   100},
        {"Batch 100K×128B",          100000,  10},
        {"Batch 1M×128B",            1000000, 1},
    };
    int num_batch = sizeof(batch_tests) / sizeof(batch_tests[0]);

    std::vector<uint8_t> data_batch = random_data(1000000 * 128);

    for (int i = 0; i < num_batch; ++i) {
        auto& t = batch_tests[i];
        double ms = bench_gpu_batch(data_batch.data(), t.num_msgs, t.repeats);
        double total_mb = (double)t.num_msgs * 128.0 / (1024.0 * 1024.0);
        double mbps = total_mb / (ms / 1000.0);
        double us_per_op = ms * 1000.0 / t.num_msgs / t.repeats;
        std::printf("  %-22s %9.3f ms  %8.2f MB/s  (%.3f μs/msg)\n",
                     t.label, ms, mbps, us_per_op);
    }

    // ── Speedup summary (before cleanup) ──
    std::printf("\n── Speedup vs CPU (1 MB streaming) ──────────────────\n");
    double cpu_1mb_ms = bench_cpu(data_1mb.data(), 1048576, 100);
    std::printf("  CPU (1 MB):    %9.3f ms  (baseline)\n", cpu_1mb_ms);
#ifdef JP_AVX2
    double opt_1mb_ms = bench_opt(data_1mb.data(), 1048576, 100);
    std::printf("  OPT (1 MB):    %9.3f ms  (%.2fx)\n", opt_1mb_ms, cpu_1mb_ms / opt_1mb_ms);
#endif

    double gpu_128b_ms = bench_gpu_single(data_1mb.data(), 128, 100000);
    std::printf("  GPU (128 B):   %9.3f μs  (per hash)\n", gpu_128b_ms * 1000);

    double gpu_batch_ms = bench_gpu_batch(data_batch.data(), 1000000, 1);
    double gpu_total_mb = 1000000.0 * 128.0 / (1024.0 * 1024.0);
    std::printf("  GPU batch:     %9.3f ms  (%.2f MB/s)\n", gpu_batch_ms, gpu_total_mb / (gpu_batch_ms / 1000.0));

    musa_sha512_cleanup();
    std::printf("\n");
    return 0;
}
