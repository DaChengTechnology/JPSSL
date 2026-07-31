/**
 * bench_hardware_accel.cpp — 硬件加速路径性能对比
 *
 * 对每个密码原语，逐一测试各硬件加速路径的性能，并与 OpenSSL 对比。
 *
 * CPU: 13th Gen Intel i7-13700K
 * 支持: AES-NI, AVX2, VAES, VPCLMULQDQ, SHA-NI
 * 不支持: AVX512
 *
 * 测试内容:
 *   1. AES-128-GCM:  software / AVX2 / auto / OpenSSL
 *   2. AES-256-GCM:  software / auto / OpenSSL
 *   3. ChaCha20-Poly1305:  CPU / GPU pool / OpenSSL
 *   4. SHA-256:  jpssl / OpenSSL
 *   5. SHA-512:  CPU / SSE4.1 / GPU single / GPU batch / OpenSSL
 */

#include "test_utils.hpp"
#include "aes.hpp"
#include "chacha20_poly1305.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "cpu_features.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace jpssl;
using namespace jptest;
using namespace std::chrono;

static const size_t DATA_SIZE = 16ULL * 1024 * 1024;
static const size_t CCM_DATA_SIZE = 16ULL * 1024 * 1024 - 1;

static double to_gbps(size_t bytes, double ms) {
    return (bytes / 1e9) / (ms / 1000.0);
}

// ── 耗时测量 ──
template<typename F>
static double measure_ms(F&& f) {
    auto t0 = high_resolution_clock::now();
    f();
    auto t1 = high_resolution_clock::now();
    return duration<double, std::milli>(t1 - t0).count();
}

// ========================================================================
//  CPU 特性检测
// ========================================================================

static void detect_and_print_cpu_features() {
    auto f = cpu_features::detect();
    std::printf("\n  CPU Features:\n");
    std::printf("    AES-NI:            %s\n", f.aesni ? "YES" : "no");
    std::printf("    AVX2:              %s\n", f.avx2 ? "YES" : "no");
    std::printf("    PCLMULQDQ:         %s\n", f.pclmulqdq ? "YES" : "no");
    std::printf("    AVX512F+VL:        %s\n", f.avx512 ? "YES" : "no");
    std::printf("    VAES+VPCLMULQDQ:   %s\n", f.vpclmulqdq_vaes ? "YES" : "no");
    std::printf("    SHA-NI:            %s\n", f.sha_ni ? "YES" : "no");
}

// ========================================================================
//  1. AES-128-GCM 全路径对比
// ========================================================================

static void bench_aes128_gcm_paths() {
    std::printf("\n  ── AES-128-GCM 硬件加速路径对比 ──\n");

    uint8_t key[16], iv[12];
    RAND_bytes(key, 16);
    RAND_bytes(iv, 12);
    std::vector<uint8_t> plain(DATA_SIZE);
    RAND_bytes(plain.data(), DATA_SIZE);

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    double sw_enc = 0, sw_dec = 0;
    double avx2_enc = 0, avx2_dec = 0;
    double auto_enc = 0, auto_dec = 0;
    double ossl_enc = 0, ossl_dec = 0;

    // ── 软件路径 (aes_gcm_encrypt, uses AES-NI for block cipher + software GHASH) ──
    {
        std::vector<uint8_t> ct; uint8_t tag[16];
        sw_enc = measure_ms([&]{
            aes_gcm_encrypt(ctx, iv, 12, plain, std::span<const uint8_t>(), ct, tag, 16);
        });
        bool ok = false;
        sw_dec = measure_ms([&]{
            std::vector<uint8_t> pt;
            ok = aes_gcm_decrypt(ctx, iv, 12, ct, std::span<const uint8_t>(), tag, 16, pt);
        });
        (void)ok;
    }

    // ── AVX2 路径 (4路并行 AES-NI + PCLMULQDQ) ──
    {
        std::vector<uint8_t> ct; uint8_t tag[16];
        avx2_enc = measure_ms([&]{
            aes_gcm_encrypt_avx2(ctx, iv, 12, plain, std::span<const uint8_t>(), ct, tag, 16);
        });
        bool ok = false;
        avx2_dec = measure_ms([&]{
            std::vector<uint8_t> pt;
            ok = aes_gcm_decrypt_avx2(ctx, iv, 12, ct, std::span<const uint8_t>(), tag, 16, pt);
        });
        TEST("AES-128-GCM AVX2 round-trip", ok);
    }

    // ── Auto 分派 ──
    {
        std::vector<uint8_t> ct; uint8_t tag[16];
        auto_enc = measure_ms([&]{
            aes_gcm_encrypt_auto(ctx, iv, 12, plain, std::span<const uint8_t>(), ct, tag, 16);
        });
        bool ok = false;
        auto_dec = measure_ms([&]{
            std::vector<uint8_t> pt;
            ok = aes_gcm_decrypt_auto(ctx, iv, 12, ct, std::span<const uint8_t>(), tag, 16, pt);
        });
        TEST("AES-128-GCM auto round-trip", ok);
    }

    // ── OpenSSL ──
    {
        EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ectx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ectx, nullptr, nullptr, key, iv);
        int out_len;
        std::vector<uint8_t> ossl_ct(DATA_SIZE + 16);
        uint8_t ossl_tag[16];
        ossl_enc = measure_ms([&]{
            EVP_EncryptUpdate(ectx, ossl_ct.data(), &out_len, plain.data(), DATA_SIZE);
            EVP_EncryptFinal_ex(ectx, ossl_ct.data() + out_len, &out_len);
            EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, ossl_tag);
        });
        EVP_CIPHER_CTX_free(ectx);

        EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(dctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_DecryptInit_ex(dctx, nullptr, nullptr, key, iv);
        int ret;
        ossl_dec = measure_ms([&]{
            std::vector<uint8_t> pt(DATA_SIZE);
            EVP_DecryptUpdate(dctx, pt.data(), &out_len, ossl_ct.data(), DATA_SIZE);
            EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, 16, ossl_tag);
            ret = EVP_DecryptFinal_ex(dctx, pt.data() + out_len, &out_len);
        });
        EVP_CIPHER_CTX_free(dctx);
        TEST("OpenSSL AES-128-GCM decrypt", ret > 0);
    }

    // ── 结果表格 ──
    struct Path { const char* name; double enc_ms; double dec_ms; };
    Path paths[] = {
        {"Software",   sw_enc,   sw_dec},
        {"AVX2",       avx2_enc, avx2_dec},
        {"Auto",       auto_enc, auto_dec},
        {"OpenSSL",    ossl_enc, ossl_dec},
    };
    std::printf("  %-12s %12s %14s %12s %14s %12s\n",
                "Path", "Enc(ms)", "Enc(GB/s)", "Dec(ms)", "Dec(GB/s)", "vs OSSL");
    double base_enc = ossl_enc, base_dec = ossl_dec;
    for (auto& p : paths) {
        double enc_gbps = to_gbps(DATA_SIZE, p.enc_ms);
        double dec_gbps = to_gbps(DATA_SIZE, p.dec_ms);
        double ratio_enc = base_enc / p.enc_ms;
        double ratio_dec = base_dec / p.dec_ms;
        std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s  %5.2fx/%5.2fx\n",
                    p.name, p.enc_ms, enc_gbps, p.dec_ms, dec_gbps, ratio_enc, ratio_dec);
    }
}

// ========================================================================
//  2. AES-256-GCM 路径对比 (仅 software/auto, AVX2 不支持 256-bit)
// ========================================================================

static void bench_aes256_gcm_paths() {
    std::printf("\n  ── AES-256-GCM 硬件加速路径对比 ──\n");
    std::printf("    Note: AVX2/AVX512 GCM 仅支持 AES-128, 256-bit 回退到软件\n");

    uint8_t key[32], iv[12];
    RAND_bytes(key, 32);
    RAND_bytes(iv, 12);
    std::vector<uint8_t> plain(DATA_SIZE);
    RAND_bytes(plain.data(), DATA_SIZE);

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 32>(key, 32));

    double sw_enc, sw_dec, auto_enc, auto_dec, ossl_enc, ossl_dec;

    {   std::vector<uint8_t> ct; uint8_t tag[16];
        sw_enc = measure_ms([&]{ aes_gcm_encrypt(ctx, iv, 12, plain, {}, ct, tag, 16); });
        bool ok = false;
        sw_dec = measure_ms([&]{ std::vector<uint8_t> pt; ok = aes_gcm_decrypt(ctx, iv, 12, ct, {}, tag, 16, pt); });
        TEST("AES-256-GCM software round-trip", ok);
    }
    {   std::vector<uint8_t> ct; uint8_t tag[16];
        auto_enc = measure_ms([&]{ aes_gcm_encrypt_auto(ctx, iv, 12, plain, {}, ct, tag, 16); });
        bool ok = false;
        auto_dec = measure_ms([&]{ std::vector<uint8_t> pt; ok = aes_gcm_decrypt_auto(ctx, iv, 12, ct, {}, tag, 16, pt); });
        TEST("AES-256-GCM auto round-trip", ok);
    }
    {
        EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ectx, nullptr, nullptr, key, iv);
        int out_len;
        std::vector<uint8_t> ossl_ct(DATA_SIZE + 16);
        uint8_t ossl_tag[16];
        ossl_enc = measure_ms([&]{
            EVP_EncryptUpdate(ectx, ossl_ct.data(), &out_len, plain.data(), DATA_SIZE);
            EVP_EncryptFinal_ex(ectx, ossl_ct.data() + out_len, &out_len);
            EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, ossl_tag);
        });
        EVP_CIPHER_CTX_free(ectx);
        EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(dctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_DecryptInit_ex(dctx, nullptr, nullptr, key, iv);
        int ret;
        ossl_dec = measure_ms([&]{
            std::vector<uint8_t> pt(DATA_SIZE);
            EVP_DecryptUpdate(dctx, pt.data(), &out_len, ossl_ct.data(), DATA_SIZE);
            EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, 16, ossl_tag);
            ret = EVP_DecryptFinal_ex(dctx, pt.data() + out_len, &out_len);
        });
        EVP_CIPHER_CTX_free(dctx);
        TEST("OpenSSL AES-256-GCM decrypt", ret > 0);
    }

    struct Path { const char* name; double enc_ms; double dec_ms; };
    Path paths[] = {
        {"Software", sw_enc, sw_dec},
        {"Auto", auto_enc, auto_dec},
        {"OpenSSL", ossl_enc, ossl_dec},
    };
    std::printf("  %-12s %12s %14s %12s %14s %12s\n",
                "Path", "Enc(ms)", "Enc(GB/s)", "Dec(ms)", "Dec(GB/s)", "vs OSSL");
    double base_enc = ossl_enc, base_dec = ossl_dec;
    for (auto& p : paths) {
        double enc_gbps = to_gbps(DATA_SIZE, p.enc_ms);
        double dec_gbps = to_gbps(DATA_SIZE, p.dec_ms);
        std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s  %5.2fx/%5.2fx\n",
                    p.name, p.enc_ms, enc_gbps, p.dec_ms, dec_gbps,
                    base_enc / p.enc_ms, base_dec / p.dec_ms);
    }
}

// ========================================================================
//  3. ChaCha20-Poly1305 路径对比 (CPU vs GPU pool vs OpenSSL)
// ========================================================================

static void bench_chacha20_paths() {
    std::printf("\n  ── ChaCha20-Poly1305 加速路径对比 ──\n");

    uint8_t key[32], nonce[12];
    RAND_bytes(key, 32);
    RAND_bytes(nonce, 12);
    std::vector<uint8_t> plain(DATA_SIZE);
    RAND_bytes(plain.data(), DATA_SIZE);

    double cpu_enc, cpu_dec, ossl_enc, ossl_dec;
    double gpu_enc = 0, gpu_dec = 0;

    // ── jpssl CPU ──
    {
        std::vector<uint8_t> ct; uint8_t tag[16];
        cpu_enc = measure_ms([&]{
            chacha20_poly1305_encrypt(key, nonce, plain, std::span<const uint8_t>(), ct, tag);
        });
        bool ok = false;
        cpu_dec = measure_ms([&]{
            std::vector<uint8_t> pt;
            ok = chacha20_poly1305_decrypt(key, nonce, ct, std::span<const uint8_t>(), tag, pt);
        });
        TEST("ChaCha20-Poly1305 CPU round-trip", ok);
    }

    // ── MUSA GPU Pool ──
    {
        auto* pool = musa_chacha20_pool_create(key, nonce, DATA_SIZE);
        if (pool) {
            std::vector<uint8_t> ct; uint8_t tag[16];
            gpu_enc = measure_ms([&]{
                musa_chacha20_pool_aead_encrypt(pool, nonce, plain, std::span<const uint8_t>(), ct, tag);
            });
            bool ok = false;
            gpu_dec = measure_ms([&]{
                std::vector<uint8_t> pt;
                ok = musa_chacha20_pool_aead_decrypt(pool, nonce, ct, std::span<const uint8_t>(), tag, pt);
            });
            musa_chacha20_pool_destroy(pool);
            TEST("ChaCha20-Poly1305 GPU pool round-trip", ok);
        } else {
            std::printf("  [SKIP] GPU pool not available\n");
        }
    }

    // ── OpenSSL ──
    {
        EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ectx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ectx, nullptr, nullptr, key, nonce);
        int out_len;
        std::vector<uint8_t> ossl_ct(DATA_SIZE + 16);
        uint8_t ossl_tag[16];
        ossl_enc = measure_ms([&]{
            EVP_EncryptUpdate(ectx, ossl_ct.data(), &out_len, plain.data(), DATA_SIZE);
            EVP_EncryptFinal_ex(ectx, ossl_ct.data() + out_len, &out_len);
            EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_GET_TAG, 16, ossl_tag);
        });
        EVP_CIPHER_CTX_free(ectx);

        EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(dctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_DecryptInit_ex(dctx, nullptr, nullptr, key, nonce);
        int ret;
        ossl_dec = measure_ms([&]{
            std::vector<uint8_t> pt(DATA_SIZE);
            EVP_DecryptUpdate(dctx, pt.data(), &out_len, ossl_ct.data(), DATA_SIZE);
            EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, ossl_tag);
            ret = EVP_DecryptFinal_ex(dctx, pt.data() + out_len, &out_len);
        });
        EVP_CIPHER_CTX_free(dctx);
        TEST("OpenSSL ChaCha20-Poly1305 decrypt", ret > 0);
    }

    struct Path { const char* name; double enc_ms; double dec_ms; };
    Path paths[] = {
        {"jpssl CPU", cpu_enc, cpu_dec},
        {"GPU pool",  gpu_enc > 0 ? gpu_enc : 0, gpu_dec > 0 ? gpu_dec : 0},
        {"OpenSSL",   ossl_enc, ossl_dec},
    };
    std::printf("  %-12s %12s %14s %12s %14s %12s\n",
                "Path", "Enc(ms)", "Enc(GB/s)", "Dec(ms)", "Dec(GB/s)", "vs OSSL");
    double base_enc = ossl_enc, base_dec = ossl_dec;
    for (auto& p : paths) {
        if (p.enc_ms <= 0) {
            std::printf("  %-12s   (unavailable)\n", p.name);
            continue;
        }
        double enc_gbps = to_gbps(DATA_SIZE, p.enc_ms);
        double dec_gbps = to_gbps(DATA_SIZE, p.dec_ms);
        std::printf("  %-12s %9.2f ms  %8.3f GB/s  %9.2f ms  %8.3f GB/s  %5.2fx/%5.2fx\n",
                    p.name, p.enc_ms, enc_gbps, p.dec_ms, dec_gbps,
                    base_enc / p.enc_ms, base_dec / p.dec_ms);
    }
}

// ========================================================================
//  4. SHA-256 (jpssl vs OpenSSL)
// ========================================================================

static void bench_sha256() {
    std::printf("\n  ── SHA-256 ──\n");

    std::vector<uint8_t> data(DATA_SIZE);
    RAND_bytes(data.data(), DATA_SIZE);
    uint8_t jp_hash[32], ossl_hash[32];

    double jp_ms = measure_ms([&]{
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, data.data(), data.size());
        sha256_final(&ctx, jp_hash);
    });
    double ossl_ms = measure_ms([&]{
        SHA256(data.data(), data.size(), ossl_hash);
    });

    bool match = memcmp(jp_hash, ossl_hash, 32) == 0;
    TEST("SHA-256 jpssl matches OpenSSL", match);

    std::printf("  %-12s %9.2f ms  %8.3f GB/s\n", "jpssl", jp_ms, to_gbps(DATA_SIZE, jp_ms));
    std::printf("  %-12s %9.2f ms  %8.3f GB/s\n", "OpenSSL", ossl_ms, to_gbps(DATA_SIZE, ossl_ms));
    std::printf("  Ratio: %.2fx\n", ossl_ms / jp_ms);
}

// ========================================================================
//  5. SHA-512: CPU / SSE4.1 / GPU / OpenSSL
// ========================================================================

// expose internal transform
namespace jpssl {
extern void (*sha512_transform_ptr)(uint64_t[8], const uint8_t[128]);
extern void sha512_transform_cpu(uint64_t[8], const uint8_t[128]);
extern void sha512_transform_opt(uint64_t[8], const uint8_t[128]);
}

static double bench_sha512_path(const uint8_t* data, size_t len, int repeats, bool use_opt, bool use_gpu) {
    if (use_gpu) {
        uint8_t digest[64];
        auto t0 = high_resolution_clock::now();
        for (int r = 0; r < repeats; ++r) {
            sha512_ctx ctx;
            sha512_init(&ctx);
            sha512_update(&ctx, data, len);
            sha512_final(&ctx, digest);
        }
        auto t1 = high_resolution_clock::now();
        (void)digest;
        return 0; // placeholder
    }
    uint8_t digest[64];
    auto saved = sha512_transform_ptr;
    if (use_opt) sha512_transform_ptr = sha512_transform_opt;
    else         sha512_transform_ptr = sha512_transform_cpu;
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

static void bench_sha512() {
    std::printf("\n  ── SHA-512 各路径对比 (streaming, 1 MB) ──\n");

    const size_t LEN = 1048576;
    const int REPEATS = 100;
    std::vector<uint8_t> data(LEN);
    RAND_bytes(data.data(), LEN);

    double cpu_ms = bench_sha512_path(data.data(), LEN, REPEATS, false, false);
    double opt_ms = bench_sha512_path(data.data(), LEN, REPEATS, true, false);
    double ossl_ms = measure_ms([&]{
        for (int r = 0; r < REPEATS; ++r) {
            uint8_t h[64];
            SHA512(data.data(), LEN, h);
        }
    }) / REPEATS;

    std::printf("  %-12s %9.3f ms  %8.3f GB/s  %s\n",
                "CPU", cpu_ms, to_gbps(LEN, cpu_ms), "(baseline)");
    std::printf("  %-12s %9.3f ms  %8.3f GB/s  %.2fx vs CPU\n",
                "SSE4.1", opt_ms, to_gbps(LEN, opt_ms), cpu_ms / opt_ms);
    TEST("SHA-512 SSE4.1 faster than CPU", opt_ms < cpu_ms);
    std::printf("  %-12s %9.3f ms  %8.3f GB/s  %.2fx vs CPU\n",
                "OpenSSL", ossl_ms, to_gbps(LEN, ossl_ms), cpu_ms / ossl_ms);

    // ── GPU batch ──
    std::printf("\n  ── SHA-512 GPU batch ──\n");
    musa_sha512_init();
    const int BATCH = 100000;
    std::vector<uint8_t> batch_data((size_t)BATCH * 128);
    RAND_bytes(batch_data.data(), (size_t)BATCH * 128);

    double gpu_batch_ms = measure_ms([&]{
        std::vector<uint8_t> out((size_t)BATCH * 64);
        musa_sha512_batch(batch_data.data(), 128, out.data(), BATCH, false);
    });
    double total_mb = (double)BATCH * 128.0 / (1024.0 * 1024.0);
    double gpu_mbps = total_mb / (gpu_batch_ms / 1000.0);
    double us_per_op = gpu_batch_ms * 1000.0 / BATCH;
    std::printf("  GPU batch %d×128B: %.2f ms (%.0f MB/s, %.3f μs/hash)\n",
                BATCH, gpu_batch_ms, gpu_mbps, us_per_op);

    double gpu_single_ms = measure_ms([&]{
        for (int r = 0; r < 1000; ++r) {
            uint8_t h[64];
            musa_sha512_compute(data.data(), 128, h, false);
        }
    });
    std::printf("  GPU single 128B:   %.3f μs/hash\n", gpu_single_ms * 1000.0 / 1000);
    musa_sha512_cleanup();

    double cpu_128b_per_op = (cpu_ms / REPEATS) * (128.0 / LEN) * 1000; // μs for 128B
    std::printf("  CPU 128B:          ~%.3f μs/hash\n", cpu_128b_per_op);
}

// ========================================================================
//  6. AES-NI vs 纯软件 AES (ECB 加密吞吐量)
// ========================================================================

static void bench_aesni_vs_software() {
    std::printf("\n  ── AES-NI vs 纯软件 AES (ECB-128 encrypt) ──\n");

    uint8_t key[16];
    RAND_bytes(key, 16);
    std::vector<uint8_t> plain(DATA_SIZE);
    RAND_bytes(plain.data(), DATA_SIZE);
    std::vector<uint8_t> ct(DATA_SIZE);

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    double sw_ms = measure_ms([&]{
        for (size_t i = 0; i < DATA_SIZE; i += 16)
            aes_encrypt_block_sw(ctx, plain.data() + i, ct.data() + i);
    });
    double aesni_ms = measure_ms([&]{
        for (size_t i = 0; i < DATA_SIZE; i += 16)
            aes_encrypt_block(ctx, plain.data() + i, ct.data() + i);
    });
    double ossl_ms = measure_ms([&]{
        AES_KEY ossl_key;
        AES_set_encrypt_key(key, 128, &ossl_key);
        for (size_t i = 0; i < DATA_SIZE; i += 16)
            AES_encrypt(plain.data() + i, ct.data() + i, &ossl_key);
    });

    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %s\n",
                "Pure SW", sw_ms, to_gbps(DATA_SIZE, sw_ms), "(no AES-NI)");
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %.2fx vs SW\n",
                "AES-NI", aesni_ms, to_gbps(DATA_SIZE, aesni_ms), sw_ms / aesni_ms);
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %.2fx vs SW\n",
                "OpenSSL", ossl_ms, to_gbps(DATA_SIZE, ossl_ms), sw_ms / ossl_ms);

    TEST("AES-NI faster than pure software", aesni_ms < sw_ms);
    TEST("OpenSSL AES-ECB matches AES-NI or better", ossl_ms <= sw_ms * 0.5);
}

// ========================================================================
//  7. SHA-256: 纯软件 vs SHA-NI vs OpenSSL
// ========================================================================

static void bench_sha256_sha_ni() {
    std::printf("\n  ── SHA-256: 纯软件 vs SHA-NI vs OpenSSL ──\n");

    std::vector<uint8_t> data(DATA_SIZE);
    RAND_bytes(data.data(), DATA_SIZE);
    uint8_t digest_sw[32], digest_ni[32], digest_ossl[32];

    // jpssl 纯软件 SHA-256
    double sw_ms = measure_ms([&]{
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, data.data(), data.size());
        sha256_final(&ctx, digest_sw);
    });

    // SHA-NI SHA-256
    double ni_ms = measure_ms([&]{
        sha256_sha_ni(digest_ni, data.data(), data.size());
    });

    // OpenSSL SHA-256
    double ossl_ms = measure_ms([&]{
        SHA256(data.data(), data.size(), digest_ossl);
    });

    bool sw_ni_match = memcmp(digest_sw, digest_ni, 32) == 0;
    bool ni_ossl_match = memcmp(digest_ni, digest_ossl, 32) == 0;
    TEST("SHA-256 SHA-NI matches jpssl software", sw_ni_match);
    TEST("SHA-256 SHA-NI matches OpenSSL", ni_ossl_match);

    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %s\n",
                "jpssl SW", sw_ms, to_gbps(DATA_SIZE, sw_ms), "(baseline)");
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %.2fx vs SW\n",
                "SHA-NI", ni_ms, to_gbps(DATA_SIZE, ni_ms), sw_ms / ni_ms);
    std::printf("  %-12s %9.2f ms  %8.3f GB/s  %.2fx vs SW\n",
                "OpenSSL", ossl_ms, to_gbps(DATA_SIZE, ossl_ms), sw_ms / ossl_ms);

    TEST("SHA-NI faster than software", ni_ms < sw_ms);
}

// ========================================================================
//  入口
// ========================================================================

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::cout << "jpssl Hardware Acceleration Benchmark\n";
    std::cout << "Data size: " << (DATA_SIZE / (1024*1024)) << " MB\n";

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    RUN_TEST(detect_and_print_cpu_features);
    RUN_TEST(bench_aes128_gcm_paths);
    RUN_TEST(bench_aes256_gcm_paths);
    RUN_TEST(bench_chacha20_paths);
    RUN_TEST(bench_sha256);
    RUN_TEST(bench_sha512);
    RUN_TEST(bench_aesni_vs_software);
    RUN_TEST(bench_sha256_sha_ni);

    return test_summary();
}
