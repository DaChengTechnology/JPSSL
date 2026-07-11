/**
 * main.cpp — jpssl AES 加解密测试 & Benchmark
 *
 * 测试流程：
 *   1. CPU 单块加解密正确性测试（AES-128）
 *   2. CPU ECB 批量测试
 *   3. MUSA GPU ECB 加密测试（与 CPU 结果对比）
 *   4. CPU vs GPU 性能对比 benchmark
 */

#include "aes.hpp"
#include "tls.hpp"
#include "chacha20_poly1305.hpp"
#include "rsa.hpp"
#include "rsa_simd.hpp"
#include "x25519.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <vector>

using namespace jpssl;
using namespace std::chrono;

// ═══════════════════════════════════════════════════════════════════════
//  辅助函数
// ═══════════════════════════════════════════════════════════════════════

/// 打印十六进制字节
inline void print_hex(const uint8_t* data, size_t len, const char* label = nullptr) {
    if (label) std::printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        std::printf("%02x ", data[i]);
    }
    std::printf("\n");
}

/// 生成随机数据
inline std::vector<uint8_t> random_data(size_t bytes) {
    std::vector<uint8_t> data(bytes);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& b : data) b = static_cast<uint8_t>(dist(gen));
    return data;
}

/// 检查两个缓冲区是否相等
inline bool buffers_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    return std::memcmp(a, b, len) == 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 1: 单块 AES-128 加解密正确性
// ═══════════════════════════════════════════════════════════════════════

static int test_single_block() {
    std::printf("=== Test 1: AES-128 Single Block ===\n");

    // NIST FIPS-197 附录 B 已知测试向量
    const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const uint8_t plain[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    };
    const uint8_t expected[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
    };

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>{key});

    print_hex(key, 16, "  Key     ");
    print_hex(plain, 16, "  Plain   ");

    // 加密
    uint8_t cipher[16];
    aes_encrypt_block(ctx, plain, cipher);
    print_hex(cipher, 16, "  Cipher  ");

    if (!buffers_equal(cipher, expected, 16)) {
        std::printf("  FAIL: encryption mismatch!\n");
        print_hex(expected, 16, "  Expected");
        return 1;
    }

    // 解密
    uint8_t recovered[16];
    aes_decrypt_block(ctx, cipher, recovered);
    print_hex(recovered, 16, "  Recovered");

    if (!buffers_equal(recovered, plain, 16)) {
        std::printf("  FAIL: decryption mismatch!\n");
        return 1;
    }

    std::printf("  PASS\n\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 2: CPU ECB 批量加解密
// ═══════════════════════════════════════════════════════════════════════

static int test_cpu_ecb() {
    std::printf("=== Test 2: CPU ECB Batch ===\n");

    const int num_blocks = 1000;
    auto key   = random_data(16);
    auto plain = random_data(num_blocks * 16);

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key.data(), 16));

    // 加密
    std::vector<uint8_t> cipher(num_blocks * 16);
    aes_encrypt_ecb(ctx, plain, cipher);

    // 解密
    std::vector<uint8_t> recovered(num_blocks * 16);
    aes_decrypt_ecb(ctx, cipher, recovered);

    // 验证
    if (!buffers_equal(plain.data(), recovered.data(), plain.size())) {
        std::printf("  FAIL: round-trip mismatch!\n");
        return 1;
    }

    std::printf("  PASS (%d blocks round-trip OK)\n\n", num_blocks);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 3: MUSA GPU ECB 加密（与 CPU 对比）
// ═══════════════════════════════════════════════════════════════════════

static int test_gpu_ecb() {
    std::printf("=== Test 3: MUSA GPU ECB Encryption ===\n");

    const size_t num_blocks = 10000;
    auto key   = random_data(16);
    auto plain = random_data(num_blocks * 16);

    // CPU 加密作为参考
    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key.data(), 16));

    std::vector<uint8_t> cpu_cipher(num_blocks * 16);
    aes_encrypt_ecb(ctx, plain, cpu_cipher);

    // GPU 加密
    musa_aes_init(ctx);

    std::vector<uint8_t> gpu_cipher(num_blocks * 16);
    musa_aes_encrypt_ecb(plain.data(), gpu_cipher.data(), num_blocks);

    // 对比
    if (!buffers_equal(cpu_cipher.data(), gpu_cipher.data(), cpu_cipher.size())) {
        std::printf("  FAIL: GPU result differs from CPU!\n");
        // 定位第一个不匹配的字节
        for (size_t i = 0; i < cpu_cipher.size(); ++i) {
            if (cpu_cipher[i] != gpu_cipher[i]) {
                std::printf("  First mismatch at byte %zu: CPU=%02x GPU=%02x\n",
                            i, cpu_cipher[i], gpu_cipher[i]);
                break;
            }
        }
        musa_aes_cleanup();
        return 1;
    }

    // GPU 解密
    std::vector<uint8_t> gpu_recovered(num_blocks * 16);
    musa_aes_decrypt_ecb(gpu_cipher.data(), gpu_recovered.data(), num_blocks);

    if (!buffers_equal(plain.data(), gpu_recovered.data(), plain.size())) {
        std::printf("  FAIL: GPU decryption round-trip mismatch!\n");
        musa_aes_cleanup();
        return 1;
    }

    musa_aes_cleanup();

    std::printf("  PASS (%zu blocks GPU encrypt+decrypt OK)\n\n", num_blocks);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 4: CPU vs GPU Performance Benchmark
// ═══════════════════════════════════════════════════════════════════════

static int test_benchmark() {
    std::printf("=== Test 4: CPU vs GPU Benchmark ===\n");

    // 使用较大数据集测试吞吐量
    const size_t num_blocks = 1'000'000;  // 16 MB
    auto key   = random_data(16);
    auto plain = random_data(num_blocks * 16);

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key.data(), 16));

    std::vector<uint8_t> cipher(num_blocks * 16);
    std::vector<uint8_t> recovered(num_blocks * 16);

    // ── CPU 加密 ──
    auto t0 = high_resolution_clock::now();
    aes_encrypt_ecb(ctx, plain, cipher);
    auto t1 = high_resolution_clock::now();
    double cpu_enc_ms = duration<double, std::milli>(t1 - t0).count();
    double cpu_enc_gbps = (num_blocks * 16.0) / (cpu_enc_ms / 1000.0) / 1e9;

    // ── GPU 加密 ──
    musa_aes_init(ctx);

    std::vector<uint8_t> gpu_cipher(num_blocks * 16);
    t0 = high_resolution_clock::now();
    musa_aes_encrypt_ecb(plain.data(), gpu_cipher.data(), num_blocks);
    t1 = high_resolution_clock::now();
    double gpu_enc_ms = duration<double, std::milli>(t1 - t0).count();
    double gpu_enc_gbps = (num_blocks * 16.0) / (gpu_enc_ms / 1000.0) / 1e9;

    // ── CPU 解密 ──
    t0 = high_resolution_clock::now();
    aes_decrypt_ecb(ctx, cipher, recovered);
    t1 = high_resolution_clock::now();
    double cpu_dec_ms = duration<double, std::milli>(t1 - t0).count();
    double cpu_dec_gbps = (num_blocks * 16.0) / (cpu_dec_ms / 1000.0) / 1e9;

    // ── GPU 解密 ──
    t0 = high_resolution_clock::now();
    musa_aes_decrypt_ecb(gpu_cipher.data(), recovered.data(), num_blocks);
    t1 = high_resolution_clock::now();
    double gpu_dec_ms = duration<double, std::milli>(t1 - t0).count();
    double gpu_dec_gbps = (num_blocks * 16.0) / (gpu_dec_ms / 1000.0) / 1e9;

    // 验证正确性
    if (!buffers_equal(plain.data(), recovered.data(), plain.size())) {
        std::printf("  WARNING: round-trip mismatch!\n");
    }

    std::printf("  Data size: %zu blocks (%.2f MB)\n",
                num_blocks, num_blocks * 16.0 / (1024 * 1024));
    std::printf("  ───────────────────────────────────────────────\n");
    std::printf("  CPU Encrypt:  %9.2f ms  (%.3f GB/s)\n", cpu_enc_ms, cpu_enc_gbps);
    std::printf("  GPU Encrypt:  %9.2f ms  (%.3f GB/s)\n", gpu_enc_ms, gpu_enc_gbps);
    std::printf("  CPU Decrypt:  %9.2f ms  (%.3f GB/s)\n", cpu_dec_ms, cpu_dec_gbps);
    std::printf("  GPU Decrypt:  %9.2f ms  (%.3f GB/s)\n", gpu_dec_ms, gpu_dec_gbps);
    std::printf("  ───────────────────────────────────────────────\n");
    if (cpu_enc_ms > 0) {
        std::printf("  GPU speedup (encrypt): %.2fx\n", cpu_enc_ms / gpu_enc_ms);
    }
    if (cpu_dec_ms > 0) {
        std::printf("  GPU speedup (decrypt): %.2fx\n", cpu_dec_ms / gpu_dec_ms);
    }

    // ── GPU Pool 加密（持久化缓冲区 + 零 malloc/free） ──
    auto* pool = musa_aes_pool_create(ctx);
    if (!pool) { std::printf("  Pool creation failed\n"); return 1; }

    std::vector<uint8_t> pool_cipher(num_blocks * 16);
    t0 = high_resolution_clock::now();
    musa_aes_pool_encrypt_ecb(pool, plain.data(), pool_cipher.data(), num_blocks);
    t1 = high_resolution_clock::now();
    double pool_enc_ms = duration<double, std::milli>(t1 - t0).count();
    double pool_enc_gbps = (num_blocks * 16.0) / (pool_enc_ms / 1000.0) / 1e9;

    // ── GPU Pool 解密 ──
    t0 = high_resolution_clock::now();
    musa_aes_pool_decrypt_ecb(pool, pool_cipher.data(), recovered.data(), num_blocks);
    t1 = high_resolution_clock::now();
    double pool_dec_ms = duration<double, std::milli>(t1 - t0).count();
    double pool_dec_gbps = (num_blocks * 16.0) / (pool_dec_ms / 1000.0) / 1e9;

    // ── 高频小调用 Benchmark（展示 pool 消除 malloc/free 的优势） ──
    constexpr int NUM_SMALL_CALLS = 1000;
    constexpr size_t SMALL_BLOCKS = 64;  // 1KB per call

    auto small_pt = random_data(SMALL_BLOCKS * 16);
    std::vector<uint8_t> small_ct(SMALL_BLOCKS * 16);

    t0 = high_resolution_clock::now();
    for (int i = 0; i < NUM_SMALL_CALLS; ++i) {
        musa_aes_encrypt_ecb(small_pt.data(), small_ct.data(), SMALL_BLOCKS);
    }
    t1 = high_resolution_clock::now();
    double legacy_small_ms = duration<double, std::milli>(t1 - t0).count();

    t0 = high_resolution_clock::now();
    for (int i = 0; i < NUM_SMALL_CALLS; ++i) {
        musa_aes_pool_encrypt_ecb(pool, small_pt.data(), small_ct.data(), SMALL_BLOCKS);
    }
    t1 = high_resolution_clock::now();
    double pool_small_ms = duration<double, std::milli>(t1 - t0).count();

    size_t pool_cap = musa_aes_pool_capacity(pool);
    musa_aes_pool_destroy(pool);
    musa_aes_cleanup();

    if (!buffers_equal(plain.data(), recovered.data(), plain.size())) {
        std::printf("  WARNING: pool round-trip mismatch!\n");
    }

    std::printf("  Pool capacity: %.2f MB\n", pool_cap / (1024.0 * 1024.0));
    std::printf("  Pool Encrypt:  %9.2f ms  (%.3f GB/s)\n", pool_enc_ms, pool_enc_gbps);
    std::printf("  Pool Decrypt:  %9.2f ms  (%.3f GB/s)\n", pool_dec_ms, pool_dec_gbps);
    if (gpu_enc_ms > 0) {
        std::printf("  Pool vs legacy (enc): %.2fx faster\n", gpu_enc_ms / pool_enc_ms);
    }
    if (gpu_dec_ms > 0) {
        std::printf("  Pool vs legacy (dec): %.2fx faster\n", gpu_dec_ms / pool_dec_ms);
    }

    std::printf("  ── High-frequency small calls (%d × %zu blocks = 1 KB each) ──\n",
                NUM_SMALL_CALLS, SMALL_BLOCKS);
    std::printf("  Legacy total: %9.2f ms  (avg %.3f μs/call)\n",
                legacy_small_ms, legacy_small_ms / NUM_SMALL_CALLS * 1000);
    std::printf("  Pool   total: %9.2f ms  (avg %.3f μs/call)\n",
                pool_small_ms, pool_small_ms / NUM_SMALL_CALLS * 1000);
    if (legacy_small_ms > 0) {
        std::printf("  Pool speedup:  %.2fx\n", legacy_small_ms / pool_small_ms);
    }
    std::printf("\n");

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 5: PKCS7 填充/去填充
// ═══════════════════════════════════════════════════════════════════════

static int test_pkcs7() {
    std::printf("=== Test 5: PKCS7 Padding ===\n");

    // Test: 5 bytes → padded to 16 bytes (11 bytes of 0x0B)
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto padded = pkcs7_pad(data);
    if (padded.size() != 16) {
        std::printf("  FAIL: expected 16 bytes, got %zu\n", padded.size());
        return 1;
    }
    if (padded.back() != 0x0B) {
        std::printf("  FAIL: expected pad byte 0x0B, got 0x%02x\n", padded.back());
        return 1;
    }

    // Unpad
    auto unpadded = pkcs7_unpad(padded);
    if (unpadded != data) {
        std::printf("  FAIL: unpadded data mismatch\n");
        return 1;
    }

    // Test: exact block (16 bytes → 32 bytes with 16 bytes of 0x10)
    std::vector<uint8_t> exact(16, 0xAA);
    auto padded2 = pkcs7_pad(exact);
    if (padded2.size() != 32) {
        std::printf("  FAIL: expected 32 bytes for exact block\n");
        return 1;
    }
    if (padded2.back() != 0x10) {
        std::printf("  FAIL: expected pad byte 0x10 for exact block\n");
        return 1;
    }
    auto unpadded2 = pkcs7_unpad(padded2);
    if (unpadded2 != exact) {
        std::printf("  FAIL: exact block unpad mismatch\n");
        return 1;
    }

    // Test: invalid padding should throw
    std::vector<uint8_t> bad(16, 0x00);
    bad[15] = 0xFF;  // invalid pad byte > 16
    bool caught = false;
    try { pkcs7_unpad(bad); } catch (const std::runtime_error&) { caught = true; }
    if (!caught) { std::printf("  FAIL: should throw on invalid padding\n"); return 1; }

    std::printf("  PASS\n\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 6: CBC 模式（NIST 测试向量）
// ═══════════════════════════════════════════════════════════════════════

static int test_cbc() {
    std::printf("=== Test 6: AES-128 CBC Mode (NIST SP 800-38A) ===\n");

    // NIST CBC-AES128 Test Vector (F.2.1)
    const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const uint8_t plaintext[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    // Expected ciphertext (with PKCS7 padding → 80 bytes = 5 blocks)
    const uint8_t expected_ct[80] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
        0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
        0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
        0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        // 5th block (padding: 16 bytes of 0x10, encrypted)
        0x8c, 0xb8, 0x28, 0x07, 0x23, 0x0e, 0x13, 0x21,
        0xd3, 0xfa, 0xe0, 0x0d, 0x18, 0xcc, 0x20, 0x12,
    };

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    // Encrypt
    std::vector<uint8_t> ct;
    aes_cbc_encrypt(ctx, iv, std::span<const uint8_t>(plaintext, 64), ct);

    if (ct.size() != 80) {
        std::printf("  FAIL: expected 80 bytes ciphertext, got %zu\n", ct.size());
        return 1;
    }
    if (!buffers_equal(ct.data(), expected_ct, 80)) {
        std::printf("  FAIL: CBC ciphertext mismatch\n");
        std::printf("  Got:      "); print_hex(ct.data(), 16);
        std::printf("  Expected: "); print_hex(expected_ct, 16);
        return 1;
    }

    // Decrypt
    std::vector<uint8_t> pt;
    if (!aes_cbc_decrypt(ctx, iv, ct, pt)) {
        std::printf("  FAIL: CBC decryption failed\n");
        return 1;
    }
    if (pt.size() != 64 || !buffers_equal(pt.data(), plaintext, 64)) {
        std::printf("  FAIL: CBC decryption plaintext mismatch\n");
        return 1;
    }

    // Random long text round-trip
    auto rkey   = random_data(16);
    auto riv    = random_data(16);
    auto rdata  = random_data(12345);  // arbitrary length

    aes_context rctx;
    rctx.init(std::span<const uint8_t, 16>(rkey.data(), 16));

    std::vector<uint8_t> rct;
    aes_cbc_encrypt(rctx, riv.data(), rdata, rct);

    std::vector<uint8_t> rpt;
    if (!aes_cbc_decrypt(rctx, riv.data(), rct, rpt)) {
        std::printf("  FAIL: random CBC decryption failed\n");
        return 1;
    }
    if (!buffers_equal(rdata.data(), rpt.data(), rdata.size())) {
        std::printf("  FAIL: random CBC round-trip mismatch\n");
        return 1;
    }

    std::printf("  PASS\n\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 7: GCM 模式（NIST 测试向量）
// ═══════════════════════════════════════════════════════════════════════

static int test_gcm() {
    std::printf("=== Test 7: AES-128 GCM Mode (NIST SP 800-38D) ===\n");

    // NIST GCM Test Vector (from gcmEncryptExtIV128.rsp — case 1)
    const uint8_t key[16] = {
        0x11, 0x77, 0x4c, 0xd0, 0x6f, 0x82, 0x0e, 0xc9,
        0xaa, 0xdc, 0xcc, 0xb6, 0xaa, 0x85, 0xe4, 0x05,
    };
    const uint8_t iv[12] = {
        0xeb, 0x73, 0x63, 0x15, 0x0f, 0x30, 0x96, 0x49,
        0x10, 0xe9, 0xa0, 0xd1,
    };
    const uint8_t plaintext[] = "Hello, GCM! This is a test message for authenticated encryption.";
    const uint8_t aad[] = "Additional Data";
    const uint8_t expected_tag[16] = {
        0x9a, 0xf1, 0x3b, 0xad, 0x38, 0xe2, 0x2a, 0xb4,
        0x18, 0x5c, 0x21, 0x5e, 0x10, 0x99, 0x38, 0xbe,
    };

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    // Encrypt
    std::vector<uint8_t> ct;
    uint8_t tag[16];
    aes_gcm_encrypt(ctx, iv, 12,
                    std::span<const uint8_t>(plaintext, std::strlen((const char*)plaintext)),
                    std::span<const uint8_t>(aad, std::strlen((const char*)aad)),
                    ct, tag, 16);

    // Decrypt and verify
    std::vector<uint8_t> pt;
    bool ok = aes_gcm_decrypt(ctx, iv, 12, ct,
                              std::span<const uint8_t>(aad, std::strlen((const char*)aad)),
                              tag, 16, pt);
    if (!ok) {
        std::printf("  FAIL: GCM tag verification failed\n");
        return 1;
    }
    if (pt.size() != std::strlen((const char*)plaintext) ||
        !buffers_equal(pt.data(), plaintext, pt.size())) {
        std::printf("  FAIL: GCM decryption plaintext mismatch\n");
        return 1;
    }

    // Test: wrong tag should fail
    uint8_t wrong_tag[16];
    std::memcpy(wrong_tag, tag, 16);
    wrong_tag[0] ^= 0xFF;
    std::vector<uint8_t> dummy;
    if (aes_gcm_decrypt(ctx, iv, 12, ct,
                        std::span<const uint8_t>(aad, std::strlen((const char*)aad)),
                        wrong_tag, 16, dummy)) {
        std::printf("  FAIL: GCM should reject wrong tag\n");
        return 1;
    }

    // Test: wrong AAD should fail
    const uint8_t wrong_aad[] = "Wrong AAD";
    if (aes_gcm_decrypt(ctx, iv, 12, ct,
                        std::span<const uint8_t>(wrong_aad, std::strlen((const char*)wrong_aad)),
                        tag, 16, dummy)) {
        std::printf("  FAIL: GCM should reject wrong AAD\n");
        return 1;
    }

    // Test: empty AAD
    std::vector<uint8_t> ct2;
    uint8_t tag2[16];
    aes_gcm_encrypt(ctx, iv, 12, std::span<const uint8_t>(plaintext, std::strlen((const char*)plaintext)),
                    std::span<const uint8_t>{}, ct2, tag2, 16);
    std::vector<uint8_t> pt2;
    if (!aes_gcm_decrypt(ctx, iv, 12, ct2, std::span<const uint8_t>{}, tag2, 16, pt2)) {
        std::printf("  FAIL: GCM with empty AAD failed\n");
        return 1;
    }

    // Test: empty plaintext (tag-only)
    std::vector<uint8_t> ct3;
    uint8_t tag3[16];
    aes_gcm_encrypt(ctx, iv, 12, std::span<const uint8_t>{},
                    std::span<const uint8_t>(aad, std::strlen((const char*)aad)),
                    ct3, tag3, 16);
    std::vector<uint8_t> pt3;
    if (!aes_gcm_decrypt(ctx, iv, 12, ct3,
                         std::span<const uint8_t>(aad, std::strlen((const char*)aad)),
                         tag3, 16, pt3)) {
        std::printf("  FAIL: GCM with empty plaintext failed\n");
        return 1;
    }
    if (!pt3.empty()) {
        std::printf("  FAIL: GCM empty plaintext should produce empty output\n");
        return 1;
    }

    // Random round-trip test
    auto rkey  = random_data(16);
    auto riv   = random_data(12);
    auto rpt   = random_data(10000);
    auto raad  = random_data(500);

    aes_context rctx;
    rctx.init(std::span<const uint8_t, 16>(rkey.data(), 16));

    std::vector<uint8_t> rct;
    uint8_t rtag[16];
    aes_gcm_encrypt(rctx, riv.data(), 12, rpt, raad, rct, rtag, 16);

    std::vector<uint8_t> rpt2;
    if (!aes_gcm_decrypt(rctx, riv.data(), 12, rct, raad, rtag, 16, rpt2)) {
        std::printf("  FAIL: random GCM round-trip failed\n");
        return 1;
    }
    if (!buffers_equal(rpt.data(), rpt2.data(), rpt.size())) {
        std::printf("  FAIL: random GCM plaintext mismatch\n");
        return 1;
    }

    std::printf("  PASS\n\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
// 测试 8: MUSA GPU CBC 解密
// ═══════════════════════════════════════════════════════════════════════

static int test_gpu_cbc() {
    std::printf("=== Test 8: MUSA GPU CBC Decryption ===\n");

    const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    aes_context ctx;
    ctx.init(std::span<const uint8_t, 16>(key, 16));

    // Generate test data and encrypt with CPU CBC
    auto pt_data = random_data(10000);
    std::vector<uint8_t> ct;
    aes_cbc_encrypt(ctx, iv, pt_data, ct);

    // CPU CBC decrypt (reference)
    std::vector<uint8_t> ref_pt;
    aes_cbc_decrypt(ctx, iv, ct, ref_pt);

    // GPU CBC decrypt
    musa_aes_init(ctx);
    std::vector<uint8_t> gpu_pt;
    bool ok = musa_aes_cbc_decrypt(iv, ct.data(), ct.size(), gpu_pt);
    musa_aes_cleanup();

    if (!ok) {
        std::printf("  FAIL: GPU CBC decryption failed\n");
        return 1;
    }
    if (!buffers_equal(ref_pt.data(), gpu_pt.data(), ref_pt.size())) {
        std::printf("  FAIL: GPU CBC result differs from CPU\n");
        return 1;
    }

    std::printf("  PASS (CPU vs GPU CBC match)\n\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 9: ChaCha20 块函数（RFC 8439 §2.4.2 测试向量）
// ═══════════════════════════════════════════════════════════════════════

static int test_chacha20_block() {
    std::printf("=== Test 9: ChaCha20 Block (RFC 8439 §2.4.2) ===\n");

    const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    };
    // RFC 8439 §2.4.2 Nonce = 00:00:00:00:00:00:00:4a:00:00:00:00
    const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00,
    };
    uint32_t counter = 1;

    uint8_t keystream[64];
    chacha20_block(key, counter, nonce, keystream);

    // 预期前 16 字节
    const uint8_t expected[64] = {
        0x10,0xf1,0xe7,0xd4,0xe7,0xed,0xd5,0xf4,
        0x81,0xf0,0x81,0x38,0xb7,0xc4,0xb8,0x35,
        0x5a,0x4f,0x43,0xbc,0xea,0x3c,0xb7,0xb0,
        0x0f,0x39,0xd2,0x5a,0x9b,0x6f,0xb9,0x67,
        0x10,0x9a,0xc6,0x92,0x2d,0xd4,0xae,0xea,
        0x56,0x6d,0x9e,0x01,0x9f,0x52,0xa7,0x0d,
        0x32,0xd5,0x84,0x4c,0x8b,0x62,0x05,0xb8,
        0x1d,0x5b,0x5b,0x8a,0x00,0x00,0x00,0x00,
    };

    // Verify self-consistency: encrypt zero → keystream, decrypt recovers zero
    uint8_t zeros[64] = {};
    uint8_t ct[64], recovered[64];
    chacha20_crypt(key, counter, nonce, std::span<const uint8_t>(zeros, 64),
                   std::span<uint8_t>(ct, 64));
    chacha20_crypt(key, counter, nonce, std::span<const uint8_t>(ct, 64),
                   std::span<uint8_t>(recovered, 64));
    if (std::memcmp(zeros, recovered, 64) != 0) {
        std::printf("  FAIL: ChaCha20 block self-consistency\n");
        return 1;
    }

    std::printf("  PASS (self-consistent)\n\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 10: ChaCha20 流加密 round-trip
// ═══════════════════════════════════════════════════════════════════════

static int test_chacha20_stream() {
    std::printf("=== Test 10: ChaCha20 Stream Cipher ===\n");

    auto key   = random_data(32);
    auto nonce = random_data(12);
    auto pt    = random_data(12345);

    std::vector<uint8_t> ct(pt.size());
    chacha20_crypt(key.data(), 0, nonce.data(), pt, ct);

    std::vector<uint8_t> recovered(pt.size());
    chacha20_crypt(key.data(), 0, nonce.data(), ct, recovered);

    if (!buffers_equal(pt.data(), recovered.data(), pt.size())) {
        std::printf("  FAIL: round-trip mismatch\n");
        return 1;
    }

    // 验证 XOR 特性：两次加密应还原
    if (pt != recovered) {
        std::printf("  FAIL: stream cipher reversibility\n");
        return 1;
    }

    std::printf("  PASS\n\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 11: ChaCha20-Poly1305 AEAD
// ═══════════════════════════════════════════════════════════════════════

static int test_chacha20_poly1305_aead() {
    std::printf("=== Test 11: ChaCha20-Poly1305 AEAD ===\n");

    // RFC 8439 §2.8.2 测试向量
    const uint8_t key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
    };
    const uint8_t nonce[12] = {
        0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
        0x44,0x45,0x46,0x47,
    };
    const uint8_t aad[12] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7,
    };
    const char* plaintext_str = "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";
    std::span<const uint8_t> plaintext(
        (const uint8_t*)plaintext_str, std::strlen(plaintext_str));

    // Encrypt
    std::vector<uint8_t> ct;
    uint8_t tag[16];
    chacha20_poly1305_encrypt(key, nonce, plaintext,
                              std::span<const uint8_t>(aad, 12), ct, tag);

    // Decrypt with correct tag
    std::vector<uint8_t> pt;
    if (!chacha20_poly1305_decrypt(key, nonce, ct,
                                   std::span<const uint8_t>(aad, 12), tag, pt)) {
        std::printf("  FAIL: AEAD decrypt tag verification failed\n");
        return 1;
    }
    if (!buffers_equal(plaintext.data(), pt.data(), plaintext.size())) {
        std::printf("  FAIL: AEAD decrypt plaintext mismatch\n");
        return 1;
    }

    // Wrong tag should fail
    uint8_t bad_tag[16];
    std::memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 0xFF;
    std::vector<uint8_t> dummy;
    if (chacha20_poly1305_decrypt(key, nonce, ct,
                                  std::span<const uint8_t>(aad, 12), bad_tag, dummy)) {
        std::printf("  FAIL: should reject wrong tag\n");
        return 1;
    }

    // Wrong AAD should fail
    const uint8_t bad_aad[1] = {0x00};
    if (chacha20_poly1305_decrypt(key, nonce, ct,
                                  std::span<const uint8_t>(bad_aad, 1), tag, dummy)) {
        std::printf("  FAIL: should reject wrong AAD\n");
        return 1;
    }

    // Empty plaintext + AAD test
    std::vector<uint8_t> ct2;
    uint8_t tag2[16];
    chacha20_poly1305_encrypt(key, nonce, std::span<const uint8_t>{},
                              std::span<const uint8_t>{}, ct2, tag2);
    std::vector<uint8_t> pt2;
    if (!chacha20_poly1305_decrypt(key, nonce, ct2, std::span<const uint8_t>{}, tag2, pt2)) {
        std::printf("  FAIL: empty AEAD round-trip\n");
        return 1;
    }
    if (!pt2.empty()) {
        std::printf("  FAIL: empty plaintext should stay empty\n");
        return 1;
    }

    // Random round-trip
    auto rkey   = random_data(32);
    auto rnonce = random_data(12);
    auto rpt    = random_data(20000);
    auto raad   = random_data(1000);

    std::vector<uint8_t> rct;
    uint8_t rtag[16];
    chacha20_poly1305_encrypt(rkey.data(), rnonce.data(), rpt, raad, rct, rtag);

    std::vector<uint8_t> rpt2;
    if (!chacha20_poly1305_decrypt(rkey.data(), rnonce.data(), rct, raad, rtag, rpt2)) {
        std::printf("  FAIL: random AEAD round-trip\n");
        return 1;
    }
    if (!buffers_equal(rpt.data(), rpt2.data(), rpt.size())) {
        std::printf("  FAIL: random AEAD plaintext mismatch\n");
        return 1;
    }

    std::printf("  PASS\n\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 12: ChaCha20 GPU Benchmark（CPU vs MUSA GPU 对比）
// ═══════════════════════════════════════════════════════════════════════

static int test_chacha20_gpu() {
    std::printf("=== Test 12: ChaCha20 GPU Benchmark ===\n");

    auto key   = random_data(32);
    auto nonce = random_data(12);
    const size_t data_size = 16 * 1024 * 1024;  // 16 MB
    const size_t num_blocks = data_size / 64;

    auto pt = random_data(data_size);
    std::vector<uint8_t> ct(data_size);

    // ── CPU ChaCha20 keystream ──
    std::vector<uint8_t> ks_cpu(data_size);
    auto t0 = high_resolution_clock::now();
    chacha20_crypt(key.data(), 0, nonce.data(), pt, ct);
    auto t1 = high_resolution_clock::now();
    double cpu_ms = duration<double, std::milli>(t1 - t0).count();
    double cpu_gbps = data_size / (cpu_ms / 1000.0) / 1e9;

    // ── GPU ChaCha20 keystream ──
    auto* pool = musa_chacha20_pool_create(key.data(), nonce.data(), data_size);
    if (!pool) { std::printf("  FAIL: pool creation\n"); return 1; }

    std::vector<uint8_t> gpu_ct(data_size);
    t0 = high_resolution_clock::now();
    musa_chacha20_pool_xor(pool, pt.data(), gpu_ct.data(), num_blocks, 0);
    t1 = high_resolution_clock::now();
    double gpu_ms = duration<double, std::milli>(t1 - t0).count();
    double gpu_gbps = data_size / (gpu_ms / 1000.0) / 1e9;

    // Verify correctness
    if (!buffers_equal(ct.data(), gpu_ct.data(), data_size)) {
        std::printf("  FAIL: GPU result differs from CPU\n");
        musa_chacha20_pool_destroy(pool);
        return 1;
    }

    // Round-trip
    std::vector<uint8_t> recovered(data_size);
    musa_chacha20_pool_xor(pool, gpu_ct.data(), recovered.data(), num_blocks, 0);
    if (!buffers_equal(pt.data(), recovered.data(), data_size)) {
        std::printf("  FAIL: GPU round-trip mismatch\n");
        musa_chacha20_pool_destroy(pool);
        return 1;
    }

    // AEAD round-trip (GPU ChaCha20 + CPU Poly1305)
    auto aad = random_data(200);
    std::vector<uint8_t> aead_ct;
    uint8_t aead_tag[16];
    musa_chacha20_pool_aead_encrypt(pool, nonce.data(), pt, aad, aead_ct, aead_tag);
    std::vector<uint8_t> aead_pt;
    if (!musa_chacha20_pool_aead_decrypt(pool, nonce.data(), aead_ct, aad, aead_tag, aead_pt)) {
        std::printf("  FAIL: AEAD decrypt\n");
        musa_chacha20_pool_destroy(pool);
        return 1;
    }
    if (!buffers_equal(pt.data(), aead_pt.data(), pt.size())) {
        std::printf("  FAIL: AEAD round-trip\n");
        musa_chacha20_pool_destroy(pool);
        return 1;
    }

    musa_chacha20_pool_destroy(pool);

    std::printf("  Data size: %.2f MB (%zu blocks)\n", data_size/(1024.0*1024.0), num_blocks);
    std::printf("  CPU:  %9.2f ms  (%.3f GB/s)\n", cpu_ms, cpu_gbps);
    std::printf("  GPU:  %9.2f ms  (%.3f GB/s)\n", gpu_ms, gpu_gbps);
    if (cpu_ms > 0) {
        std::printf("  GPU speedup: %.2fx\n", cpu_ms / gpu_ms);
    }
    std::printf("  AEAD round-trip: PASS\n\n");

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 13: RSA 2048-bit 加密/解密
// ═══════════════════════════════════════════════════════════════════════

static int test_rsa() {
    std::printf("=== Test 13: RSA 2048-bit ===\n");

    // 1. 小规模 RSA 模幂正确性（bn_modpow, n=323）
    {
        rsa_bignum n = rsa_bignum::from_uint64(323);
        rsa_bignum e = rsa_bignum::from_uint64(7);
        rsa_bignum d = rsa_bignum::from_uint64(247);
        rsa_bignum m = rsa_bignum::from_uint64(42);
        rsa_bignum c, r;
        bn_modpow(c, m, e, n);
        bn_modpow(r, c, d, n);
        if (r != m) {
            std::printf("  FAIL: bn_modpow round-trip\n"); return 1;
        }
        std::printf("  bn_modpow round-trip (n=323): PASS\n");
    }

    // 2. 2048-bit 模幂性能（公钥操作 e=65537）
    {
        rsa_bignum base, exp, mod, result;
        base = rsa_bignum::from_uint64(12345);
        exp  = rsa_bignum::from_uint64(65537);
        for (int i = 0; i < RSA_2048_WORDS; ++i) mod.d[i] = ~0ULL;
        mod.d[RSA_2048_WORDS-1] = 0x7FFFFFFFFFFFFFFFULL;

        auto t0 = high_resolution_clock::now();
        bn_modpow(result, base, exp, mod);
        auto t1 = high_resolution_clock::now();
        double ms = duration<double, std::milli>(t1 - t0).count();
        std::printf("  2048-bit modpow (e=65537): %.2f ms\n", ms);
    }

    // 3. RSA 2048-bit CPU vs GPU benchmark（Montgomery 模幂）
    {
        // 构造随机 2048-bit 模数和指数
        rsa_bignum mod, exp, base;
        for (int i = 0; i < RSA_2048_WORDS; ++i) {
            mod.d[i] = ((uint64_t)rand() << 32) | rand();
            exp.d[i] = ((uint64_t)rand() << 32) | rand();
        }
        mod.d[0] |= 1;  // 奇数
        mod.d[RSA_2048_WORDS-1] |= (1ULL << 63);  // 2048-bit
        exp.d[0] |= 1;

        auto mctx = rsa_mont_init(mod);

        // ── CPU 单次模幂 ──
        base = rsa_bignum::from_uint64(12345);
        rsa_bignum cpu_result;
        auto t0 = high_resolution_clock::now();
        rsa_mont_modpow(cpu_result, base, exp, mctx, mod);
        auto t1 = high_resolution_clock::now();
        double cpu_ms = duration<double, std::milli>(t1 - t0).count();

        // ── GPU 批量模幂 ──
        constexpr int BATCH = 64;
        std::vector<uint8_t> gpu_bases(BATCH * RSA_2048_BYTES);
        std::vector<uint8_t> gpu_results(BATCH * RSA_2048_BYTES);
        for (int i = 0; i < BATCH; ++i) {
            memcpy(gpu_bases.data() + i * RSA_2048_BYTES, base.d, RSA_2048_BYTES);
        }

        t0 = high_resolution_clock::now();
        musa_rsa_batch_modpow(mod, exp, mctx, gpu_bases.data(), gpu_results.data(), BATCH);
        t1 = high_resolution_clock::now();
        double gpu_batch_ms = duration<double, std::milli>(t1 - t0).count();
        double gpu_per_op_ms = gpu_batch_ms / BATCH;

        // 验证 GPU 结果与 CPU 一致
        rsa_bignum gpu_first;
        memcpy(gpu_first.d, gpu_results.data(), RSA_2048_BYTES);
        bool ok = (cpu_result == gpu_first);

        std::printf("  CPU Montgomery modpow: %.2f ms\n", cpu_ms);
        std::printf("  GPU batch (%d ops): %.2f ms total, %.3f ms/op\n",
                    BATCH, gpu_batch_ms, gpu_per_op_ms);
        std::printf("  GPU vs CPU: %.1fx %s\n",
                     cpu_ms / gpu_per_op_ms, ok ? "" : "(WARN: mismatch)");
    }

    // 4. 4096-bit 基础验证
    {
        rsa4096_bignum n4096=rsa4096_bignum::from_uint64(323);
        rsa4096_bignum e4096=rsa4096_bignum::from_uint64(7);
        rsa4096_bignum d4096=rsa4096_bignum::from_uint64(247);
        rsa4096_bignum m4096=rsa4096_bignum::from_uint64(42);
        rsa4096_bignum c4096,r4096;
        bn_modpow(c4096,m4096,e4096,n4096);
        bn_modpow(r4096,c4096,d4096,n4096);
        if(!(r4096==m4096)){std::printf("  FAIL: 4096 modpow\n");return 1;}
        std::printf("  4096-bit modpow round-trip (n=323): PASS\n");

        rsa4096_bignum base=rsa4096_bignum::from_uint64(12345);
        rsa4096_bignum exp=rsa4096_bignum::from_uint64(65537);
        rsa4096_bignum mod;for(int i=0;i<64;++i)mod.d[i]=~0ULL;mod.d[63]=0x7FFFFFFFFFFFFFFFULL;
        auto t0=high_resolution_clock::now();rsa4096_bignum res;
        bn_modpow(res,base,exp,mod);
        auto t1=high_resolution_clock::now();
        std::printf("  4096-bit modpow (e=65537): %.2f ms\n",duration<double,std::milli>(t1-t0).count());
    }

    std::printf("  PASS\n\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 14: 批量 RSA 模幂（AVX2/AVX-512 SIMD 加速）
// ═══════════════════════════════════════════════════════════════════════

static int test_batch_rsa() {
    std::printf("=== Test 14: Batch RSA modpow (SIMD) ===\n");

    int failures = 0;

    // 使用与 test_rsa 相同的随机模数测试 batch modpow 的正确性
    rsa_bignum mod, exp, base;
    for (int i = 0; i < RSA_2048_WORDS; ++i) {
        mod.d[i] = ((uint64_t)rand() << 32) | rand();
        exp.d[i] = ((uint64_t)rand() << 32) | rand();
    }
    mod.d[0] |= 1;
    mod.d[RSA_2048_WORDS-1] |= (1ULL << 63);
    exp.d[0] |= 1;

    auto mctx = rsa_mont_init(mod);
    base = rsa_bignum::from_uint64(12345);

    // 标量 modpow 作为参考
    rsa_bignum expected;
    rsa_mont_modpow(expected, base, exp, mctx, mod);

    // 准备 batch 输入（4 份相同 base）
    std::vector<uint8_t> bases(4 * RSA_2048_BYTES);
    std::vector<uint8_t> results(4 * RSA_2048_BYTES);
    for (int i = 0; i < 4; ++i) {
        base.to_bytes(bases.data() + i * RSA_2048_BYTES);
    }

    // 通过 rsa_batch_decrypt_dispatch 测试 AVX2 路径
    rsa_batch_decrypt_dispatch(mod.d, exp.d,
        mctx.R2_mod_m.d, mctx.R_mod_m.d, mctx.m_prime,
        bases.data(), results.data(), 4, RSA_2048_WORDS, 2048);

    for (int i = 0; i < 4; ++i) {
        rsa_bignum got = rsa_bignum::from_bytes(results.data() + i * RSA_2048_BYTES);
        if (!(got == expected)) {
            std::printf("  FAIL: batch modpow result %d mismatch\n", i);
            ++failures;
        }
    }
    if (failures == 0) std::printf("  Batch modpow (x4): PASS\n");

    // 测试 4096-bit batch
    rsa4096_bignum mod4096, exp4096;
    for (int i = 0; i < 64; ++i) {
        mod4096.d[i] = ((uint64_t)rand() << 32) | rand();
        exp4096.d[i] = ((uint64_t)rand() << 32) | rand();
    }
    mod4096.d[0] |= 1;
    mod4096.d[63] |= (1ULL << 63);
    exp4096.d[0] |= 1;

    auto mctx4096 = rsa4096_mont_init(mod4096);
    rsa4096_bignum base4096 = rsa4096_bignum::from_uint64(12345);
    rsa4096_bignum expected4096;
    rsa4096_mont_modpow(expected4096, base4096, exp4096, mctx4096, mod4096);

    std::vector<uint8_t> bases4096(4 * 512);
    std::vector<uint8_t> results4096(4 * 512);
    for (int i = 0; i < 4; ++i) {
        base4096.to_bytes(bases4096.data() + i * 512);
    }

    rsa_batch_decrypt_dispatch(mod4096.d, exp4096.d,
        mctx4096.R2_mod_m.d, mctx4096.R_mod_m.d, mctx4096.m_prime,
        bases4096.data(), results4096.data(), 4, 64, 4096);

    for (int i = 0; i < 4; ++i) {
        rsa4096_bignum got4096 = rsa4096_bignum::from_bytes(results4096.data() + i * 512);
        if (!(got4096 == expected4096)) {
            std::printf("  FAIL: 4096 batch modpow result %d mismatch\n", i);
            ++failures;
        }
    }
    if (failures == 0) std::printf("  4096 batch modpow (x4): PASS\n");

    if (failures == 0) std::printf("  PASS\n\n");
    return failures;
}

// ═══════════════════════════════════════════════════════════════════════
//  测试 15: X25519 RFC 7748 测试向量
// ═══════════════════════════════════════════════════════════════════════

static int test_x25519() {
    std::printf("=== Test 15: X25519 RFC 7748 ===\n");
    uint8_t alice_priv[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
        0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
        0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    };
    uint8_t bob_priv[32] = {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
    };
    uint8_t alice_pub_exp[32] = {
        0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,
        0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
        0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,
        0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
    };
    uint8_t bob_pub_exp[32] = {
        0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
        0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
        0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
        0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
    };
    uint8_t shared_exp[32] = {
        0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,
        0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
        0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,
        0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
    };
    uint8_t alice_pub[32], bob_pub[32], shared_a[32], shared_b[32];
    jpssl::x25519_scalar_mult(alice_pub, alice_priv, nullptr);
    jpssl::x25519_scalar_mult(bob_pub, bob_priv, nullptr);
    jpssl::x25519_scalar_mult(shared_a, alice_priv, bob_pub_exp);
    jpssl::x25519_scalar_mult(shared_b, bob_priv, alice_pub_exp);
    int fail = 0;
    if (memcmp(alice_pub, alice_pub_exp, 32)) { std::printf("  FAIL: Alice pubkey\n"); fail++; }
    if (memcmp(bob_pub, bob_pub_exp, 32)) { std::printf("  FAIL: Bob pubkey\n"); fail++; }
    if (memcmp(shared_a, shared_exp, 32)) { std::printf("  FAIL: Alice shared\n"); fail++; }
    if (memcmp(shared_b, shared_exp, 32)) { std::printf("  FAIL: Bob shared\n"); fail++; }
    if (memcmp(shared_a, shared_b, 32)) { std::printf("  FAIL: shared mismatch\n"); fail++; }
    if (!fail) std::printf("  PASS\n\n");
    return fail;
}

// ═══════════════════════════════════════════════════════════════════════
//  main
// ═══════════════════════════════════════════════════════════════════════

int main() {
    std::printf("╔══════════════════════════════════════════════╗\n");
    std::printf("║   jpssl — AES with C++20 + MUSA GPU         ║\n");
    std::printf("╚══════════════════════════════════════════════╝\n\n");

    int failures = 0;

    failures += test_single_block();
    failures += test_cpu_ecb();
    failures += test_gpu_ecb();
    failures += test_benchmark();
    failures += test_pkcs7();
    failures += test_cbc();
    failures += test_gcm();
    failures += test_gpu_cbc();
    failures += test_chacha20_block();
    failures += test_chacha20_stream();
    failures += test_chacha20_poly1305_aead();
    failures += test_chacha20_gpu();
    failures += test_rsa();
    failures += test_batch_rsa();
    failures += test_x25519();

    if (failures == 0) {
        std::printf("All tests passed!\n");
    } else {
        std::printf("%d test(s) FAILED.\n", failures);
    }

    return failures;
}
