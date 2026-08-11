/**
 * bench_cipher_suites.cpp — 密码套件吞吐量测试 & OpenSSL 对比
 *
 * 覆盖以下 11 个密码套件：
 *
 *   TLS 1.3:
 *     TLS_AES_128_GCM_SHA256          (0x1301) — AES-128-GCM + SHA-256
 *     TLS_AES_256_GCM_SHA384          (0x1302) — AES-256-GCM + SHA-384
 *     TLS_CHACHA20_POLY1305_SHA256    (0x1303) — ChaCha20-Poly1305 + SHA-256
 *     TLS_AES_128_CCM_SHA256          (0x1304) — AES-128-CCM + SHA-256
 *     TLS_AES_128_CCM_8_SHA256        (0x1305) — AES-128-CCM-8 + SHA-256
 *
 *   TLS 1.2:
 *     TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256          (0xC02B)
 *     TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384          (0xC02C)
 *     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256             (0xC02F)
 *     TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384             (0xC030)
 *     TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256       (0xCCA8)
 *     TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256     (0xCCA9)
 *
 * 基准方法（与 bench_ed25519_ossl 一致）：
 *   - 预热 + 自适应迭代次数，每轮约 target_ms，取 rounds 轮中的最小值，
 *     消除 CPU 频率波动与首次调用开销的影响；
 *   - jpssl 与 OpenSSL 的输出缓冲均预先分配，计时区间不含堆分配；
 *   - 默认按 TLS 记录尺寸（16 KiB）分片加密，每条记录使用
 *     base_iv ^ seq 风格的独立 nonce，更贴近真实 TLS 记录层；
 *     --record 0 退化为整块原始吞吐。
 *
 * 编译：需要链接 OpenSSL (libssl + libcrypto)
 */

#include "test_utils.hpp"
#include "tls.hpp"
#include "aes.hpp"
#include "chacha20_poly1305.hpp"
#include "sha256.hpp"
#include "sha512.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <chrono>
#include <vector>
#include <cstring>
#include <iostream>
#include <cstdio>
#include <string>
#include <cmath>
#include <algorithm>

using namespace jpssl;
using namespace jpssl::tls;
using namespace jptest;
using namespace std::chrono;

// ═══════════════════════════════════════════════════════════════════════
//  参数与计时工具
// ═══════════════════════════════════════════════════════════════════════

static constexpr size_t DEFAULT_DATA = 16ULL * 1024 * 1024;  // 16 MB
static constexpr size_t DEFAULT_RECORD = 16 * 1024;          // TLS 1.3 最大记录载荷
// CCM with 12-byte nonce: max plaintext per call = 2^24 - 1
static constexpr size_t CCM_MAX = (1ULL << 24) - 1;

struct Opts {
    size_t data_size = DEFAULT_DATA;
    size_t record_size = DEFAULT_RECORD;  // 0 = 整块
    int rounds = 5;
    double target_ms = 200.0;
    bool with_ossl = true;
};

static void print_usage() {
    std::printf(
        "usage: bench_cipher_suites [--data-mb N] [--record N] [--rounds N]"
        " [--target-ms N] [--no-ossl]\n"
        "  --data-mb N    每个方向的数据量（MiB，默认 16）\n"
        "  --record N     TLS 记录尺寸（字节，默认 16384；0 = 整块单次调用）\n"
        "  --rounds N     基准轮数，取最小值（默认 5）\n"
        "  --target-ms N  每轮目标时长 ms（默认 200）\n"
        "  --no-ossl      跳过 OpenSSL 对照\n");
}

static Opts parse_args(int argc, char** argv) {
    Opts o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> long long {
            if (i + 1 >= argc) { std::printf("missing value for %s\n", a.c_str()); exit(1); }
            return std::atoll(argv[++i]);
        };
        if (a == "--data-mb") {
            long long v = next();
            o.data_size = (size_t)std::max<long long>(1, v) * 1024 * 1024;
        } else if (a == "--record") {
            o.record_size = (size_t)std::max<long long>(0, next());
        } else if (a == "--rounds") {
            o.rounds = (int)std::max<long long>(1, next());
        } else if (a == "--target-ms") {
            o.target_ms = std::max(10.0, (double)next());
        } else if (a == "--no-ossl") {
            o.with_ossl = false;
        } else if (a == "-h" || a == "--help") {
            print_usage();
            exit(0);
        } else {
            std::printf("unknown option: %s\n", a.c_str());
            print_usage();
            exit(1);
        }
    }
    return o;
}

static double to_gbps(size_t bytes, double ms) {
    return (bytes / 1e9) / (ms / 1000.0);
}

/// 预热 + 自适应迭代 + 多轮取最小（返回单次调用毫秒数）
template <typename F>
static double bench_min_ms(const Opts& o, F&& f) {
    f();  // 预热（含首次 CPU 特性检测 / 缓冲预分配）
    auto t0 = steady_clock::now();
    const int est = 8;
    for (int i = 0; i < est; ++i) f();
    auto t1 = steady_clock::now();
    double per_ns = duration<double, std::nano>(t1 - t0).count() / est;
    if (per_ns < 1000.0) {
        const int est2 = 2000;
        t0 = steady_clock::now();
        for (int i = 0; i < est2; ++i) f();
        t1 = steady_clock::now();
        per_ns = duration<double, std::nano>(t1 - t0).count() / est2;
    }
    long long iters = 1;
    if (per_ns > 0.0) {
        iters = (long long)(o.target_ms * 1e6 / per_ns);
        iters = iters < 1 ? 1 : (iters > 2000000 ? 2000000 : iters);
    }
    double best = 1e300;
    for (int r = 0; r < o.rounds; ++r) {
        auto s = steady_clock::now();
        for (long long i = 0; i < iters; ++i) f();
        auto e = steady_clock::now();
        double ms = duration<double, std::milli>(e - s).count() / iters;
        if (ms < best) best = ms;
    }
    return best;
}

/// TLS 风格每条记录 nonce：前 4 字节固定，后 8 字节 = base_iv ^ seq（大端）
static void record_iv(const uint8_t base_iv[12], uint64_t seq, uint8_t out[12]) {
    std::memcpy(out, base_iv, 12);
    for (int i = 0; i < 8; ++i)
        out[4 + i] ^= (uint8_t)(seq >> (56 - 8 * i));
}

/// 按 record_size 分片执行 fn(record_index, offset, len)；返回总字节数
template <typename F>
static void run_records(size_t total, size_t record_size, F&& fn) {
    if (record_size == 0 || record_size >= total) {
        fn(0, 0, total);
        return;
    }
    size_t off = 0;
    uint64_t seq = 0;
    while (off < total) {
        size_t len = std::min(record_size, total - off);
        fn(seq, off, len);
        off += len;
        ++seq;
    }
}

static void print_suite_header(const char* title, const char** suites);

// ═══════════════════════════════════════════════════════════════════════
//  AEAD 基准框架
// ═══════════════════════════════════════════════════════════════════════

struct AeadResult {
    double jp_enc_gbps = 0, jp_dec_gbps = 0;
    double os_enc_gbps = 0, os_dec_gbps = 0;
};

static void print_aead_table(const std::string& label, const AeadResult& r, const Opts& o) {
    std::printf("  %-12s %10s %12s", "", "jpssl", "OpenSSL");
    if (o.with_ossl) std::printf(" %9s", "ratio");
    std::printf("\n");
    std::printf("  %-12s %8.3f GB/s %10.3f GB/s", "Encrypt", r.jp_enc_gbps, r.os_enc_gbps);
    if (o.with_ossl && r.os_enc_gbps > 0)
        std::printf(" %8.2fx", r.jp_enc_gbps / r.os_enc_gbps);
    std::printf("\n");
    std::printf("  %-12s %8.3f GB/s %10.3f GB/s", "Decrypt", r.jp_dec_gbps, r.os_dec_gbps);
    if (o.with_ossl && r.os_dec_gbps > 0)
        std::printf(" %8.2fx", r.jp_dec_gbps / r.os_dec_gbps);
    std::printf("\n");
}

/// jpssl AEAD 加密：整块或按记录分片，每次使用 record_iv 派生 nonce
template <typename EncFn>
static double bench_jp_encrypt(const Opts& o, size_t total,
                               const uint8_t base_iv[12],
                               const uint8_t* plain, std::vector<uint8_t>& ct,
                               uint8_t tag[16], EncFn&& enc) {
    const size_t rec = (o.record_size && o.record_size < total) ? o.record_size : 0;
    return bench_min_ms(o, [&] {
        run_records(total, rec, [&](uint64_t seq, size_t off, size_t len) {
            uint8_t iv[12];
            record_iv(base_iv, seq, iv);
            enc(iv, jpssl::span<const uint8_t>(plain + off, len), ct, tag);
        });
    });
}

/// jpssl AEAD 解密（验证 tag）
template <typename DecFn>
static double bench_jp_decrypt(const Opts& o, size_t total,
                               const uint8_t base_iv[12],
                               const std::vector<uint8_t>& ct, const uint8_t tag[16],
                               std::vector<uint8_t>& pt, DecFn&& dec) {
    const size_t rec = (o.record_size && o.record_size < total) ? o.record_size : 0;
    return bench_min_ms(o, [&] {
        run_records(total, rec, [&](uint64_t seq, size_t off, size_t len) {
            uint8_t iv[12];
            record_iv(base_iv, seq, iv);
            dec(iv, jpssl::span<const uint8_t>(ct.data() + off, len), tag, pt);
        });
    });
}

// ═══════════════════════════════════════════════════════════════════════
//  AES-GCM（128/256 共用框架）
// ═══════════════════════════════════════════════════════════════════════

static void benchmark_gcm(const char* title, const char** suites, int bits,
                          const Opts& o, AeadResult& out) {
    print_suite_header(title, suites);

    std::vector<uint8_t> key(bits / 8), iv(12), plain(o.data_size);
    RAND_bytes(key.data(), key.size());
    RAND_bytes(iv.data(), 12);
    RAND_bytes(plain.data(), plain.size());

    aes_context ctx;
    if (bits == 128) ctx.init(jpssl::span<const uint8_t, 16>(key.data(), 16));
    else if (bits == 192) ctx.init(jpssl::span<const uint8_t, 24>(key.data(), 24));
    else ctx.init(jpssl::span<const uint8_t, 32>(key.data(), 32));

    std::vector<uint8_t> ct, pt;
    uint8_t tag[16];

    // ── 正确性（与 OpenSSL 交叉验证）──
    aes_gcm_encrypt_auto(ctx, iv.data(), 12, plain, jpssl::span<const uint8_t>(), ct, tag, 16);
    std::vector<uint8_t> ct2;
    bool ok = aes_gcm_decrypt_auto(ctx, iv.data(), 12, ct, jpssl::span<const uint8_t>(),
                                   tag, 16, pt);
    TEST(std::string("jpssl AES-") + std::to_string(bits) + "-GCM round-trip", ok && pt == plain);

    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* c = (bits == 128) ? EVP_aes_128_gcm()
                         : (bits == 192) ? EVP_aes_192_gcm() : EVP_aes_256_gcm();
    EVP_EncryptInit_ex(ectx, c, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ectx, nullptr, nullptr, key.data(), iv.data());
    int outl = 0, outl2 = 0;
    std::vector<uint8_t> ossl_ct(plain.size() + 16);
    uint8_t ossl_tag[16];
    EVP_EncryptUpdate(ectx, ossl_ct.data(), &outl, plain.data(), (int)plain.size());
    EVP_EncryptFinal_ex(ectx, ossl_ct.data() + outl, &outl2);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, ossl_tag);
    EVP_CIPHER_CTX_free(ectx);
    TEST(std::string("AES-") + std::to_string(bits) + "-GCM tag vs OpenSSL",
         ct.size() == (size_t)outl + outl2 && memcmp(tag, ossl_tag, 16) == 0 &&
         memcmp(ct.data(), ossl_ct.data(), ct.size()) == 0);

    // ── 基准 ──
    ct.resize(plain.size());
    pt.resize(plain.size());
    uint8_t jp_tag[16];
    const size_t total = plain.size();
    const size_t rec = (o.record_size && o.record_size < total) ? o.record_size : 0;

    double jp_enc_ms = bench_jp_encrypt(o, total, iv.data(), plain.data(), ct, jp_tag,
        [&](const uint8_t* ivr, jpssl::span<const uint8_t> p, std::vector<uint8_t>& c,
            uint8_t* tg) {
            aes_gcm_encrypt_auto(ctx, ivr, 12, p, jpssl::span<const uint8_t>(), c, tg, 16);
        });
    double jp_dec_ms = bench_jp_decrypt(o, total, iv.data(), ct, jp_tag, pt,
        [&](const uint8_t* ivr, jpssl::span<const uint8_t> c, const uint8_t* tg,
            std::vector<uint8_t>& p) {
            aes_gcm_decrypt_auto(ctx, ivr, 12, c, jpssl::span<const uint8_t>(), tg, 16, p);
        });

    double os_enc_ms = 0, os_dec_ms = 0;
    if (o.with_ossl) {
        EVP_CIPHER_CTX* e2 = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e2, c, nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(e2, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(e2, nullptr, nullptr, key.data(), iv.data());
        std::vector<uint8_t> oc(plain.size() + 16);
        uint8_t otag[16];
        os_enc_ms = bench_min_ms(o, [&] {
            run_records(total, rec, [&](uint64_t seq, size_t off, size_t len) {
                uint8_t ivr[12];
                record_iv(iv.data(), seq, ivr);
                EVP_EncryptInit_ex(e2, nullptr, nullptr, nullptr, ivr);
                int ol = 0, ol2 = 0;
                EVP_EncryptUpdate(e2, oc.data(), &ol, plain.data() + off, (int)len);
                EVP_EncryptFinal_ex(e2, oc.data() + ol, &ol2);
                EVP_CIPHER_CTX_ctrl(e2, EVP_CTRL_GCM_GET_TAG, 16, otag);
            });
        });
        EVP_CIPHER_CTX_free(e2);

        EVP_CIPHER_CTX* d2 = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(d2, c, nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(d2, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_DecryptInit_ex(d2, nullptr, nullptr, key.data(), iv.data());
        std::vector<uint8_t> op(plain.size());
        os_dec_ms = bench_min_ms(o, [&] {
            run_records(total, rec, [&](uint64_t seq, size_t off, size_t len) {
                uint8_t ivr[12];
                record_iv(iv.data(), seq, ivr);
                EVP_DecryptInit_ex(d2, nullptr, nullptr, nullptr, ivr);
                int ol = 0, ol2 = 0;
                EVP_DecryptUpdate(d2, op.data() + off, &ol, ct.data() + off, (int)len);
                EVP_CIPHER_CTX_ctrl(d2, EVP_CTRL_GCM_SET_TAG, 16, jp_tag);
                EVP_DecryptFinal_ex(d2, op.data() + off + ol, &ol2);
            });
        });
        EVP_CIPHER_CTX_free(d2);
    }

    out.jp_enc_gbps = to_gbps(total, jp_enc_ms);
    out.jp_dec_gbps = to_gbps(total, jp_dec_ms);
    out.os_enc_gbps = o.with_ossl ? to_gbps(total, os_enc_ms) : 0;
    out.os_dec_gbps = o.with_ossl ? to_gbps(total, os_dec_ms) : 0;
    print_aead_table("AES-GCM", out, o);
}

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20-Poly1305
// ═══════════════════════════════════════════════════════════════════════

static void benchmark_chacha(const char* title, const char** suites,
                             const Opts& o, AeadResult& out) {
    print_suite_header(title, suites);

    uint8_t key[32], nonce[12];
    RAND_bytes(key, 32);
    RAND_bytes(nonce, 12);
    std::vector<uint8_t> plain(o.data_size);
    RAND_bytes(plain.data(), plain.size());
    std::vector<uint8_t> ct, pt;
    uint8_t tag[16];

    chacha20_poly1305_encrypt(key, nonce, plain, jpssl::span<const uint8_t>(), ct, tag);
    bool ok = chacha20_poly1305_decrypt(key, nonce, ct, jpssl::span<const uint8_t>(), tag, pt);
    TEST("jpssl ChaCha20-Poly1305 round-trip", ok && pt == plain);

    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ectx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ectx, nullptr, nullptr, key, nonce);
    int outl = 0, outl2 = 0;
    std::vector<uint8_t> ossl_ct(plain.size() + 16);
    uint8_t ossl_tag[16];
    EVP_EncryptUpdate(ectx, ossl_ct.data(), &outl, plain.data(), (int)plain.size());
    EVP_EncryptFinal_ex(ectx, ossl_ct.data() + outl, &outl2);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_GET_TAG, 16, ossl_tag);
    EVP_CIPHER_CTX_free(ectx);
    TEST("ChaCha20-Poly1305 tag vs OpenSSL",
         ct.size() == (size_t)outl + outl2 && memcmp(tag, ossl_tag, 16) == 0);

    ct.resize(plain.size());
    pt.resize(plain.size());
    uint8_t jp_tag[16];
    const size_t total = plain.size();
    const size_t rec = (o.record_size && o.record_size < total) ? o.record_size : 0;

    double jp_enc_ms = bench_jp_encrypt(o, total, nonce, plain.data(), ct, jp_tag,
        [&](const uint8_t* ivr, jpssl::span<const uint8_t> p, std::vector<uint8_t>& c,
            uint8_t* tg) {
            chacha20_poly1305_encrypt(key, ivr, p, jpssl::span<const uint8_t>(), c, tg);
        });
    double jp_dec_ms = bench_jp_decrypt(o, total, nonce, ct, jp_tag, pt,
        [&](const uint8_t* ivr, jpssl::span<const uint8_t> c, const uint8_t* tg,
            std::vector<uint8_t>& p) {
            chacha20_poly1305_decrypt(key, ivr, c, jpssl::span<const uint8_t>(), tg, p);
        });

    double os_enc_ms = 0, os_dec_ms = 0;
    if (o.with_ossl) {
        EVP_CIPHER_CTX* e2 = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e2, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(e2, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(e2, nullptr, nullptr, key, nonce);
        std::vector<uint8_t> oc(plain.size() + 16);
        uint8_t otag[16];
        os_enc_ms = bench_min_ms(o, [&] {
            run_records(total, rec, [&](uint64_t seq, size_t off, size_t len) {
                uint8_t ivr[12];
                record_iv(nonce, seq, ivr);
                EVP_EncryptInit_ex(e2, nullptr, nullptr, nullptr, ivr);
                int ol = 0, ol2 = 0;
                EVP_EncryptUpdate(e2, oc.data(), &ol, plain.data() + off, (int)len);
                EVP_EncryptFinal_ex(e2, oc.data() + ol, &ol2);
                EVP_CIPHER_CTX_ctrl(e2, EVP_CTRL_AEAD_GET_TAG, 16, otag);
            });
        });
        EVP_CIPHER_CTX_free(e2);

        EVP_CIPHER_CTX* d2 = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(d2, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(d2, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_DecryptInit_ex(d2, nullptr, nullptr, key, nonce);
        std::vector<uint8_t> op(plain.size());
        os_dec_ms = bench_min_ms(o, [&] {
            run_records(total, rec, [&](uint64_t seq, size_t off, size_t len) {
                uint8_t ivr[12];
                record_iv(nonce, seq, ivr);
                EVP_DecryptInit_ex(d2, nullptr, nullptr, nullptr, ivr);
                int ol = 0, ol2 = 0;
                EVP_DecryptUpdate(d2, op.data() + off, &ol, ct.data() + off, (int)len);
                EVP_CIPHER_CTX_ctrl(d2, EVP_CTRL_AEAD_SET_TAG, 16, jp_tag);
                EVP_DecryptFinal_ex(d2, op.data() + off + ol, &ol2);
            });
        });
        EVP_CIPHER_CTX_free(d2);
    }

    out.jp_enc_gbps = to_gbps(total, jp_enc_ms);
    out.jp_dec_gbps = to_gbps(total, jp_dec_ms);
    out.os_enc_gbps = o.with_ossl ? to_gbps(total, os_enc_ms) : 0;
    out.os_dec_gbps = o.with_ossl ? to_gbps(total, os_dec_ms) : 0;
    print_aead_table("ChaCha20", out, o);
}

// ═══════════════════════════════════════════════════════════════════════
//  AES-CCM（tag 长度可配）
// ═══════════════════════════════════════════════════════════════════════

static void benchmark_ccm(const char* title, const char** suites, int tag_len,
                          const Opts& o, AeadResult& out) {
    print_suite_header(title, suites);

    const size_t total = std::min(o.data_size, CCM_MAX);
    uint8_t key[16], nonce[12];
    RAND_bytes(key, 16);
    RAND_bytes(nonce, 12);
    std::vector<uint8_t> plain(total);
    RAND_bytes(plain.data(), plain.size());
    std::vector<uint8_t> ct, pt;
    uint8_t tag[16];

    aes_context ctx;
    ctx.init(jpssl::span<const uint8_t, 16>(key, 16));

    aes_ccm_encrypt(ctx, nonce, 12, plain, jpssl::span<const uint8_t>(), ct, tag, tag_len);
    bool ok = aes_ccm_decrypt(ctx, nonce, 12, ct, jpssl::span<const uint8_t>(), tag, tag_len, pt);
    TEST(std::string("jpssl AES-128-CCM-") + std::to_string(tag_len) + " round-trip",
         ok && pt == plain);

    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ectx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_SET_TAG, tag_len, nullptr);
    EVP_EncryptInit_ex(ectx, nullptr, nullptr, key, nonce);
    int outl = 0;
    EVP_EncryptUpdate(ectx, nullptr, &outl, nullptr, (int)total);
    std::vector<uint8_t> ossl_ct(total + 16);
    uint8_t ossl_tag[16];
    int outl2 = 0;
    EVP_EncryptUpdate(ectx, ossl_ct.data(), &outl, plain.data(), (int)total);
    EVP_EncryptFinal_ex(ectx, ossl_ct.data() + outl, &outl2);
    EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_GET_TAG, tag_len, ossl_tag);
    EVP_CIPHER_CTX_free(ectx);
    TEST(std::string("AES-128-CCM-") + std::to_string(tag_len) + " tag vs OpenSSL",
         ct.size() == (size_t)outl + outl2 && memcmp(tag, ossl_tag, tag_len) == 0);

    ct.resize(total);
    pt.resize(total);
    uint8_t jp_tag[16];
    const size_t rec = (o.record_size && o.record_size < total) ? o.record_size : 0;

    double jp_enc_ms = bench_jp_encrypt(o, total, nonce, plain.data(), ct, jp_tag,
        [&](const uint8_t* ivr, jpssl::span<const uint8_t> p, std::vector<uint8_t>& c,
            uint8_t* tg) {
            aes_ccm_encrypt(ctx, ivr, 12, p, jpssl::span<const uint8_t>(), c, tg, tag_len);
        });
    double jp_dec_ms = bench_jp_decrypt(o, total, nonce, ct, jp_tag, pt,
        [&](const uint8_t* ivr, jpssl::span<const uint8_t> c, const uint8_t* tg,
            std::vector<uint8_t>& p) {
            aes_ccm_decrypt(ctx, ivr, 12, c, jpssl::span<const uint8_t>(), tg, tag_len, p);
        });

    double os_enc_ms = 0, os_dec_ms = 0;
    if (o.with_ossl) {
        EVP_CIPHER_CTX* e2 = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e2, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(e2, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_CIPHER_CTX_ctrl(e2, EVP_CTRL_AEAD_SET_TAG, tag_len, nullptr);
        EVP_EncryptInit_ex(e2, nullptr, nullptr, key, nonce);
        std::vector<uint8_t> oc(total + 16);
        uint8_t otag[16];
        os_enc_ms = bench_min_ms(o, [&] {
            run_records(total, rec, [&](uint64_t seq, size_t off, size_t len) {
                uint8_t ivr[12];
                record_iv(nonce, seq, ivr);
                EVP_EncryptInit_ex(e2, nullptr, nullptr, nullptr, ivr);
                int ol = 0;
                EVP_EncryptUpdate(e2, nullptr, &ol, nullptr, (int)len);
                int ol2 = 0;
                EVP_EncryptUpdate(e2, oc.data(), &ol, plain.data() + off, (int)len);
                EVP_EncryptFinal_ex(e2, oc.data() + ol, &ol2);
                EVP_CIPHER_CTX_ctrl(e2, EVP_CTRL_AEAD_GET_TAG, tag_len, otag);
            });
        });
        EVP_CIPHER_CTX_free(e2);

        EVP_CIPHER_CTX* d2 = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(d2, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(d2, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_CIPHER_CTX_ctrl(d2, EVP_CTRL_AEAD_SET_TAG, tag_len, nullptr);
        EVP_DecryptInit_ex(d2, nullptr, nullptr, key, nonce);
        std::vector<uint8_t> op(total);
        os_dec_ms = bench_min_ms(o, [&] {
            run_records(total, rec, [&](uint64_t seq, size_t off, size_t len) {
                uint8_t ivr[12];
                record_iv(nonce, seq, ivr);
                EVP_DecryptInit_ex(d2, nullptr, nullptr, nullptr, ivr);
                int ol = 0;
                EVP_DecryptUpdate(d2, nullptr, &ol, nullptr, (int)len);
                int ol2 = 0;
                EVP_DecryptUpdate(d2, op.data() + off, &ol, ct.data() + off, (int)len);
                EVP_CIPHER_CTX_ctrl(d2, EVP_CTRL_AEAD_SET_TAG, tag_len, jp_tag);
                EVP_DecryptFinal_ex(d2, op.data() + off + ol, &ol2);
            });
        });
        EVP_CIPHER_CTX_free(d2);
    }

    out.jp_enc_gbps = to_gbps(total, jp_enc_ms);
    out.jp_dec_gbps = to_gbps(total, jp_dec_ms);
    out.os_enc_gbps = o.with_ossl ? to_gbps(total, os_enc_ms) : 0;
    out.os_dec_gbps = o.with_ossl ? to_gbps(total, os_dec_ms) : 0;
    print_aead_table(std::string("CCM-") + std::to_string(tag_len), out, o);
}

// ═══════════════════════════════════════════════════════════════════════
//  SHA-256 / SHA-384 吞吐
// ═══════════════════════════════════════════════════════════════════════

static void benchmark_hash(const char* title, int bits, const Opts& o, double& jp_out,
                           double& os_out) {
    std::printf("\n  ── %s ──\n", title);
    std::vector<uint8_t> data(o.data_size);
    RAND_bytes(data.data(), data.size());

    if (bits == 256) {
        uint8_t jp_hash[32], ossl_hash[32];
        sha256_ctx ctx;
        double jp_ms = bench_min_ms(o, [&] {
            sha256_init(&ctx);
            sha256_update(&ctx, data.data(), data.size());
            sha256_final(&ctx, jp_hash);
        });
        double os_ms = 0;
        if (o.with_ossl) {
            os_ms = bench_min_ms(o, [&] {
                SHA256(data.data(), data.size(), ossl_hash);
            });
            TEST("SHA-256 jpssl matches OpenSSL", memcmp(jp_hash, ossl_hash, 32) == 0);
        }
        jp_out = to_gbps(data.size(), jp_ms);
        os_out = o.with_ossl ? to_gbps(data.size(), os_ms) : 0;
    } else {
        uint8_t jp_hash[48], ossl_hash[48];
        sha512_ctx ctx;
        double jp_ms = bench_min_ms(o, [&] {
            sha384_init(&ctx);
            sha512_update(&ctx, data.data(), data.size());
            sha512_final(&ctx, jp_hash);
        });
        double os_ms = 0;
        if (o.with_ossl) {
            os_ms = bench_min_ms(o, [&] {
                SHA384(data.data(), data.size(), ossl_hash);
            });
            TEST("SHA-384 jpssl matches OpenSSL", memcmp(jp_hash, ossl_hash, 48) == 0);
        }
        jp_out = to_gbps(data.size(), jp_ms);
        os_out = o.with_ossl ? to_gbps(data.size(), os_ms) : 0;
    }
    std::printf("  %-12s %8.3f GB/s %10.3f GB/s", "jpssl", jp_out, os_out);
    if (o.with_ossl && os_out > 0) std::printf(" %8.2fx", jp_out / os_out);
    std::printf("\n");
}

// ═══════════════════════════════════════════════════════════════════════
//  套件名
// ═══════════════════════════════════════════════════════════════════════

static const char* suites_tls13_aes128_gcm[] = {"TLS_AES_128_GCM_SHA256 (0x1301)", nullptr};
static const char* suites_tls13_aes256_gcm[] = {"TLS_AES_256_GCM_SHA384 (0x1302)", nullptr};
static const char* suites_tls13_chacha[] = {"TLS_CHACHA20_POLY1305_SHA256 (0x1303)", nullptr};
static const char* suites_tls13_ccm[] = {"TLS_AES_128_CCM_SHA256 (0x1304)", nullptr};
static const char* suites_tls13_ccm8[] = {"TLS_AES_128_CCM_8_SHA256 (0x1305)", nullptr};
static const char* suites_tls12_aes128_gcm[] = {
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)",
    nullptr
};
static const char* suites_tls12_aes256_gcm[] = {
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C)",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)",
    nullptr
};
static const char* suites_tls12_chacha[] = {
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9)",
    nullptr
};

static void print_suite_header(const char* title, const char** suites) {
    std::printf("\n  ── %s ──\n", title);
    for (int i = 0; suites[i]; ++i)
        std::printf("    %s\n", suites[i]);
}

// ═══════════════════════════════════════════════════════════════════════
//  入口
// ═══════════════════════════════════════════════════════════════════════

int main(int argc, char** argv) {
    Opts o = parse_args(argc, argv);
    std::printf("jpssl Cipher Suite Benchmark & OpenSSL Comparison (%s)\n",
                OPENSSL_VERSION_TEXT);
    std::printf("Data size: %zu MiB per direction, record size: %s\n",
                o.data_size / (1024 * 1024),
                o.record_size ? (std::to_string(o.record_size) + " B").c_str() : "whole buffer");
    std::printf("Rounds: %d, target: %.0f ms/round%s\n",
                o.rounds, o.target_ms, o.with_ossl ? "" : " (no OpenSSL)");

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    AeadResult r128, r256, rchacha, rccm, rccm8;
    double sha256_jp = 0, sha256_os = 0, sha384_jp = 0, sha384_os = 0;

    benchmark_gcm("AES-128-GCM Record Layer Encryption",
                  suites_tls13_aes128_gcm, 128, o, r128);
    benchmark_gcm("AES-256-GCM Record Layer Encryption",
                  suites_tls13_aes256_gcm, 256, o, r256);
    benchmark_chacha("ChaCha20-Poly1305 Record Layer Encryption",
                     suites_tls13_chacha, o, rchacha);
    benchmark_ccm("AES-128-CCM Record Layer Encryption (tag=16)",
                  suites_tls13_ccm, 16, o, rccm);
    benchmark_ccm("AES-128-CCM-8 Record Layer Encryption (tag=8)",
                  suites_tls13_ccm8, 8, o, rccm8);
    benchmark_hash("SHA-256 Hash Throughput", 256, o, sha256_jp, sha256_os);
    benchmark_hash("SHA-384 Hash Throughput", 384, o, sha384_jp, sha384_os);

    // ── 汇总表（GB/s，ratio = jpssl / OpenSSL，>1 表示 jpssl 更快）──
    std::printf("\n\n=== Summary (GB/s) ===\n");
    std::printf("%-28s %12s %12s %10s %12s %12s %10s\n",
                "primitive", "jpssl enc", "OpenSSL enc", "enc x", "jpssl dec", "OpenSSL dec", "dec x");
    auto row = [&](const char* name, const AeadResult& r) {
        std::printf("%-28s %11.3f  %11.3f  %9.2f  %11.3f  %11.3f  %9.2f\n",
                    name, r.jp_enc_gbps, r.os_enc_gbps,
                    o.with_ossl && r.os_enc_gbps > 0 ? r.jp_enc_gbps / r.os_enc_gbps : 0,
                    r.jp_dec_gbps, r.os_dec_gbps,
                    o.with_ossl && r.os_dec_gbps > 0 ? r.jp_dec_gbps / r.os_dec_gbps : 0);
    };
    row("AES-128-GCM", r128);
    row("AES-256-GCM", r256);
    row("ChaCha20-Poly1305", rchacha);
    row("AES-128-CCM", rccm);
    row("AES-128-CCM-8", rccm8);
    std::printf("%-28s %11.3f  %11.3f  %9.2f\n", "SHA-256",
                sha256_jp, sha256_os, o.with_ossl && sha256_os > 0 ? sha256_jp / sha256_os : 0);
    std::printf("%-28s %11.3f  %11.3f  %9.2f\n", "SHA-384",
                sha384_jp, sha384_os, o.with_ossl && sha384_os > 0 ? sha384_jp / sha384_os : 0);

    std::printf("\n=== Cipher Suite → AEAD Primitive Mapping ===\n");
    std::printf("  TLS 1.3 Suites:\n");
    std::printf("    TLS_AES_128_GCM_SHA256        → AES-128-GCM\n");
    std::printf("    TLS_AES_256_GCM_SHA384        → AES-256-GCM\n");
    std::printf("    TLS_CHACHA20_POLY1305_SHA256  → ChaCha20-Poly1305\n");
    std::printf("    TLS_AES_128_CCM_SHA256        → AES-128-CCM\n");
    std::printf("    TLS_AES_128_CCM_8_SHA256      → AES-128-CCM-8\n");
    std::printf("  TLS 1.2 Suites:\n");
    std::printf("    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256        → AES-128-GCM\n");
    std::printf("    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384        → AES-256-GCM\n");
    std::printf("    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256           → AES-128-GCM\n");
    std::printf("    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384           → AES-256-GCM\n");
    std::printf("    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256     → ChaCha20-Poly1305\n");
    std::printf("    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256   → ChaCha20-Poly1305\n");
    std::printf("\n");

    return test_summary();
}
