// bench_aes_cbc_unalign.cpp — AES-CBC 非对齐测试对比组 (AES-128/256, 自动 PKCS7 填充)
//
// 在 bench_aes_cbc.cpp 基础上增加【非对齐测试对比组】(与 OpenSSL 对比):
//   1. 非对齐长度: 17 / 1001 / 32767 / 100003 (均非 16 倍数, 走 PKCS7 填充路径)
//   2. 非对齐指针 offset: 数据起始地址偏移 1/3/7/13 字节 (alloc size = n+offset+16);
//      性能至少 offset=0 与 3; 自检 1/3/7/13 全覆盖
//   3. 自检 (始终执行): 非对齐长度+偏移下 jpssl sw/aesni 与 OpenSSL 交叉一致
//      (ct 前缀比较法, IV 用同一个数组)、offset 指针结果 == offset=0 结果、
//      jpssl/OpenSSL 双向解密一致; 任一 FAIL 以非零码退出。
//   4. 性能基准: 长度 {17,1001,32767,100003} x offset {0,3} (加密+解密);
//      BENCH_SMOKE=1 时只测 {17,1001} x offset{0,3}、~80ms、1 轮;
//      未设置时全量、~150ms、3 轮取最小。
//
// 说明 (对比方法):
//   - jpssl 的 CBC 走 PKCS7 自动填充: 密文 = ceil(n/16)*16 字节。
//     OpenSSL 对照分两种:
//       * padding=0 (nopad): 只处理 floor(n/16)*16 字节 (n 非 16 倍数时剩余部分
//         在 EncryptFinal 报错、不产出), 与 jpssl 密文前 floor(n/16)*16 字节逐字节一致
//         —— 即"ct 前缀比较法"。
//       * padding=1 (PKCS7): 密文与 jpssl 密文全等 (长度 ceil(n/16)*16)。
//   - 非对齐指针通过"数据缓冲 + offset 起始"实现, IV 恒用同一个数组 IV16.data()。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_aes_cbc_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_aes_cbc_unalign
//
// 输出 CSV: benchmarks/results/bench_aes_cbc_unalign.csv
//   列头: algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps
//   algo 形如 aes-128-cbc-enc-unalign; impl 为 jpssl-sw / jpssl-aesni / openssl。

#include "aes.hpp"
#include "cpu_features.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

using jpssl::aes_context;

using Clock = std::chrono::steady_clock;

// 阻止编译器把输出缓冲区相关调用折叠/消除
static volatile int g_sink = 0;

// ── 固定测试数据 ────────────────────────────────────────────────
static const std::array<uint8_t, 16> K16 = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const std::array<uint8_t, 32> K32 = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
static const std::array<uint8_t, 16> IV16 = {
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

// 非对齐长度档位 (均非 16 倍数, PKCS7 填充路径)
static const std::vector<size_t> g_sizes = {17, 1001, 32767, 100003};
// 非对齐指针 offset: 自检全覆盖; 性能取 {0,3}
static const std::vector<size_t> g_offsets_check = {0, 1, 3, 7, 13};
static const std::vector<size_t> g_offsets_bench = {0, 3};

// ── 确定性伪随机填充 (只写 buf[off, off+n)) ─────────────────────
static void fill_at(std::vector<uint8_t>& buf, size_t off, size_t n, uint32_t seed) {
    uint32_t x = seed * 2654435761u + 12345u;
    for (size_t i = 0; i < n; ++i) {
        x = x * 1664525u + 1013904223u;
        buf[off + i] = static_cast<uint8_t>(x >> 24);
    }
}

// ── 自适应微基准: 每轮约 target_ms, 取 rounds 轮中最小值 ────────
template <typename F>
static double auto_bench(F&& f, double target_ms, int rounds) {
    f();  // 预热
    const int est_n = 8;
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
    double best = 1e300;
    for (int r = 0; r < rounds; ++r) {
        auto s = Clock::now();
        for (long long i = 0; i < iters; ++i) f();
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / iters;
        if (ns < best) best = ns;
    }
    return best;
}

// ── 结果收集 ────────────────────────────────────────────────────
struct Row {
    std::string algo;
    std::string impl;
    size_t size;
    size_t offset;
    double ns;
    double mbps;
    bool skipped;
};
static std::vector<Row> g_rows;
static bool g_all_pass = true;

static void record(const char* algo, const char* impl, size_t size, size_t offset, double ns) {
    double mbps = size / ns * 1000.0;  // bytes/ns * 1000 = MB/s
    g_rows.push_back({algo, impl, size, offset, ns, mbps, false});
    printf("%-26s %-12s %9zu %4zu %12.1f %12.1f\n", algo, impl, size, offset, ns, mbps);
}

static void record_skip(const char* algo, const char* impl, size_t size, size_t offset,
                        const char* why) {
    g_rows.push_back({algo, impl, size, offset, 0.0, 0.0, true});
    printf("%-26s %-12s %9zu %4zu SKIP (%s)\n", algo, impl, size, offset, why);
}

// ── OpenSSL 基础封装 (pad: 0=nopad, 1=PKCS7; EVP_EncryptInit_ex 可能重置 padding, 每 op 强制) ──
static void ossl_cipher_enc(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                            const uint8_t* in, size_t n, int pad, uint8_t* out,
                            EVP_CIPHER_CTX* ctx) {
    EVP_EncryptInit_ex(ctx, ciph, nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, pad);
    int outl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, in, static_cast<int>(n));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, out + outl, &fin);
}

static void ossl_cipher_dec(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                            const uint8_t* in, size_t n, int pad, uint8_t* out,
                            EVP_CIPHER_CTX* ctx) {
    EVP_DecryptInit_ex(ctx, ciph, nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, pad);
    int outl = 0;
    EVP_DecryptUpdate(ctx, out, &outl, in, static_cast<int>(n));
    int fin = 0;
    EVP_DecryptFinal_ex(ctx, out + outl, &fin);
}

// ── 自检辅助 ────────────────────────────────────────────────────
static int g_checks = 0;

static bool check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) g_all_pass = false;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    return ok;
}

// ── 非对齐 CBC 交叉验证 ─────────────────────────────────────────
// pt0 : 对齐明文缓冲 (n+16, 数据在 data()+0)
// ptO : 非对齐明文缓冲 (n+offset+16, 数据在 data()+offset)
// enc : enc(data_ptr, n, ct)   —— jpssl 实现 (PKCS7 自动填充)
// dec : dec(ct_ptr, ct_len, pt) -> bool —— jpssl 实现 (PKCS7 去填充)
// 验证点:
//   1. offset 指针加密结果 == offset=0 加密结果
//   2. jpssl 密文长度 == ceil(n/16)*16 (PKCS7)
//   3. ct 前缀比较: jpssl 密文前 floor(n/16)*16 字节 == OpenSSL(nopad) 密文
//   4. 全等比较:    jpssl 密文 == OpenSSL(PKCS7) 密文
//   5. jpssl 解密 roundtrip (密文经非对齐指针读入) == 明文
//   6. jpssl 解密 @offset == jpssl 解密 @offset=0 (解密侧 offset 一致性)
//   7. OpenSSL(PKCS7) 解密 roundtrip == 明文
//   8. OpenSSL(PKCS7) 解密 jpssl 密文 == 明文 (OpenSSL 解密 jpssl 方向)
//   9. jpssl 解密 OpenSSL(PKCS7) 密文 == 明文 (jpssl 解密 OpenSSL 方向)
template <typename E, typename D>
static void validate_unalign_padded(const char* name, size_t n, size_t offset,
                                    const std::vector<uint8_t>& pt0,
                                    const std::vector<uint8_t>& ptO,
                                    E&& enc, D&& dec,
                                    const EVP_CIPHER* ciph, const uint8_t* key,
                                    const uint8_t* iv) {
    const size_t full = ((n + 15) / 16) * 16;   // jpssl/OpenSSL PKCS7 密文长度
    const size_t prefix = (n / 16) * 16;        // OpenSSL nopad 可产出的字节数

    std::vector<uint8_t> ct0, ctO;
    enc(pt0.data(), n, ct0);
    enc(ptO.data() + offset, n, ctO);

    // 1. offset 指针结果 == offset=0 结果 (加密)
    bool ok = ctO == ct0;
    check(ok, (std::string(name) + " offset ct == ct@off0").c_str());
    // 2. 密文长度 == PKCS7 填充长度
    ok = ct0.size() == full && ctO.size() == full;
    check(ok, (std::string(name) + " ct len == ceil(n/16)*16").c_str());

    // 3. ct 前缀比较法: jpssl 密文前 prefix 字节 == OpenSSL(nopad) 密文
    EVP_CIPHER_CTX* e0 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(e0, 0);
    std::vector<uint8_t> onp(prefix);
    ossl_cipher_enc(ciph, key, iv, ptO.data() + offset, n, 0, onp.data(), e0);
    EVP_CIPHER_CTX_free(e0);
    ok = std::equal(onp.begin(), onp.end(), ctO.begin());
    check(ok, (std::string(name) + " ct prefix == OpenSSL(nopad)").c_str());

    // 4. 全等: jpssl 密文 == OpenSSL(PKCS7) 密文
    EVP_CIPHER_CTX* e1 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(e1, 1);
    std::vector<uint8_t> op7(full);
    ossl_cipher_enc(ciph, key, iv, ptO.data() + offset, n, 1, op7.data(), e1);
    EVP_CIPHER_CTX_free(e1);
    ok = std::equal(op7.begin(), op7.end(), ctO.begin());
    check(ok, (std::string(name) + " ct == OpenSSL(PKCS7)").c_str());

    // 密文置于非对齐指针处, 供解密侧验证
    std::vector<uint8_t> cbuf(full + offset + 16);
    std::memcpy(cbuf.data() + offset, ctO.data(), full);
    std::vector<uint8_t> cbuf0(full + 16);
    std::memcpy(cbuf0.data(), ct0.data(), full);

    const std::vector<uint8_t> expected(ptO.begin() + static_cast<ptrdiff_t>(offset),
                                        ptO.begin() + static_cast<ptrdiff_t>(offset + n));

    // 5. jpssl 解密 roundtrip (非对齐指针读入)
    std::vector<uint8_t> jpt;
    bool okd = dec(cbuf.data() + offset, full, jpt);
    ok = okd && jpt == expected;
    check(ok, (std::string(name) + " jpssl decrypt roundtrip (unalign ptr)").c_str());

    // 6. jpssl 解密 @offset == jpssl 解密 @offset=0
    std::vector<uint8_t> jpt0;
    okd = dec(cbuf0.data(), full, jpt0);
    ok = okd && jpt0 == jpt;
    check(ok, (std::string(name) + " jpssl decrypt @off==@off0").c_str());

    // 7. OpenSSL(PKCS7) 解密 roundtrip
    EVP_CIPHER_CTX* d1 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(d1, 1);
    std::vector<uint8_t> opt(n);
    ossl_cipher_dec(ciph, key, iv, op7.data(), full, 1, opt.data(), d1);
    EVP_CIPHER_CTX_free(d1);
    ok = opt == expected;
    check(ok, (std::string(name) + " OpenSSL decrypt roundtrip").c_str());

    // 8. OpenSSL(PKCS7) 解密 jpssl 密文 == 明文
    EVP_CIPHER_CTX* d2 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(d2, 1);
    std::vector<uint8_t> opt2(n);
    ossl_cipher_dec(ciph, key, iv, ctO.data(), full, 1, opt2.data(), d2);
    EVP_CIPHER_CTX_free(d2);
    ok = opt2 == expected;
    check(ok, (std::string(name) + " OpenSSL decrypts jpssl ct").c_str());

    // 9. jpssl 解密 OpenSSL(PKCS7) 密文 == 明文
    std::vector<uint8_t> jpt2;
    okd = dec(op7.data(), full, jpt2);
    ok = okd && jpt2 == expected;
    check(ok, (std::string(name) + " jpssl decrypts OpenSSL ct").c_str());
}

// ── CBC 非对齐基准: jpssl sw/aesni (PKCS7 填充) vs OpenSSL (padding=0) ──
template <typename E, typename D>
static void bench_unalign_block(const char* algo, size_t size, size_t offset,
                                const aes_context& ctx,
                                const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                                E&& jenc, D&& jdec, const char* impl,
                                double target_ms, int rounds) {
    const size_t full = ((size + 15) / 16) * 16;
    const size_t prefix = (size / 16) * 16;

    // 明文: 非对齐指针处 (alloc size+offset+16)
    std::vector<uint8_t> pb(size + offset + 16, 0xa5);
    fill_at(pb, offset, size, 0x00B100C);

    std::vector<uint8_t> jct, jpt;
    jenc(pb.data() + offset, size, jct);

    char algo_e[64], algo_d[64];
    std::snprintf(algo_e, sizeof(algo_e), "%s-enc", algo);
    std::snprintf(algo_d, sizeof(algo_d), "%s-dec", algo);

    double nse = auto_bench([&] {
        jenc(pb.data() + offset, size, jct);
        g_sink ^= jct[0];
    }, target_ms, rounds);
    record(algo_e, impl, size, offset, nse);

    // 解密输入: 密文置于非对齐指针处
    std::vector<uint8_t> cb(full + offset + 16, 0x3c);
    std::memcpy(cb.data() + offset, jct.data(), full);
    double nsd = auto_bench([&] {
        jdec(cb.data() + offset, full, jpt);
        g_sink ^= jpt[0];
    }, target_ms, rounds);
    record(algo_d, impl, size, offset, nsd);

    // OpenSSL 对照 (padding=0: 只处理 floor 块)
    EVP_CIPHER_CTX* c_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(c_enc, 0);
    EVP_CIPHER_CTX* c_dec = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(c_dec, 0);
    std::vector<uint8_t> oct(prefix), opt(prefix);
    nse = auto_bench([&] {
        ossl_cipher_enc(ciph, key, iv, pb.data() + offset, size, 0, oct.data(), c_enc);
        g_sink ^= oct[0];
    }, target_ms, rounds);
    record(algo_e, "openssl", size, offset, nse);
    nsd = auto_bench([&] {
        ossl_cipher_dec(ciph, key, iv, oct.data(), prefix, 0, opt.data(), c_dec);
        g_sink ^= opt[0];
    }, target_ms, rounds);
    record(algo_d, "openssl", size, offset, nsd);
    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// ── main ────────────────────────────────────────────────────────
int main() {
    auto feats = jpssl::cpu_features::detect();
    printf("=== bench_aes_cbc_unalign: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("CPU features: AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES+VPCLMULQDQ=%d SHA-NI=%d\n",
           (int)feats.aesni, (int)feats.avx2, (int)feats.pclmulqdq,
           (int)feats.avx512, (int)feats.vpclmulqdq_vaes, (int)feats.sha_ni);
    if (feats.avx512) printf("  WARNING: AVX512 available on this host\n");

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    const bool smoke = [] {
        const char* e = std::getenv("BENCH_SMOKE");
        return e != nullptr && std::string(e) == "1";
    }();
    std::vector<size_t> bench_sizes =
        smoke ? std::vector<size_t>{17, 1001} : g_sizes;
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;
    printf("Mode: %s (bench sizes %zu, offsets %zu, %.0fms/round, %d round%s)\n",
           smoke ? "SMOKE" : "FULL", bench_sizes.size(), g_offsets_bench.size(),
           target_ms, rounds, rounds > 1 ? "s" : "");

    aes_context ctx128, ctx256;
    ctx128.init(K16);
    ctx256.init(K32);

    // ── 自检 (先于基准, 始终覆盖全部非对齐长度 x 全部 offset, 全 PASS 才继续) ──
    printf("\n=== Correctness self-checks (unalign len x offset, jpssl <-> OpenSSL) ===\n");
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_cbc() : EVP_aes_128_cbc();
        const char* kn = keysz ? "aes-256-cbc" : "aes-128-cbc";

        for (size_t n : g_sizes) {
            for (size_t off : g_offsets_check) {
                // pt0: 对齐 (offset=0); ptO: 非对齐 (offset=off); 同一明文
                std::vector<uint8_t> pt0(n + 16, 0x5a), ptO(n + off + 16, 0xa5);
                fill_at(pt0, 0, n, 0xA11CE);
                fill_at(ptO, off, n, 0xA11CE);

                char nm[96];
                std::snprintf(nm, sizeof(nm), "%s/sw@%zu@off%zu", kn, n, off);
                validate_unalign_padded(
                    nm, n, off, pt0, ptO,
                    [&](const uint8_t* p, size_t nn, std::vector<uint8_t>& c) {
                        jpssl::aes_cbc_encrypt_sw(ctx, IV16.data(), std::span(p, nn), c);
                    },
                    [&](const uint8_t* c, size_t nn, std::vector<uint8_t>& p) -> bool {
                        return jpssl::aes_cbc_decrypt_sw(ctx, IV16.data(), std::span(c, nn), p);
                    },
                    ciph, key, IV16.data());

                std::snprintf(nm, sizeof(nm), "%s/aesni@%zu@off%zu", kn, n, off);
                validate_unalign_padded(
                    nm, n, off, pt0, ptO,
                    [&](const uint8_t* p, size_t nn, std::vector<uint8_t>& c) {
                        jpssl::aes_cbc_encrypt_aesni(ctx, IV16.data(), std::span(p, nn), c);
                    },
                    [&](const uint8_t* c, size_t nn, std::vector<uint8_t>& p) -> bool {
                        return jpssl::aes_cbc_decrypt_aesni(ctx, IV16.data(), std::span(c, nn), p);
                    },
                    ciph, key, IV16.data());
            }
        }
    }

    if (!g_all_pass) {
        printf("\nSelf-check FAILED — aborting benchmark (exit 1)\n");
        return 1;
    }
    printf("All self-checks passed (%d checks)\n", g_checks);

    // ── 基准 ──
    printf("\n=== Benchmarks (%s: %.0fms/round, %d round%s) ===\n",
           smoke ? "SMOKE" : "FULL", target_ms, rounds, rounds > 1 ? "s" : "");
    printf("%-26s %-12s %9s %4s %12s %12s\n", "algo", "impl", "size", "off", "ns/op", "MB/s");

    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_cbc() : EVP_aes_128_cbc();
        char algo[64];
        std::snprintf(algo, sizeof(algo), "%s%s", keysz ? "aes-256-cbc" : "aes-128-cbc",
                      "-unalign");
        for (size_t s : bench_sizes) {
            for (size_t off : g_offsets_bench) {
                bench_unalign_block(algo, s, off, ctx, ciph, key, IV16.data(),
                                    [&](const uint8_t* p, size_t nn, std::vector<uint8_t>& c) {
                                        jpssl::aes_cbc_encrypt_sw(ctx, IV16.data(),
                                                                  std::span(p, nn), c);
                                    },
                                    [&](const uint8_t* c, size_t nn, std::vector<uint8_t>& p) {
                                        return jpssl::aes_cbc_decrypt_sw(ctx, IV16.data(),
                                                                         std::span(c, nn), p);
                                    },
                                    "jpssl-sw", target_ms, rounds);
                bench_unalign_block(algo, s, off, ctx, ciph, key, IV16.data(),
                                    [&](const uint8_t* p, size_t nn, std::vector<uint8_t>& c) {
                                        jpssl::aes_cbc_encrypt_aesni(ctx, IV16.data(),
                                                                    std::span(p, nn), c);
                                    },
                                    [&](const uint8_t* c, size_t nn, std::vector<uint8_t>& p) {
                                        return jpssl::aes_cbc_decrypt_aesni(ctx, IV16.data(),
                                                                           std::span(c, nn), p);
                                    },
                                    "jpssl-aesni", target_ms, rounds);
            }
        }
    }

    // ── 写 CSV ──
    std::filesystem::path csv_dir = std::filesystem::path("benchmarks") / "results";
    std::error_code ec;
    std::filesystem::create_directories(csv_dir, ec);
    std::string csv_path = (csv_dir / "bench_aes_cbc_unalign.csv").string();
    {
        std::ofstream f(csv_path);
        f << "algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps\n";
        for (const auto& r : g_rows) {
            if (r.skipped) continue;
            f << r.algo << ',' << r.impl << ',' << r.size << ',' << r.offset << ','
              << r.ns << ',' << r.mbps << '\n';
        }
    }
    printf("\nCSV written to %s\n", std::filesystem::absolute(csv_path).string().c_str());
    printf("Done. All self-checks passed, exit 0.\n");
    return 0;
}
