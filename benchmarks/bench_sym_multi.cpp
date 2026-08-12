// bench_sym_multi.cpp — 对称加密多长度 × 多实现 × OpenSSL 对比微基准
//
// 覆盖:
//   AES-128/256-ECB (无填充) : jpssl sw / aesni / auto(无填充自动分派) vs OpenSSL
//   AES-128/256-CBC          : jpssl sw / aesni vs OpenSSL (padding=0)
//   AES-128/256-GCM          : jpssl sw / aesni / avx2 / vaes / avx512 / auto vs OpenSSL
//   ChaCha20-Poly1305        : jpssl auto(AEAD) / avx2(流) / avx512(流) vs OpenSSL
//
// 说明:
//   - 运行时 CPU 特性检测 (jpssl::cpu_features); 不支持的实现仅打印 SKIP, 绝不调用
//     (avx512 在本机无 AVX512 时会 SIGILL)。
//   - jpssl 的 ECB/CBC 走 PKCS7 自动填充接口 (库无公共"无填充标量 ECB/CBC"),
//     长度均为 16 的倍数, 填充会附加一整块; 与 OpenSSL (padding=0) 交叉验证时
//     比较密文前 n 字节并做解密往返。
//   - 微基准: 先估时再自适应迭代使每轮约 150ms, 取 3 轮最小值。
//   - 正确性: 每个 (算法,实现) 与 OpenSSL 交叉验证 (密文+tag 一致 / 解密往返 /
//     AEAD 篡改拒绝), 任一 FAIL 以非零码退出。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -DJP_AVX2 -DJP_AVX512 -DJP_VAES -Iinclude -Isrc \
//       benchmarks/bench_sym_multi.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a \
//       -lcrypto -o /tmp/bench_sym_multi

#include "aes.hpp"
#include "chacha20_poly1305.hpp"
#include "cpu_features.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
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
static const std::array<uint8_t, 12> IV12 = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b};

// 消息长度矩阵 (均为 16 的倍数)
static const std::vector<size_t> g_sizes = {16, 256, 4096, 65536, 1048576};

// 测试明文填充 (确定性伪随机)
static void fill_test(std::vector<uint8_t>& v, size_t n, uint32_t seed) {
    v.resize(n);
    uint32_t x = seed * 2654435761u + 12345u;
    for (size_t i = 0; i < n; ++i) {
        x = x * 1664525u + 1013904223u;
        v[i] = static_cast<uint8_t>(x >> 24);
    }
}

// ── 自适应微基准: 每轮约 target_ms, 取 rounds 轮中最小值 ────────
template <typename F>
static double auto_bench(F&& f, double target_ms = 150.0, int rounds = 3) {
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
    double ns;
    double mbps;
    bool skipped;
};
static std::vector<Row> g_rows;
static bool g_all_pass = true;

static void record(const char* algo, const char* impl, size_t size, double ns) {
    double mbps = size / ns * 1000.0;  // bytes/ns * 1000 = MB/s
    g_rows.push_back({algo, impl, size, ns, mbps, false});
    printf("%-26s %-12s %9zu %12.1f %12.1f\n", algo, impl, size, ns, mbps);
}

static void record_skip(const char* algo, const char* impl, size_t size, const char* why) {
    g_rows.push_back({algo, impl, size, 0.0, 0.0, true});
    printf("%-26s %-12s %9zu SKIP (%s)\n", algo, impl, size, why);
}

// ── OpenSSL 基础封装 ────────────────────────────────────────────

static void ossl_cipher_enc(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                            const uint8_t* in, size_t n, uint8_t* out,
                            EVP_CIPHER_CTX* ctx) {
    EVP_EncryptInit_ex(ctx, ciph, nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // EVP_EncryptInit_ex 可能重置 padding, 每 op 强制
    int outl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, in, static_cast<int>(n));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, out + outl, &fin);
}

static void ossl_cipher_dec(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                            const uint8_t* in, size_t n, uint8_t* out,
                            EVP_CIPHER_CTX* ctx) {
    EVP_DecryptInit_ex(ctx, ciph, nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // 每 op 强制关闭填充
    int outl = 0;
    EVP_DecryptUpdate(ctx, out, &outl, in, static_cast<int>(n));
    int fin = 0;
    EVP_DecryptFinal_ex(ctx, out + outl, &fin);
}

// GCM 加密 (AAD 可为空)
static void ossl_gcm_enc(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                         const std::vector<uint8_t>& pt, const std::vector<uint8_t>& aad,
                         std::vector<uint8_t>& ct, uint8_t tag[16], EVP_CIPHER_CTX* ctx) {
    EVP_EncryptInit_ex(ctx, ciph, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV12.size()), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    int outl = 0;
    if (!aad.empty())
        EVP_EncryptUpdate(ctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size()));
    ct.resize(pt.size());
    EVP_EncryptUpdate(ctx, ct.data(), &outl, pt.data(), static_cast<int>(pt.size()));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, ct.data() + outl, &fin);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
}

// GCM 解密; 返回 tag 是否通过
static bool ossl_gcm_dec(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                         const std::vector<uint8_t>& ct, const std::vector<uint8_t>& aad,
                         const uint8_t tag[16], std::vector<uint8_t>& pt,
                         EVP_CIPHER_CTX* ctx) {
    EVP_DecryptInit_ex(ctx, ciph, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV12.size()), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag));
    int outl = 0;
    if (!aad.empty())
        EVP_DecryptUpdate(ctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size()));
    pt.resize(ct.size());
    EVP_DecryptUpdate(ctx, pt.data(), &outl, ct.data(), static_cast<int>(ct.size()));
    int fin = 0;
    return EVP_DecryptFinal_ex(ctx, pt.data() + outl, &fin) == 1;
}

// ChaCha20-Poly1305 加密
static void ossl_ccp_enc(const uint8_t* key, const uint8_t* nonce,
                         const std::vector<uint8_t>& pt, const std::vector<uint8_t>& aad,
                         std::vector<uint8_t>& ct, uint8_t tag[16], EVP_CIPHER_CTX* ctx) {
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce);
    int outl = 0;
    if (!aad.empty())
        EVP_EncryptUpdate(ctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size()));
    ct.resize(pt.size());
    EVP_EncryptUpdate(ctx, ct.data(), &outl, pt.data(), static_cast<int>(pt.size()));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, ct.data() + outl, &fin);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
}

// ChaCha20-Poly1305 解密
static bool ossl_ccp_dec(const uint8_t* key, const uint8_t* nonce,
                         const std::vector<uint8_t>& ct, const std::vector<uint8_t>& aad,
                         const uint8_t tag[16], std::vector<uint8_t>& pt,
                         EVP_CIPHER_CTX* ctx) {
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag));
    int outl = 0;
    if (!aad.empty())
        EVP_DecryptUpdate(ctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size()));
    pt.resize(ct.size());
    EVP_DecryptUpdate(ctx, pt.data(), &outl, ct.data(), static_cast<int>(ct.size()));
    int fin = 0;
    return EVP_DecryptFinal_ex(ctx, pt.data() + outl, &fin) == 1;
}

// ── 自检辅助 ────────────────────────────────────────────────────
static int g_checks = 0;

static bool check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) g_all_pass = false;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    return ok;
}

// ── 块密码 (ECB/CBC) 交叉验证: jpssl(自动 PKCS7 填充) vs OpenSSL(padding=0) ──
// jpssl 密文 = n+16 字节, 前 n 字节应等于 OpenSSL 无填充密文
template <typename EncFn, typename DecFn>
static bool validate_block_padded(const char* name, size_t n,
                                  EncFn jenc, DecFn jdec,
                                  const EVP_CIPHER* ciph, const uint8_t* key,
                                  const uint8_t* iv) {
    std::vector<uint8_t> pt, jct, jpt, oct, opt;
    fill_test(pt, n, 0xA11CE);
    jenc(pt, jct);  // jpssl 加密 (n+16)
    EVP_CIPHER_CTX* enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(enc, 0);
    oct.resize(n);
    ossl_cipher_enc(ciph, key, iv, pt.data(), n, oct.data(), enc);
    EVP_CIPHER_CTX_free(enc);

    bool ok = jct.size() == n + 16 && std::equal(oct.begin(), oct.end(), jct.begin());
    check(ok, (std::string(name) + " ct prefix == OpenSSL (padding=0)").c_str());

    bool d1 = jdec(jct, jpt);
    ok = d1 && jpt == pt;
    check(ok, (std::string(name) + " jpssl decrypt roundtrip").c_str());

    EVP_CIPHER_CTX* dec = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(dec, 0);
    opt.resize(n);
    ossl_cipher_dec(ciph, key, iv, oct.data(), n, opt.data(), dec);
    EVP_CIPHER_CTX_free(dec);
    ok = opt == pt;
    check(ok, (std::string(name) + " OpenSSL decrypt roundtrip").c_str());

    // OpenSSL 解密 jpssl 密文前 n 字节
    EVP_CIPHER_CTX* dec2 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(dec2, 0);
    std::vector<uint8_t> opt2(n);
    ossl_cipher_dec(ciph, key, iv, jct.data(), n, opt2.data(), dec2);
    EVP_CIPHER_CTX_free(dec2);
    ok = opt2 == pt;
    check(ok, (std::string(name) + " OpenSSL decrypts jpssl ct").c_str());
    return ok;
}

// 无填充块密码 (jpssl aes_encrypt_ecb 等): 密文逐字节一致
template <typename EncFn, typename DecFn>
static bool validate_block_nopad(const char* name, size_t n,
                                 EncFn jenc, DecFn jdec,
                                 const EVP_CIPHER* ciph, const uint8_t* key,
                                 const uint8_t* iv) {
    std::vector<uint8_t> pt, jct, oct, opt;
    fill_test(pt, n, 0xBADC0DE);
    jct.resize(n);
    jenc(pt, jct);
    EVP_CIPHER_CTX* enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(enc, 0);
    oct.resize(n);
    ossl_cipher_enc(ciph, key, iv, pt.data(), n, oct.data(), enc);
    EVP_CIPHER_CTX_free(enc);

    bool ok = jct == oct;
    check(ok, (std::string(name) + " ct == OpenSSL (padding=0)").c_str());

    std::vector<uint8_t> jpt(n);
    jdec(jct, jpt);
    ok = jpt == pt;
    check(ok, (std::string(name) + " jpssl decrypt roundtrip").c_str());

    EVP_CIPHER_CTX* dec = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(dec, 0);
    opt.resize(n);
    ossl_cipher_dec(ciph, key, iv, oct.data(), n, opt.data(), dec);
    EVP_CIPHER_CTX_free(dec);
    ok = opt == pt;
    check(ok, (std::string(name) + " OpenSSL decrypt roundtrip").c_str());
    return ok;
}

// ── GCM 专用交叉验证 (含 OpenSSL 字节级对比) ────────────────────
struct GcmImpl {
    const char* impl;
    void (*enc)(const aes_context&, const uint8_t*, size_t, std::span<const uint8_t>,
                std::span<const uint8_t>, std::vector<uint8_t>&, uint8_t*, size_t);
    bool (*dec)(const aes_context&, const uint8_t*, size_t, std::span<const uint8_t>,
                std::span<const uint8_t>, const uint8_t*, size_t, std::vector<uint8_t>&);
};

static bool validate_gcm_impl(const char* name, const aes_context& ctx, const EVP_CIPHER* ciph,
                              const uint8_t* key, size_t n, const GcmImpl& gi) {
    std::vector<uint8_t> pt, aad, jct, oct, p2, p3, bct;
    uint8_t jtag[16] = {0}, otag[16] = {0};
    fill_test(pt, n, 0x0A55C0DE);

    gi.enc(ctx, IV12.data(), IV12.size(), pt, aad, jct, jtag, 16);

    EVP_CIPHER_CTX* ctxo = EVP_CIPHER_CTX_new();
    ossl_gcm_enc(ciph, key, IV12.data(), pt, aad, oct, otag, ctxo);

    bool ok = jct == oct && std::memcmp(jtag, otag, 16) == 0;
    check(ok, (std::string(name) + " ct+tag == OpenSSL").c_str());

    // jpssl 解密 OpenSSL 密文
    bool d1 = gi.dec(ctx, IV12.data(), IV12.size(), oct, aad, otag, 16, p2);
    ok = d1 && p2 == pt;
    check(ok, (std::string(name) + " jpssl decrypts OpenSSL ct").c_str());

    // OpenSSL 解密 jpssl 密文
    bool o1 = ossl_gcm_dec(ciph, key, IV12.data(), jct, aad, jtag, p3, ctxo);
    ok = o1 && p3 == pt;
    check(ok, (std::string(name) + " OpenSSL decrypts jpssl ct").c_str());

    // 篡改 tag → jpssl 拒绝
    uint8_t bad_tag[16];
    std::memcpy(bad_tag, jtag, 16);
    bad_tag[5] ^= 0x80;
    std::vector<uint8_t> p4;
    ok = !gi.dec(ctx, IV12.data(), IV12.size(), jct, aad, bad_tag, 16, p4);
    check(ok, (std::string(name) + " rejects tampered tag").c_str());

    // 篡改密文 → OpenSSL 拒绝
    bct = jct;
    bct[0] ^= 0x40;
    std::vector<uint8_t> p5;
    ok = !ossl_gcm_dec(ciph, key, IV12.data(), bct, aad, jtag, p5, ctxo);
    check(ok, (std::string(name) + " OpenSSL rejects tampered ct").c_str());
    EVP_CIPHER_CTX_free(ctxo);
    return ok;
}

// ── ChaCha20-Poly1305 专用交叉验证 ──────────────────────────────
struct CcpImpl {
    const char* impl;
    void (*enc)(const uint8_t[32], const uint8_t[12], std::span<const uint8_t>,
                std::span<const uint8_t>, std::vector<uint8_t>&, uint8_t[16]);
    bool (*dec)(const uint8_t[32], const uint8_t[12], std::span<const uint8_t>,
                std::span<const uint8_t>, const uint8_t[16], std::vector<uint8_t>&);
};

static bool validate_ccp_impl(const char* name, size_t n, const CcpImpl& ci) {
    std::vector<uint8_t> pt, aad, jct, oct, p2, p3, bct;
    uint8_t jtag[16] = {0}, otag[16] = {0};
    fill_test(pt, n, 0xC1A0520);

    ci.enc(K32.data(), IV12.data(), pt, aad, jct, jtag);

    EVP_CIPHER_CTX* ctxo = EVP_CIPHER_CTX_new();
    ossl_ccp_enc(K32.data(), IV12.data(), pt, aad, oct, otag, ctxo);

    bool ok = jct == oct && std::memcmp(jtag, otag, 16) == 0;
    check(ok, (std::string(name) + " ct+tag == OpenSSL").c_str());

    bool d1 = ci.dec(K32.data(), IV12.data(), oct, aad, otag, p2);
    ok = d1 && p2 == pt;
    check(ok, (std::string(name) + " jpssl decrypts OpenSSL ct").c_str());

    bool o1 = ossl_ccp_dec(K32.data(), IV12.data(), jct, aad, jtag, p3, ctxo);
    ok = o1 && p3 == pt;
    check(ok, (std::string(name) + " OpenSSL decrypts jpssl ct").c_str());

    uint8_t bad_tag[16];
    std::memcpy(bad_tag, jtag, 16);
    bad_tag[7] ^= 0x02;
    std::vector<uint8_t> p4;
    ok = !ci.dec(K32.data(), IV12.data(), jct, aad, bad_tag, p4);
    check(ok, (std::string(name) + " rejects tampered tag").c_str());

    bct = jct;
    bct[0] ^= 0x08;
    std::vector<uint8_t> p5;
    ok = !ossl_ccp_dec(K32.data(), IV12.data(), bct, aad, jtag, p5, ctxo);
    check(ok, (std::string(name) + " OpenSSL rejects tampered ct").c_str());
    EVP_CIPHER_CTX_free(ctxo);
    return ok;
}

// ── 各算法基准入口 ──────────────────────────────────────────────

// ECB/CBC 块密码: jpssl sw/aesni (PKCS7 填充) + auto(仅 ECB, 无填充)
template <typename E, typename D>
static void bench_block(const char* algo, size_t size,
                        const aes_context& ctx,
                        const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                        E&& jenc, D&& jdec, const char* impl) {
    // 准备密文 (供解密基准)
    std::vector<uint8_t> pt, jct, jpt;
    fill_test(pt, size, 0x00B100C);
    jenc(pt, jct);

    char algo_e[64], algo_d[64];
    std::snprintf(algo_e, sizeof(algo_e), "%s-enc", algo);
    std::snprintf(algo_d, sizeof(algo_d), "%s-dec", algo);

    double nse = auto_bench([&] {
        jenc(pt, jct);
        g_sink ^= jct[0];
    });
    record(algo_e, impl, size, nse);

    double nsd = auto_bench([&] {
        jdec(jct, jpt);
        g_sink ^= jpt[0];
    });
    record(algo_d, impl, size, nsd);

    // OpenSSL 对照
    EVP_CIPHER_CTX* c_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(c_enc, 0);
    EVP_CIPHER_CTX* c_dec = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(c_dec, 0);
    std::vector<uint8_t> oct(size), opt(size);
    nse = auto_bench([&] {
        ossl_cipher_enc(ciph, key, iv, pt.data(), size, oct.data(), c_enc);
        g_sink ^= oct[0];
    });
    record(algo_e, "openssl", size, nse);
    nsd = auto_bench([&] {
        ossl_cipher_dec(ciph, key, iv, oct.data(), size, opt.data(), c_dec);
        g_sink ^= opt[0];
    });
    record(algo_d, "openssl", size, nsd);
    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// GCM
static void bench_gcm(const char* algo, size_t size,
                      const aes_context& ctx, const EVP_CIPHER* ciph, const uint8_t* key,
                      const jpssl::cpu_features& feats) {
    std::vector<uint8_t> pt, aad, jct, jpt;
    uint8_t jtag[16] = {0};
    fill_test(pt, size, 0x6C0C);

    char algo_e[64], algo_d[64];
    std::snprintf(algo_e, sizeof(algo_e), "%s-enc", algo);
    std::snprintf(algo_d, sizeof(algo_d), "%s-dec", algo);

    struct GcmRow {
        const char* impl;
        void (*enc)(const aes_context&, const uint8_t*, size_t, std::span<const uint8_t>,
                    std::span<const uint8_t>, std::vector<uint8_t>&, uint8_t*, size_t);
        bool (*dec)(const aes_context&, const uint8_t*, size_t, std::span<const uint8_t>,
                    std::span<const uint8_t>, const uint8_t*, size_t, std::vector<uint8_t>&);
        bool gate;
        const char* skip_why;
    };
    const std::vector<GcmRow> rows = {
        {"jpssl-sw", jpssl::aes_gcm_encrypt_sw, jpssl::aes_gcm_decrypt_sw, true, ""},
        {"jpssl-aesni", jpssl::aes_gcm_encrypt_aesni, jpssl::aes_gcm_decrypt_aesni, true, ""},
        {"jpssl-avx2", jpssl::aes_gcm_encrypt_avx2, jpssl::aes_gcm_decrypt_avx2, feats.avx2, "no AVX2"},
        {"jpssl-vaes", jpssl::aes_gcm_encrypt_vaes, jpssl::aes_gcm_decrypt_vaes, feats.vpclmulqdq_vaes, "no VAES/VPCLMULQDQ"},
        {"jpssl-avx512", jpssl::aes_gcm_encrypt_avx512, jpssl::aes_gcm_decrypt_avx512, feats.avx512, "no AVX512"},
        {"jpssl-auto", jpssl::aes_gcm_encrypt_auto, jpssl::aes_gcm_decrypt_auto, true, ""},
    };

    for (const auto& r : rows) {
        if (!r.gate) {
            record_skip(algo_e, r.impl, size, r.skip_why);
            record_skip(algo_d, r.impl, size, r.skip_why);
            continue;
        }
        jct.clear();
        r.enc(ctx, IV12.data(), IV12.size(), pt, aad, jct, jtag, 16);
        double nse = auto_bench([&] {
            r.enc(ctx, IV12.data(), IV12.size(), pt, aad, jct, jtag, 16);
            g_sink ^= jct[0] ^ jtag[0];
        });
        record(algo_e, r.impl, size, nse);

        double nsd = auto_bench([&] {
            bool ok2 = r.dec(ctx, IV12.data(), IV12.size(), jct, aad, jtag, 16, jpt);
            g_sink ^= (int)ok2 ^ jpt[0];
        });
        record(algo_d, r.impl, size, nsd);
    }

    // OpenSSL 对照
    EVP_CIPHER_CTX* c_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* c_dec = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> oct, opt;
    uint8_t otag[16] = {0};
    ossl_gcm_enc(ciph, key, IV12.data(), pt, aad, oct, otag, c_enc);
    double nse = auto_bench([&] {
        ossl_gcm_enc(ciph, key, IV12.data(), pt, aad, oct, otag, c_enc);
        g_sink ^= oct[0] ^ otag[0];
    });
    record(algo_e, "openssl", size, nse);

    double nsd = auto_bench([&] {
        bool ok2 = ossl_gcm_dec(ciph, key, IV12.data(), oct, aad, otag, opt, c_dec);
        g_sink ^= (int)ok2 ^ opt[0];
    });
    record(algo_d, "openssl", size, nsd);
    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// ChaCha20-Poly1305
static void bench_ccp(const char* algo, size_t size, const jpssl::cpu_features& feats) {
    std::vector<uint8_t> pt, aad, jct, jpt;
    uint8_t jtag[16] = {0};
    fill_test(pt, size, 0xC1C1A);
    std::vector<uint8_t> stream_out(size);

    char algo_e[64], algo_d[64];
    std::snprintf(algo_e, sizeof(algo_e), "%s-enc", algo);
    std::snprintf(algo_d, sizeof(algo_d), "%s-dec", algo);

    // jpssl 默认 AEAD (自动分派)
    jpssl::chacha20_poly1305_encrypt(K32.data(), IV12.data(), pt, aad, jct, jtag);
    double nse = auto_bench([&] {
        jpssl::chacha20_poly1305_encrypt(K32.data(), IV12.data(), pt, aad, jct, jtag);
        g_sink ^= jct[0] ^ jtag[0];
    });
    record(algo_e, "jpssl-auto", size, nse);
    double nsd = auto_bench([&] {
        bool ok2 = jpssl::chacha20_poly1305_decrypt(K32.data(), IV12.data(), jct, aad, jtag, jpt);
        g_sink ^= (int)ok2 ^ jpt[0];
    });
    record(algo_d, "jpssl-auto", size, nsd);

    // jpssl AVX2 流 (chacha20_crypt_avx2, 需 AVX2)
    if (feats.avx2) {
        nse = auto_bench([&] {
            jpssl::chacha20_crypt_avx2(K32.data(), 1, IV12.data(), pt, stream_out);
            g_sink ^= stream_out[0];
        });
        record(algo_e, "jpssl-avx2", size, nse);
        nsd = auto_bench([&] {
            jpssl::chacha20_crypt_avx2(K32.data(), 1, IV12.data(), stream_out, pt);
            g_sink ^= pt[0];
        });
        record(algo_d, "jpssl-avx2", size, nsd);
    } else {
        record_skip(algo_e, "jpssl-avx2", size, "no AVX2");
        record_skip(algo_d, "jpssl-avx2", size, "no AVX2");
    }

    // jpssl AVX512 流 (需 AVX512; 本机 SKIP)
    if (feats.avx512) {
        nse = auto_bench([&] {
            jpssl::chacha20_crypt_avx512(K32.data(), 1, IV12.data(), pt, stream_out);
            g_sink ^= stream_out[0];
        });
        record(algo_e, "jpssl-avx512", size, nse);
        nsd = auto_bench([&] {
            jpssl::chacha20_crypt_avx512(K32.data(), 1, IV12.data(), stream_out, pt);
            g_sink ^= pt[0];
        });
        record(algo_d, "jpssl-avx512", size, nsd);
    } else {
        record_skip(algo_e, "jpssl-avx512", size, "no AVX512");
        record_skip(algo_d, "jpssl-avx512", size, "no AVX512");
    }

    // OpenSSL 对照
    EVP_CIPHER_CTX* c_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* c_dec = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> oct, opt;
    uint8_t otag[16] = {0};
    ossl_ccp_enc(K32.data(), IV12.data(), pt, aad, oct, otag, c_enc);
    nse = auto_bench([&] {
        ossl_ccp_enc(K32.data(), IV12.data(), pt, aad, oct, otag, c_enc);
        g_sink ^= oct[0] ^ otag[0];
    });
    record(algo_e, "openssl", size, nse);
    nsd = auto_bench([&] {
        bool ok2 = ossl_ccp_dec(K32.data(), IV12.data(), oct, aad, otag, opt, c_dec);
        g_sink ^= (int)ok2 ^ opt[0];
    });
    record(algo_d, "openssl", size, nsd);
    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// ── main ────────────────────────────────────────────────────────
int main() {
    auto feats = jpssl::cpu_features::detect();
    printf("=== bench_sym_multi: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("CPU features: AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES+VPCLMULQDQ=%d SHA-NI=%d\n",
           (int)feats.aesni, (int)feats.avx2, (int)feats.pclmulqdq,
           (int)feats.avx512, (int)feats.vpclmulqdq_vaes, (int)feats.sha_ni);
    if (feats.avx512) printf("  WARNING: AVX512 available on this host\n");

    // 准备 OpenSSL 上下文 (仅确保 OpenSSL 库初始化)
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    aes_context ctx128, ctx256;
    ctx128.init(K16);
    ctx256.init(K32);

    const std::vector<size_t> sizes = g_sizes;

    // ── 自检 (先于基准, 全 PASS 才继续) ──
    printf("\n=== Correctness self-checks (jpssl <-> OpenSSL) ===\n");

    // ECB 128/256: sw (pkcs7), aesni (pkcs7), auto (no padding)
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
        const char* kn = keysz ? "aes-256-ecb" : "aes-128-ecb";

        for (size_t n : {size_t(256), size_t(1048576)}) {
            char nm[80];
            std::snprintf(nm, sizeof(nm), "%s/sw@%zu", kn, n);
            validate_block_padded(nm, n,
                                  [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                                      jpssl::aes_encrypt_ecb_pkcs7_sw(ctx, p, c);
                                  },
                                  [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                                      return jpssl::aes_decrypt_ecb_pkcs7_sw(ctx, c, p);
                                  },
                                  ciph, key, nullptr);
            std::snprintf(nm, sizeof(nm), "%s/aesni@%zu", kn, n);
            validate_block_padded(nm, n,
                                  [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                                      jpssl::aes_encrypt_ecb_pkcs7_aesni(ctx, p, c);
                                  },
                                  [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                                      return jpssl::aes_decrypt_ecb_pkcs7_aesni(ctx, c, p);
                                  },
                                  ciph, key, nullptr);
            std::snprintf(nm, sizeof(nm), "%s/auto@%zu", kn, n);
            validate_block_nopad(nm, n,
                                 [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                                     jpssl::aes_encrypt_ecb(ctx, p, c);
                                 },
                                 [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                                     jpssl::aes_decrypt_ecb(ctx, c, p);
                                 },
                                 ciph, key, nullptr);
        }
    }

    // CBC 128/256: sw, aesni
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_cbc() : EVP_aes_128_cbc();
        const char* kn = keysz ? "aes-256-cbc" : "aes-128-cbc";

        for (size_t n : {size_t(256), size_t(1048576)}) {
            char nm[80];
            std::snprintf(nm, sizeof(nm), "%s/sw@%zu", kn, n);
            validate_block_padded(nm, n,
                                  [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                                      jpssl::aes_cbc_encrypt_sw(ctx, IV16.data(), p, c);
                                  },
                                  [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                                      return jpssl::aes_cbc_decrypt_sw(ctx, IV16.data(), c, p);
                                  },
                                  ciph, key, IV16.data());
            std::snprintf(nm, sizeof(nm), "%s/aesni@%zu", kn, n);
            validate_block_padded(nm, n,
                                  [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                                      jpssl::aes_cbc_encrypt_aesni(ctx, IV16.data(), p, c);
                                  },
                                  [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                                      return jpssl::aes_cbc_decrypt_aesni(ctx, IV16.data(), c, p);
                                  },
                                  ciph, key, IV16.data());
        }
    }

    // GCM 128/256: 每个实现交叉验证
    const GcmImpl gcm_impls[] = {
        {"sw", jpssl::aes_gcm_encrypt_sw, jpssl::aes_gcm_decrypt_sw},
        {"aesni", jpssl::aes_gcm_encrypt_aesni, jpssl::aes_gcm_decrypt_aesni},
        {"avx2", jpssl::aes_gcm_encrypt_avx2, jpssl::aes_gcm_decrypt_avx2},
        {"vaes", jpssl::aes_gcm_encrypt_vaes, jpssl::aes_gcm_decrypt_vaes},
        {"avx512", jpssl::aes_gcm_encrypt_avx512, jpssl::aes_gcm_decrypt_avx512},
        {"auto", jpssl::aes_gcm_encrypt_auto, jpssl::aes_gcm_decrypt_auto},
    };
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
        const char* kn = keysz ? "aes-256-gcm" : "aes-128-gcm";
        for (const auto& gi : gcm_impls) {
            if (std::string(gi.impl) == "avx2" && !feats.avx2) continue;
            if (std::string(gi.impl) == "vaes" && !feats.vpclmulqdq_vaes) continue;
            if (std::string(gi.impl) == "avx512" && !feats.avx512) continue;
            char nm[80];
            std::snprintf(nm, sizeof(nm), "%s/%s", kn, gi.impl);
            validate_gcm_impl(nm, ctx, ciph, key, 4096, gi);
        }
    }

    // ChaCha20-Poly1305: auto 与 avx2 交叉验证
    {
        CcpImpl auto_ci{"auto", jpssl::chacha20_poly1305_encrypt, jpssl::chacha20_poly1305_decrypt};
        validate_ccp_impl("chacha20-poly1305/auto", 4096, auto_ci);
        // chacha20_crypt_avx2 是流密码 (非 AEAD): 与 chacha20_crypt 对标验证
        {
            std::vector<uint8_t> pt, o1, o2;
            fill_test(pt, 4096, 0xC1A0521);
            o1.resize(4096);
            o2.resize(4096);
            jpssl::chacha20_crypt(K32.data(), 1, IV12.data(), pt, o1);
            if (feats.avx2) {
                jpssl::chacha20_crypt_avx2(K32.data(), 1, IV12.data(), pt, o2);
                check(o1 == o2, "chacha20 stream avx2 == default");
                bool ok = true;
                if (feats.avx512) {
                    std::vector<uint8_t> o3(4096);
                    jpssl::chacha20_crypt_avx512(K32.data(), 1, IV12.data(), pt, o3);
                    ok = o1 == o3;
                    check(ok, "chacha20 stream avx512 == default");
                }
                (void)ok;
            }
        }
    }

    if (!g_all_pass) {
        printf("\nSelf-check FAILED — aborting benchmark (exit 1)\n");
        return 1;
    }
    printf("All self-checks passed (%d checks)\n", g_checks);

    // ── 基准 ──
    printf("\n=== Benchmarks (min of 3 rounds, ~150ms/round) ===\n");
    printf("%-26s %-12s %9s %12s %12s\n", "algo", "impl", "size", "ns/op", "MB/s");

    // ECB
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
        char algo[64];
        std::snprintf(algo, sizeof(algo), "%s", keysz ? "aes-256-ecb" : "aes-128-ecb");
        for (size_t s : sizes) {
            bench_block(algo, s, ctx, ciph, key, nullptr,
                        [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                            jpssl::aes_encrypt_ecb_pkcs7_sw(ctx, p, c);
                        },
                        [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                            return jpssl::aes_decrypt_ecb_pkcs7_sw(ctx, c, p);
                        },
                        "jpssl-sw");
            bench_block(algo, s, ctx, ciph, key, nullptr,
                        [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                            jpssl::aes_encrypt_ecb_pkcs7_aesni(ctx, p, c);
                        },
                        [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                            return jpssl::aes_decrypt_ecb_pkcs7_aesni(ctx, c, p);
                        },
                        "jpssl-aesni");
            bench_block(algo, s, ctx, ciph, key, nullptr,
                        [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                            c.resize(p.size());
                            jpssl::aes_encrypt_ecb(ctx, p, c);
                        },
                        [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                            p.resize(c.size());
                            jpssl::aes_decrypt_ecb(ctx, c, p);
                        },
                        "jpssl-auto");
        }
    }

    // CBC
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_cbc() : EVP_aes_128_cbc();
        char algo[64];
        std::snprintf(algo, sizeof(algo), "%s", keysz ? "aes-256-cbc" : "aes-128-cbc");
        for (size_t s : sizes) {
            bench_block(algo, s, ctx, ciph, key, IV16.data(),
                        [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                            jpssl::aes_cbc_encrypt_sw(ctx, IV16.data(), p, c);
                        },
                        [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                            return jpssl::aes_cbc_decrypt_sw(ctx, IV16.data(), c, p);
                        },
                        "jpssl-sw");
            bench_block(algo, s, ctx, ciph, key, IV16.data(),
                        [&](std::vector<uint8_t>& p, std::vector<uint8_t>& c) {
                            jpssl::aes_cbc_encrypt_aesni(ctx, IV16.data(), p, c);
                        },
                        [&](std::vector<uint8_t>& c, std::vector<uint8_t>& p) {
                            return jpssl::aes_cbc_decrypt_aesni(ctx, IV16.data(), c, p);
                        },
                        "jpssl-aesni");
        }
    }

    // GCM
    for (int keysz = 0; keysz < 2; ++keysz) {
        const aes_context& ctx = keysz ? ctx256 : ctx128;
        const uint8_t* key = keysz ? K32.data() : K16.data();
        const EVP_CIPHER* ciph = keysz ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
        char algo[64];
        std::snprintf(algo, sizeof(algo), "%s", keysz ? "aes-256-gcm" : "aes-128-gcm");
        for (size_t s : sizes) bench_gcm(algo, s, ctx, ciph, key, feats);
    }

    // ChaCha20-Poly1305
    for (size_t s : sizes) bench_ccp("chacha20-poly1305", s, feats);

    // ── 写 CSV ──
    std::filesystem::path csv_dir = std::filesystem::path("benchmarks") / "results";
    std::error_code ec;
    std::filesystem::create_directories(csv_dir, ec);
    std::string csv_path = (csv_dir / "bench_sym_multi.csv").string();
    {
        std::ofstream f(csv_path);
        f << "algo,impl,size_bytes,ns_per_op,throughput_mbps\n";
        for (const auto& r : g_rows) {
            if (r.skipped) continue;
            f << r.algo << ',' << r.impl << ',' << r.size << ','
              << r.ns << ',' << r.mbps << '\n';
        }
    }
    printf("\nCSV written to %s\n", csv_path.c_str());
    printf("Done. All self-checks passed, exit 0.\n");
    return 0;
}
