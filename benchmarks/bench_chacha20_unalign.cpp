// bench_chacha20_unalign.cpp — ChaCha20-Poly1305 非对齐测试对比组 (jpssl vs OpenSSL)
//
// 目标: 在非对齐 (unaligned) 缓冲区下验证并对比 jpssl 与 OpenSSL 的
//       ChaCha20-Poly1305 AEAD 与 ChaCha20 流加密:
//   长度: 17 / 1001 / 32767 / 100003 (均非 16 的倍数 → AEAD 任意长度; 流加密同样)
//   指针偏移: 明文/密文起始偏移 1 / 3 / 7 / 13 (自检全覆盖);
//             性能基准覆盖 offset {0, 3}
//   AAD: 一个 17B 非对齐 AAD 用例 (+ offset==0 对照)
//
// 覆盖实现:
//   AEAD (key 32B / nonce 12B / tag 16B):
//     jpssl    chacha20_poly1305_encrypt / decrypt  (公开接口; 明文/密文输入 span
//              置于偏移处; 输出经公开 API 写 std::vector — 见下方注记)
//     openssl  EVP_chacha20_poly1305               (in/out 均直接写偏移缓冲区)
//   流加密 (非 AEAD, 对称 XOR):
//     jpssl      chacha20_crypt          (公开默认入口; 运行时自动分派 SIMD)
//     jpssl-avx2 chacha20_crypt_avx2     (强制 AVX2 实现)
//     jpssl-avx512 chacha20_crypt_avx512 (仅 cpu_has_avx512() 时调用, 否则 SKIP — 绝不调用)
//     openssl    EVP_chacha20            (16B IV = [LE32(counter)||nonce12])
//
// 注记:
//   - 公开 API chacha20_poly1305_encrypt/decrypt 的密文/明文输出为 std::vector
//     (allocator 对齐), 无法通过公开接口置偏移; 故 jpssl AEAD 的"非对齐"体现在
//     输入 span (明文/密文/AAD) 的指针偏移, 输出偏移由 OpenSSL 侧与流加密侧覆盖。
//     正确性以"jpssl 输出 vs OpenSSL 偏移输出逐字节一致"交叉验证。
//   - 流加密 chacha20_crypt* 接受 span, in/out 均可置于任意偏移, 双向非对齐全覆盖。
//   - AVX512: 本机不支持 → record_skip + [SKIP], 绝不对 chacha20_crypt_avx512 发起调用
//     (否则 SIGILL)。
//
// 正确性自检 (始终执行, 与 BENCH_SMOKE 无关):
//   - AEAD: jpssl 与 OpenSSL ct+tag 逐字节一致; 双向解密往返 (jpssl 解密 OpenSSL ct /
//     OpenSSL 解密 jpssl ct); 篡改 tag (jpssl 拒绝) 与篡改 ct (OpenSSL 拒绝);
//     offset==0 对照; 17B 非对齐 AAD 用例。任一 FAIL → 非零退出, 不写 CSV。
//   - 流加密: chacha20_crypt == chacha20_crypt_avx2 == (avx512 若有) == OpenSSL 流,
//     逐字节一致。
// 性能基准:
//   全量: 长度 {17,1001,32767,100003} × offset {0,3}, ~150ms/轮, 3 轮取最小
//   BENCH_SMOKE=1: 长度 {17,1001} × offset {0,3}, ~80ms/轮, 1 轮
// 输出: benchmarks/results/bench_chacha20_unalign.csv
//   列头: algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps
//   algo: chacha20-poly1305-enc-unalign / chacha20-poly1305-dec-unalign /
//         chacha20-stream-unalign
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_chacha20_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_chacha20_unalign

#include "chacha20_poly1305.hpp"
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

using Clock = std::chrono::steady_clock;

// 阻止编译器把输出缓冲区相关调用折叠/消除
static volatile int g_sink = 0;

// ── 固定测试数据 ────────────────────────────────────────────────
static const std::array<uint8_t, 32> K32 = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
static const std::array<uint8_t, 12> IV12 = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b};

// 非对齐长度矩阵 (均非 16 的倍数)
static const std::vector<size_t> g_sizes = {17, 1001, 32767, 100003};
// 自检偏移 (全覆盖) / 性能偏移
static const int g_off_check[] = {1, 3, 7, 13};
static const int g_off_bench[] = {0, 3};
static constexpr size_t MAX_OFF = 13;
static constexpr size_t AAD_N = 17;  // 非对齐 AAD 用例长度

// 确定性伪随机填充指定字节区间
static void fill_range(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed * 2654435761u + 12345u;
    for (size_t i = 0; i < n; ++i) {
        x = x * 1664525u + 1013904223u;
        p[i] = static_cast<uint8_t>(x >> 24);
    }
}

// 偏移测试缓冲区: 容量 ≥ n + MAX_OFF + 64, 保证 data()+off 处写 n 字节不越界
static std::vector<uint8_t> make_buf(size_t n) {
    return std::vector<uint8_t>(n + MAX_OFF + 64);
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
    int offset;
    double ns;
    double mbps;
    bool skipped;
};
static std::vector<Row> g_rows;
static bool g_all_pass = true;

static void record(const char* algo, const char* impl, size_t size, int offset, double ns) {
    double mbps = size / ns * 1000.0;  // bytes/ns * 1000 = MB/s
    g_rows.push_back({algo, impl, size, offset, ns, mbps, false});
    printf("%-30s %-12s %9zu %7d %12.1f %12.1f\n", algo, impl, size, offset, ns, mbps);
}

static void record_skip(const char* algo, const char* impl, size_t size, int offset, const char* why) {
    g_rows.push_back({algo, impl, size, offset, 0.0, 0.0, true});
    printf("%-30s %-12s %9zu %7d SKIP (%s)\n", algo, impl, size, offset, why);
}

// ── OpenSSL 基础封装 (raw 指针 + 长度, 支持非对齐 in/out) ───────

// ChaCha20-Poly1305 加密 (AAD 可为空; pt/ct 可置于任意偏移)
static void ossl_ccp_enc(EVP_CIPHER_CTX* ctx, const uint8_t key[32], const uint8_t nonce[12],
                         const uint8_t* pt, size_t pt_len,
                         const uint8_t* aad, size_t aad_len,
                         uint8_t* ct, uint8_t tag[16]) {
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce);
    int outl = 0;
    if (aad_len > 0)
        EVP_EncryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aad_len));
    EVP_EncryptUpdate(ctx, ct, &outl, pt, static_cast<int>(pt_len));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, ct + outl, &fin);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
}

// ChaCha20-Poly1305 解密; 返回 tag 是否通过
static bool ossl_ccp_dec(EVP_CIPHER_CTX* ctx, const uint8_t key[32], const uint8_t nonce[12],
                         const uint8_t* ct, size_t ct_len,
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t tag[16], uint8_t* pt) {
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nonce);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag));
    int outl = 0;
    if (aad_len > 0)
        EVP_DecryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aad_len));
    EVP_DecryptUpdate(ctx, pt, &outl, ct, static_cast<int>(ct_len));
    int fin = 0;
    return EVP_DecryptFinal_ex(ctx, pt + outl, &fin) == 1;
}

// ChaCha20 流加密 (OpenSSL): 16B IV = [LE32(counter) || nonce12],
// 与 jpssl chacha20_crypt(key, counter, nonce12) 的 keystream 布局逐字节对齐
static void ossl_chacha20_stream(EVP_CIPHER_CTX* ctx, const uint8_t key[32], uint32_t counter,
                                 const uint8_t nonce[12],
                                 const uint8_t* in, size_t n, uint8_t* out) {
    uint8_t ivec[16];
    ivec[0] = static_cast<uint8_t>(counter & 0xff);
    ivec[1] = static_cast<uint8_t>((counter >> 8) & 0xff);
    ivec[2] = static_cast<uint8_t>((counter >> 16) & 0xff);
    ivec[3] = static_cast<uint8_t>((counter >> 24) & 0xff);
    std::memcpy(ivec + 4, nonce, 12);
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key, ivec);
    int outl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, in, static_cast<int>(n));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, out + outl, &fin);
}

// ── 自检辅助 ────────────────────────────────────────────────────
static int g_checks = 0;
static int g_pass = 0;

static bool check(bool ok, const char* what) {
    ++g_checks;
    if (ok) ++g_pass; else g_all_pass = false;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    return ok;
}

// ── 正确性自检: AEAD (jpssl 公开接口) × OpenSSL, 单档位 (size, offset, aad_len) ──
// aad_len==0 → 无 AAD; aad_len>0 → AAD 置于同一 offset (非对齐 AAD 用例)
static void validate_ccp(size_t n, int off, size_t aad_len) {
    std::vector<uint8_t> ptbuf = make_buf(n), oct_buf = make_buf(n), p2_buf = make_buf(n);
    std::vector<uint8_t> aadbuf = make_buf(aad_len > 0 ? aad_len : 1);
    std::vector<uint8_t> jct, p2, p3, bct_buf;
    uint8_t jtag[16] = {0}, otag[16] = {0};
    fill_range(ptbuf.data() + off, n, 0xC1A0520 + static_cast<uint32_t>(off));
    if (aad_len > 0) fill_range(aadbuf.data() + off, aad_len, 0xAADAAAD);
    std::span<const uint8_t> pt_span(ptbuf.data() + off, n);
    std::span<const uint8_t> aad_span(aadbuf.data() + off, aad_len);

    char nm[128];
    if (aad_len > 0)
        std::snprintf(nm, sizeof(nm), "chacha20-poly1305/jpssl@%zu/off=%d/aad%zu", n, off, aad_len);
    else
        std::snprintf(nm, sizeof(nm), "chacha20-poly1305/jpssl@%zu/off=%d", n, off);

    EVP_CIPHER_CTX* ctxo = EVP_CIPHER_CTX_new();

    // jpssl 加密 (明文输入 span 置于 offset) vs OpenSSL (in/out 均置于 offset)
    jpssl::chacha20_poly1305_encrypt(K32.data(), IV12.data(), pt_span, aad_span, jct, jtag);
    ossl_ccp_enc(ctxo, K32.data(), IV12.data(), ptbuf.data() + off, n,
                 aadbuf.data() + off, aad_len, oct_buf.data() + off, otag);
    bool ok = jct.size() == n &&
              std::memcmp(jct.data(), oct_buf.data() + off, n) == 0 &&
              std::memcmp(jtag, otag, 16) == 0;
    check(ok, (std::string(nm) + " ct+tag == OpenSSL (unaligned)").c_str());

    // jpssl 解密 OpenSSL 密文 (密文输入 span 置于 offset)
    bool d1 = jpssl::chacha20_poly1305_decrypt(
        K32.data(), IV12.data(), std::span<const uint8_t>(oct_buf.data() + off, n),
        aad_span, otag, p2);
    ok = d1 && p2.size() == n &&
         std::memcmp(p2.data(), ptbuf.data() + off, n) == 0;
    check(ok, (std::string(nm) + " jpssl decrypts OpenSSL ct").c_str());

    // OpenSSL 解密 jpssl 密文 (明文输出置于 offset)
    bool o1 = ossl_ccp_dec(ctxo, K32.data(), IV12.data(), jct.data(), n,
                           aadbuf.data() + off, aad_len, jtag, p2_buf.data() + off);
    ok = o1 && std::memcmp(p2_buf.data() + off, ptbuf.data() + off, n) == 0;
    check(ok, (std::string(nm) + " OpenSSL decrypts jpssl ct").c_str());

    // 篡改 tag → jpssl 拒绝
    uint8_t bad_tag[16];
    std::memcpy(bad_tag, jtag, 16);
    bad_tag[7] ^= 0x02;
    std::vector<uint8_t> p4;
    ok = !jpssl::chacha20_poly1305_decrypt(
        K32.data(), IV12.data(), std::span<const uint8_t>(oct_buf.data() + off, n),
        aad_span, bad_tag, p4);
    check(ok, (std::string(nm) + " jpssl rejects tampered tag").c_str());

    // 篡改密文 → OpenSSL 拒绝 (保持同一 offset)
    bct_buf = oct_buf;
    uint8_t* bctp = bct_buf.data() + off;
    bctp[0] ^= 0x08;
    ok = !ossl_ccp_dec(ctxo, K32.data(), IV12.data(), bctp, n,
                       aadbuf.data() + off, aad_len, otag, p3.data());
    check(ok, (std::string(nm) + " OpenSSL rejects tampered ct").c_str());

    EVP_CIPHER_CTX_free(ctxo);
}

// ── 正确性自检: 流加密多实现互比 + OpenSSL 对齐, 单档位 (size, offset) ──
static void validate_stream(size_t n, int off) {
    std::vector<uint8_t> inbuf = make_buf(n), o0b = make_buf(n), o1b = make_buf(n),
                         o2b = make_buf(n), o3b = make_buf(n);
    fill_range(inbuf.data() + off, n, 0xC1A0521 + static_cast<uint32_t>(off));
    uint8_t* in = inbuf.data() + off;
    char nm[128];
    std::snprintf(nm, sizeof(nm), "chacha20-stream/jpssl@%zu/off=%d", n, off);
    bool ok;

    // 加密与解密同为 XOR, 语义对称; 统一以 counter=1 (AEAD 实际使用值) 加密明文
    jpssl::chacha20_crypt(K32.data(), 1, IV12.data(),
                          std::span<const uint8_t>(in, n),
                          std::span<uint8_t>(o0b.data() + off, n));  // 公开默认入口

    if (jpssl::cpu_has_avx2()) {
        jpssl::chacha20_crypt_avx2(K32.data(), 1, IV12.data(),
                                   std::span<const uint8_t>(in, n),
                                   std::span<uint8_t>(o1b.data() + off, n));
        ok = std::memcmp(o0b.data() + off, o1b.data() + off, n) == 0;
        check(ok, (std::string(nm) + " avx2 == default (unaligned)").c_str());
    } else {
        printf("  [SKIP] %s avx2 (no AVX2)\n", nm);
    }

    if (jpssl::cpu_has_avx512()) {
        jpssl::chacha20_crypt_avx512(K32.data(), 1, IV12.data(),
                                     std::span<const uint8_t>(in, n),
                                     std::span<uint8_t>(o2b.data() + off, n));
        ok = std::memcmp(o0b.data() + off, o2b.data() + off, n) == 0;
        check(ok, (std::string(nm) + " avx512 == default (unaligned)").c_str());
    } else {
        printf("  [SKIP] %s avx512 (no AVX512, never called)\n", nm);
    }

    // 与 OpenSSL chacha20 流对齐 (16B IV = [LE32(counter)||nonce12])
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    ossl_chacha20_stream(c, K32.data(), 1, IV12.data(), in, n, o3b.data() + off);
    ok = std::memcmp(o0b.data() + off, o3b.data() + off, n) == 0;
    check(ok, (std::string(nm) + " == OpenSSL chacha20 stream (unaligned)").c_str());
    EVP_CIPHER_CTX_free(c);
}

// ── 性能基准: 单档位 (size, offset), 全部实现路径 ────────────────
static void bench_one(size_t size, int off, double target_ms, int rounds) {
    std::vector<uint8_t> ptbuf = make_buf(size), ctbuf = make_buf(size), pt2buf = make_buf(size);
    std::vector<uint8_t> sobuf = make_buf(size);  // 流加密输出 (置于 offset)
    std::vector<uint8_t> aadbuf = make_buf(1);
    std::vector<uint8_t> jct, jpt;
    uint8_t jtag[16] = {0}, otag[16] = {0};
    fill_range(ptbuf.data() + off, size, 0xC1C1A + static_cast<uint32_t>(off));
    const uint8_t* pt = ptbuf.data() + off;
    uint8_t* ct = ctbuf.data() + off;
    std::span<const uint8_t> pt_span(pt, size);
    std::span<const uint8_t> aad_span(aadbuf.data(), 0);  // 空 AAD (与参考一致)
    const char* algo_e = "chacha20-poly1305-enc-unalign";
    const char* algo_d = "chacha20-poly1305-dec-unalign";
    const char* algo_s = "chacha20-stream-unalign";
    double nse = 0.0, nsd = 0.0;

    // ── AEAD: jpssl 公开接口 (明文输入 span 置于 offset) ──
    jpssl::chacha20_poly1305_encrypt(K32.data(), IV12.data(), pt_span, aad_span, jct, jtag);
    nse = auto_bench(
        [&] { jpssl::chacha20_poly1305_encrypt(K32.data(), IV12.data(), pt_span, aad_span, jct, jtag);
              g_sink ^= jct[0] ^ jtag[0]; }, target_ms, rounds);
    record(algo_e, "jpssl", size, off, nse);
    nsd = auto_bench(
        [&] { bool ok2 = jpssl::chacha20_poly1305_decrypt(
                  K32.data(), IV12.data(),
                  std::span<const uint8_t>(jct.data(), jct.size()), aad_span, jtag, jpt);
              g_sink ^= (int)ok2 ^ jpt[0]; }, target_ms, rounds);
    record(algo_d, "jpssl", size, off, nsd);

    // ── 流加密: jpssl 公开默认入口 chacha20_crypt (in/out 均置于 offset) ──
    nse = auto_bench(
        [&] { jpssl::chacha20_crypt(K32.data(), 1, IV12.data(),
                                    std::span<const uint8_t>(pt, size),
                                    std::span<uint8_t>(sobuf.data() + off, size));
              g_sink ^= sobuf[off]; }, target_ms, rounds);
    record(algo_s, "jpssl", size, off, nse);

    // ── 流加密: jpssl AVX2 强制实现 ──
    if (jpssl::cpu_has_avx2()) {
        nse = auto_bench(
            [&] { jpssl::chacha20_crypt_avx2(K32.data(), 1, IV12.data(),
                                             std::span<const uint8_t>(pt, size),
                                             std::span<uint8_t>(sobuf.data() + off, size));
                  g_sink ^= sobuf[off]; }, target_ms, rounds);
        record(algo_s, "jpssl-avx2", size, off, nse);
    } else {
        record_skip(algo_s, "jpssl-avx2", size, off, "no AVX2");
    }

    // ── 流加密: jpssl AVX512 强制实现 (不支持 → SKIP, 绝不调用) ──
    if (jpssl::cpu_has_avx512()) {
        nse = auto_bench(
            [&] { jpssl::chacha20_crypt_avx512(K32.data(), 1, IV12.data(),
                                               std::span<const uint8_t>(pt, size),
                                               std::span<uint8_t>(sobuf.data() + off, size));
                  g_sink ^= sobuf[off]; }, target_ms, rounds);
        record(algo_s, "jpssl-avx512", size, off, nse);
    } else {
        record_skip(algo_s, "jpssl-avx512", size, off, "no AVX512");
    }

    // ── AEAD + 流: OpenSSL 对照 (in/out 均置于 offset) ──
    EVP_CIPHER_CTX* c_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* c_dec = EVP_CIPHER_CTX_new();
    ossl_ccp_enc(c_enc, K32.data(), IV12.data(), pt, size, nullptr, 0, ct, otag);
    nse = auto_bench(
        [&] { ossl_ccp_enc(c_enc, K32.data(), IV12.data(), pt, size, nullptr, 0, ct, otag);
              g_sink ^= ct[0] ^ otag[0]; }, target_ms, rounds);
    record(algo_e, "openssl", size, off, nse);
    nsd = auto_bench(
        [&] { bool ok2 = ossl_ccp_dec(c_dec, K32.data(), IV12.data(), ct, size,
                                      nullptr, 0, otag, pt2buf.data() + off);
              g_sink ^= (int)ok2 ^ pt2buf[off]; }, target_ms, rounds);
    record(algo_d, "openssl", size, off, nsd);
    nse = auto_bench(
        [&] { ossl_chacha20_stream(c_enc, K32.data(), 1, IV12.data(),
                                   pt, size, sobuf.data() + off);
              g_sink ^= sobuf[off]; }, target_ms, rounds);
    record(algo_s, "openssl", size, off, nse);

    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// ── main ────────────────────────────────────────────────────────
int main() {
    const bool smoke = [] {
        const char* e = std::getenv("BENCH_SMOKE");
        return e != nullptr && *e != '\0' && std::string(e) != "0";
    }();

    auto feats = jpssl::cpu_features::detect();
    const bool have_avx2 = jpssl::cpu_has_avx2();
    const bool have_avx512 = jpssl::cpu_has_avx512();

    printf("=== bench_chacha20_unalign: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("CPU features: AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES+VPCLMULQDQ=%d SHA-NI=%d\n",
           (int)feats.aesni, (int)feats.avx2, (int)feats.pclmulqdq,
           (int)feats.avx512, (int)feats.vpclmulqdq_vaes, (int)feats.sha_ni);
    printf("mode: %s (BENCH_SMOKE=%d), avx2=%d avx512=%d\n",
           smoke ? "smoke" : "full", (int)smoke, (int)have_avx2, (int)have_avx512);
    if (have_avx512) printf("  WARNING: AVX512 available on this host\n");

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    // ── 正确性自检 (始终全部长度 × 偏移 1/3/7/13 + offset==0 对照, 与 smoke 无关) ──
    printf("\n=== Correctness self-checks (unaligned, jpssl <-> OpenSSL) ===\n");
    for (size_t n : g_sizes) {
        for (int off : g_off_check) validate_ccp(n, off, 0);
        validate_ccp(n, 0, 0);  // offset==0 对照
    }
    // 17B 非对齐 AAD 用例 (+ offset==0 对照)
    validate_ccp(17, 13, AAD_N);
    validate_ccp(17, 0, AAD_N);
    for (size_t n : g_sizes) {
        for (int off : g_off_check) validate_stream(n, off);
        validate_stream(n, 0);  // offset==0 对照
    }

    if (!g_all_pass) {
        printf("\nSelf-check FAILED (%d/%d checks passed) — aborting benchmark (exit 1)\n",
               g_pass, g_checks);
        return 1;
    }
    printf("All self-checks passed (%d checks)\n", g_checks);

    // ── 性能基准 ──
    const std::vector<size_t> sizes = smoke ? std::vector<size_t>{17, 1001} : g_sizes;
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;
    printf("\n=== Benchmarks (mode=%s, %.0fms/round, %d round(s), min) ===",
           smoke ? "smoke" : "full", target_ms, rounds);
    printf("  sizes x offsets: ");
    for (size_t s : sizes) printf("%zu,", s);
    printf(" x {0,3}\n");
    printf("%-30s %-12s %9s %7s %12s %12s\n", "algo", "impl", "size", "offset", "ns/op", "MB/s");

    for (size_t s : sizes)
        for (int off : g_off_bench) bench_one(s, off, target_ms, rounds);

    // ── 写 CSV ──
    std::filesystem::path csv_dir = std::filesystem::path("benchmarks") / "results";
    std::error_code ec;
    std::filesystem::create_directories(csv_dir, ec);
    std::string csv_path = (csv_dir / "bench_chacha20_unalign.csv").string();
    size_t csv_rows = 0;
    {
        std::ofstream f(csv_path);
        if (!f) {
            printf("\nERROR: cannot write %s\n", csv_path.c_str());
            return 1;
        }
        f << "algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps\n";
        for (const auto& r : g_rows) {
            if (r.skipped) continue;
            f << r.algo << ',' << r.impl << ',' << r.size << ',' << r.offset << ','
              << r.ns << ',' << r.mbps << '\n';
            ++csv_rows;
        }
    }
    size_t skip_count = 0;
    for (const auto& r : g_rows) if (r.skipped) ++skip_count;
    printf("\nCSV written to %s (%zu data rows, %zu SKIP rows)\n",
           csv_path.c_str(), csv_rows, skip_count);
    if (!have_avx512) printf("AVX512: not supported on this host — SKIP (never called)\n");
    printf("Done. All self-checks passed (%d), exit 0.\n", g_pass);
    return 0;
}
