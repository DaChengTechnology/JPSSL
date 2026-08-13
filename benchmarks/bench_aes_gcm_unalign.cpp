// bench_aes_gcm_unalign.cpp — AES-128-GCM 非对齐测试对比组 (jpssl vs OpenSSL)
//
// 在 benchmarks/bench_aes_gcm.cpp（已验证的 GcmImpl 表 / validate_gcm_impl /
// auto_bench / CSV 写法）基础上，聚焦 GCM 的【非对齐输入】行为：
//
//   1. 非对齐长度: 17 / 1001 / 32767 / 100003 字节
//      (GCM 是任意长度 AEAD，覆盖整块 + 余数边界)
//   2. 非对齐指针 offset: 明文/密文/AAD/tag 起始地址偏移 1/3/7/13
//      - 自检: offset 1/3/7/13 全覆盖, 并与 offset=0 结果逐字节一致
//      - 性能: offset {0,3}
//      - AAD: 空 AAD + 17B AAD（AAD 指针同样非对齐）
//   3. 自检始终执行（与 BENCH_SMOKE 无关）:
//      jpssl 各实现与 OpenSSL ct+tag 一致 / 双向解密一致 / 篡改拒绝 /
//      offset 指针与 offset=0 一致; 任一 FAIL → 非零退出
//   4. 性能基准: 长度 {17,1001,32767,100003} × offset {0,3} (加密+解密)
//      BENCH_SMOKE=1: 长度 {17,1001} × offset {0,3}, ~80ms, 1 轮
//      未设置: 全量, ~150ms, 3 轮取最小
//
// 运行时 CPU 特性检测; 不支持的实现仅打印 SKIP, 绝不调用
// (本机无 AVX512, 直接调用 avx512 变体会 SIGILL)。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_aes_gcm_unalign.cpp
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto -o /tmp/bench_aes_gcm_unalign
//
// 运行:
//   BENCH_SMOKE=1 /tmp/bench_aes_gcm_unalign   # smoke: 长度 {17,1001} × offset {0,3}
//   /tmp/bench_aes_gcm_unalign                 # 全量: 长度 × offset {0,3}
//
// 输出:
//   benchmarks/results/bench_aes_gcm_unalign.csv
//   (列头 algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps;
//    algo 形如 aes-128-gcm-enc-unalign; SKIP 的实现不入 CSV, 仅 stdout 注明)

#include "aes.hpp"
#include "cpu_features.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

using jpssl::aes_context;

using Clock = std::chrono::steady_clock;

// 阻止编译器把输出缓冲区相关调用折叠/消除
static volatile int g_sink = 0;

// ── 固定测试数据 (AES-128) ───────────────────────────────────────
static const std::array<uint8_t, 16> K16 = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
// IV 12B (GCM 推荐)
static const std::array<uint8_t, 12> IV12 = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b};

// 非对齐长度 (整块 + 余数边界)
static const std::vector<size_t> g_sizes_full = {17, 1001, 32767, 100003};
static const std::vector<size_t> g_sizes_smoke = {17, 1001};
// 自检非对齐 offset 全覆盖; 性能至少 offset {0,3}
static const std::vector<size_t> g_offsets_check = {1, 3, 7, 13};
static const std::vector<size_t> g_offsets_bench = {0, 3};

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
    size_t offset;
    double ns;
    double mbps;
};
static std::vector<Row> g_rows;
static bool g_all_pass = true;

static void record(const char* algo, const char* impl, size_t size, size_t off, double ns) {
    double mbps = size / ns * 1000.0;  // bytes/ns * 1000 = MB/s
    g_rows.push_back({algo, impl, size, off, ns, mbps});
    printf("%-30s %-12s %9zu off=%-2zu %12.1f %12.1f\n",
           algo, impl, size, off, ns, mbps);
}

static void record_skip(const char* algo, const char* impl, size_t size, size_t off,
                        const char* why) {
    printf("%-30s %-12s %9zu off=%-2zu SKIP (%s)\n", algo, impl, size, off, why);
}

// ── 自检辅助 ────────────────────────────────────────────────────
static int g_checks = 0;

static bool check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) g_all_pass = false;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    return ok;
}

// ── OpenSSL GCM 封装 (原始指针版本, 支持非对齐输入) ─────────────
// GCM 加密 (AAD 可为空), tag 16B
static void ossl_gcm_enc(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                         const uint8_t* pt, size_t pt_len, const uint8_t* aad, size_t aad_len,
                         std::vector<uint8_t>& ct, uint8_t* tag, EVP_CIPHER_CTX* ctx) {
    EVP_EncryptInit_ex(ctx, ciph, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    int outl = 0;
    if (aad_len)
        EVP_EncryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aad_len));
    ct.resize(pt_len);
    EVP_EncryptUpdate(ctx, ct.data(), &outl, pt, static_cast<int>(pt_len));
    int fin = 0;
    EVP_EncryptFinal_ex(ctx, ct.data() + outl, &fin);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
}

// GCM 解密; 返回 tag 是否通过
static bool ossl_gcm_dec(const EVP_CIPHER* ciph, const uint8_t* key, const uint8_t* iv,
                         const uint8_t* ct, size_t ct_len, const uint8_t* aad, size_t aad_len,
                         const uint8_t* tag, std::vector<uint8_t>& pt, EVP_CIPHER_CTX* ctx) {
    EVP_DecryptInit_ex(ctx, ciph, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag));
    int outl = 0;
    if (aad_len)
        EVP_DecryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aad_len));
    pt.resize(ct_len);
    EVP_DecryptUpdate(ctx, pt.data(), &outl, ct, static_cast<int>(ct_len));
    int fin = 0;
    return EVP_DecryptFinal_ex(ctx, pt.data() + outl, &fin) == 1;
}

// ── GCM 实现表 (宏保护变体在编译期已可见; 运行期用 CPU 特性门控) ─
struct GcmImpl {
    const char* impl;  // CSV/输出 id: jpssl-sw / jpssl-aesni / ... / openssl 单独处理
    void (*enc)(const aes_context&, const uint8_t*, size_t, std::span<const uint8_t>,
                std::span<const uint8_t>, std::vector<uint8_t>&, uint8_t*, size_t);
    bool (*dec)(const aes_context&, const uint8_t*, size_t, std::span<const uint8_t>,
                std::span<const uint8_t>, const uint8_t*, size_t, std::vector<uint8_t>&);
    bool gate;
    const char* skip_why;
};

static std::vector<GcmImpl> make_impls(const jpssl::cpu_features& feats) {
    return {
        {"jpssl-sw", jpssl::aes_gcm_encrypt_sw, jpssl::aes_gcm_decrypt_sw, true, ""},
        {"jpssl-aesni", jpssl::aes_gcm_encrypt_aesni, jpssl::aes_gcm_decrypt_aesni, true, ""},
        {"jpssl-avx2", jpssl::aes_gcm_encrypt_avx2, jpssl::aes_gcm_decrypt_avx2,
         feats.avx2, "no AVX2"},
#if defined(__x86_64__) && defined(JP_VAES)
        {"jpssl-vaes", jpssl::aes_gcm_encrypt_vaes, jpssl::aes_gcm_decrypt_vaes,
         feats.vpclmulqdq_vaes, "no VAES/VPCLMULQDQ"},
#endif
#if defined(JP_AVX512)
        {"jpssl-avx512", jpssl::aes_gcm_encrypt_avx512, jpssl::aes_gcm_decrypt_avx512,
         feats.avx512, "no AVX512 (SIGILL if called; never called)"},
#endif
        {"jpssl-auto", jpssl::aes_gcm_encrypt_auto, jpssl::aes_gcm_decrypt_auto, true, ""},
    };
}

// ── 非对齐自检: 一个 (长度, AAD) 组合 × 全部实现 × offset 1/3/7/13 ──
// 每项检查:
//   a) jpssl 加密 (非对齐 pt/aad/tag) 与 OpenSSL 加密 (同指针) ct+tag 逐字节一致
//   b) jpssl 解密 OpenSSL 密文 (非对齐 ct/aad/tag) == 原始明文
//   c) OpenSSL 解密 jpssl 密文 (非对齐 ct/aad/tag) == 原始明文
//   d) 篡改 tag → jpssl 拒绝
//   e) 篡改密文 → OpenSSL 拒绝
//   f) offset 指针结果与 offset=0 结果逐字节一致
static void validate_unalign(const aes_context& ctx, const EVP_CIPHER* ciph, const uint8_t* key,
                             size_t n, size_t aad_len, const jpssl::cpu_features& feats) {
    const size_t slack = 64;  // >= max offset (13) + tag(16) 余量
    std::vector<uint8_t> pt_ref(n), aad_ref;
    fill_test(pt_ref, n, 0xA55A0FF0u ^ static_cast<uint32_t>(n));
    if (aad_len) fill_test(aad_ref, aad_len, 0x17AAD17u);

    // 注意: 每个 offset 使用【独立缓冲】(在 data()+off 处放同一份 pt_ref),
    // 不可共用一个池 —— 不同 offset 的切片会重叠, 后写的切片会覆盖先写的。
    EVP_CIPHER_CTX* ctxo = EVP_CIPHER_CTX_new();
    const auto impls = make_impls(feats);

    for (const auto& gi : impls) {
        char base[96];
        std::snprintf(base, sizeof(base), "aes-128-gcm/%s@%zu aad=%zu", gi.impl, n, aad_len);
        if (!gi.gate) {
            printf("  [SKIP] %s: %s\n", base, gi.skip_why);
            continue;
        }
        char nm[192];

        // ── offset=0 基准 (独立缓冲, data()+0 处填入 pt_ref) ──
        std::vector<uint8_t> pt0(n + slack, 0), aad0buf(aad_len + slack, 0);
        std::memcpy(pt0.data(), pt_ref.data(), n);
        if (aad_len) std::memcpy(aad0buf.data(), aad_ref.data(), aad_len);
        std::span<const uint8_t> aad0 = aad_len
                                            ? std::span<const uint8_t>(aad0buf.data(), aad_len)
                                            : std::span<const uint8_t>{};
        std::vector<uint8_t> ct0, oct0;
        uint8_t tag0[16] = {0}, otag0[16] = {0};
        gi.enc(ctx, IV12.data(), IV12.size(),
               std::span<const uint8_t>(pt0.data(), n), aad0, ct0, tag0, 16);
        ossl_gcm_enc(ciph, key, IV12.data(), pt0.data(), n,
                     aad_len ? aad0buf.data() : nullptr, aad_len, oct0, otag0, ctxo);
        std::snprintf(nm, sizeof(nm), "%s off=0 ct+tag == OpenSSL", base);
        check(ct0 == oct0 && std::memcmp(tag0, otag0, 16) == 0, nm);

        // ── offset 1/3/7/13 (每个 offset 独立缓冲, 不重叠) ──
        for (size_t off : g_offsets_check) {
            std::vector<uint8_t> pt_buf(n + slack, 0), ct_buf(n + slack, 0),
                                 aad_buf(aad_len + slack, 0);
            std::memcpy(pt_buf.data() + off, pt_ref.data(), n);
            if (aad_len) std::memcpy(aad_buf.data() + off, aad_ref.data(), aad_len);
            uint8_t tagbuf[48];  // 16B tag 以 tagbuf+off 写入, off<=13
            std::span<const uint8_t> apt(pt_buf.data() + off, n);
            std::span<const uint8_t> aadt = aad_len
                                                ? std::span<const uint8_t>(aad_buf.data() + off, aad_len)
                                                : std::span<const uint8_t>{};

            std::vector<uint8_t> jct, oct, p2, p3, p4, p5;
            uint8_t jtag[16] = {0}, otag[16] = {0};

            // a) jpssl 加密 vs OpenSSL 加密 (同非对齐指针) ct+tag 逐字节一致
            gi.enc(ctx, IV12.data(), IV12.size(), apt, aadt, jct, tagbuf + off, 16);
            std::memcpy(jtag, tagbuf + off, 16);
            ossl_gcm_enc(ciph, key, IV12.data(), pt_buf.data() + off, n,
                         aad_len ? aad_buf.data() + off : nullptr, aad_len, oct, otag, ctxo);
            std::snprintf(nm, sizeof(nm), "%s off=%zu ct+tag == OpenSSL", base, off);
            check(jct == oct && std::memcmp(jtag, otag, 16) == 0, nm);

            // b) jpssl 解密 OpenSSL 密文 (ct/AAD/tag 均非对齐)
            std::memcpy(ct_buf.data() + off, oct.data(), n);
            std::memcpy(tagbuf + off, otag, 16);
            bool d1 = gi.dec(ctx, IV12.data(), IV12.size(),
                             std::span<const uint8_t>(ct_buf.data() + off, n), aadt,
                             tagbuf + off, 16, p2);
            std::snprintf(nm, sizeof(nm), "%s off=%zu jpssl dec OpenSSL ct", base, off);
            check(d1 && p2 == pt_ref, nm);

            // c) OpenSSL 解密 jpssl 密文 (ct/AAD/tag 均非对齐)
            std::memcpy(ct_buf.data() + off, jct.data(), n);
            std::memcpy(tagbuf + off, jtag, 16);
            bool o1 = ossl_gcm_dec(ciph, key, IV12.data(), ct_buf.data() + off, n,
                                   aad_len ? aad_buf.data() + off : nullptr, aad_len,
                                   tagbuf + off, p3, ctxo);
            std::snprintf(nm, sizeof(nm), "%s off=%zu OpenSSL dec jpssl ct", base, off);
            check(o1 && p3 == pt_ref, nm);

            // d) 篡改 tag → jpssl 拒绝
            std::memcpy(ct_buf.data() + off, jct.data(), n);
            std::memcpy(tagbuf + off, jtag, 16);
            tagbuf[off] ^= 0x80;
            std::snprintf(nm, sizeof(nm), "%s off=%zu rejects tampered tag", base, off);
            bool d2 = gi.dec(ctx, IV12.data(), IV12.size(),
                             std::span<const uint8_t>(ct_buf.data() + off, n), aadt,
                             tagbuf + off, 16, p4);
            check(!d2, nm);

            // e) 篡改密文 → OpenSSL 拒绝
            std::memcpy(ct_buf.data() + off, jct.data(), n);
            ct_buf[off] ^= 0x40;
            std::memcpy(tagbuf + off, jtag, 16);
            std::snprintf(nm, sizeof(nm), "%s off=%zu OpenSSL rejects tampered ct", base, off);
            bool o2 = ossl_gcm_dec(ciph, key, IV12.data(), ct_buf.data() + off, n,
                                   aad_len ? aad_buf.data() + off : nullptr, aad_len,
                                   tagbuf + off, p5, ctxo);
            check(!o2, nm);

            // f) offset 指针结果 == offset=0 结果 (ct+tag 逐字节一致)
            std::snprintf(nm, sizeof(nm), "%s off=%zu result == offset0", base, off);
            check(jct == ct0 && std::memcmp(jtag, tag0, 16) == 0, nm);
        }
    }
    EVP_CIPHER_CTX_free(ctxo);
}

// ── 非对齐性能基准: 一个 (长度, offset) × 全部实现 + OpenSSL ─────
// 加密: 输入明文指针 = pt_pool+off (非对齐), 输出 tag = tagbuf+off
// 解密: 输入密文指针 = ct_pool+off (非对齐), 输入 tag = tagbuf+off
static void bench_gcm_unalign(const char* base, size_t size, size_t off,
                              const aes_context& ctx, const EVP_CIPHER* ciph, const uint8_t* key,
                              const jpssl::cpu_features& feats,
                              double target_ms, int rounds) {
    const size_t slack = 64;
    std::vector<uint8_t> pt_pool(size + slack), ct_pool(size + slack);
    fill_test(pt_pool, size + slack, 0x6C0C6C0Cu);
    uint8_t tagbuf[48];
    std::span<const uint8_t> aad{};  // 性能基准 AAD 为空 (与参考文件一致)
    std::vector<uint8_t> jct(size), jpt(size), oct(size), opt(size);

    char algo_e[80], algo_d[80];
    std::snprintf(algo_e, sizeof(algo_e), "%s-enc-unalign", base);
    std::snprintf(algo_d, sizeof(algo_d), "%s-dec-unalign", base);

    for (const auto& r : make_impls(feats)) {
        if (!r.gate) {
            record_skip(algo_e, r.impl, size, off, r.skip_why);
            record_skip(algo_d, r.impl, size, off, r.skip_why);
            continue;
        }
        // 加密
        r.enc(ctx, IV12.data(), IV12.size(),
              std::span<const uint8_t>(pt_pool.data() + off, size), aad, jct, tagbuf + off, 16);
        double nse = auto_bench([&] {
            r.enc(ctx, IV12.data(), IV12.size(),
                  std::span<const uint8_t>(pt_pool.data() + off, size), aad, jct, tagbuf + off, 16);
            g_sink ^= jct[0] ^ tagbuf[off];
        }, target_ms, rounds);
        record(algo_e, r.impl, size, off, nse);

        // 解密 (输入密文非对齐; 密文与 tag 提前就位, tag 已由 enc 写入 tagbuf+off)
        std::memcpy(ct_pool.data() + off, jct.data(), size);
        double nsd = auto_bench([&] {
            bool ok2 = r.dec(ctx, IV12.data(), IV12.size(),
                             std::span<const uint8_t>(ct_pool.data() + off, size), aad,
                             tagbuf + off, 16, jpt);
            g_sink ^= (int)ok2 ^ jpt[0];
        }, target_ms, rounds);
        record(algo_d, r.impl, size, off, nsd);
    }

    // OpenSSL 对照 (输入指针同样非对齐)
    EVP_CIPHER_CTX* c_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* c_dec = EVP_CIPHER_CTX_new();
    uint8_t otag[16] = {0};
    ossl_gcm_enc(ciph, key, IV12.data(), pt_pool.data() + off, size, nullptr, 0,
                 oct, tagbuf + off, c_enc);
    std::memcpy(otag, tagbuf + off, 16);
    double nse = auto_bench([&] {
        ossl_gcm_enc(ciph, key, IV12.data(), pt_pool.data() + off, size, nullptr, 0,
                     oct, tagbuf + off, c_enc);
        g_sink ^= oct[0] ^ tagbuf[off];
    }, target_ms, rounds);
    record(algo_e, "openssl", size, off, nse);

    std::memcpy(ct_pool.data() + off, oct.data(), size);
    std::memcpy(tagbuf + off, otag, 16);
    double nsd = auto_bench([&] {
        bool ok2 = ossl_gcm_dec(ciph, key, IV12.data(), ct_pool.data() + off, size,
                                nullptr, 0, tagbuf + off, opt, c_dec);
        g_sink ^= (int)ok2 ^ opt[0];
    }, target_ms, rounds);
    record(algo_d, "openssl", size, off, nsd);
    EVP_CIPHER_CTX_free(c_enc);
    EVP_CIPHER_CTX_free(c_dec);
}

// ── main ────────────────────────────────────────────────────────
int main() {
    const bool smoke = std::getenv("BENCH_SMOKE") != nullptr;
    const std::vector<size_t> sizes = smoke ? g_sizes_smoke : g_sizes_full;
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;

    auto feats = jpssl::cpu_features::detect();
    printf("=== bench_aes_gcm_unalign: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("mode=%s sizes=%zu offsets_bench=%zu target_ms=%.0f rounds=%d\n",
           smoke ? "SMOKE" : "FULL", sizes.size(), g_offsets_bench.size(), target_ms, rounds);
    printf("CPU features: AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES+VPCLMULQDQ=%d SHA-NI=%d\n",
           (int)feats.aesni, (int)feats.avx2, (int)feats.pclmulqdq,
           (int)feats.avx512, (int)feats.vpclmulqdq_vaes, (int)feats.sha_ni);
    if (!feats.avx512)
        printf("  NOTE: AVX512 unavailable on this host — jpssl-avx512 will SKIP (never called)\n");

    // 确保 OpenSSL 库初始化
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    aes_context ctx128;
    ctx128.init(K16);

    // ── 自检 (先于基准, 始终全长度 × offset 1/3/7/13, AAD 空 + 17B) ──
    printf("\n=== Correctness self-checks (AES-128-GCM unaligned, tag 16B, "
           "AAD empty + AAD 17B) ===\n");
    for (size_t n : g_sizes_full) {
        validate_unalign(ctx128, EVP_aes_128_gcm(), K16.data(), n, 0, feats);
        validate_unalign(ctx128, EVP_aes_128_gcm(), K16.data(), n, 17, feats);
    }

    if (!g_all_pass) {
        printf("\nSelf-checks FAILED (%d checks, some FAIL). Aborting before benchmark.\n", g_checks);
        return 1;
    }
    printf("Self-checks: %d checks, all PASS.\n", g_checks);

    // ── 性能基准 ────────────────────────────────────────────────
    printf("\n=== Benchmark (ns/op, MB/s) ===\n");
    for (size_t n : sizes)
        for (size_t off : g_offsets_bench)
            bench_gcm_unalign("aes-128-gcm", n, off, ctx128, EVP_aes_128_gcm(),
                              K16.data(), feats, target_ms, rounds);

    // ── 写 CSV (SKIP 的实现不入 CSV) ────────────────────────────
    std::filesystem::path csv_dir = std::filesystem::path("benchmarks") / "results";
    std::error_code ec;
    std::filesystem::create_directories(csv_dir, ec);
    std::string csv_path = (csv_dir / "bench_aes_gcm_unalign.csv").string();
    {
        std::ofstream f(csv_path);
        f << "algo,impl,size_bytes,offset_bytes,ns_per_op,throughput_mbps\n";
        for (const auto& r : g_rows) {
            f << r.algo << ',' << r.impl << ',' << r.size << ','
              << r.offset << ',' << r.ns << ',' << r.mbps << '\n';
        }
    }
    printf("\nCSV written to %s (%zu data rows)\n", csv_path.c_str(), g_rows.size());
    printf("Done. All self-checks passed, exit 0.\n");
    (void)g_sink;
    return 0;
}
