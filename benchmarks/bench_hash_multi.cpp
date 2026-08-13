// bench_hash_multi.cpp — 哈希/HMAC/HKDF 多长度 × 多实现 × OpenSSL 对比微基准
//
// 覆盖矩阵 (消息长度: 16 / 256 / 4096 / 65536 / 1048576 字节):
//   SHA-1      : jpssl scalar (sha1_init/update/final)
//                jpssl sha1_multi_avx2 (8 条等长消息批量, cpu_has_avx2 守卫)
//                OpenSSL EVP_sha1
//   SHA-256    : jpssl scalar / jpssl sha256_sha_ni (cpu_has_sha_ni 守卫) / OpenSSL EVP_sha256
//   SHA-512    : jpssl scalar / jpssl opt(SSE4.1) / OpenSSL EVP_sha512
//                scalar 与 opt 通过替换 jpssl::sha512_transform_ptr 切换
//                (注意: 该库构建时 JP_AVX2=ON, sha512_opt.cpp 的静态初始化
//                 默认把指针指向 opt; 因此"scalar"用例须显式换回 cpu 指针)
//   SHA3-256/384/512 : jpssl sha3.hpp / OpenSSL EVP_sha3_*
//   HMAC-SHA256/512  : jpssl hmac.hpp / OpenSSL HMAC()   (固定 32B 密钥)
//   HKDF-SHA256/512  : jpssl hkdf.hpp / OpenSSL EVP_KDF("HKDF")  (IKM 长度即矩阵长度)
//
// API 适配说明:
//   - hmac.hpp / hkdf.hpp 只提供 SHA-256 与 SHA-384 变体, 没有 SHA-512 变体;
//     HMAC-SHA512 与 HKDF-SHA512 依据 RFC 2104 / RFC 5869 在本文件内用
//     include/sha512.hpp 的 init/update/final 原语实现, 正确性用 OpenSSL 交叉验证。
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -Iinclude -Isrc benchmarks/bench_hash_multi.cpp \
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto -o /tmp/bench_hash_multi
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_hash_multi.csv
//   CSV 列: algo,impl,size_bytes,ns_per_op,throughput_mbps
//   (sha1 avx2-batch 一行吞吐量按 8×size_bytes 字节计算, ns_per_op 为整批 8 条消息的时间)
//
// 正确性: 每个算法/长度对 jpssl(含各变体) 与 OpenSSL 摘要/MAC/KDF 输出逐字节比对,
//   打印 PASS/FAIL; 任一 FAIL 立即非零退出, 全部 PASS 才进行基准并写 CSV。

#include "sha1.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "sha3.hpp"
#include "hmac.hpp"
#include "hkdf.hpp"
#include "cpu_features.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/opensslv.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// 库内符号 (sha512_cpu.cpp / sha512_opt.cpp), 用于切换 SHA-512 实现路径
namespace jpssl {
extern void (*sha512_transform_ptr)(uint64_t[8], const uint8_t[128]);
extern void sha512_transform_cpu(uint64_t[8], const uint8_t[128]);
extern void sha512_transform_opt(uint64_t[8], const uint8_t[128]);
} // namespace jpssl

using Clock = std::chrono::steady_clock;

static volatile uint8_t g_sink = 0;  // 阻止编译器把纯计算优化掉

// ── 自适应迭代微基准: 每轮跑约 target_ms, rounds 轮取最小值 ──
template <typename F>
static double auto_bench(F&& f, double target_ms = 200.0, int rounds = 3) {
    f();  // 预热
    int est_n = 8;
    auto t0 = Clock::now();
    for (int i = 0; i < est_n; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / est_n;
    if (est_ns < 1000.0) {  // 太快, 加大估计样本
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

// ── 结果收集 ──
struct Row {
    std::string algo;
    std::string impl;
    size_t size;
    double ns;
    double bytes_per_op;
};
static std::vector<Row> g_rows;

template <typename F>
static void bench_case(const char* algo, const char* impl, size_t size,
                       double bytes_per_op, F&& f) {
    double ns = auto_bench(std::forward<F>(f));
    g_rows.push_back({algo, impl, size, ns, bytes_per_op});
    std::printf("%-13s %-18s %10zu %12.0f %12.1f\n",
                algo, impl, size, ns, bytes_per_op * 1000.0 / ns);
}

static std::string to_hex(const uint8_t* d, size_t n) {
    static const char* hexd = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s += hexd[d[i] >> 4];
        s += hexd[d[i] & 0xf];
    }
    return s;
}

// ── 数据 ──
static constexpr size_t kMax = 1048576 + 128;
static uint8_t g_data[kMax];
static uint8_t g_batch[8][kMax];

static void fill_deterministic(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        p[i] = (uint8_t)(x >> 24);
    }
}

static constexpr size_t kSizes[] = {16, 256, 4096, 65536, 1048576};

// ── jpssl 哈希封装 (streaming, 与 OpenSSL streaming 对齐) ──
static void jp_sha1(const uint8_t* d, size_t n, uint8_t out[20]) {
    jpssl::sha1_ctx c; jpssl::sha1_init(&c);
    if (n) jpssl::sha1_update(&c, d, n);
    jpssl::sha1_final(&c, out);
}
static void jp_sha256(const uint8_t* d, size_t n, uint8_t out[32]) {
    jpssl::sha256_ctx c; jpssl::sha256_init(&c);
    if (n) jpssl::sha256_update(&c, d, n);
    jpssl::sha256_final(&c, out);
}
static void jp_sha512(const uint8_t* d, size_t n, uint8_t out[64]) {
    jpssl::sha512_ctx c; jpssl::sha512_init(&c);
    if (n) jpssl::sha512_update(&c, d, n);
    jpssl::sha512_final(&c, out);
}
static void jp_sha3(const uint8_t* d, size_t n, uint8_t out[64], int bits) {
    jpssl::sha3_ctx c;
    if (bits == 256) jpssl::sha3_256_init(&c);
    else if (bits == 384) jpssl::sha3_384_init(&c);
    else jpssl::sha3_512_init(&c);
    if (n) jpssl::sha3_update(&c, d, n);
    jpssl::sha3_final(&c, out);
}

// ── OpenSSL 哈希 (复用 ctx, 每次 op 重新 Init) ──
struct OsslDigest {
    const EVP_MD* md;
    EVP_MD_CTX* ctx;
    uint8_t out[64];
    unsigned int out_len = 0;
    explicit OsslDigest(const EVP_MD* m) : md(m), ctx(EVP_MD_CTX_new()) {}
    ~OsslDigest() { EVP_MD_CTX_free(ctx); }
    void op(const uint8_t* data, size_t len) {
        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, data, len);
        EVP_DigestFinal_ex(ctx, out, &out_len);
    }
};

// ── HMAC ──
static void jp_hmac_sha256(const uint8_t* key, const uint8_t* msg, size_t n, uint8_t mac[32]) {
    jpssl::hmac_sha256(key, 32, msg, n, mac);
}
static void ossl_hmac(const EVP_MD* md, const uint8_t* key, const uint8_t* msg, size_t n, uint8_t* mac, size_t mac_len) {
    unsigned int l = 0;
    HMAC(md, key, 32, msg, n, mac, &l);
    if (l != mac_len) std::memset(mac, 0, mac_len);
}

// HMAC-SHA512 (RFC 2104, 用 jpssl sha512 原语实现; 库内无 hmac_sha512)
static void hmac_sha512_local(const uint8_t* key, size_t key_len,
                              const uint8_t* msg, size_t msg_len, uint8_t mac[64]) {
    uint8_t ikey[128], okey[128], tk[64];
    jpssl::sha512_ctx ctx;
    if (key_len > 128) {
        jpssl::sha512_init(&ctx);
        jpssl::sha512_update(&ctx, key, key_len);
        jpssl::sha512_final(&ctx, tk);
        key = tk; key_len = 64;
    }
    std::memset(ikey, 0, 128); std::memset(okey, 0, 128);
    std::memcpy(ikey, key, key_len); std::memcpy(okey, key, key_len);
    for (int i = 0; i < 128; ++i) { ikey[i] ^= 0x36; okey[i] ^= 0x5c; }
    jpssl::sha512_init(&ctx);
    jpssl::sha512_update(&ctx, ikey, 128);
    jpssl::sha512_update(&ctx, msg, msg_len);
    jpssl::sha512_final(&ctx, tk);
    jpssl::sha512_init(&ctx);
    jpssl::sha512_update(&ctx, okey, 128);
    jpssl::sha512_update(&ctx, tk, 64);
    jpssl::sha512_final(&ctx, mac);
}

// ── HKDF ──
static void jp_hkdf_sha256(const uint8_t* salt, size_t salt_len,
                           const uint8_t* ikm, size_t ikm_len,
                           const uint8_t* info, size_t info_len,
                           uint8_t* out, size_t out_len) {
    uint8_t prk[32];
    jpssl::hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    jpssl::hkdf_expand(prk, info, info_len, out, out_len);
}

// HKDF-SHA512 (RFC 5869, 用上面的 HMAC-SHA512; 库内无 hkdf_sha512)
static void jp_hkdf_sha512(const uint8_t* salt, size_t salt_len,
                           const uint8_t* ikm, size_t ikm_len,
                           const uint8_t* info, size_t info_len,
                           uint8_t* out, size_t out_len) {
    uint8_t prk[64];
    if (!salt || salt_len == 0) {
        uint8_t z[64] = {};
        hmac_sha512_local(z, 64, ikm, ikm_len, prk);
    } else {
        hmac_sha512_local(salt, salt_len, ikm, ikm_len, prk);
    }
    uint8_t t[64];
    size_t t_len = 0;
    uint8_t counter = 1;
    uint8_t hmac_in[64 + 32 + 1];  // Tprev(≤64) || info(≤32) || counter
    while (out_len > 0) {
        size_t p = 0;
        if (t_len) { std::memcpy(hmac_in + p, t, t_len); p += t_len; }
        std::memcpy(hmac_in + p, info, info_len); p += info_len;
        hmac_in[p++] = counter;
        hmac_sha512_local(prk, 64, hmac_in, p, t);
        size_t n = (out_len < 64) ? out_len : 64;
        std::memcpy(out, t, n); out += n; out_len -= n;
        t_len = 64; ++counter;
    }
}

// OpenSSL EVP_KDF("HKDF") 封装
struct OsslKdf {
    EVP_KDF* kdf = nullptr;
    EVP_KDF_CTX* kctx = nullptr;
    const char* digest = nullptr;
    const uint8_t* salt = nullptr; size_t salt_len = 0;
    const uint8_t* info = nullptr; size_t info_len = 0;
    bool ok = false;
    explicit OsslKdf(const char* d) : digest(d) {
        kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
        if (kdf) kctx = EVP_KDF_CTX_new(kdf);
        ok = (kctx != nullptr);
    }
    ~OsslKdf() {
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
    }
    bool derive(const uint8_t* ikm, size_t ikm_len, uint8_t* out, size_t out_len) {
        OSSL_PARAM params[5];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest), 0);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(ikm), ikm_len);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt), salt_len);
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info), info_len);
        params[4] = OSSL_PARAM_construct_end();
        return EVP_KDF_derive(kctx, out, out_len, params) == 1;
    }
};

int main() {
    std::printf("=== jpssl hash/HMAC/HKDF vs OpenSSL 微基准 ===\n");
    std::printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    std::printf("CPU features   : AES-NI=%d AVX2=%d PCLMULQDQ=%d VAES=%d SHA-NI=%d ADX=%d AVX512=%d NEON=%d\n",
                (int)jpssl::cpu_has_aesni(), (int)jpssl::cpu_has_avx2(),
                (int)jpssl::cpu_has_pclmulqdq(), (int)jpssl::cpu_has_vpclmulqdq_vaes(),
                (int)jpssl::cpu_has_sha_ni(), (int)jpssl::cpu_has_adx(),
                (int)jpssl::cpu_has_avx512(), (int)jpssl::cpu_has_neon());

    // ── 数据准备 (确定性内容) ──
    fill_deterministic(g_data, kMax, 0x12345678u);
    for (int i = 0; i < 8; ++i) fill_deterministic(g_batch[i], kMax, 0x1000 + (uint32_t)i);

    uint8_t key32[32], salt[32], info[16];
    for (int i = 0; i < 32; ++i) key32[i] = (uint8_t)(0x01 + i);
    for (int i = 0; i < 32; ++i) salt[i]  = (uint8_t)(0x40 + i);
    for (int i = 0; i < 16; ++i) info[i]  = (uint8_t)(0x80 + i);

    // ── 正确性自检 (jpssl vs OpenSSL) ──
    std::printf("\n--- 正确性自检 (jpssl 各实现 vs OpenSSL) ---\n");
    bool all_pass = true;
    auto check = [&](const char* what, const std::string& got, const std::string& want) {
        bool ok = (got == want);
        all_pass = all_pass && ok;
        std::printf("  check %-38s : %s\n", what, ok ? "PASS" : "FAIL");
        if (!ok) {
            std::printf("        jpssl = %s\n", got.c_str());
            std::printf("        openssl = %s\n", want.c_str());
        }
    };

    OsslDigest od_sha1(EVP_sha1()), od_sha256(EVP_sha256()), od_sha512(EVP_sha512());
    OsslDigest od_sha3_256(EVP_sha3_256()), od_sha3_384(EVP_sha3_384()), od_sha3_512(EVP_sha3_512());

    const bool has_avx2 = jpssl::cpu_has_avx2();
    const bool has_sha_ni = jpssl::cpu_has_sha_ni();

    for (size_t s : kSizes) {
        char tag[64];
        // SHA-1
        {
            uint8_t a[20];
            jp_sha1(g_data, s, a); od_sha1.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha1 scalar  len=%zu", s);
            check(tag, to_hex(a, 20), to_hex(od_sha1.out, od_sha1.out_len));
        }
        if (has_avx2) {
            const uint8_t* m[8];
            for (int i = 0; i < 8; ++i) m[i] = g_batch[i];
            uint8_t out8[8][20];
            jpssl::sha1_multi_avx2(m, s, out8);
            std::string jh, oh;
            for (int i = 0; i < 8; ++i) {
                od_sha1.op(g_batch[i], s);
                jh += to_hex(out8[i], 20);
                oh += to_hex(od_sha1.out, od_sha1.out_len);
            }
            std::snprintf(tag, sizeof(tag), "sha1 avx2-batch x8 len=%zu", s);
            check(tag, jh, oh);
        }
        // SHA-256
        {
            uint8_t a[32];
            jp_sha256(g_data, s, a); od_sha256.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha256 scalar  len=%zu", s);
            check(tag, to_hex(a, 32), to_hex(od_sha256.out, 32));
        }
        if (has_sha_ni) {
            uint8_t a[32];
            jpssl::sha256_sha_ni(a, g_data, s); od_sha256.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha256 sha_ni  len=%zu", s);
            check(tag, to_hex(a, 32), to_hex(od_sha256.out, 32));
        }
        // SHA-512 scalar / opt
        {
            uint8_t a[64];
            jpssl::sha512_transform_ptr = jpssl::sha512_transform_cpu;
            jp_sha512(g_data, s, a); od_sha512.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha512 scalar  len=%zu", s);
            check(tag, to_hex(a, 64), to_hex(od_sha512.out, 64));
            jpssl::sha512_transform_ptr = jpssl::sha512_transform_opt;
            jp_sha512(g_data, s, a); od_sha512.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha512 opt     len=%zu", s);
            check(tag, to_hex(a, 64), to_hex(od_sha512.out, 64));
        }
        // SHA3
        {
            uint8_t a[64];
            jp_sha3(g_data, s, a, 256); od_sha3_256.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha3-256       len=%zu", s);
            check(tag, to_hex(a, 32), to_hex(od_sha3_256.out, 32));
            jp_sha3(g_data, s, a, 384); od_sha3_384.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha3-384       len=%zu", s);
            check(tag, to_hex(a, 48), to_hex(od_sha3_384.out, 48));
            jp_sha3(g_data, s, a, 512); od_sha3_512.op(g_data, s);
            std::snprintf(tag, sizeof(tag), "sha3-512       len=%zu", s);
            check(tag, to_hex(a, 64), to_hex(od_sha3_512.out, 64));
        }
        // HMAC
        {
            uint8_t m1[32], m2[32];
            jp_hmac_sha256(key32, g_data, s, m1);
            ossl_hmac(EVP_sha256(), key32, g_data, s, m2, 32);
            std::snprintf(tag, sizeof(tag), "hmac-sha256    len=%zu", s);
            check(tag, to_hex(m1, 32), to_hex(m2, 32));
        }
        {
            uint8_t m1[64], m2[64];
            hmac_sha512_local(key32, 32, g_data, s, m1);
            ossl_hmac(EVP_sha512(), key32, g_data, s, m2, 64);
            std::snprintf(tag, sizeof(tag), "hmac-sha512    len=%zu", s);
            check(tag, to_hex(m1, 64), to_hex(m2, 64));
        }
        // HKDF
        {
            uint8_t o1[32], o2[32];
            jp_hkdf_sha256(salt, 32, g_data, s, info, 16, o1, 32);
            OsslKdf kd("SHA256");
            kd.salt = salt; kd.salt_len = 32; kd.info = info; kd.info_len = 16;
            if (!kd.ok || !kd.derive(g_data, s, o2, 32)) { check("hkdf-sha256 (ossl kdf)", "kdf-error", "ok"); }
            else {
                std::snprintf(tag, sizeof(tag), "hkdf-sha256    len=%zu", s);
                check(tag, to_hex(o1, 32), to_hex(o2, 32));
            }
        }
        {
            uint8_t o1[32], o2[32];
            jp_hkdf_sha512(salt, 32, g_data, s, info, 16, o1, 32);
            OsslKdf kd("SHA512");
            kd.salt = salt; kd.salt_len = 32; kd.info = info; kd.info_len = 16;
            if (!kd.ok || !kd.derive(g_data, s, o2, 32)) { check("hkdf-sha512 (ossl kdf)", "kdf-error", "ok"); }
            else {
                std::snprintf(tag, sizeof(tag), "hkdf-sha512    len=%zu", s);
                check(tag, to_hex(o1, 32), to_hex(o2, 32));
            }
        }
    }

    if (!all_pass) {
        std::printf("\n正确性自检存在 FAIL, 放弃基准并退出(1)\n");
        return 1;
    }
    std::printf("\n正确性自检: 全部 PASS\n");

    // ── 基准 ──
    std::printf("\n--- 基准 (每轮约 200ms, 3 轮取最小值) ---\n");
    std::printf("%-13s %-18s %10s %12s %12s\n", "algo", "impl", "size_bytes", "ns/op", "MB/s");

    // SHA-1
    for (size_t s : kSizes) {
        uint8_t out[20];
        bench_case("sha1", "jpssl-scalar", s, (double)s,
                   [&] { jp_sha1(g_data, s, out); g_sink ^= out[0]; });
        if (has_avx2) {
            const uint8_t* m[8];
            for (int i = 0; i < 8; ++i) m[i] = g_batch[i];
            uint8_t out8[8][20];
            bench_case("sha1", "jpssl-avx2-batch", s, 8.0 * (double)s,
                       [&] { jpssl::sha1_multi_avx2(m, s, out8); g_sink ^= out8[0][0]; });
        } else {
            std::printf("SKIP sha1 jpssl-avx2-batch (cpu_has_avx2()=false)\n");
        }
        bench_case("sha1", "openssl", s, (double)s,
                   [&] { od_sha1.op(g_data, s); g_sink ^= od_sha1.out[0]; });
    }

    // SHA-256
    for (size_t s : kSizes) {
        uint8_t out[32];
        bench_case("sha256", "jpssl-scalar", s, (double)s,
                   [&] { jp_sha256(g_data, s, out); g_sink ^= out[0]; });
        if (has_sha_ni) {
            bench_case("sha256", "jpssl-sha_ni", s, (double)s,
                       [&] { jpssl::sha256_sha_ni(out, g_data, s); g_sink ^= out[0]; });
        } else {
            std::printf("SKIP sha256 jpssl-sha_ni (cpu_has_sha_ni()=false)\n");
        }
        bench_case("sha256", "openssl", s, (double)s,
                   [&] { od_sha256.op(g_data, s); g_sink ^= od_sha256.out[0]; });
    }

    // SHA-512 (scalar = 显式换 cpu 指针; opt = 默认 SSE4.1 指针)
    for (size_t s : kSizes) {
        uint8_t out[64];
        jpssl::sha512_transform_ptr = jpssl::sha512_transform_cpu;
        bench_case("sha512", "jpssl-scalar", s, (double)s,
                   [&] { jp_sha512(g_data, s, out); g_sink ^= out[0]; });
        jpssl::sha512_transform_ptr = jpssl::sha512_transform_opt;
        bench_case("sha512", "jpssl-opt", s, (double)s,
                   [&] { jp_sha512(g_data, s, out); g_sink ^= out[0]; });
        bench_case("sha512", "openssl", s, (double)s,
                   [&] { od_sha512.op(g_data, s); g_sink ^= od_sha512.out[0]; });
    }
    jpssl::sha512_transform_ptr = jpssl::sha512_transform_opt;  // 恢复默认

    // SHA3
    for (size_t s : kSizes) {
        uint8_t out[64];
        bench_case("sha3-256", "jpssl-scalar", s, (double)s,
                   [&] { jp_sha3(g_data, s, out, 256); g_sink ^= out[0]; });
        bench_case("sha3-256", "openssl", s, (double)s,
                   [&] { od_sha3_256.op(g_data, s); g_sink ^= od_sha3_256.out[0]; });
        bench_case("sha3-384", "jpssl-scalar", s, (double)s,
                   [&] { jp_sha3(g_data, s, out, 384); g_sink ^= out[0]; });
        bench_case("sha3-384", "openssl", s, (double)s,
                   [&] { od_sha3_384.op(g_data, s); g_sink ^= od_sha3_384.out[0]; });
        bench_case("sha3-512", "jpssl-scalar", s, (double)s,
                   [&] { jp_sha3(g_data, s, out, 512); g_sink ^= out[0]; });
        bench_case("sha3-512", "openssl", s, (double)s,
                   [&] { od_sha3_512.op(g_data, s); g_sink ^= od_sha3_512.out[0]; });
    }

    // HMAC (固定 32B 密钥)
    for (size_t s : kSizes) {
        uint8_t m1[32], m2[64];
        bench_case("hmac-sha256", "jpssl-scalar", s, (double)s,
                   [&] { jp_hmac_sha256(key32, g_data, s, m1); g_sink ^= m1[0]; });
        bench_case("hmac-sha256", "openssl", s, (double)s,
                   [&] { ossl_hmac(EVP_sha256(), key32, g_data, s, m2, 32); g_sink ^= m2[0]; });
        bench_case("hmac-sha512", "jpssl-scalar", s, (double)s,
                   [&] { hmac_sha512_local(key32, 32, g_data, s, m2); g_sink ^= m2[0]; });
        bench_case("hmac-sha512", "openssl", s, (double)s,
                   [&] { ossl_hmac(EVP_sha512(), key32, g_data, s, m2, 64); g_sink ^= m2[0]; });
    }

    // HKDF (固定 32B salt / 16B info, OKM=32B, IKM 长度=矩阵长度)
    OsslKdf kd256("SHA256"), kd512("SHA512");
    kd256.salt = salt; kd256.salt_len = 32; kd256.info = info; kd256.info_len = 16;
    kd512.salt = salt; kd512.salt_len = 32; kd512.info = info; kd512.info_len = 16;
    if (!kd256.ok || !kd512.ok) std::printf("WARN: OpenSSL EVP_KDF 初始化失败 (kd256.ok=%d kd512.ok=%d)\n",
                                            (int)kd256.ok, (int)kd512.ok);
    for (size_t s : kSizes) {
        uint8_t o1[32], o2[32];
        bench_case("hkdf-sha256", "jpssl-scalar", s, (double)s,
                   [&] { jp_hkdf_sha256(salt, 32, g_data, s, info, 16, o1, 32); g_sink ^= o1[0]; });
        bench_case("hkdf-sha256", "openssl", s, (double)s,
                   [&] { kd256.derive(g_data, s, o2, 32); g_sink ^= o2[0]; });
        bench_case("hkdf-sha512", "jpssl-scalar", s, (double)s,
                   [&] { jp_hkdf_sha512(salt, 32, g_data, s, info, 16, o1, 32); g_sink ^= o1[0]; });
        bench_case("hkdf-sha512", "openssl", s, (double)s,
                   [&] { kd512.derive(g_data, s, o2, 32); g_sink ^= o2[0]; });
    }

    // ── 64KB 长度汇总 ──
    const char* algos[] = {"sha1", "sha256", "sha512", "sha3-256", "sha3-384",
                           "sha3-512", "hmac-sha256", "hmac-sha512", "hkdf-sha256", "hkdf-sha512"};
    std::printf("\n--- 64KB 长度对比 (ratio = openssl / jpssl-best, >1 表示 jpssl 快) ---\n");
    for (const char* a : algos) {
        double jp_best = 1e300;
        double os_ns = 0.0;
        std::string jp_impl;
        for (const Row& r : g_rows) {
            if (r.algo != a || r.size != 65536) continue;
            if (r.impl == "openssl") os_ns = r.ns;
            else if (r.ns < jp_best) { jp_best = r.ns; jp_impl = r.impl; }
        }
        std::printf("%-12s jpssl-best(%s) %10.0f ns/op   openssl %10.0f ns/op   ratio %.2fx\n",
                    a, jp_impl.c_str(), jp_best, os_ns,
                    (os_ns > 0.0 && jp_best < 1e299) ? os_ns / jp_best : 0.0);
    }

    // ── 写 CSV ──
    std::system("mkdir -p benchmarks/results");
    std::FILE* fp = std::fopen("benchmarks/results/bench_hash_multi.csv", "w");
    if (!fp) {
        std::printf("ERROR: 无法写 CSV 文件\n");
        return 1;
    }
    std::fprintf(fp, "algo,impl,size_bytes,ns_per_op,throughput_mbps\n");
    for (const Row& r : g_rows) {
        double mbps = r.bytes_per_op * 1000.0 / r.ns;
        std::fprintf(fp, "%s,%s,%zu,%.1f,%.3f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.ns, mbps);
    }
    std::fclose(fp);
    std::printf("\nCSV 已写入 benchmarks/results/bench_hash_multi.csv (%zu 行)\n", g_rows.size());
    return 0;
}
