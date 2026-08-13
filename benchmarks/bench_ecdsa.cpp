// bench_ecdsa.cpp — ECDSA 全量测试: keygen / sign / verify × 多消息长度 × OpenSSL 对比
//
// 覆盖矩阵:
//   ECDSA P-256 (SHA-256) / P-384 (SHA-384):
//     keygen            (与消息无关, size_bytes=0)
//     sign / verify     消息长度 32 / 256 / 1024 / 65536 字节
//   实现路径: jpssl (ecdsa_p256_* / ecdsa_p384_*), openssl (EC_KEY + ECDSA_do_sign,
//             签名统一转为固定 r||s 格式, 64B / 96B)
//
// 正确性自检 (始终执行, 消息 32B):
//   jpssl 签 → OpenSSL 验  (jpssl 私钥推导 OpenSSL EC_KEY)
//   OpenSSL 签 → jpssl 验  (OpenSSL 用 jpssl 私钥签名)
//   jpssl 自环 (jpssl 签 → jpssl 验)
//   篡改拒绝 (消息翻转 1 字节, 两实现均须验签失败)
//   任一 FAIL 非零退出且不输出 CSV。
//
// 全量 vs smoke (环境变量 BENCH_SMOKE=1):
//   默认:    4 档消息长度, 每档每操作约 150ms, 3 轮取最小
//   smoke:   仅 32B 一档,    每档每操作约  80ms, 1 轮
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_ecdsa.csv
//   CSV 列头: algo,impl,size_bytes,ns_per_op,ops_per_sec
//
// 编译 (worktree 根, 单行):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc
//   benchmarks/bench_ecdsa.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto
//   -o /tmp/bench_ecdsa
// 运行:
//   BENCH_SMOKE=1 /tmp/bench_ecdsa   # smoke 自检 + 32B 一档
//   /tmp/bench_ecdsa                 # 全量 4 档

#include "ecdsa.hpp"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

static volatile int g_sink = 0;
static int g_fail = 0;
static int g_pass = 0;

// ─────────────────────────────────────────────────────────────────────
// 全量 / smoke 开关 (BENCH_SMOKE=1 → 仅 32B 一档, ~80ms, 1 轮)
// ─────────────────────────────────────────────────────────────────────
static bool g_smoke = false;
static double g_target_ms = 150.0;   // 每档每操作目标时长
static int g_rounds = 3;             // 轮数, 取最小

// ─────────────────────────────────────────────────────────────────────
// CSV 行记录
// ─────────────────────────────────────────────────────────────────────
struct Row {
    std::string algo, impl;
    size_t size;
    double ns;
};
static std::vector<Row> g_rows;

static void emit_row(const char* algo, const char* impl, size_t size, double ns) {
    g_rows.push_back({algo, impl, size, ns});
    printf("  %-22s %-18s %6zu %13.1f ns/op %12.2f ops/s\n",
           algo, impl, size, ns, 1e9 / ns);
}

// ─────────────────────────────────────────────────────────────────────
// 自适应迭代微基准: 每轮约 g_target_ms, g_rounds 轮取最小值
// est_n: 首次耗时估计的调用次数 (keygen 等慢操作传 1)
// ─────────────────────────────────────────────────────────────────────
template <typename F>
static double auto_bench(const char* name, F&& f, int est_n = 8) {
    f(); // 预热
    auto t0 = Clock::now();
    for (int i = 0; i < est_n; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / est_n;
    if (est_ns < 1000.0) {  // 太快, 重新用更多次估计
        const int est_n2 = 2000;
        t0 = Clock::now();
        for (int i = 0; i < est_n2; ++i) f();
        t1 = Clock::now();
        est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / est_n2;
    }
    long long iters = 1;
    if (est_ns > 0.0) {
        iters = static_cast<long long>(g_target_ms * 1e6 / est_ns);
        if (iters < 1) iters = 1;
        if (iters > 2000000) iters = 2000000;
    }

    double best = 1e300;
    for (int r = 0; r < g_rounds; ++r) {
        auto s = Clock::now();
        for (long long i = 0; i < iters; ++i) f();
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / iters;
        if (ns < best) best = ns;
    }
    printf("  %-22s %-18s %6s %13.1f ns/op %12.2f ops/s   (iters=%lld)\n",
           name, "", "", best, 1e9 / best, iters);
    return best;
}

// ═════════════════════════════════════════════════════════════════════
//  OpenSSL 侧辅助 (固定 r||s 转换, 结构取自 bench_sig_multi.cpp 已验证实现)
// ═════════════════════════════════════════════════════════════════════

// OpenSSL ECDSA: 从私钥派生 EC_KEY 并签 SHA-256/SHA-384 摘要, 输出固定 r||s
// rs_len 为 r||s 总长 (P-256: 64, P-384: 96) —— 注意勿传 rs_len/2
static bool ossl_ecdsa_sign_rs(int nid, const uint8_t* priv, int key_len,
                               const EVP_MD* md, int rs_len,
                               const uint8_t* msg, size_t msg_len, uint8_t* rs) {
    BIGNUM* d = BN_bin2bn(priv, key_len, nullptr);
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(nid);
    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, grp);
    EC_KEY_set_private_key(key, d);
    EC_POINT* Q = EC_POINT_new(grp);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_mul(grp, Q, d, nullptr, nullptr, ctx);
    EC_KEY_set_public_key(key, Q);

    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, md, nullptr);
    EVP_DigestUpdate(mctx, msg, msg_len);
    EVP_DigestFinal_ex(mctx, digest, &dlen);
    ECDSA_SIG* sig = ECDSA_do_sign(digest, dlen, key);

    const BIGNUM *r = nullptr, *s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    int rl = BN_num_bytes(r), sl = BN_num_bytes(s);
    memset(rs, 0, (size_t)rs_len);
    BN_bn2bin(r, rs + (rs_len / 2 - rl));
    BN_bn2bin(s, rs + rs_len - sl);

    ECDSA_SIG_free(sig);
    EVP_MD_CTX_free(mctx);
    BN_CTX_free(ctx);
    EC_POINT_free(Q);
    EC_KEY_free(key);
    EC_GROUP_free(grp);
    BN_free(d);
    return true;
}

// OpenSSL ECDSA 验签 (固定 r||s), rs_len 为 r||s 总长
static bool ossl_ecdsa_verify_rs(int nid, const uint8_t* pub, int pub_len,
                                 const EVP_MD* md, int rs_len,
                                 const uint8_t* msg, size_t msg_len, const uint8_t* rs) {
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(nid);
    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, grp);
    BIGNUM* x = BN_bin2bn(pub, pub_len / 2, nullptr);
    BIGNUM* y = BN_bin2bn(pub + pub_len / 2, pub_len / 2, nullptr);
    EC_POINT* Q = EC_POINT_new(grp);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_set_affine_coordinates(grp, Q, x, y, ctx);
    EC_KEY_set_public_key(key, Q);

    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, md, nullptr);
    EVP_DigestUpdate(mctx, msg, msg_len);
    EVP_DigestFinal_ex(mctx, digest, &dlen);
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(rs, (int)(rs_len / 2), nullptr);
    BIGNUM* s = BN_bin2bn(rs + rs_len / 2, (int)(rs_len / 2), nullptr);
    ECDSA_SIG_set0(sig, r, s);
    int ok = ECDSA_do_verify(digest, dlen, sig, key);

    ECDSA_SIG_free(sig);
    EVP_MD_CTX_free(mctx);
    BN_CTX_free(ctx);
    EC_POINT_free(Q);
    EC_KEY_free(key);
    EC_GROUP_free(grp);
    BN_free(x);
    BN_free(y);
    return ok == 1;
}

// ═════════════════════════════════════════════════════════════════════
//  互操作自检
// ═════════════════════════════════════════════════════════════════════
struct EcdsaCtx {
    int nid;
    const EVP_MD* md;
    int key_len, pub_len, sig_len;
    uint8_t pub[96], priv[48], sig[96];
};

static void selfcheck(const char* algo, bool jp2os, bool os2jp, bool jp_self,
                      bool tamper_jp, bool tamper_os) {
    printf("  interop %-26s jpssl->openssl %-4s openssl->jpssl %-4s jpssl-self %-4s "
           "tamper-reject %s/%s\n",
           algo,
           jp2os ? "PASS" : "FAIL", os2jp ? "PASS" : "FAIL", jp_self ? "PASS" : "FAIL",
           tamper_jp ? "PASS" : "FAIL", tamper_os ? "PASS" : "FAIL");
    if (jp2os) ++g_pass; else ++g_fail;
    if (os2jp) ++g_pass; else ++g_fail;
    if (jp_self) ++g_pass; else ++g_fail;
    if (tamper_jp) ++g_pass; else ++g_fail;
    if (tamper_os) ++g_pass; else ++g_fail;
}

static bool ecdsa_selfcheck(EcdsaCtx& c, const uint8_t* msg, size_t msglen) {
    if (c.key_len == 32) jpssl::ecdsa_p256_keygen(c.pub, c.priv);
    else                 jpssl::ecdsa_p384_keygen(c.pub, c.priv);
    if (c.key_len == 32) jpssl::ecdsa_p256_sign(c.priv, msg, msglen, c.sig);
    else                 jpssl::ecdsa_p384_sign(c.priv, msg, msglen, c.sig);

    // 方向 1: jpssl 签 → OpenSSL 验 (注意 rs_len 传 c.sig_len 总长)
    bool jp2os = ossl_ecdsa_verify_rs(c.nid, c.pub, c.pub_len, c.md, c.sig_len,
                                      msg, msglen, c.sig);
    // 方向 2: OpenSSL 签 (用 jpssl 私钥) → jpssl 验
    uint8_t osig[96];
    ossl_ecdsa_sign_rs(c.nid, c.priv, c.key_len, c.md, c.sig_len, msg, msglen, osig);
    bool os2jp = (c.key_len == 32) ? jpssl::ecdsa_p256_verify(c.pub, msg, msglen, osig)
                                   : jpssl::ecdsa_p384_verify(c.pub, msg, msglen, osig);
    // 自环: jpssl 签 → jpssl 验
    bool jp_self = (c.key_len == 32) ? jpssl::ecdsa_p256_verify(c.pub, msg, msglen, c.sig)
                                     : jpssl::ecdsa_p384_verify(c.pub, msg, msglen, c.sig);
    // 篡改拒绝: 消息翻转 1 字节, 两实现均须验签失败
    std::vector<uint8_t> tmsg(msg, msg + msglen);
    tmsg[0] ^= 0x01;
    bool tamper_jp = !((c.key_len == 32) ? jpssl::ecdsa_p256_verify(c.pub, tmsg.data(), msglen, c.sig)
                                         : jpssl::ecdsa_p384_verify(c.pub, tmsg.data(), msglen, c.sig));
    bool tamper_os = !ossl_ecdsa_verify_rs(c.nid, c.pub, c.pub_len, c.md, c.sig_len,
                                           tmsg.data(), msglen, c.sig);

    const char* algo = (c.key_len == 32) ? "ecdsa-p256 SHA-256" : "ecdsa-p384 SHA-384";
    selfcheck(algo, jp2os, os2jp, jp_self, tamper_jp, tamper_os);
    return jp2os && os2jp && jp_self && tamper_jp && tamper_os;
}

// ═════════════════════════════════════════════════════════════════════
//  基准
// ═════════════════════════════════════════════════════════════════════
using JpKeygen = void (*)(uint8_t*, uint8_t*);
using JpSign   = void (*)(const uint8_t*, const uint8_t*, size_t, uint8_t*);
using JpVerify = bool (*)(const uint8_t*, const uint8_t*, size_t, const uint8_t*);

// 单条曲线: keygen (size=0) + sign/verify × 各消息长度, jpssl 与 openssl 各一行
static void bench_curve(const char* algo, int nid, const EVP_MD* md,
                        JpKeygen jp_keygen, JpSign jp_sign, JpVerify jp_verify,
                        const std::vector<size_t>& sizes,
                        const std::vector<std::vector<uint8_t>>& msgs) {
    std::string kg = std::string(algo) + "-keygen";
    std::string sg = std::string(algo) + "-sign";
    std::string vf = std::string(algo) + "-verify";

    printf("  --- %s keygen / sign / verify ---\n", algo);
    uint8_t pub[96], priv[48], sig[96];
    double kg_jp = auto_bench(kg.c_str(), [&] { jp_keygen(pub, priv); }, 1);
    emit_row(kg.c_str(), "jpssl", 0, kg_jp);

    EC_KEY* eck = EC_KEY_new_by_curve_name(nid);
    double kg_os = auto_bench(kg.c_str(), [&] { EC_KEY_generate_key(eck); }, 1);
    emit_row(kg.c_str(), "openssl", 0, kg_os);

    for (size_t i = 0; i < sizes.size(); ++i) {
        const size_t size = sizes[i];
        const uint8_t* m = msgs[i].data();

        // OpenSSL 侧摘要 (哈希不计入计时)
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int dlen = 0;
        EVP_MD_CTX* dctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(dctx, md, nullptr);
        EVP_DigestUpdate(dctx, m, size);
        EVP_DigestFinal_ex(dctx, digest, &dlen);
        EVP_MD_CTX_free(dctx);

        // 该消息长度下的有效签名 (供 verify 基准用)
        jp_sign(priv, m, size, sig);
        ECDSA_SIG* sig_os = ECDSA_do_sign(digest, dlen, eck);

        double sj = auto_bench(sg.c_str(), [&] { jp_sign(priv, m, size, sig); g_sink ^= sig[0]; });
        emit_row(sg.c_str(), "jpssl", size, sj);
        double so = auto_bench(sg.c_str(),
                               [&] { ECDSA_SIG_free(ECDSA_do_sign(digest, dlen, eck)); });
        emit_row(sg.c_str(), "openssl", size, so);
        double vj = auto_bench(vf.c_str(), [&] { g_sink ^= jp_verify(pub, m, size, sig) ? 1 : 0; });
        emit_row(vf.c_str(), "jpssl", size, vj);
        double vo = auto_bench(vf.c_str(),
                               [&] { g_sink ^= ECDSA_do_verify(digest, dlen, sig_os, eck); });
        emit_row(vf.c_str(), "openssl", size, vo);

        ECDSA_SIG_free(sig_os);
    }
    EC_KEY_free(eck);
}

int main() {
    const char* e = getenv("BENCH_SMOKE");
    g_smoke = (e && strcmp(e, "1") == 0);
    if (g_smoke) { g_target_ms = 80.0; g_rounds = 1; }

    printf("=== jpssl ECDSA full test: P-256+SHA-256 / P-384+SHA-384 vs OpenSSL ===\n");
    printf("OpenSSL %s | mode: %s (target_ms=%.0f, rounds=%d)\n",
           OPENSSL_VERSION_TEXT,
           g_smoke ? "SMOKE (32B only)" : "FULL (4 sizes, min of rounds)",
           g_target_ms, g_rounds);

    // 消息长度矩阵 + 确定性消息数据
    const std::vector<size_t> sizes = g_smoke ? std::vector<size_t>{32}
                                              : std::vector<size_t>{32, 256, 1024, 65536};
    std::vector<std::vector<uint8_t>> msgs;
    for (size_t n : sizes) {
        std::vector<uint8_t> m(n);
        uint64_t x = 0x9e3779b97f4a7c15ull;
        for (size_t i = 0; i < n; ++i) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            m[i] = static_cast<uint8_t>(x);
        }
        msgs.push_back(std::move(m));
    }
    const uint8_t* m32 = msgs[0].data();
    const size_t m32len = msgs[0].size();

    // ── 1. 互操作自检 (始终执行) ─────────────────────────────────────
    printf("\n=== interop self-tests ===\n");
    EcdsaCtx ec_p256{NID_X9_62_prime256v1, EVP_sha256(), 32, 64, 64, {}, {}, {}};
    EcdsaCtx ec_p384{NID_secp384r1, EVP_sha384(), 48, 96, 96, {}, {}, {}};

    if (!ecdsa_selfcheck(ec_p256, m32, m32len)) ++g_fail;
    if (!ecdsa_selfcheck(ec_p384, m32, m32len)) ++g_fail;

    if (g_fail) {
        printf("\ninterop FAILED (%d), abort without CSV\n", g_fail);
        return 1;
    }
    printf("all interop self-tests PASS (pass=%d)\n", g_pass);

    // ── 2. 基准测量 ──────────────────────────────────────────────────
    printf("\n=== ECDSA ===\n");
    bench_curve("ecdsa-p256", NID_X9_62_prime256v1, EVP_sha256(),
                &jpssl::ecdsa_p256_keygen, &jpssl::ecdsa_p256_sign, &jpssl::ecdsa_p256_verify,
                sizes, msgs);
    bench_curve("ecdsa-p384", NID_secp384r1, EVP_sha384(),
                &jpssl::ecdsa_p384_keygen, &jpssl::ecdsa_p384_sign, &jpssl::ecdsa_p384_verify,
                sizes, msgs);

    // ── 3. CSV 输出 ──────────────────────────────────────────────────
    std::filesystem::create_directories("benchmarks/results");
    const char* csv_path = "benchmarks/results/bench_ecdsa.csv";
    FILE* csv = std::fopen(csv_path, "w");
    if (!csv) {
        printf("ERROR: cannot open %s\n", csv_path);
        return 2;
    }
    std::fprintf(csv, "algo,impl,size_bytes,ns_per_op,ops_per_sec\n");
    for (const Row& r : g_rows) {
        std::fprintf(csv, "%s,%s,%zu,%.2f,%.2f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.ns, 1e9 / r.ns);
    }
    std::fclose(csv);
    printf("\nCSV written: %s (%zu rows)\n", csv_path, g_rows.size());
    printf("(sink=%d, selfcheck pass=%d)\n", g_sink, g_pass);
    return 0;
}
