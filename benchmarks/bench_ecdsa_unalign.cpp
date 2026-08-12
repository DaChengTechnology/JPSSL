// bench_ecdsa_unalign.cpp — ECDSA 非对齐测试对比组 (P-256+SHA-256 / P-384+SHA-384)
//   与 OpenSSL 对比, 产出独立 CSV benchmarks/results/bench_ecdsa_unalign.csv
//
// 背景: ECDSA 签名先哈希, 消息长度/对齐理论上对签名耗时无影响。
//   本程序验证该假设并记录测量数据 (与 OpenSSL 对比)。
//
// 非对齐组的定义 (对本算法):
//   1. 非对齐消息长度: 3 / 999 / 32761 (签名消息), 与 32 / 256 对齐档对照;
//      覆盖 jpssl sign/verify 与 openssl。
//   2. 非对齐指针 offset: 消息起始偏移 1/3; 性能至少 offset=0 与 3;
//      自检 offset 1/3/7。
//   3. 自检 (始终执行): 非对齐下两方向互验通过 (jpssl->openssl, openssl->jpssl,
//      自环, 篡改拒绝); 任一 FAIL 非零退出且不输出 CSV。
//      (keygen 不重复测 —— 见 bench_ecdsa.cpp)
//   4. 性能基准: 消息长度 {3,999,32761} × offset {0,3} (sign+verify);
//      BENCH_SMOKE=1: 长度 {3} × offset {0,3}, ~80ms, 1 轮;
//      未设置: 全量, ~150ms, 3 轮取最小。
//
// CSV 列头: algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec
//   algo: ecdsa-p256-sign-unalign / ecdsa-p256-verify-unalign / ecdsa-p384-*
//   impl: jpssl / openssl
//
// 写法复用 benchmarks/bench_ecdsa.cpp (已验证): 固定 r||s 互验
//   (ossl_ecdsa_sign_rs / ossl_ecdsa_verify_rs, 注意 rs_len 传全量 sig_len),
//   auto_bench 自适应迭代微基准, OpenSSL 侧摘要不记入计时。
//
// 编译 (worktree 根, 单行):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_VAES -Iinclude -Isrc
//   benchmarks/bench_ecdsa_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//   -lcrypto -o /tmp/bench_ecdsa_unalign
// 运行:
//   BENCH_SMOKE=1 /tmp/bench_ecdsa_unalign   # 自检 + 长度{3}×offset{0,3}
//   /tmp/bench_ecdsa_unalign                 # 全量 (长度{3,999,32761}×offset{0,3} + 32/256 对照)

#include "ecdsa.hpp"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

using Clock = std::chrono::steady_clock;

static volatile int g_sink = 0;
static int g_fail = 0;
static int g_pass = 0;

// ─────────────────────────────────────────────────────────────────────
// 全量 / smoke 开关 (BENCH_SMOKE=1 → 仅长度{3}×offset{0,3}, ~80ms, 1 轮)
// ─────────────────────────────────────────────────────────────────────
static bool g_smoke = false;
static double g_target_ms = 150.0;   // 每档每操作目标时长
static int g_rounds = 3;             // 轮数, 取最小

// ─────────────────────────────────────────────────────────────────────
// CSV 行记录 (含 offset_bytes 列)
// ─────────────────────────────────────────────────────────────────────
struct Row {
    std::string algo, impl;
    size_t size;
    size_t offset;
    double ns;
};
static std::vector<Row> g_rows;

static void emit_row(const char* algo, const char* impl, size_t size, size_t offset, double ns) {
    g_rows.push_back({algo, impl, size, offset, ns});
    printf("  %-26s %-18s %6zu %3zu %13.1f ns/op %12.2f ops/s\n",
           algo, impl, size, offset, ns, 1e9 / ns);
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
    printf("  %-26s %-18s %6s %3s %13.1f ns/op %12.2f ops/s   (iters=%lld)\n",
           name, "", "", "", best, 1e9 / best, iters);
    return best;
}

// 确定性消息填充 (与 bench_ecdsa.cpp 相同 xorshift)
static void fill_msg(uint8_t* p, size_t n) {
    uint64_t x = 0x9e3779b97f4a7c15ull;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        p[i] = static_cast<uint8_t>(x);
    }
}

// ═════════════════════════════════════════════════════════════════════
//  OpenSSL 侧辅助 (固定 r||s 转换, 结构取自 bench_ecdsa.cpp 已验证实现)
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
//  非对齐互操作自检 (结构取自 bench_ecdsa.cpp, msg 已含 offset)
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
//  基准 (keygen 不重复测; openssl 侧密钥只建一次, 摘要不记入计时)
// ═════════════════════════════════════════════════════════════════════
using JpSign   = void (*)(const uint8_t*, const uint8_t*, size_t, uint8_t*);
using JpVerify = bool (*)(const uint8_t*, const uint8_t*, size_t, const uint8_t*);

struct Combo {
    size_t size;   // 消息长度 (字节)
    int offset;    // 消息起始指针偏移 (字节)
};

// 单条曲线: sign/verify × {(size,offset)} 矩阵, jpssl 与 openssl 各一行
static void bench_curve_unalign(const char* algo, int nid, const EVP_MD* md,
                                JpSign jp_sign, JpVerify jp_verify, int key_len,
                                const std::vector<Combo>& combos,
                                const std::vector<std::vector<uint8_t>>& bufs) {
    std::string sg = std::string(algo) + "-sign-unalign";
    std::string vf = std::string(algo) + "-verify-unalign";
    printf("  --- %s sign/verify unaligned (size × offset) ---\n", algo);

    uint8_t pub[96], priv[48], sig[96];
    if (key_len == 32) jpssl::ecdsa_p256_keygen(pub, priv);
    else               jpssl::ecdsa_p384_keygen(pub, priv);

    // openssl 侧密钥对 (自用, 只建一次)
    EC_KEY* eck = EC_KEY_new_by_curve_name(nid);
    EC_KEY_generate_key(eck);

    for (size_t i = 0; i < combos.size(); ++i) {
        const size_t size = combos[i].size;
        const int offset = combos[i].offset;
        const uint8_t* m = bufs[i].data() + offset;

        // OpenSSL 侧摘要 (哈希不计入计时, 与 bench_ecdsa.cpp 一致)
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int dlen = 0;
        EVP_MD_CTX* dctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(dctx, md, nullptr);
        EVP_DigestUpdate(dctx, m, size);
        EVP_DigestFinal_ex(dctx, digest, &dlen);
        EVP_MD_CTX_free(dctx);

        // 该 (size,offset) 下的有效签名 (供 verify 基准用)
        jp_sign(priv, m, size, sig);
        ECDSA_SIG* sig_os = ECDSA_do_sign(digest, dlen, eck);

        double sj = auto_bench(sg.c_str(), [&] { jp_sign(priv, m, size, sig); g_sink ^= sig[0]; });
        emit_row(sg.c_str(), "jpssl", size, (size_t)offset, sj);
        double so = auto_bench(sg.c_str(),
                               [&] { ECDSA_SIG_free(ECDSA_do_sign(digest, dlen, eck)); });
        emit_row(sg.c_str(), "openssl", size, (size_t)offset, so);
        double vj = auto_bench(vf.c_str(), [&] { g_sink ^= jp_verify(pub, m, size, sig) ? 1 : 0; });
        emit_row(vf.c_str(), "jpssl", size, (size_t)offset, vj);
        double vo = auto_bench(vf.c_str(),
                               [&] { g_sink ^= ECDSA_do_verify(digest, dlen, sig_os, eck); });
        emit_row(vf.c_str(), "openssl", size, (size_t)offset, vo);

        ECDSA_SIG_free(sig_os);
    }
    EC_KEY_free(eck);
}

int main() {
    const char* e = getenv("BENCH_SMOKE");
    g_smoke = (e && strcmp(e, "1") == 0);
    if (g_smoke) { g_target_ms = 80.0; g_rounds = 1; }

    printf("=== jpssl ECDSA unaligned-message/offset test: P-256+SHA-256 / P-384+SHA-384 vs OpenSSL ===\n");
    printf("OpenSSL %s | mode: %s (target_ms=%.0f, rounds=%d)\n",
           OPENSSL_VERSION_TEXT,
           g_smoke ? "SMOKE (len{3}×offset{0,3})"
                   : "FULL (len{3,999,32761}×offset{0,3} + 32/256 aligned controls)",
           g_target_ms, g_rounds);

    // ── 1. 非对齐互操作自检 (始终执行): 消息 len 999 × offset {1,3,7} ──
    printf("\n=== unaligned interop self-tests (msg len 999, offsets 1/3/7) ===\n");
    EcdsaCtx ec_p256{NID_X9_62_prime256v1, EVP_sha256(), 32, 64, 64, {}, {}, {}};
    EcdsaCtx ec_p384{NID_secp384r1, EVP_sha384(), 48, 96, 96, {}, {}, {}};

    const size_t self_len = 999;
    std::vector<uint8_t> selfbuf(self_len + 16);
    fill_msg(selfbuf.data(), selfbuf.size());

    for (int off : {1, 3, 7}) {
        const uint8_t* m = selfbuf.data() + off;
        if (!ecdsa_selfcheck(ec_p256, m, self_len)) ++g_fail;
        if (!ecdsa_selfcheck(ec_p384, m, self_len)) ++g_fail;
    }

    if (g_fail) {
        printf("\nunaligned interop FAILED (%d), abort without CSV\n", g_fail);
        return 1;
    }
    printf("all unaligned interop self-tests PASS (pass=%d)\n", g_pass);

    // ── 2. 基准测量 ──
    std::vector<Combo> combos;
    if (g_smoke) {
        combos = {{3, 0}, {3, 3}};
    } else {
        for (size_t s : {size_t(3), size_t(999), size_t(32761)})
            for (int o : {0, 3}) combos.push_back({s, o});
        // 对齐档对照: 32 / 256 @ offset 0
        for (size_t s : {size_t(32), size_t(256)}) combos.push_back({s, 0});
    }
    std::vector<std::vector<uint8_t>> bufs;
    bufs.reserve(combos.size());
    for (const Combo& c : combos) {
        std::vector<uint8_t> b(c.size + 16);
        fill_msg(b.data(), b.size());
        bufs.push_back(std::move(b));
    }

    printf("\n=== ECDSA unaligned benchmark ===\n");
    bench_curve_unalign("ecdsa-p256", NID_X9_62_prime256v1, EVP_sha256(),
                        &jpssl::ecdsa_p256_sign, &jpssl::ecdsa_p256_verify, 32,
                        combos, bufs);
    bench_curve_unalign("ecdsa-p384", NID_secp384r1, EVP_sha384(),
                        &jpssl::ecdsa_p384_sign, &jpssl::ecdsa_p384_verify, 48,
                        combos, bufs);

    // ── 3. CSV 输出 ──
    std::filesystem::create_directories("benchmarks/results");
    const char* csv_path = "benchmarks/results/bench_ecdsa_unalign.csv";
    FILE* csv = std::fopen(csv_path, "w");
    if (!csv) {
        printf("ERROR: cannot open %s\n", csv_path);
        return 2;
    }
    std::fprintf(csv, "algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec\n");
    for (const Row& r : g_rows) {
        std::fprintf(csv, "%s,%s,%zu,%zu,%.2f,%.2f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.offset, r.ns, 1e9 / r.ns);
    }
    std::fclose(csv);
    printf("\nCSV written: %s (%zu rows)\n", csv_path, g_rows.size());
    printf("(sink=%d, selfcheck pass=%d, fail=%d)\n", g_sink, g_pass, g_fail);
    return 0;
}
