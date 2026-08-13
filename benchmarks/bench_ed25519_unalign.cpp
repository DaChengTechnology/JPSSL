// bench_ed25519_unalign.cpp — Ed25519 非对齐测试对比组: 非对齐消息长度 × 非对齐指针 offset × 各实现 × OpenSSL
//
// 覆盖矩阵:
//   非对齐消息长度 : 3 / 999 / 32761 (签名消息), 与 32 对照 (自检含 32; 性能矩阵 {3,999,32761})
//   非对齐指针    : 消息起始字节偏移 offset ∈ {0,1,3,7}; 性能用 {0,3}, 自检用 {1,3,7}
//   实现路径      : jpssl 默认 (ed25519_keygen/sign/verify, 内部派发 r51)
//                  jpssl r51 显式 (ed25519_*_r51)
//                  jpssl ref10 scalar (ed25519_ref10_impl::*, 头文件未暴露, 本文件 extern 声明)
//                  jpssl 批量验签 (ed25519_batch_verify, N=64, 非对齐消息)
//                  OpenSSL (EVP_PKEY ED25519)
//                  avx512: 本机 cpu_has_avx512()=false → 仅 SKIP, 绝不调用 (调用会 SIGILL)
//
// 正确性自检 (始终执行):
//   - 每个 (长度,offset) 下: 各实现与 OpenSSL 两方向互验 (jpssl 签→openssl 验, openssl 签→jpssl 验)
//   - 各实现内部一致: 默认==r51==scalar 签名逐字节相同 (Ed25519 确定性签名), 各自自验
//   - 批量 N=64 (非对齐消息) 与 OpenSSL 逐条循环验签一致 + 负例 (破坏 1 条签名必须拒绝)
//   - 任一 FAIL → 非零退出且不写 CSV
//   (注意: 批量私钥缓冲为 64B — ed25519_keygen 写 pub[32]+priv[64]; 先例文件曾因 32B 越界崩溃)
//
// 性能基准: sign / verify / batch(N=64) × {3,999,32761} × offset{0,3}
//   BENCH_SMOKE=1: 长度 {3} × offset{0,3}, ~80ms/轮, 1 轮
//   默认全量      : 长度 {3,999,32761} × offset{0,3}, ~150ms/轮, 3 轮取最小
//   keygen 不重复测 (仅基准前生成一次, 不计时)
//
// 输出: stdout 人类可读表格 + benchmarks/results/bench_ed25519_unalign.csv
//   CSV 列: algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec
//   algo: ed25519-sign-unalign / ed25519-verify-unalign / ed25519-batch-unalign
//   impl: jpssl / jpssl-r51 / jpssl-scalar / jpssl-batch64 / openssl
//   (可用环境变量 BENCH_CSV_PATH 覆盖 CSV 输出路径)
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES \
//       -Iinclude -Isrc benchmarks/bench_ed25519_unalign.cpp \
//       /home/jp/jpssl/build-main-verify/libjpssl_cpu.a -lcrypto \
//       -o /tmp/bench_ed25519_unalign
//
// 运行 (worktree 根, 以便相对路径 CSV 落在 <worktree>/benchmarks/results/):
//   BENCH_SMOKE=1 /tmp/bench_ed25519_unalign      # smoke: 退出 0 且 CSV 有数据
//   /tmp/bench_ed25519_unalign                    # 全量

#include "ed25519.hpp"
#include "ed25519_batch.hpp"
#include "cpu_features.hpp"

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

// ─────────────────────────────────────────────────────────────────────
// 头文件未声明、但静态库已导出 (T 符号) 的后端实现声明 (ref10 scalar)
// ─────────────────────────────────────────────────────────────────────
namespace jpssl {
namespace ed25519_ref10_impl {
void ed25519_keygen(uint8_t pub[32], uint8_t priv[64]);
void ed25519_sign(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]);
bool ed25519_verify(const uint8_t pub[32], const uint8_t* msg, size_t msg_len,
                    const uint8_t sig[64]);
}
} // namespace jpssl

static volatile int g_sink = 0;

// ─────────────────────────────────────────────────────────────────────
// CSV 行记录
// ─────────────────────────────────────────────────────────────────────
struct Row {
    std::string algo, impl;
    size_t size;
    int offset;
    double ns;
};
static std::vector<Row> g_rows;

static void emit_row(const char* algo, const char* impl, size_t size, int offset, double ns) {
    g_rows.push_back({algo, impl, size, offset, ns});
    printf("  %-20s %-18s size=%6zu off=%d %13.1f ns/op %12.2f ops/s\n",
           algo, impl, size, offset, ns, 1e9 / ns);
}

static int g_skip_count = 0;
static void skip(const char* msg) {
    ++g_skip_count;
    printf("  SKIP %s\n", msg);
}

// ─────────────────────────────────────────────────────────────────────
// 自适应迭代微基准: 每轮约 target_ms, rounds 轮取最小值 (复用 bench_ed25519.cpp 写法)
// ─────────────────────────────────────────────────────────────────────
template <typename F>
static double auto_bench(const char* name, F&& f, double target_ms = 150.0,
                         int rounds = 3, int est_n = 8) {
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
    printf("  %-20s %-18s %6s %6s %13.1f ns/op %12.2f ops/s   (iters=%lld)\n",
           name, "", "", "", best, 1e9 / best, iters);
    return best;
}

// ─────────────────────────────────────────────────────────────────────
// 单条实现路径描述 (keygen 仅用于自检密钥, 不参与基准计时)
// ─────────────────────────────────────────────────────────────────────
struct SigImpl {
    const char* name;
    void (*keygen)(uint8_t pub[32], uint8_t priv[64]);
    void (*sign)(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]);
    bool (*verify)(const uint8_t pub[32], const uint8_t* msg, size_t msg_len,
                   const uint8_t sig[64]);
};

static const SigImpl kImpls[] = {
    {"jpssl",        jpssl::ed25519_keygen,
                      jpssl::ed25519_sign,
                      jpssl::ed25519_verify},
    {"jpssl-r51",    jpssl::ed25519_keygen_r51,
                      jpssl::ed25519_sign_r51,
                      jpssl::ed25519_verify_r51},
    {"jpssl-scalar", jpssl::ed25519_ref10_impl::ed25519_keygen,
                      jpssl::ed25519_ref10_impl::ed25519_sign,
                      jpssl::ed25519_ref10_impl::ed25519_verify},
};

// ─────────────────────────────────────────────────────────────────────
// 互操作自检
// ─────────────────────────────────────────────────────────────────────
static int g_fail = 0;
static int g_pass = 0;

static void selfcheck(const char* what, bool ok) {
    printf("  selfcheck %-58s : %s\n", what, ok ? "PASS" : "FAIL");
    if (ok) ++g_pass; else ++g_fail;
}

// 单条路径 × OpenSSL 两方向互验 (同一 priv, 各实现签→openssl 验 / openssl 签→各实现验)
// + 内部一致 (默认==r51==scalar 签名逐字节相同) + 自验; 消息指针非对齐 (offset)
static void interop_unalign_selfchecks(const uint8_t* msg, size_t msglen, int offset) {
    uint8_t pub[32], priv[64];
    jpssl::ed25519_keygen(pub, priv);

    EVP_PKEY* ossl_key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    if (!ossl_key) { selfcheck("openssl keygen", false); return; }
    uint8_t ossl_pub[32];
    size_t plen = 32;
    EVP_PKEY_get_raw_public_key(ossl_key, ossl_pub, &plen);
    uint8_t ossl_sig[64];
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    size_t slen = 64;
    bool ossl_sign_ok = EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ossl_key) == 1
        && EVP_DigestSign(mctx, ossl_sig, &slen, msg, msglen) == 1 && slen == 64;
    char what[96];
    std::snprintf(what, sizeof what, "openssl keygen+sign (len=%zu off=%d)", msglen, offset);
    selfcheck(what, ossl_sign_ok);

    uint8_t sigs[3][64];
    for (int i = 0; i < 3; ++i) kImpls[i].sign(priv, msg, msglen, sigs[i]);

    // 内部一致: Ed25519 确定性签名 → 默认==r51==scalar 逐字节相同
    bool cons = memcmp(sigs[0], sigs[1], 64) == 0 && memcmp(sigs[0], sigs[2], 64) == 0;
    std::snprintf(what, sizeof what, "default==r51==scalar sig (len=%zu off=%d)", msglen, offset);
    selfcheck(what, cons);

    for (int i = 0; i < 3; ++i) {
        const SigImpl& im = kImpls[i];
        // 自验: 自身签名 → 自身验
        std::snprintf(what, sizeof what, "%s self-roundtrip (len=%zu off=%d)", im.name, msglen, offset);
        selfcheck(what, im.verify(pub, msg, msglen, sigs[i]));
        // jpssl 签 → OpenSSL 验
        EVP_PKEY* jp_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub, 32);
        bool jp2os = jp_pub != nullptr
            && EVP_MD_CTX_reset(mctx) == 1
            && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, jp_pub) == 1
            && EVP_DigestVerify(mctx, sigs[i], 64, msg, msglen) == 1;
        EVP_PKEY_free(jp_pub);
        std::snprintf(what, sizeof what, "%s jpssl->openssl (len=%zu off=%d)", im.name, msglen, offset);
        selfcheck(what, jp2os);
        // OpenSSL 签 → jpssl 验
        bool os2jp = ossl_sign_ok && im.verify(ossl_pub, msg, msglen, ossl_sig);
        std::snprintf(what, sizeof what, "%s openssl->jpssl (len=%zu off=%d)", im.name, msglen, offset);
        selfcheck(what, os2jp);
    }

    EVP_PKEY_free(ossl_key);
    EVP_MD_CTX_free(mctx);
}

// ─────────────────────────────────────────────────────────────────────
// 批量验签 (N=64, 非对齐消息) 自检: 与 OpenSSL 逐条循环验签一致 + 负例
// ─────────────────────────────────────────────────────────────────────
static constexpr int kBatchN = 64;

struct BatchCtx {
    std::vector<std::array<uint8_t, 32>> pubs;
    std::vector<std::array<uint8_t, 64>> privs;   // 64B! ed25519_keygen 写 pub[32]+priv[64]
    std::vector<std::array<uint8_t, 64>> sigs;
    std::vector<const uint8_t*> pub_ptrs, msg_ptrs, sig_ptrs;
    std::vector<size_t> lens;
    std::vector<EVP_PKEY*> ovpubs;

    ~BatchCtx() {
        for (EVP_PKEY* k : ovpubs) EVP_PKEY_free(k);
    }
};

static void batch_build(BatchCtx& c, const uint8_t* msg, size_t msglen) {
    c.pubs.resize(kBatchN);
    c.privs.resize(kBatchN);
    c.sigs.resize(kBatchN);
    c.pub_ptrs.resize(kBatchN);
    c.msg_ptrs.resize(kBatchN, msg);
    c.sig_ptrs.resize(kBatchN);
    c.lens.resize(kBatchN, msglen);
    for (int i = 0; i < kBatchN; ++i) {
        jpssl::ed25519_keygen(c.pubs[i].data(), c.privs[i].data());
        jpssl::ed25519_sign(c.privs[i].data(), msg, msglen, c.sigs[i].data());
        c.pub_ptrs[i] = c.pubs[i].data();
        c.sig_ptrs[i] = c.sigs[i].data();
        c.ovpubs.push_back(
            EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, c.pubs[i].data(), 32));
    }
}

static void batch_unalign_selfchecks(BatchCtx& c, const uint8_t* msg, size_t msglen, int offset) {
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool jp_ok = jpssl::ed25519_batch_verify(
        c.pub_ptrs.data(), c.msg_ptrs.data(), c.lens.data(), c.sig_ptrs.data(), kBatchN);
    bool os_ok = true;
    for (int i = 0; i < kBatchN; ++i) {
        if (EVP_MD_CTX_reset(mctx) != 1
            || EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, c.ovpubs[i]) != 1
            || EVP_DigestVerify(mctx, c.sigs[i].data(), 64, msg, msglen) != 1) {
            os_ok = false;
            break;
        }
    }
    char what[96];
    std::snprintf(what, sizeof what, "batch x64 jpssl==openssl-loop (len=%zu off=%d)", msglen, offset);
    selfcheck(what, jp_ok && os_ok);

    // 负例: 破坏第 4 条签名 → 批量必须拒绝
    {
        uint8_t corrupt[64];
        memcpy(corrupt, c.sigs[3].data(), 64);
        corrupt[0] ^= 0x01;
        const uint8_t* saved = c.sig_ptrs[3];
        c.sig_ptrs[3] = corrupt;
        bool neg = !jpssl::ed25519_batch_verify(
            c.pub_ptrs.data(), c.msg_ptrs.data(), c.lens.data(), c.sig_ptrs.data(), 64);
        c.sig_ptrs[3] = saved;
        std::snprintf(what, sizeof what, "batch x64 negative (len=%zu off=%d)", msglen, offset);
        selfcheck(what, neg);
    }
    EVP_MD_CTX_free(mctx);
}

// ─────────────────────────────────────────────────────────────────────
// 非对齐消息缓冲: 长度 → (len+16) 确定性数据, offset 0..7 均可安全指向
// ─────────────────────────────────────────────────────────────────────
struct MsgBuf {
    size_t len;
    std::vector<uint8_t> data;  // len + 16 (留出 offset 空间)
    const uint8_t* ptr(int off) const { return data.data() + off; }
};

static MsgBuf make_msg(size_t len) {
    MsgBuf b;
    b.len = len;
    b.data.resize(len + 16);
    uint64_t x = 0x9e3779b97f4a7c15ull;
    for (size_t i = 0; i < b.data.size(); ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        b.data[i] = static_cast<uint8_t>(x);
    }
    return b;
}

static const MsgBuf& find_msg(const std::vector<MsgBuf>& bufs, size_t len) {
    for (const MsgBuf& b : bufs) {
        if (b.len == len) return b;
    }
    std::abort(); // 不应发生
}

// ─────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────
int main() {
    const bool smoke = std::getenv("BENCH_SMOKE") != nullptr;
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds = smoke ? 1 : 3;

    const auto feats = jpssl::cpu_features::detect();
    printf("=== bench_ed25519_unalign: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    printf("mode    : %s\n", smoke ? "SMOKE (len{3} x off{0,3}, 1 round, ~80ms)"
                                   : "FULL (len{3,999,32761} x off{0,3}, 3 rounds, ~150ms)");
    printf("CPU     : x86_64  AES-NI=%d AVX2=%d PCLMULQDQ=%d AVX512=%d VAES=%d SHA-NI=%d\n",
           feats.aesni ? 1 : 0, feats.avx2 ? 1 : 0, feats.pclmulqdq ? 1 : 0,
           feats.avx512 ? 1 : 0, feats.vpclmulqdq_vaes ? 1 : 0, feats.sha_ni ? 1 : 0);
    printf("batch backend size (ed25519_batch_size): %d\n", jpssl::ed25519_batch_size());

    const std::array<size_t, 4> kCheckSizes = {3, 999, 32761, 32};      // 自检: 含 32 对照
    const std::array<int, 3> kCheckOffsets = {1, 3, 7};
    std::vector<size_t> perf_sizes;
    if (smoke) perf_sizes.push_back(3);
    else { perf_sizes.push_back(3); perf_sizes.push_back(999); perf_sizes.push_back(32761); }
    const std::array<int, 2> kPerfOffsets = {0, 3};

    std::vector<MsgBuf> bufs;
    for (size_t s : kCheckSizes) bufs.push_back(make_msg(s));

    // ── 1. 互操作自检 (始终执行) ────────────────────────────────────
    printf("\n=== unalign interop self-tests (len x offset) ===\n");
    for (size_t sz : kCheckSizes) {
        const MsgBuf& b = find_msg(bufs, sz);
        for (int off : kCheckOffsets) interop_unalign_selfchecks(b.ptr(off), sz, off);
    }

    printf("\n=== unalign batch N=64 self-tests ===\n");
    for (size_t sz : {size_t(3), size_t(999), size_t(32761)}) {
        const MsgBuf& b = find_msg(bufs, sz);
        for (int off : kCheckOffsets) {
            BatchCtx bc;
            batch_build(bc, b.ptr(off), sz);
            batch_unalign_selfchecks(bc, b.ptr(off), sz, off);
        }
    }

    if (g_fail) {
        printf("\nself-tests FAILED (%d), abort without CSV\n", g_fail);
        return 1;
    }
    printf("all self-tests PASS (%d checks)\n", g_pass);

    // ── 2. SKIP 说明 ────────────────────────────────────────────────
    printf("\n=== SKIPs (不支持的实现, 绝不被调用) ===\n");
    if (!feats.avx512) {
        skip("ed25519-avx512 sign/verify/interop : cpu_has_avx512()=false (本机调用会 SIGILL, 不在本组测量)");
    }
    if (g_skip_count == 0) printf("  (none)\n");

    // 供基准使用的 jpssl 默认密钥与 OpenSSL 密钥 (keygen 不重复测)
    uint8_t pub[32], priv[64], sig_for[64];
    jpssl::ed25519_keygen(pub, priv);

    EVP_PKEY* ossl_pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub, 32);
    EVP_PKEY* ossl_key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    uint8_t ossl_sig[64];

    // ── 3. 基准测量: sign / verify × 长度 × offset ──────────────────
    printf("\n=== unalign sign / verify (len x offset) ===\n");
    for (size_t sz : perf_sizes) {
        const MsgBuf& b = find_msg(bufs, sz);
        for (int off : kPerfOffsets) {
            const uint8_t* m = b.ptr(off);
            jpssl::ed25519_sign(priv, m, sz, sig_for);  // 该 (长度,offset) 下的基准签名 (各验签共用)

            for (const SigImpl& im : kImpls) {
                uint8_t sbuf[64];
                double s = auto_bench("ed25519-sign-unalign", [&, im, m, sz] {
                    im.sign(priv, m, sz, sbuf);
                    g_sink ^= sbuf[0];
                }, target_ms, rounds);
                emit_row("ed25519-sign-unalign", im.name, sz, off, s);
            }
            {
                double s = auto_bench("ed25519-sign-unalign", [&, m, sz] {
                    size_t sl = 64;
                    EVP_MD_CTX_reset(mctx);
                    EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ossl_key);
                    EVP_DigestSign(mctx, ossl_sig, &sl, m, sz);
                    g_sink ^= ossl_sig[0];
                }, target_ms, rounds);
                emit_row("ed25519-sign-unalign", "openssl", sz, off, s);
            }

            for (const SigImpl& im : kImpls) {
                double v = auto_bench("ed25519-verify-unalign", [&, im, m, sz] {
                    g_sink ^= im.verify(pub, m, sz, sig_for) ? 1 : 0;
                }, target_ms, rounds);
                emit_row("ed25519-verify-unalign", im.name, sz, off, v);
            }
            {
                double v = auto_bench("ed25519-verify-unalign", [&, m, sz] {
                    EVP_MD_CTX_reset(mctx);
                    EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ossl_pubkey);
                    int r = EVP_DigestVerify(mctx, sig_for, 64, m, sz);
                    g_sink ^= r;
                }, target_ms, rounds);
                emit_row("ed25519-verify-unalign", "openssl", sz, off, v);
            }
        }
    }

    // ── 3b. 批量验签基准 (N=64, 非对齐消息) ─────────────────────────
    printf("\n=== unalign batch verify N=64 (len x offset) ===\n");
    for (size_t sz : perf_sizes) {
        const MsgBuf& b = find_msg(bufs, sz);
        for (int off : kPerfOffsets) {
            BatchCtx bc;
            batch_build(bc, b.ptr(off), sz);

            double bb = auto_bench("ed25519-batch-unalign", [&] {
                g_sink ^= jpssl::ed25519_batch_verify(
                    bc.pub_ptrs.data(), bc.msg_ptrs.data(), bc.lens.data(), bc.sig_ptrs.data(),
                    kBatchN) ? 1 : 0;
            }, target_ms, rounds, 1);
            emit_row("ed25519-batch-unalign", "jpssl-batch64", sz, off, bb);

            double bo = auto_bench("ed25519-batch-unalign", [&, m = b.ptr(off), sz] {
                int r = 0;
                for (int i = 0; i < kBatchN; ++i) {
                    EVP_MD_CTX_reset(mctx);
                    EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, bc.ovpubs[i]);
                    r ^= EVP_DigestVerify(mctx, bc.sigs[i].data(), 64, m, sz);
                }
                g_sink ^= r;
            }, target_ms, rounds, 1);
            emit_row("ed25519-batch-unalign", "openssl", sz, off, bo);
        }
    }

    // ── 4. CSV 输出 ──────────────────────────────────────────────────
    std::filesystem::create_directories("benchmarks/results");
    const char* csv_path = std::getenv("BENCH_CSV_PATH");
    if (!csv_path) csv_path = "benchmarks/results/bench_ed25519_unalign.csv";
    FILE* csv = std::fopen(csv_path, "w");
    if (!csv) {
        printf("ERROR: cannot open %s\n", csv_path);
        return 2;
    }
    std::fprintf(csv, "algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec\n");
    for (const Row& r : g_rows) {
        std::fprintf(csv, "%s,%s,%zu,%d,%.2f,%.2f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.offset, r.ns, 1e9 / r.ns);
    }
    std::fclose(csv);
    printf("\nCSV written: %s (%zu rows)\n", csv_path, g_rows.size());

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(ossl_pubkey);
    EVP_PKEY_free(ossl_key);
    printf("(sink=%d, self-test PASS=%d, skips=%d)\n", g_sink, g_pass, g_skip_count);
    return 0;
}
