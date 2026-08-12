// bench_ed448_unalign.cpp — Ed448 非对齐(un-aligned)测试/基准对比组: jpssl vs OpenSSL
//
// 非对齐组定义 (相对 bench_ed448.cpp 的对齐基线):
//   1. 非对齐消息长度 : 3 / 999 / 32761 (签名消息), 32 作为对照控制
//   2. 非对齐指针 offset: 消息起始偏移 1/3
//      - 自检覆盖 offset 1/3/7
//      - 性能覆盖 offset 0(对齐对照) 与 3
//   3. 自检 (始终执行, 任一 FAIL 非零退出且不输出 CSV):
//      S1. 非对齐消息 jpssl 签名 → OpenSSL 验签 (size x offset = 3/999/32761 x 1/3/7)
//      S2. 非对齐消息 OpenSSL 签名 → jpssl 验签 (同上矩阵)
//      S3. 32B offset=0 对照控制, 两方向互验 (对齐基线 sanity)
//      S4. 确定性: size=999 时 off=3 与 off=0 (相同字节内容) 签名一致;
//          且 off=3 的签名可在 off=7 处被 jpssl 与 OpenSSL 同时验过
//      S5. 篡改签名被 jpssl 与 OpenSSL 同时拒绝 (size=3 off=7)
//      S6. jpssl 批量验签 (N=64, 消息长度 999, 偏移 1/3/7 轮换) 与
//          OpenSSL 逐条循环验签结果一致
//      S7. 显式 AVX2 批量后端 N=64 (cpu_has_avx2 时) 结果一致
//      S8. AVX512: 本机不可用 → SKIP (绝不调用)
//      keygen 不重复测 (对齐基线 bench_ed448.cpp 已测)
//   4. 性能基准: 消息长度 {3,999,32761} x offset {0,3} (sign+verify)
//      BENCH_SMOKE=1: 长度 {3} x offset {0,3}, ~80ms/轮, 1 轮
//      未设置      : 3 档, ~150ms/轮, 3 轮取最小
//
// 输出: benchmarks/results/bench_ed448_unalign.csv
//   列头: algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec
//   algo: ed448-sign-unalign / ed448-verify-unalign / ed448-batch-unalign
//   impl: jpssl / jpssl-avx2 / jpssl-batch64 / openssl
//   (batch 行 size_bytes = 消息长度 999B, offset_bytes = 3, N=64 编码在 impl 名
//    jpssl-batch64; 显式后端行 jpssl-avx2 也在 N=64 记录)
//
// 编译 (worktree 根):
//   g++ -O2 -std=c++20 -fopenmp -DJP_AVX2 -DJP_AVX512 -DJP_VAES -Iinclude -Isrc
//       benchmarks/bench_ed448_unalign.cpp /home/jp/jpssl/build-main-verify/libjpssl_cpu.a
//       -lcrypto -o /tmp/bench_ed448_unalign

#include "ed448.hpp"
#include "ed448_batch.hpp"
#include "cpu_features.hpp"

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <algorithm>
#include <array>
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

// ───────────────────────────────────────────────
// 非对齐矩阵
// ───────────────────────────────────────────────
static const std::array<size_t, 3> kUnalignSizes = {3, 999, 32761};   // 非对齐消息长度
static const std::array<size_t, 3> kSelfOffsets   = {1, 3, 7};         // 自检 offset
static const std::array<size_t, 2> kPerfOffsets   = {0, 3};            // 性能 offset (0=对齐对照, 3=非对齐)

// 确定性消息内容 (与 bench_ed448.cpp 同源算法)
static std::vector<uint8_t> g_msg(size_t n) {
    std::vector<uint8_t> m(n);
    uint64_t x = 0x9e3779b97f4a7c15ull;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        m[i] = static_cast<uint8_t>(x);
    }
    return m;
}

// 返回一个缓冲区, 消息内容 g_msg(len) 被放置在 [off, off+len), 其余区域填 0xA5
// —— 相同 (off=0 对齐 / off>0 非对齐) 的缓冲区内容完全一致, 供 offset 对照
static std::vector<uint8_t> g_msg_off(size_t len, size_t off, size_t tail_pad = 16) {
    std::vector<uint8_t> buf(off + len + tail_pad);
    std::fill(buf.begin(), buf.end(), static_cast<uint8_t>(0xA5));
    const std::vector<uint8_t> content = g_msg(len);
    std::memcpy(buf.data() + off, content.data(), len);
    return buf;
}

// ───────────────────────────────────────────────
// CSV 行记录 (含 offset 维度)
// ───────────────────────────────────────────────
struct Row {
    std::string algo, impl;
    size_t size, offset;
    double ns;
};
static std::vector<Row> g_rows;

static void emit_row(const char* algo, const char* impl, size_t size, size_t offset, double ns) {
    g_rows.push_back({algo, impl, size, offset, ns});
    std::printf("  %-24s %-14s %6zu %5zu %13.1f ns/op %12.2f ops/s\n",
                algo, impl, size, offset, ns, 1e9 / ns);
}

static int g_skip_count = 0;
static void skip(const char* msg) {
    ++g_skip_count;
    std::printf("  SKIP %s\n", msg);
}

static int g_pass = 0, g_fail = 0;
static void selfcheck(const char* name, bool ok) {
    if (ok) { ++g_pass; std::printf("  selfcheck %-46s : PASS\n", name); }
    else    { ++g_fail; std::printf("  selfcheck %-46s : FAIL\n", name); }
}

// ───────────────────────────────────────────────
// 自适应迭代微基准: 每轮约 target_ms, rounds 轮取最小值
// ───────────────────────────────────────────────
template <typename F>
static double auto_bench(const char* name, F&& f, double target_ms, int rounds) {
    f(); // 预热
    auto t0 = Clock::now();
    for (int i = 0; i < 8; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / 8;
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
    std::printf("  %-24s %-14s %6s %5s %13.1f ns/op %12.2f ops/s   (iters=%lld)\n",
                name, "", "", "", best, 1e9 / best, iters);
    return best;
}

// ───────────────────────────────────────────────
// main
// ───────────────────────────────────────────────
int main() {
    const bool smoke = (std::getenv("BENCH_SMOKE") != nullptr);
    const double target_ms = smoke ? 80.0 : 150.0;
    const int rounds       = smoke ? 1 : 3;

    const auto feats = jpssl::cpu_features::detect();
    std::printf("=== bench_ed448_unalign: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);
    std::printf("CPU : x86_64 AVX2=%d AVX512=%d NEON=%d\n",
                feats.avx2 ? 1 : 0, feats.avx512 ? 1 : 0, feats.neon ? 1 : 0);
    std::printf("mode: %s (target_ms=%.0f, rounds=%d)\n",
                smoke ? "SMOKE" : "FULL", target_ms, rounds);
    std::printf("jpssl ed448_batch_size() = %d (%s)\n", jpssl::ed448_batch_size(),
                jpssl::ed448_batch_size() == 8 ? "AVX512" :
                (jpssl::ed448_batch_size() == 4 ? "AVX2" : "scalar"));

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY* ossl_key = nullptr;
    EVP_PKEY* ossl_pubkey = nullptr;

    // ── 0. 密钥 (keygen 不重复测, 只生成一次供全程序使用) ──────────────
    uint8_t pub[57], priv[114];
    uint8_t ossl_pub[57];
    jpssl::ed448_generate_keypair(pub, priv);
    ossl_pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr, pub, 57);
    ossl_key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED448");
    size_t plen = 57;
    EVP_PKEY_get_raw_public_key(ossl_key, ossl_pub, &plen);

    // ── 1. 正确性自检 (始终执行) ────────────────────────────────────
    std::printf("\n=== unaligned interop self-tests ===\n");

    // S1. 非对齐消息 jpssl 签名 → OpenSSL 验签 (3/999/32761 x 1/3/7)
    for (size_t size : kUnalignSizes) {
        for (size_t off : kSelfOffsets) {
            const auto buf = g_msg_off(size, off);
            const uint8_t* m = buf.data() + off;
            uint8_t sig[114];
            jpssl::ed448_sign(priv, m, size, sig);
            bool ok = ossl_pubkey != nullptr
                && EVP_MD_CTX_reset(mctx) == 1
                && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ossl_pubkey) == 1
                && EVP_DigestVerify(mctx, sig, 114, m, size) == 1;
            char nm[128];
            std::snprintf(nm, sizeof nm, "ed448-unx jpssl->ossl size=%zu off=%zu", size, off);
            selfcheck(nm, ok);
        }
    }

    // S2. 非对齐消息 OpenSSL 签名 → jpssl 验签 (3/999/32761 x 1/3/7)
    for (size_t size : kUnalignSizes) {
        for (size_t off : kSelfOffsets) {
            const auto buf = g_msg_off(size, off);
            const uint8_t* m = buf.data() + off;
            uint8_t ossl_sig[114];
            size_t slen = 114;
            bool sgn = ossl_key != nullptr
                && EVP_MD_CTX_reset(mctx) == 1
                && EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ossl_key) == 1
                && EVP_DigestSign(mctx, ossl_sig, &slen, m, size) == 1
                && slen == 114;
            bool ok = sgn && jpssl::ed448_verify(ossl_pub, m, size, ossl_sig);
            char nm[128];
            std::snprintf(nm, sizeof nm, "ed448-unx ossl->jpssl size=%zu off=%zu", size, off);
            selfcheck(nm, ok);
        }
    }

    // S3. 32B offset=0 对照控制 (对齐基线 sanity, 两方向)
    {
        const auto buf = g_msg_off(32, 0);
        const uint8_t* m = buf.data();
        uint8_t sig[114];
        jpssl::ed448_sign(priv, m, 32, sig);
        bool jp2os = EVP_MD_CTX_reset(mctx) == 1
            && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ossl_pubkey) == 1
            && EVP_DigestVerify(mctx, sig, 114, m, 32) == 1;
        selfcheck("ed448-unx control(32B,off=0) jpssl->ossl", jp2os);

        uint8_t ossl_sig[114];
        size_t slen = 114;
        bool sgn = EVP_MD_CTX_reset(mctx) == 1
            && EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ossl_key) == 1
            && EVP_DigestSign(mctx, ossl_sig, &slen, m, 32) == 1 && slen == 114;
        selfcheck("ed448-unx control(32B,off=0) ossl->jpssl", sgn && jpssl::ed448_verify(ossl_pub, m, 32, ossl_sig));
    }

    // S4. 确定性 + offset 等价性 (size=999: off3 与 off0 内容一致 → 签名一致;
    //      且 off3 的签名可在 off7 处被 jpssl 与 OpenSSL 同时验过)
    {
        const size_t size = 999;
        const auto b0 = g_msg_off(size, 0);
        const auto b3 = g_msg_off(size, 3);
        const auto b7 = g_msg_off(size, 7);
        uint8_t s0[114], s3[114];
        jpssl::ed448_sign(priv, b0.data(), size, s0);
        jpssl::ed448_sign(priv, b3.data() + 3, size, s3);
        selfcheck("ed448-unx sig(off3)==sig(off0) deterministic size=999",
                  std::memcmp(s0, s3, 114) == 0);
        const uint8_t* m7 = b7.data() + 7;
        bool cv = jpssl::ed448_verify(pub, m7, size, s3)
            && EVP_MD_CTX_reset(mctx) == 1
            && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ossl_pubkey) == 1
            && EVP_DigestVerify(mctx, s3, 114, m7, size) == 1;
        selfcheck("ed448-unx sig(off3) verifies at off7 jpssl+ossl size=999", cv);
    }

    // S5. 篡改签名拒绝 (size=3 off=7)
    {
        const auto buf = g_msg_off(3, 7);
        const uint8_t* m = buf.data() + 7;
        uint8_t sig[114];
        jpssl::ed448_sign(priv, m, 3, sig);
        sig[57] ^= 0x01;
        bool jp_reject = !jpssl::ed448_verify(pub, m, 3, sig);
        bool os_reject = ossl_pubkey != nullptr
            && EVP_MD_CTX_reset(mctx) == 1
            && EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ossl_pubkey) == 1
            && EVP_DigestVerify(mctx, sig, 114, m, 3) <= 0;
        selfcheck("ed448-unx tampered sig rejected jpssl+ossl size=3 off=7", jp_reject && os_reject);
    }

    // S6/S7. 批量验签数据集 (N=64, 消息长度 999, 偏移 1/3/7 轮换 → 非对齐)
    constexpr int BN = 64;
    const size_t bmsg_len = 999;
    const std::array<size_t, 3> boffsets = {1, 3, 7};
    std::vector<std::array<uint8_t, 57>>  bpubs(BN);
    std::vector<std::array<uint8_t, 114>> bprivs(BN), bsigs(BN);
    std::vector<std::vector<uint8_t>>     bbuffs(BN);
    std::vector<const uint8_t*> pubp(BN), msgp(BN), sigp(BN);
    std::vector<size_t> lens(BN, bmsg_len);
    std::vector<EVP_PKEY*> ovpubs(BN);
    for (int i = 0; i < BN; ++i) {
        const size_t off = boffsets[i % 3];
        bbuffs[i] = g_msg_off(bmsg_len, off);
        jpssl::ed448_generate_keypair(bpubs[i].data(), bprivs[i].data());
        jpssl::ed448_sign(bprivs[i].data(), bbuffs[i].data() + off, bmsg_len, bsigs[i].data());
        pubp[i] = bpubs[i].data();
        msgp[i] = bbuffs[i].data() + off;
        sigp[i] = bsigs[i].data();
        ovpubs[i] = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr, bpubs[i].data(), 57);
    }

    {
        bool batch_ok = jpssl::ed448_batch_verify(pubp.data(), msgp.data(), lens.data(),
                                                  sigp.data(), BN);
        bool loop_ok = true;
        for (int i = 0; i < BN; ++i) {
            if (ovpubs[i] == nullptr) { loop_ok = false; continue; }
            EVP_MD_CTX_reset(mctx);
            EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ovpubs[i]);
            loop_ok = loop_ok && (EVP_DigestVerify(mctx, bsigs[i].data(), 114,
                                                   msgp[i], bmsg_len) == 1);
        }
        selfcheck("ed448-unx batch64(N=64,len=999,off=1/3/7) == ossl loop", batch_ok && loop_ok);

        if (feats.avx2) {
            bool ok = jpssl::detail::ed448_batch_verify_avx2(pubp.data(), msgp.data(),
                                                             lens.data(), sigp.data(), BN);
            selfcheck("ed448-unx batch64 explicit avx2 (N=64,len=999,off=1/3/7)", ok);
        } else {
            skip("ed448-unx batch-avx2 : cpu_has_avx2()=false (不调用 AVX2 代码)");
        }
        if (feats.avx512) {
            bool ok = jpssl::detail::ed448_batch_verify_avx512(pubp.data(), msgp.data(),
                                                               lens.data(), sigp.data(), BN);
            selfcheck("ed448-unx batch64 explicit avx512 (N=64)", ok);
        } else {
            skip("ed448-unx batch-avx512 : cpu_has_avx512()=false (本机无 AVX512, 调用会 SIGILL)");
        }
    }

    if (g_fail) {
        std::printf("\ninterop FAILED (%d FAIL / %d PASS), abort without CSV\n", g_fail, g_pass);
        return 1;
    }
    std::printf("all self-tests PASS (%d)\n", g_pass);

    // ── 2. SKIP 说明 (不支持的实现, 绝不被调用) ─────────────────────
    std::printf("\n=== SKIPs (不支持的实现, 绝不被调用) ===\n");
    skip("ed448-sign/verify jpssl-avx2 : 头文件与库均未导出 Ed448 单条 SIMD 签名/验签变体 (仅批量验签后端存在)");
    skip("ed448-sign/verify jpssl-avx512 : 头文件与库均未导出 Ed448 单条 SIMD 签名/验签变体");
    if (!feats.avx512)
        skip("ed448-batch jpssl-avx512 : cpu_has_avx512()=false (本机无 AVX512, 调用会 SIGILL)");
    if (!feats.neon)
        skip("ed448 NEON : 本机为 x86_64, NEON 不可用");

    // ── 3. 性能基准: 消息长度 {3,999,32761} x offset {0,3} (sign+verify) ──
    std::vector<size_t> sizes;
    if (smoke) sizes.push_back(3);
    else sizes.assign(kUnalignSizes.begin(), kUnalignSizes.end());

    std::printf("\n=== Ed448 sign/verify (sizes=%s, offsets={0,3}) ===\n",
                smoke ? "3" : "3,999,32761");
    uint8_t sbuf[114];
    for (size_t size : sizes) {
        for (size_t off : kPerfOffsets) {
            const auto buf = g_msg_off(size, off);
            const uint8_t* m = buf.data() + off;

            // 验签基准用当前 (size,off) 消息的有效签名 (jpssl 私钥签发),
            // 保证 jpssl 与 OpenSSL 两条验签路径都运行在"有效签名"路径上
            uint8_t vfysig[114];
            jpssl::ed448_sign(priv, m, size, vfysig);

            double s1 = auto_bench("ed448-sign-unalign", [&] {
                jpssl::ed448_sign(priv, m, size, sbuf);
                g_sink ^= sbuf[0];
            }, target_ms, rounds);
            emit_row("ed448-sign-unalign", "jpssl", size, off, s1);

            double s2 = auto_bench("ed448-sign-unalign", [&] {
                size_t sl = 114;
                EVP_MD_CTX_reset(mctx);
                EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, ossl_key);
                EVP_DigestSign(mctx, sbuf, &sl, m, size);
                g_sink ^= sbuf[0];
            }, target_ms, rounds);
            emit_row("ed448-sign-unalign", "openssl", size, off, s2);

            double v1 = auto_bench("ed448-verify-unalign", [&] {
                g_sink ^= jpssl::ed448_verify(pub, m, size, vfysig) ? 1 : 0;
            }, target_ms, rounds);
            emit_row("ed448-verify-unalign", "jpssl", size, off, v1);

            double v2 = auto_bench("ed448-verify-unalign", [&] {
                EVP_MD_CTX_reset(mctx);
                EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ossl_pubkey);
                int r = EVP_DigestVerify(mctx, vfysig, 114, m, size);
                g_sink ^= r;
            }, target_ms, rounds);
            emit_row("ed448-verify-unalign", "openssl", size, off, v2);
        }
    }

    // ── 4. 批量验签基准: N=64, 消息长度 999, offset=3 (统一非对齐) ──────
    std::printf("\n=== Ed448 batch verify (N=64, size=999, offset=3) ===\n");
    {
        // 独立数据集: 统一 offset=3, 使 CSV offset_bytes 列精确
        std::vector<std::array<uint8_t, 57>>  bpubs2(BN);
        std::vector<std::array<uint8_t, 114>> bprivs2(BN), bsigs2(BN);
        std::vector<std::vector<uint8_t>>     bbuffs2(BN);
        std::vector<const uint8_t*> pubp2(BN), msgp2(BN), sigp2(BN);
        std::vector<size_t> lens2(BN, bmsg_len);
        std::vector<EVP_PKEY*> ovpubs2(BN);
        for (int i = 0; i < BN; ++i) {
            bbuffs2[i] = g_msg_off(bmsg_len, 3);
            jpssl::ed448_generate_keypair(bpubs2[i].data(), bprivs2[i].data());
            jpssl::ed448_sign(bprivs2[i].data(), bbuffs2[i].data() + 3, bmsg_len, bsigs2[i].data());
            pubp2[i] = bpubs2[i].data();
            msgp2[i] = bbuffs2[i].data() + 3;
            sigp2[i] = bsigs2[i].data();
            ovpubs2[i] = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr, bpubs2[i].data(), 57);
        }

        double b_def = auto_bench("ed448-batch-unalign", [&] {
            g_sink ^= jpssl::ed448_batch_verify(pubp2.data(), msgp2.data(), lens2.data(),
                                                sigp2.data(), BN) ? 1 : 0;
        }, target_ms, rounds);
        emit_row("ed448-batch-unalign", "jpssl-batch64", bmsg_len, 3, b_def);

        if (feats.avx2) {
            double b_a2 = auto_bench("ed448-batch-unalign", [&] {
                g_sink ^= jpssl::detail::ed448_batch_verify_avx2(
                    pubp2.data(), msgp2.data(), lens2.data(), sigp2.data(), BN) ? 1 : 0;
            }, target_ms, rounds);
            emit_row("ed448-batch-unalign", "jpssl-avx2", bmsg_len, 3, b_a2);
        }

        double b_ossl = auto_bench("ed448-batch-unalign", [&] {
            int r = 0;
            for (int i = 0; i < BN; ++i) {
                EVP_MD_CTX_reset(mctx);
                EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, ovpubs2[i]);
                r ^= EVP_DigestVerify(mctx, bsigs2[i].data(), 114, msgp2[i], bmsg_len);
            }
            g_sink ^= r;
        }, target_ms, rounds);
        emit_row("ed448-batch-unalign", "openssl", bmsg_len, 3, b_ossl);

        for (EVP_PKEY* k : ovpubs2) EVP_PKEY_free(k);
    }

    // ── 5. CSV 输出 ──────────────────────────────────────────────────
    std::filesystem::create_directories("benchmarks/results");
    const char* csv_path = "benchmarks/results/bench_ed448_unalign.csv";
    FILE* csv = std::fopen(csv_path, "w");
    if (!csv) {
        std::printf("ERROR: cannot open %s (run from worktree root)\n", csv_path);
        return 2;
    }
    std::fprintf(csv, "algo,impl,size_bytes,offset_bytes,ns_per_op,ops_per_sec\n");
    for (const Row& r : g_rows) {
        std::fprintf(csv, "%s,%s,%zu,%zu,%.2f,%.2f\n",
                     r.algo.c_str(), r.impl.c_str(), r.size, r.offset, r.ns, 1e9 / r.ns);
    }
    std::fclose(csv);
    std::printf("\nCSV written: %s (%zu rows)\n", csv_path, g_rows.size());

    for (EVP_PKEY* k : ovpubs) EVP_PKEY_free(k);
    EVP_PKEY_free(ossl_key);
    EVP_PKEY_free(ossl_pubkey);
    EVP_MD_CTX_free(mctx);
    std::printf("(sink=%d, passes=%d, skips=%d)\n", g_sink, g_pass, g_skip_count);
    return 0;
}
