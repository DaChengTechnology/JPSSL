// bench_ed25519_ossl.cpp - jpssl Ed25519 vs OpenSSL Ed25519 微基准
//
// 覆盖: 密钥生成 / 签名 / 验签 / 批量验签
// 说明: Ed25519 是签名算法, 没有加密/解密; 这里的"加解密速度"即签名/验签速度。
//
// 编译需链接 OpenSSL libcrypto (仅测试端对照, jpssl 库本身不依赖 OpenSSL)。

#include "ed25519.hpp"
#include "ed25519_batch.hpp"

#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using jpssl::ed25519_keygen;
using jpssl::ed25519_sign;
using jpssl::ed25519_verify;

using Clock = std::chrono::steady_clock;

// 阻止编译器把纯函数调用优化掉
static volatile int g_sink = 0;

static const uint8_t g_msg[256] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static constexpr size_t g_msglen = sizeof(g_msg);

// 自适应迭代次数的微基准: 每轮跑约 target_ms, 取 3 轮中最小值
template <typename F>
static double auto_bench(const char* name, F&& f, double target_ms = 250.0, int rounds = 3) {
    // 先估算单次耗时
    f();
    const int est_n = 8;
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
    printf("%-30s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    return best;
}

int main() {
    printf("=== Ed25519: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);

    // ---- 互操作性自检: 两边签名/验签互通 ----
    uint8_t jp_pub[32], jp_priv[64], jp_sig[64];
    ed25519_keygen(jp_pub, jp_priv);
    ed25519_sign(jp_priv, g_msg, g_msglen, jp_sig);
    g_sink ^= jp_pub[0] ^ jp_sig[0];

    EVP_PKEY* ossl_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, jp_pub, 32);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    bool ok1 = (ossl_pub != nullptr)
            && EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, ossl_pub) == 1
            && EVP_DigestVerify(mctx, jp_sig, 64, g_msg, g_msglen) == 1;

    EVP_PKEY* ossl_key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    uint8_t ossl_pub_buf[32];
    size_t plen = 32;
    EVP_PKEY_get_raw_public_key(ossl_key, ossl_pub_buf, &plen);
    uint8_t ossl_sig[64];
    EVP_MD_CTX_reset(mctx);
    bool sgn_ok = EVP_DigestSignInit(mctx, NULL, NULL, NULL, ossl_key) == 1;
    size_t slen = 64;
    sgn_ok = sgn_ok && EVP_DigestSign(mctx, ossl_sig, &slen, g_msg, g_msglen) == 1;
    bool ok2 = sgn_ok && slen == 64 && ed25519_verify(ossl_pub_buf, g_msg, g_msglen, ossl_sig);

    printf("OpenSSL verifies jpssl signature : %s\n", ok1 ? "PASS" : "FAIL");
    printf("jpssl verifies OpenSSL signature : %s\n", ok2 ? "PASS" : "FAIL");
    if (!ok1 || !ok2) {
        printf("interop FAILED, abort\n");
        return 1;
    }

    // ---- 批量验签数据准备: 256 组 jpssl 密钥/签名 ----
    constexpr int BN = 256;
    std::vector<std::array<uint8_t, 32>> pubs(BN);
    std::vector<std::array<uint8_t, 64>> privs(BN);
    std::vector<std::array<uint8_t, 64>> sigs(BN);
    std::vector<const uint8_t*> pub_ptrs(BN), msg_ptrs(BN, g_msg), sig_ptrs(BN);
    std::vector<size_t> lens(BN, g_msglen);
    std::vector<EVP_PKEY*> vpubs(BN);
    for (int i = 0; i < BN; ++i) {
        ed25519_keygen(pubs[i].data(), privs[i].data());
        ed25519_sign(privs[i].data(), g_msg, g_msglen, sigs[i].data());
        pub_ptrs[i] = pubs[i].data();
        sig_ptrs[i] = sigs[i].data();
        vpubs[i] = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubs[i].data(), 32);
    }
    int bs = jpssl::ed25519_batch_size();
    printf("jpssl batch backend size        : %d (%s)\n", bs, bs == 8 ? "AVX512" : "scalar");

    printf("\n%-30s %12s %14s\n", "case", "ns/op", "Kops/s");

    // ---- 密钥生成 ----
    double jp_kg = auto_bench("jpssl keygen", [] {
        uint8_t pub[32], priv[64];
        ed25519_keygen(pub, priv);
        g_sink ^= pub[0] ^ priv[0];
    });
    double os_kg = auto_bench("openssl keygen", [] {
        EVP_PKEY* k = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
        if (k != nullptr) EVP_PKEY_free(k);
    });

    // ---- 签名 ----
    double jp_sn = auto_bench("jpssl sign", [&] {
        ed25519_sign(jp_priv, g_msg, g_msglen, jp_sig);
        g_sink ^= jp_sig[0];
    });
    double os_sn = auto_bench("openssl sign", [&] {
        EVP_MD_CTX_reset(mctx);
        EVP_DigestSignInit(mctx, NULL, NULL, NULL, ossl_key);
        size_t sl = 64;
        EVP_DigestSign(mctx, ossl_sig, &sl, g_msg, g_msglen);
        g_sink ^= ossl_sig[0];
    });

    // ---- 验签 ----
    double jp_vf = auto_bench("jpssl verify", [&] {
        g_sink ^= ed25519_verify(jp_pub, g_msg, g_msglen, jp_sig) ? 1 : 0;
    });
    double os_vf = auto_bench("openssl verify", [&] {
        EVP_MD_CTX_reset(mctx);
        EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, ossl_pub);
        int r = EVP_DigestVerify(mctx, jp_sig, 64, g_msg, g_msglen);
        g_sink ^= r;
    });

    // ---- 批量验签: jpssl 批量 API vs OpenSSL 逐条循环 (OpenSSL 无批量 API) ----
    double jp_batch = auto_bench("jpssl batch verify x256", [&] {
        g_sink ^= jpssl::ed25519_batch_verify(
            pub_ptrs.data(), msg_ptrs.data(), lens.data(), sig_ptrs.data(), BN) ? 1 : 0;
    });
    double os_batch = auto_bench("openssl verify x256 (loop)", [&] {
        for (int i = 0; i < BN; ++i) {
            EVP_MD_CTX_reset(mctx);
            EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, vpubs[i]);
            int r = EVP_DigestVerify(mctx, sigs[i].data(), 64, g_msg, g_msglen);
            g_sink ^= r;
        }
    });

    printf("\n=== summary (ns/op, ratio = openssl / jpssl, >1 means jpssl faster) ===\n");
    printf("keygen  : jpssl %10.0f   openssl %10.0f   ratio %.2fx\n", jp_kg, os_kg, os_kg / jp_kg);
    printf("sign    : jpssl %10.0f   openssl %10.0f   ratio %.2fx\n", jp_sn, os_sn, os_sn / jp_sn);
    printf("verify  : jpssl %10.0f   openssl %10.0f   ratio %.2fx\n", jp_vf, os_vf, os_vf / jp_vf);
    printf("batch256: jpssl %10.0f   openssl %10.0f   ratio %.2fx (per-sig: %.0f vs %.0f ns)\n",
           jp_batch, os_batch, os_batch / jp_batch, jp_batch / BN, os_batch / BN);

    for (EVP_PKEY* k : vpubs) EVP_PKEY_free(k);
    EVP_PKEY_free(ossl_pub);
    EVP_PKEY_free(ossl_key);
    EVP_MD_CTX_free(mctx);
    (void)g_sink;
    return 0;
}
