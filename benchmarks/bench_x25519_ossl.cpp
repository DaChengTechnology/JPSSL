// bench_x25519_ossl.cpp - jpssl X25519 vs OpenSSL X25519 吞吐量基准
// 覆盖: 公钥生成(标量 x 基点) / ECDH 共享密钥(标量 x 对端点) / 密钥对生成
// 说明: OpenSSL 4.x 不再公开裸 X25519() 函数, OpenSSL 侧使用 EVP raw-key API (与测试一致)。
// 编译需链接 OpenSSL libcrypto (仅基准对照用, jpssl 库本身不依赖 OpenSSL)。
#include "x25519.hpp"

#include <openssl/evp.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>

using Clock = std::chrono::steady_clock;

// 防止编译器把纯函数调用优化掉
static volatile int g_sink = 0;

// 自适应迭代次数: 每轮约 target_ms, 取 3 轮中最小
template <typename F>
static double auto_bench(const char* name, F&& f, double target_ms = 300.0, int rounds = 3) {
    f();
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
    printf("%-36s %12.0f ns/op %12.1f Kops/s\n", name, best, 1e6 / best);
    return best;
}

int main() {
    printf("=== X25519: jpssl vs OpenSSL (%s) ===\n", OPENSSL_VERSION_TEXT);

    uint8_t alice_priv[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
        0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
        0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
    };
    uint8_t bob_pub[32] = {
        0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
        0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
        0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
        0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
    };

    // ---- 互操作自检: jpssl 与 OpenSSL 共享密钥一致 (防止基准测量错误实现) ----
    uint8_t jp_ss[32], ossl_ss[32];
    jpssl::x25519_scalar_mult(jp_ss, alice_priv, bob_pub);

    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, bob_pub, 32);
    EVP_PKEY* ours = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, alice_priv, 32);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ours, NULL);
    bool interop = peer && ours && ctx
            && EVP_PKEY_derive_init(ctx) == 1
            && EVP_PKEY_derive_set_peer(ctx, peer) == 1;
    size_t sslen = 32;
    interop = interop && EVP_PKEY_derive(ctx, ossl_ss, &sslen) == 1 && sslen == 32;
    interop = interop && memcmp(jp_ss, ossl_ss, 32) == 0;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(ours);
    printf("jpssl shared secret == OpenSSL        : %s\n", interop ? "PASS" : "FAIL");
    if (!interop) return 1;

    uint8_t out[32];

    // ---- jpssl ----
    double jp_pub = auto_bench("jpssl pubkey (scalar*base)", [&] {
        jpssl::x25519_scalar_mult(out, alice_priv, nullptr);
        g_sink ^= out[0];
    });
    double jp_ecdh = auto_bench("jpssl ECDH (scalar*peer)", [&] {
        jpssl::x25519_scalar_mult(out, alice_priv, bob_pub);
        g_sink ^= out[0];
    });
    uint8_t pub[32], priv[32];
    double jp_keygen = auto_bench("jpssl keypair (w/ RNG)", [&] {
        jpssl::x25519_generate_keypair(pub, priv);
        g_sink ^= pub[0] ^ priv[0];
    });

    // ---- OpenSSL ----
    double ossl_pub = auto_bench("OpenSSL pubkey (EVP raw)", [&] {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, alice_priv, 32);
        size_t len = 32;
        if (pkey) EVP_PKEY_get_raw_public_key(pkey, out, &len);
        EVP_PKEY_free(pkey);
        g_sink ^= out[0];
    });
    double ossl_ecdh = auto_bench("OpenSSL ECDH (EVP derive)", [&] {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, alice_priv, 32);
        EVP_PKEY* p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, bob_pub, 32);
        EVP_PKEY_CTX* c = pkey ? EVP_PKEY_CTX_new(pkey, NULL) : NULL;
        size_t len = 32;
        if (c && p && EVP_PKEY_derive_init(c) == 1
                && EVP_PKEY_derive_set_peer(c, p) == 1)
            EVP_PKEY_derive(c, out, &len);
        EVP_PKEY_CTX_free(c);
        EVP_PKEY_free(p);
        EVP_PKEY_free(pkey);
        g_sink ^= out[0];
    });
    double ossl_keygen = auto_bench("OpenSSL keygen (EVP_Q_keygen)", [&] {
        EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
        size_t len = 32;
        if (pkey) EVP_PKEY_get_raw_public_key(pkey, out, &len);
        EVP_PKEY_free(pkey);
        g_sink ^= out[0];
    });

    printf("\n--- 吞吐量对比 (jpssl / OpenSSL) ---\n");
    printf("pubkey   : %.2fx\n", ossl_pub / jp_pub);
    printf("ECDH     : %.2fx\n", ossl_ecdh / jp_ecdh);
    printf("keygen   : %.2fx\n", ossl_keygen / jp_keygen);
    return 0;
}
