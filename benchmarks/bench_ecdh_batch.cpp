// bench_ecdh_batch.cpp - 批量 ECDH vs 逐条（P-256/P-384）
// 覆盖: 相同输入下逐条循环 vs 批量 API（每 16 条一块、块内 2 次求逆），
// 另附 OpenSSL ECDH_compute_key 逐条参考值。
// 编译需链接 OpenSSL libcrypto（仅测试端对照，jpssl 库本身不依赖 OpenSSL）。
#include "ecdsa.hpp"

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using Clock = std::chrono::steady_clock;

static volatile int g_sink = 0;

// 测量一次调用处理 items_per_call 条的平均单条耗时（3 轮取最小）。
template <typename F>
static double bench_per_item(F&& f, int items_per_call, double target_ms = 200.0) {
    f();
    auto t0 = Clock::now();
    for (int i = 0; i < 8; ++i) f();
    auto t1 = Clock::now();
    double est_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / 8.0;
    long long iters = 1;
    if (est_ns > 0.0) {
        iters = static_cast<long long>(target_ms * 1e6 / est_ns);
        if (iters < 1) iters = 1;
        if (iters > 2000000) iters = 2000000;
    }
    double best = 1e300;
    for (int r = 0; r < 3; ++r) {
        auto s = Clock::now();
        for (long long i = 0; i < iters; ++i) f();
        auto e = Clock::now();
        double per = std::chrono::duration<double, std::nano>(e - s).count() / iters / items_per_call;
        if (per < best) best = per;
    }
    return best;
}

static EC_KEY* make_key_from_bin(int nid, const uint8_t* priv, int priv_len,
                                 const uint8_t* pub, int pub_len) {
    EC_KEY* key = EC_KEY_new_by_curve_name(nid);
    BIGNUM* d = BN_bin2bn(priv, priv_len, nullptr);
    EC_KEY_set_private_key(key, d);
    BN_free(d);
    const EC_GROUP* grp = EC_KEY_get0_group(key);
    EC_POINT* P = EC_POINT_new(grp);
    BIGNUM* x = BN_bin2bn(pub, pub_len / 2, nullptr);
    BIGNUM* y = BN_bin2bn(pub + pub_len / 2, pub_len / 2, nullptr);
    EC_POINT_set_affine_coordinates(grp, P, x, y, nullptr);
    EC_KEY_set_public_key(key, P);
    EC_POINT_free(P);
    BN_free(x);
    BN_free(y);
    return key;
}

template <int NBYTES, int NPUB>
struct curve_ops {
    void (*keygen)(uint8_t* pub, uint8_t* priv);
    bool (*ecdh)(uint8_t* shared, const uint8_t* priv, const uint8_t* pub);
    bool (*ecdh_batch)(uint8_t* shared, const uint8_t* priv, const uint8_t* pub, int count);
};

template <int NBYTES, int NPUB>
static void bench_curve(const char* label, const curve_ops<NBYTES, NPUB>& ops,
                        int nid, int count) {
    std::vector<uint8_t> priv((size_t)count * NBYTES);
    std::vector<uint8_t> pub((size_t)count * NPUB);
    std::vector<uint8_t> sh1((size_t)count * NBYTES);
    std::vector<uint8_t> sh2((size_t)count * NBYTES);
    for (int i = 0; i < count; ++i)
        ops.keygen(pub.data() + (size_t)i * NPUB, priv.data() + (size_t)i * NBYTES);

    char name[96];
    std::snprintf(name, sizeof name, "%s N=%d per-op (jpssl)", label, count);
    double per = bench_per_item([&] {
        for (int i = 0; i < count; ++i)
            ops.ecdh(sh1.data() + (size_t)i * NBYTES,
                     priv.data() + (size_t)i * NBYTES,
                     pub.data() + (size_t)i * NPUB);
    }, count);
    printf("%-38s %12.1f ns/op %10.2f Kops/s\n", name, per, 1e6 / per);

    std::snprintf(name, sizeof name, "%s N=%d batch  (jpssl)", label, count);
    double bat = bench_per_item([&] {
        ops.ecdh_batch(sh2.data(), priv.data(), pub.data(), count);
    }, count);
    printf("%-38s %12.1f ns/op %10.2f Kops/s\n", name, bat, 1e6 / bat);
    printf("%-38s %11.2fx\n", "batch speedup vs per-op", per / bat);

    bool same = std::memcmp(sh1.data(), sh2.data(), (size_t)count * NBYTES) == 0;
    printf("%-38s %s\n", "batch == per-op check", same ? "PASS" : "FAIL");

    EC_KEY* a = make_key_from_bin(nid, priv.data(), NBYTES, pub.data(), NPUB);
    EC_KEY* b = make_key_from_bin(nid, priv.data() + NBYTES, NBYTES,
                                  pub.data() + NPUB, NPUB);
    uint8_t out[NBYTES];
    double ossl = bench_per_item([&] {
        ECDH_compute_key(out, NBYTES, EC_KEY_get0_public_key(b), a, nullptr);
    }, 1);
    printf("%-38s %12.1f ns/op %10.2f Kops/s\n", "OpenSSL ECDH per-op", ossl, 1e6 / ossl);
    printf("%-38s %11.2fx\n", "jpssl batch vs OpenSSL", ossl / bat);
    printf("\n");
    g_sink ^= (int)per ^ (int)bat ^ (int)ossl ^ (int)same;

    EC_KEY_free(a);
    EC_KEY_free(b);
}

int main() {
    printf("=== ECDH: batch vs per-op (jpssl), OpenSSL reference ===\n\n");

    const curve_ops<32, 64> p256 = {
        jpssl::ecdsa_p256_keygen,
        jpssl::ecdsa_p256_ecdh,
        jpssl::ecdsa_p256_ecdh_batch,
    };
    const curve_ops<48, 96> p384 = {
        jpssl::ecdsa_p384_keygen,
        jpssl::ecdsa_p384_ecdh,
        jpssl::ecdsa_p384_ecdh_batch,
    };

    bench_curve("P-256", p256, NID_X9_62_prime256v1, 100);
    bench_curve("P-256", p256, NID_X9_62_prime256v1, 1000);
    bench_curve("P-384", p384, NID_secp384r1, 100);
    bench_curve("P-384", p384, NID_secp384r1, 1000);

    printf("(sink=%d)\n", g_sink);
    return 0;
}
