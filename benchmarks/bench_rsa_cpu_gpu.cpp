// bench_rsa_cpu_gpu.cpp — RSA CPU vs GPU vs OpenSSL 综合性能基准
//
// 覆盖:
//   1. RSA-2048 私钥运算 c^d mod n:
//        OpenSSL BN_mod_exp / jpssl CPU 标量 / jpssl CPU AVX2 批量 / jpssl GPU 批量
//   2. RSA-2048 公钥运算 m^e mod n (e=65537): OpenSSL / jpssl CPU
//   3. RSA-4096 私钥运算: OpenSSL / jpssl CPU 标量 / jpssl CPU AVX2 批量
//        (GPU 4096 为 CPU fallback, 无 kernel)
//
// 构建: cmake -DJP_ENABLE_BENCH=ON .. && make bench_rsa_cpu_gpu
// 运行: ./bench_rsa_cpu_gpu
#include "rsa.hpp"
#include "rsa_simd.hpp"
#include "cpu_features.hpp"
#include <openssl/bn.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

using namespace jpssl;
using namespace std::chrono;

static double ms_now() {
    return duration<double, std::milli>(
        high_resolution_clock::now().time_since_epoch()).count();
}

template<typename F>
static double measure_ms(F&& f, int reps) {
    double t0 = ms_now();
    for (int r = 0; r < reps; ++r) f();
    double t1 = ms_now();
    return (t1 - t0) / reps;
}

static void random_bn(rsa_bignum& bn, std::mt19937_64& rng, int bitlen) {
    for (int i = 0; i < RSA_2048_WORDS; ++i) bn.d[i] = rng();
    bn.d[0] |= 1ULL;
    if (bitlen == 0) { bn.d[RSA_2048_WORDS-1] |= (1ULL<<63); }
    else {
        const int w = (bitlen-1)>>6, b = (bitlen-1)&63;
        bn.d[w] |= (1ULL<<b);
        for (int i = w+1; i < RSA_2048_WORDS; ++i) bn.d[i] = 0;
        if (b < 63) bn.d[w] &= (1ULL<<(b+1))-1;
    }
}
static void random_bn4096(rsa4096_bignum& bn, std::mt19937_64& rng) {
    for (int i = 0; i < RSA_4096_WORDS; ++i) bn.d[i] = rng();
    bn.d[0] |= 1ULL;
    bn.d[RSA_4096_WORDS-1] |= (1ULL<<63);
}

int main() {
    std::printf("═══ RSA Benchmark: jpssl CPU vs jpssl GPU vs OpenSSL ═══\n");
    auto feat = cpu_features::detect();
    std::printf("CPU: AVX2=%s AVX512=%s | OpenSSL %s\n\n",
                feat.avx2?"Y":"N", feat.avx512?"Y":"N", OpenSSL_version(OPENSSL_VERSION));

    std::mt19937_64 rng(20260731);
    BN_CTX* bctx = BN_CTX_new();

    // ─────────────────────────────────────────────────────────────────
    //  1. RSA-2048 私钥运算 c^d mod n
    // ─────────────────────────────────────────────────────────────────
    std::printf("═══ RSA-2048 私钥运算 c^d mod n ═══\n");
    {
        rsa_bignum n, d, e(rsa_bignum::from_uint64(65537));
        random_bn(n, rng, 0); random_bn(d, rng, 0);
        auto mctx = rsa_mont_init(n);
        rsa_bignum base; random_bn(base, rng, 0);
        { rsa_bignum t; bn_mod(t, base, n); base = t; }
        uint8_t baseb[256]; base.to_bytes(baseb);
        std::vector<uint8_t> bases(1024*256), res(1024*256);
        for (int i = 0; i < 1024; ++i) memcpy(bases.data()+i*256, baseb, 256);

        // OpenSSL
        BIGNUM* o_n = BN_new(); BIGNUM* o_d = BN_new(); BIGNUM* o_b = BN_new();
        BN_bin2bn((const unsigned char*)baseb, 256, o_b);
        { uint8_t nb[256]; n.to_bytes(nb); BN_bin2bn(nb, 256, o_n); }
        { uint8_t db[256]; d.to_bytes(db); BN_bin2bn(db, 256, o_d); }
        BIGNUM* c = BN_new();
        double t_ossl = measure_ms([&]{ BN_mod_exp(c, o_b, o_d, o_n, bctx); }, 50);
        BN_free(c); BN_free(o_n); BN_free(o_d); BN_free(o_b);

        // jpssl CPU 标量
        rsa_bignum out;
        double t_jp = measure_ms([&]{ rsa_mont_modpow(out, base, d, mctx, n); }, 50);

        // jpssl CPU 标量 + 4-bit 窗口化
        double t_win = measure_ms([&]{ rsa_mont_modpow_win(out, base, d, mctx, n); }, 50);

        // jpssl CPU OpenMP 4线程 批量 (n=256)
        double t_omp = 0;
        if (feat.avx2) {
            t_omp = measure_ms([&]{ rsa_batch_decrypt_dispatch(n.d, d.d, mctx.R2_mod_m.d, mctx.R_mod_m.d, mctx.m_prime, bases.data(), res.data(), 256, RSA_2048_WORDS, 2048); }, 5);
        }

        // jpssl CPU AVX2 批量 (仅在支持时)
        double t_b4=0, t_b64=0, t_b256=0;
        if (feat.avx2) {
            t_b4   = measure_ms([&]{ rsa_batch_decrypt_dispatch(n.d, d.d, mctx.R2_mod_m.d, mctx.R_mod_m.d, mctx.m_prime, bases.data(), res.data(), 4, RSA_2048_WORDS, 2048); }, 30);
            t_b64  = measure_ms([&]{ rsa_batch_decrypt_dispatch(n.d, d.d, mctx.R2_mod_m.d, mctx.R_mod_m.d, mctx.m_prime, bases.data(), res.data(), 64, RSA_2048_WORDS, 2048); }, 10);
            t_b256 = measure_ms([&]{ rsa_batch_decrypt_dispatch(n.d, d.d, mctx.R2_mod_m.d, mctx.R_mod_m.d, mctx.m_prime, bases.data(), res.data(), 256, RSA_2048_WORDS, 2048); }, 5);
        }

        // jpssl GPU 批量 (仅在 MUSA 启用时)
        double t_g4=0, t_g64=0, t_g256=0, t_g1024=0;
#ifdef JP_MUSA
        t_g4    = measure_ms([&]{ musa_rsa_batch_modpow(n, d, mctx, bases.data(), res.data(), 4); }, 3);
        t_g64   = measure_ms([&]{ musa_rsa_batch_modpow(n, d, mctx, bases.data(), res.data(), 64); }, 3);
        t_g256  = measure_ms([&]{ musa_rsa_batch_modpow(n, d, mctx, bases.data(), res.data(), 256); }, 3);
        t_g1024 = measure_ms([&]{ musa_rsa_batch_modpow(n, d, mctx, bases.data(), res.data(), 1024); }, 3);
#endif

        std::printf("  %-28s %10s %12s\n", "实现", "ms/op", "ops/s");
        std::printf("  %-28s %10.3f %12.1f\n", "OpenSSL BN_mod_exp", t_ossl, 1000.0/t_ossl);
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU 标量", t_jp, 1000.0/t_jp);
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU 标量+窗口化", t_win, 1000.0/t_win);
        if (feat.avx2)
            std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU OpenMP×4 batch=256", t_omp, 1000.0*256/t_omp);
        if (feat.avx2) {
            std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU AVX2 batch=4", t_b4, 1000.0*4/t_b4);
            std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU AVX2 batch=64", t_b64, 1000.0*64/t_b64);
            std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU AVX2 batch=256", t_b256, 1000.0*256/t_b256);
        }
#ifdef JP_MUSA
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl GPU batch=4", t_g4, 1000.0*4/t_g4);
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl GPU batch=64", t_g64, 1000.0*64/t_g64);
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl GPU batch=256", t_g256, 1000.0*256/t_g256);
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl GPU batch=1024", t_g1024, 1000.0*1024/t_g1024);
#endif
    }

    // ─────────────────────────────────────────────────────────────────
    //  2. RSA-2048 公钥运算 m^e mod n
    // ─────────────────────────────────────────────────────────────────
    std::printf("\n═══ RSA-2048 公钥运算 m^e mod n (e=65537) ═══\n");
    {
        rsa_bignum n, e(rsa_bignum::from_uint64(65537));
        random_bn(n, rng, 0);
        auto mctx = rsa_mont_init(n);
        rsa_bignum base; random_bn(base, rng, 0);
        { rsa_bignum t; bn_mod(t, base, n); base = t; }
        uint8_t baseb[256]; base.to_bytes(baseb);

        BIGNUM* o_n = BN_new(); BIGNUM* o_e = BN_new(); BIGNUM* o_b = BN_new();
        { uint8_t nb[256]; n.to_bytes(nb); BN_bin2bn(nb, 256, o_n); }
        BN_set_word(o_e, 65537);
        BN_bin2bn((const unsigned char*)baseb, 256, o_b);
        BIGNUM* c = BN_new();
        double t_ossl = measure_ms([&]{ BN_mod_exp(c, o_b, o_e, o_n, bctx); }, 300);
        BN_free(c); BN_free(o_n); BN_free(o_e); BN_free(o_b);

        rsa_bignum out;
        double t_jp = measure_ms([&]{ rsa_mont_modpow(out, base, e, mctx, n); }, 300);

        // 批量数据
        std::vector<uint8_t> pk_bases(1024*256), pk_res(1024*256);
        for (int i = 0; i < 1024; ++i) memcpy(pk_bases.data()+i*256, baseb, 256);

        // OpenMP×4 批量 (e=65537, exp_bits=17)
        double t_omp = 0;
        if (feat.avx2)
            t_omp = measure_ms([&]{ rsa_batch_decrypt_dispatch(n.d, e.d, mctx.R2_mod_m.d, mctx.R_mod_m.d, mctx.m_prime, pk_bases.data(), pk_res.data(), 256, RSA_2048_WORDS, e.bit_length()); }, 20);

        // GPU 批量
        double t_g64=0, t_g256=0, t_g1024=0;
#ifdef JP_MUSA
        t_g64   = measure_ms([&]{ musa_rsa_batch_modpow(n, e, mctx, pk_bases.data(), pk_res.data(), 64); }, 5);
        t_g256  = measure_ms([&]{ musa_rsa_batch_modpow(n, e, mctx, pk_bases.data(), pk_res.data(), 256); }, 5);
        t_g1024 = measure_ms([&]{ musa_rsa_batch_modpow(n, e, mctx, pk_bases.data(), pk_res.data(), 1024); }, 5);
#endif

        std::printf("  %-28s %10.3f %12.1f\n", "OpenSSL BN_mod_exp", t_ossl, 1000.0/t_ossl);
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU 标量", t_jp, 1000.0/t_jp);
        if (feat.avx2)
            std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU OpenMP×4 batch=256", t_omp, 1000.0*256/t_omp);
#ifdef JP_MUSA
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl GPU batch=64", t_g64, 1000.0*64/t_g64);
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl GPU batch=256", t_g256, 1000.0*256/t_g256);
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl GPU batch=1024", t_g1024, 1000.0*1024/t_g1024);
#endif
    }

    // ─────────────────────────────────────────────────────────────────
    //  3. RSA-4096 私钥运算
    // ─────────────────────────────────────────────────────────────────
    std::printf("\n═══ RSA-4096 私钥运算 c^d mod n ═══\n");
    {
        rsa4096_bignum n4, d4;
        random_bn4096(n4, rng); random_bn4096(d4, rng);
        auto mctx4 = rsa4096_mont_init(n4);
        rsa4096_bignum base4; random_bn4096(base4, rng);
        { rsa4096_bignum t; bn_mod(t, base4, n4); base4 = t; }
        uint8_t base4b[512]; base4.to_bytes(base4b);
        std::vector<uint8_t> bases4(64*512), res4(64*512);
        for (int i = 0; i < 64; ++i) memcpy(bases4.data()+i*512, base4b, 512);

        BIGNUM* o_n = BN_new(); BIGNUM* o_d = BN_new(); BIGNUM* o_b = BN_new();
        { uint8_t nb[512]; n4.to_bytes(nb); BN_bin2bn(nb, 512, o_n); }
        { uint8_t db[512]; d4.to_bytes(db); BN_bin2bn(db, 512, o_d); }
        BN_bin2bn((const unsigned char*)base4b, 512, o_b);
        BIGNUM* c = BN_new();
        double t_ossl = measure_ms([&]{ BN_mod_exp(c, o_b, o_d, o_n, bctx); }, 30);
        BN_free(c); BN_free(o_n); BN_free(o_d); BN_free(o_b);

        rsa4096_bignum out4;
        double t_jp = measure_ms([&]{ rsa4096_mont_modpow(out4, base4, d4, mctx4, n4); }, 30);

        double t_b4=0, t_b64=0;
        if (feat.avx2) {
            t_b4  = measure_ms([&]{ rsa_batch_decrypt_dispatch(n4.d, d4.d, mctx4.R2_mod_m.d, mctx4.R_mod_m.d, mctx4.m_prime, bases4.data(), res4.data(), 4, RSA_4096_WORDS, 4096); }, 10);
            t_b64 = measure_ms([&]{ rsa_batch_decrypt_dispatch(n4.d, d4.d, mctx4.R2_mod_m.d, mctx4.R_mod_m.d, mctx4.m_prime, bases4.data(), res4.data(), 64, RSA_4096_WORDS, 4096); }, 5);
        }

        std::printf("  %-28s %10.3f %12.1f\n", "OpenSSL BN_mod_exp", t_ossl, 1000.0/t_ossl);
        std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU 标量", t_jp, 1000.0/t_jp);
        if (feat.avx2) {
            std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU AVX2 batch=4", t_b4, 1000.0*4/t_b4);
            std::printf("  %-28s %10.3f %12.1f\n", "jpssl CPU AVX2 batch=64", t_b64, 1000.0*64/t_b64);
        }
    }

    // ─────────────────────────────────────────────────────────────────
    //  4. RSA-4096 公钥运算 m^e mod n
    // ─────────────────────────────────────────────────────────────────
    std::printf("\n═══ RSA-4096 公钥运算 m^e mod n (e=65537) ═══\n");
    {
        rsa4096_bignum n4, e4(rsa4096_bignum::from_uint64(65537)), base4;
        random_bn4096(n4, rng);
        random_bn4096(base4, rng);
        { rsa4096_bignum t; bn_mod(t, base4, n4); base4 = t; }
        auto mctx4 = rsa4096_mont_init(n4);
        uint8_t base4b[512]; base4.to_bytes(base4b);
        std::vector<uint8_t> bases4(1024*512), res4(1024*512);
        for (int i = 0; i < 1024; ++i) memcpy(bases4.data()+i*512, base4b, 512);

        // OpenSSL
        BIGNUM* o_n = BN_new(); BIGNUM* o_e = BN_new(); BIGNUM* o_b = BN_new();
        { uint8_t nb[512]; n4.to_bytes(nb); BN_bin2bn(nb, 512, o_n); }
        BN_set_word(o_e, 65537);
        BN_bin2bn((const unsigned char*)base4b, 512, o_b);
        BIGNUM* c = BN_new();
        double t_ossl = measure_ms([&]{ BN_mod_exp(c, o_b, o_e, o_n, bctx); }, 100);
        BN_free(c); BN_free(o_n); BN_free(o_e); BN_free(o_b);

        // jpssl CPU 标量
        rsa4096_bignum out4;
        double t_jp = measure_ms([&]{ rsa4096_mont_modpow(out4, base4, e4, mctx4, n4); }, 100);

        // OpenMP×4 批量 (e=65537, 17-bit 指数)
        double t_omp = 0;
        if (feat.avx2)
            t_omp = measure_ms([&]{ rsa_batch_decrypt_dispatch(n4.d, e4.d, mctx4.R2_mod_m.d, mctx4.R_mod_m.d, mctx4.m_prime, bases4.data(), res4.data(), 128, RSA_4096_WORDS, e4.bit_length()); }, 20);

        // GPU 4096 kernel
        double t_g16=0, t_g64=0, t_g256=0;
#ifdef JP_MUSA
        t_g16  = measure_ms([&]{ musa4096_rsa_batch_modpow(n4, e4, mctx4, bases4.data(), res4.data(), 16); }, 3);
        t_g64  = measure_ms([&]{ musa4096_rsa_batch_modpow(n4, e4, mctx4, bases4.data(), res4.data(), 64); }, 3);
        t_g256 = measure_ms([&]{ musa4096_rsa_batch_modpow(n4, e4, mctx4, bases4.data(), res4.data(), 256); }, 3);
#endif

        std::printf("  %-28s %10.4f %12.1f\n", "OpenSSL BN_mod_exp", t_ossl, 1000.0/t_ossl);
        std::printf("  %-28s %10.4f %12.1f\n", "jpssl CPU 标量", t_jp, 1000.0/t_jp);
        if (feat.avx2)
            std::printf("  %-28s %10.4f %12.1f\n", "jpssl CPU OpenMP×4 batch=128", t_omp, 1000.0*128/t_omp);
#ifdef JP_MUSA
        std::printf("  %-28s %10.4f %12.1f\n", "jpssl GPU batch=16", t_g16, 1000.0*16/t_g16);
        std::printf("  %-28s %10.4f %12.1f\n", "jpssl GPU batch=64", t_g64, 1000.0*64/t_g64);
        std::printf("  %-28s %10.4f %12.1f\n", "jpssl GPU batch=256", t_g256, 1000.0*256/t_g256);
#endif
    }

#ifdef JP_MUSA
    // ─────────────────────────────────────────────────────────────────
    //  5. RSA-4096 CRT GPU 批量解密 (复用 2048 kernel)
    //     密钥首次运行生成 (~5-10 分钟) 并缓存到构建目录 rsa4096_crt_key.bin
    // ─────────────────────────────────────────────────────────────────
    std::printf("\n═══ RSA-4096 CRT GPU 批量解密 ═══\n");
    {
        rsa4096_crt_key crt;
        bool have_key = false;
        FILE* kf = std::fopen("rsa4096_crt_key.bin", "rb");
        if (kf) { have_key = (fread(&crt, sizeof(crt), 1, kf) == 1); fclose(kf); }
        if (!have_key) {
            rsa4096_public_key pub;
            std::printf("  [生成 4096 CRT 密钥... 首次约 5-10 分钟]\n");
            fflush(stdout);
            if (!rsa4096_keygen_crt(pub, crt)) { std::printf("  [4096 CRT keygen FAIL]\n"); }
            else {
                kf = std::fopen("rsa4096_crt_key.bin", "wb");
                if (kf) { fwrite(&crt, sizeof(crt), 1, kf); fclose(kf); }
                std::printf("  [密钥已缓存到 rsa4096_crt_key.bin]\n");
            }
        }
        rsa4096_bignum e(rsa4096_bignum::from_uint64(65537));
        rsa4096_public_key pub; pub.n = crt.n; pub.e = e;
        std::vector<uint8_t> pt = {'h','e','l','l','o'};
        uint8_t ct[512];
        rsa4096_encrypt(pub, pt, ct);
        std::vector<uint8_t> cts(256*512), pts(256*512);
        for (int i = 0; i < 256; ++i) memcpy(cts.data()+i*512, ct, 512);

        double t64  = measure_ms([&]{ musa4096_crt_batch_decrypt(crt, cts.data(), pts.data(), 64); }, 2);
        double t128 = measure_ms([&]{ musa4096_crt_batch_decrypt(crt, cts.data(), pts.data(), 128); }, 2);
        double t256 = measure_ms([&]{ musa4096_crt_batch_decrypt(crt, cts.data(), pts.data(), 256); }, 2);

        std::printf("  %-28s %10.0f %12.1f\n", "CRT GPU batch=64", t64, 1000.0*64/t64);
        std::printf("  %-28s %10.0f %12.1f\n", "CRT GPU batch=128", t128, 1000.0*128/t128);
        std::printf("  %-28s %10.0f %12.1f\n", "CRT GPU batch=256", t256, 1000.0*256/t256);
    }
#endif

    BN_CTX_free(bctx);
    std::printf("\nDone.\n");
    return 0;
}
