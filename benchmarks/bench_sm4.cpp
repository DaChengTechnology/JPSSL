/**
 * bench_sm4.cpp - SM4 performance: jpssl vs OpenSSL
 *
 * Compare:
 *   1. SM4-ECB encrypt/decrypt: jpssl (scalar C++) vs OpenSSL EVP
 *   2. SM4-GCM encrypt/decrypt: jpssl (auto dispatch) vs OpenSSL SM4-GCM
 *      (falls back to SM4-CTR when the provider lacks SM4-GCM)
 *   3. Reference AES-128 (hardware accelerated): OpenSSL AES-128-ECB /
 *      AES-128-CTR / AES-128-GCM, plus jpssl AES-128-GCM
 *
 * Build:
 *   cmake --build build-win --target bench_sm4
 * Run:
 *   build-win/benchmarks/bench_sm4.exe
 */
#include "test_utils.hpp"
#include "sm4.hpp"
#include "sm4_gcm.hpp"
#include "aes.hpp"
#include "cpu_features.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <span>
#include <vector>

using namespace jpssl;
using namespace jptest;
using namespace std::chrono;

static constexpr size_t DATA_SIZE = 16ULL * 1024 * 1024; // 16 MiB

static double to_gbps(size_t bytes, double ms) {
    return (bytes / 1e9) / (ms / 1000.0);
}

template <typename F>
static double best_ms(F&& f, int iters = 5) {
    double best = 1e300;
    for (int i = 0; i < iters; ++i) {
        auto t0 = high_resolution_clock::now();
        f();
        auto t1 = high_resolution_clock::now();
        double ms = duration<double, std::milli>(t1 - t0).count();
        if (ms < best) best = ms;
    }
    return best;
}

static void print_row(const char* label, double ms, size_t bytes) {
    std::printf("  %-28s %10.2f ms  %8.3f GB/s\n",
                label, ms, to_gbps(bytes, ms));
}

static void print_ratio(const char* label, double ossl_ms, double jp_ms) {
    if (jp_ms < ossl_ms)
        std::printf("  %-28s jpssl %.2fx faster\n", label, ossl_ms / jp_ms);
    else
        std::printf("  %-28s OpenSSL %.2fx faster\n", label, jp_ms / ossl_ms);
}

// ========================================================================
//  1. SM4-ECB: jpssl (scalar) vs OpenSSL
// ========================================================================
static void bench_sm4_ecb() {
    std::printf("\n=== SM4-ECB (16 MiB, best of 5) ===\n");

    uint8_t key[16];
    RAND_bytes(key, 16);
    std::vector<uint8_t> plain(DATA_SIZE);
    RAND_bytes(plain.data(), (int)DATA_SIZE);

    sm4_ctx sctx;
    sm4_init(&sctx, key);
    std::vector<uint8_t> jp_ct(DATA_SIZE), jp_pt(DATA_SIZE);
    sm4_ecb_encrypt(&sctx, plain, jp_ct);
    sm4_ecb_decrypt(&sctx, jp_ct, jp_pt);
    TEST("jpssl SM4-ECB round-trip", std::memcmp(jp_pt.data(), plain.data(), DATA_SIZE) == 0);

    double jp_enc_ms = best_ms([&] { sm4_ecb_encrypt(&sctx, plain, jp_ct); });
    double jp_dec_ms = best_ms([&] { sm4_ecb_decrypt(&sctx, jp_ct, jp_pt); });

    EVP_CIPHER_CTX* ec = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ec, EVP_sm4_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ec, 0);
    std::vector<uint8_t> ossl_ct(DATA_SIZE + 16);
    double ossl_enc_ms = best_ms([&] {
        int l1 = 0, l2 = 0;
        EVP_EncryptUpdate(ec, ossl_ct.data(), &l1, plain.data(), (int)DATA_SIZE);
        EVP_EncryptFinal_ex(ec, ossl_ct.data() + l1, &l2);
    });
    EVP_CIPHER_CTX_free(ec);

    EVP_CIPHER_CTX* dc = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(dc, EVP_sm4_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(dc, 0);
    std::vector<uint8_t> ossl_pt(DATA_SIZE + 16);
    double ossl_dec_ms = best_ms([&] {
        int l1 = 0, l2 = 0;
        EVP_DecryptUpdate(dc, ossl_pt.data(), &l1, ossl_ct.data(), (int)DATA_SIZE);
        EVP_DecryptFinal_ex(dc, ossl_pt.data() + l1, &l2);
    });
    EVP_CIPHER_CTX_free(dc);
    TEST("OpenSSL SM4-ECB round-trip", std::memcmp(ossl_pt.data(), plain.data(), DATA_SIZE) == 0);

    print_row("jpssl  SM4-ECB enc", jp_enc_ms, DATA_SIZE);
    print_row("OpenSSL SM4-ECB enc", ossl_enc_ms, DATA_SIZE);
    print_ratio("SM4-ECB enc", ossl_enc_ms, jp_enc_ms);
    print_row("jpssl  SM4-ECB dec", jp_dec_ms, DATA_SIZE);
    print_row("OpenSSL SM4-ECB dec", ossl_dec_ms, DATA_SIZE);
    print_ratio("SM4-ECB dec", ossl_dec_ms, jp_dec_ms);
}

// ========================================================================
//  OpenSSL AEAD helper (12-byte IV, 16-byte tag)
// ========================================================================
static void ossl_aead_init(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher) {
    EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
}

static double ossl_gcm_enc_best_ms(const EVP_CIPHER* cipher, const uint8_t* key,
                                   const uint8_t* iv, const uint8_t* in,
                                   uint8_t* out, uint8_t* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ossl_aead_init(ctx, cipher);
    double ms = best_ms([&] {
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
        int l1 = 0, l2 = 0;
        EVP_EncryptUpdate(ctx, out, &l1, in, (int)DATA_SIZE);
        EVP_EncryptFinal_ex(ctx, out + l1, &l2);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    });
    EVP_CIPHER_CTX_free(ctx);
    return ms;
}

static double ossl_gcm_dec_best_ms(const EVP_CIPHER* cipher, const uint8_t* key,
                                   const uint8_t* iv, const uint8_t* in,
                                   uint8_t* out, const uint8_t* tag, bool* ok) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ossl_aead_init(ctx, cipher);
    double ms = best_ms([&] {
        EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
        int l1 = 0, l2 = 0;
        EVP_DecryptUpdate(ctx, out, &l1, in, (int)DATA_SIZE);
        int ret = EVP_DecryptFinal_ex(ctx, out + l1, &l2);
        *ok = (ret > 0);
    });
    EVP_CIPHER_CTX_free(ctx);
    return ms;
}

// ========================================================================
//  2. SM4-GCM / SM4-CTR: jpssl vs OpenSSL
// ========================================================================
static void bench_sm4_gcm() {
    std::printf("\n=== SM4-GCM / SM4-CTR (16 MiB, best of 5) ===\n");

    uint8_t key[16], iv[12];
    RAND_bytes(key, 16);
    RAND_bytes(iv, 12);
    std::vector<uint8_t> plain(DATA_SIZE);
    RAND_bytes(plain.data(), (int)DATA_SIZE);

    // ---- jpssl SM4-GCM ----
    sm4_ctx sctx;
    sm4_init(&sctx, key);
    std::vector<uint8_t> jp_ct, jp_pt;
    uint8_t jp_tag[16];
    sm4_gcm_encrypt_auto(&sctx, iv, 12, plain, {}, jp_ct, jp_tag, 16);
    bool jp_ok = sm4_gcm_decrypt_auto(&sctx, iv, 12, jp_ct, {}, jp_tag, 16, jp_pt);
    TEST("jpssl SM4-GCM round-trip",
         jp_ok && jp_pt.size() == DATA_SIZE &&
         std::memcmp(jp_pt.data(), plain.data(), DATA_SIZE) == 0);

    double jp_gcm_enc_ms = best_ms([&] {
        sm4_gcm_encrypt_auto(&sctx, iv, 12, plain, {}, jp_ct, jp_tag, 16);
    });
    double jp_gcm_dec_ms = best_ms([&] {
        sm4_gcm_decrypt_auto(&sctx, iv, 12, jp_ct, {}, jp_tag, 16, jp_pt);
    });
    print_row("jpssl  SM4-GCM enc", jp_gcm_enc_ms, DATA_SIZE);
    print_row("jpssl  SM4-GCM dec", jp_gcm_dec_ms, DATA_SIZE);

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
    if (cpu_has_avx2()) {
        double jp_gcm_cpu_enc_ms = best_ms([&] {
            sm4_gcm_encrypt(&sctx, iv, 12, plain, {}, jp_ct, jp_tag, 16);
        });
        double jp_gcm_avx2_enc_ms = best_ms([&] {
            sm4_gcm_encrypt_avx2(&sctx, iv, 12, plain, {}, jp_ct, jp_tag, 16);
        });
        double jp_gcm_avx2_dec_ms = best_ms([&] {
            sm4_gcm_decrypt_avx2(&sctx, iv, 12, jp_ct, {}, jp_tag, 16, jp_pt);
        });
        print_row("jpssl  SM4-GCM enc (CPU)", jp_gcm_cpu_enc_ms, DATA_SIZE);
        print_row("jpssl  SM4-GCM enc (AVX2)", jp_gcm_avx2_enc_ms, DATA_SIZE);
        print_row("jpssl  SM4-GCM dec (AVX2)", jp_gcm_avx2_dec_ms, DATA_SIZE);
        if (jp_gcm_cpu_enc_ms < jp_gcm_avx2_enc_ms)
            std::printf("  %-28s scalar %.2fx faster\n", "AVX2 vs scalar (enc)",
                        jp_gcm_avx2_enc_ms / jp_gcm_cpu_enc_ms);
        else
            std::printf("  %-28s AVX2 %.2fx faster\n", "AVX2 vs scalar (enc)",
                        jp_gcm_cpu_enc_ms / jp_gcm_avx2_enc_ms);
    }
#endif

    // ---- OpenSSL SM4-GCM (if provider supports it) ----
    EVP_CIPHER* sm4_gcm = EVP_CIPHER_fetch(nullptr, "SM4-GCM", nullptr);
    if (sm4_gcm != nullptr) {
        std::vector<uint8_t> ossl_ct(DATA_SIZE + 16), ossl_pt(DATA_SIZE + 16);
        uint8_t ossl_tag[16];
        double ossl_enc_ms = ossl_gcm_enc_best_ms(sm4_gcm, key, iv,
                                                  plain.data(), ossl_ct.data(), ossl_tag);
        bool ok = false;
        double ossl_dec_ms = ossl_gcm_dec_best_ms(sm4_gcm, key, iv,
                                                  ossl_ct.data(), ossl_pt.data(), ossl_tag, &ok);
        TEST("OpenSSL SM4-GCM round-trip",
             ok && std::memcmp(ossl_pt.data(), plain.data(), DATA_SIZE) == 0);
        print_row("OpenSSL SM4-GCM enc", ossl_enc_ms, DATA_SIZE);
        print_ratio("SM4-GCM enc", ossl_enc_ms, jp_gcm_enc_ms);
        print_row("OpenSSL SM4-GCM dec", ossl_dec_ms, DATA_SIZE);
        print_ratio("SM4-GCM dec", ossl_dec_ms, jp_gcm_dec_ms);
        EVP_CIPHER_free(sm4_gcm);
    } else {
        std::printf("  [skip] OpenSSL provider has no SM4-GCM; using SM4-CTR as stream-mode reference\n");
    }

    // ---- OpenSSL SM4-CTR (stream-mode reference) ----
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cctx, EVP_sm4_ctr(), nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(cctx, 0);
    std::vector<uint8_t> ctr_out(DATA_SIZE), ctr_back(DATA_SIZE);
    double ossl_ctr_ms = best_ms([&] {
        int l1 = 0, l2 = 0;
        EVP_EncryptUpdate(cctx, ctr_out.data(), &l1, plain.data(), (int)DATA_SIZE);
        EVP_EncryptFinal_ex(cctx, ctr_out.data() + l1, &l2);
    });
    EVP_CIPHER_CTX_free(cctx);

    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(dctx, EVP_sm4_ctr(), nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(dctx, 0);
    best_ms([&] {
        int l1 = 0, l2 = 0;
        EVP_EncryptUpdate(dctx, ctr_back.data(), &l1, ctr_out.data(), (int)DATA_SIZE);
        EVP_EncryptFinal_ex(dctx, ctr_back.data() + l1, &l2);
    });
    EVP_CIPHER_CTX_free(dctx);
    TEST("OpenSSL SM4-CTR round-trip", std::memcmp(ctr_back.data(), plain.data(), DATA_SIZE) == 0);
    print_row("OpenSSL SM4-CTR (enc=dec)", ossl_ctr_ms, DATA_SIZE);
    print_ratio("OpenSSL SM4-CTR vs jpssl GCM", ossl_ctr_ms, jp_gcm_enc_ms);
}

// ========================================================================
//  3. Reference: AES-128 (hardware accelerated)
// ========================================================================
static void bench_aes128_reference() {
    std::printf("\n=== Reference AES-128 (16 MiB, best of 5) ===\n");

    uint8_t key[16], iv[12];
    RAND_bytes(key, 16);
    RAND_bytes(iv, 12);
    std::vector<uint8_t> plain(DATA_SIZE);
    RAND_bytes(plain.data(), (int)DATA_SIZE);

    // OpenSSL AES-128-ECB
    EVP_CIPHER_CTX* ec = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ec, EVP_aes_128_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ec, 0);
    std::vector<uint8_t> ossl_ct(DATA_SIZE + 16);
    double aes_ecb_enc = best_ms([&] {
        int l1 = 0, l2 = 0;
        EVP_EncryptUpdate(ec, ossl_ct.data(), &l1, plain.data(), (int)DATA_SIZE);
        EVP_EncryptFinal_ex(ec, ossl_ct.data() + l1, &l2);
    });
    EVP_CIPHER_CTX_free(ec);
    print_row("OpenSSL AES-128-ECB enc", aes_ecb_enc, DATA_SIZE);

    // OpenSSL AES-128-CTR
    EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(cctx, EVP_aes_128_ctr(), nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(cctx, 0);
    double aes_ctr = best_ms([&] {
        int l1 = 0, l2 = 0;
        EVP_EncryptUpdate(cctx, ossl_ct.data(), &l1, plain.data(), (int)DATA_SIZE);
        EVP_EncryptFinal_ex(cctx, ossl_ct.data() + l1, &l2);
    });
    EVP_CIPHER_CTX_free(cctx);
    print_row("OpenSSL AES-128-CTR (enc=dec)", aes_ctr, DATA_SIZE);

    // OpenSSL AES-128-GCM
    std::vector<uint8_t> ossl_pt(DATA_SIZE + 16);
    uint8_t ossl_tag[16];
    double aes_gcm_enc = ossl_gcm_enc_best_ms(EVP_aes_128_gcm(), key, iv,
                                              plain.data(), ossl_ct.data(), ossl_tag);
    bool ok = false;
    double aes_gcm_dec = ossl_gcm_dec_best_ms(EVP_aes_128_gcm(), key, iv,
                                              ossl_ct.data(), ossl_pt.data(), ossl_tag, &ok);
    TEST("OpenSSL AES-128-GCM round-trip",
         ok && std::memcmp(ossl_pt.data(), plain.data(), DATA_SIZE) == 0);
    print_row("OpenSSL AES-128-GCM enc", aes_gcm_enc, DATA_SIZE);
    print_row("OpenSSL AES-128-GCM dec", aes_gcm_dec, DATA_SIZE);

    // jpssl AES-128-GCM (same library, for in-library reference)
    aes_context actx;
    actx.init(std::span<const uint8_t, 16>(key, 16));
    std::vector<uint8_t> jp_ct, jp_pt;
    uint8_t jp_tag[16];
    aes_gcm_encrypt_auto(actx, iv, 12, plain, {}, jp_ct, jp_tag, 16);
    bool jp_ok = aes_gcm_decrypt_auto(actx, iv, 12, jp_ct, {}, jp_tag, 16, jp_pt);
    TEST("jpssl AES-128-GCM round-trip",
         jp_ok && jp_pt.size() == DATA_SIZE &&
         std::memcmp(jp_pt.data(), plain.data(), DATA_SIZE) == 0);
    double jp_gcm_enc = best_ms([&] {
        aes_gcm_encrypt_auto(actx, iv, 12, plain, {}, jp_ct, jp_tag, 16);
    });
    double jp_gcm_dec = best_ms([&] {
        aes_gcm_decrypt_auto(actx, iv, 12, jp_ct, {}, jp_tag, 16, jp_pt);
    });
    print_row("jpssl  AES-128-GCM enc", jp_gcm_enc, DATA_SIZE);
    print_row("jpssl  AES-128-GCM dec", jp_gcm_dec, DATA_SIZE);
}

int main() {
    std::printf("=== SM4 vs OpenSSL benchmark ===\n");
    std::printf("OpenSSL: %s\n", OPENSSL_VERSION_TEXT);
    auto f = cpu_features::detect();
    std::printf("CPU: AES-NI=%s AVX2=%s VAES+VPCLMULQDQ=%s AVX512=%s\n",
                f.aesni ? "Y" : "N", f.avx2 ? "Y" : "N",
                f.vpclmulqdq_vaes ? "Y" : "N", f.avx512 ? "Y" : "N");
    std::printf("SM4-GCM dispatch level: %d (%s)\n", sm4_gcm_auto_level(),
                sm4_gcm_auto_level() == 1 ? "AVX2" : "scalar CPU");
    std::printf("Data: %llu bytes (16 MiB), best of 5 runs, single-thread\n",
                (unsigned long long)DATA_SIZE);

    bench_sm4_ecb();
    bench_sm4_gcm();
    bench_aes128_reference();

    std::printf("\nDone.\n");
    return 0;
}
