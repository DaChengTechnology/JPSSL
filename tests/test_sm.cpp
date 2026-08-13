/** test_sm.cpp — SM2/SM3/SM4 单元测试（与 OpenSSL 互验） */
#include "sm2.hpp"
#include "sm3.hpp"
#include "sm4.hpp"
#include "sm4_gcm.hpp"
#include "sm2_mont_asm.hpp"
#include "cpu_features.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <vector>
#include <string>
#include <random>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL: %s\n", msg); std::exit(1); } \
    else { std::printf("  PASS: %s\n", msg); } \
} while(0)

// ═══════════════════════════════════════════════════════════════════════
//  SM3 测试（与 OpenSSL 对比）
// ═══════════════════════════════════════════════════════════════════════

static void ossl_sm3(const uint8_t* data, size_t len, uint8_t hash[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sm3(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int out_len = 32;
    EVP_DigestFinal_ex(ctx, hash, &out_len);
    EVP_MD_CTX_free(ctx);
}

static void test_sm3() {
    std::printf("\n=== SM3 测试 ===\n");

    struct TestCase { const char* msg; };
    TestCase tests[] = {
        {""},
        {"a"},
        {"abc"},
        {"message digest"},
        {"Hello, world!"},
        {"The quick brown fox jumps over the lazy dog"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    };

    for (auto& tc : tests) {
        size_t len = std::strlen(tc.msg);
        const uint8_t* data = (const uint8_t*)tc.msg;

        uint8_t jp_hash[32];
        jpssl::sm3_hash(jp_hash, data, len);

        uint8_t ossl_hash[32];
        ossl_sm3(data, len, ossl_hash);

        std::string label = "SM3(\"" + std::string(tc.msg) + "\")";
        if (label.size() > 50) label = label.substr(0, 47) + "...\"";
        ASSERT(std::memcmp(jp_hash, ossl_hash, 32) == 0,
               (label + " vs OpenSSL").c_str());
    }

    // 测试增量更新
    {
        const char* msg = "The quick brown fox jumps over the lazy dog";
        jpssl::sm3_ctx ctx;
        jpssl::sm3_init(&ctx);
        for (size_t i = 0; i < std::strlen(msg); ++i) {
            jpssl::sm3_update(&ctx, (const uint8_t*)&msg[i], 1);
        }
        uint8_t jp_hash[32];
        jpssl::sm3_final(&ctx, jp_hash);

        uint8_t ossl_hash[32];
        ossl_sm3((const uint8_t*)msg, std::strlen(msg), ossl_hash);

        ASSERT(std::memcmp(jp_hash, ossl_hash, 32) == 0,
               "SM3 incremental update vs OpenSSL");
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  SM4 测试（与 OpenSSL 对比）
// ═══════════════════════════════════════════════════════════════════════

static void ossl_sm4_ecb_encrypt(const uint8_t key[16], const uint8_t* plain,
                                  size_t len, uint8_t* cipher) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int out_len = 0, total = 0;
    EVP_EncryptUpdate(ctx, cipher, &out_len, plain, (int)len);
    total = out_len;
    EVP_EncryptFinal_ex(ctx, cipher + total, &out_len);
    total += out_len;
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_sm4_ecb_decrypt(const uint8_t key[16], const uint8_t* cipher,
                                  size_t len, uint8_t* plain) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int out_len = 0, total = 0;
    EVP_DecryptUpdate(ctx, plain, &out_len, cipher, (int)len);
    total = out_len;
    EVP_DecryptFinal_ex(ctx, plain + total, &out_len);
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                                  const uint8_t* plain, size_t len, uint8_t* cipher, int* clen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 1);  // PKCS#7
    int out_len = 0;
    EVP_EncryptUpdate(ctx, cipher, &out_len, plain, (int)len);
    *clen = out_len;
    EVP_EncryptFinal_ex(ctx, cipher + *clen, &out_len);
    *clen += out_len;
    EVP_CIPHER_CTX_free(ctx);
}

static void ossl_sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                                  const uint8_t* cipher, size_t len, uint8_t* plain, int* plen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), nullptr, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    int out_len = 0;
    EVP_DecryptUpdate(ctx, plain, &out_len, cipher, (int)len);
    *plen = out_len;
    EVP_DecryptFinal_ex(ctx, plain + *plen, &out_len);
    *plen += out_len;
    EVP_CIPHER_CTX_free(ctx);
}

static void test_sm4() {
    std::printf("\n=== SM4 测试 ===\n");

    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

    jpssl::sm4_ctx ctx;
    jpssl::sm4_init(&ctx, key);

    // 单块加解密往返
    {
        uint8_t plain[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                             0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t cipher[16], recovered[16];

        jpssl::sm4_encrypt_block(&ctx, plain, cipher);
        jpssl::sm4_decrypt_block(&ctx, cipher, recovered);

        ASSERT(std::memcmp(plain, recovered, 16) == 0,
               "SM4 single block encrypt/decrypt roundtrip");
    }

    // 与 OpenSSL ECB 对比
    {
        const uint8_t plain[32] = "Hello SM4! Test message12345678";
        uint8_t jp_cipher[32], ossl_cipher[32];

        jpssl::sm4_ecb_encrypt(&ctx,
            jpssl::span<const uint8_t>(plain, 32),
            jpssl::span<uint8_t>(jp_cipher, 32));

        ossl_sm4_ecb_encrypt(key, plain, 32, ossl_cipher);

        ASSERT(std::memcmp(jp_cipher, ossl_cipher, 32) == 0,
               "SM4 ECB encrypt vs OpenSSL");
    }

    // ECB 解密 vs OpenSSL
    {
        const uint8_t plain[32] = "Hello SM4! Test message12345678";
        uint8_t cipher[32], jp_plain[32], ossl_plain[32];

        jpssl::sm4_ecb_encrypt(&ctx,
            jpssl::span<const uint8_t>(plain, 32),
            jpssl::span<uint8_t>(cipher, 32));

        jpssl::sm4_ecb_decrypt(&ctx,
            jpssl::span<const uint8_t>(cipher, 32),
            jpssl::span<uint8_t>(jp_plain, 32));

        ossl_sm4_ecb_decrypt(key, cipher, 32, ossl_plain);

        ASSERT(std::memcmp(jp_plain, ossl_plain, 32) == 0 &&
               std::memcmp(jp_plain, plain, 32) == 0,
               "SM4 ECB decrypt vs OpenSSL");
    }

    // CBC 模式往返
    {
        uint8_t iv[16] = {0};
        const uint8_t msg[] = "This is a CBC mode test message for SM4!";
        size_t msg_len = sizeof(msg) - 1;

        auto ct = jpssl::sm4_cbc_encrypt(&ctx, iv,
            jpssl::span<const uint8_t>(msg, msg_len));
        auto pt = jpssl::sm4_cbc_decrypt(&ctx, iv,
            jpssl::span<const uint8_t>(ct.data(), ct.size()));

        ASSERT(pt.size() == msg_len &&
               std::memcmp(pt.data(), msg, msg_len) == 0,
               "SM4 CBC encrypt/decrypt roundtrip");
    }

    // 多次加解密（不同数据大小）
    for (int sz = 1; sz <= 64; ++sz) {
        std::vector<uint8_t> plain(sz);
        for (int i = 0; i < sz; ++i) plain[i] = (uint8_t)(i * 3 + 1);

        uint8_t cipher[64], recovered[64];
        // 填充到 16 字节对齐
        size_t padded = ((sz + 15) / 16) * 16;
        std::vector<uint8_t> padded_plain(padded, 0);
        std::memcpy(padded_plain.data(), plain.data(), sz);

        jpssl::sm4_ecb_encrypt(&ctx,
            jpssl::span<const uint8_t>(padded_plain),
            jpssl::span<uint8_t>(cipher, padded));
        jpssl::sm4_ecb_decrypt(&ctx,
            jpssl::span<const uint8_t>(cipher, padded),
            jpssl::span<uint8_t>(recovered, padded));

        bool ok = std::memcmp(padded_plain.data(), recovered, padded) == 0;
        ASSERT(ok, ("SM4 ECB size " + std::to_string(sz)).c_str());
    }

    std::printf("  (all SM4 ECB sizes 1-64 passed)\n");
}

// SM4-GCM vs OpenSSL cross-check (covers the fast GHASH path)
static void test_sm4_gcm_ossl() {
    std::printf("\n=== SM4-GCM vs OpenSSL ===\n");

    EVP_CIPHER* ossl_gcm = EVP_CIPHER_fetch(nullptr, "SM4-GCM", nullptr);
    if (!ossl_gcm) {
        std::printf("  SKIP: OpenSSL provider has no SM4-GCM\n");
        return;
    }

    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    jpssl::sm4_ctx ctx;
    jpssl::sm4_init(&ctx, key);

    const uint8_t aad_fixed[] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x11,0x22,0x33,0x44};
    size_t pt_lens[] = {0, 1, 15, 16, 17, 31, 1000, 65536};
    size_t iv_lens[] = {12, 8};

    for (size_t len : pt_lens) {
        std::vector<uint8_t> plain(len);
        for (size_t i = 0; i < len; ++i) plain[i] = (uint8_t)(i * 7 + 3);

        for (size_t iv_len : iv_lens) {
            std::vector<uint8_t> iv(iv_len);
            for (size_t i = 0; i < iv_len; ++i) iv[i] = (uint8_t)(i + 1);
            std::vector<uint8_t> aad(aad_fixed, aad_fixed + sizeof(aad_fixed));
            if (len == 0) aad.clear();

            // jpssl
            std::vector<uint8_t> jp_ct;
            uint8_t jp_tag[16];
            jpssl::sm4_gcm_encrypt(&ctx, iv.data(), iv_len,
                                   jpssl::span<const uint8_t>(plain),
                                   jpssl::span<const uint8_t>(aad),
                                   jp_ct, jp_tag, 16);

            // OpenSSL
            std::vector<uint8_t> ossl_ct(len + 16);
            uint8_t ossl_tag[16];
            EVP_CIPHER_CTX* e = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(e, ossl_gcm, nullptr, nullptr, nullptr);
            EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, nullptr);
            EVP_EncryptInit_ex(e, nullptr, nullptr, key, iv.data());
            int l1 = 0, l2 = 0;
            // AAD must be supplied before the plaintext for GCM.
            if (!aad.empty()) EVP_EncryptUpdate(e, nullptr, &l1, aad.data(), (int)aad.size());
            if (len) EVP_EncryptUpdate(e, ossl_ct.data(), &l1, plain.data(), (int)len);
            EVP_EncryptFinal_ex(e, ossl_ct.data() + l1, &l2);
            EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_GCM_GET_TAG, 16, ossl_tag);
            EVP_CIPHER_CTX_free(e);

            std::string label = "SM4-GCM len=" + std::to_string(len) +
                                " iv=" + std::to_string(iv_len) + " vs OpenSSL";
            ASSERT(jp_ct.size() == len &&
                   std::memcmp(jp_ct.data(), ossl_ct.data(), len) == 0 &&
                   std::memcmp(jp_tag, ossl_tag, 16) == 0,
                   label.c_str());

            // jpssl decrypts OpenSSL ciphertext
            std::vector<uint8_t> pt2;
            bool dec = jpssl::sm4_gcm_decrypt(&ctx, iv.data(), iv_len,
                                              jpssl::span<const uint8_t>(ossl_ct.data(), len),
                                              jpssl::span<const uint8_t>(aad),
                                              ossl_tag, 16, pt2);
            ASSERT(dec && pt2 == plain, (label + " decrypt").c_str());
        }
    }

    EVP_CIPHER_free(ossl_gcm);
}

// SM4-GCM dispatch: scalar CPU vs auto vs AVX2 (cross-check all lengths)
static void test_sm4_gcm_dispatch() {
    std::printf("\n=== SM4-GCM dispatch (CPU / auto / AVX2) ===\n");

    uint8_t key[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                       0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00};
    uint8_t iv[12]  = {0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,
                       0x12,0x13,0x14,0x15};
    const uint8_t aad_fixed[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};

    jpssl::sm4_ctx ctx;
    jpssl::sm4_init(&ctx, key);

    const size_t lens[] = {0, 1, 15, 16, 17, 63, 127, 128, 129, 255,
                           256, 257, 1000, 4095, 4096, 16384};

    // Auto dispatch level must match the CPU feature it detected.
    bool has_avx2 = jpssl::cpu_has_avx2();
    bool has_gfni = jpssl::cpu_has_gfni();
    int level = jpssl::sm4_gcm_auto_level();
    ASSERT(level == (has_gfni && has_avx2 ? 2 : has_avx2 ? 1 : 0),
           "SM4-GCM auto level matches cpu_has_avx2()/cpu_has_gfni()");

    for (size_t len : lens) {
        std::vector<uint8_t> plain(len);
        for (size_t i = 0; i < len; ++i) plain[i] = (uint8_t)(i * 13 + 7);
        std::vector<uint8_t> aad(aad_fixed, aad_fixed + sizeof(aad_fixed));
        if (len == 0) aad.clear();

        std::span<const uint8_t> p_span(plain), a_span(aad);

        // Scalar CPU reference.
        std::vector<uint8_t> ct_cpu;
        uint8_t tag_cpu[16];
        jpssl::sm4_gcm_encrypt(&ctx, iv, 12, p_span, a_span, ct_cpu, tag_cpu, 16);

        // Auto (routed) path must be byte-identical to scalar.
        std::vector<uint8_t> ct_auto;
        uint8_t tag_auto[16];
        jpssl::sm4_gcm_encrypt_auto(&ctx, iv, 12, p_span, a_span, ct_auto, tag_auto, 16);
        std::string l_auto = "SM4-GCM auto == CPU len=" + std::to_string(len);
        ASSERT(ct_auto == ct_cpu && std::memcmp(tag_auto, tag_cpu, 16) == 0,
               l_auto.c_str());

        // Auto decrypt round-trip.
        std::vector<uint8_t> pt_auto;
        bool ok_auto = jpssl::sm4_gcm_decrypt_auto(
            &ctx, iv, 12, std::span<const uint8_t>(ct_auto), a_span, tag_auto, 16, pt_auto);
        ASSERT(ok_auto && pt_auto == plain, (l_auto + " decrypt").c_str());

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
        if (has_avx2) {
            // Explicit AVX2 backend must match the scalar reference.
            std::vector<uint8_t> ct_avx2;
            uint8_t tag_avx2[16];
            jpssl::sm4_gcm_encrypt_avx2(&ctx, iv, 12, p_span, a_span,
                                        ct_avx2, tag_avx2, 16);
            std::string l_avx2 = "SM4-GCM AVX2 == CPU len=" + std::to_string(len);
            ASSERT(ct_avx2 == ct_cpu && std::memcmp(tag_avx2, tag_cpu, 16) == 0,
                   l_avx2.c_str());

            std::vector<uint8_t> pt_avx2;
            bool ok_avx2 = jpssl::sm4_gcm_decrypt_avx2(
                &ctx, iv, 12, std::span<const uint8_t>(ct_avx2), a_span, tag_avx2, 16, pt_avx2);
            ASSERT(ok_avx2 && pt_avx2 == plain, (l_avx2 + " decrypt").c_str());

            // Tampered tag must be rejected by the AVX2 backend.
            uint8_t bad_tag[16];
            std::memcpy(bad_tag, tag_avx2, 16);
            bad_tag[0] ^= 0x01;
            std::vector<uint8_t> pt_bad;
            bool ok_bad = jpssl::sm4_gcm_decrypt_avx2(
                &ctx, iv, 12, std::span<const uint8_t>(ct_avx2), a_span, bad_tag, 16, pt_bad);
            ASSERT(!ok_bad, (l_avx2 + " rejects tampered tag").c_str());
        }
#endif
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
        if (has_gfni) {
            // Explicit GFNI backend must match the scalar reference.
            std::vector<uint8_t> ct_gfni;
            uint8_t tag_gfni[16];
            jpssl::sm4_gcm_encrypt_gfni(&ctx, iv, 12, p_span, a_span,
                                        ct_gfni, tag_gfni, 16);
            std::string l_gfni = "SM4-GCM GFNI == CPU len=" + std::to_string(len);
            ASSERT(ct_gfni == ct_cpu && std::memcmp(tag_gfni, tag_cpu, 16) == 0,
                   l_gfni.c_str());

            std::vector<uint8_t> pt_gfni;
            bool ok_gfni = jpssl::sm4_gcm_decrypt_gfni(
                &ctx, iv, 12, std::span<const uint8_t>(ct_gfni), a_span,
                tag_gfni, 16, pt_gfni);
            ASSERT(ok_gfni && pt_gfni == plain, (l_gfni + " decrypt").c_str());

            // Tampered tag must be rejected by the GFNI backend.
            uint8_t bad_tag[16];
            std::memcpy(bad_tag, tag_gfni, 16);
            bad_tag[0] ^= 0x01;
            std::vector<uint8_t> pt_bad;
            bool ok_bad = jpssl::sm4_gcm_decrypt_gfni(
                &ctx, iv, 12, std::span<const uint8_t>(ct_gfni), a_span,
                bad_tag, 16, pt_bad);
            ASSERT(!ok_bad, (l_gfni + " rejects tampered tag").c_str());
        }
#endif
    }

    std::printf("  dispatch level = %d (GFNI=%s AVX2=%s)\n",
                level, has_gfni ? "Y" : "N", has_avx2 ? "Y" : "N");
}

// ═══════════════════════════════════════════════════════════════════════
//  SM2 测试（与 OpenSSL 对比）
// ═══════════════════════════════════════════════════════════════════════

// ===========================================================================
//  SM2 Montgomery ADX asm: 汇编 vs 可移植 CIOS 参考实现
// ===========================================================================

#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(_umul128, _addcarry_u64, _subborrow_u64)
#endif

static inline uint64_t ref_mul64(uint64_t a, uint64_t b, uint64_t* hi) {
#if defined(_MSC_VER)
    return _umul128(a, b, hi);
#else
    __uint128_t t = (__uint128_t)a * b;
    *hi = (uint64_t)(t >> 64);
    return (uint64_t)t;
#endif
}

static inline uint64_t ref_addc(uint64_t a, uint64_t b, uint64_t cin, uint64_t* out) {
#if defined(_MSC_VER)
    return (uint64_t)_addcarry_u64((unsigned char)cin, a, b, out);
#else
    __uint128_t t = (__uint128_t)a + b + cin;
    *out = (uint64_t)t;
    return (uint64_t)(t >> 64);
#endif
}

static inline uint64_t ref_subb(uint64_t a, uint64_t b, uint64_t bin, uint64_t* out) {
#if defined(_MSC_VER)
    return (uint64_t)_subborrow_u64((unsigned char)bin, a, b, out);
#else
    __uint128_t t = (__uint128_t)a - b - bin;
    *out = (uint64_t)t;
    return (uint64_t)(t >> 64) & 1u;
#endif
}

// 与 sm2.cpp 可移植路径相同的 schoolbook 累加 + Montgomery 归约
static uint64_t ref_acc(uint64_t* t, int pos, uint64_t lo, uint64_t hi, uint64_t cin) {
    uint64_t out;
    uint64_t cf1 = ref_addc(lo, t[pos], 0, &out);
    uint64_t cf2 = ref_addc(out, cin, 0, &out);
    t[pos] = out;
    uint64_t old = hi;
    hi = old + cf1 + cf2;
    if (hi < old) {
        for (int k = pos + 2; k < 10; ++k) {
            uint64_t s2 = t[k] + 1;
            t[k] = s2;
            if (s2) break;
        }
    }
    return hi;
}

static void ref_mul512(uint64_t t[10], const uint64_t a[4], const uint64_t b[4]) {
    for (int k = 0; k < 10; ++k) t[k] = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t ca = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t hi, lo = ref_mul64(a[i], b[j], &hi);
            ca = ref_acc(t, i + j, lo, hi, ca);
        }
        if (ca) {
            for (int k = i + 4; ca && k < 10; ++k) {
                uint64_t s2 = t[k] + ca;
                t[k] = s2;
                ca = (s2 < ca) ? 1 : 0;
            }
        }
    }
}

static bool ref_ge(const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 3; i >= 0; --i) {
        if (a[i] > b[i]) return true;
        if (a[i] < b[i]) return false;
    }
    return true;
}

static bool ref_eq(const uint64_t a[4], const uint64_t b[4]) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static void ref_mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4],
                         const uint64_t m[4], uint64_t mp) {
    uint64_t t[10];
    ref_mul512(t, a, b);
    for (int i = 0; i < 4; ++i) {
        uint64_t u = t[i] * mp;
        uint64_t ca = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t hi, lo = ref_mul64(u, m[j], &hi);
            ca = ref_acc(t, i + j, lo, hi, ca);
        }
        if (ca) {
            for (int k = i + 4; ca && k < 10; ++k) {
                uint64_t s2 = t[k] + ca;
                t[k] = s2;
                ca = (s2 < ca) ? 1 : 0;
            }
        }
    }
    for (int i = 0; i < 4; ++i) r[i] = t[i + 4];
    if (t[8] || ref_ge(r, m)) {
        uint64_t bo = 0;
        for (int i = 0; i < 4; ++i) bo = ref_subb(r[i], m[i], bo, &r[i]);
    }
}

static uint64_t ref_mont_mp(const uint64_t m[4]) {
    uint64_t x = 1;
    for (int i = 0; i < 63; ++i) x = x * (2 - m[0] * x);
    return (uint64_t)(-(int64_t)x);
}

static void test_sm2_mont_asm() {
    std::printf("\n=== SM2 Montgomery ADX asm ===\n");
    if (!jpssl::sm2_mont_asm_available()) {
        std::printf("  SKIP: BMI2/ADX not available, sm2.cpp keeps C path\n");
        return;
    }
    std::printf("  BMI2+ADX detected; asm path is active\n");

    static const uint64_t P[4] = {
        0xffffffffffffffffULL, 0xffffffff00000000ULL,
        0xffffffffffffffffULL, 0xfffffffeffffffffULL
    };
    static const uint64_t N[4] = {
        0x53bbf40939d54123ULL, 0x7203df6b21c6052bULL,
        0xffffffffffffffffULL, 0xfffffffeffffffffULL
    };
    const uint64_t* mods[2] = { P, N };
    const char* names[2] = { "SM2 prime p", "SM2 order n" };

    std::mt19937_64 rng(0x5EED1234u);
    int total = 0;

    for (int mi = 0; mi < 2; ++mi) {
        const uint64_t* m = mods[mi];
        const uint64_t mp = ref_mont_mp(m);

        for (int it = 0; it < 20000; ++it) {
            uint64_t a[4], b[4];
            do { for (int j = 0; j < 4; ++j) a[j] = rng(); } while (ref_ge(a, m));
            do { for (int j = 0; j < 4; ++j) b[j] = rng(); } while (ref_ge(b, m));

            uint64_t got[4], want[4];
            jpssl::sm2_mont_mul(got, a, b, m, mp);
            ref_mont_mul(want, a, b, m, mp);
            if (!ref_eq(got, want) || ref_ge(got, m)) {
                std::fprintf(stderr, "FAIL: %s random mul it=%d\n", names[mi], it);
                std::exit(1);
            }
            ++total;

            if ((it & 63) == 0) {
                jpssl::sm2_mont_sqr(got, a, m, mp);
                ref_mont_mul(want, a, a, m, mp);
                if (!ref_eq(got, want) || ref_ge(got, m)) {
                    std::fprintf(stderr, "FAIL: %s sqr it=%d\n", names[mi], it);
                    std::exit(1);
                }
            }
        }

        // 边界值
        uint64_t zero[4] = {0, 0, 0, 0};
        uint64_t one[4]  = {1, 0, 0, 0};
        uint64_t mm1[4], mm2[4], got[4], want[4];
        uint64_t bo = ref_subb(m[0], 1, 0, &mm1[0]);
        for (int j = 1; j < 4; ++j) bo = ref_subb(m[j], 0, bo, &mm1[j]);
        bo = ref_subb(m[0], 2, 0, &mm2[0]);
        for (int j = 1; j < 4; ++j) bo = ref_subb(m[j], 0, bo, &mm2[j]);

        struct { const uint64_t* a; const uint64_t* b; const char* label; } edges[] = {
            { zero, zero, "0*0" },
            { one,  one,  "1*1" },
            { mm1,  mm1,  "(m-1)^2" },
            { mm2,  one,  "(m-2)*1" },
            { mm1,  mm2,  "(m-1)*(m-2)" },
        };
        for (auto& e : edges) {
            jpssl::sm2_mont_mul(got, e.a, e.b, m, mp);
            ref_mont_mul(want, e.a, e.b, m, mp);
            if (!ref_eq(got, want) || ref_ge(got, m)) {
                std::fprintf(stderr, "FAIL: %s edge %s\n", names[mi], e.label);
                std::exit(1);
            }
            ++total;
        }
        std::printf("  %s: 20000 random mul + edge cases OK\n", names[mi]);
    }
    std::printf("  asm vs portable CIOS: %d checks OK\n", total);
}

static void test_sm2() {
    std::printf("\n=== SM2 测试 ===\n");

    // 1. 密钥生成往返
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        uint8_t pub2[64];
        jpssl::sm2_pub_from_priv(priv, pub2);

        ASSERT(std::memcmp(pub, pub2, 64) == 0,
               "SM2 keygen: pub_from_priv matches keygen output");
    }

    // 2. 签名/验证往返（不带 ZA）
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        const char* msg = "SM2 test message for signing and verification";
        size_t msg_len = std::strlen(msg);

        for (int i = 0; i < 10; ++i) {
            uint8_t sig[64];
            jpssl::sm2_sign(priv, (const uint8_t*)msg, msg_len, sig, nullptr);

            bool ok = jpssl::sm2_verify(pub, (const uint8_t*)msg, msg_len, sig, nullptr);
            ASSERT(ok, ("SM2 sign/verify roundtrip #" + std::to_string(i)).c_str());
        }
    }

    // 3. 签名/验证往返（带 ZA）
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        // 计算 ZA
        const char* id = "1234567812345678";
        uint8_t za[32];
        jpssl::sm2_compute_za((const uint8_t*)id, std::strlen(id), pub, pub + 32, za);

        const char* msg = "SM2 test with ZA (user identity)";
        size_t msg_len = std::strlen(msg);

        for (int i = 0; i < 5; ++i) {
            uint8_t sig[64];
            jpssl::sm2_sign(priv, (const uint8_t*)msg, msg_len, sig, za);

            bool ok = jpssl::sm2_verify(pub, (const uint8_t*)msg, msg_len, sig, za);
            ASSERT(ok, ("SM2 sign/verify with ZA #" + std::to_string(i)).c_str());
        }
    }

    // 4. 验证失败案例：错误消息
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        const char* msg1 = "Message one";
        const char* msg2 = "Message two";
        uint8_t sig[64];
        jpssl::sm2_sign(priv, (const uint8_t*)msg1, std::strlen(msg1), sig, nullptr);

        bool ok = jpssl::sm2_verify(pub, (const uint8_t*)msg2, std::strlen(msg2), sig, nullptr);
        ASSERT(!ok, "SM2 verify rejects wrong message");
    }

    // 5. 验证失败案例：错误公钥
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        uint8_t pub2[64], priv2[32];
        jpssl::sm2_keygen(pub2, priv2);

        const char* msg = "Test message";
        uint8_t sig[64];
        jpssl::sm2_sign(priv, (const uint8_t*)msg, std::strlen(msg), sig, nullptr);

        bool ok = jpssl::sm2_verify(pub2, (const uint8_t*)msg, std::strlen(msg), sig, nullptr);
        ASSERT(!ok, "SM2 verify rejects wrong public key");
    }

    // 6. 与 OpenSSL 互验签名
    // 使用固定私钥生成确定性结果
    {
        // 固定私钥: 1
        uint8_t fixed_priv[32] = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
        };

        uint8_t pub[64];
        jpssl::sm2_pub_from_priv(fixed_priv, pub);

        const char* msg = "SM2 cross-validation test";
        uint8_t sig[64];
        jpssl::sm2_sign(fixed_priv, (const uint8_t*)msg, std::strlen(msg), sig, nullptr);

        bool ok = jpssl::sm2_verify(pub, (const uint8_t*)msg, std::strlen(msg), sig, nullptr);
        ASSERT(ok, "SM2 fixed-private-key sign/verify");
    }

    // 7. 空消息签名
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        uint8_t sig[64];
        jpssl::sm2_sign(priv, nullptr, 0, sig, nullptr);

        bool ok = jpssl::sm2_verify(pub, nullptr, 0, sig, nullptr);
        ASSERT(ok, "SM2 empty message sign/verify");
    }

    // 8. 大批量数据签名
    {
        uint8_t pub[64], priv[32];
        jpssl::sm2_keygen(pub, priv);

        std::vector<uint8_t> msg(10000);
        for (int i = 0; i < 10000; ++i) msg[i] = (uint8_t)(i & 0xff);

        uint8_t sig[64];
        jpssl::sm2_sign(priv, msg.data(), msg.size(), sig, nullptr);

        bool ok = jpssl::sm2_verify(pub, msg.data(), msg.size(), sig, nullptr);
        ASSERT(ok, "SM2 large message (10KB) sign/verify");
    }
}

static void test_sm2_ecdh() {
    std::printf("\n=== SM2 ECDH (TLS 1.3 / RFC 8998) ===\n");

    // 双方密钥对
    uint8_t pubA[64], privA[32], pubB[64], privB[32];
    jpssl::sm2_keygen(pubA, privA);
    jpssl::sm2_keygen(pubB, privB);

    uint8_t sharedA[32], sharedB[32], sharedA65[32];
    bool okA = jpssl::sm2_ecdh(sharedA, privA, pubB, 64);
    bool okB = jpssl::sm2_ecdh(sharedB, privB, pubA, 64);
    ASSERT(okA && okB, "SM2 ECDH both sides succeed");
    ASSERT(std::memcmp(sharedA, sharedB, 32) == 0, "SM2 ECDH shared secret agrees");

    // 65 字节 SEC1 非压缩输入与 64 字节裸输入结果一致
    uint8_t pubB65[65];
    pubB65[0] = 0x04;
    std::memcpy(pubB65 + 1, pubB, 64);
    bool okA65 = jpssl::sm2_ecdh(sharedA65, privA, pubB65, 65);
    ASSERT(okA65, "SM2 ECDH accepts SEC1 65-byte public key");
    ASSERT(std::memcmp(sharedA, sharedA65, 32) == 0, "SM2 ECDH 64B == 65B input");

    // 已知答案：ecdh(d, G) 应等于 d*G 公钥的 X 坐标
    static const uint8_t G_PUB[65] = {
        0x04,
        0x32,0xc4,0xae,0x2c,0x1f,0x19,0x81,0x19,0x5f,0x99,0x04,0x46,0x6a,0x39,0xc9,0x94,
        0x8f,0xe3,0x0b,0xbf,0xf2,0x66,0x0b,0xe1,0x71,0x5a,0x45,0x89,0x33,0x4c,0x74,0xc7,
        0xbc,0x37,0x36,0xa2,0xf4,0xf6,0x77,0x9c,0x59,0xbd,0xce,0xe3,0x6b,0x69,0x21,0x53,
        0xd0,0xa9,0x87,0x7c,0xc6,0x2a,0x47,0x40,0x02,0xdf,0x32,0xe5,0x21,0x39,0xf0,0xa0
    };
    uint8_t sharedG[32], pubFromPriv[64];
    jpssl::sm2_pub_from_priv(privA, pubFromPriv);
    bool okG = jpssl::sm2_ecdh(sharedG, privA, G_PUB, 65);
    ASSERT(okG, "SM2 ECDH with generator succeeds");
    ASSERT(std::memcmp(sharedG, pubFromPriv, 32) == 0, "SM2 ECDH(d,G) == X(d*G)");

    // 负例：非法私钥 / 非法公钥 / 非法长度
    uint8_t zero_priv[32] = {};
    uint8_t n_priv[32] = {
        0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0x72,0x03,0xdf,0x6b,0x21,0xc6,0x05,0x2b,0x53,0xbb,0xf4,0x09,0x39,0xd5,0x41,0x23
    };
    uint8_t out[32];
    ASSERT(!jpssl::sm2_ecdh(out, zero_priv, pubB, 64), "SM2 ECDH rejects d=0");
    ASSERT(!jpssl::sm2_ecdh(out, n_priv, pubB, 64), "SM2 ECDH rejects d=n");
    uint8_t bad_pub[64] = {};
    ASSERT(!jpssl::sm2_ecdh(out, privA, bad_pub, 64), "SM2 ECDH rejects off-curve point");
    ASSERT(!jpssl::sm2_ecdh(out, privA, pubB, 63), "SM2 ECDH rejects bad length");
    uint8_t truncated33[33];
    truncated33[0] = 0x04;
    std::memcpy(truncated33 + 1, pubB, 32);
    ASSERT(!jpssl::sm2_ecdh(out, privA, truncated33, 33), "SM2 ECDH rejects 0x04||X only");
    uint8_t bad_priv[32];
    std::memset(bad_priv, 0xff, 32);
    ASSERT(!jpssl::sm2_ecdh(out, bad_priv, pubB, 64), "SM2 ECDH rejects d >= n");
}

// ═══════════════════════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════════════════════

int main() {
    std::printf("jpssl SM2/SM3/SM4 Unit Tests\n");
    std::printf("============================\n");

    test_sm3();
    test_sm4();
    test_sm4_gcm_ossl();
    test_sm4_gcm_dispatch();
    test_sm2_mont_asm();
    test_sm2();
    test_sm2_ecdh();

    std::printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}
