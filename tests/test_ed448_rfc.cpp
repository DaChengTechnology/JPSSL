/**
 * test_ed448_rfc.cpp — Ed448 测试向量验证
 *
 * 测试覆盖:
 *   1. Ed448 密钥派生 + 签名 + 自验证
 *   2. Ed448 与 OpenSSL 签名互操作性（我们签，OpenSSL 验）
 *   3. Ed448 与 OpenSSL 签名互操作性（OpenSSL 签，我们验）
 *   4. 篡改签名/消息导致验证失败
 *   5. 确定性签名（同 seed + 同 msg 产生同签名）
 *   6. 多轮签名验证稳定性
 *   7. RFC 8032 §7.6 测试向量 1 (空消息)
 */
#include "ed448.hpp"
#include "sha3.hpp"
#include <cstdio>
#include <cstring>
#include <openssl/evp.h>

using namespace jpssl;

static void print_hex(const char* label, const uint8_t* data, size_t n) {
    printf("%s: ", label);
    for (size_t i = 0; i < n; ++i) printf("%02x", data[i]);
    printf("\n");
}

static bool check_eq(const char* name, const uint8_t* got, const uint8_t* exp, size_t n) {
    bool ok = (memcmp(got, exp, n) == 0);
    printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        print_hex("  Got     ", got, n);
        print_hex("  Expected", exp, n);
    }
    return ok;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool ossl_ed448_verify(const uint8_t pub[57], const uint8_t* msg, size_t msg_len, const uint8_t sig[114]) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr, pub, 57);
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        ok = (EVP_DigestVerify(ctx, sig, 114, msg, msg_len) == 1);
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

static bool ossl_ed448_sign(const uint8_t priv_seed[57], const uint8_t* msg, size_t msg_len, uint8_t sig[114]) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, nullptr, priv_seed, 57);
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;
    size_t sig_len = 114;
    if (ctx && EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        ok = (EVP_DigestSign(ctx, sig, &sig_len, msg, msg_len) == 1);
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

int main() {
    bool all = true;

    // ════════════════════════════════════════════════════════════════════
    // 测试 1: Ed448 密钥派生 + 签名 + 自验证
    // ════════════════════════════════════════════════════════════════════
    {
        uint8_t pub[57], priv[114];
        ed448_generate_keypair(pub, priv);

        const uint8_t msg[] = "Ed448 self-test message";
        uint8_t sig[114];
        ed448_sign(priv, msg, sizeof(msg) - 1, sig);

        bool ok = ed448_verify(pub, msg, sizeof(msg) - 1, sig);
        printf("[%s] Ed448 self sign+verify\n", ok ? "PASS" : "FAIL");
        all &= ok;
    }

    // ════════════════════════════════════════════════════════════════════
    // 测试 2: 我们签名，OpenSSL 验证
    // ════════════════════════════════════════════════════════════════════
    {
        uint8_t pub[57], priv[114];
        ed448_generate_keypair(pub, priv);

        const uint8_t msg[] = "Our signature, OpenSSL verifies";
        uint8_t sig[114];
        ed448_sign(priv, msg, sizeof(msg) - 1, sig);

        bool ok = ossl_ed448_verify(pub, msg, sizeof(msg) - 1, sig);
        printf("[%s] Ed448 OpenSSL verifies our signature\n", ok ? "PASS" : "FAIL");
        all &= ok;
    }

    // ════════════════════════════════════════════════════════════════════
    // 测试 3: OpenSSL 签名，我们验证
    // ════════════════════════════════════════════════════════════════════
    {
        uint8_t pub[57], priv[114];
        ed448_generate_keypair(pub, priv);

        const uint8_t msg[] = "OpenSSL signs, we verify";
        uint8_t ossl_sig[114];
        bool sign_ok = ossl_ed448_sign(priv, msg, sizeof(msg) - 1, ossl_sig);
        printf("[%s] OpenSSL Ed448 sign\n", sign_ok ? "PASS" : "FAIL");
        all &= sign_ok;

        if (sign_ok) {
            bool our_verify = ed448_verify(pub, msg, sizeof(msg) - 1, ossl_sig);
            printf("[%s] Our Ed448 verify OpenSSL signature\n", our_verify ? "PASS" : "FAIL");
            all &= our_verify;
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // 测试 4: 篡改签名/消息导致验证失败
    // ════════════════════════════════════════════════════════════════════
    {
        uint8_t pub[57], priv[114];
        ed448_generate_keypair(pub, priv);

        const uint8_t msg[] = "Tamper detection test";
        uint8_t sig[114];
        ed448_sign(priv, msg, sizeof(msg) - 1, sig);

        // 篡改签名
        uint8_t bad_sig[114];
        memcpy(bad_sig, sig, 114);
        bad_sig[0] ^= 0x01;
        bool bad1 = ed448_verify(pub, msg, sizeof(msg) - 1, bad_sig);
        printf("[%s] Ed448 reject tampered signature\n", !bad1 ? "PASS" : "FAIL");
        all &= !bad1;

        // 篡改消息
        const uint8_t bad_msg[] = "tamper detection test!";
        bool bad2 = ed448_verify(pub, bad_msg, sizeof(bad_msg) - 1, sig);
        printf("[%s] Ed448 reject tampered message\n", !bad2 ? "PASS" : "FAIL");
        all &= !bad2;
    }

    // ════════════════════════════════════════════════════════════════════
    // 测试 5: 确定性签名
    // ════════════════════════════════════════════════════════════════════
    {
        uint8_t seed[57];
        for (int i = 0; i < 57; ++i) seed[i] = (uint8_t)(i + 1);

        const uint8_t msg[] = "Deterministic signature test";
        uint8_t sig1[114], sig2[114];
        ed448_sign(seed, msg, sizeof(msg) - 1, sig1);
        ed448_sign(seed, msg, sizeof(msg) - 1, sig2);
        bool ok = (memcmp(sig1, sig2, 114) == 0);
        printf("[%s] Ed448 deterministic signature\n", ok ? "PASS" : "FAIL");
        all &= ok;

        // 用 OpenSSL 验证
        uint8_t pub[57];
        ed448_keygen(pub, seed);
        bool ossl_ok = ossl_ed448_verify(pub, msg, sizeof(msg) - 1, sig1);
        printf("[%s] Deterministic sig OpenSSL verify\n", ossl_ok ? "PASS" : "FAIL");
        all &= ossl_ok;
    }

    // ════════════════════════════════════════════════════════════════════
    // 测试 6: 多轮签名验证稳定性
    // ════════════════════════════════════════════════════════════════════
    {
        uint8_t pub[57], priv[114];
        ed448_generate_keypair(pub, priv);
        bool ok = true;
        for (int i = 0; i < 3 && ok; ++i) {
            uint8_t msg[32];
            for (int j = 0; j < 32; ++j) msg[j] = (uint8_t)(i * 32 + j);
            uint8_t sig[114];
            ed448_sign(priv, msg, 32, sig);
            if (!ed448_verify(pub, msg, 32, sig)) { ok = false; break; }
            msg[0] ^= 1;
            if (ed448_verify(pub, msg, 32, sig)) { ok = false; break; }
        }
        printf("[%s] 3-round sign/verify stability\n", ok ? "PASS" : "FAIL");
        all &= ok;
    }

    // ════════════════════════════════════════════════════════════════════
    // DEBUG: Base point roundtrip and [1]B check
    // ════════════════════════════════════════════════════════════════════
    {
        static const uint8_t B_ENC[57] = {
            0x14,0xfa,0x30,0xf2,0x5b,0x79,0x08,0x98,0xad,0xc8,0xd7,0x4e,
            0x2c,0x13,0xbd,0xfd,0xc4,0x39,0x7c,0xe6,0x1c,0xff,0xd3,0x3a,
            0xd7,0xc2,0xa0,0x05,0x1e,0x9c,0x78,0x87,0x40,0x98,0xa3,0x6c,
            0x73,0x73,0xea,0x4b,0x62,0xc7,0xc9,0x56,0x37,0x20,0x76,0x88,
            0x24,0xbc,0xb6,0x6e,0x71,0x46,0x3f,0x69,0x00
        };
        // Test roundtrip
        {
            jpssl::ed448_point BP;
            bool bok = jpssl::ed448_debug_decode(BP, B_ENC);
            uint8_t re_enc[57];
            jpssl::ed448_debug_encode(BP, re_enc);
            bool bmatch = bok && memcmp(B_ENC, re_enc, 57) == 0;
            printf("[%s] Base point roundtrip\n", bmatch ? "PASS" : "FAIL");
            if (!bmatch) {
                print_hex("  B_ENC", B_ENC, 57);
                print_hex("  re-enc", re_enc, 57);
                printf("  decode=%s\n", bok ? "OK" : "FAIL");
            }
            all &= bmatch;
        }
        // Test [1]B = B
        {
            jpssl::ed448_point BP;
            jpssl::ed448_debug_decode(BP, B_ENC);
            uint8_t one[57] = {1};
            jpssl::ed448_point B1;
            jpssl::ed448_debug_scalar_mult(B1, one, BP);
            uint8_t b1_enc[57];
            jpssl::ed448_debug_encode(B1, b1_enc);
            bool b1_ok = memcmp(B_ENC, b1_enc, 57) == 0;
            printf("[%s] [1]B = B\n", b1_ok ? "PASS" : "FAIL");
            if (!b1_ok) {
                print_hex("  B    ", B_ENC, 57);
                print_hex("  [1]B ", b1_enc, 57);
            }
            all &= b1_ok;
        }
        // Test [2]B vs B+B
        {
            jpssl::ed448_point BP;
            jpssl::ed448_debug_decode(BP, B_ENC);
            uint8_t two[57] = {2};
            jpssl::ed448_point B2;
            jpssl::ed448_debug_scalar_mult(B2, two, BP);
            uint8_t b2_enc[57];
            jpssl::ed448_debug_encode(B2, b2_enc);
            
            jpssl::ed448_point sum;
            jpssl::ed448_debug_point_add(sum, BP, BP);
            uint8_t sum_enc[57];
            jpssl::ed448_debug_encode(sum, sum_enc);
            bool b2_ok = memcmp(b2_enc, sum_enc, 57) == 0;
            printf("[%s] [2]B == B+B\n", b2_ok ? "PASS" : "FAIL");
            if (!b2_ok) { print_hex("  [2]B", b2_enc, 57); print_hex("  B+B ", sum_enc, 57); }
            all &= b2_ok;
        }
        // Test [3]B = [2]B + B
        {
            jpssl::ed448_point BP;
            jpssl::ed448_debug_decode(BP, B_ENC);
            uint8_t three[57] = {3};
            jpssl::ed448_point B3;
            jpssl::ed448_debug_scalar_mult(B3, three, BP);
            uint8_t b3_enc[57];
            jpssl::ed448_debug_encode(B3, b3_enc);
            
            jpssl::ed448_point B2;
            uint8_t two[57] = {2};
            jpssl::ed448_debug_scalar_mult(B2, two, BP);
            jpssl::ed448_point expected;
            jpssl::ed448_debug_point_add(expected, B2, BP);
            uint8_t exp_enc[57];
            jpssl::ed448_debug_encode(expected, exp_enc);
            bool b3_ok = memcmp(b3_enc, exp_enc, 57) == 0;
            printf("[%s] [3]B == [2]B + B\n", b3_ok ? "PASS" : "FAIL");
            if (!b3_ok) { print_hex("  [3]B", b3_enc, 57); print_hex("  [2]B+B", exp_enc, 57); }
            all &= b3_ok;
        }
        // Progressive scalar test up to 500
        {
            jpssl::ed448_point BP;
            jpssl::ed448_debug_decode(BP, B_ENC);
            jpssl::ed448_point cur;
            jpssl::ed448_debug_decode(cur, B_ENC);
            uint8_t expected[57], got[57];
            bool all_ok = true;
            for (int n = 2; n <= 500; ++n) {
                jpssl::ed448_debug_point_add(cur, cur, BP);
                jpssl::ed448_debug_encode(cur, expected);
                uint8_t scalar_n[57] = {};
                scalar_n[0] = (uint8_t)(n & 0xFF);
                scalar_n[1] = (uint8_t)((n >> 8) & 0xFF);
                jpssl::ed448_point Gn;
                jpssl::ed448_debug_scalar_mult(Gn, scalar_n, BP);
                jpssl::ed448_debug_encode(Gn, got);
                if (memcmp(expected, got, 57) != 0) {
                    printf("[FAIL] scalar_mult([%d]B) at n=%d\n", n, n);
                    print_hex("  expected", expected, 57);
                    print_hex("  got     ", got, 57);
                    all_ok = false; break;
                }
            }
            if (all_ok) printf("[PASS] [2..500]B scalar_mult == repeated add\n");
            all &= all_ok;
        }
        // Test with the exact RFC scalar (mod_L value)
        {
            jpssl::ed448_point BP;
            jpssl::ed448_debug_decode(BP, B_ENC);
            // Unreduced (pruned) scalar from SHAKE256 of RFC seed
            const char* s_hex = "e83930a0cea0808ec7ed6667f472a588b411f0545ba4f3ee75025e1d38519cb905c036d81eeed17483f9f56615ceee4fa70501a71fc0bbb700";
            uint8_t s_bytes[57];
            hex_to_bytes(s_hex, s_bytes, 57);
            jpssl::ed448_point Gs;
            jpssl::ed448_debug_scalar_mult(Gs, s_bytes, BP);
            uint8_t gs_enc[57];
            jpssl::ed448_debug_encode(Gs, gs_enc);
            const char* exp_pub_hex = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
            uint8_t exp_pub[57];
            hex_to_bytes(exp_pub_hex, exp_pub, 57);
            bool exact_ok = memcmp(gs_enc, exp_pub, 57) == 0;
            printf("[%s] RFC scalar * B = expected public key\n", exact_ok ? "PASS" : "FAIL");
            if (!exact_ok) {
                print_hex("  got     ", gs_enc, 57);
                print_hex("  expected", exp_pub, 57);
            }
            all &= exact_ok;
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // 测试 7: RFC 8032 §7.6 测试向量 1 (空消息)
    //   私钥 seed: 6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b
    //   公钥:     5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180
    // ════════════════════════════════════════════════════════════════════
    {
        // RFC 8032 §7.6 (§7.4 in HTML) test vector 1: empty message
        const char* priv_hex = "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
        const char* pub_hex = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";

            uint8_t priv[57], exp_pub[57];
            if (!hex_to_bytes(priv_hex, priv, 57) || !hex_to_bytes(pub_hex, exp_pub, 57)) {
                printf("[FAIL] RFC8032 §7.6 #1 hex parse\n");
                all = false;
            } else {
                uint8_t pub[57];
                ed448_keygen(pub, priv);
                all &= check_eq("RFC8032 §7.6 #1 keygen", pub, exp_pub, 57);

                // 签名空消息，用 OpenSSL 验证
                uint8_t sig[114];
                ed448_sign(priv, nullptr, 0, sig);
                bool ossl_ok = ossl_ed448_verify(pub, nullptr, 0, sig);
                printf("[%s] RFC8032 §7.6 #1 empty msg OpenSSL verify\n", ossl_ok ? "PASS" : "FAIL");
                all &= ossl_ok;
            }
    }

    // ════════════════════════════════════════════════════════════════════
    // 测试 8: 1 字节消息测试
    // ════════════════════════════════════════════════════════════════════
    {
        // 用一个简单的 seed
        uint8_t priv[57];
        for (int i = 0; i < 57; ++i) priv[i] = (uint8_t)(0x42 + i);

        uint8_t pub[57];
        ed448_keygen(pub, priv);

        const uint8_t msg[] = {0x03};
        uint8_t sig[114];
        ed448_sign(priv, msg, 1, sig);

        bool ossl_ok = ossl_ed448_verify(pub, msg, 1, sig);
        printf("[%s] Ed448 1-byte msg OpenSSL verify\n", ossl_ok ? "PASS" : "FAIL");
        all &= ossl_ok;
    }

    printf("\n%s\n", all ? "ALL ED448 TESTS PASSED" : "SOME ED448 TESTS FAILED");
    return all ? 0 : 1;
}
