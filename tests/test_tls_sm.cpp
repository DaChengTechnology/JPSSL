/** test_tls_sm.cpp — RFC 8998 TLS 1.3 SM cipher suite 测试 */
#include "tls.hpp"
#include "sm2.hpp"
#include "sm3.hpp"
#include "sm4.hpp"
#include "sm4_gcm.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <memory>
#include <cassert>

using namespace jpssl::tls;
using namespace jpssl;

#define TEST(name, cond) do { \
    if (cond) std::printf("  PASS: %s\n", name); \
    else { std::fprintf(stderr, "  FAIL: %s\n", name); std::exit(1); } \
} while(0)

static int tests_passed = 0, tests_failed = 0;

static void test_sm4_gcm_aead() {
    std::printf("\n=== SM4-GCM AEAD 测试 ===\n");

    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    sm4_ctx ctx;
    sm4_init(&ctx, key);

    const uint8_t plain[] = "SM4-GCM encryption test!";
    const uint8_t aad[] = "additional data";
    uint8_t iv[12] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b};

    std::vector<uint8_t> ciphertext;
    uint8_t tag[16];
    sm4_gcm_encrypt(&ctx, iv, 12,
                    std::span<const uint8_t>(plain, sizeof(plain)-1),
                    std::span<const uint8_t>(aad, sizeof(aad)-1),
                    ciphertext, tag, 16);

    TEST("SM4-GCM encrypt non-empty", !ciphertext.empty());
    TEST("SM4-GCM ciphertext length matches plain",
         ciphertext.size() == sizeof(plain) - 1);

    std::vector<uint8_t> recovered;
    bool ok = sm4_gcm_decrypt(&ctx, iv, 12,
                              std::span<const uint8_t>(ciphertext),
                              std::span<const uint8_t>(aad, sizeof(aad)-1),
                              tag, 16, recovered);

    TEST("SM4-GCM decrypt success", ok);
    TEST("SM4-GCM roundtrip data matches",
         recovered.size() == sizeof(plain)-1 &&
         std::memcmp(recovered.data(), plain, sizeof(plain)-1) == 0);

    // Tampered tag test
    tag[0] ^= 0x01;
    std::vector<uint8_t> dummy;
    bool bad = sm4_gcm_decrypt(&ctx, iv, 12,
                               std::span<const uint8_t>(ciphertext),
                               std::span<const uint8_t>(aad, sizeof(aad)-1),
                               tag, 16, dummy);
    TEST("SM4-GCM rejects tampered tag", !bad);
}

static void test_sm4_gcm_empty() {
    std::printf("\n=== SM4-GCM Empty Plaintext ===\n");
    uint8_t key[16] = {0};
    sm4_ctx ctx;
    sm4_init(&ctx, key);

    uint8_t iv[12] = {0};
    std::vector<uint8_t> ct;
    uint8_t tag[16];
    sm4_gcm_encrypt(&ctx, iv, 12,
                    std::span<const uint8_t>(),
                    std::span<const uint8_t>(),
                    ct, tag, 16);
    TEST("SM4-GCM empty encrypt produces empty ciphertext", ct.empty());

    std::vector<uint8_t> pt;
    bool ok = sm4_gcm_decrypt(&ctx, iv, 12,
                              std::span<const uint8_t>(ct),
                              std::span<const uint8_t>(),
                              tag, 16, pt);
    TEST("SM4-GCM empty decrypt success", ok);
    TEST("SM4-GCM empty decrypt produces empty plaintext", pt.empty());
}

static void test_tls13_sm_handshake() {
    std::printf("\n=== RFC 8998 TLS 1.3 SM Handshake ===\n");

    // 创建 SM2 服务端证书
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::SM2_SM3;
    sm2_keygen(server_cert->pub.sm2, server_cert->priv.sm2);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    // 客户端：请求 TLS_SM4_GCM_SM3
    tls_session client;
    client.server_name = "localhost";
    client.cipher_suite = CipherSuite::TLS_SM4_GCM_SM3;
    std::vector<uint8_t> client_hello;
    bool ch_ok = tls13_make_client_hello(client, client_hello);
    TEST("SM Handshake: ClientHello generated", ch_ok);
    TEST("SM Handshake: ClientHello non-empty", !client_hello.empty());

    // 服务端处理
    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                           server_flight, cert_mgr);
    TEST("SM Handshake: ServerFlight generated", sh_ok);
    TEST("SM Handshake: Server cipher suite is SM4-GCM-SM3",
         server.cipher_suite == CipherSuite::TLS_SM4_GCM_SM3);

    // 客户端处理 ServerFlight
    std::vector<uint8_t> client_finished;
    std::printf("  [DEBUG] ServerFlight size=%zu\n", server_flight.size());
    std::printf("  [DEBUG] Client cipher_suite=%d\n", (int)client.cipher_suite);
    std::printf("  [DEBUG] Server cipher_suite=%d\n", (int)server.cipher_suite);
    // Dump first bytes of ServerFlight for debugging
    std::printf("  [DEBUG] SF hex: "); for(int i=0;i<48 && i<(int)server_flight.size();i++) std::printf("%02x",server_flight[i]); std::printf("\n");
    bool cf_ok = tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                             client_finished, &cert_mgr);
    TEST("SM Handshake: Client processed ServerFlight", cf_ok);

    // 服务端验证 Client Finished
    bool fin_ok = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("SM Handshake: Server verified Client Finished", fin_ok);

    if (!cf_ok || !fin_ok) {
        std::fprintf(stderr, "SM handshake incomplete, skipping record tests\n");
        return;
    }

    // 记录层：客户端→服务端
    const uint8_t app_data[] = "RFC 8998 SM4-GCM application data!";
    auto encrypted = tls_encrypt(client, ContentType::APPLICATION_DATA,
                                  app_data, sizeof(app_data) - 1);
    TEST("SM Record: Client encrypt non-empty", !encrypted.empty());

    ContentType ct;
    std::vector<uint8_t> decrypted;
    bool dec_ok = tls_decrypt(server, encrypted.data(), encrypted.size(), ct, decrypted);
    TEST("SM Record: Server decrypt success", dec_ok);
    TEST("SM Record: Decrypted content matches",
         decrypted.size() == sizeof(app_data) - 1 &&
         std::memcmp(decrypted.data(), app_data, sizeof(app_data) - 1) == 0);

    // 记录层：服务端→客户端
    const uint8_t resp[] = "Server response via SM4-GCM!";
    auto server_enc = tls_encrypt(server, ContentType::APPLICATION_DATA,
                                   resp, sizeof(resp) - 1);
    ContentType ct2;
    std::vector<uint8_t> client_dec;
    bool dec_ok2 = tls_decrypt(client, server_enc.data(), server_enc.size(), ct2, client_dec);
    TEST("SM Record: Client decrypt success", dec_ok2);
    TEST("SM Record: Response matches",
         client_dec.size() == sizeof(resp) - 1 &&
         std::memcmp(client_dec.data(), resp, sizeof(resp) - 1) == 0);
}

int main() {
    std::printf("=== RFC 8998 TLS SM Cipher Suite Tests ===\n");
    test_sm4_gcm_aead();
    test_sm4_gcm_empty();
    test_tls13_sm_handshake();
    std::printf("\n=== ALL RFC 8998 TESTS PASSED ===\n");
    return 0;
}
