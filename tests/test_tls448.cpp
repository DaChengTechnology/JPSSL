/**
 * test_tls448.cpp — TLS 1.3 X448/Ed448 握手单元测试
 *
 * 测试覆盖:
 *   1. Ed448 证书签名/验证（含篡改检测）
 *   2. X448 + Ed448 完整握手往返
 *   3. X25519 + Ed448 混合算法握手（Ed448 证书 + X25519 密钥交换）
 *   4. 多证书管理器含 Ed448 证书
 *   5. 篡改 Finished 消息的握手失败检测
 *   6. 与 OpenSSL Ed448 签名互通性验证
 */
#include "test_utils.hpp"
#include "tls.hpp"
#include "ed448.hpp"
#include "ed25519.hpp"
#include "ecdsa.hpp"
#include "rsa.hpp"
#include "x448.hpp"
#include "x25519.hpp"
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace jpssl::tls;
using namespace jpssl;

// ─── 辅助：OpenSSL Ed448 验证（互操作性测试）────────────────────────
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

// ========================================================================
//  测试 1: Ed448 证书签名验证
// ========================================================================

void test_ed448_certificate() {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "ed448.test";
    cert->sig_alg = SignatureAlgorithm::ED448;
    ed448_generate_keypair(cert->pub.ed448, cert->priv.ed448);

    const uint8_t test_data[] = "Test message for Ed448 signature";
    uint8_t sig[114];
    size_t sig_len;

    bool sign_ok = cert->sign(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("Ed448 sign success", sign_ok);
    TEST("Ed448 sig length 114", sig_len == 114);

    bool verify_ok = cert->verify(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("Ed448 verify valid signature", verify_ok);

    // 篡改签名
    uint8_t bad_sig[114];
    memcpy(bad_sig, sig, 114);
    bad_sig[0] ^= 0xFF;
    bool verify_bad = cert->verify(test_data, sizeof(test_data) - 1, bad_sig, sig_len);
    TEST("Ed448 reject tampered signature", !verify_bad);

    // 篡改消息
    const uint8_t bad_data[] = "Test message for Ed448 signature!";
    bool verify_bad_msg = cert->verify(bad_data, sizeof(bad_data) - 1, sig, sig_len);
    TEST("Ed448 reject tampered message", !verify_bad_msg);
}

// ========================================================================
//  测试 2: Ed448 与 OpenSSL 互操作性
// ========================================================================

void test_ed448_openssl_interop() {
    uint8_t pub[57], priv[114];
    ed448_generate_keypair(pub, priv);

    const uint8_t msg[] = "Ed448 OpenSSL interop test message";
    uint8_t sig[114];
    ed448_sign(priv, msg, sizeof(msg) - 1, sig);

    // 使用 OpenSSL 验证我们的签名
    bool ok = ossl_ed448_verify(pub, msg, sizeof(msg) - 1, sig);
    TEST("Ed448 OpenSSL verifies our signature", ok);
}

// ========================================================================
//  测试 3: TLS 1.3 X448 + Ed448 完整握手
// ========================================================================

void test_tls13_x448_ed448_handshake() {
    // ── 准备 Ed448 服务端证书 ──
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ED448;
    ed448_generate_keypair(server_cert->pub.ed448, server_cert->priv.ed448);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    // ── 客户端发起握手（使用 X448 密钥交换）──
    tls_session client;
    client.server_name = "localhost";
    client.ks_group = NamedGroup::X448;  // 关键：选择 X448
    std::vector<uint8_t> client_hello;
    bool ch_ok = tls13_make_client_hello(client, client_hello);
    TEST("X448+Ed448: ClientHello generated", ch_ok);
    TEST("X448+Ed448: ClientHello not empty", !client_hello.empty());

    // ── 服务端处理 ClientHello ──
    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                           server_flight, cert_mgr);
    TEST("X448+Ed448: ServerFlight generated", sh_ok);
    TEST("X448+Ed448: server selected X448", server.ks_group == NamedGroup::X448);

    // ── 客户端处理 ServerFlight ──
    std::vector<uint8_t> client_finished;
    bool cf_ok = tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                             client_finished, &cert_mgr);
    TEST("X448+Ed448: Client processed ServerFlight", cf_ok);

    // ── 服务端验证 Client Finished ──
    bool ok_fin = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("X448+Ed448: Server verified Client Finished", ok_fin);

    // ── 记录层加解密测试 ──
    const uint8_t app_data[] = "Hello, TLS 1.3 with X448+Ed448!";
    auto encrypted = tls_encrypt(client, ContentType::APPLICATION_DATA, app_data, sizeof(app_data) - 1);
    TEST("X448+Ed448: Client encrypt", !encrypted.empty());

    ContentType ct;
    std::vector<uint8_t> decrypted;
    bool dec_ok = tls_decrypt(server, encrypted.data(), encrypted.size(), ct, decrypted);
    TEST("X448+Ed448: Server decrypt", dec_ok);
    TEST("X448+Ed448: Content type APPLICATION_DATA", ct == ContentType::APPLICATION_DATA);
    TEST("X448+Ed448: Decrypted matches",
         decrypted.size() == sizeof(app_data) - 1 &&
         std::memcmp(decrypted.data(), app_data, sizeof(app_data) - 1) == 0);

    // 服务端回包测试
    const uint8_t resp[] = "Server response over X448+Ed448";
    auto server_enc = tls_encrypt(server, ContentType::APPLICATION_DATA, resp, sizeof(resp) - 1);
    ContentType ct2;
    std::vector<uint8_t> client_dec;
    bool dec_ok2 = tls_decrypt(client, server_enc.data(), server_enc.size(), ct2, client_dec);
    TEST("X448+Ed448: Client decrypt server response", dec_ok2);
    TEST("X448+Ed448: Response matches",
         client_dec.size() == sizeof(resp) - 1 &&
         std::memcmp(client_dec.data(), resp, sizeof(resp) - 1) == 0);
}

// ========================================================================
//  测试 4: X25519 + Ed448 混合算法握手
//  (X25519 密钥交换 + Ed448 证书签名)
// ========================================================================

void test_tls13_x25519_ed448_hybrid() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ED448;
    ed448_generate_keypair(server_cert->pub.ed448, server_cert->priv.ed448);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    // 客户端默认使用 X25519
    tls_session client;
    client.server_name = "localhost";
    client.ks_group = NamedGroup::X25519;
    std::vector<uint8_t> client_hello;
    bool ch_ok = tls13_make_client_hello(client, client_hello);
    TEST("X25519+Ed448: ClientHello generated", ch_ok);

    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                           server_flight, cert_mgr);
    TEST("X25519+Ed448: ServerFlight generated", sh_ok);
    TEST("X25519+Ed448: server uses X25519", server.ks_group == NamedGroup::X25519);

    std::vector<uint8_t> client_finished;
    bool cf_ok = tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                             client_finished, &cert_mgr);
    TEST("X25519+Ed448: Client processed ServerFlight", cf_ok);

    bool ok_fin = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("X25519+Ed448: Server verified Client Finished", ok_fin);

    // 记录层往返
    const uint8_t msg[] = "Hybrid X25519+Ed448 test";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, msg, sizeof(msg) - 1);
    ContentType ct;
    std::vector<uint8_t> dec;
    bool dec_ok = tls_decrypt(server, enc.data(), enc.size(), ct, dec);
    TEST("X25519+Ed448: Round-trip decrypt", dec_ok);
    TEST("X25519+Ed448: Decrypted matches",
         dec.size() == sizeof(msg) - 1 &&
         std::memcmp(dec.data(), msg, sizeof(msg) - 1) == 0);
}

// ========================================================================
//  测试 5: 多证书管理器（含 Ed448）
//  验证 SNI 能正确路由到不同算法的证书
// ========================================================================

void test_multi_cert_with_ed448() {
    tls_certificate_manager mgr;

    // Ed25519 证书
    auto c1 = std::make_unique<tls_certificate>();
    c1->subject_name = "ed25519.example.com";
    c1->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(c1->pub.ed25519, c1->priv.ed25519);
    mgr.add_certificate("ed25519.example.com", std::move(c1));

    // Ed448 证书
    auto c2 = std::make_unique<tls_certificate>();
    c2->subject_name = "ed448.example.com";
    c2->sig_alg = SignatureAlgorithm::ED448;
    ed448_generate_keypair(c2->pub.ed448, c2->priv.ed448);
    mgr.add_certificate("ed448.example.com", std::move(c2));

    // ECDSA 证书
    auto c3 = std::make_unique<tls_certificate>();
    c3->subject_name = "ecdsa.example.com";
    c3->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    ecdsa_p256_keygen(c3->pub.ecdsa_p256, c3->priv.ecdsa_p256);
    mgr.add_certificate("ecdsa.example.com", std::move(c3));

    TEST("Multi-cert: count 3", mgr.count() == 3);

    // 对 ed448.example.com 发起 X448 握手
    tls_session client;
    client.server_name = "ed448.example.com";
    client.ks_group = NamedGroup::X448;
    std::vector<uint8_t> ch;
    bool ch_ok = tls13_make_client_hello(client, ch);
    TEST("Multi-cert: ClientHello for ed448.example.com", ch_ok);

    tls_session server;
    std::vector<uint8_t> sf;
    bool sf_ok = tls13_make_server_flight(server, ch.data(), ch.size(), sf, mgr);
    TEST("Multi-cert: ServerFlight for ed448.example.com", sf_ok);

    std::vector<uint8_t> cf;
    bool cf_ok = tls13_process_server_flight(client, sf.data(), sf.size(), cf, &mgr);
    TEST("Multi-cert: Client finished for ed448.example.com", cf_ok);

    bool fin_ok = tls13_process_client_finished(server, cf.data(), cf.size());
    TEST("Multi-cert: Handshake complete for ed448.example.com", fin_ok);

    // 对 ecdsa.example.com 发起 X25519 握手
    tls_session client2;
    client2.server_name = "ecdsa.example.com";
    client2.ks_group = NamedGroup::X25519;
    std::vector<uint8_t> ch2;
    tls13_make_client_hello(client2, ch2);
    tls_session server2;
    std::vector<uint8_t> sf2;
    bool sf2_ok = tls13_make_server_flight(server2, ch2.data(), ch2.size(), sf2, mgr);
    TEST("Multi-cert: ServerFlight for ecdsa.example.com", sf2_ok);

    std::vector<uint8_t> cf2;
    bool cf2_ok = tls13_process_server_flight(client2, sf2.data(), sf2.size(), cf2, &mgr);
    TEST("Multi-cert: Client finished for ecdsa.example.com", cf2_ok);
}

// ========================================================================
//  测试 6: 篡改握手消息导致失败
// ========================================================================

void test_tampered_handshake_fails() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ED448;
    ed448_generate_keypair(server_cert->pub.ed448, server_cert->priv.ed448);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client;
    client.server_name = "localhost";
    client.ks_group = NamedGroup::X448;
    std::vector<uint8_t> client_hello;
    tls13_make_client_hello(client, client_hello);

    tls_session server;
    std::vector<uint8_t> server_flight;
    tls13_make_server_flight(server, client_hello.data(), client_hello.size(), server_flight, cert_mgr);

    // 篡改 ServerFlight 中的某个字节
    if (server_flight.size() > 100) {
        server_flight[100] ^= 0x01;
    }
    std::vector<uint8_t> client_finished;
    bool cf_ok = tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                             client_finished, &cert_mgr);
    TEST("Tampered ServerFlight rejected", !cf_ok);
}

// ========================================================================
//  测试 7: 简化 API（X448+Ed448）
// ========================================================================

void test_simplified_x448_ed448() {
    tls_certificate_manager cert_mgr;
    auto cert = std::make_unique<tls_certificate>();
    cert->sig_alg = SignatureAlgorithm::ED448;
    ed448_generate_keypair(cert->pub.ed448, cert->priv.ed448);
    cert_mgr.add_certificate("localhost", std::move(cert));

    tls_session client, server;
    client.ks_group = NamedGroup::X448;
    std::vector<uint8_t> client_hello;

    bool ch_ok = tls13_make_client_hello(client, client_hello);
    TEST("Simplified X448: ClientHello", ch_ok);

    std::vector<uint8_t> server_response;
    bool sh_ok = tls13_handshake_server(server, client_hello.data(), client_hello.size(),
                                        server_response, cert_mgr);
    TEST("Simplified X448: Server handshake", sh_ok);

    std::vector<uint8_t> client_finished;
    bool done = tls13_process_server_flight(client, server_response.data(), server_response.size(),
                                            client_finished, &cert_mgr);
    TEST("Simplified X448: Client done", done);

    // 服务端验证 Client Finished，派生应用密钥
    bool svr_fin_ok = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("Simplified X448: Server finished", svr_fin_ok);

    // 应用数据
    const uint8_t msg[] = "Simplified X448+Ed448 API";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, msg, sizeof(msg) - 1);
    ContentType ct;
    std::vector<uint8_t> dec;
    bool dec_ok = tls_decrypt(server, enc.data(), enc.size(), ct, dec);
    TEST("Simplified X448: Decrypt round-trip", dec_ok);
}

// ========================================================================
//  入口
// ========================================================================

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::cout << "Running TLS 1.3 X448/Ed448 unit tests\n" << std::endl;

    RUN_TEST(test_ed448_certificate);
    RUN_TEST(test_ed448_openssl_interop);
    RUN_TEST(test_tls13_x448_ed448_handshake);
    RUN_TEST(test_tls13_x25519_ed448_hybrid);
    RUN_TEST(test_multi_cert_with_ed448);
    RUN_TEST(test_tampered_handshake_fails);
    RUN_TEST(test_simplified_x448_ed448);

    return test_summary();
}
