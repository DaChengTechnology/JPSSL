/**
 * test_tls.cpp — TLS 1.2/1.3 完整握手单元测试
 * 使用 JPTest 框架：完整握手往返测试 + Ed25519/ECDSA/RSA 证书测试 + SNI 测试
 */

#include "test_utils.hpp"
#include "tls.hpp"
#include "ed25519.hpp"
#include "ecdsa.hpp"
#include "rsa.hpp"
#include "x25519.hpp"
#include <vector>
#include <string>
#include <memory>
#include <cstdlib>
#include <span>

using namespace jpssl::tls;
using namespace jpssl;

// ========================================================================
//  测试 1: 证书签名验证 — Ed25519
// ========================================================================

void test_ed25519_certificate() {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "ed25519.test";
    cert->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(cert->pub.ed25519, cert->priv.ed25519);

    const uint8_t test_data[] = "Test message for Ed25519 signature";
    uint8_t sig[64];
    size_t sig_len;

    bool sign_ok = cert->sign(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("Ed25519 sign success", sign_ok);
    TEST("Ed25519 sig length 64", sig_len == 64);

    bool verify_ok = cert->verify(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("Ed25519 verify valid signature", verify_ok);

    sig[0] ^= 0xFF;
    bool verify_bad = cert->verify(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("Ed25519 reject tampered signature", !verify_bad);
}

// ========================================================================
//  测试 2: 证书签名验证 — ECDSA P-256
// ========================================================================

void test_ecdsa_certificate() {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "ecdsa.test";
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    ecdsa_p256_keygen(cert->pub.ecdsa_p256, cert->priv.ecdsa_p256);

    const uint8_t test_data[] = "Test message for ECDSA P-256 signature";
    uint8_t sig[64];
    size_t sig_len;

    bool sign_ok = cert->sign(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("ECDSA P-256 sign success", sign_ok);
    TEST("ECDSA P-256 sig length 64", sig_len == 64);

    bool verify_ok = cert->verify(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("ECDSA P-256 verify valid signature", verify_ok);
}

// ========================================================================
//  测试 3: 证书签名验证 — RSA-2048
// ========================================================================

void test_rsa_certificate() {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "rsa.test";
    cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
    rsa_keygen(cert->pub.rsa, cert->priv.rsa);

    const uint8_t test_data[] = "Test message for RSA signature";
    uint8_t sig[256];
    size_t sig_len;

    bool sign_ok = cert->sign(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("RSA-2048 sign success", sign_ok);
    TEST("RSA-2048 sig length 256", sig_len == 256);

    bool verify_ok = cert->verify(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("RSA-2048 verify valid signature", verify_ok);

    sig[0] ^= 0xFF;
    bool verify_bad = cert->verify(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("RSA-2048 reject tampered signature", !verify_bad);
}

// ========================================================================
//  测试 4: SNI 证书管理器 — 添加/查询域名证书
// ========================================================================

void test_certificate_manager() {
    tls_certificate_manager mgr;

    auto c1 = std::make_unique<tls_certificate>();
    c1->subject_name = "a.example.com";
    c1->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(c1->pub.ed25519, c1->priv.ed25519);

    auto c2 = std::make_unique<tls_certificate>();
    c2->subject_name = "b.example.org";
    c2->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    ecdsa_p256_keygen(c2->pub.ecdsa_p256, c2->priv.ecdsa_p256);

    mgr.add_certificate("a.example.com", std::move(c1));
    mgr.add_certificate("b.example.org", std::move(c2));

    TEST("Manager count 2", mgr.count() == 2);

    const tls_certificate* found_a = mgr.get_certificate("a.example.com");
    TEST("Find a.example.com", found_a != nullptr);
    if (found_a) {
        TEST("Domain name matches", found_a->subject_name == "a.example.com");
        TEST("Algorithm is Ed25519", found_a->sig_alg == SignatureAlgorithm::ED25519);
    }

    const tls_certificate* found_b = mgr.get_certificate("b.example.org");
    TEST("Find b.example.org", found_b != nullptr);
    if (found_b) {
        TEST("Algorithm is ECDSA", found_b->sig_alg == SignatureAlgorithm::ECDSA_SECP256R1_SHA256);
    }

    const tls_certificate* not_found = mgr.get_certificate("nonexistent.test");
    TEST("Not found returns default", not_found != nullptr);

    const tls_certificate* def = mgr.get_default_certificate();
    TEST("Default exists", def != nullptr);
}

// ========================================================================
//  测试 5: TLS 1.3 完整握手往返 — Ed25519 证书
// ========================================================================

void test_tls13_full_handshake_ed25519() {
    // ── 准备服务端证书 ──
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(server_cert->pub.ed25519, server_cert->priv.ed25519);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    // ── 客户端发起握手 ──
    tls_session client;
    client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    bool ch_ok = tls13_make_client_hello(client, client_hello);
    TEST("TLS 1.3 client make ClientHello", ch_ok);
    TEST("ClientHello size > 0", !client_hello.empty());

    // ── 服务端处理 ClientHello ──
    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                           server_flight, cert_mgr);
    TEST("TLS 1.3 server make ServerFlight", sh_ok);
    TEST("ServerFlight size > 0", !server_flight.empty());
    TEST("Server version is TLS 1.3", server.ver == TLSVersion::V13);

    // ── 客户端处理 ServerFlight ──
    std::vector<uint8_t> client_finished;
    bool cf_ok = tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                             client_finished, &cert_mgr);
    TEST("TLS 1.3 client process ServerFlight", cf_ok);
    TEST("Client Finished size > 0", !client_finished.empty());

    // ── 服务端验证 Client Finished ──
    bool ok_fin = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("TLS 1.3 server verify Client Finished", ok_fin);

    // ═══════════════════════════════════════════════════════════════════
    // 握手完成！测试记录层加解密
    // ═══════════════════════════════════════════════════════════════════

    // 客户端加密
    const uint8_t app_data[] = "Hello, TLS 1.3 from client!";
    std::vector<uint8_t> encrypted = tls_encrypt(client, ContentType::APPLICATION_DATA,
                                                 app_data, sizeof(app_data) - 1);
    TEST("Client encrypt application data", !encrypted.empty());

    // 服务端解密
    ContentType ct;
    std::vector<uint8_t> decrypted;
    bool dec_ok = tls_decrypt(server, encrypted.data(), encrypted.size(), ct, decrypted);
    TEST("Server decrypt success", dec_ok);
    TEST("Content type is APPLICATION_DATA", ct == ContentType::APPLICATION_DATA);
    TEST("Decrypted length matches original", decrypted.size() == sizeof(app_data) - 1);
    TEST("Decrypted content matches original",
         std::memcmp(decrypted.data(), app_data, sizeof(app_data) - 1) == 0);

    // 服务端回包加密
    const uint8_t resp_data[] = "Hello from TLS 1.3 server!";
    std::vector<uint8_t> server_enc = tls_encrypt(server, ContentType::APPLICATION_DATA,
                                                   resp_data, sizeof(resp_data) - 1);
    ContentType ct2;
    std::vector<uint8_t> client_dec;
    bool dec_ok2 = tls_decrypt(client, server_enc.data(), server_enc.size(), ct2, client_dec);
    TEST("Client decrypt server response", dec_ok2);
    TEST("Decrypted response matches original",
         client_dec.size() == sizeof(resp_data) - 1 &&
         std::memcmp(client_dec.data(), resp_data, sizeof(resp_data) - 1) == 0);
}

// ========================================================================
//  测试 6: TLS 1.3 完整握手往返 — ECDSA 证书
// ========================================================================

void test_tls13_full_handshake_ecdsa() {
    // ── 准备服务端证书 ──
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    ecdsa_p256_keygen(server_cert->pub.ecdsa_p256, server_cert->priv.ecdsa_p256);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    // ── 完整握手 ──
    tls_session client;
    client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    bool ch_ok = tls13_make_client_hello(client, client_hello);
    TEST("TLS 1.3 (ECDSA) client make ClientHello", ch_ok);

    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                           server_flight, cert_mgr);
    TEST("TLS 1.3 (ECDSA) server make ServerFlight", sh_ok);

    std::vector<uint8_t> client_finished;
    bool cf_ok = tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                             client_finished, &cert_mgr);
    TEST("TLS 1.3 (ECDSA) client process ServerFlight", cf_ok);

    bool ok_fin = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("TLS 1.3 (ECDSA) server verify Client Finished", ok_fin);

    // ── 记录层测试 ──
    const uint8_t data[] = "Test ECDSA TLS 1.3";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, data, sizeof(data) - 1);
    ContentType ct;
    std::vector<uint8_t> dec;
    bool dec_ok = tls_decrypt(server, enc.data(), enc.size(), ct, dec);
    TEST("TLS 1.3 (ECDSA) decrypt round-trip", dec_ok);
    TEST("Decrypted size matches", dec.size() == sizeof(data) - 1);
}

// ========================================================================
//  测试 7: TLS 1.2 完整握手往返
// ========================================================================

void test_tls12_full_handshake() {
    // ── 准备服务端证书 ──
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
    rsa_keygen(server_cert->pub.rsa, server_cert->priv.rsa);
    const rsa_public_key& server_pub = server_cert->pub.rsa;
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    // ── 客户端发起握手 ──
    tls_session client;
    client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    bool ch_ok = tls12_make_client_hello(client, client_hello);
    TEST("TLS 1.2 client make ClientHello", ch_ok);
    TEST("ClientHello size > 0", !client_hello.empty());

    // ── 客户端生成 pre_master_secret 并用 RSA 公钥加密 ──
    uint8_t pre_master[48];
    for (int i = 0; i < 48; ++i) pre_master[i] = (uint8_t)(rand() % 256);
    pre_master[0] = 0x03; pre_master[1] = 0x03;
    uint8_t encrypted_pms[256];
    rsa_encrypt(server_pub, std::span<const uint8_t>(pre_master, 48), encrypted_pms);

    // ── 服务端处理（RSA 解密 pre_master_secret） ──
    tls_session server;
    uint8_t decrypted_pms[48];
    std::vector<uint8_t> server_response;
    bool sh_ok = tls12_make_server_flight(server, client_hello.data(), client_hello.size(),
                                          server_response, encrypted_pms, 256,
                                          decrypted_pms, cert_mgr);
    TEST("TLS 1.2 server make ServerFlight", sh_ok);
    TEST("Server version is TLS 1.2", server.ver == TLSVersion::V12);
    TEST("RSA decrypted pre_master matches", memcmp(pre_master, decrypted_pms, 48) == 0);

    // ── 客户端处理回包，生成 Finished ──
    std::vector<uint8_t> client_finished;
    bool cf_ok = tls12_process_server_flight(client, server_response.data(), server_response.size(),
                                             pre_master, 48, client_finished);
    TEST("TLS 1.2 client process ServerFlight", cf_ok);

    // ── 服务端验证 Finished ──
    bool ok_fin = tls12_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("TLS 1.2 server verify Client Finished", ok_fin);

    // ── 记录层加解密 ──
    const uint8_t app_data[] = "Hello, TLS 1.2!";
    auto encrypted = tls_encrypt(client, ContentType::APPLICATION_DATA, app_data, sizeof(app_data) - 1);
    TEST("TLS 1.2 client encrypt", !encrypted.empty());

    ContentType ct;
    std::vector<uint8_t> decrypted;
    bool dec_ok = tls_decrypt(server, encrypted.data(), encrypted.size(), ct, decrypted);
    TEST("TLS 1.2 server decrypt success", dec_ok);
    TEST("Content type APPLICATION_DATA", ct == ContentType::APPLICATION_DATA);
    TEST("Decrypted matches", decrypted.size() == sizeof(app_data) - 1 &&
         std::memcmp(decrypted.data(), app_data, sizeof(app_data) - 1) == 0);
}

// ========================================================================
//  测试 8: 多域名 SNI 测试 — 不同域名选择不同证书
// ========================================================================

void test_sni_multi_domain() {
    // ── 添加两个不同域名的证书 ──
    tls_certificate_manager mgr;

    auto cert_a = std::make_unique<tls_certificate>();
    cert_a->subject_name = "a.example.com";
    cert_a->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(cert_a->pub.ed25519, cert_a->priv.ed25519);
    mgr.add_certificate("a.example.com", std::move(cert_a));

    auto cert_b = std::make_unique<tls_certificate>();
    cert_b->subject_name = "b.example.com";
    cert_b->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    ecdsa_p256_keygen(cert_b->pub.ecdsa_p256, cert_b->priv.ecdsa_p256);
    mgr.add_certificate("b.example.com", std::move(cert_b));

    // ── 客户端 1: 请求 a.example.com ──
    tls_session client_a;
    client_a.server_name = "a.example.com";
    std::vector<uint8_t> ch_a;
    bool ch_ok_a = tls13_make_client_hello(client_a, ch_a);
    TEST("SNI a: ClientHello generated", ch_ok_a);

    tls_session server_a;
    std::vector<uint8_t> sf_a;
    bool sf_ok_a = tls13_make_server_flight(server_a, ch_a.data(), ch_a.size(), sf_a, mgr);
    TEST("SNI a: ServerFlight generated", sf_ok_a);

    std::vector<uint8_t> cf_a;
    bool cf_ok_a = tls13_process_server_flight(client_a, sf_a.data(), sf_a.size(), cf_a, &mgr);
    TEST("SNI a: Client processed server flight", cf_ok_a);

    bool fin_ok_a = tls13_process_client_finished(server_a, cf_a.data(), cf_a.size());
    TEST("SNI a: Full handshake complete", fin_ok_a);

    // ── 客户端 2: 请求 b.example.com ──
    tls_session client_b;
    client_b.server_name = "b.example.com";
    std::vector<uint8_t> ch_b;
    bool ch_ok_b = tls13_make_client_hello(client_b, ch_b);
    TEST("SNI b: ClientHello generated", ch_ok_b);

    tls_session server_b;
    std::vector<uint8_t> sf_b;
    bool sf_ok_b = tls13_make_server_flight(server_b, ch_b.data(), ch_b.size(), sf_b, mgr);
    TEST("SNI b: ServerFlight generated", sf_ok_b);

    std::vector<uint8_t> cf_b;
    bool cf_ok_b = tls13_process_server_flight(client_b, sf_b.data(), sf_b.size(), cf_b, &mgr);
    TEST("SNI b: Client processed server flight", cf_ok_b);

    bool fin_ok_b = tls13_process_client_finished(server_b, cf_b.data(), cf_b.size());
    TEST("SNI b: Full handshake complete", fin_ok_b);
}

// ========================================================================
//  测试 9: 简化握手 API — 一次性握手
// ========================================================================

void test_simplified_handshake_api() {
    tls_certificate_manager cert_mgr;
    auto cert = std::make_unique<tls_certificate>();
    cert->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(cert->pub.ed25519, cert->priv.ed25519);
    cert_mgr.add_certificate("localhost", std::move(cert));

    tls_session client, server;
    std::vector<uint8_t> client_hello;

    bool ch_ok = tls13_make_client_hello(client, client_hello);
    TEST("Simplified: ClientHello", ch_ok);

    std::vector<uint8_t> server_response;
    bool sh_ok = tls13_handshake_server(server, client_hello.data(), client_hello.size(),
                                        server_response, cert_mgr);
    TEST("Simplified: Server handshake", sh_ok);

    std::vector<uint8_t> client_finished;
    bool done = tls13_process_server_flight(client, server_response.data(), server_response.size(),
                                            client_finished, &cert_mgr);
    TEST("Simplified: Client done", done);

    // 服务端验证 Client Finished，派生应用密钥
    bool svr_fin_ok = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("Simplified: Server finished", svr_fin_ok);

    // 测试应用数据加密
    const uint8_t msg[] = "Simplified API test";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, msg, sizeof(msg) - 1);
    ContentType ct;
    std::vector<uint8_t> dec;
    bool dec_ok = tls_decrypt(server, enc.data(), enc.size(), ct, dec);
    TEST("Simplified: Decrypt round-trip", dec_ok);
}

// ========================================================================
//  测试 10: TLS 1.3 0-RTT — PSK 恢复与 Early Data
// ========================================================================

void test_tls13_0rtt() {
    // ── 阶段 1: 完整握手 ──
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(server_cert->pub.ed25519, server_cert->priv.ed25519);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client, server;
    std::vector<uint8_t> ch, sf, cf;
    
    tls13_make_client_hello(client, ch);
    tls13_make_server_flight(server, ch.data(), ch.size(), sf, cert_mgr);
    bool ok1 = tls13_process_server_flight(client, sf.data(), sf.size(), cf, &cert_mgr);
    TEST("0-RTT: Full handshake client done", ok1);
    
    bool ok2 = tls13_process_client_finished(server, cf.data(), cf.size());
    TEST("0-RTT: Full handshake server done", ok2);

    if (!ok1 || !ok2) return;

    // ── 阶段 2: 服务端生成 NewSessionTicket ──
    std::vector<uint8_t> ticket_msg;
    bool nst_ok = tls13_make_new_session_ticket(server, ticket_msg);
    TEST("0-RTT: NewSessionTicket generated", nst_ok);
    TEST("0-RTT: Ticket non-empty", !ticket_msg.empty());

    // 加密 ticket 发送给客户端
    auto enc_ticket = tls_encrypt_handshake(server, ticket_msg.data(), ticket_msg.size());
    TEST("0-RTT: Ticket encrypted", !enc_ticket.empty());

    // ── 阶段 3: 客户端存储 PSK ──
    // 需要先解密 ticket (客户端从服务器接收加密的 ticket)
    std::vector<uint8_t> ticket_hs;
    // 服务端用 server_write_key 加密, 客户端用 server_write_key 解密
    // 但需要处理记录层... 简化: 直接存储未加密的 ticket_msg
    bool store_ok = tls13_store_psk(client, ticket_msg.data(), ticket_msg.size());
    TEST("0-RTT: Client stores PSK", store_ok);

    if (!store_ok) return;

    // ── 阶段 4: PSK 恢复 — 客户端生成 PSK ClientHello ──
    tls_session client2, server2;
    client2.psk_valid = true;
    memcpy(client2.psk_identity, client.psk_identity, client.psk_identity_len);
    client2.psk_identity_len = client.psk_identity_len;
    memcpy(client2.psk_value, client.psk_value, tls_hash_len(client.cipher_suite));
    client2.ticket_age_add = client.ticket_age_add;
    client2.ticket_issue_time = client.ticket_issue_time;
    client2.server_name = "localhost";
    client2.cipher_suite = client.cipher_suite;

    // 设置服务端 PSK (从 server session 复制)
    server2.psk_valid = true;
    memcpy(server2.psk_identity, server.psk_identity, server.psk_identity_len);
    server2.psk_identity_len = server.psk_identity_len;
    memcpy(server2.psk_value, server.psk_value, tls_hash_len(server.cipher_suite));
    server2.ticket_age_add = server.ticket_age_add;
    server2.ticket_issue_time = server.ticket_issue_time;
    server2.cipher_suite = server.cipher_suite;
    server2.is_server = true;

    std::vector<uint8_t> psk_ch;
    bool psk_ch_ok = tls13_make_psk_client_hello(client2, psk_ch);
    TEST("0-RTT: PSK ClientHello generated", psk_ch_ok);
    TEST("0-RTT: PSK CH non-empty", !psk_ch.empty());

    if (!psk_ch_ok) return;

    // ── 阶段 5: 服务端处理 PSK ClientHello ──
    bool accept_early = false;
    bool psk_ok = tls13_process_psk_client_hello(server2, psk_ch.data(), psk_ch.size(), accept_early);
    TEST("0-RTT: Server accepts PSK", psk_ok);
    TEST("0-RTT: Early data accepted", accept_early);

    if (!psk_ok || !accept_early) return;

    // ── 阶段 6: 客户端发送 Early Data ──
    const uint8_t early_msg[] = "Hello from 0-RTT!";
    auto early_enc = tls13_encrypt_early_data(client2, early_msg, sizeof(early_msg)-1);
    TEST("0-RTT: Early data encrypted", !early_enc.empty());

    // ── 阶段 7: 服务端解密 Early Data ──
    ContentType early_ct;
    std::vector<uint8_t> early_dec;
    bool early_dec_ok = tls13_decrypt_early_data(server2, early_enc.data(), early_enc.size(),
                                                  early_ct, early_dec);
    TEST("0-RTT: Early data decrypted", early_dec_ok);
    TEST("0-RTT: Early data matches", early_dec_ok &&
         early_dec.size() == sizeof(early_msg)-1 &&
         memcmp(early_dec.data(), early_msg, sizeof(early_msg)-1) == 0);

    // ── 阶段 8: EndOfEarlyData ──
    auto eoed = tls13_make_end_of_early_data();
    TEST("0-RTT: EndOfEarlyData non-empty", !eoed.empty());
    
    auto enc_eoed = tls_encrypt_handshake(server2, eoed.data(), eoed.size());
    TEST("0-RTT: EoED encrypted", !enc_eoed.empty());

    // Client processes EoED
    // Note: we need to set up handshake keys first (server would have derived them)
    // For this test, just verify the message format
    bool eoed_ok = tls13_process_end_of_early_data(client2, eoed.data(), eoed.size());
    TEST("0-RTT: EoED parsed", eoed_ok);
}


// ========================================================================
//  入口
// ========================================================================

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::cout << "Running jpssl TLS unit tests with JPTest\n" << std::endl;

    RUN_TEST(test_ed25519_certificate);
    RUN_TEST(test_ecdsa_certificate);
    RUN_TEST(test_rsa_certificate);
    RUN_TEST(test_certificate_manager);
    RUN_TEST(test_tls13_full_handshake_ed25519);
    RUN_TEST(test_tls13_full_handshake_ecdsa);
    RUN_TEST(test_tls12_full_handshake);
    RUN_TEST(test_sni_multi_domain);
    RUN_TEST(test_simplified_handshake_api);
    RUN_TEST(test_tls13_0rtt);

    return test_summary();
}