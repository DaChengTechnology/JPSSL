/**
 * test_tls.cpp — TLS 1.2/1.3 完整握手单元测试
 * 使用 JPTest 框架：完整握手往返测试 + Ed25519/ECDSA/RSA 证书测试 + SNI 测试
 */

#include "test_utils.hpp"
#include "tls.hpp"
#include "ed25519.hpp"
#include "ed448.hpp"
#include "ecdsa.hpp"
#include "rsa.hpp"
#include "x25519.hpp"
#include "dh.hpp"
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
    // TLS 1.3 ECDSA 签名为 DER 编码（RFC 8446 §4.4.3），长度约 70-72 字节
    uint8_t sig[96];
    size_t sig_len;

    bool sign_ok = cert->sign(test_data, sizeof(test_data) - 1, sig, sig_len);
    TEST("ECDSA P-256 sign success", sign_ok);
    TEST("ECDSA P-256 sig is DER encoded", sign_ok && sig_len >= 8 && sig[0] == 0x30);

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
//  测试 11: TLS 1.3 0-RTT — 全部加密套件 × 认证套件组合矩阵
// ========================================================================

static const char* cs_name(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:       return "AES128-GCM-SHA256";
        case CipherSuite::TLS_AES_256_GCM_SHA384:       return "AES256-GCM-SHA384";
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256: return "CHACHA20-POLY1305-SHA256";
        case CipherSuite::TLS_AES_128_CCM_SHA256:       return "AES128-CCM-SHA256";
        case CipherSuite::TLS_AES_128_CCM_8_SHA256:     return "AES128-CCM8-SHA256";
        case CipherSuite::TLS_SM4_GCM_SM3:              return "SM4-GCM-SM3";
        case CipherSuite::TLS_SM4_CCM_SM3:              return "SM4-CCM-SM3";
        default: return "?";
    }
}

static const char* sig_name(SignatureAlgorithm sig) {
    switch (sig) {
        case SignatureAlgorithm::ED25519:                 return "Ed25519";
        case SignatureAlgorithm::ED448:                   return "Ed448";
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256:  return "ECDSA-P256";
        case SignatureAlgorithm::ECDSA_SECP384R1_SHA384:  return "ECDSA-P384";
        case SignatureAlgorithm::ECDSA_SECP521R1_SHA512:  return "ECDSA-P521";
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA256:     return "RSA-PSS-256";
        case SignatureAlgorithm::SM2_SM3:                 return "SM2-SM3";
        default: return "?";
    }
}

static std::unique_ptr<tls_certificate> make_cert_for_sig(SignatureAlgorithm sig) {
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = sig;
    switch (sig) {
        case SignatureAlgorithm::ED25519:                ed25519_keygen(cert->pub.ed25519, cert->priv.ed25519); break;
        case SignatureAlgorithm::ED448:                  ed448_keygen(cert->pub.ed448, cert->priv.ed448); break;
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256: ecdsa_p256_keygen(cert->pub.ecdsa_p256, cert->priv.ecdsa_p256); break;
        case SignatureAlgorithm::ECDSA_SECP384R1_SHA384: ecdsa_p384_keygen(cert->pub.ecdsa_p384, cert->priv.ecdsa_p384); break;
        case SignatureAlgorithm::ECDSA_SECP521R1_SHA512: ecdsa_p521_keygen(cert->pub.ecdsa_p521, cert->priv.ecdsa_p521); break;
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA256:    rsa_keygen(cert->pub.rsa, cert->priv.rsa); break;
        case SignatureAlgorithm::SM2_SM3:                sm2_keygen(cert->pub.sm2, cert->priv.sm2); break;
        default: return nullptr;
    }
    return cert;
}

// 单个组合的 0-RTT 完整流程（完整握手 → NewSessionTicket → PSK 恢复 → early data 往返 → EoED）。
// 返回空串表示成功，否则返回失败阶段描述。
static std::string run_0rtt_combination(CipherSuite cs, SignatureAlgorithm sig) {
    tls_certificate_manager cert_mgr;
    auto cert = make_cert_for_sig(sig);
    if (!cert) return "make cert";
    cert_mgr.add_certificate("localhost", std::move(cert));

    // ── 阶段 1: 完整握手（指定加密套件）──
    tls_session client;
    client.server_name = "localhost";
    client.cipher_suite = cs;
    std::vector<uint8_t> ch;
    if (!tls13_make_client_hello(client, ch)) return "client hello";

    tls_session server;
    server.cipher_suite = cs;   // 服务端显式偏好目标套件
    std::vector<uint8_t> sf;
    if (!tls13_make_server_flight(server, ch.data(), ch.size(), sf, cert_mgr)) return "server flight";
    if (server.cipher_suite != cs) return "cipher not negotiated";

    std::vector<uint8_t> cf;
    if (!tls13_process_server_flight(client, sf.data(), sf.size(), cf, &cert_mgr)) return "client process";
    if (!tls13_process_client_finished(server, cf.data(), cf.size())) return "client finished";

    // ── 阶段 1.5: 主记录层应用数据双向往返（验证协商套件的记录层正确性）──
    const uint8_t app_msg[] = "TLS1.3 app data round-trip";
    auto app_enc = tls_encrypt(client, ContentType::APPLICATION_DATA, app_msg, sizeof(app_msg) - 1);
    ContentType app_ct;
    std::vector<uint8_t> app_dec;
    if (!tls_decrypt(server, app_enc.data(), app_enc.size(), app_ct, app_dec)) return "app record decrypt";
    if (app_dec.size() != sizeof(app_msg) - 1 ||
        memcmp(app_dec.data(), app_msg, sizeof(app_msg) - 1) != 0) return "app record mismatch";
    auto app_enc2 = tls_encrypt(server, ContentType::APPLICATION_DATA, app_msg, sizeof(app_msg) - 1);
    ContentType app_ct2;
    if (!tls_decrypt(client, app_enc2.data(), app_enc2.size(), app_ct2, app_dec)) return "app record decrypt2";
    if (app_dec.size() != sizeof(app_msg) - 1 ||
        memcmp(app_dec.data(), app_msg, sizeof(app_msg) - 1) != 0) return "app record mismatch2";

    // ── 阶段 2: NewSessionTicket → 客户端存储 PSK ──
    std::vector<uint8_t> ticket;
    if (!tls13_make_new_session_ticket(server, ticket)) return "new session ticket";
    if (!tls13_store_psk(client, ticket.data(), ticket.size())) return "store psk";

    // ── 阶段 3: PSK 恢复握手（0-RTT）──
    tls_session client2, server2;
    client2.server_name = "localhost";
    client2.cipher_suite = client.cipher_suite;
    client2.psk_valid = true;
    client2.psk_identity_len = client.psk_identity_len;
    memcpy(client2.psk_identity, client.psk_identity, client.psk_identity_len);
    memcpy(client2.psk_value, client.psk_value, tls_hash_len(client.cipher_suite));
    client2.ticket_age_add = client.ticket_age_add;
    client2.ticket_issue_time = client.ticket_issue_time;

    server2.is_server = true;
    server2.cipher_suite = server.cipher_suite;
    server2.psk_valid = true;
    server2.psk_identity_len = server.psk_identity_len;
    memcpy(server2.psk_identity, server.psk_identity, server.psk_identity_len);
    memcpy(server2.psk_value, server.psk_value, tls_hash_len(server.cipher_suite));
    server2.ticket_age_add = server.ticket_age_add;
    server2.ticket_issue_time = server.ticket_issue_time;

    std::vector<uint8_t> psk_ch;
    if (!tls13_make_psk_client_hello(client2, psk_ch)) return "psk client hello";
    bool accept_early = false;
    if (!tls13_process_psk_client_hello(server2, psk_ch.data(), psk_ch.size(), accept_early)) return "psk process";
    if (!accept_early) return "early data not accepted";

    // ── 阶段 4: 0-RTT early data 往返 ──
    const uint8_t early_msg[] = "0-RTT matrix payload";
    auto early_enc = tls13_encrypt_early_data(client2, early_msg, sizeof(early_msg) - 1);
    if (early_enc.empty()) return "early encrypt";
    ContentType early_ct;
    std::vector<uint8_t> early_dec;
    if (!tls13_decrypt_early_data(server2, early_enc.data(), early_enc.size(), early_ct, early_dec)) return "early decrypt";
    if (early_dec.size() != sizeof(early_msg) - 1 ||
        memcmp(early_dec.data(), early_msg, sizeof(early_msg) - 1) != 0) return "early mismatch";

    // ── 阶段 5: EndOfEarlyData ──
    auto eoed = tls13_make_end_of_early_data();
    if (eoed.empty()) return "eoed make";
    if (!tls13_process_end_of_early_data(client2, eoed.data(), eoed.size())) return "eoed process";

    return "";
}

void test_tls13_0rtt_matrix() {
    std::printf("\n=== TLS 1.3 0-RTT: 全部加密套件 × 认证套件组合 ===\n");
    const CipherSuite ciphers[] = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_AES_128_CCM_SHA256,
        CipherSuite::TLS_AES_128_CCM_8_SHA256,
        CipherSuite::TLS_SM4_GCM_SM3,
        CipherSuite::TLS_SM4_CCM_SM3,
    };
    const SignatureAlgorithm sigs[] = {
        SignatureAlgorithm::ED25519,
        SignatureAlgorithm::ED448,
        SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        SignatureAlgorithm::ECDSA_SECP521R1_SHA512,
        SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SignatureAlgorithm::SM2_SM3,
    };
    int fail_count = 0, total = 0;
    const int iterations = 5;   // 每个组合重复 5 次完整流程，暴露间歇性/未初始化内存问题
    for (CipherSuite cs : ciphers) {
        for (SignatureAlgorithm sig : sigs) {
            ++total;
            std::string d;
            for (int it = 0; it < iterations; ++it) {
                d = run_0rtt_combination(cs, sig);
                if (!d.empty()) break;
            }
            std::string name = std::string(cs_name(cs)) + " + " + sig_name(sig);
            if (d.empty()) {
                ++::jptest::g_pass;
                std::cout << "  \u2713 0-RTT matrix: " << name << std::endl;
            } else {
                ++::jptest::g_fail;
                ++fail_count;
                ::jptest::g_last_fail_msg = name;
                std::cout << "  \u2717 0-RTT matrix: " << name << " — fail at: " << d << std::endl;
            }
        }
    }
    std::printf("  0-RTT matrix: %d combinations, %d failed\n", total, fail_count);
}

// ========================================================================
//  signature_algorithms / signature_algorithms_cert 测试
// ========================================================================

// 解析 ClientHello 扩展区
static size_t ch_ext_offset(const std::vector<uint8_t>& ch) {
    size_t off = 4 + 2 + 32;
    uint8_t sid_len = ch[off++];
    off += sid_len;
    uint16_t cs_len = (uint16_t)((ch[off] << 8) | ch[off + 1]);
    off += 2 + cs_len;
    uint8_t cm_len = ch[off++];
    off += cm_len;
    return off;
}

// 查找并解析 signature_algorithms 类扩展（0x000d / 0x0032）
static bool ch_find_sig_alg_ext(const std::vector<uint8_t>& ch, uint16_t want,
                                std::vector<uint16_t>& out) {
    size_t off = ch_ext_offset(ch);
    if (off + 2 > ch.size()) return false;
    size_t total = (size_t)((ch[off] << 8) | ch[off + 1]);
    size_t p = off + 2, end = p + total;
    if (end > ch.size()) return false;
    while (p + 4 <= end) {
        uint16_t type = (uint16_t)((ch[p] << 8) | ch[p + 1]);
        size_t elen = (size_t)((ch[p + 2] << 8) | ch[p + 3]);
        if (p + 4 + elen > end) return false;
        if (type == want) {
            out.clear();
            size_t list_len = (size_t)((ch[p + 4] << 8) | ch[p + 5]);
            for (size_t i = 0; i + 2 <= list_len; i += 2)
                out.push_back((uint16_t)((ch[p + 6 + i] << 8) | ch[p + 6 + i + 1]));
            return true;
        }
        p += 4 + elen;
    }
    return false;
}

void test_signature_algorithm_extensions() {
    // 默认列表包含全部支持的方案
    auto def = tls_default_signature_algorithms();
    TEST("Default list size", def.size() == 12);
    TEST("Default includes ed25519", std::find(def.begin(), def.end(), 0x0807) != def.end());
    TEST("Default includes rsa_pss_rsae_sha256", std::find(def.begin(), def.end(), 0x0804) != def.end());
    TEST("Default includes rsa_pkcs1_sha384", std::find(def.begin(), def.end(), 0x0501) != def.end());
    TEST("Default includes ecdsa_p384", std::find(def.begin(), def.end(), 0x0503) != def.end());
    TEST("Default includes sm2_sm3", std::find(def.begin(), def.end(), 0x0708) != def.end());

    // TLS 1.3 ClientHello 携带两个扩展
    tls_session c13; c13.server_name = "localhost";
    std::vector<uint8_t> ch13;
    TEST("TLS 1.3 make CH", tls13_make_client_hello(c13, ch13));
    std::vector<uint16_t> algs, cert_algs;
    TEST("TLS 1.3 CH has signature_algorithms",
         ch_find_sig_alg_ext(ch13, 0x000d, algs));
    TEST("TLS 1.3 CH sig list == default", algs == def);
    TEST("TLS 1.3 CH has signature_algorithms_cert",
         ch_find_sig_alg_ext(ch13, 0x0032, cert_algs));
    TEST("TLS 1.3 CH cert list == default", cert_algs == def);

    // 自定义列表生效，且 cert 列表被过滤为 sig 列表子集
    tls_session c13b; c13b.server_name = "localhost";
    c13b.sig_algs = {(uint16_t)SignatureAlgorithm::ED25519};
    c13b.sig_algs_cert = {
        (uint16_t)SignatureAlgorithm::ED25519,
        (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256
    };
    std::vector<uint8_t> ch13b;
    tls13_make_client_hello(c13b, ch13b);
    std::vector<uint16_t> algs_b, cert_algs_b;
    ch_find_sig_alg_ext(ch13b, 0x000d, algs_b);
    ch_find_sig_alg_ext(ch13b, 0x0032, cert_algs_b);
    TEST("Custom sig list respected", algs_b.size() == 1 && algs_b[0] == 0x0807);
    TEST("Custom cert list filtered to subset", cert_algs_b.size() == 1 && cert_algs_b[0] == 0x0807);

    // TLS 1.2 ClientHello 同样携带两个扩展
    tls_session c12; c12.server_name = "localhost";
    std::vector<uint8_t> ch12;
    TEST("TLS 1.2 make CH", tls12_make_client_hello(c12, ch12));
    std::vector<uint16_t> algs12, cert_algs12;
    TEST("TLS 1.2 CH has signature_algorithms",
         ch_find_sig_alg_ext(ch12, 0x000d, algs12));
    TEST("TLS 1.2 CH sig list == default", algs12 == def);
    TEST("TLS 1.2 CH has signature_algorithms_cert",
         ch_find_sig_alg_ext(ch12, 0x0032, cert_algs12));
    TEST("TLS 1.2 CH cert list == default", cert_algs12 == def);

    // PSK ClientHello 也携带两个扩展
    tls_session cpsk; cpsk.server_name = "localhost";
    cpsk.psk_valid = true;
    cpsk.psk_identity_len = 4;
    std::memcpy(cpsk.psk_identity, "tkt!", 4);
    cpsk.psk_value[0] = 0xAA;
    std::vector<uint8_t> chpsk;
    TEST("PSK make CH", tls13_make_psk_client_hello(cpsk, chpsk));
    std::vector<uint16_t> algs_psk, cert_algs_psk;
    TEST("PSK CH has signature_algorithms",
         ch_find_sig_alg_ext(chpsk, 0x000d, algs_psk));
    TEST("PSK CH has signature_algorithms_cert",
         ch_find_sig_alg_ext(chpsk, 0x0032, cert_algs_psk));
}

void test_tls13_full_handshake_ecdsa_p384() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP384R1_SHA384;
    ecdsa_p384_keygen(server_cert->pub.ecdsa_p384, server_cert->priv.ecdsa_p384);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client; client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    TEST("TLS 1.3 (P-384) make CH", tls13_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                          server_flight, cert_mgr);
    TEST("TLS 1.3 (P-384) server flight", sh_ok);
    TEST("TLS 1.3 (P-384) negotiated ecdsa_secp384r1_sha384",
         server.selected_sig_alg == (uint16_t)SignatureAlgorithm::ECDSA_SECP384R1_SHA384);

    std::vector<uint8_t> client_finished;
    bool cf_ok = tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                             client_finished, &cert_mgr);
    TEST("TLS 1.3 (P-384) client process", cf_ok);
    bool fin = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("TLS 1.3 (P-384) finished", fin);

    const uint8_t data[] = "P-384 ECDSA TLS 1.3";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, data, sizeof(data) - 1);
    ContentType ct; std::vector<uint8_t> dec;
    TEST("TLS 1.3 (P-384) record round-trip",
         tls_decrypt(server, enc.data(), enc.size(), ct, dec) && dec.size() == sizeof(data) - 1);
}

void test_tls13_full_handshake_rsa_pss() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::RSA_PSS_RSAE_SHA256;
    rsa_keygen(server_cert->pub.rsa, server_cert->priv.rsa);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client; client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    TEST("TLS 1.3 (RSA-PSS) make CH", tls13_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                          server_flight, cert_mgr);
    TEST("TLS 1.3 (RSA-PSS) server flight", sh_ok);
    TEST("TLS 1.3 (RSA-PSS) negotiated rsa_pss_rsae_sha256",
         server.selected_sig_alg == (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256);

    std::vector<uint8_t> client_finished;
    TEST("TLS 1.3 (RSA-PSS) client process",
         tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                     client_finished, &cert_mgr));
    TEST("TLS 1.3 (RSA-PSS) finished",
         tls13_process_client_finished(server, client_finished.data(), client_finished.size()));

    const uint8_t data[] = "RSA-PSS TLS 1.3";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, data, sizeof(data) - 1);
    ContentType ct; std::vector<uint8_t> dec;
    TEST("TLS 1.3 (RSA-PSS) record round-trip",
         tls_decrypt(server, enc.data(), enc.size(), ct, dec) && dec.size() == sizeof(data) - 1);
}

// ECDSA P-521 证书的 TLS 1.3 完整握手（签名算法 0x0603，SHA-512）
void test_tls13_full_handshake_ecdsa_p521() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP521R1_SHA512;
    ecdsa_p521_keygen(server_cert->pub.ecdsa_p521, server_cert->priv.ecdsa_p521);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client; client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    TEST("TLS 1.3 (P-521) make CH", tls13_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                          server_flight, cert_mgr);
    TEST("TLS 1.3 (P-521) server flight", sh_ok);
    TEST("TLS 1.3 (P-521) negotiated ecdsa_secp521r1_sha512",
         server.selected_sig_alg == (uint16_t)SignatureAlgorithm::ECDSA_SECP521R1_SHA512);

    std::vector<uint8_t> client_finished;
    bool cf_ok = tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                             client_finished, &cert_mgr);
    TEST("TLS 1.3 (P-521) client process", cf_ok);
    bool fin = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("TLS 1.3 (P-521) finished", fin);

    const uint8_t data[] = "P-521 ECDSA TLS 1.3";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, data, sizeof(data) - 1);
    ContentType ct; std::vector<uint8_t> dec;
    TEST("TLS 1.3 (P-521) record round-trip",
         tls_decrypt(server, enc.data(), enc.size(), ct, dec) && dec.size() == sizeof(data) - 1);
}

// TLS 1.3 完整握手：ECDSA P-256 证书 + secp256r1 ECDHE 密钥交换
void test_tls13_full_handshake_ecdsa_p256_ecdh() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    ecdsa_p256_keygen(server_cert->pub.ecdsa_p256, server_cert->priv.ecdsa_p256);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client; client.server_name = "localhost";
    client.ks_group = NamedGroup::secp256r1;
    std::vector<uint8_t> client_hello;
    TEST("TLS 1.3 (P-256 ECDHE) make CH", tls13_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                          server_flight, cert_mgr);
    TEST("TLS 1.3 (P-256 ECDHE) server flight", sh_ok);
    TEST("TLS 1.3 (P-256 ECDHE) group secp256r1", server.ks_group == NamedGroup::secp256r1);

    std::vector<uint8_t> client_finished;
    bool cf_ok = tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                             client_finished, &cert_mgr);
    TEST("TLS 1.3 (P-256 ECDHE) client process", cf_ok);
    TEST("TLS 1.3 (P-256 ECDHE) client group secp256r1", client.ks_group == NamedGroup::secp256r1);
    bool fin = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("TLS 1.3 (P-256 ECDHE) finished", fin);

    const uint8_t data[] = "P-256 ECDHE TLS 1.3";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, data, sizeof(data) - 1);
    ContentType ct; std::vector<uint8_t> dec;
    TEST("TLS 1.3 (P-256 ECDHE) record round-trip",
         tls_decrypt(server, enc.data(), enc.size(), ct, dec) && dec.size() == sizeof(data) - 1);
}

// TLS 1.3 完整握手：ECDSA P-384 证书 + secp384r1 ECDHE 密钥交换
void test_tls13_full_handshake_ecdsa_p384_ecdh() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP384R1_SHA384;
    ecdsa_p384_keygen(server_cert->pub.ecdsa_p384, server_cert->priv.ecdsa_p384);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client; client.server_name = "localhost";
    client.ks_group = NamedGroup::secp384r1;
    std::vector<uint8_t> client_hello;
    TEST("TLS 1.3 (P-384 ECDHE) make CH", tls13_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                          server_flight, cert_mgr);
    TEST("TLS 1.3 (P-384 ECDHE) server flight", sh_ok);
    TEST("TLS 1.3 (P-384 ECDHE) group secp384r1", server.ks_group == NamedGroup::secp384r1);

    std::vector<uint8_t> client_finished;
    bool cf_ok = tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                             client_finished, &cert_mgr);
    TEST("TLS 1.3 (P-384 ECDHE) client process", cf_ok);
    TEST("TLS 1.3 (P-384 ECDHE) client group secp384r1", client.ks_group == NamedGroup::secp384r1);
    bool fin = tls13_process_client_finished(server, client_finished.data(), client_finished.size());
    TEST("TLS 1.3 (P-384 ECDHE) finished", fin);

    const uint8_t data[] = "P-384 ECDHE TLS 1.3";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, data, sizeof(data) - 1);
    ContentType ct; std::vector<uint8_t> dec;
    TEST("TLS 1.3 (P-384 ECDHE) record round-trip",
         tls_decrypt(server, enc.data(), enc.size(), ct, dec) && dec.size() == sizeof(data) - 1);
}

// RSA-PKCS1 证书在 TLS 1.3 中必须改用 PSS 做 CertificateVerify（RFC 8446）
void test_tls13_rsa_pkcs1_cert_uses_pss() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
    rsa_keygen(server_cert->pub.rsa, server_cert->priv.rsa);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client; client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    tls13_make_client_hello(client, client_hello);

    tls_session server;
    std::vector<uint8_t> server_flight;
    bool sh_ok = tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                          server_flight, cert_mgr);
    TEST("TLS 1.3 (RSA pkcs1 cert) server flight", sh_ok);
    TEST("TLS 1.3 (RSA pkcs1 cert) negotiated rsa_pss_rsae_sha256",
         server.selected_sig_alg == (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256);
    std::vector<uint8_t> client_finished;
    TEST("TLS 1.3 (RSA pkcs1 cert) client process",
         tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                     client_finished, &cert_mgr));
    TEST("TLS 1.3 (RSA pkcs1 cert) finished",
         tls13_process_client_finished(server, client_finished.data(), client_finished.size()));
}

void test_tls13_rejects_unadvertised_scheme() {
    // 服务端 ECDSA P-256 证书，客户端只广告 ed25519 -> 服务端必须中止
    {
        tls_certificate_manager cert_mgr;
        auto server_cert = std::make_unique<tls_certificate>();
        server_cert->subject_name = "localhost";
        server_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
        ecdsa_p256_keygen(server_cert->pub.ecdsa_p256, server_cert->priv.ecdsa_p256);
        cert_mgr.add_certificate("localhost", std::move(server_cert));

        tls_session client; client.server_name = "localhost";
        client.sig_algs = {(uint16_t)SignatureAlgorithm::ED25519};
        client.sig_algs_cert = {(uint16_t)SignatureAlgorithm::ED25519};
        std::vector<uint8_t> client_hello;
        tls13_make_client_hello(client, client_hello);

        tls_session server;
        std::vector<uint8_t> server_flight;
        TEST("Server aborts when no common scheme",
             !tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                       server_flight, cert_mgr));
    }
    // 反向：服务端 Ed25519 证书，客户端只广告 ECDSA -> 中止
    {
        tls_certificate_manager cert_mgr;
        auto server_cert = std::make_unique<tls_certificate>();
        server_cert->subject_name = "localhost";
        server_cert->sig_alg = SignatureAlgorithm::ED25519;
        ed25519_keygen(server_cert->pub.ed25519, server_cert->priv.ed25519);
        cert_mgr.add_certificate("localhost", std::move(server_cert));

        tls_session client; client.server_name = "localhost";
        client.sig_algs = {(uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256};
        client.sig_algs_cert = {(uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256};
        std::vector<uint8_t> client_hello;
        tls13_make_client_hello(client, client_hello);

        tls_session server;
        std::vector<uint8_t> server_flight;
        TEST("Server aborts when cert scheme unadvertised",
             !tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                       server_flight, cert_mgr));
    }
}

void test_signature_algorithms_cert_enforcement() {
    // 证书链签名方案在客户端 sig_algs_cert 内 -> 握手成功
    {
        tls_certificate_manager cert_mgr;
        auto server_cert = std::make_unique<tls_certificate>();
        server_cert->subject_name = "localhost";
        server_cert->sig_alg = SignatureAlgorithm::ED25519;
        ed25519_keygen(server_cert->pub.ed25519, server_cert->priv.ed25519);
        cert_mgr.add_certificate("localhost", std::move(server_cert));

        tls_session client; client.server_name = "localhost";
        client.sig_algs = {(uint16_t)SignatureAlgorithm::ED25519};
        client.sig_algs_cert = {(uint16_t)SignatureAlgorithm::ED25519};
        std::vector<uint8_t> client_hello;
        tls13_make_client_hello(client, client_hello);

        tls_session server;
        std::vector<uint8_t> server_flight;
        TEST("Handshake ok when cert scheme allowed",
             tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                      server_flight, cert_mgr));
    }
    // 证书链签名方案不在客户端 sig_algs_cert 内 -> 服务端中止
    {
        tls_certificate_manager cert_mgr;
        auto server_cert = std::make_unique<tls_certificate>();
        server_cert->subject_name = "localhost";
        server_cert->sig_alg = SignatureAlgorithm::ED25519;
        ed25519_keygen(server_cert->pub.ed25519, server_cert->priv.ed25519);
        cert_mgr.add_certificate("localhost", std::move(server_cert));

        tls_session client; client.server_name = "localhost";
        // 证书列表非空且为 sig_algs 子集，但不包含服务端 Ed25519 证书的链签名方案
        client.sig_algs = {
            (uint16_t)SignatureAlgorithm::ED25519,
            (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256
        };
        client.sig_algs_cert = {(uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256};
        std::vector<uint8_t> client_hello;
        tls13_make_client_hello(client, client_hello);

        tls_session server;
        std::vector<uint8_t> server_flight;
        TEST("Server aborts when cert chain scheme disallowed",
             !tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                       server_flight, cert_mgr));
    }
    // 手工构造非子集的 signature_algorithms_cert -> 服务端中止
    {
        tls_certificate_manager cert_mgr;
        auto server_cert = std::make_unique<tls_certificate>();
        server_cert->subject_name = "localhost";
        server_cert->sig_alg = SignatureAlgorithm::ED25519;
        ed25519_keygen(server_cert->pub.ed25519, server_cert->priv.ed25519);
        cert_mgr.add_certificate("localhost", std::move(server_cert));

        tls_session client; client.server_name = "localhost";
        client.sig_algs = {(uint16_t)SignatureAlgorithm::ED25519};
        client.sig_algs_cert = {(uint16_t)SignatureAlgorithm::ED25519};
        std::vector<uint8_t> client_hello;
        tls13_make_client_hello(client, client_hello);
        // 追加一个含非子集方案的 signature_algorithms_cert 扩展
        std::vector<uint8_t> extra = {
            0x00, 0x32,             // type
            0x00, 0x06,             // ext data len
            0x00, 0x04,             // list len: 2 schemes
            0x08, 0x07,             // ed25519
            0x04, 0x01              // rsa_pkcs1_sha256 (不在 sig_algs 内)
        };
        size_t eo = ch_ext_offset(client_hello);
        uint16_t total = (uint16_t)((client_hello[eo] << 8) | client_hello[eo + 1]);
        client_hello[eo] = (uint8_t)((total + extra.size()) >> 8);
        client_hello[eo + 1] = (uint8_t)(total + extra.size());
        client_hello.insert(client_hello.end(), extra.begin(), extra.end());
        uint32_t hs_len = (uint32_t)client_hello.size() - 4;
        client_hello[1] = (uint8_t)(hs_len >> 16);
        client_hello[2] = (uint8_t)(hs_len >> 8);
        client_hello[3] = (uint8_t)hs_len;

        tls_session server;
        std::vector<uint8_t> server_flight;
        TEST("Server rejects non-subset signature_algorithms_cert",
             !tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                       server_flight, cert_mgr));
    }
}

// 线级校验：CertificateVerify 签名的内容是 RFC 8446 上下文串 + 64 个 0x00 + Transcript-Hash
void test_tls13_cert_verify_rfc8446_content() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(server_cert->pub.ed25519, server_cert->priv.ed25519);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client; client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    tls13_make_client_hello(client, client_hello);

    tls_session server;
    std::vector<uint8_t> server_flight;
    TEST("server flight ok", tls13_make_server_flight(server, client_hello.data(),
                                                      client_hello.size(), server_flight, cert_mgr));

    // 用服务端握手密钥解密握手记录（此时 server_write_key 仍是握手流量密钥）
    tls_session dec = server;
    dec.is_server = false;
    dec.server_seq = 0;
    ContentType ct;
    std::vector<uint8_t> hs;
    size_t sh_len = (size_t)((server_flight[1] << 16) | (server_flight[2] << 8) | server_flight[3]);
    bool dec_ok = tls_decrypt(dec, server_flight.data() + 4 + sh_len,
                              server_flight.size() - 4 - sh_len, ct, hs);
    TEST("decrypt handshake flight", dec_ok);

    // 解析 Certificate / CertificateVerify 消息
    const uint8_t* cert_msg = nullptr; size_t cert_len = 0;
    const uint8_t* cv_msg = nullptr; size_t cv_len = 0;
    size_t ho = 0;
    while (ho + 4 <= hs.size()) {
        size_t hlen = (size_t)((hs[ho + 1] << 16) | (hs[ho + 2] << 8) | hs[ho + 3]);
        if (ho + 4 + hlen > hs.size()) break;
        if (hs[ho] == 11) { cert_msg = hs.data() + ho; cert_len = 4 + hlen; }
        if (hs[ho] == 15) { cv_msg = hs.data() + ho; cv_len = 4 + hlen; }
        ho += 4 + hlen;
    }
    TEST("Certificate found", cert_msg != nullptr);
    TEST("CertificateVerify found", cv_msg != nullptr);

    if (cert_msg && cv_msg) {
        uint16_t scheme = (uint16_t)((cv_msg[4] << 8) | cv_msg[5]);
        size_t sig_len = (size_t)((cv_msg[6] << 8) | cv_msg[7]);
        TEST("CV scheme is ed25519", scheme == (uint16_t)SignatureAlgorithm::ED25519);
        TEST("CV sig length 64", sig_len == 64);

        // 重建 pre-CertificateVerify transcript：CH || SH || EE || Certificate
        tls_session s2;
        s2.cipher_suite = server.cipher_suite;
        tls_transcript_update(s2, client_hello.data(), client_hello.size());
        tls_transcript_update(s2, server_flight.data(), 4 + sh_len);
        tls_transcript_update(s2, hs.data(), (size_t)(hs[1] << 16 | hs[2] << 8 | hs[3]) + 4); // EE
        tls_transcript_update(s2, cert_msg, cert_len);
        tls_transcript_finalize(s2);

        static const char* ctx = "TLS 1.3, server CertificateVerify";
        std::vector<uint8_t> content;
        content.insert(content.end(), 64, 0x20);  // RFC 8446 4.4.3: 64 个 0x20 空格
        content.insert(content.end(), ctx, ctx + strlen(ctx));
        content.push_back(0x00);             // RFC 8446 4.4.3: 单个 0x00 分隔符
        content.insert(content.end(), s2.transcript_hash, s2.transcript_hash + tls_hash_len(s2.cipher_suite));

        const tls_certificate* cert = cert_mgr.get_default_certificate();
        TEST("CV verifies over RFC 8446 context content",
             cert->verify_scheme(scheme, content.data(), content.size(), cv_msg + 8, sig_len));
        // 若签名的只是裸 transcript 哈希，则无法通过上下文内容校验
        TEST("CV rejects raw-hash content",
             !cert->verify_scheme(scheme, s2.transcript_hash, tls_hash_len(s2.cipher_suite),
                                  cv_msg + 8, sig_len));
    }
}

// TLS 1.2 ECDHE：服务端按客户端 signature_algorithms 协商 ServerKeyExchange 签名方案
void test_tls12_skx_scheme_selection() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    ecdsa_p256_keygen(server_cert->pub.ecdsa_p256, server_cert->priv.ecdsa_p256);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client; client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    TEST("TLS 1.2 make CH", tls12_make_client_hello(client, client_hello));

    tls_session server;
    uint8_t pms[48] = {};
    std::vector<uint8_t> server_response;
    bool ok = tls12_make_server_flight(server, client_hello.data(), client_hello.size(),
                                       server_response, nullptr, 0, pms, cert_mgr);
    TEST("TLS 1.2 server flight", ok);
    TEST("TLS 1.2 negotiated ecdsa_secp256r1_sha256",
         server.selected_sig_alg == (uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256);
}

void test_sign_scheme_cert_verify_context() {
    // 直接验证 sign_scheme / verify_scheme 对 RFC 8446 上下文内容的对称性
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "ctx.test";
    cert->sig_alg = SignatureAlgorithm::ED25519;
    ed25519_keygen(cert->pub.ed25519, cert->priv.ed25519);

    uint8_t th[32] = {};
    for (int i = 0; i < 32; ++i) th[i] = (uint8_t)(i * 7 + 1);
    static const char* ctx = "TLS 1.3, server CertificateVerify";
    std::vector<uint8_t> content;
    content.insert(content.end(), 64, 0x20);  // RFC 8446 4.4.3: 64 个 0x20 空格
    content.insert(content.end(), ctx, ctx + strlen(ctx));
    content.push_back(0x00);             // RFC 8446 4.4.3: 单个 0x00 分隔符
    content.insert(content.end(), th, th + 32);

    uint8_t sig[64]; size_t sig_len = 0;
    TEST("sign over context content",
         cert->sign_scheme((uint16_t)SignatureAlgorithm::ED25519,
                           content.data(), content.size(), sig, sig_len));
    TEST("verify over context content",
         cert->verify_scheme((uint16_t)SignatureAlgorithm::ED25519,
                             content.data(), content.size(), sig, sig_len));
    uint8_t raw_sig[64]; size_t raw_len = 0;
    cert->sign_scheme((uint16_t)SignatureAlgorithm::ED25519, th, 32, raw_sig, raw_len);
    TEST("raw-hash signature rejected against context content",
         !cert->verify_scheme((uint16_t)SignatureAlgorithm::ED25519,
                              content.data(), content.size(), raw_sig, raw_len));
}

static const char* SERVER_CERT_PEM =
R"PEM(
-----BEGIN CERTIFICATE-----
MIHiMIGVAhQ3QcBTRWB5/0iXP6dBWv6L09fu1zAFBgMrZXAwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTI2MDgwNjExNDIyMFoXDTM2MDgwMzExNDIyMFowFDESMBAG
A1UEAwwJbG9jYWxob3N0MCowBQYDK2VwAyEA4iYoNNrvHeItoFmTGVDkodw8CdKs
XDWpnIvHQ/DtzNswBQYDK2VwA0EACoJvkELy68lHdU97+PBNxNgefWiEzBkP8ISU
LE7kbfXfeBMQADx99HX7vOI3h53SseMChzTe7SUKRHcxY1DgAQ==
-----END CERTIFICATE-----
)PEM";
static const char* SERVER_KEY_PEM =
R"PEM(
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDYkFyRVsdWOvuF3Q4Y0twsB7pTfoUW/ggunW6tT4Q3W
-----END PRIVATE KEY-----
)PEM";
static const char* SERVER_CSR_PEM =
R"PEM(
-----BEGIN CERTIFICATE REQUEST-----
MIGTMEcCAQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCowBQYDK2VwAyEA4iYoNNrv
HeItoFmTGVDkodw8CdKsXDWpnIvHQ/DtzNugADAFBgMrZXADQQBgxWcoFgUMaVQv
Aq9VUoYMwqFoqGM/DoxnsSyj2eV8O+y5V7TZ/iazPDP+kmd+/vmE7RKxg4jqVlHV
YF7XpWYN
-----END CERTIFICATE REQUEST-----
)PEM";
static const char* CA_CERT_PEM =
R"PEM(
-----BEGIN CERTIFICATE-----
MIIBODCB66ADAgECAhRk2rBvarvzp+G3+u2YLA11bUgYmDAFBgMrZXAwEjEQMA4G
A1UEAwwHVGVzdCBDQTAeFw0yNjA4MDYxMTQyMjBaFw0zNjA4MDMxMTQyMjBaMBIx
EDAOBgNVBAMMB1Rlc3QgQ0EwKjAFBgMrZXADIQBuLZ82R06cJi7HWkHgaax10zOq
+8Z4cTlcN+K4voQ7wqNTMFEwHQYDVR0OBBYEFAkYXk9nD3iOJsx/A2kMzQBpCrVB
MB8GA1UdIwQYMBaAFAkYXk9nD3iOJsx/A2kMzQBpCrVBMA8GA1UdEwEB/wQFMAMB
Af8wBQYDK2VwA0EAgv7CZN/t/4lDEZ9weJ+LJGmHZrhykQWIFnNp5neKK/Zn0vSm
vmxoNgNVpj6/0wqwFiSgUo7dXN8tDXqkoyeOAQ==
-----END CERTIFICATE-----
)PEM";
static const char* LEAF_CERT_PEM =
R"PEM(
-----BEGIN CERTIFICATE-----
MIIBPzCB8qADAgECAhRB5WGBrrfR4zpwyLjjoGT7Zyv9LTAFBgMrZXAwEjEQMA4G
A1UEAwwHVGVzdCBDQTAeFw0yNjA4MDYxMTQyMjBaFw0zNjA4MDMxMTQyMjBaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAOImKDTa7x3iLaBZkxlQ5KHc
PAnSrFw1qZyLx0Pw7czbo1gwVjAUBgNVHREEDTALgglsb2NhbGhvc3QwHQYDVR0O
BBYEFMHpNbL5goC1YSf6IDu0EDZpfiXjMB8GA1UdIwQYMBaAFAkYXk9nD3iOJsx/
A2kMzQBpCrVBMAUGAytlcANBAPfsOG5xhxhrBX92rQDTLxXjuotD3Ois5A6/OPTY
UJ7mSNvkpNZPN32t2DizB7vMu0hIU6HBOR8yncuZcyFU2gQ=
-----END CERTIFICATE-----
)PEM";
static const char* WRONG_CA_PEM =
R"PEM(
-----BEGIN CERTIFICATE-----
MIIBOjCB7aADAgECAhQMubxwFkp+fp75RasIsKScp35nNzAFBgMrZXAwEzERMA8G
A1UEAwwIV3JvbmcgQ0EwHhcNMjYwODA2MTE1MjM5WhcNMzYwODAzMTE1MjM5WjAT
MREwDwYDVQQDDAhXcm9uZyBDQTAqMAUGAytlcAMhAI0oTX+lXP7KNk2nQcbvpDCw
N+7b/UEi0PB8isBYHsQTo1MwUTAdBgNVHQ4EFgQUV6I2dnZY0MOCL1R3BH+re2tG
ItwwHwYDVR0jBBgwFoAUV6I2dnZY0MOCL1R3BH+re2tGItwwDwYDVR0TAQH/BAUw
AwEB/zAFBgMrZXADQQB4hbTRr/jbAPDQwM03q7BWm3XaXmKprJRHzdieUWq/WvN8
EmG+mpwGw9DQxDOvM4n3Y3DDCktRPDNJIelniRIB
-----END CERTIFICATE-----
)PEM";

// ========================================================================
//  服务端 PEM / CSR 证书加载
// ========================================================================

void test_tls_cert_from_pem() {
    auto cert = tls_certificate::from_pem(SERVER_CERT_PEM, SERVER_KEY_PEM);
    TEST("from_pem 构造成功", cert != nullptr);
    if (!cert) return;
    TEST("from_pem subject_name=localhost", cert->subject_name == "localhost");
    TEST("from_pem sig_alg=ED25519", cert->sig_alg == SignatureAlgorithm::ED25519);
    TEST("from_pem cert_data 非空", !cert->cert_data.empty());
    const uint8_t msg[] = "PEM certificate signing test";
    uint8_t sig[64]; size_t sig_len = 0;
    TEST("from_pem sign 成功", cert->sign(msg, sizeof(msg) - 1, sig, sig_len));
    TEST("from_pem verify 成功", cert->verify(msg, sizeof(msg) - 1, sig, sig_len));
    // 错误输入
    std::string err;
    auto bad = tls_certificate::from_pem("garbage", SERVER_KEY_PEM, &err);
    TEST("无效证书 PEM 失败", bad == nullptr);
    TEST("错误信息已填充", !err.empty());
}

void test_tls_cert_from_csr_pem() {
    auto cert = tls_certificate::from_csr_pem(SERVER_CSR_PEM, SERVER_KEY_PEM);
    TEST("from_csr_pem 构造成功", cert != nullptr);
    if (!cert) return;
    TEST("from_csr_pem subject_name=localhost", cert->subject_name == "localhost");
    TEST("from_csr_pem sig_alg=ED25519", cert->sig_alg == SignatureAlgorithm::ED25519);
    const uint8_t msg[] = "CSR certificate signing test";
    uint8_t sig[64]; size_t sig_len = 0;
    TEST("from_csr_pem sign 成功", cert->sign(msg, sizeof(msg) - 1, sig, sig_len));
    TEST("from_csr_pem verify 成功", cert->verify(msg, sizeof(msg) - 1, sig, sig_len));
}

// ========================================================================
//  服务端 PEM 加载 + 客户端 x509 链验证（TLS 1.3 完整握手）
// ========================================================================

void test_tls13_pem_server_x509_verify() {
    // 服务端：CA 签发的 leaf 证书 + 私钥（从 PEM 加载）
    auto srv_cert = tls_certificate::from_pem(LEAF_CERT_PEM, SERVER_KEY_PEM);
    TEST("服务端 from_pem(leaf) 构造成功", srv_cert != nullptr);
    if (!srv_cert) return;
    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate("localhost", std::move(srv_cert));

    // 客户端：信任库仅含 CA 根，x509 验证应通过
    tls_session client;
    client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    TEST("客户端 make ClientHello", tls13_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> server_flight;
    TEST("服务端 make ServerFlight", tls13_make_server_flight(server, client_hello.data(),
                                                              client_hello.size(),
                                                              server_flight, cert_mgr));

    auto trust = tls_trust_store::from_pem(CA_CERT_PEM);
    TEST("trust store 解析 CA", trust.count() >= 1);

    std::vector<uint8_t> client_finished;
    TEST("客户端 x509 链验证通过", tls13_process_server_flight(client, server_flight.data(),
                                                               server_flight.size(),
                                                               client_finished, nullptr, &trust));
    TEST("客户端 Finished 生成", !client_finished.empty());
    TEST("服务端验证 Client Finished", tls13_process_client_finished(server, client_finished.data(),
                                                                     client_finished.size()));

    // 应用数据往返
    const uint8_t app_data[] = "PEM + x509 verify handshake OK";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, app_data, sizeof(app_data) - 1);
    ContentType ct; std::vector<uint8_t> dec;
    TEST("服务端解密应用数据", tls_decrypt(server, enc.data(), enc.size(), ct, dec));
    TEST("内容一致", dec.size() == sizeof(app_data) - 1 &&
                    std::memcmp(dec.data(), app_data, sizeof(app_data) - 1) == 0);
}

void test_tls13_csr_server_handshake() {
    // 服务端从 CSR + 私钥加载（cert_data 留空，握手时自动生成自签证书）
    auto srv_cert = tls_certificate::from_csr_pem(SERVER_CSR_PEM, SERVER_KEY_PEM);
    TEST("服务端 from_csr_pem 构造成功", srv_cert != nullptr);
    if (!srv_cert) return;
    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate("localhost", std::move(srv_cert));

    tls_session client;
    client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    TEST("客户端 make ClientHello", tls13_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> server_flight;
    TEST("服务端 make ServerFlight", tls13_make_server_flight(server, client_hello.data(),
                                                              client_hello.size(),
                                                              server_flight, cert_mgr));

    std::vector<uint8_t> client_finished;
    // CSR 自签证书：用 cert_manager 预期证书模式完成握手
    TEST("客户端处理 ServerFlight", tls13_process_server_flight(client, server_flight.data(),
                                                                 server_flight.size(),
                                                                 client_finished, &cert_mgr));
    TEST("客户端 Finished 生成", !client_finished.empty());
    TEST("服务端验证 Client Finished", tls13_process_client_finished(server, client_finished.data(),
                                                                     client_finished.size()));
}

// ========================================================================
//  系统信任库加载 + 客户端鲁棒性测试
// ========================================================================

void test_tls_trust_store_system() {
    auto sys = tls_trust_store::from_system();
    // 系统信任库仅在部署了 CA bundle 的平台（Linux/macOS 等）非空；
    // Windows 没有 /etc/ssl 等路径，from_system() 返回空属正常行为。
    if (sys.empty()) {
        std::cout << "  (skip: 平台无系统 CA bundle，跳过非空断言)" << std::endl;
    } else {
        TEST("系统信任库加载非空", !sys.empty());
    }
    // 缓存命中：重复调用返回相同结果
    auto sys2 = tls_trust_store::from_system();
    TEST("系统信任库缓存一致", sys2.count() == sys.count());
    if (!sys.empty()) {
        // 抽查根证书基本结构（issuer 非空、可解析）
        bool any_issuer = false;
        for (const auto& c : sys.ca_roots)
            if (!c.issuer_name().empty()) { any_issuer = true; break; }
        TEST("根证书含 issuer 信息", any_issuer);
    }
}

// 构造一次完整 TLS 1.3 服务端 flight（CA 签发 leaf 证书），供鲁棒性测试复用
static bool make_server_flight_for_robust(std::vector<uint8_t>& server_flight,
                                          tls_certificate_manager& cert_mgr,
                                          tls_session* server_out = nullptr) {
    auto srv_cert = tls_certificate::from_pem(LEAF_CERT_PEM, SERVER_KEY_PEM);
    if (!srv_cert) return false;
    cert_mgr.add_certificate("localhost", std::move(srv_cert));
    tls_session client;
    client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    if (!tls13_make_client_hello(client, client_hello)) return false;
    tls_session server;
    if (!tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                  server_flight, cert_mgr)) return false;
    if (server_out) *server_out = server;
    return true;
}

void test_tls13_robustness_malformed() {
    tls_certificate_manager cert_mgr;
    std::vector<uint8_t> sf;
    if (!make_server_flight_for_robust(sf, cert_mgr)) { TEST("构造 flight", false); return; }
    TEST("构造 flight", !sf.empty());
    auto trust = tls_trust_store::from_pem(CA_CERT_PEM);

    // 截断：只给前 10 字节 → 握手必须失败（不崩溃）
    {
        tls_session client;
        client.server_name = "localhost";
        std::vector<uint8_t> cf;
        TEST("截断 flight 拒绝", !tls13_process_server_flight(client, sf.data(), 10, cf, nullptr, &trust));
    }
    // 空输入
    {
        tls_session client;
        client.server_name = "localhost";
        std::vector<uint8_t> cf;
        TEST("空 flight 拒绝", !tls13_process_server_flight(client, nullptr, 0, cf, nullptr, &trust));
    }
    // 随机字节
    {
        tls_session client;
        client.server_name = "localhost";
        std::vector<uint8_t> junk(64);
        for (auto& b : junk) b = (uint8_t)(b * 31 + 7);
        std::vector<uint8_t> cf;
        TEST("随机字节拒绝", !tls13_process_server_flight(client, junk.data(), junk.size(), cf, nullptr, &trust));
    }
    // 篡改证书消息中的一个字节（加密 flight 后部）
    if (sf.size() > 32) {
        tls_session client;
        client.server_name = "localhost";
        auto tampered = sf;
        tampered[tampered.size() - 16] ^= 0x01;  // 破坏加密 record 尾部
        std::vector<uint8_t> cf;
        TEST("篡改加密记录拒绝", !tls13_process_server_flight(client, tampered.data(), tampered.size(),
                                                               cf, nullptr, &trust));
    }
}

void test_tls13_robustness_hostname() {
    // 证书 SAN 是 localhost，但客户端请求 server_name 不匹配 → 握手失败
    tls_certificate_manager cert_mgr;
    std::vector<uint8_t> sf;
    if (!make_server_flight_for_robust(sf, cert_mgr)) return;
    auto trust = tls_trust_store::from_pem(CA_CERT_PEM);

    tls_session client;
    client.server_name = "evil.example.com";  // 与证书不匹配
    std::vector<uint8_t> cf;
    TEST("主机名不匹配拒绝", !tls13_process_server_flight(client, sf.data(), sf.size(), cf, nullptr, &trust));
}

void test_tls13_robustness_expired_cert() {
    // 构造一张过期 CA 签发的 leaf：链验证应因有效期失败
    uint8_t ca_pub[64], ca_priv[32];
    ecdsa_p256_keygen(ca_pub, ca_priv);
    x509::x509_builder ca_b;
    x509::DistinguishedName ca_dn;
    ca_dn.push_back({std::vector<uint8_t>(x509::OID_CN, x509::OID_CN + 3), "Expired CA"});
    ca_b.set_subject(ca_dn).set_issuer(ca_dn);
    uint8_t ca_ser[8] = {0xE1};
    ca_b.set_serial(ca_ser, 8);
    uint64_t now = (uint64_t)time(nullptr);
    ca_b.set_validity(now - 3 * 86400, now - 2 * 86400);  // 已过期
    ca_b.set_key(x509::KeyType::ECDSA_P256, ca_pub, 64);
    ca_b.set_ca(true);
    auto ca_cert = ca_b.build_and_sign(x509::KeyType::ECDSA_P256, ca_priv, 32);

    // 用过期 CA 签发 leaf（leaf 本身有效期内，但链根过期）
    uint8_t leaf_pub[64], leaf_priv[32];
    ecdsa_p256_keygen(leaf_pub, leaf_priv);
    x509::x509_builder leaf_b;
    x509::DistinguishedName leaf_dn;
    leaf_dn.push_back({std::vector<uint8_t>(x509::OID_CN, x509::OID_CN + 3), "localhost"});
    leaf_b.set_subject(leaf_dn).set_issuer(ca_dn);
    uint8_t leaf_ser[8] = {0xE2};
    leaf_b.set_serial(leaf_ser, 8);
    leaf_b.set_validity(now - 86400, now + 365 * 86400);
    leaf_b.set_key(x509::KeyType::ECDSA_P256, leaf_pub, 64);
    leaf_b.set_ca(false);
    leaf_b.add_san_dns("localhost");
    auto leaf_cert = leaf_b.build_and_sign(x509::KeyType::ECDSA_P256, ca_priv, 32);

    // 本库链验证：过期根必须失败
    auto chain = x509::x509_verify_chain({leaf_cert, ca_cert}, now);
    TEST("过期 CA 链验证失败", !chain.success);

    // TLS 握手路径：trust store 用过期 CA → 握手失败
    auto srv_cert = std::make_unique<tls_certificate>();
    srv_cert->subject_name = "localhost";
    srv_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    std::memcpy(srv_cert->pub.ecdsa_p256, leaf_pub, 64);
    std::memcpy(srv_cert->priv.ecdsa_p256, leaf_priv, 32);
    srv_cert->cert_data = leaf_cert.to_der();
    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate("localhost", std::move(srv_cert));

    tls_session client;
    client.server_name = "localhost";
    std::vector<uint8_t> ch;
    TEST("过期场景 ClientHello", tls13_make_client_hello(client, ch));
    tls_session server;
    std::vector<uint8_t> sf;
    TEST("过期场景 ServerFlight", tls13_make_server_flight(server, ch.data(), ch.size(), sf, cert_mgr));

    tls_trust_store trust;
    trust.ca_roots.push_back(ca_cert);
    std::vector<uint8_t> cf;
    TEST("过期 CA 信任库拒绝握手", !tls13_process_server_flight(client, sf.data(), sf.size(),
                                                                  cf, nullptr, &trust));
}

void test_tls13_client_x509_verify_reject() {
    // 服务端：CA 签发的 leaf（与上例相同）
    auto srv_cert = tls_certificate::from_pem(LEAF_CERT_PEM, SERVER_KEY_PEM);
    if (!srv_cert) return;
    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate("localhost", std::move(srv_cert));

    tls_session client;
    client.server_name = "localhost";
    std::vector<uint8_t> client_hello;
    tls13_make_client_hello(client, client_hello);

    tls_session server;
    std::vector<uint8_t> server_flight;
    tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                             server_flight, cert_mgr);

    // 客户端信任库用错误 CA → x509 链验证必须失败
    auto trust = tls_trust_store::from_pem(WRONG_CA_PEM);
    std::vector<uint8_t> client_finished;
    TEST("错误 CA 拒绝握手", !tls13_process_server_flight(client, server_flight.data(),
                                                           server_flight.size(),
                                                           client_finished, nullptr, &trust));
}

// ========================================================================
//  TLS 1.2 DHE (RFC 7919 ffdhe2048) / PSK (RFC 4279/5487) 测试
// ========================================================================

// ffdhe2048 DH 模块：密钥对一致性 + 越界公钥拒绝
void test_dh_ffdhe2048() {
    uint8_t a_pub[256], a_priv[32], b_pub[256], b_priv[32];
    jpssl::dh::ffdhe2048_keypair(a_pub, a_priv);
    jpssl::dh::ffdhe2048_keypair(b_pub, b_priv);
    uint8_t s1[256], s2[256];
    TEST("ffdhe2048 shared A->B", jpssl::dh::ffdhe2048_shared(s1, a_priv, b_pub));
    TEST("ffdhe2048 shared B->A", jpssl::dh::ffdhe2048_shared(s2, b_priv, a_pub));
    TEST("ffdhe2048 shared equal", memcmp(s1, s2, 256) == 0);

    uint8_t bad[256];
    memset(bad, 0, sizeof(bad));
    TEST("ffdhe2048 reject Y=0", !jpssl::dh::ffdhe2048_shared(s1, a_priv, bad));
    memset(bad, 0xFF, sizeof(bad)); // 全 0xFF > p，越界
    TEST("ffdhe2048 reject Y>=p", !jpssl::dh::ffdhe2048_shared(s1, a_priv, bad));
    memcpy(bad, jpssl::dh::ffdhe2048_p, 256);
    TEST("ffdhe2048 reject Y=p", !jpssl::dh::ffdhe2048_shared(s1, a_priv, bad));

    // minimal 编码：剥离前导零
    uint8_t z[256] = {0};
    z[255] = 0x2A;
    uint8_t minimal[256];
    size_t n = jpssl::dh::ffdhe2048_shared_minimal(z, minimal);
    TEST("ffdhe2048 minimal len", n == 1 && minimal[0] == 0x2A);
}

// 构造仅含指定套件的 TLS 1.2 ClientHello（DHE/PSK 定向测试用）
static std::vector<uint8_t> make_tls12_ch_single(const tls_session& s, uint16_t suite,
                                                 bool add_ffdhe_group,
                                                 bool add_sig_algs) {
    std::vector<uint8_t> ch;
    ch.push_back((uint8_t)HandshakeType::CLIENT_HELLO);
    ch.push_back(0); ch.push_back(0); ch.push_back(0);
    ch.push_back(0x03); ch.push_back(0x03);
    ch.insert(ch.end(), s.client_random, s.client_random + 32);
    ch.push_back(0); // session_id_len
    ch.push_back(0); ch.push_back(2); // 1 个套件
    ch.push_back((uint8_t)(suite >> 8)); ch.push_back((uint8_t)suite);
    ch.push_back(1); ch.push_back(0); // compression: null
    std::vector<uint8_t> ext;
    if (add_ffdhe_group) {
        ext.push_back(0x00); ext.push_back(0x0a); // supported_groups
        ext.push_back(0x00); ext.push_back(0x02);
        ext.push_back(0x01); ext.push_back(0x00); // ffdhe2048
    }
    if (add_sig_algs) {
        std::vector<uint16_t> algs = tls_default_signature_algorithms();
        size_t list_len = algs.size() * 2;
        ext.push_back(0x00); ext.push_back(0x0d); // signature_algorithms
        ext.push_back((uint8_t)((2 + list_len) >> 8)); ext.push_back((uint8_t)(2 + list_len));
        ext.push_back((uint8_t)(list_len >> 8)); ext.push_back((uint8_t)list_len);
        for (uint16_t a : algs) {
            ext.push_back((uint8_t)(a >> 8)); ext.push_back((uint8_t)a);
        }
    }
    uint16_t ext_total = (uint16_t)ext.size();
    ch.push_back((uint8_t)(ext_total >> 8)); ch.push_back((uint8_t)ext_total);
    ch.insert(ch.end(), ext.begin(), ext.end());
    size_t len = ch.size() - 4;
    ch[1] = (uint8_t)(len >> 16); ch[2] = (uint8_t)(len >> 8); ch[3] = (uint8_t)len;
    return ch;
}

static void fill_random(uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)(std::rand() & 0xFF);
}

// TLS 1.2 DHE-RSA 完整握手（服务端 tls12_make_server_hello_flight + 客户端完整路径）
void test_tls12_dhe_rsa_handshake() {
    tls_certificate_manager cert_mgr;
    auto server_cert = std::make_unique<tls_certificate>();
    server_cert->subject_name = "localhost";
    server_cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
    rsa_keygen(server_cert->pub.rsa, server_cert->priv.rsa);
    cert_mgr.add_certificate("localhost", std::move(server_cert));

    tls_session client;
    client.server_name = "localhost";
    fill_random(client.client_random, 32);
    auto ch = make_tls12_ch_single(client, 0x009E, /*ffdhe=*/true, /*sig_algs=*/true);
    client.tls12_client_hello_cache = ch;

    tls_session server;
    std::vector<uint8_t> hello_flight;
    TEST("DHE-RSA server hello flight",
         tls12_make_server_hello_flight(server, ch.data(), ch.size(), hello_flight, cert_mgr));
    TEST("DHE-RSA suite negotiated",
         server.cipher_suite == CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);

    std::vector<uint8_t> cke, client_finished;
    TEST("DHE-RSA client process flight",
         tls12_process_server_flight(client, hello_flight.data(), hello_flight.size(),
                                     nullptr, 0, client_finished, &cke, &cert_mgr));
    TEST("DHE-RSA CKE produced", !cke.empty());

    // 服务端：CKE 入 transcript 后处理并验证客户端 Finished
    tls_transcript_update(server, cke.data(), cke.size());
    std::vector<uint8_t> dummy;
    TEST("DHE-RSA server process CKE",
         tls12_process_client_key_exchange(server, cke.data() + 4, cke.size() - 4, dummy));
    TEST("DHE-RSA master secret match",
         memcmp(client.master_secret, server.master_secret, 48) == 0);
    TEST("DHE-RSA server verify client finished",
         tls12_verify_finished(server, client_finished.data(), client_finished.size(), false));

    // 服务端 Finished：客户端验证
    tls_transcript_update(server, client_finished.data(), client_finished.size());
    std::vector<uint8_t> sf = tls12_make_finished(server, /*for_server=*/true);
    TEST("DHE-RSA client verify server finished",
         tls12_verify_finished(client, sf.data(), sf.size(), true));

    // 记录层往返
    const uint8_t app[] = "DHE-RSA application data";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, app, sizeof(app) - 1);
    ContentType ct;
    std::vector<uint8_t> dec;
    TEST("DHE-RSA encrypt", !enc.empty());
    TEST("DHE-RSA decrypt", tls_decrypt(server, enc.data(), enc.size(), ct, dec));
    TEST("DHE-RSA roundtrip", dec.size() == sizeof(app) - 1 &&
         memcmp(dec.data(), app, sizeof(app) - 1) == 0);
}

// TLS 1.2 PSK 完整握手（纯 PSK，无证书）
void test_tls12_psk_handshake() {
    static const uint8_t kPsk[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                   0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
    static const char kIdent[] = "jpssl-test-identity";

    tls_psk_store psk_store;
    psk_store.add(kIdent, std::vector<uint8_t>(kPsk, kPsk + sizeof(kPsk)));

    tls_session client;
    client.tls12_psk_valid = true;
    memcpy(client.tls12_psk_identity, kIdent, sizeof(kIdent) - 1);
    client.tls12_psk_identity_len = sizeof(kIdent) - 1;
    memcpy(client.tls12_psk_value, kPsk, sizeof(kPsk));
    client.tls12_psk_value_len = sizeof(kPsk);
    fill_random(client.client_random, 32);
    auto ch = make_tls12_ch_single(client, 0x00AE, /*ffdhe=*/false, /*sig_algs=*/false);
    client.tls12_client_hello_cache = ch;

    // 服务端：无证书，仅 PSK 存储
    tls_certificate_manager cert_mgr;
    tls_session server;
    std::vector<uint8_t> hello_flight;
    TEST("PSK server hello flight",
         tls12_make_server_hello_flight(server, ch.data(), ch.size(), hello_flight,
                                        cert_mgr, &psk_store));
    TEST("PSK suite negotiated",
         server.cipher_suite == CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256);

    std::vector<uint8_t> cke, client_finished;
    TEST("PSK client process flight",
         tls12_process_server_flight(client, hello_flight.data(), hello_flight.size(),
                                     nullptr, 0, client_finished, &cke));
    TEST("PSK CKE produced", !cke.empty());

    tls_transcript_update(server, cke.data(), cke.size());
    std::vector<uint8_t> dummy;
    TEST("PSK server process CKE",
         tls12_process_client_key_exchange(server, cke.data() + 4, cke.size() - 4,
                                           dummy, &psk_store));
    TEST("PSK master secret match",
         memcmp(client.master_secret, server.master_secret, 48) == 0);
    TEST("PSK server verify client finished",
         tls12_verify_finished(server, client_finished.data(), client_finished.size(), false));

    tls_transcript_update(server, client_finished.data(), client_finished.size());
    std::vector<uint8_t> sf = tls12_make_finished(server, /*for_server=*/true);
    TEST("PSK client verify server finished",
         tls12_verify_finished(client, sf.data(), sf.size(), true));

    const uint8_t app[] = "PSK application data";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, app, sizeof(app) - 1);
    ContentType ct;
    std::vector<uint8_t> dec;
    TEST("PSK encrypt", !enc.empty());
    TEST("PSK decrypt", tls_decrypt(server, enc.data(), enc.size(), ct, dec));
    TEST("PSK roundtrip", dec.size() == sizeof(app) - 1 &&
         memcmp(dec.data(), app, sizeof(app) - 1) == 0);
}

// TLS 1.2 DHE-PSK 完整握手（RFC 4279 §3）
void test_tls12_dhe_psk_handshake() {
    static const uint8_t kPsk[] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    static const char kIdent[] = "dhe-psk-identity";

    tls_psk_store psk_store;
    psk_store.add(kIdent, std::vector<uint8_t>(kPsk, kPsk + sizeof(kPsk)));

    tls_session client;
    client.tls12_psk_valid = true;
    memcpy(client.tls12_psk_identity, kIdent, sizeof(kIdent) - 1);
    client.tls12_psk_identity_len = sizeof(kIdent) - 1;
    memcpy(client.tls12_psk_value, kPsk, sizeof(kPsk));
    client.tls12_psk_value_len = sizeof(kPsk);
    fill_random(client.client_random, 32);
    auto ch = make_tls12_ch_single(client, 0x00B2, /*ffdhe=*/true, /*sig_algs=*/false);
    client.tls12_client_hello_cache = ch;

    tls_certificate_manager cert_mgr;
    tls_session server;
    std::vector<uint8_t> hello_flight;
    TEST("DHE-PSK server hello flight",
         tls12_make_server_hello_flight(server, ch.data(), ch.size(), hello_flight,
                                        cert_mgr, &psk_store));
    TEST("DHE-PSK suite negotiated",
         server.cipher_suite == CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256);

    std::vector<uint8_t> cke, client_finished;
    TEST("DHE-PSK client process flight",
         tls12_process_server_flight(client, hello_flight.data(), hello_flight.size(),
                                     nullptr, 0, client_finished, &cke));
    TEST("DHE-PSK CKE produced", !cke.empty());

    tls_transcript_update(server, cke.data(), cke.size());
    std::vector<uint8_t> dummy;
    TEST("DHE-PSK server process CKE",
         tls12_process_client_key_exchange(server, cke.data() + 4, cke.size() - 4,
                                           dummy, &psk_store));
    TEST("DHE-PSK master secret match",
         memcmp(client.master_secret, server.master_secret, 48) == 0);
    TEST("DHE-PSK server verify client finished",
         tls12_verify_finished(server, client_finished.data(), client_finished.size(), false));

    tls_transcript_update(server, client_finished.data(), client_finished.size());
    std::vector<uint8_t> sf = tls12_make_finished(server, /*for_server=*/true);
    TEST("DHE-PSK client verify server finished",
         tls12_verify_finished(client, sf.data(), sf.size(), true));

    const uint8_t app[] = "DHE-PSK application data";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, app, sizeof(app) - 1);
    ContentType ct;
    std::vector<uint8_t> dec;
    TEST("DHE-PSK encrypt", !enc.empty());
    TEST("DHE-PSK decrypt", tls_decrypt(server, enc.data(), enc.size(), ct, dec));
    TEST("DHE-PSK roundtrip", dec.size() == sizeof(app) - 1 &&
         memcmp(dec.data(), app, sizeof(app) - 1) == 0);
}

// 未知 PSK 身份必须被服务端拒绝
void test_tls12_psk_unknown_identity() {
    static const uint8_t kPsk[] = {0xAA,0xBB};
    static const char kIdent[] = "known-identity";
    tls_psk_store psk_store;
    psk_store.add(kIdent, std::vector<uint8_t>(kPsk, kPsk + sizeof(kPsk)));

    tls_session client;
    client.tls12_psk_valid = true;
    memcpy(client.tls12_psk_identity, "unknown-identity", 16);
    client.tls12_psk_identity_len = 16;
    memcpy(client.tls12_psk_value, kPsk, sizeof(kPsk));
    client.tls12_psk_value_len = sizeof(kPsk);
    fill_random(client.client_random, 32);
    auto ch = make_tls12_ch_single(client, 0x00AE, false, false);
    client.tls12_client_hello_cache = ch;

    tls_certificate_manager cert_mgr;
    tls_session server;
    std::vector<uint8_t> hello_flight;
    TEST("PSK unknown identity hello flight",
         tls12_make_server_hello_flight(server, ch.data(), ch.size(), hello_flight,
                                        cert_mgr, &psk_store));
    std::vector<uint8_t> cke, client_finished;
    TEST("PSK unknown identity client process",
         tls12_process_server_flight(client, hello_flight.data(), hello_flight.size(),
                                     nullptr, 0, client_finished, &cke));
    std::vector<uint8_t> dummy;
    TEST("PSK unknown identity rejected by server",
         !tls12_process_client_key_exchange(server, cke.data() + 4, cke.size() - 4,
                                            dummy, &psk_store));
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
    RUN_TEST(test_tls13_0rtt_matrix);
    RUN_TEST(test_signature_algorithm_extensions);
    RUN_TEST(test_tls13_full_handshake_ecdsa_p384);
    RUN_TEST(test_tls13_full_handshake_ecdsa_p521);
    RUN_TEST(test_tls13_full_handshake_ecdsa_p256_ecdh);
    RUN_TEST(test_tls13_full_handshake_ecdsa_p384_ecdh);
    RUN_TEST(test_tls13_full_handshake_rsa_pss);
    RUN_TEST(test_tls13_rsa_pkcs1_cert_uses_pss);
    RUN_TEST(test_tls13_rejects_unadvertised_scheme);
    RUN_TEST(test_signature_algorithms_cert_enforcement);
    RUN_TEST(test_tls13_cert_verify_rfc8446_content);
    RUN_TEST(test_tls12_skx_scheme_selection);
    RUN_TEST(test_sign_scheme_cert_verify_context);
    RUN_TEST(test_tls_cert_from_pem);
    RUN_TEST(test_tls_cert_from_csr_pem);
    RUN_TEST(test_tls13_pem_server_x509_verify);
    RUN_TEST(test_tls13_client_x509_verify_reject);
    RUN_TEST(test_tls13_csr_server_handshake);
    RUN_TEST(test_tls_trust_store_system);
    RUN_TEST(test_tls13_robustness_malformed);
    RUN_TEST(test_tls13_robustness_hostname);
    RUN_TEST(test_tls13_robustness_expired_cert);
    RUN_TEST(test_dh_ffdhe2048);
    RUN_TEST(test_tls12_dhe_rsa_handshake);
    RUN_TEST(test_tls12_psk_handshake);
    RUN_TEST(test_tls12_dhe_psk_handshake);
    RUN_TEST(test_tls12_psk_unknown_identity);

    return test_summary();
}
