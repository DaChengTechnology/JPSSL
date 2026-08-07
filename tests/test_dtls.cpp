/**
 * test_dtls.cpp — DTLS 1.2 (RFC 6347) / DTLS 1.3 (RFC 9147) 单元测试
 *
 * 覆盖：
 *   - 内存数据报握手机（dtls_handshake_step）：DTLS 1.2/1.3 × 多种密码套件
 *   - cookie 交换（HelloVerifyRequest）
 *   - 多种密钥交换组（X25519 / P-256 / X448）与签名证书
 *   - 应用数据加解密（双向 + 大消息分片）
 *   - UDP socket 端到端握手与数据交换
 */

#include "test_utils.hpp"
#include "dtls.hpp"
#include "ecdsa.hpp"
#include "ed25519.hpp"
#include "x509.hpp"
#include <memory>
#include <cstring>
#include <thread>
#include <chrono>

using namespace jpssl::dtls;
using namespace jpssl;
using jpssl::tls::CipherSuite;
using jpssl::tls::NamedGroup;
using jpssl::tls::SignatureAlgorithm;
using jpssl::tls::tls_certificate;
using jpssl::tls::tls_certificate_manager;
using jpssl::tls::tls_trust_store;

// ═══════════════════════════════════════════════════════════════════════
//  证书辅助
// ═══════════════════════════════════════════════════════════════════════
static tls_certificate_manager make_cert_mgr(const char* dns, tls_trust_store* trust) {
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);
    x509::x509_builder b;
    x509::DistinguishedName dn;
    dn.push_back({std::vector<uint8_t>(x509::OID_CN, x509::OID_CN + 3), dns});
    b.set_subject(dn).set_issuer(dn);
    uint8_t ser[8] = {0x51, 0x51, 0x51, 0x51};
    b.set_serial(ser, 8);
    uint64_t now = (uint64_t)time(nullptr);
    b.set_validity(now - 3600, now + 365 * 86400);
    b.set_key(x509::KeyType::ECDSA_P256, pub, 64);
    b.set_ca(true);
    b.add_san_dns(dns);
    auto ca_cert = b.build_and_sign(x509::KeyType::ECDSA_P256, priv, 32);
    if (trust) trust->ca_roots.push_back(ca_cert);
    tls_certificate_manager mgr;
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = dns;
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    memcpy(cert->pub.ecdsa_p256, pub, 64);
    memcpy(cert->priv.ecdsa_p256, priv, 32);
    cert->cert_data = ca_cert.to_der();
    mgr.add_certificate(dns, std::move(cert));
    return mgr;
}

// ═══════════════════════════════════════════════════════════════════════
//  内存数据报握手
// ═══════════════════════════════════════════════════════════════════════
static bool run_handshake(dtls_session& client, dtls_session& server,
                          tls_certificate_manager& cert_mgr,
                          const tls_trust_store* trust = nullptr) {
    std::vector<uint8_t> dg;
    int guard = 0;
    while (!(client.handshake_done && server.handshake_done)) {
        if (guard++ > 40) return false;
        if (!client.handshake_done) {
            dtls_handshake_input in;
            if (!dg.empty()) { in.datagram = dg.data(); in.datagram_len = dg.size(); }
            in.trust_store = trust;
            auto step = dtls_handshake_step(client, in);
            if (!step.ok) return false;
            dg = step.out;
        }
        if (!server.handshake_done && !dg.empty()) {
            dtls_handshake_input sin;
            sin.datagram = dg.data(); sin.datagram_len = dg.size();
            sin.cert_manager = &cert_mgr;
            auto step = dtls_handshake_step(server, sin);
            if (!step.ok) return false;
            dg = step.out;
        }
        if (client.handshake_done && server.handshake_done) break;
        if (client.handshake_done && dg.empty()) break;
    }
    return client.handshake_done && server.handshake_done;
}

static bool app_roundtrip(dtls_session& a, dtls_session& b,
                          const uint8_t* msg, size_t len) {
    auto enc = dtls_protect_application(a, msg, len);
    std::vector<uint8_t> dec;
    if (!dtls_unprotect_application(b, enc.data(), enc.size(), dec)) return false;
    return dec.size() == len && memcmp(dec.data(), msg, len) == 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  DTLS 1.2 测试
// ═══════════════════════════════════════════════════════════════════════
void test_dtls12_aes128() {
    tls_trust_store trust;
    auto cert_mgr = make_cert_mgr("dtls.test", &trust);
    dtls_session client, server;
    client.ver = DTLSVersion::V12;
    client.server_name = "dtls.test";
    client.cipher_suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    server.ver = DTLSVersion::V12;
    server.is_server = true;
    server.cipher_suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

    TEST("DTLS1.2 AES-128 handshake", run_handshake(client, server, cert_mgr, &trust));
    TEST("client done", client.handshake_done);
    TEST("server done", server.handshake_done);
    TEST("peer finished", server.peer_finished);

    static const uint8_t msg[] = "Hello DTLS 1.2 AES-GCM!";
    TEST("c->s app data", app_roundtrip(client, server, msg, sizeof(msg) - 1));
    TEST("s->c app data", app_roundtrip(server, client, msg, sizeof(msg) - 1));

    // 大消息分片（跨多条 record）
    std::vector<uint8_t> big(10000);
    for (size_t i = 0; i < big.size(); ++i) big[i] = (uint8_t)(i * 7);
    TEST("c->s 10KB app data", app_roundtrip(client, server, big.data(), big.size()));
}

void test_dtls12_chacha20() {
    tls_trust_store trust;
    auto cert_mgr = make_cert_mgr("dtls.test", &trust);
    dtls_session client, server;
    client.ver = DTLSVersion::V12;
    client.server_name = "dtls.test";
    client.cipher_suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
    server.ver = DTLSVersion::V12;
    server.is_server = true;
    server.cipher_suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;

    TEST("DTLS1.2 ChaCha20 handshake", run_handshake(client, server, cert_mgr, &trust));
    TEST("DTLS1.2 ChaCha20 key_len 32", client.key_len == 32 && client.iv_len == 12);

    static const uint8_t msg[] = "ChaCha20 DTLS";
    TEST("c->s chacha app", app_roundtrip(client, server, msg, sizeof(msg) - 1));
}

void test_dtls12_cookie() {
    tls_trust_store trust;
    auto cert_mgr = make_cert_mgr("dtls.test", &trust);
    dtls_session client, server;
    client.ver = DTLSVersion::V12;
    client.server_name = "dtls.test";
    client.cipher_suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    server.ver = DTLSVersion::V12;
    server.is_server = true;
    server.require_cookie = true;
    server.cipher_suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

    // 客户端首包
    dtls_handshake_input in;
    auto step = dtls_handshake_step(client, in);
    TEST("client first CH", step.ok && !step.out.empty());
    TEST("client not done yet", !step.done);

    // 服务端收到无 cookie 的 CH → HelloVerifyRequest
    dtls_handshake_input sin;
    sin.datagram = step.out.data(); sin.datagram_len = step.out.size();
    sin.cert_manager = &cert_mgr;
    auto sstep = dtls_handshake_step(server, sin);
    TEST("server sends HVR", sstep.ok && !sstep.out.empty());
    TEST("server still waiting", !sstep.done);
    TEST("HVR is 13-byte-header record", sstep.out.size() > 13);

    // 客户端收到 HVR → 带 cookie 重发 CH
    dtls_handshake_input in2;
    in2.datagram = sstep.out.data(); in2.datagram_len = sstep.out.size();
    in2.trust_store = &trust;
    auto cstep = dtls_handshake_step(client, in2);
    TEST("client resends CH with cookie", cstep.ok && !cstep.out.empty());
    TEST("client got HVR", client.hvr_received);

    // 剩余握手：从服务端处理带 cookie 的 CH 开始
    std::vector<uint8_t> dg = cstep.out;
    int guard = 0;
    while (!(client.handshake_done && server.handshake_done)) {
        if (guard++ > 40) { TEST("cookie handshake loop", false); break; }
        if (!server.handshake_done && !dg.empty()) {
            dtls_handshake_input si;
            si.datagram = dg.data(); si.datagram_len = dg.size();
            si.cert_manager = &cert_mgr;
            auto r = dtls_handshake_step(server, si);
            if (!r.ok) break;
            dg = r.out;
        }
        if (!client.handshake_done && !dg.empty()) {
            dtls_handshake_input ci;
            ci.datagram = dg.data(); ci.datagram_len = dg.size();
            ci.trust_store = &trust;
            auto r = dtls_handshake_step(client, ci);
            if (!r.ok) break;
            dg = r.out;
        }
        if (client.handshake_done && dg.empty()) break;
    }
    TEST("DTLS1.2 cookie handshake completes", client.handshake_done && server.handshake_done);
    TEST("server validated cookie", server.client_hello_ok);
}

void test_dtls12_record_format() {
    tls_trust_store trust;
    auto cert_mgr = make_cert_mgr("dtls.test", &trust);
    dtls_session client, server;
    client.ver = DTLSVersion::V12;
    client.server_name = "dtls.test";
    server.ver = DTLSVersion::V12;
    server.is_server = true;
    TEST("DTLS1.2 setup handshake", run_handshake(client, server, cert_mgr, &trust));

    uint8_t msg[4] = {1, 2, 3, 4};
    auto enc = dtls_protect_application(client, msg, 4);
    // 头部：type(23) || fe fd || epoch(2)=1 || seq(6) || len(2)=4+16
    TEST("record header size", enc.size() >= 13 + 4 + 16);
    TEST("record type 23", enc[0] == 23);
    TEST("record version fefd", enc[1] == 0xfe && enc[2] == 0xfd);
    TEST("record epoch 1", enc[3] == 0 && enc[4] == 1);
    uint16_t rlen = (uint16_t)((enc[11] << 8) | enc[12]);
    TEST("record length = pt + tag", rlen == 4 + 16);
    TEST("record total size matches", enc.size() == 13 + rlen);

    // 篡改密文 → 认证失败（静默丢弃）
    auto tampered = enc;
    tampered[13] ^= 0xFF;
    std::vector<uint8_t> out;
    TEST("tampered record rejected", !dtls_unprotect_application(server, tampered.data(), tampered.size(), out));
}

// ═══════════════════════════════════════════════════════════════════════
//  DTLS 1.3 测试
// ═══════════════════════════════════════════════════════════════════════
void test_dtls13_aes128() {
    tls_trust_store trust;
    auto cert_mgr = make_cert_mgr("dtls.test", &trust);
    dtls_session client, server;
    client.ver = DTLSVersion::V13;
    client.server_name = "dtls.test";
    client.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    server.ver = DTLSVersion::V13;
    server.is_server = true;
    server.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;

    TEST("DTLS1.3 AES-128 handshake", run_handshake(client, server, cert_mgr, &trust));
    TEST("client done", client.handshake_done);
    TEST("server done", server.handshake_done);
    static const uint8_t msg[] = "Hello DTLS 1.3!";
    TEST("c->s app data", app_roundtrip(client, server, msg, sizeof(msg) - 1));
    TEST("s->c app data", app_roundtrip(server, client, msg, sizeof(msg) - 1));
    std::vector<uint8_t> big(20000);
    for (size_t i = 0; i < big.size(); ++i) big[i] = (uint8_t)(i * 3 + 1);
    TEST("c->s 20KB app data", app_roundtrip(client, server, big.data(), big.size()));
}

void test_dtls13_aes256() {
    tls_trust_store trust;
    auto cert_mgr = make_cert_mgr("dtls.test", &trust);
    dtls_session client, server;
    client.ver = DTLSVersion::V13;
    client.server_name = "dtls.test";
    client.cipher_suite = CipherSuite::TLS_AES_256_GCM_SHA384;
    server.ver = DTLSVersion::V13;
    server.is_server = true;
    server.cipher_suite = CipherSuite::TLS_AES_256_GCM_SHA384;

    TEST("DTLS1.3 AES-256 (SHA-384) handshake", run_handshake(client, server, cert_mgr, &trust));
    static const uint8_t msg[] = "DTLS 1.3 AES-256-GCM";
    TEST("DTLS1.3 AES-256 app", app_roundtrip(client, server, msg, sizeof(msg) - 1));
}

void test_dtls13_chacha20() {
    tls_trust_store trust;
    auto cert_mgr = make_cert_mgr("dtls.test", &trust);
    dtls_session client, server;
    client.ver = DTLSVersion::V13;
    client.server_name = "dtls.test";
    client.cipher_suite = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
    server.ver = DTLSVersion::V13;
    server.is_server = true;
    server.cipher_suite = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;

    TEST("DTLS1.3 ChaCha20 handshake", run_handshake(client, server, cert_mgr, &trust));
    static const uint8_t msg[] = "DTLS 1.3 ChaCha20-Poly1305";
    TEST("DTLS1.3 ChaCha20 app", app_roundtrip(client, server, msg, sizeof(msg) - 1));
}

void test_dtls13_groups() {
    // P-256
    {
        tls_trust_store trust;
        auto cert_mgr = make_cert_mgr("dtls.test", &trust);
        dtls_session client, server;
        client.ver = DTLSVersion::V13;
        client.server_name = "dtls.test";
        client.ks_group = NamedGroup::secp256r1;
        server.ver = DTLSVersion::V13;
        server.is_server = true;
        server.ks_group = NamedGroup::secp256r1;
        TEST("DTLS1.3 P-256 handshake", run_handshake(client, server, cert_mgr, &trust));
        static const uint8_t msg[] = "P-256";
        TEST("DTLS1.3 P-256 app", app_roundtrip(client, server, msg, sizeof(msg) - 1));
    }
    // X448
    {
        tls_trust_store trust;
        auto cert_mgr = make_cert_mgr("dtls.test", &trust);
        dtls_session client, server;
        client.ver = DTLSVersion::V13;
        client.server_name = "dtls.test";
        client.ks_group = NamedGroup::X448;
        server.ver = DTLSVersion::V13;
        server.is_server = true;
        server.ks_group = NamedGroup::X448;
        TEST("DTLS1.3 X448 handshake", run_handshake(client, server, cert_mgr, &trust));
        static const uint8_t msg[] = "X448";
        TEST("DTLS1.3 X448 app", app_roundtrip(client, server, msg, sizeof(msg) - 1));
    }
}

void test_dtls13_no_trust() {
    // 不提供信任库：握手仍应完成（CertificateVerify 跳过校验）
    auto cert_mgr = make_cert_mgr("dtls.test", nullptr);
    dtls_session client, server;
    client.ver = DTLSVersion::V13;
    client.server_name = "dtls.test";
    server.ver = DTLSVersion::V13;
    server.is_server = true;
    TEST("DTLS1.3 no-trust handshake", run_handshake(client, server, cert_mgr, nullptr));
}

void test_dtls13_wrong_trust() {
    // 服务端证书 = CA 签发的 leaf；客户端信任库放错误的 CA → 链验证必须失败
    // 生成真实 CA 并签发 leaf
    uint8_t ca_pub[64], ca_priv[32];
    ecdsa_p256_keygen(ca_pub, ca_priv);
    x509::x509_builder ca_b;
    x509::DistinguishedName ca_dn;
    ca_dn.push_back({std::vector<uint8_t>(x509::OID_CN, x509::OID_CN + 3), "Real CA"});
    ca_b.set_subject(ca_dn).set_issuer(ca_dn);
    uint8_t ca_ser[8] = {0x01};
    ca_b.set_serial(ca_ser, 8);
    ca_b.set_validity((uint64_t)time(nullptr), (uint64_t)time(nullptr) + 86400 * 365);
    ca_b.set_key(x509::KeyType::ECDSA_P256, ca_pub, 64);
    ca_b.set_ca(true);
    auto ca_cert = ca_b.build_and_sign(x509::KeyType::ECDSA_P256, ca_priv, 32);

    uint8_t leaf_pub[64], leaf_priv[32];
    ecdsa_p256_keygen(leaf_pub, leaf_priv);
    x509::x509_builder leaf_b;
    x509::DistinguishedName leaf_dn;
    leaf_dn.push_back({std::vector<uint8_t>(x509::OID_CN, x509::OID_CN + 3), "dtls.test"});
    leaf_b.set_subject(leaf_dn).set_issuer(ca_dn);
    uint8_t leaf_ser[8] = {0x02};
    leaf_b.set_serial(leaf_ser, 8);
    leaf_b.set_validity((uint64_t)time(nullptr), (uint64_t)time(nullptr) + 86400 * 365);
    leaf_b.set_key(x509::KeyType::ECDSA_P256, leaf_pub, 64);
    leaf_b.set_ca(false);
    leaf_b.add_san_dns("dtls.test");
    auto leaf_cert = leaf_b.build_and_sign(x509::KeyType::ECDSA_P256, ca_priv, 32);

    tls_certificate_manager cert_mgr;
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = "dtls.test";
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    memcpy(cert->pub.ecdsa_p256, leaf_pub, 64);
    memcpy(cert->priv.ecdsa_p256, leaf_priv, 32);
    cert->cert_data = leaf_cert.to_der();
    cert_mgr.add_certificate("dtls.test", std::move(cert));

    // 错误 CA
    tls_trust_store wrong_trust;
    uint8_t wpub[64], wpriv[32];
    ecdsa_p256_keygen(wpub, wpriv);
    x509::x509_builder wb;
    x509::DistinguishedName wdn;
    wdn.push_back({std::vector<uint8_t>(x509::OID_CN, x509::OID_CN + 3), "Wrong CA"});
    wb.set_subject(wdn).set_issuer(wdn);
    uint8_t wser[8] = {0x99};
    wb.set_serial(wser, 8);
    wb.set_validity((uint64_t)time(nullptr), (uint64_t)time(nullptr) + 86400);
    wb.set_key(x509::KeyType::ECDSA_P256, wpub, 64);
    wb.set_ca(true);
    auto wrong_ca = wb.build_and_sign(x509::KeyType::ECDSA_P256, wpriv, 32);
    wrong_trust.ca_roots.push_back(wrong_ca);

    dtls_session client, server;
    client.ver = DTLSVersion::V13;
    client.server_name = "dtls.test";
    server.ver = DTLSVersion::V13;
    server.is_server = true;
    TEST("DTLS1.3 wrong CA rejected", !run_handshake(client, server, cert_mgr, &wrong_trust));
}

// 正确的 CA 信任库应通过
void test_dtls13_correct_trust() {
    tls_trust_store trust;
    auto cert_mgr = make_cert_mgr("dtls.test", &trust);
    dtls_session client, server;
    client.ver = DTLSVersion::V13;
    client.server_name = "dtls.test";
    server.ver = DTLSVersion::V13;
    server.is_server = true;
    TEST("DTLS1.3 correct CA accepted", run_handshake(client, server, cert_mgr, &trust));
}

// ═══════════════════════════════════════════════════════════════════════
//  UDP socket 端到端
// ═══════════════════════════════════════════════════════════════════════
void test_dtls_socket() {
    auto cert_mgr = make_cert_mgr("dtls.test", nullptr);

    dtls_connection server;
    server.set_version(DTLSVersion::V13);
    TEST("server bind", server.bind(0, "127.0.0.1"));
    uint16_t port = server.local_port();
    TEST("server bound port != 0", port != 0);

    bool srv_ok = false, cli_ok = false;
    std::thread t([&] {
        srv_ok = server.server_handshake(cert_mgr);
    });

    dtls_connection client;
    client.set_version(DTLSVersion::V13);
    client.set_server_name("dtls.test");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    cli_ok = client.connect("127.0.0.1", port);

    t.join();
    TEST("server handshake ok", srv_ok);
    TEST("client handshake ok", cli_ok);

    if (srv_ok && cli_ok) {
        const char* msg = "DTLS over UDP!";
        TEST("client send", client.send((const uint8_t*)msg, strlen(msg)));
        std::vector<uint8_t> got;
        TEST("server recv", server.recv(got));
        TEST("server got correct data", got.size() == strlen(msg) && memcmp(got.data(), msg, got.size()) == 0);

        const char* reply = "pong";
        TEST("server send", server.send((const uint8_t*)reply, strlen(reply)));
        std::vector<uint8_t> got2;
        TEST("client recv", client.recv(got2));
        TEST("client got correct data", got2.size() == strlen(reply) && memcmp(got2.data(), reply, got2.size()) == 0);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  入口
// ═══════════════════════════════════════════════════════════════════════
int main() {
    std::cout << "Running jpssl DTLS 1.2/1.3 unit tests\n" << std::endl;
    RUN_TEST(test_dtls12_aes128);
    RUN_TEST(test_dtls12_chacha20);
    RUN_TEST(test_dtls12_cookie);
    RUN_TEST(test_dtls12_record_format);
    RUN_TEST(test_dtls13_aes128);
    RUN_TEST(test_dtls13_aes256);
    RUN_TEST(test_dtls13_chacha20);
    RUN_TEST(test_dtls13_groups);
    RUN_TEST(test_dtls13_no_trust);
    RUN_TEST(test_dtls13_wrong_trust);
    RUN_TEST(test_dtls13_correct_trust);
    RUN_TEST(test_dtls_socket);
    return test_summary();
}
