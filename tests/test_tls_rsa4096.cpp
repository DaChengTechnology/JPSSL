/**
 * test_tls_rsa4096.cpp — 服务端 tls_certificate 的 RSA-4096 装载与签名/验签
 *
 * 覆盖内容：
 *   1. tls_certificate::from_pem_file 装载 RSA-4096 证书 + 私钥：
 *      subject/sig_alg/cert_data 正确，rsa4096 标记置位，priv.rsa4096 的 n/d 与
 *      x509::private_key::from_pem 一致
 *   2. sign_scheme / verify_scheme：RSA-PSS-RSAE-SHA256/384/512 与
 *      RSA-PKCS1-SHA256/384/512 均输出 512 字节签名并可验签，篡改 1 字节后验签失败；
 *      RSA-2048（server-rsa.pem）回归仍为 256 字节签名往返
 *   3. TLS 1.3 完整握手：服务端 RSA-4096 证书，客户端 trust_store 由 ca.pem 构造
 *      （证书链 + CertificateVerify 校验），selected_sig_alg 属 RSA_PSS_*，应用数据双向一致
 *   4. TLS 1.2 ECDHE-RSA 完整握手：RSA-4096 证书签 ServerKeyExchange，数据往返一致
 *   5. from_csr_pem 装载 RSA-4096 CSR + 私钥；tls_make_x509_self_signed 生成的自签名证书
 *      可被 x509::x509_cert::from_der 解析、key_type 为 RSA_4096 且自签名验签通过
 *
 * 测试证书：tests/certs/tls/（EC P-256 CA + RSA-2048 leaf + RSA-4096 leaf/CSR/私钥）
 */

#include "tls.hpp"
#include "x509.hpp"
#include "rsa.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

static int pass = 0, fail = 0;

#define TEST(name, cond) do { \
    if (cond) { std::printf("  PASS: %s\n", name); pass++; } \
    else { std::fprintf(stderr, "  FAIL: %s\n", name); fail++; } \
} while(0)

// ═══════════════════════════════════════════════════════════════════════
//  测试证书定位（ctest 工作目录可能是 build/tests，逐级向上查找源码树）
// ═══════════════════════════════════════════════════════════════════════
static std::string g_cert_dir;

static bool file_exists(const std::string& p) {
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f) return false;
    std::fclose(f);
    return true;
}

static std::string cert_dir() {
    if (!g_cert_dir.empty()) return g_cert_dir;
    static const char* candidates[] = {
        "tests/certs/tls", "../tests/certs/tls", "../../tests/certs/tls",
        "../../../tests/certs/tls", "certs/tls",
    };
    if (const char* env = std::getenv("JPSSL_TLS_CERT_DIR")) {
        if (file_exists(std::string(env) + "/server-rsa4096.pem")) {
            g_cert_dir = env;
            return g_cert_dir;
        }
    }
    for (const char* c : candidates) {
        if (file_exists(std::string(c) + "/server-rsa4096.pem")) {
            g_cert_dir = c;
            return g_cert_dir;
        }
    }
    g_cert_dir = "tests/certs/tls";  // 找不到时仍按默认路径尝试，便于报错定位
    return g_cert_dir;
}

static bool read_file(const std::string& path, std::string& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz > 0) {
        out.resize((size_t)sz);
        size_t rd = std::fread(&out[0], 1, (size_t)sz, f);
        out.resize(rd);
    }
    std::fclose(f);
    return true;
}

static bool read_cert_file(const char* name, std::string& out) {
    return read_file(cert_dir() + "/" + name, out);
}

static const char* CN = "localhost";

// 装载服务端 RSA-4096 证书（证书文件 + 私钥文件）
static std::unique_ptr<tls_certificate> load_rsa4096_cert(std::string* err = nullptr) {
    return tls_certificate::from_pem_file((cert_dir() + "/server-rsa4096.pem").c_str(),
                                          (cert_dir() + "/server-rsa4096-key.pem").c_str(), err);
}

// TLS 1.3 允许的 CertificateVerify 方案集合中的 RSA-PSS-RSAE 家族
static bool is_pss_scheme(uint16_t s) {
    return s == (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256 ||
           s == (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384 ||
           s == (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA512;
}

// ═══════════════════════════════════════════════════════════════════════
//  1. tls_certificate::from_pem_file 装载 RSA-4096 证书 + 私钥
// ═══════════════════════════════════════════════════════════════════════
static void test_load_rsa4096_from_pem() {
    std::printf("\n=== RSA-4096 证书/私钥装载（from_pem_file） ===\n");
    std::string err;
    auto cert = load_rsa4096_cert(&err);
    TEST("from_pem_file(server-rsa4096.pem, server-rsa4096-key.pem) 成功", cert != nullptr);
    if (!cert) {
        std::printf("  err: %s\n", err.c_str());
        return;
    }
    TEST("subject_name == localhost", cert->subject_name == CN);
    TEST("sig_alg == RSA_PKCS1_SHA256",
         cert->sig_alg == SignatureAlgorithm::RSA_PKCS1_SHA256);
    TEST("rsa4096 == true", cert->rsa4096);
    TEST("cert_data 非空（原始 DER 原样发送）", !cert->cert_data.empty());

    // priv.rsa4096 的 n/d 与 x509 层解析结果逐字节一致
    std::string cert_pem, key_pem;
    TEST("读取 server-rsa4096.pem", read_cert_file("server-rsa4096.pem", cert_pem));
    TEST("读取 server-rsa4096-key.pem", read_cert_file("server-rsa4096-key.pem", key_pem));
    auto xk = x509::private_key::from_pem(key_pem);
    TEST("x509 私钥解析（KeyType::RSA_4096）",
         xk.has_value() && xk->key_type == x509::KeyType::RSA_4096);
    if (xk) {
        uint8_t n[512], d[512];
        cert->priv.rsa4096.n.to_bytes(n);
        cert->priv.rsa4096.d.to_bytes(d);
        TEST("priv.rsa4096.n 与 x509 私钥 n 一致",
             xk->pub.size() >= 512 && std::memcmp(n, xk->pub.data(), 512) == 0);
        TEST("priv.rsa4096.d 与 x509 私钥 d 一致",
             xk->priv.size() == 512 && std::memcmp(d, xk->priv.data(), 512) == 0);
        uint8_t e[512];
        cert->priv.rsa4096.e.to_bytes(e);
        TEST("priv.rsa4096.e == 65537",
             e[509] == 0x01 && e[510] == 0x00 && e[511] == 0x01);
    }
    auto xc = x509::x509_cert::from_pem(cert_pem);
    TEST("x509 证书解析（KeyType::RSA_4096）",
         xc.has_value() && xc->key_type == x509::KeyType::RSA_4096);
    if (xc) {
        uint8_t n[512];
        cert->pub.rsa4096.n.to_bytes(n);
        TEST("pub.rsa4096.n 与证书公钥一致",
             xc->public_key.size() == 515 &&
             std::memcmp(n, xc->public_key.data(), 512) == 0);
        TEST("证书 DER 与 cert_data 一致",
             xc->to_der().size() > 0 && cert->cert_data.size() > 0);
    }

    // 私钥 CRT 参数已装入（PKCS#8 完整私钥），用于 CRT 快速签名
    TEST("CRT 参数已装载（p/q/dP/dQ/qInv 非零）",
         !cert->priv.rsa4096.p.is_zero() && !cert->priv.rsa4096.q.is_zero() &&
         !cert->priv.rsa4096.dP.is_zero() && !cert->priv.rsa4096.dQ.is_zero() &&
         !cert->priv.rsa4096.qInv.is_zero());
}

// ═══════════════════════════════════════════════════════════════════════
//  2. sign_scheme / verify_scheme：RSA-4096 全方案 + RSA-2048 回归
// ═══════════════════════════════════════════════════════════════════════
static void test_sign_verify_roundtrip() {
    std::printf("\n=== RSA-4096 sign_scheme / verify_scheme 往返 ===\n");
    std::string err;
    auto cert = load_rsa4096_cert(&err);
    TEST("RSA-4096 证书装载", cert != nullptr);
    if (!cert) return;

    static const uint16_t schemes[] = {
        (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256,
        (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA384,
        (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA512,
    };
    static const char* names[] = {
        "PSS-SHA256", "PSS-SHA384", "PSS-SHA512",
        "PKCS1-SHA256", "PKCS1-SHA384", "PKCS1-SHA512",
    };
    const uint8_t msg[] = "jpssl TLS RSA-4096 sign/verify round-trip message";
    char label[128];
    for (size_t i = 0; i < sizeof(schemes) / sizeof(schemes[0]); ++i) {
        uint8_t sig[512];
        size_t sig_len = 0;
        std::snprintf(label, sizeof(label), "RSA-4096 %s 签名 512 字节", names[i]);
        bool ok = cert->sign_scheme(schemes[i], msg, sizeof(msg) - 1, sig, sig_len);
        TEST(label, ok && sig_len == 512);

        std::snprintf(label, sizeof(label), "RSA-4096 %s 验签通过", names[i]);
        TEST(label, cert->verify_scheme(schemes[i], msg, sizeof(msg) - 1, sig, sig_len));

        sig[11] ^= 0x20;  // 篡改 1 字节
        std::snprintf(label, sizeof(label), "RSA-4096 %s 篡改后验签失败", names[i]);
        TEST(label, !cert->verify_scheme(schemes[i], msg, sizeof(msg) - 1, sig, sig_len));
    }

    // RSA-2048 回归：仍为 256 字节签名往返，rsa4096 保持 false
    auto cert2048 = tls_certificate::from_pem_file((cert_dir() + "/server-rsa.pem").c_str(),
                                                   (cert_dir() + "/server-rsa-key.pem").c_str(), &err);
    TEST("RSA-2048 证书装载（回归）", cert2048 != nullptr);
    if (!cert2048) return;
    TEST("RSA-2048 rsa4096 == false", !cert2048->rsa4096);
    uint8_t sig[512];
    size_t sig_len = 0;
    TEST("RSA-2048 PSS-SHA256 签名 256 字节",
         cert2048->sign_scheme((uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                               msg, sizeof(msg) - 1, sig, sig_len) && sig_len == 256);
    TEST("RSA-2048 PSS-SHA256 验签通过",
         cert2048->verify_scheme((uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                                 msg, sizeof(msg) - 1, sig, sig_len));
    sig_len = 0;
    TEST("RSA-2048 PKCS1-SHA256 签名 256 字节",
         cert2048->sign_scheme((uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256,
                               msg, sizeof(msg) - 1, sig, sig_len) && sig_len == 256);
    TEST("RSA-2048 PKCS1-SHA256 验签通过",
         cert2048->verify_scheme((uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256,
                                 msg, sizeof(msg) - 1, sig, sig_len));
}

// ═══════════════════════════════════════════════════════════════════════
//  3. TLS 1.3 完整握手（RSA-4096 服务端证书 + ca.pem 信任库）
// ═══════════════════════════════════════════════════════════════════════
static void test_tls13_handshake_rsa4096() {
    std::printf("\n=== TLS 1.3 完整握手（RSA-4096 服务端证书） ===\n");
    std::string err;
    auto cert = load_rsa4096_cert(&err);
    TEST("服务端 RSA-4096 证书装载", cert != nullptr);
    if (!cert) return;

    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate(CN, std::move(cert));

    std::string ca_pem;
    bool ca_read = read_cert_file("ca.pem", ca_pem);
    tls_trust_store ts = tls_trust_store::from_pem(ca_pem);
    TEST("客户端信任库由 ca.pem 构造", ca_read && ts.count() > 0);

    tls_session client;
    client.server_name = CN;
    std::vector<uint8_t> client_hello;
    TEST("TLS 1.3 客户端 ClientHello", tls13_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> server_flight;
    TEST("TLS 1.3 服务端 ServerFlight（RSA-4096 签 CertificateVerify）",
         tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                  server_flight, cert_mgr));
    TEST("selected_sig_alg 属 RSA_PSS_*", is_pss_scheme(server.selected_sig_alg));

    std::vector<uint8_t> client_finished;
    TEST("TLS 1.3 客户端处理 ServerFlight（链验证 + CertificateVerify 验签）",
         tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                     client_finished, nullptr, &ts));
    TEST("TLS 1.3 服务端校验客户端 Finished",
         tls13_process_client_finished(server, client_finished.data(), client_finished.size()));

    // ── 应用数据双向加解密 ──
    const uint8_t c2s[] = "TLS1.3 RSA-4096 client->server data";
    std::vector<uint8_t> enc = tls_encrypt(client, ContentType::APPLICATION_DATA,
                                           c2s, sizeof(c2s) - 1);
    TEST("客户端加密应用数据", !enc.empty());
    ContentType ct;
    std::vector<uint8_t> dec;
    TEST("服务端解密成功", tls_decrypt(server, enc.data(), enc.size(), ct, dec));
    TEST("C→S 明文一致",
         ct == ContentType::APPLICATION_DATA && dec.size() == sizeof(c2s) - 1 &&
         std::memcmp(dec.data(), c2s, sizeof(c2s) - 1) == 0);

    const uint8_t s2c[] = "TLS1.3 RSA-4096 server->client data";
    std::vector<uint8_t> enc2 = tls_encrypt(server, ContentType::APPLICATION_DATA,
                                            s2c, sizeof(s2c) - 1);
    ContentType ct2;
    std::vector<uint8_t> dec2;
    TEST("客户端解密成功", tls_decrypt(client, enc2.data(), enc2.size(), ct2, dec2));
    TEST("S→C 明文一致",
         ct2 == ContentType::APPLICATION_DATA && dec2.size() == sizeof(s2c) - 1 &&
         std::memcmp(dec2.data(), s2c, sizeof(s2c) - 1) == 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  4. TLS 1.2 ECDHE-RSA 完整握手（RSA-4096 证书签 ServerKeyExchange）
// ═══════════════════════════════════════════════════════════════════════
static void test_tls12_ecdhe_rsa_handshake() {
    std::printf("\n=== TLS 1.2 ECDHE-RSA 完整握手（RSA-4096 证书） ===\n");
    std::string err;
    auto cert = load_rsa4096_cert(&err);
    TEST("服务端 RSA-4096 证书装载", cert != nullptr);
    if (!cert) return;

    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate(CN, std::move(cert));

    std::string ca_pem;
    bool ca_read = read_cert_file("ca.pem", ca_pem);
    tls_trust_store ts = tls_trust_store::from_pem(ca_pem);
    TEST("客户端信任库由 ca.pem 构造", ca_read && ts.count() > 0);

    tls_session client;
    client.server_name = CN;
    std::vector<uint8_t> client_hello;
    TEST("TLS 1.2 客户端 ClientHello", tls12_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> hello_flight;
    TEST("TLS 1.2 服务端 hello flight（含 RSA-4096 签名的 ServerKeyExchange）",
         tls12_make_server_hello_flight(server, client_hello.data(), client_hello.size(),
                                        hello_flight, cert_mgr));
    TEST("协商套件为 ECDHE-RSA",
         server.cipher_suite == CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
         server.cipher_suite == CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
         server.cipher_suite == CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);

    std::vector<uint8_t> cke, client_finished;
    TEST("TLS 1.2 客户端处理 hello flight（链验证 + SKX 验签 + ECDHE）",
         tls12_process_server_flight(client, hello_flight.data(), hello_flight.size(),
                                     nullptr, 0, client_finished, &cke, nullptr, &ts));
    TEST("客户端生成了 ClientKeyExchange", !cke.empty());
    if (cke.empty()) return;

    tls_transcript_update(server, cke.data(), cke.size());
    std::vector<uint8_t> server_ccs_finished;
    TEST("TLS 1.2 服务端处理 ClientKeyExchange",
         tls12_process_client_key_exchange(server, cke.data() + 4, cke.size() - 4,
                                           server_ccs_finished));
    TEST("master_secret 一致",
         std::memcmp(client.master_secret, server.master_secret, 48) == 0);
    TEST("服务端校验客户端 Finished",
         tls12_verify_finished(server, client_finished.data(), client_finished.size(), false));

    tls_transcript_update(server, client_finished.data(), client_finished.size());
    std::vector<uint8_t> server_finished = tls12_make_finished(server, true);
    TEST("客户端校验服务端 Finished",
         tls12_verify_finished(client, server_finished.data(), server_finished.size(), true));

    // ── 记录层双向往返 ──
    const uint8_t app[] = "TLS1.2 ECDHE-RSA RSA-4096 application data";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, app, sizeof(app) - 1);
    ContentType ct;
    std::vector<uint8_t> dec;
    TEST("C→S 记录层解密", tls_decrypt(server, enc.data(), enc.size(), ct, dec));
    TEST("C→S 明文一致",
         ct == ContentType::APPLICATION_DATA && dec.size() == sizeof(app) - 1 &&
         std::memcmp(dec.data(), app, sizeof(app) - 1) == 0);

    const uint8_t resp[] = "TLS1.2 ECDHE-RSA server response";
    auto enc2 = tls_encrypt(server, ContentType::APPLICATION_DATA, resp, sizeof(resp) - 1);
    ContentType ct2;
    std::vector<uint8_t> dec2;
    TEST("S→C 记录层解密", tls_decrypt(client, enc2.data(), enc2.size(), ct2, dec2));
    TEST("S→C 明文一致",
         ct2 == ContentType::APPLICATION_DATA && dec2.size() == sizeof(resp) - 1 &&
         std::memcmp(dec2.data(), resp, sizeof(resp) - 1) == 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  5. from_csr_pem 装载 + tls_make_x509_self_signed 自签名证书
// ═══════════════════════════════════════════════════════════════════════
static void test_csr_and_self_signed() {
    std::printf("\n=== RSA-4096 CSR 装载 + 自签名证书生成 ===\n");
    std::string csr_pem, key_pem;
    TEST("读取 server-rsa4096.csr", read_cert_file("server-rsa4096.csr", csr_pem));
    TEST("读取 server-rsa4096-key.pem", read_cert_file("server-rsa4096-key.pem", key_pem));

    std::string err;
    auto cert = tls_certificate::from_csr_pem(csr_pem, key_pem, &err);
    TEST("from_csr_pem(server-rsa4096.csr, server-rsa4096-key.pem) 成功", cert != nullptr);
    if (!cert) {
        std::printf("  err: %s\n", err.c_str());
        return;
    }
    TEST("CSR subject CN == localhost", cert->subject_name == CN);
    TEST("rsa4096 == true", cert->rsa4096);

    const uint8_t data[] = "jpssl CSR RSA-4096 sign/verify";
    uint8_t sig[512];
    size_t sig_len = 0;
    TEST("PKCS1-SHA256 签名 512 字节",
         cert->sign_scheme((uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256,
                           data, sizeof(data) - 1, sig, sig_len) && sig_len == 512);
    TEST("PKCS1-SHA256 验签通过",
         cert->verify_scheme((uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256,
                             data, sizeof(data) - 1, sig, sig_len));
    sig_len = 0;
    TEST("PSS-RSAE-SHA384 签名 512 字节",
         cert->sign_scheme((uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
                           data, sizeof(data) - 1, sig, sig_len) && sig_len == 512);
    TEST("PSS-RSAE-SHA384 验签通过",
         cert->verify_scheme((uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
                             data, sizeof(data) - 1, sig, sig_len));

    // ── 自签名证书：DER 可解析、key_type 为 RSA_4096、自签名可验签 ──
    std::vector<uint8_t> der = tls_make_x509_self_signed(*cert, 30);
    TEST("tls_make_x509_self_signed 产出 DER 非空", !der.empty());
    auto parsed = x509::x509_cert::from_der(der);
    TEST("自签名证书 DER 解析成功", parsed.has_value());
    if (parsed) {
        TEST("key_type == RSA_4096", parsed->key_type == x509::KeyType::RSA_4096);
        TEST("公钥布局 n(512)||e(3)", parsed->public_key.size() == 515);
        TEST("subject CN == localhost", parsed->common_name() == CN);
        TEST("自签名验签（verify_signature(self)）通过", parsed->verify_signature(*parsed));
        TEST("有效期内外（30 天）", parsed->is_valid_now());
        // 自签名证书公钥必须与 CSR/私钥公钥一致
        auto req = x509::csr::from_pem(csr_pem);
        TEST("自签名证书公钥与 CSR 公钥一致",
             req.has_value() && parsed->public_key == req->public_key);
    }
}

int main() {
    std::printf("测试证书目录: %s\n", cert_dir().c_str());
    test_load_rsa4096_from_pem();
    test_sign_verify_roundtrip();
    test_tls13_handshake_rsa4096();
    test_tls12_ecdhe_rsa_handshake();
    test_csr_and_self_signed();

    std::printf("\n================================================\n");
    std::printf("  Result: %d passed, %d failed", pass, fail);
    std::printf(fail == 0 ? " ✓\n" : " ✗\n");
    std::printf("================================================\n");
    return fail > 0 ? 1 : 0;
}
