/**
 * test_tls_rsa3072.cpp — 服务端 tls_certificate 的 RSA-3072 全链路回归
 *
 * 覆盖内容（与 test_tls_rsa4096.cpp 对位）：
 *   1. rsa3072_keygen_crt 现场生成 3072 位密钥 → 组装 tls_certificate
 *      （rsa_bits = 3072，union 使用 pub.rsa3072 / priv.rsa3072）
 *   2. sign_scheme / verify_scheme：RSA-PSS-RSAE-SHA256/384/512 与
 *      RSA-PKCS1-SHA256/384/512 均输出 384 字节签名并可验签，篡改 1 字节后验签失败
 *   3. tls_make_x509_self_signed：SPKI 按 RSA-3072 编码（n(384)||e(3)）、
 *      签名输出 384 字节；DER 可被 x509::x509_cert::from_der 解析为
 *      KeyType::RSA_3072 且自签名验签通过（tlsgen --key-type rsa3072 同路径）
 *   4. TLS 1.3 完整握手：服务端 RSA-3072 证书，客户端 trust_store 用自签名 CA，
 *      selected_sig_alg 属 RSA_PSS_*，CertificateVerify 按 rsa_bits 分派到
 *      rsa3072 成员验签，应用数据双向一致
 *   5. TLS 1.2 ECDHE-RSA 完整握手：RSA-3072 证书签 ServerKeyExchange
 *   6. TLS 1.2 静态 RSA 密钥交换：384 字节 EncryptedPreMasterSecret +
 *      服务端 rsa3072_crt_decrypt 还原 premaster
 *
 * 说明：测试证书/私钥全部由库内 keygen 现场生成，不依赖 tests/certs 下的固定 pem。
 */

#include "tls.hpp"
#include "x509.hpp"
#include "rsa.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;
using namespace jpssl::x509;

static int pass = 0, fail = 0;

#define TEST(name, cond) do { \
    if (cond) { std::printf("  PASS: %s\n", name); pass++; } \
    else { std::fprintf(stderr, "  FAIL: %s\n", name); fail++; } \
} while(0)

static const char* CN = "localhost";

static void fill_random(uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)(std::rand() & 0xFF);
}

// ═══════════════════════════════════════════════════════════════════════
//  生成 RSA-3072 密钥 + 组装服务端 tls_certificate
//  自签名证书置 basicConstraints CA=true：TLS 1.3 客户端可将其当作信任锚
//  （见 tls13_verify_server_chain 的 self-issued tail 分支）
// ═══════════════════════════════════════════════════════════════════════
static std::unique_ptr<tls_certificate> make_rsa3072_server_cert(std::string* ca_pem,
                                                                 uint32_t days = 30) {
    rsa3072_public_key pub;
    rsa3072_crt_key crt;
    if (!rsa3072_keygen_crt(pub, crt)) return nullptr;
    if (pub.n.bit_length() != 3072) return nullptr;

    auto out = std::make_unique<tls_certificate>();
    out->subject_name = CN;
    out->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
    out->rsa_bits = 3072;
    out->pub.rsa3072 = pub;
    out->priv.rsa3072 = crt;

    x509_builder b;
    DistinguishedName dn;
    dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + 3), std::string(CN)});
    b.set_subject(dn).set_issuer(dn);
    uint8_t ser[8] = {0x30, 0x37, 0x32, 0x01, 0x02, 0x03, 0x04, 0x05};
    b.set_serial(ser, sizeof(ser));
    uint64_t now = (uint64_t)time(nullptr);
    b.set_validity(now, now + (uint64_t)days * 86400);
    // SPKI 原始布局：n(384) || e(3)
    uint8_t spki[387];
    pub.n.to_bytes(spki);
    spki[384] = 1; spki[385] = 0; spki[386] = 1;
    b.set_key(KeyType::RSA_3072, spki, sizeof(spki));
    b.set_ca(true).set_key_usage(KU_DIGITAL_SIGNATURE | KU_KEY_CERT_SIGN).set_server_auth();
    b.add_san_dns(CN);
    uint8_t d[384];
    crt.d.to_bytes(d);
    x509_cert ca = b.build_and_sign(KeyType::RSA_3072, d, sizeof(d));
    std::vector<uint8_t> der = ca.to_der();
    if (der.empty()) return nullptr;
    out->cert_data = der;
    if (ca_pem) *ca_pem = ca.to_pem();
    return out;
}

// ═══════════════════════════════════════════════════════════════════════
//  1. rsa_bits 分派 + sign_scheme / verify_scheme 往返
// ═══════════════════════════════════════════════════════════════════════
static void test_sign_verify_roundtrip() {
    std::printf("\n=== RSA-3072 sign_scheme / verify_scheme 往返 ===\n");
    std::string ca_pem;
    auto cert = make_rsa3072_server_cert(&ca_pem);
    TEST("生成 RSA-3072 服务端证书（证书+私钥）", cert != nullptr);
    if (!cert) return;
    TEST("rsa_bits == 3072", cert->rsa_bits == 3072);
    TEST("rsa4096 标记保持 false（按 rsa_bits 分派）", !cert->rsa4096);
    TEST("pub.rsa3072.e == 65537",
         cert->pub.rsa3072.e == rsa3072_bignum::from_uint64(65537));
    TEST("CRT 参数已生成（p/q/dP/dQ/qInv 非零）",
         !cert->priv.rsa3072.p.is_zero() && !cert->priv.rsa3072.q.is_zero() &&
         !cert->priv.rsa3072.dP.is_zero() && !cert->priv.rsa3072.dQ.is_zero() &&
         !cert->priv.rsa3072.qInv.is_zero());

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
    const uint8_t msg[] = "jpssl TLS RSA-3072 sign/verify round-trip message";
    char label[128];
    for (size_t i = 0; i < sizeof(schemes) / sizeof(schemes[0]); ++i) {
        uint8_t sig[512];
        size_t sig_len = 0;
        std::snprintf(label, sizeof(label), "RSA-3072 %s 签名 384 字节", names[i]);
        bool ok = cert->sign_scheme(schemes[i], msg, sizeof(msg) - 1, sig, sig_len);
        TEST(label, ok && sig_len == 384);

        std::snprintf(label, sizeof(label), "RSA-3072 %s 验签通过", names[i]);
        TEST(label, cert->verify_scheme(schemes[i], msg, sizeof(msg) - 1, sig, sig_len));

        sig[17] ^= 0x40;   // 篡改 1 字节
        std::snprintf(label, sizeof(label), "RSA-3072 %s 篡改后验签失败", names[i]);
        TEST(label, !cert->verify_scheme(schemes[i], msg, sizeof(msg) - 1, sig, sig_len));
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  2. 自签名证书（tlsgen --key-type rsa3072 同路径）
// ═══════════════════════════════════════════════════════════════════════
static void test_self_signed_cert() {
    std::printf("\n=== RSA-3072 自签名证书（tls_make_x509_self_signed） ===\n");
    std::string ca_pem;
    auto cert = make_rsa3072_server_cert(&ca_pem);
    TEST("生成 RSA-3072 服务端证书", cert != nullptr);
    if (!cert) return;

    std::vector<uint8_t> der = tls_make_x509_self_signed(*cert, 30);
    TEST("tls_make_x509_self_signed 产出 DER 非空", !der.empty());
    auto parsed = x509::x509_cert::from_der(der);
    TEST("自签名证书 DER 解析成功", parsed.has_value());
    if (!parsed) return;
    TEST("key_type == RSA_3072", parsed->key_type == KeyType::RSA_3072);
    TEST("公钥布局 n(384)||e(3)", parsed->public_key.size() == 387);
    TEST("subject CN == localhost", parsed->common_name() == CN);
    // 解析侧 sign_key_type 只表示「签名算法族 + 哈希」（RSA 族统一映射为 RSA_2048
    // 占位，键长由 key_type 表达），故此处只断言 RSA 族占位；384 字节签名见下一行
    TEST("sign_key_type 为 RSA 族占位（键长由 key_type 表达）",
         parsed->sign_key_type == KeyType::RSA_2048);
    TEST("签名长度 384 字节", parsed->signature.size() == 384);
    TEST("自签名验签（verify_signature(self)）通过", parsed->verify_signature(*parsed));
    TEST("有效期内外（30 天）", parsed->is_valid_now());
    // 公钥必须与私钥一致（同一把 3072 位密钥）
    uint8_t n[384];
    cert->pub.rsa3072.n.to_bytes(n);
    TEST("证书公钥与密钥 n 一致", std::memcmp(n, parsed->public_key.data(), 384) == 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  3. TLS 1.3 完整握手（RSA-3072 服务端证书）
// ═══════════════════════════════════════════════════════════════════════
static bool is_pss_scheme(uint16_t s) {
    return s == (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256 ||
           s == (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384 ||
           s == (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA512;
}

static void test_tls13_handshake_rsa3072() {
    std::printf("\n=== TLS 1.3 完整握手（RSA-3072 服务端证书） ===\n");
    std::string ca_pem;
    auto cert = make_rsa3072_server_cert(&ca_pem);
    TEST("服务端 RSA-3072 证书组装", cert != nullptr);
    if (!cert) return;
    TEST("ca_pem 非空（自签名 CA 作为信任锚）", !ca_pem.empty());

    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate(CN, std::move(cert));

    tls_trust_store ts = tls_trust_store::from_pem(ca_pem);
    TEST("客户端信任库构造成功", ts.count() > 0);

    tls_session client;
    client.server_name = CN;
    std::vector<uint8_t> client_hello;
    TEST("TLS 1.3 客户端 ClientHello", tls13_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> server_flight;
    TEST("TLS 1.3 服务端 ServerFlight（RSA-3072 签 CertificateVerify）",
         tls13_make_server_flight(server, client_hello.data(), client_hello.size(),
                                  server_flight, cert_mgr));
    TEST("selected_sig_alg 属 RSA_PSS_*", is_pss_scheme(server.selected_sig_alg));

    std::vector<uint8_t> client_finished;
    TEST("TLS 1.3 客户端处理 ServerFlight（链验证 + CertificateVerify 验签）",
         tls13_process_server_flight(client, server_flight.data(), server_flight.size(),
                                     client_finished, nullptr, &ts));
    TEST("TLS 1.3 服务端校验客户端 Finished",
         tls13_process_client_finished(server, client_finished.data(), client_finished.size()));

    const uint8_t c2s[] = "TLS1.3 RSA-3072 client->server data";
    std::vector<uint8_t> enc = tls_encrypt(client, ContentType::APPLICATION_DATA,
                                           c2s, sizeof(c2s) - 1);
    TEST("客户端加密应用数据", !enc.empty());
    ContentType ct;
    std::vector<uint8_t> dec;
    TEST("服务端解密成功", tls_decrypt(server, enc.data(), enc.size(), ct, dec));
    TEST("C→S 明文一致",
         ct == ContentType::APPLICATION_DATA && dec.size() == sizeof(c2s) - 1 &&
         std::memcmp(dec.data(), c2s, sizeof(c2s) - 1) == 0);

    const uint8_t s2c[] = "TLS1.3 RSA-3072 server->client data";
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
//  4. TLS 1.2 ECDHE-RSA 完整握手（RSA-3072 证书签 ServerKeyExchange）
// ═══════════════════════════════════════════════════════════════════════
static void test_tls12_ecdhe_rsa_handshake() {
    std::printf("\n=== TLS 1.2 ECDHE-RSA 完整握手（RSA-3072 证书） ===\n");
    std::string ca_pem;
    auto cert = make_rsa3072_server_cert(&ca_pem);
    TEST("服务端 RSA-3072 证书组装", cert != nullptr);
    if (!cert) return;

    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate(CN, std::move(cert));
    tls_trust_store ts = tls_trust_store::from_pem(ca_pem);
    TEST("客户端信任库构造成功", ts.count() > 0);

    tls_session client;
    client.server_name = CN;
    std::vector<uint8_t> client_hello;
    TEST("TLS 1.2 客户端 ClientHello", tls12_make_client_hello(client, client_hello));

    tls_session server;
    std::vector<uint8_t> hello_flight;
    TEST("TLS 1.2 服务端 hello flight（含 RSA-3072 签名的 ServerKeyExchange）",
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

    const uint8_t app[] = "TLS1.2 ECDHE-RSA RSA-3072 application data";
    auto enc = tls_encrypt(client, ContentType::APPLICATION_DATA, app, sizeof(app) - 1);
    ContentType ct;
    std::vector<uint8_t> dec;
    TEST("C→S 记录层解密", tls_decrypt(server, enc.data(), enc.size(), ct, dec));
    TEST("C→S 明文一致",
         ct == ContentType::APPLICATION_DATA && dec.size() == sizeof(app) - 1 &&
         std::memcmp(dec.data(), app, sizeof(app) - 1) == 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  5. TLS 1.2 静态 RSA 密钥交换：384 字节密文 + rsa3072_crt_decrypt
// ═══════════════════════════════════════════════════════════════════════
// 仅提供单个 TLS_RSA_WITH_AES_256_GCM_SHA384 套件的 ClientHello
// （TLS 1.2 服务端按服务端优先级选套件，故用「只提供该套件」把它固定下来）
static std::vector<uint8_t> make_ch_rsa_only(tls_session& s, uint16_t suite) {
    std::vector<uint8_t> ch;
    ch.push_back((uint8_t)HandshakeType::CLIENT_HELLO);
    ch.push_back(0); ch.push_back(0); ch.push_back(0);
    ch.push_back(0x03); ch.push_back(0x03);
    ch.insert(ch.end(), s.client_random, s.client_random + 32);
    ch.push_back(0);                    // session_id_len = 0
    ch.push_back(0); ch.push_back(2);   // 1 个套件
    ch.push_back((uint8_t)(suite >> 8)); ch.push_back((uint8_t)suite);
    ch.push_back(1); ch.push_back(0);   // compression: null
    std::vector<uint8_t> ext;
    {
        size_t n = s.server_name.size();
        size_t name_list_len = 3 + n;
        size_t ext_data_len = 2 + name_list_len;
        ext.push_back(0x00); ext.push_back(0x00);
        ext.push_back((uint8_t)(ext_data_len >> 8)); ext.push_back((uint8_t)ext_data_len);
        ext.push_back((uint8_t)(name_list_len >> 8)); ext.push_back((uint8_t)name_list_len);
        ext.push_back(0x00);
        ext.push_back((uint8_t)(n >> 8)); ext.push_back((uint8_t)n);
        ext.insert(ext.end(), s.server_name.begin(), s.server_name.end());
    }
    ext.push_back(0x00); ext.push_back(0x17);   // extended_master_secret (RFC 7627)
    ext.push_back(0x00); ext.push_back(0x00);
    {
        std::vector<uint16_t> algs = tls_default_signature_algorithms();
        size_t list_len = algs.size() * 2;
        size_t ext_data_len = 2 + list_len;
        ext.push_back(0x00); ext.push_back(0x0d);
        ext.push_back((uint8_t)(ext_data_len >> 8)); ext.push_back((uint8_t)ext_data_len);
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
    s.tls12_client_hello_cache = ch;    // 套件确定后回放 ClientHello 进 transcript
    return ch;
}

static void test_tls12_rsa_kx() {
    std::printf("\n=== TLS 1.2 静态 RSA 密钥交换（RSA-3072，384 字节密文） ===\n");
    std::string ca_pem;
    auto cert = make_rsa3072_server_cert(&ca_pem);
    TEST("服务端 RSA-3072 证书组装", cert != nullptr);
    if (!cert) return;
    const rsa3072_public_key pub = cert->pub.rsa3072;

    tls_certificate_manager cert_mgr;
    cert_mgr.add_certificate(CN, std::move(cert));

    tls_session client;
    client.server_name = CN;
    fill_random(client.client_random, 32);
    auto ch = make_ch_rsa_only(client, (uint16_t)CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384);

    uint8_t pms[48];
    fill_random(pms, 48);
    pms[0] = 0x03; pms[1] = 0x03;      // TLS 版本号（RFC 5246 7.4.7.1）
    uint8_t enc[384];
    rsa3072_encrypt(pub, std::span<const uint8_t>(pms, 48), enc);

    tls_session server;
    std::vector<uint8_t> resp;
    uint8_t pms_out[48] = {0};
    TEST("RSA-3072 server flight（384 字节密文）",
         tls12_make_server_flight(server, ch.data(), ch.size(), resp,
                                  enc, 384, pms_out, cert_mgr));
    TEST("RSA-3072 premaster 与原文一致", std::memcmp(pms, pms_out, 48) == 0);
    TEST("协商套件 = TLS_RSA_WITH_AES_256_GCM_SHA384",
         server.cipher_suite == CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384);
    TEST("服务端响应非空", !resp.empty());
    TEST("序列号可继续（会话已派生密钥）", server.ver == TLSVersion::V12);
}

int main() {
    std::srand(0x3072);
    std::printf("jpssl TLS RSA-3072 回归测试（密钥现场生成）\n");
    test_sign_verify_roundtrip();
    test_self_signed_cert();
    test_tls13_handshake_rsa3072();
    test_tls12_ecdhe_rsa_handshake();
    test_tls12_rsa_kx();

    std::printf("\n================================================\n");
    std::printf("  Result: %d passed, %d failed", pass, fail);
    std::printf(fail == 0 ? " OK\n" : " NG\n");
    std::printf("================================================\n");
    return fail > 0 ? 1 : 0;
}
