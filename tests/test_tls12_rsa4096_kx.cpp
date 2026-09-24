/**
 * test_tls12_rsa4096_kx.cpp — TLS 1.2 静态 RSA（RSA 密钥交换）套件的 RSA-4096 支持
 *
 * 覆盖内容：
 *   1. tls12_make_server_flight（旧版简化 API）：RSA-4096 证书 512 字节
 *      EncryptedPreMasterSecret 解密正确（premaster 与原文一致、ver=V12、
 *      响应非空、套件协商为 TLS_RSA_WITH_AES_256_GCM_SHA384=0x009D）；
 *      同用例回归 RSA-2048 仍走 256 字节密文。
 *   2. tls12_make_server_hello_flight + tls12_process_client_key_exchange：
 *      服务端按证书类型缓存 CRT 私钥（s.rsa4096_key），客户端生成
 *      2+512=514 字节 ClientKeyExchange，双方主密钥一致、Finished 校验通过。
 *   3. 端到端 TLS 1.2 静态 RSA 握手（RSA-4096 证书，套件固定 0x009D）+
 *      应用数据双向记录层（tls_encrypt/tls_decrypt）往返。
 *   4. RSA-2048 静态 RSA 端到端握手回归。
 *
 * 证书装载说明：基线 429447a 的 tls_router 装载路径
 * （tls_certificate::from_pem_file）尚未支持 RSA-4096（由并行任务负责），
 * 因此本测试用 x509::x509_cert::from_pem + x509::private_key::from_pem
 * 解析 PEM 后手工组装 tls_certificate（rsa4096=true，pub/priv 使用 union
 * 的 rsa4096 成员，CRT 参数右对齐 256 字节）；
 * tls_router 装载路径就绪后可改用 tls_certificate::from_pem_file。
 *
 * 测试证书：tests/certs/tls/server-rsa4096.pem / server-rsa4096-key.pem
 *           tests/certs/tls/server-rsa.pem     / server-rsa-key.pem
 */

#include "tls.hpp"
#include "rsa.hpp"
#include "x509.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

static int pass = 0, fail = 0;

#define TEST(name, cond) do { \
    if (cond) { std::printf("  PASS: %s\n", name); pass++; } \
    else { std::fprintf(stderr, "  FAIL: %s\n", name); fail++; } \
} while(0)

// 静态 RSA 套件：TLS_RSA_WITH_AES_256_GCM_SHA384 (RFC 5288)
static const uint16_t kSuiteRsaAes256GcmSha384 = 0x009D;
static const CipherSuite kSuiteRsaAes256GcmSha384Enum =
    CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384;

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

static bool read_file_content(const std::string& path, std::string& out) {
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
    return read_file_content(cert_dir() + "/" + name, out);
}

static void fill_random(uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)(std::rand() & 0xFF);
}

// ═══════════════════════════════════════════════════════════════════════
//  PEM → tls_certificate 手工组装
//    RSA-2048 → pub.rsa / priv.rsa（rsa4096 = false）
//    RSA-4096 → pub.rsa4096 / priv.rsa4096（rsa4096 = true）
// ═══════════════════════════════════════════════════════════════════════
static std::unique_ptr<tls_certificate> load_cert_pair(const char* cert_file,
                                                       const char* key_file) {
    std::string cert_pem, key_pem;
    if (!read_cert_file(cert_file, cert_pem) || !read_cert_file(key_file, key_pem))
        return nullptr;
    auto cert = x509::x509_cert::from_pem(cert_pem);
    auto key = x509::private_key::from_pem(key_pem);
    if (!cert || !key) return nullptr;
    if (!cert->public_key.empty() && cert->public_key != key->pub) return nullptr;

    auto out = std::make_unique<tls_certificate>();
    out->subject_name = cert->common_name();
    // 静态 RSA 套件的 premaster 解密分派依赖该 sig_alg（服务端解密分支条件）
    out->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
    out->cert_data = cert->to_der();   // Certificate 消息直接使用证书 DER

    if (cert->key_type == x509::KeyType::RSA_4096) {
        if (cert->public_key.size() < 515 || key->priv.size() < 512 || key->pub.size() < 515)
            return nullptr;
        // CRT 参数由 PKCS#8 私钥解析器右对齐到 dsz/2 = 256 字节
        if (key->rsa_p.size() != 256 || key->rsa_q.size() != 256 ||
            key->rsa_dP.size() != 256 || key->rsa_dQ.size() != 256 ||
            key->rsa_qInv.size() != 256)
            return nullptr;
        out->rsa4096 = true;
        out->pub.rsa4096.n = rsa4096_bignum::from_bytes(cert->public_key.data(), 512);
        out->pub.rsa4096.e = rsa4096_bignum::from_bytes(cert->public_key.data() + 512, 3);
        out->priv.rsa4096.n = rsa4096_bignum::from_bytes(key->pub.data(), 512);
        out->priv.rsa4096.e = rsa4096_bignum::from_bytes(key->pub.data() + 512, 3);
        out->priv.rsa4096.d = rsa4096_bignum::from_bytes(key->priv.data(), 512);
        out->priv.rsa4096.p = rsa4096_bignum::from_bytes(key->rsa_p.data(), 256);
        out->priv.rsa4096.q = rsa4096_bignum::from_bytes(key->rsa_q.data(), 256);
        out->priv.rsa4096.dP = rsa4096_bignum::from_bytes(key->rsa_dP.data(), 256);
        out->priv.rsa4096.dQ = rsa4096_bignum::from_bytes(key->rsa_dQ.data(), 256);
        out->priv.rsa4096.qInv = rsa4096_bignum::from_bytes(key->rsa_qInv.data(), 256);
    } else if (cert->key_type == x509::KeyType::RSA_2048) {
        if (cert->public_key.size() < 259 || key->priv.size() < 256 || key->pub.size() < 259)
            return nullptr;
        if (key->rsa_p.size() != 128 || key->rsa_q.size() != 128 ||
            key->rsa_dP.size() != 128 || key->rsa_dQ.size() != 128 ||
            key->rsa_qInv.size() != 128)
            return nullptr;
        out->rsa4096 = false;
        out->pub.rsa.n = rsa_bignum::from_bytes(cert->public_key.data(), 256);
        out->pub.rsa.e = rsa_bignum::from_bytes(cert->public_key.data() + 256, 3);
        out->priv.rsa.n = rsa_bignum::from_bytes(key->pub.data(), 256);
        out->priv.rsa.e = rsa_bignum::from_bytes(key->pub.data() + 256, 3);
        out->priv.rsa.d = rsa_bignum::from_bytes(key->priv.data(), 256);
        out->priv.rsa.p = rsa_bignum::from_bytes(key->rsa_p.data(), 128);
        out->priv.rsa.q = rsa_bignum::from_bytes(key->rsa_q.data(), 128);
        out->priv.rsa.dP = rsa_bignum::from_bytes(key->rsa_dP.data(), 128);
        out->priv.rsa.dQ = rsa_bignum::from_bytes(key->rsa_dQ.data(), 128);
        out->priv.rsa.qInv = rsa_bignum::from_bytes(key->rsa_qInv.data(), 128);
    } else {
        return nullptr;
    }
    return out;
}

// ═══════════════════════════════════════════════════════════════════════
//  仅提供单个 TLS 1.2 套件的 ClientHello（SNI + EMS + signature_algorithms）
//  TLS 1.2 服务端套件选择按服务端优先级（tls12_select_server_suite）而
//  不读取 cipher_suite_pinned（该标记仅 TLS 1.3 生效），因此定向测试通过
//  「只提供 0x009D」把静态 RSA 套件固定下来。
// ═══════════════════════════════════════════════════════════════════════
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
    if (!s.server_name.empty()) {       // server_name (SNI)
        size_t n = s.server_name.size();
        size_t name_list_len = 3 + n;
        size_t ext_data_len = 2 + name_list_len;
        ext.push_back(0x00); ext.push_back(0x00);
        ext.push_back((uint8_t)(ext_data_len >> 8)); ext.push_back((uint8_t)ext_data_len);
        ext.push_back((uint8_t)(name_list_len >> 8)); ext.push_back((uint8_t)name_list_len);
        ext.push_back(0x00);            // NameType: host_name
        ext.push_back((uint8_t)(n >> 8)); ext.push_back((uint8_t)n);
        ext.insert(ext.end(), s.server_name.begin(), s.server_name.end());
    }
    // extended_master_secret (RFC 7627)：空扩展（与 tls12_make_client_hello 一致）
    ext.push_back(0x00); ext.push_back(0x17);
    ext.push_back(0x00); ext.push_back(0x00);
    // signature_algorithms (RFC 5246 7.4.1.4.1)
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

// ═══════════════════════════════════════════════════════════════════════
//  用例 1：tls12_make_server_flight（旧版简化 API）RSA-4096 / RSA-2048
// ═══════════════════════════════════════════════════════════════════════
static void test_server_flight_rsa4096_kx() {
    std::printf("\n=== 用例 1: tls12_make_server_flight 静态 RSA 预主密钥解密 ===\n");

    // ── RSA-4096：512 字节密文 ──
    auto cert4096 = load_cert_pair("server-rsa4096.pem", "server-rsa4096-key.pem");
    TEST("组装 RSA-4096 tls_certificate", cert4096 != nullptr);
    if (!cert4096) return;
    TEST("rsa4096 标记置位", cert4096->rsa4096);
    TEST("公钥 n||e 布局（512+3）", cert4096->pub.rsa4096.e == rsa4096_bignum::from_uint64(65537));
    const rsa4096_public_key pub4096 = cert4096->pub.rsa4096;

    tls_certificate_manager mgr4096;
    mgr4096.add_certificate("localhost", std::move(cert4096));

    tls_session client4096;
    client4096.server_name = "localhost";
    fill_random(client4096.client_random, 32);
    auto ch4096 = make_ch_rsa_only(client4096, kSuiteRsaAes256GcmSha384);

    uint8_t pms[48];
    fill_random(pms, 48);
    pms[0] = 0x03; pms[1] = 0x03;      // TLS 版本号（RFC 5246 7.4.7.1）
    uint8_t enc4096[512];
    rsa4096_encrypt(pub4096, std::span<const uint8_t>(pms, 48), enc4096);

    tls_session server4096;
    std::vector<uint8_t> resp4096;
    uint8_t pms_out[48] = {0};
    TEST("RSA-4096 server flight（512 字节密文）",
         tls12_make_server_flight(server4096, ch4096.data(), ch4096.size(), resp4096,
                                  enc4096, 512, pms_out, mgr4096));
    TEST("RSA-4096 premaster 与原文一致", std::memcmp(pms, pms_out, 48) == 0);
    TEST("server.ver == TLSVersion::V12", server4096.ver == TLSVersion::V12);
    TEST("服务端响应非空", !resp4096.empty());
    TEST("协商套件 = TLS_RSA_WITH_AES_256_GCM_SHA384",
         server4096.cipher_suite == kSuiteRsaAes256GcmSha384Enum);

    // ── RSA-2048 回归：256 字节密文 ──
    auto cert2048 = load_cert_pair("server-rsa.pem", "server-rsa-key.pem");
    TEST("组装 RSA-2048 tls_certificate", cert2048 != nullptr);
    if (!cert2048) return;
    TEST("rsa4096 标记未置位（RSA-2048）", !cert2048->rsa4096);
    const rsa_public_key pub2048 = cert2048->pub.rsa;

    tls_certificate_manager mgr2048;
    mgr2048.add_certificate("localhost", std::move(cert2048));

    tls_session client2048;
    client2048.server_name = "localhost";
    fill_random(client2048.client_random, 32);
    auto ch2048 = make_ch_rsa_only(client2048, kSuiteRsaAes256GcmSha384);

    uint8_t pms2048[48];
    fill_random(pms2048, 48);
    pms2048[0] = 0x03; pms2048[1] = 0x03;
    uint8_t enc2048[256];
    rsa_encrypt(pub2048, std::span<const uint8_t>(pms2048, 48), enc2048);

    tls_session server2048;
    std::vector<uint8_t> resp2048;
    uint8_t pms_out2048[48] = {0};
    TEST("RSA-2048 server flight（256 字节密文）",
         tls12_make_server_flight(server2048, ch2048.data(), ch2048.size(), resp2048,
                                  enc2048, 256, pms_out2048, mgr2048));
    TEST("RSA-2048 premaster 与原文一致", std::memcmp(pms2048, pms_out2048, 48) == 0);
    TEST("RSA-2048 响应非空", !resp2048.empty());
}

// ═══════════════════════════════════════════════════════════════════════
//  用例 2：server_hello_flight + process_client_key_exchange（s.rsa4096_key）
// ═══════════════════════════════════════════════════════════════════════
static void test_cke_rsa4096_kx() {
    std::printf("\n=== 用例 2: hello flight + ClientKeyExchange（s.rsa4096_key 缓存）===\n");

    auto cert = load_cert_pair("server-rsa4096.pem", "server-rsa4096-key.pem");
    TEST("组装 RSA-4096 tls_certificate", cert != nullptr);
    if (!cert) return;
    tls_certificate_manager mgr;
    mgr.add_certificate("localhost", std::move(cert));

    tls_session client;
    client.server_name = "localhost";
    fill_random(client.client_random, 32);
    auto ch = make_ch_rsa_only(client, kSuiteRsaAes256GcmSha384);

    tls_session server;
    std::vector<uint8_t> hello_flight;
    TEST("RSA-4096 server hello flight",
         tls12_make_server_hello_flight(server, ch.data(), ch.size(), hello_flight, mgr));
    TEST("协商套件 = TLS_RSA_WITH_AES_256_GCM_SHA384",
         server.cipher_suite == kSuiteRsaAes256GcmSha384Enum);
    TEST("服务端缓存 RSA-4096 私钥 s.rsa4096_key", (bool)server.rsa4096_key);
    TEST("RSA-2048 私钥缓存未被使用", !server.rsa_key);

    uint8_t pms[48];
    fill_random(pms, 48);
    pms[0] = 0x03; pms[1] = 0x03;
    std::vector<uint8_t> cke, client_finished;
    TEST("客户端生成 ClientKeyExchange",
         tls12_process_server_flight(client, hello_flight.data(), hello_flight.size(),
                                     pms, 48, client_finished, &cke, &mgr));
    TEST("ClientKeyExchange 体长 = 2 + 512", cke.size() == 4 + 514);

    // 服务端：CKE 入 transcript 后按 s.rsa4096_key 做 512 字节 CRT 解密
    tls_transcript_update(server, cke.data(), cke.size());
    std::vector<uint8_t> server_ccs_finished;
    TEST("服务端解密 ClientKeyExchange",
         tls12_process_client_key_exchange(server, cke.data() + 4, cke.size() - 4,
                                           server_ccs_finished));
    TEST("主密钥一致（premaster 解密正确）",
         std::memcmp(client.master_secret, server.master_secret, 48) == 0);
    TEST("服务端校验客户端 Finished",
         tls12_verify_finished(server, client_finished.data(), client_finished.size(), false));
}

// ═══════════════════════════════════════════════════════════════════════
//  用例 3 / 4：端到端静态 RSA 握手 + 应用数据双向往返
// ═══════════════════════════════════════════════════════════════════════
static void run_static_rsa_e2e(const char* cert_file, const char* key_file,
                               bool expect4096, const char* label) {
    std::string tag = std::string(label) + ": ";

    auto cert = load_cert_pair(cert_file, key_file);
    TEST((tag + "组装 tls_certificate").c_str(), cert != nullptr);
    if (!cert) return;
    TEST((tag + "rsa4096 标记与预期一致").c_str(), cert->rsa4096 == expect4096);
    tls_certificate_manager mgr;
    mgr.add_certificate("localhost", std::move(cert));

    // 客户端 / 服务端均固定套件为 0x009D（cipher_suite_pinned 记录用户意图；
    // TLS 1.2 服务端套件选择不读取该标记，故 ClientHello 亦只提供该套件）
    tls_session client;
    client.server_name = "localhost";
    client.cipher_suite = kSuiteRsaAes256GcmSha384Enum;
    client.cipher_suite_pinned = true;
    fill_random(client.client_random, 32);
    auto ch = make_ch_rsa_only(client, kSuiteRsaAes256GcmSha384);

    tls_session server;
    server.cipher_suite = kSuiteRsaAes256GcmSha384Enum;
    server.cipher_suite_pinned = true;
    std::vector<uint8_t> hello_flight;
    TEST((tag + "server hello flight").c_str(),
         tls12_make_server_hello_flight(server, ch.data(), ch.size(), hello_flight, mgr));
    TEST((tag + "协商套件 = 0x009D").c_str(),
         server.cipher_suite == kSuiteRsaAes256GcmSha384Enum);

    uint8_t pms[48];
    fill_random(pms, 48);
    pms[0] = 0x03; pms[1] = 0x03;
    std::vector<uint8_t> cke, client_finished;
    TEST((tag + "客户端处理服务端 flight").c_str(),
         tls12_process_server_flight(client, hello_flight.data(), hello_flight.size(),
                                     pms, 48, client_finished, &cke, &mgr));
    TEST((tag + (expect4096 ? "ClientKeyExchange 体长 = 514" : "ClientKeyExchange 体长 = 258")).c_str(),
         cke.size() == 4 + (expect4096 ? 514u : 258u));

    tls_transcript_update(server, cke.data(), cke.size());
    std::vector<uint8_t> dummy;
    TEST((tag + "服务端处理 ClientKeyExchange").c_str(),
         tls12_process_client_key_exchange(server, cke.data() + 4, cke.size() - 4, dummy));
    TEST((tag + "主密钥一致").c_str(),
         std::memcmp(client.master_secret, server.master_secret, 48) == 0);
    TEST((tag + "服务端校验客户端 Finished").c_str(),
         tls12_verify_finished(server, client_finished.data(), client_finished.size(), false));

    tls_transcript_update(server, client_finished.data(), client_finished.size());
    std::vector<uint8_t> server_finished = tls12_make_finished(server, /*for_server=*/true);
    TEST((tag + "客户端校验服务端 Finished").c_str(),
         tls12_verify_finished(client, server_finished.data(), server_finished.size(), true));

    // 应用数据双向记录层往返
    const uint8_t app_c2s[] = "TLS1.2 static RSA client->server";
    auto enc_c2s = tls_encrypt(client, ContentType::APPLICATION_DATA,
                               app_c2s, sizeof(app_c2s) - 1);
    ContentType ct_c2s = ContentType::HANDSHAKE;
    std::vector<uint8_t> dec_c2s;
    TEST((tag + "应用数据 客户端→服务端").c_str(),
         !enc_c2s.empty() &&
         tls_decrypt(server, enc_c2s.data(), enc_c2s.size(), ct_c2s, dec_c2s) &&
         ct_c2s == ContentType::APPLICATION_DATA &&
         dec_c2s.size() == sizeof(app_c2s) - 1 &&
         std::memcmp(dec_c2s.data(), app_c2s, dec_c2s.size()) == 0);

    const uint8_t app_s2c[] = "TLS1.2 static RSA server->client";
    auto enc_s2c = tls_encrypt(server, ContentType::APPLICATION_DATA,
                               app_s2c, sizeof(app_s2c) - 1);
    ContentType ct_s2c = ContentType::HANDSHAKE;
    std::vector<uint8_t> dec_s2c;
    TEST((tag + "应用数据 服务端→客户端").c_str(),
         !enc_s2c.empty() &&
         tls_decrypt(client, enc_s2c.data(), enc_s2c.size(), ct_s2c, dec_s2c) &&
         ct_s2c == ContentType::APPLICATION_DATA &&
         dec_s2c.size() == sizeof(app_s2c) - 1 &&
         std::memcmp(dec_s2c.data(), app_s2c, dec_s2c.size()) == 0);
}

int main() {
    std::printf("测试证书目录: %s\n", cert_dir().c_str());
    test_server_flight_rsa4096_kx();
    test_cke_rsa4096_kx();
    std::printf("\n=== 用例 3: RSA-4096 静态 RSA 端到端握手 ===\n");
    run_static_rsa_e2e("server-rsa4096.pem", "server-rsa4096-key.pem",
                       /*expect4096=*/true, "RSA-4096");
    std::printf("\n=== 用例 4: RSA-2048 静态 RSA 端到端握手回归 ===\n");
    run_static_rsa_e2e("server-rsa.pem", "server-rsa-key.pem",
                       /*expect4096=*/false, "RSA-2048");

    std::printf("\n================================================\n");
    std::printf("  Result: %d passed, %d failed", pass, fail);
    std::printf(fail == 0 ? " ✓\n" : " ✗\n");
    std::printf("================================================\n");
    return fail > 0 ? 1 : 0;
}
