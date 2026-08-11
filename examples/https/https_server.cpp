/**
 * https_server.cpp -- HTTPS 服务器 + 内嵌国际标准 CT 日志示例
 *
 * 启动：https_server <port>
 *
 * 流程：
 *   1. 生成 ECDSA P-256 CA 与服务器证书；
 *   2. 构造带 poison 扩展的预证书，提交给内存 CT 日志（SHA-256 + ECDSA, RFC 6962）；
 *   3. 用返回的 SCT 通过 finalize_precert 生成带 SCT list 扩展的最终证书；
 *   4. 通过 tls_listener 提供 TLS 1.3 HTTPS 服务：
 *        GET /                  -> 首页（展示证书与 SCT）
 *        GET /ct/ca             -> CA 根证书（base64 DER）
 *        GET /ct/cert           -> 服务器证书（base64 DER）
 *        GET /ct/log-key        -> 日志公钥与算法（JSON）
 *        GET /ct/sth            -> 当前 STH（JSON）
 *        GET /ct/proof?leaf=<hex>&tree=<n> -> 审计路径（JSON）
 */
#include "ct_https_common.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include "jpssl_memory.hpp"
#include <string>
#include <vector>

using namespace jpssl;
using namespace jpssl::ct;
using namespace jpssl::tls;
using namespace jpssl::x509;
using jpssl_https::hex_encode;
using jpssl_https::http_404;
using jpssl_https::http_respond;
using jpssl_https::read_http_request;
using jpssl_https::request_path;

// ============================================================================
// 证书 / 日志初始化
// ============================================================================

struct server_state {
    std::unique_ptr<ct_log> log;      // 国际标准 CT 日志（SHA-256 + ECDSA）
    std::vector<uint8_t> ca_der;      // CA 根证书 DER
    std::vector<uint8_t> precert_der; // 预证书 DER（带 poison，供客户端重建 PreCert）
    std::vector<uint8_t> final_der;   // 带 SCT 的服务器证书 DER
    uint8_t log_pub[64] = {};
    uint8_t leaf_pub[64] = {};
    uint8_t leaf_priv[32] = {};
};

static std::vector<RawExtension> poison_extension() {
    return {RawExtension{
        std::vector<uint8_t>(std::begin(OID_CT_POISON), std::end(OID_CT_POISON)),
        true, {0x05, 0x00}}};
}

static x509_cert make_ec_cert(const DistinguishedName& subject, const DistinguishedName& issuer,
                              const uint8_t* pub, bool is_ca, const uint8_t* sign_priv,
                              uint64_t now, const std::vector<RawExtension>& raw_exts = {}) {
    x509_builder b;
    b.set_subject(subject).set_issuer(issuer);
    uint8_t serial[8] = {0x51, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    b.set_serial(serial, 8);
    b.set_validity(now - 86400, now + 3650 * 86400);
    b.set_key(KeyType::ECDSA_P256, pub, 64);
    b.set_ca(is_ca, is_ca ? 0 : -1);
    b.set_key_usage(is_ca ? KU_KEY_CERT_SIGN : KU_DIGITAL_SIGNATURE);
    b.cert.raw_extensions = raw_exts;
    return b.build_and_sign(KeyType::ECDSA_P256, sign_priv, 32);
}

static server_state setup_state() {
    server_state st;
    uint8_t log_priv[32];
    ecdsa_p256_keygen(st.log_pub, log_priv);
    uint8_t ca_priv[32], ca_pub[64];
    ecdsa_p256_keygen(ca_pub, ca_priv);
    ecdsa_p256_keygen(st.leaf_pub, st.leaf_priv);

    uint64_t now = (uint64_t)time(nullptr);
    DistinguishedName ca_dn;
    ca_dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + sizeof(OID_CN)), "Example CT Root CA"});
    DistinguishedName leaf_dn;
    leaf_dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + sizeof(OID_CN)), "localhost"});

    auto ca_cert = make_ec_cert(ca_dn, ca_dn, ca_pub, true, ca_priv, now);
    st.ca_der = ca_cert.to_der();
    auto precert = make_ec_cert(leaf_dn, ca_dn, st.leaf_pub, false, ca_priv, now,
                                poison_extension());
    st.precert_der = precert.to_der();

    // 内存国际 CT 日志：接受 CA 根，记录预证书
    st.log = jpssl::make_unique<ct_log>(CtHashAlg::SHA256, CtSigAlg::ECDSA_P256,
                                      log_priv, st.log_pub);
    st.log->accept_root(st.ca_der);
    std::string err;
    auto sct = st.log->add_pre_chain({st.precert_der, st.ca_der}, &err);
    if (!sct) {
        std::fprintf(stderr, "add-pre-chain failed: %s\n", err.c_str());
        std::exit(1);
    }

    // 最终证书：去掉 poison，嵌入 SCT list，CA 重新签名
    auto final_cert = finalize_precert(precert, {*sct}, KeyType::ECDSA_P256, ca_priv, 32);
    st.final_der = final_cert.to_der();
    return st;
}

// ============================================================================
// HTTP 端点
// ============================================================================

static std::string sth_json(const signed_tree_head& sth) {
    return "{\"version\":" + std::to_string(sth.version) +
           ",\"timestamp\":" + std::to_string(sth.timestamp) +
           ",\"tree_size\":" + std::to_string(sth.tree_size) +
           ",\"root_hash\":\"" + hex_encode(sth.root_hash.data(), sth.root_hash.size()) + "\"" +
           ",\"hash_alg\":" + std::to_string(sth.hash_algorithm) +
           ",\"sig_alg\":" + std::to_string(sth.signature_algorithm) +
           ",\"signature\":\"" + hex_encode(sth.signature.data(), sth.signature.size()) + "\"}";
}

static std::string index_html(const server_state& st) {
    auto scts = scts_from_cert(st.final_der);
    std::string sct_line = "no SCT found";
    if (scts && !scts->empty()) {
        const auto& s = (*scts)[0];
        sct_line = "log_id=" + hex_encode(s.log_id.data(), s.log_id.size()) +
                   " timestamp=" + std::to_string(s.timestamp) +
                   " hash_alg=" + std::to_string(s.hash_algorithm) +
                   " sig_alg=" + std::to_string(s.signature_algorithm);
    }
    std::string body =
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>jpssl HTTPS + CT</title></head>"
        "<body><h1>jpssl HTTPS server with Certificate Transparency</h1>"
        "<p>This TLS 1.3 connection is encrypted by jpssl.</p>"
        "<p>The server certificate carries a Signed Certificate Timestamp (SCT):</p>"
        "<pre>" + sct_line + "</pre>"
        "<p>CT log endpoints:</p><ul>"
        "<li><a href=\"/ct/sth\">/ct/sth</a> - signed tree head</li>"
        "<li><a href=\"/ct/cert\">/ct/cert</a> - server certificate (base64)</li>"
        "<li><a href=\"/ct/precert\">/ct/precert</a> - precertificate (base64)</li>"
        "<li><a href=\"/ct/ca\">/ct/ca</a> - CA root (base64)</li>"
        "<li><a href=\"/ct/log-key\">/ct/log-key</a> - log public key</li>"
        "<li><a href=\"/ct/proof\">/ct/proof?leaf=...</a> - inclusion proof</li>"
        "</ul></body></html>";
    return body;
}

static std::string handle_request(const server_state& st, const std::string& path) {
    if (path == "/" || path == "/index.html") {
        return http_respond("text/html; charset=utf-8", index_html(st));
    }
    if (path == "/ct/ca") {
        return http_respond("text/plain", jpssl::base64_encode(st.ca_der));
    }
    if (path == "/ct/cert") {
        return http_respond("text/plain", jpssl::base64_encode(st.final_der));
    }
    if (path == "/ct/precert") {
        return http_respond("text/plain", jpssl::base64_encode(st.precert_der));
    }
    if (path == "/ct/log-key") {
        std::string body = "{\"hash_alg\":" + std::to_string(CT_HASH_ALG_SHA256) +
                           ",\"sig_alg\":" + std::to_string(CT_SIG_ALG_ECDSA) +
                           ",\"pub\":\"" + hex_encode(st.log_pub, 64) + "\"}";
        return http_respond("application/json", body);
    }
    if (path == "/ct/sth") {
        auto sth = st.log->get_sth();
        return http_respond("application/json", sth_json(sth));
    }
    if (path.rfind("/ct/proof", 0) == 0) {
        // /ct/proof?leaf=<hex>&tree=<n>
        size_t q = path.find('?');
        std::string leaf_hex, tree_s;
        if (q != std::string::npos) {
            std::string query = path.substr(q + 1);
            size_t p0 = query.find("leaf=");
            size_t p1 = query.find("tree=");
            if (p0 != std::string::npos) {
                size_t e = query.find('&', p0);
                leaf_hex = query.substr(p0 + 5, e == std::string::npos ? std::string::npos : e - p0 - 5);
            }
            if (p1 != std::string::npos) tree_s = query.substr(p1 + 5);
        }
        std::vector<uint8_t> leaf;
        uint64_t tree = (uint64_t)std::strtoull(tree_s.c_str(), nullptr, 10);
        if (leaf_hex.empty() || !jpssl_https::hex_decode(leaf_hex, leaf) ||
            leaf.size() != 32 || tree == 0) {
            return http_respond("application/json",
                                "{\"error\":\"bad leaf/tree params\"}");
        }
        node_hash lh{};
        std::memcpy(lh.data(), leaf.data(), 32);
        uint64_t idx = 0;
        std::vector<node_hash> pathv;
        std::string body;
        if (st.log->get_proof_by_hash(lh, tree, &idx, &pathv)) {
            auto sth = st.log->get_sth();
            body = "{\"leaf_index\":" + std::to_string(idx) + ",\"audit_path\":[";
            for (size_t i = 0; i < pathv.size(); ++i) {
                if (i) body += ",";
                body += "\"" + hex_encode(pathv[i].data(), pathv[i].size()) + "\"";
            }
            body += "],\"sth\":" + sth_json(sth) + "}";
        } else {
            body = "{\"error\":\"leaf not found in tree\"}";
        }
        return http_respond("application/json", body);
    }
    return http_404();
}

// ============================================================================
// main
// ============================================================================

int main(int argc, char** argv) {
    uint16_t port = 8443;
    if (argc > 1) port = (uint16_t)std::atoi(argv[1]);

    auto st = setup_state();

    // 服务器证书管理器：CN=localhost，密钥为 leaf 密钥，cert_data 为带 SCT 的最终证书
    tls_certificate_manager cert_mgr;
    auto cert = jpssl::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    std::memcpy(cert->pub.ecdsa_p256, st.leaf_pub, 64);
    std::memcpy(cert->priv.ecdsa_p256, st.leaf_priv, 32);
    cert->cert_data = st.final_der;
    cert_mgr.add_certificate("localhost", std::move(cert));

    tls_listener listener;
    std::string err;
    if (!listener.listen(port, "0.0.0.0", &err)) {
        std::fprintf(stderr, "listen failed: %s\n", err.c_str());
        return 1;
    }
    std::printf("HTTPS+CT server listening on port %u (CT log tree size %zu)\n",
                (unsigned)listener.local_port(), st.log->tree_size());
    std::printf("  try: https_client 127.0.0.1 %u\n", (unsigned)listener.local_port());

    for (;;) {
        tls_connection conn;
        if (!listener.accept(conn, cert_mgr, &err)) {
            std::fprintf(stderr, "accept failed: %s\n", err.c_str());
            continue;
        }
        std::string req, rerr;
        if (!read_http_request(conn, req, &rerr)) {
            conn.close();
            continue;
        }
        std::string path = request_path(req);
        std::string resp = handle_request(st, path);
        conn.send(resp, &rerr);
        conn.close();
    }
    return 0;
}
