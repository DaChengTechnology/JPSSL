/**
 * https_client.cpp -- HTTPS 客户端 + 国际 CT 审计示例
 *
 * 启动：https_client <host> <port>
 *
 * 流程：
 *   1. TLS 1.3 连接（本示例握手后自行校验，故 trust_store 传 nullptr；
 *      生产环境应通过 tls_certificate_manager 固定/按 CA 校验 CertificateVerify）；
 *   2. 拉取首页 /ct/cert /ct/ca /ct/log-key /ct/sth；
 *   3. 校验服务器证书链（leaf <- CA root）；
 *   4. 校验 SCT 签名（日志 ECDSA P-256 公钥）；
 *   5. 校验 STH 签名；
 *   6. 由证书 + SCT 构造 MerkleTreeLeaf 并计算叶哈希；
 *   7. 请求 /ct/proof 获取审计路径并对照 STH 校验包含性证明。
 */
#include "ct_https_common.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

using namespace jpssl;
using namespace jpssl::ct;
using namespace jpssl::tls;
using namespace jpssl::x509;
using jpssl_https::hex_decode;
using jpssl_https::hex_encode;
using jpssl_https::http_get;
using jpssl_https::json_get_string;
using jpssl_https::json_get_u64;

static bool json_parse_hex_array(const std::string& json, const std::string& key,
                                 std::vector<std::vector<uint8_t>>& out) {
    std::string pat = "\"" + key + "\":[";
    size_t p = json.find(pat);
    if (p == std::string::npos) return false;
    p += pat.size();
    size_t end = json.find(']', p);
    if (end == std::string::npos) return false;
    std::string arr = json.substr(p, end - p);
    size_t pos = 0;
    while (true) {
        size_t q1 = arr.find('"', pos);
        if (q1 == std::string::npos) break;
        size_t q2 = arr.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        std::vector<uint8_t> h;
        if (!hex_decode(arr.substr(q1 + 1, q2 - q1 - 1), h)) return false;
        out.push_back(std::move(h));
        pos = q2 + 1;
    }
    return true;
}

static bool check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    return ok;
}

// 服务器每个响应后关闭连接：每个请求单独建立 TLS 连接
static std::string https_get(const std::string& host, uint16_t port,
                             const std::string& path, std::string* err_out = nullptr) {
    tls_connection conn;
    std::string err;
    if (!conn.connect(host, port, nullptr, &err)) {
        if (err_out) *err_out = err;
        return {};
    }
    auto body = http_get(conn, host, path);
    conn.close();
    return body;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <host> <port>\n", argv[0]);
        return 2;
    }
    std::string host = argv[1];
    uint16_t port = (uint16_t)std::atoi(argv[2]);

    bool all_ok = true;
    tls_connection conn;
    std::string err;
    if (!conn.connect(host, port, nullptr, &err)) {
        std::fprintf(stderr, "connect failed: %s\n", err.c_str());
        return 1;
    }
    std::printf("TLS 1.3 connected to %s:%u, cipher %04x\n",
                host.c_str(), (unsigned)port, (unsigned)conn.session().cipher_suite);

    // 1) 首页（首个连接，展示 TLS 信息）
    std::string home = http_get(conn, host, "/");
    all_ok &= check(home.find("Certificate Transparency") != std::string::npos,
                    "GET / returns CT page");
    std::printf("  (page size %zu bytes)\n", home.size());
    conn.close();

    // 2) 服务器证书 / 预证书 / CA / 日志公钥 / STH
    std::string cert_b64 = https_get(host, port, "/ct/cert");
    std::string precert_b64 = https_get(host, port, "/ct/precert");
    std::string ca_b64 = https_get(host, port, "/ct/ca");
    std::string log_key_json = https_get(host, port, "/ct/log-key");
    std::string sth_json = https_get(host, port, "/ct/sth");

    auto cert_der = base64_decode(cert_b64);
    auto precert_der = base64_decode(precert_b64);
    auto ca_der = base64_decode(ca_b64);
    all_ok &= check(cert_der.has_value() && precert_der.has_value() && ca_der.has_value(),
                    "fetch cert + precert + CA (base64)");
    if (!cert_der || !precert_der || !ca_der) return 1;

    std::vector<uint8_t> log_pub;
    all_ok &= check(hex_decode(json_get_string(log_key_json, "pub"), log_pub) &&
                    log_pub.size() == 64,
                    "parse log public key");

    // 3) 证书链校验：leaf <- CA
    auto leaf = x509_cert::from_der(*cert_der);
    auto ca = x509_cert::from_der(*ca_der);
    all_ok &= check(leaf.has_value() && ca.has_value(), "parse server cert + CA");
    if (!leaf || !ca) return 1;
    auto vr = x509_verify_chain({*leaf, *ca}, (uint64_t)time(nullptr));
    all_ok &= check(vr.success, ("cert chain verify: " + vr.error).c_str());

    // 4) SCT 签名校验：证书里的 SCT 是“预证书条目”，需重建 PreCert
    //    signed_entry = PreCert { issuer_key_hash = SHA-256(CA SPKI), precert TBS }
    auto scts = scts_from_cert(*cert_der);
    all_ok &= check(scts.has_value() && !scts->empty(), "extract SCT from certificate");
    if (!scts || scts->empty()) return 1;
    const auto& sct = (*scts)[0];

    auto precert_cert = x509_cert::from_der(*precert_der);
    all_ok &= check(precert_cert.has_value(), "parse precert");
    pre_cert pc;
    if (precert_cert) pc.tbs_certificate = precert_cert->tbs_raw; // 带 poison 的预证书 TBS
    {
        // issuer_key_hash = SHA-256(CA SubjectPublicKeyInfo DER)
        size_t off = 0;
        auto c = der::decode_tlv(ca_der->data(), ca_der->size(), off);
        size_t io = 0;
        auto t = der::decode_tlv(c->value.data(), c->value.size(), io);
        std::vector<std::vector<uint8_t>> elems;
        size_t pos = 0;
        while (pos < t->value.size()) {
            size_t s = pos;
            auto el = der::decode_tlv(t->value.data(), t->value.size(), pos);
            if (!el) break;
            elems.emplace_back(t->value.begin() + s, t->value.begin() + pos);
        }
        size_t idx = (elems[0][0] & 0xE0) == 0xA0 ? 1 : 0;
        auto& spki = elems[idx + 5];
        sha256(spki.data(), spki.size(), pc.issuer_key_hash.data());
    }
    auto precert_signed_entry = make_precert_signed_entry(pc);
    all_ok &= check(verify_sct_std(sct, log_pub.data(), LogEntryType::PRECERT_ENTRY,
                                   precert_signed_entry),
                    "SCT signature verified (ECDSA P-256)");
    std::printf("  SCT: log_id=%s timestamp=%llu hash_alg=%u sig_alg=%u\n",
                hex_encode(sct.log_id.data(), sct.log_id.size()).c_str(),
                (unsigned long long)sct.timestamp, (unsigned)sct.hash_algorithm,
                (unsigned)sct.signature_algorithm);

    // 5) STH 签名校验
    signed_tree_head sth;
    sth.version = (uint8_t)json_get_u64(sth_json, "version");
    sth.timestamp = json_get_u64(sth_json, "timestamp");
    sth.tree_size = json_get_u64(sth_json, "tree_size");
    {
        std::vector<uint8_t> rh;
        hex_decode(json_get_string(sth_json, "root_hash"), rh);
        if (rh.size() == 32) std::memcpy(sth.root_hash.data(), rh.data(), 32);
    }
    sth.hash_algorithm = (uint8_t)json_get_u64(sth_json, "hash_alg");
    sth.signature_algorithm = (uint8_t)json_get_u64(sth_json, "sig_alg");
    {
        std::vector<uint8_t> sg;
        hex_decode(json_get_string(sth_json, "signature"), sg);
        sth.signature = sg;
    }
    all_ok &= check(verify_sth_std(sth, log_pub.data()),
                    "STH signature verified (ECDSA P-256)");
    std::printf("  STH: tree_size=%llu root=%s\n",
                (unsigned long long)sth.tree_size,
                hex_encode(sth.root_hash.data(), sth.root_hash.size()).c_str());

    // 6) 构造 MerkleTreeLeaf（PRECERT 条目）并计算叶哈希（与日志侧一致）
    merkle_tree_leaf leaf_entry;
    leaf_entry.version = CT_VERSION_V1;
    leaf_entry.leaf_type = MerkleLeafType::TIMESTAMPED_ENTRY;
    leaf_entry.timestamp = sct.timestamp;
    leaf_entry.entry_type = LogEntryType::PRECERT_ENTRY;
    leaf_entry.signed_entry = precert_signed_entry;
    leaf_entry.extensions = sct.extensions; // 日志签发时扩展为空
    auto leaf_serialized = serialize_merkle_tree_leaf(leaf_entry);
    node_hash leaf_hash{};
    sha256_leaf_hash(leaf_serialized.data(), leaf_serialized.size(), leaf_hash.data());
    std::printf("  leaf hash: %s\n",
                hex_encode(leaf_hash.data(), leaf_hash.size()).c_str());

    // 7) 请求审计路径并校验包含性证明
    std::string proof_path = "/ct/proof?leaf=" +
                             hex_encode(leaf_hash.data(), leaf_hash.size()) +
                             "&tree=" + std::to_string(sth.tree_size);
    std::string proof_json = https_get(host, port, proof_path);
    uint64_t leaf_index = json_get_u64(proof_json, "leaf_index");
    std::vector<std::vector<uint8_t>> path_bytes;
    all_ok &= check(json_parse_hex_array(proof_json, "audit_path", path_bytes),
                    "parse audit path");
    std::vector<node_hash> path;
    for (const auto& b : path_bytes) {
        node_hash h{};
        if (b.size() == 32) std::memcpy(h.data(), b.data(), 32);
        path.push_back(h);
    }
    all_ok &= check(verify_audit_path((size_t)leaf_index, (size_t)sth.tree_size,
                                      leaf_hash, path, sth.root_hash, CtHashAlg::SHA256),
                    "inclusion proof verified against STH");

    std::printf("\n%s\n", all_ok ? "ALL CT CHECKS PASSED" : "SOME CHECKS FAILED");
    return all_ok ? 0 : 1;
}
