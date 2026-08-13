/**
 * dtls_common.hpp -- DTLS 服务器/客户端示例共用工具
 *
 * 提供：
 *   - 命令行参数解析（--key value / 位置参数）
 *   - 内存生成 ECDSA P-256 自签证书（无需外部证书文件即可跑通演示）
 *   - 密码套件 / 密钥交换组名称解析
 */
#pragma once

#include "dtls.hpp"
#include "ecdsa.hpp"
#include "jpssl_memory.hpp"
#include "x509.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace jpssl::dtls_examples {

using jpssl::dtls::DTLSVersion;
using jpssl::tls::CipherSuite;
using jpssl::tls::NamedGroup;
using jpssl::tls::SignatureAlgorithm;
using jpssl::tls::tls_certificate;
using jpssl::tls::tls_certificate_manager;
using jpssl::tls::tls_trust_store;
using jpssl::x509::DistinguishedName;
using jpssl::x509::KeyType;
using jpssl::x509::OID_CN;
using jpssl::x509::x509_builder;

/// 生成一个 ECDSA P-256 自签证书（CN/SAN=localhost，CA=true），
/// 同时作为服务器证书；返回的 tls_certificate 包含私钥与 DER。
static std::unique_ptr<tls_certificate> make_self_signed_ecdsa_cert() {
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);

    x509_builder b;
    DistinguishedName dn;
    dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + 3), "localhost"});
    b.set_subject(dn).set_issuer(dn);
    uint8_t serial[8] = {0x51, 0x44, 0x54, 0x4c, 0x53, 0x00, 0x00, 0x01};
    b.set_serial(serial, sizeof(serial));
    uint64_t now = (uint64_t)time(nullptr);
    b.set_validity(now - 3600, now + 365 * 86400);
    b.set_key(KeyType::ECDSA_P256, pub, 64);
    b.set_ca(true, 0);
    b.set_key_usage(jpssl::x509::KU_DIGITAL_SIGNATURE | jpssl::x509::KU_KEY_CERT_SIGN);
    b.add_san_dns("localhost");
    auto cert_der = b.build_and_sign(KeyType::ECDSA_P256, priv, 32);

    auto cert = jpssl::make_unique<tls_certificate>();
    cert->subject_name = "localhost";
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    std::memcpy(cert->pub.ecdsa_p256, pub, 64);
    std::memcpy(cert->priv.ecdsa_p256, priv, 32);
    cert->cert_data = cert_der.to_der();
    return cert;
}

/// 从 PEM 文件加载服务器证书（链）与私钥。
static bool load_cert_files(const char* cert_path, const char* key_path,
                            tls_certificate_manager& cert_mgr,
                            std::string& err) {
    auto cert = tls_certificate::from_pem_file(cert_path, key_path, &err);
    if (!cert) return false;
    cert_mgr.add_certificate(cert->subject_name, std::move(cert));
    return true;
}

/// 密码套件名称解析（按版本给默认值）。
static const char* cipher_default(DTLSVersion ver) {
    return ver == DTLSVersion::V12 ? "aes128-gcm" : "aes128-gcm";
}

static bool parse_cipher(const std::string& name, DTLSVersion ver,
                         CipherSuite& cs) {
    if (name == "aes128-gcm") {
        cs = ver == DTLSVersion::V12
                 ? CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                 : CipherSuite::TLS_AES_128_GCM_SHA256;
        return true;
    }
    if (name == "aes256-gcm") {
        cs = ver == DTLSVersion::V12
                 ? CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                 : CipherSuite::TLS_AES_256_GCM_SHA384;
        return true;
    }
    if (name == "chacha20") {
        cs = ver == DTLSVersion::V12
                 ? CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                 : CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
        return true;
    }
    return false;
}

static bool parse_group(const std::string& name, NamedGroup& g) {
    if (name == "x25519") { g = NamedGroup::X25519; return true; }
    if (name == "p256" || name == "secp256r1") { g = NamedGroup::secp256r1; return true; }
    if (name == "x448") { g = NamedGroup::X448; return true; }
    return false;
}

/// 简易参数扫描：识别 "--key value"（或 "--key=value"）与位置参数。
class arg_parser {
public:
    explicit arg_parser(int argc, char** argv) : argc_(argc), argv_(argv) {}

    std::string get(const std::string& key, const std::string& def = "") const {
        for (int i = 1; i < argc_; ++i) {
            std::string a = argv_[i];
            if (a.rfind(key + "=", 0) == 0)
                return a.substr(key.size() + 1);
            if (a == key && i + 1 < argc_) return argv_[i + 1];
        }
        return def;
    }

    bool has(const std::string& key) const {
        for (int i = 1; i < argc_; ++i)
            if (argv_[i] == key) return true;
        return false;
    }

    std::string positional(size_t idx) const {
        size_t n = 0;
        for (int i = 1; i < argc_; ++i) {
            if (argv_[i][0] == '-') {
                // 跳过 "--key value" 的值
                std::string a = argv_[i];
                if (a.rfind("=", 0) == std::string::npos &&
                    i + 1 < argc_ && argv_[i + 1][0] != '-')
                    ++i;
                continue;
            }
            if (n == idx) return argv_[i];
            ++n;
        }
        return "";
    }

private:
    int argc_;
    char** argv_;
};

static void print_session_info(const char* side, jpssl::dtls::dtls_connection& c) {
    const auto& s = c.session();
    const char* cs_name = "other";
    switch (s.cipher_suite) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:
            cs_name = "AES-128-GCM"; break;
        case CipherSuite::TLS_AES_256_GCM_SHA384:
            cs_name = "AES-256-GCM"; break;
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            cs_name = "CHACHA20-POLY1305"; break;
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            cs_name = "ECDHE-ECDSA-AES128-GCM"; break;
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            cs_name = "ECDHE-ECDSA-AES256-GCM"; break;
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            cs_name = "ECDHE-ECDSA-CHACHA20"; break;
        default: break;
    }
    std::printf("%s: %s handshake done, cipher=%s, key_share=%u, suite=%u\n",
                side,
                s.ver == DTLSVersion::V13 ? "DTLS 1.3" : "DTLS 1.2",
                cs_name,
                (unsigned)s.ks_group, (unsigned)s.cipher_suite);
}

} // namespace jpssl::dtls_examples
