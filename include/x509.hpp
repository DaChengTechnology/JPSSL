#pragma once
/**
 * x509.hpp — X.509 v3 证书 (RFC 5280) DER 编解码与验证
 *
 * 支持算法: RSA-2048/4096, Ed25519, Ed448, ECDSA P-256, SM2
 * 支持扩展: BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAlternativeName
 * 支持格式: DER 与 PEM 证书、PKCS#8/PKCS#1/SEC1 私钥、PKCS#10 CSR
 * 完全自包含的 DER 编码器/解码器，无外部依赖。
 */
#include "rsa.hpp"
#include "ed25519.hpp"
#include "ed448.hpp"
#include "ecdsa.hpp"
#include "sm2.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "sm3.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include "jpssl_span.hpp"
#include "jpssl_optional.hpp"
#include <ctime>

namespace jpssl::x509 {

// ═══════════════════════════════════════════════════════════════════════
//  ASN.1 DER 基本类型标记
// ═══════════════════════════════════════════════════════════════════════
enum class ASN1Tag : uint8_t {
    BOOLEAN           = 0x01,
    INTEGER           = 0x02,
    BIT_STRING        = 0x03,
    OCTET_STRING      = 0x04,
    NULL_TAG          = 0x05,
    OID               = 0x06,
    UTF8_STRING       = 0x0C,
    PRINTABLE_STRING  = 0x13,
    IA5_STRING        = 0x16,
    UTCTime           = 0x17,
    GeneralizedTime   = 0x18,
    SEQUENCE          = 0x30,
    SET               = 0x31,
    // 上下文特定 (constructed)
    CONTEXT0  = 0xA0,
    CONTEXT1  = 0xA1,
    CONTEXT2  = 0xA2,
    CONTEXT3  = 0xA3,
};

// ═══════════════════════════════════════════════════════════════════════
//  OID 常量 (RFC 5280, RFC 8410, RFC 5758, GB/T 35275)
// ═══════════════════════════════════════════════════════════════════════
// Signature algorithms
inline const uint8_t OID_RSA_ENCRYPTION[]      = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01};  // 1.2.840.113549.1.1.1
inline const uint8_t OID_SHA256_WITH_RSA[]      = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B};  // 1.2.840.113549.1.1.11
inline const uint8_t OID_SHA384_WITH_RSA[]      = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0C};  // 1.2.840.113549.1.1.12
inline const uint8_t OID_SHA512_WITH_RSA[]      = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0D};  // 1.2.840.113549.1.1.13
inline const uint8_t OID_EC_PUBLIC_KEY[]        = {0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01};            // 1.2.840.10045.2.1
inline const uint8_t OID_EC_SECP256R1[]         = {0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};      // 1.2.840.10045.3.1.7
inline const uint8_t OID_EC_SECP384R1[]         = {0x2B,0x81,0x04,0x00,0x22};                   // 1.3.132.0.34  (secp384r1)
inline const uint8_t OID_EC_SECP521R1[]         = {0x2B,0x81,0x04,0x00,0x23};                   // 1.3.132.0.35  (secp521r1)
inline const uint8_t OID_ECDSA_WITH_SHA256[]    = {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};      // 1.2.840.10045.4.3.2
inline const uint8_t OID_ECDSA_WITH_SHA384[]    = {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x03};      // 1.2.840.10045.4.3.3
inline const uint8_t OID_ECDSA_WITH_SHA512[]    = {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x04};      // 1.2.840.10045.4.3.4
inline const uint8_t OID_ED25519[]              = {0x2B,0x65,0x70};                                // 1.3.101.112
inline const uint8_t OID_ED448[]                = {0x2B,0x65,0x71};                                // 1.3.101.113
// SM2 / SM3 (GM/T 35275)
// SM2 curve: 1.2.156.10197.1.301
inline const uint8_t OID_SM2[]                  = {0x2A,0x81,0x1C,0xCF,0x55,0x01,0x82,0x2D};      // 1.2.156.10197.1.301
// SM2-with-SM3 signature: 1.2.156.10197.1.501
inline const uint8_t OID_SM2_WITH_SM3[]         = {0x2A,0x81,0x1C,0xCF,0x55,0x01,0x83,0x75};       // 1.2.156.10197.1.501

// Extensions
inline const uint8_t OID_BASIC_CONSTRAINTS[]    = {0x55,0x1D,0x13};                                // 2.5.29.19
inline const uint8_t OID_KEY_USAGE[]            = {0x55,0x1D,0x0F};                                // 2.5.29.15
inline const uint8_t OID_EXT_KEY_USAGE[]        = {0x55,0x1D,0x25};                                // 2.5.29.37
inline const uint8_t OID_SUBJECT_ALT_NAME[]     = {0x55,0x1D,0x11};                                // 2.5.29.17

// Extended Key Usage OIDs
inline const uint8_t OID_EKU_SERVER_AUTH[]      = {0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01};      // 1.3.6.1.5.5.7.3.1
inline const uint8_t OID_EKU_CLIENT_AUTH[]      = {0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x02};      // 1.3.6.1.5.5.7.3.2

// Name attributes
inline const uint8_t OID_CN[]                   = {0x55,0x04,0x03};                                // 2.5.4.3  commonName
inline const uint8_t OID_O[]                    = {0x55,0x04,0x0A};                                // 2.5.4.10 organizationName
inline const uint8_t OID_C[]                    = {0x55,0x04,0x06};                                // 2.5.4.6  countryName

// ═══════════════════════════════════════════════════════════════════════
//  密钥类型枚举
// ═══════════════════════════════════════════════════════════════════════
enum class KeyType : uint8_t {
    RSA_2048,
    RSA_4096,
    Ed25519,
    Ed448,
    ECDSA_P256,
    ECDSA_P384,
    SM2,
    ECDSA_P521,
};

// ═══════════════════════════════════════════════════════════════════════
//  KeyUsage 和 ExtendedKeyUsage
// ═══════════════════════════════════════════════════════════════════════
enum KeyUsageBits : uint16_t {
    KU_DIGITAL_SIGNATURE = 0x8000,
    KU_NON_REPUDIATION   = 0x4000,
    KU_KEY_ENCIPHERMENT  = 0x2000,
    KU_DATA_ENCIPHERMENT = 0x1000,
    KU_KEY_AGREEMENT     = 0x0800,
    KU_KEY_CERT_SIGN     = 0x0400,
    KU_CRL_SIGN          = 0x0200,
    KU_ENCIPHER_ONLY     = 0x0100,
    KU_DECIPHER_ONLY     = 0x0080,
};

enum class ExtKeyUsage : uint8_t {
    SERVER_AUTH,
    CLIENT_AUTH,
};

// ═══════════════════════════════════════════════════════════════════════
//  Distinguished Name (RDN)
// ═══════════════════════════════════════════════════════════════════════
struct NameAttribute {
    std::vector<uint8_t> oid;
    std::string value;       // UTF-8 (for CN, O) or IA5 (for email)
};

using DistinguishedName = std::vector<NameAttribute>;

// ═══════════════════════════════════════════════════════════════════════
//  X.509 扩展
// ═══════════════════════════════════════════════════════════════════════
struct BasicConstraints {
    bool ca = false;
    int path_len = -1;       // -1 = absent
};

struct KeyUsage {
    uint16_t bits = 0;
};

struct ExtKeyUsageList {
    std::vector<ExtKeyUsage> usages;
};

struct SubjectAlternativeName {
    std::vector<std::string> dns_names;  // DNS
    std::vector<std::string> ip_addrs;  // IP (not yet implemented)
};

/// Raw (opaque) X.509 extension, preserved verbatim through parse/encode.
/// `oid` holds raw DER-encoded OID bytes (same format as the OID_* constants),
/// `extn_value` holds the contents of the Extension's extnValue OCTET STRING.
struct RawExtension {
    std::vector<uint8_t> oid;
    bool critical = false;
    std::vector<uint8_t> extn_value;
};

// ═══════════════════════════════════════════════════════════════════════
//  X.509 v3 证书
// ═══════════════════════════════════════════════════════════════════════
struct x509_cert {
    // TBSCertificate
    int version = 2;                     // 0=v1, 1=v2, 2=v3
    std::vector<uint8_t> serial_number;  // up to 20 bytes
    DistinguishedName issuer;
    DistinguishedName subject;
    uint64_t not_before = 0;             // Unix timestamp
    uint64_t not_after = 0;              // Unix timestamp

    // SubjectPublicKeyInfo
    KeyType key_type = KeyType::Ed25519;
    std::vector<uint8_t> public_key;     // raw key bytes

    // Extensions (v3)
    jpssl::optional<BasicConstraints> basic_constraints;
    jpssl::optional<KeyUsage> key_usage;
    jpssl::optional<ExtKeyUsageList> ext_key_usage;
    jpssl::optional<SubjectAlternativeName> subject_alt_name;
    std::vector<RawExtension> raw_extensions;  // extensions not modeled above

    // Signature
    KeyType sign_key_type = KeyType::Ed25519;
    std::vector<uint8_t> signature;      // raw signature bytes
    std::vector<uint8_t> tbs_raw;        // raw TBS bytes (for verification, set by from_der)

    // ── 辅助方法 ────────────────────────────────────────────────────────
    /// 从 DER 编码的证书解析
    static jpssl::optional<x509_cert> from_der(const uint8_t* data, size_t len);
    static jpssl::optional<x509_cert> from_der(const std::vector<uint8_t>& der);

    /// 从 PEM 编码的证书解析 (-----BEGIN CERTIFICATE-----)
    static jpssl::optional<x509_cert> from_pem(const std::string& pem);
    static jpssl::optional<x509_cert> from_pem(const char* data, size_t len);

    /// 编码为 DER
    std::vector<uint8_t> to_der() const;

    /// 编码为 PEM (-----BEGIN CERTIFICATE-----)
    std::string to_pem() const;

    /// 获取 subject CN
    std::string common_name() const;
    /// 获取 issuer CN
    std::string issuer_name() const;

    /// 验证证书签名（用颁发者公钥）
    bool verify_signature(const x509_cert& issuer) const;

    /// 是否在有效期内
    bool is_valid_now() const;
    /// 是否在指定时间有效
    bool is_valid_at(uint64_t now_unix) const;

    /// 是否是 CA 证书
    bool is_ca() const;

    /// 获取 SAN DNS 名称
    std::vector<std::string> dns_names() const;
};

// ═══════════════════════════════════════════════════════════════════════
//  私钥 (PKCS#8 / PKCS#1 / SEC1 / RFC 8410)
// ═══════════════════════════════════════════════════════════════════════
struct private_key {
    KeyType key_type = KeyType::Ed25519;
    std::vector<uint8_t> priv;   // raw private key bytes（库内原始格式）
    std::vector<uint8_t> pub;    // 公钥 raw bytes（解析时从密钥中恢复，可为空）

    /// 从 DER 编码的私钥解析 (PKCS#8 / PKCS#1 RSA / SEC1 EC / RFC 8410)
    static jpssl::optional<private_key> from_der(const uint8_t* data, size_t len);
    static jpssl::optional<private_key> from_der(const std::vector<uint8_t>& der);

    /// 从 PEM 编码的私钥解析:
    ///   -----BEGIN PRIVATE KEY-----        (PKCS#8)
    ///   -----BEGIN RSA PRIVATE KEY-----     (PKCS#1)
    ///   -----BEGIN EC PRIVATE KEY-----      (SEC1)
    ///   -----BEGIN ED25519 PRIVATE KEY----- (RFC 8410)
    ///   -----BEGIN ED448 PRIVATE KEY-----   (RFC 8410)
    static jpssl::optional<private_key> from_pem(const std::string& pem);
    static jpssl::optional<private_key> from_pem(const char* data, size_t len);

    /// 从加密 PEM 私钥解析 (-----BEGIN ENCRYPTED PRIVATE KEY-----)
    /// 支持 PBES2 (RFC 8018): PBKDF2-HMAC-SHA256 + AES-128/256-CBC
    static jpssl::optional<private_key> from_pem_encrypted(const std::string& pem,
                                                         const std::string& password);
    static jpssl::optional<private_key> from_pem_encrypted(const char* data, size_t len,
                                                         const std::string& password);
};

// ═══════════════════════════════════════════════════════════════════════
//  PKCS#10 证书签名请求 (CSR)
// ═══════════════════════════════════════════════════════════════════════
struct csr {
    // CertificationRequestInfo
    DistinguishedName subject;
    KeyType key_type = KeyType::Ed25519;
    std::vector<uint8_t> public_key;   // raw key bytes（与 x509_cert 相同格式）

    // Signature
    KeyType sign_key_type = KeyType::Ed25519;
    std::vector<uint8_t> signature;    // raw signature bytes
    std::vector<uint8_t> tbs_raw;      // raw CertificationRequestInfo bytes（供验签）

    /// 从 DER 编码的 CSR 解析
    static jpssl::optional<csr> from_der(const uint8_t* data, size_t len);
    static jpssl::optional<csr> from_der(const std::vector<uint8_t>& der);

    /// 从 PEM 编码的 CSR 解析 (-----BEGIN CERTIFICATE REQUEST-----)
    static jpssl::optional<csr> from_pem(const std::string& pem);
    static jpssl::optional<csr> from_pem(const char* data, size_t len);
};

// ═══════════════════════════════════════════════════════════════════════
//  X.509 证书生成器
// ═══════════════════════════════════════════════════════════════════════
struct x509_builder {
    x509_cert cert;

    x509_builder& set_version(int v) { cert.version = v; return *this; }
    x509_builder& set_serial(const uint8_t* serial, size_t len) {
        cert.serial_number.assign(serial, serial + len); return *this;
    }
    x509_builder& set_subject(DistinguishedName dn) { cert.subject = std::move(dn); return *this; }
    x509_builder& set_issuer(DistinguishedName dn) { cert.issuer = std::move(dn); return *this; }
    x509_builder& set_validity(uint64_t from, uint64_t to) {
        cert.not_before = from; cert.not_after = to; return *this;
    }
    x509_builder& set_key(KeyType type, const uint8_t* key_data, size_t len) {
        cert.key_type = type;
        cert.public_key.assign(key_data, key_data + len); return *this;
    }
    x509_builder& set_ca(bool is_ca, int path_len = -1) {
        cert.basic_constraints = BasicConstraints{is_ca, path_len}; return *this;
    }
    x509_builder& set_key_usage(uint16_t bits) {
        cert.key_usage = KeyUsage{bits}; return *this;
    }
    x509_builder& set_server_auth() {
        cert.ext_key_usage = ExtKeyUsageList{{ExtKeyUsage::SERVER_AUTH}}; return *this;
    }
    x509_builder& add_san_dns(std::string dns) {
        if (!cert.subject_alt_name) cert.subject_alt_name = SubjectAlternativeName{};
        cert.subject_alt_name->dns_names.push_back(std::move(dns)); return *this;
    }

    /// 构建并签发证书 (self-signed if issuer_key == sign_key)
    /// sign_key_type: 签名算法对应密钥类型
    /// sign_priv_data: 签名私钥 raw bytes
    /// sign_priv_len: 私钥长度
    x509_cert build_and_sign(KeyType sign_key_type,
                             const uint8_t* sign_priv_data, size_t sign_priv_len);
};

// ═══════════════════════════════════════════════════════════════════════
//  证书链验证
// ═══════════════════════════════════════════════════════════════════════
struct verify_result {
    bool success = false;
    std::string error;
};

/// 验证证书链 (leaf -> intermediate... -> root)
/// root 必须是自签名且 CA=true
verify_result x509_verify_chain(const std::vector<x509_cert>& chain,
                                uint64_t now_unix = 0);

// ═══════════════════════════════════════════════════════════════════════
//  DER 低层 API (内部使用)
// ═══════════════════════════════════════════════════════════════════════
namespace der {

/// TLV 编码: type + length + value
std::vector<uint8_t> encode_tlv(ASN1Tag tag, const std::vector<uint8_t>& value);
std::vector<uint8_t> encode_tlv(ASN1Tag tag, const uint8_t* value, size_t len);

/// 长度编码 (DER: definite form)
void encode_length(std::vector<uint8_t>& out, size_t len);

/// 简单类型编码
std::vector<uint8_t> encode_integer(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> encode_oid(const uint8_t* oid, size_t len);
std::vector<uint8_t> encode_oid(const std::vector<uint8_t>& oid);
std::vector<uint8_t> encode_bit_string(const uint8_t* data, size_t len, uint8_t unused_bits=0);
std::vector<uint8_t> encode_octet_string(const uint8_t* data, size_t len);
std::vector<uint8_t> encode_null();
std::vector<uint8_t> encode_utc_time(uint64_t unix_time);
std::vector<uint8_t> encode_printable_string(const std::string& s);
std::vector<uint8_t> encode_ia5_string(const std::string& s);
std::vector<uint8_t> encode_utf8_string(const std::string& s);

/// 构造 SEQUENCE
std::vector<uint8_t> encode_sequence(const std::vector<uint8_t>& body);
std::vector<uint8_t> encode_set(const std::vector<uint8_t>& body);

/// 构造 EXPLICIT 上下文标记
std::vector<uint8_t> encode_context(ASN1Tag tag, const std::vector<uint8_t>& value);

/// Name 编码 (SEQUENCE OF SET OF AttributeTypeAndValue)
std::vector<uint8_t> encode_name(const DistinguishedName& dn);

/// SubjectPublicKeyInfo 编码
std::vector<uint8_t> encode_spki(KeyType key_type, const uint8_t* raw_key, size_t raw_key_len);

/// AlgorithmIdentifier 编码
std::vector<uint8_t> encode_sig_algo(KeyType key_type);

/// Extensions 编码
std::vector<uint8_t> encode_extensions(const x509_cert& cert);

/// 解码辅助
struct TLV {
    ASN1Tag tag;
    size_t total_len;        // 包含 tag+length+value 的总长度
    std::vector<uint8_t> value;
    bool is_constructed() const;
};

/// 解码一个 TLV
jpssl::optional<TLV> decode_tlv(const uint8_t* data, size_t len, size_t& offset);

/// 解码整数
std::vector<uint8_t> tlv_to_integer(const TLV& tlv);
/// 解码 OID
std::vector<uint8_t> tlv_to_oid(const TLV& tlv);
/// 解码 bit string
std::vector<uint8_t> tlv_to_bit_string(const TLV& tlv);
/// 解码 octet string
std::vector<uint8_t> tlv_to_octet_string(const TLV& tlv);
/// 解码 UTCTime 为 unix timestamp
jpssl::optional<uint64_t> tlv_to_utc_time(const TLV& tlv);
/// 解码 string
std::string tlv_to_string(const TLV& tlv);

/// 比较 OID
bool oid_equal(const std::vector<uint8_t>& a, const uint8_t* b, size_t b_len);
bool oid_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

} // namespace der

} // namespace jpssl::x509
