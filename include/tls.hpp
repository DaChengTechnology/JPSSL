#pragma once
/** tls.hpp — TLS 1.2/1.3 完整握手流程 + SNI 多域名证书切换 */
#include "aes.hpp"
#include "chacha20_poly1305.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "hkdf.hpp"
#include "hmac.hpp"
#include "x25519.hpp"
#include "ed25519.hpp"
#include "x448.hpp"
#include "ed448.hpp"
#include "ecdsa.hpp"
#include "rsa.hpp"
#include "sm2.hpp"
#include "sm3.hpp"
#include "sm4.hpp"
#include "sm4_gcm.hpp"
#include "sm4_ccm.hpp"
#include "x509.hpp"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <memory>
namespace jpssl::tls {

enum class TLSVersion { V12=0x0303, V13=0x0304 };
enum class ContentType { CHANGE_CIPHER_SPEC=20, ALERT=21, HANDSHAKE=22, APPLICATION_DATA=23 };
enum class AlertLevel { WARNING=1, FATAL=2 };
enum class AlertDescription { CLOSE_NOTIFY=0, UNEXPECTED_MESSAGE=10, BAD_RECORD_MAC=20, DECRYPTION_FAILED=21, RECORD_OVERFLOW=22, DECOMPRESSION_FAILURE=30, HANDSHAKE_FAILURE=40, BAD_CERTIFICATE=42, UNSUPPORTED_CERTIFICATE=43, CERTIFICATE_REVOKED=44, CERTIFICATE_EXPIRED=45, CERTIFICATE_UNKNOWN=46, ILLEGAL_PARAMETER=47, UNKNOWN_CA=48, ACCESS_DENIED=49, DECODE_ERROR=50, DECRYPT_ERROR=51, PROTOCOL_VERSION=70, INSUFFICIENT_SECURITY=71, INTERNAL_ERROR=80, USER_CANCELED=90, NO_RENEGOTIATION=100, UNSUPPORTED_EXTENSION=110 };
enum class HandshakeType { 
    CLIENT_HELLO=1, SERVER_HELLO=2, NEW_SESSION_TICKET=4, END_OF_EARLY_DATA=5,
    ENCRYPTED_EXTENSIONS=8, CERTIFICATE=11, SERVER_KEY_EXCHANGE=12,
    CERTIFICATE_REQUEST=13, SERVER_HELLO_DONE=14, CERT_VERIFY=15,
    CLIENT_KEY_EXCHANGE=16, FINISHED=20
};
enum class ExtensionType { SERVER_NAME=0, SUPPORTED_VERSIONS=0x2b, KEY_SHARE=0x33, SUPPORTED_GROUPS=0x0a, SIGNATURE_ALGORITHMS=0x0d, SIGNATURE_ALGORITHMS_CERT=0x32, PRE_SHARED_KEY=41, PSK_KEY_EXCHANGE_MODES=45, EARLY_DATA=42 };
// TLS signature schemes (RFC 8446 sec 4.2.3, RFC 8998 sec 4.3)
// rsa_pkcs1_* may only be used to verify certificate-chain signatures in TLS 1.3.
enum class SignatureAlgorithm : uint16_t {
    RSA_PKCS1_SHA256=0x0401, RSA_PKCS1_SHA384=0x0501, RSA_PKCS1_SHA512=0x0601,
    ECDSA_SECP256R1_SHA256=0x0403, ECDSA_SECP384R1_SHA384=0x0503,
    ECDSA_SECP521R1_SHA512=0x0603,
    RSA_PSS_RSAE_SHA256=0x0804, RSA_PSS_RSAE_SHA384=0x0805, RSA_PSS_RSAE_SHA512=0x0806,
    ED25519=0x0807, ED448=0x0808,
    SM2_SM3=0x0708
};
// TLS 1.3 NamedGroup (RFC 8446 §4.2.7, RFC 8998 §4.2.1)
enum class NamedGroup : uint16_t {
    secp256r1=0x0017, secp384r1=0x0018, X25519=0x001d, X448=0x001e, curveSM2=0x0029
};

/// TLS 单条 record 明文上限（RFC 5246 / RFC 8446：2^14 字节）。
/// 大于该值的长消息由 tls_encrypt / tls_connection::send 自动分片为多条 record，
/// 由 tls_decrypt / tls_connection::recv 自动合并还原。
inline constexpr size_t TLS_MAX_RECORD_PLAINTEXT = 16384;

// TLS 1.3 CipherSuite (RFC 8446 §B.4, RFC 8998 §4.1)
enum class CipherSuite : uint16_t {
    // TLS 1.2
    TLS_RSA_WITH_AES_128_GCM_SHA256       = 0x009C,
    TLS_RSA_WITH_AES_256_GCM_SHA384       = 0x009D,
    TLS_RSA_WITH_AES_128_CBC_SHA256       = 0x003D,
    TLS_RSA_WITH_AES_256_CBC_SHA256       = 0x003E,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  = 0xC030,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
    // TLS 1.3
    TLS_AES_128_GCM_SHA256       = 0x1301,
    TLS_AES_256_GCM_SHA384       = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256       = 0x1304,
    TLS_SM4_GCM_SM3              = 0x00C6,
    TLS_SM4_CCM_SM3              = 0x00C7
};

struct tls_record { ContentType type; TLSVersion ver; std::vector<uint8_t> payload; };

// ═══════════════════════════════════════════════════════════════════════
//  TLS 会话状态
// ═══════════════════════════════════════════════════════════════════════
// 用于 support SHA-256、SHA-384 和 SM3 transcript
union transcript_ctx_union {
    sha256_ctx sha256;
    sha512_ctx sha512;
    sm3_ctx   sm3;
    transcript_ctx_union() : sha256{} {}
};

struct tls_session {
    TLSVersion ver;
    std::string server_name; // SNI: 客户端请求的服务器名称
    uint8_t client_random[32], server_random[32];
    uint8_t handshake_secret[48], master_secret[48]; // 48 for SHA-384 suites, first 32 for SHA-256
    uint8_t client_write_key[32], server_write_key[32];
    uint8_t client_write_iv[12], server_write_iv[12];
    uint64_t client_seq, server_seq;
    aes_context aes_ctx;
    sm4_ctx   sm4;                // SM4 cipher context for SM cipher suites

    // TLS 1.2 会话状态
    uint8_t session_id[32];       // 会话 ID (TLS 1.2 会话恢复)
    uint8_t session_id_len = 0;
    bool tls12_ccs_received = false;  // ChangeCipherSpec 已接收
    bool tls12_ccs_sent = false;     // ChangeCipherSpec 已发送
    bool tls12_secure = false;       // 加密层已激活

    bool is_server = false;
    CipherSuite cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    transcript_ctx_union transcript_ctx; // TLS 1.3 握手 transcript 哈希
    uint8_t transcript_hash[48]; // 已计算的 transcript 哈希 (32 for SHA-256, 48 for SHA-384)
    bool transcript_ready = false;
    NamedGroup ks_group = NamedGroup::X25519;
    uint8_t ks_priv[56];       // curveSM2(32) / X448(56) / X25519(32) / secp256r1(32) / secp384r1(48)
    uint8_t ks_pub[96];        // secp384r1(96) / curveSM2(64) / X448(56) / X25519(32) / secp256r1(64)
    // SM 套件客户端额外生成的 X25519 兜底临时对（RFC 8998 要求 curveSM2
    // 必须出现，但非 SM 服务器可能回落到 X25519）
    uint8_t ks_priv_x25519[32];
    uint8_t ks_pub_x25519[32];

    // 0-RTT / PSK 支持
    bool psk_valid = false;                // 客户端: 是否有可用 PSK
    uint8_t psk_identity[32];              // PSK 标识 (ticket)
    uint8_t psk_identity_len = 0;
    uint8_t psk_value[48];                 // PSK 值 (resumption secret, hash_len bytes)
    uint32_t ticket_age_add = 0;           // ticket 混淆 age
    uint64_t ticket_issue_time = 0;        // ticket 签发时间戳 (用于 replay 保护)

    // 0-RTT early data 密钥 (仅客户端发送, 服务端接收)
    uint8_t client_early_write_key[32];
    uint8_t client_early_write_iv[12];
    uint64_t client_early_seq = 0;
    bool early_data_accepted = false;      // 服务端: 是否接受了 early_data

    // 可配置的 signature_algorithms / signature_algorithms_cert 列表
    // 为空时使用 tls_default_signature_algorithms() 全量默认值
    std::vector<uint16_t> sig_algs;
    std::vector<uint16_t> sig_algs_cert;
    // 本次握手协商出的签名方案（CertificateVerify / ServerKeyExchange）
    uint16_t selected_sig_alg = 0;
};

// 默认支持的签名方案全量列表（RFC 8446 + RFC 8998，客户端偏好序）
// rsa_pkcs1_* 仅用于证书链签名验证；TLS 1.3 CertificateVerify 只允许 PSS/ECDSA/EdDSA/SM2
inline std::vector<uint16_t> tls_default_signature_algorithms() {
    return {
        (uint16_t)SignatureAlgorithm::ED25519,
        (uint16_t)SignatureAlgorithm::ED448,
        (uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        (uint16_t)SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        (uint16_t)SignatureAlgorithm::ECDSA_SECP521R1_SHA512,
        (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256,
        (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA384,
        (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA512,
        (uint16_t)SignatureAlgorithm::SM2_SM3
    };
}

// TLS 1.3 CertificateVerify 允许使用的方案（不含 rsa_pkcs1_*）
inline bool tls_scheme_allowed_for_cert_verify(uint16_t scheme) {
    switch (scheme) {
        case (uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256:
        case (uint16_t)SignatureAlgorithm::ECDSA_SECP384R1_SHA384:
        case (uint16_t)SignatureAlgorithm::ECDSA_SECP521R1_SHA512:
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256:
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384:
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA512:
        case (uint16_t)SignatureAlgorithm::ED25519:
        case (uint16_t)SignatureAlgorithm::ED448:
        case (uint16_t)SignatureAlgorithm::SM2_SM3:
            return true;
        default:
            return false;
    }
}

// 根据 cipher suite 返回 hash 长度
inline size_t tls_hash_len(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_256_GCM_SHA384: return 48;
        default: return 32;
    }
}

// 判断 cipher suite 是否使用 SHA-384
inline bool tls_use_sha384(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_256_GCM_SHA384: return true;
        default: return false;
    }
}

// 判断 cipher suite 是否使用 SM3 哈希
inline bool tls_use_sm3(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_SM4_GCM_SM3:
        case CipherSuite::TLS_SM4_CCM_SM3:
            return true;
        default: return false;
    }
}

// 判断 cipher suite 是否使用 SM4 作为 AEAD
inline bool tls_use_sm4(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_SM4_GCM_SM3:
        case CipherSuite::TLS_SM4_CCM_SM3:
            return true;
        default: return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  证书结构（含私钥，用于签名 CertificateVerify）
// ═══════════════════════════════════════════════════════════════════════
struct tls_certificate {
    std::string subject_name;
    std::vector<uint8_t> cert_data;

    // 公钥
    union PublicKey {
        PublicKey() : rsa{} {}
        rsa_public_key rsa;
        uint8_t ed25519[32];
        uint8_t ed448[57];
        uint8_t ecdsa_p256[64];
        uint8_t ecdsa_p384[96];
        uint8_t ecdsa_p521[132];
        uint8_t sm2[64];           // SM2 未压缩公钥 (x||y)
    } pub;
    // 私钥
    union PrivateKey {
        PrivateKey() : rsa{} {}
        rsa_private_key rsa;
        uint8_t ed25519[64];
        uint8_t ed448[57];
        uint8_t ecdsa_p256[32];
        uint8_t ecdsa_p384[48];
        uint8_t ecdsa_p521[66];
        uint8_t sm2[32];           // SM2 私钥
    } priv;
    SignatureAlgorithm sig_alg;

    // 按证书自身 sig_alg 签名/验签
    bool sign(const uint8_t* data, size_t data_len, uint8_t* sig, size_t& sig_len) const;
    bool verify(const uint8_t* data, size_t data_len, const uint8_t* sig, size_t sig_len) const;

    // 按指定 TLS 签名方案签名/验签（客户端验证对端 CertificateVerify 时使用）
    bool sign_scheme(uint16_t scheme, const uint8_t* data, size_t data_len,
                     uint8_t* sig, size_t& sig_len,
                     const uint8_t za[32] = nullptr) const;
    bool verify_scheme(uint16_t scheme, const uint8_t* data, size_t data_len,
                       const uint8_t* sig, size_t sig_len,
                       const uint8_t za[32] = nullptr) const;
};

// ═══════════════════════════════════════════════════════════════════════
//  多域名证书管理器
// ═══════════════════════════════════════════════════════════════════════
class tls_certificate_manager {
public:
    void add_certificate(const std::string& domain, std::unique_ptr<tls_certificate> cert);
    const tls_certificate* get_certificate(const std::string& domain) const;
    const tls_certificate* get_default_certificate() const;
    size_t count() const { return certificates.size(); }
private:
    std::map<std::string, std::unique_ptr<tls_certificate>> certificates;
    std::string default_domain;
};

// ═══════════════════════════════════════════════════════════════════════
//  SNI 解析
// ═══════════════════════════════════════════════════════════════════════
std::string tls_parse_server_name(const uint8_t* extensions, size_t ext_len);

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.3 完整握手 API
// ═══════════════════════════════════════════════════════════════════════

// 客户端: 生成 ClientHello（含 SNI 扩展）
// 密钥交换组由 s.ks_group 决定（默认 X25519，可设为 X448）
bool tls13_make_client_hello(tls_session& s, std::vector<uint8_t>& client_hello);

// 客户端: 处理服务端回包 (ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished)
// 返回生成的 Client Finished 消息
bool tls13_process_server_flight(tls_session& s, const uint8_t* data, size_t len,
                                  std::vector<uint8_t>& client_finished,
                                  const tls_certificate_manager* cert_manager = nullptr);

// 服务端: 处理 ClientHello 并生成完整回包 (ServerHello + EE + Certificate + CV + Finished)
bool tls13_make_server_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                               std::vector<uint8_t>& server_flight,
                               const tls_certificate_manager& cert_manager);

// 服务端: 处理客户端 Finished 消息
bool tls13_process_client_finished(tls_session& s, const uint8_t* data, size_t len);

// 简化版客户端握手（一次性，兼容旧 API）
bool tls13_handshake_client(tls_session& s, std::vector<uint8_t>& client_hello,
                             const uint8_t* server_response, size_t resp_len);

// 简化版服务端握手（一次性，兼容旧 API）
bool tls13_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                             std::vector<uint8_t>& server_response,
                             const tls_certificate_manager& cert_manager);

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.2 完整握手 API (RFC 5246)
// ═══════════════════════════════════════════════════════════════════════

// 客户端: 生成 ClientHello (RSA key exchange)
bool tls12_make_client_hello(tls_session& s, std::vector<uint8_t>& client_hello);

// 客户端: 处理服务端回包 (ServerHello+Certificate+ServerHelloDone) → 生成 ClientKeyExchange+CCS+Finished
bool tls12_process_server_flight(tls_session& s, const uint8_t* server_response, size_t resp_len,
                                  const uint8_t* pre_master_secret, size_t pms_len,
                                  std::vector<uint8_t>& client_finished);

// 服务端: 处理 ClientHello → 生成 ServerHello+Certificate+ServerHelloDone
// 返回完整的 server_flight (不含加密部分，CCS+Finished 需要单独调用)
bool tls12_make_server_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                               std::vector<uint8_t>& server_response,
                               const uint8_t* encrypted_pms, size_t epms_len,
                               uint8_t pre_master_secret[48],
                               const tls_certificate_manager& cert_manager);

// 服务端: 处理 ClientKeyExchange → 生成 CCS + Finished (加密)
// encrypted_pms: ClientKeyExchange 中的加密 pre-master
// 返回加密的 Finished 消息 (含 CCS 前缀)
bool tls12_process_client_key_exchange(tls_session& s, const uint8_t* encrypted_pms, size_t epms_len,
                                        std::vector<uint8_t>& server_ccs_finished);

// 服务端: 处理客户端 Finished
bool tls12_process_client_finished(tls_session& s, const uint8_t* data, size_t len);

// 密钥派生
void tls12_derive_keys(tls_session& s, const uint8_t pre_master[48]);

// ── 消息构造辅助 ────────────────────────────────────────────────────────

// 构造 TLS 1.2 Certificate 消息
std::vector<uint8_t> tls12_make_certificate(const tls_certificate& cert);

// 构造 ClientKeyExchange (RSA 加密的 pre-master)
std::vector<uint8_t> tls12_make_client_key_exchange(const rsa_public_key& server_pub,
                                                     const uint8_t pre_master[48]);

// 构造 ChangeCipherSpec 记录
std::vector<uint8_t> tls_make_change_cipher_spec();

// 构造 Alert 记录
std::vector<uint8_t> tls_make_alert(AlertLevel level, AlertDescription desc);

// 构造 ServerHelloDone 消息
std::vector<uint8_t> tls12_make_server_hello_done();

// 构造 TLS 1.2 Finished (明文，不含 CCS)
std::vector<uint8_t> tls12_make_finished(tls_session& s, bool for_server);

// 验证 TLS 1.2 Finished
bool tls12_verify_finished(tls_session& s, const uint8_t* data, size_t len, bool for_server);

// 简化版（兼容旧 API）
bool tls12_handshake_client(tls_session& s, std::vector<uint8_t>& client_hello,
                             const uint8_t* server_response, size_t resp_len,
                             const uint8_t* pre_master_secret, size_t pms_len);
bool tls12_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                             std::vector<uint8_t>& server_response,
                             const uint8_t* encrypted_pms, size_t epms_len,
                             uint8_t pre_master_secret[48],
                             const tls_certificate_manager& cert_manager);

// ═══════════════════════════════════════════════════════════════════════
//  记录层加密/解密
// ═══════════════════════════════════════════════════════════════════════
/// 加密应用数据。len > TLS_MAX_RECORD_PLAINTEXT 时自动拆分为多条
/// <=16KiB 的 record，返回拼接后的完整字节流（可直接写入对端）。
std::vector<uint8_t> tls_encrypt(tls_session& s, ContentType ct, const uint8_t* data, size_t len);

/// 解密 tls_encrypt 产生的字节流：内部逐条解析 record 并把明文合并到 out。
/// 单条 record 与拼接的多条 record 均支持；解析失败返回 false。
bool tls_decrypt(tls_session& s, const uint8_t* record, size_t len, ContentType& ct, std::vector<uint8_t>& out);

// 加密握手消息（TLS 1.3 内部使用）
std::vector<uint8_t> tls_encrypt_handshake(tls_session& s, const uint8_t* hs_msg, size_t hs_len);

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.3 服务端专用 API — 显式方向，自文档化
// ═══════════════════════════════════════════════════════════════════════

/// 服务端发送加密应用数据给客户端（使用 server_write_key）
/// 等价于 tls_encrypt(s, ct, data, len)，要求 s.is_server == true
inline std::vector<uint8_t> tls_server_encrypt(tls_session& s, ContentType ct,
                                                 const uint8_t* data, size_t len) {
    return tls_encrypt(s, ct, data, len);
}

/// 服务端解密客户端发来的加密数据（使用 client_write_key）
/// 等价于 tls_decrypt(s, record, len, ct, out)，要求 s.is_server == true
inline bool tls_server_decrypt(tls_session& s, const uint8_t* record, size_t len,
                                ContentType& ct, std::vector<uint8_t>& out) {
    return tls_decrypt(s, record, len, ct, out);
}

/// 服务端发送加密握手消息给客户端（TLS 1.3 内部使用）
/// 等价于 tls_encrypt_handshake(s, hs_msg, hs_len)，要求 s.is_server == true
inline std::vector<uint8_t> tls_server_encrypt_handshake(tls_session& s,
                                                          const uint8_t* hs_msg, size_t hs_len) {
    return tls_encrypt_handshake(s, hs_msg, hs_len);
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.3 0-RTT / PSK API
// ═══════════════════════════════════════════════════════════════════════

// 服务端: 生成 NewSessionTicket (handshake 完成后调用)
// 在 tls13_process_client_finished 之后, 派生 resumption_master_secret 并生成 ticket
bool tls13_make_new_session_ticket(tls_session& s, std::vector<uint8_t>& ticket_msg,
                                   uint32_t ticket_lifetime = 86400);

// 客户端: 存储从 NewSessionTicket 中提取的 PSK
bool tls13_store_psk(tls_session& s, const uint8_t* ticket_msg, size_t ticket_len);

// 客户端: 用 PSK 生成含 pre_shared_key 扩展的 ClientHello
// 调用前需先设置 s.psk_valid = true 并填充 psk 字段, 或调用 tls13_store_psk
bool tls13_make_psk_client_hello(tls_session& s, std::vector<uint8_t>& client_hello);

// 客户端: 加密 0-RTT early data
std::vector<uint8_t> tls13_encrypt_early_data(tls_session& s,
                                              const uint8_t* data, size_t len);

// 服务端: 处理 PSK ClientHello, 返回是否接受 early_data
bool tls13_process_psk_client_hello(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                                    bool& accept_early_data);

// 服务端: 解密 0-RTT early data (accept_early_data=true 时可用)
bool tls13_decrypt_early_data(tls_session& s, const uint8_t* record, size_t record_len,
                              ContentType& ct, std::vector<uint8_t>& out);

// 服务端: 生成 EndOfEarlyData 消息 (accept_early_data=true 且在 EE 之前发送)
std::vector<uint8_t> tls13_make_end_of_early_data();

// 客户端: 处理 EndOfEarlyData 消息
bool tls13_process_end_of_early_data(tls_session& s, const uint8_t* data, size_t len);

// ═══════════════════════════════════════════════════════════════════════
//  辅助函数
// ═══════════════════════════════════════════════════════════════════════
void tls_transcript_update(tls_session& s, const uint8_t* data, size_t len);
void tls_transcript_finalize(tls_session& s);
std::vector<uint8_t> tls_make_x509_self_signed(const tls_certificate& cert, uint32_t validity_days = 365);
x509::KeyType tls_sig_alg_to_key_type(SignatureAlgorithm sig_alg);
}
