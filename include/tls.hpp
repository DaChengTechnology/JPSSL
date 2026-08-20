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
namespace jpssl {
namespace tls {

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
enum class ExtensionType { SERVER_NAME=0, ALPN=0x0010, SUPPORTED_VERSIONS=0x2b, KEY_SHARE=0x33, SUPPORTED_GROUPS=0x0a, SIGNATURE_ALGORITHMS=0x0d, SIGNATURE_ALGORITHMS_CERT=0x32, PRE_SHARED_KEY=41, PSK_KEY_EXCHANGE_MODES=45, EARLY_DATA=42 };
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
constexpr size_t TLS_MAX_RECORD_PLAINTEXT = 16384;

// TLS 1.3 CipherSuite (RFC 8446 §B.4, RFC 8998 §4.1)
enum class CipherSuite : uint16_t {
    // TLS 1.2
    TLS_RSA_WITH_AES_128_GCM_SHA256       = 0x009C,
    TLS_RSA_WITH_AES_256_GCM_SHA384       = 0x009D,
    TLS_RSA_WITH_AES_128_CBC_SHA256       = 0x003C,
    TLS_RSA_WITH_AES_256_CBC_SHA256       = 0x003D,
    // DHE-RSA（RFC 5288 / RFC 5246 / RFC 7905）
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256       = 0x009E,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384       = 0x009F,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256       = 0x0067,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256       = 0x006B,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAA,
    // PSK（RFC 5487 / RFC 7905）
    TLS_PSK_WITH_AES_128_GCM_SHA256           = 0x00A8,
    TLS_PSK_WITH_AES_256_GCM_SHA384           = 0x00A9,
    TLS_PSK_WITH_AES_128_CBC_SHA256           = 0x00AE,
    TLS_PSK_WITH_AES_256_CBC_SHA384           = 0x00AF,
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256     = 0xCCAB,
    // DHE-PSK（RFC 5487 / RFC 7905）
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256       = 0x00AA,
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384       = 0x00AB,
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256       = 0x00B2,
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384       = 0x00B3,
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAD,
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
    TLS_AES_128_CCM_8_SHA256     = 0x1305,
    TLS_SM4_GCM_SM3              = 0x00C6,
    TLS_SM4_CCM_SM3              = 0x00C7,
    UNKNOWN                      = 0xFFFF   ///< 未知/未支持套件标记（select_cipher_suite 对无法识别的 ID 返回此值）
};

struct tls_record { ContentType type; TLSVersion ver; std::vector<uint8_t> payload; };

// ═══════════════════════════════════════════════════════════════════════
//  QUIC (RFC 9001 / RFC 9369) 支持
// ═══════════════════════════════════════════════════════════════════════
/// QUIC 协议版本（线格式 32 位版本号）。
/// V1 = RFC 9000/9001（版本号 0x00000001），V2 = RFC 9369（版本号 0x6b3343cf）。
/// QUIC v2 与 v1 的 TLS 握手完全一致，区别仅在初始盐、数据包保护密钥派生标签
/// 与线格式（RFC 9369 §3.3）。
enum class QuicVersion : uint32_t {
    V1 = 0x00000001,
    V2 = 0x6b3343cf
};

/// QUIC 传输参数（RFC 9000 §18）——通过 TLS 扩展 0x0039 在
/// ClientHello（客户端参数）与 EncryptedExtensions（服务端参数）中携带，
/// 并由 TLS 握手签名提供完整性保护（RFC 9001 §8.2）。
/// 字段按参数 ID 排列；值为 0 / 空向量表示该参数缺省（编码时省略）。
struct quic_transport_parameters {
    std::vector<uint8_t> original_destination_connection_id; // 0x00 server only
    uint64_t max_idle_timeout = 0;                            // 0x01 (0 = 禁用)
    std::vector<uint8_t> stateless_reset_token;              // 0x02 server only (16 字节)
    uint64_t max_udp_payload_size = 65527;                   // 0x03 (>= 1200)
    uint64_t initial_max_data = 0;                           // 0x04
    uint64_t initial_max_stream_data_bidi_local = 0;         // 0x05
    uint64_t initial_max_stream_data_bidi_remote = 0;        // 0x06
    uint64_t initial_max_stream_data_uni = 0;                // 0x07
    uint64_t initial_max_streams_bidi = 0;                   // 0x08
    uint64_t initial_max_streams_uni = 0;                    // 0x09
    uint64_t ack_delay_exponent = 3;                         // 0x0a (<= 20)
    uint64_t max_ack_delay = 25;                             // 0x0b (< 2^14)
    bool disable_active_migration = false;                   // 0x0c (零长度值)
    std::vector<uint8_t> preferred_address;                  // 0x0d server only (原始编码)
    uint64_t active_connection_id_limit = 2;                 // 0x0e (>= 2)
    std::vector<uint8_t> initial_source_connection_id;       // 0x0f
    std::vector<uint8_t> retry_source_connection_id;         // 0x10 server only
    /// 未知/扩展参数（含 RFC 9368 version_information 等），解码时原样保留。
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> custom;

    /// 编码为 TLS 扩展 0x0039 的 extension_data（RFC 9000 §18.1 传输参数序列）。
    std::vector<uint8_t> encode() const;
    /// 解码；非法值（长度/范围错误）返回 false。
    static bool decode(const uint8_t* data, size_t len, quic_transport_parameters& out);
};

/// QUIC 数据包保护 secret（RFC 9001 §5.1）：Handshake / 1-RTT 两阶段
/// "client in"/"server in" 各 48 字节（SHA-384 套件取前 48，SHA-256 取前 32）。
/// 仅 quic_mode 会话按需堆分配（普通 TLS 连接不占用这 192 字节）。
struct quic_secrets_block {
    uint8_t client_hs[48] = {};
    uint8_t server_hs[48] = {};
    uint8_t client_app[48] = {};
    uint8_t server_app[48] = {};
};

/// 一组 QUIC 数据包保护密钥（RFC 9001 §5.1）：AEAD key + IV + 头部保护 hp。
struct quic_packet_keys {
    uint8_t key[32] = {}; size_t key_len = 0;   // 16 (AES-128) / 32 (AES-256/ChaCha20)
    uint8_t iv[12] = {};
    uint8_t hp[32] = {};  size_t hp_len = 0;    // 与 AEAD key 等长
};

/// QUIC Initial 密钥（RFC 9001 §5.2，恒为 AEAD_AES_128_GCM + SHA-256）。
struct quic_initial_keys {
    uint8_t initial_secret[32] = {};
    quic_packet_keys client;
    quic_packet_keys server;
};

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

// TLS 1.2 DHE（RFC 7919 ffdhe2048）：服务端临时密钥对。
// 仅 DHE 套件按需堆分配（ECDHE/ECDSA 默认连接不占用这 288 字节）。
struct tls12_dhe_keys {
    uint8_t priv[32];  // 私钥指数
    uint8_t pub[256];  // 大端公钥
};

struct tls_session {
    // ═══ 16 字节对齐成员：aes_context（含 AES-NI key schedule，alignof=16）
    aes_context aes_ctx;

    // ═══ 8 字节对齐成员（string/vector/shared_ptr/uint64）══════════
    std::string server_name;             // SNI: 客户端请求的服务器名称
    transcript_ctx_union transcript_ctx; // TLS 1.3 握手 transcript 哈希
    quic_transport_parameters quic_transport_params;      // 本端 QUIC 传输参数
    quic_transport_parameters quic_peer_transport_params; // 对端 QUIC 传输参数
    std::shared_ptr<jpssl::rsa_private_key> rsa_key;      // TLS 1.2 服务端 RSA 私钥（按需堆分配）
    std::shared_ptr<tls12_dhe_keys> dhe_keys;             // TLS 1.2 DHE 临时密钥对（按需）
    std::shared_ptr<quic_secrets_block> quic_secrets;     // QUIC 数据包保护 secret（按需）
    std::vector<uint8_t> tls12_client_hello_cache;        // 客户端 ClientHello 缓存（TLS 1.2）
    std::vector<uint8_t> tls13_client_hello_cache;        // TLS 1.3 ClientHello（协商哈希后重建 transcript 用）
    std::vector<uint16_t> sig_algs;                       // signature_algorithms
    std::vector<uint16_t> sig_algs_cert;                  // signature_algorithms_cert
    std::vector<std::string> alpn_protos;                 // ALPN 本地协议列表
    std::string alpn_selected;                            // 本次协商出的协议
    uint64_t client_seq, server_seq;
    uint64_t ticket_issue_time = 0;      // ticket 签发时间戳 (用于 replay 保护)
    uint64_t client_early_seq = 0;       // early data 序号
    size_t tls12_psk_identity_len = 0;
    size_t tls12_psk_value_len = 0;

    // ═══ 4 字节对齐成员 ═══════════════════════════════════════════
    sm4_ctx sm4;                         // SM4 cipher context for SM cipher suites
    TLSVersion ver;
    QuicVersion quic_version = QuicVersion::V1;
    uint32_t ticket_age_add = 0;         // ticket 混淆 age

    // ═══ 2 字节对齐成员 ═══════════════════════════════════════════
    CipherSuite cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    NamedGroup ks_group = NamedGroup::X25519;
    uint16_t selected_sig_alg = 0;       // 本次握手协商出的签名方案

    // ═══ 1 字节成员（标志位与密钥/随机数数组，无对齐要求）════════
    uint8_t client_random[32], server_random[32];
    uint8_t handshake_secret[48], master_secret[48]; // 48 for SHA-384 suites, first 32 for SHA-256
    // RFC 8446 7.1：handshake traffic secrets（Finished 密钥的 BaseKey）
    uint8_t client_hs_traffic[48], server_hs_traffic[48];
    uint8_t client_write_key[32], server_write_key[32];
    // TLS 1.2 CBC（RFC 5246 6.3）需要 16 字节 IV；TLS 1.3 / GCM / ChaCha20 只用前 12 字节
    uint8_t client_write_iv[16], server_write_iv[16];
    // TLS 1.2 CBC 独立 MAC secret（RFC 5246 6.3：key_block 先排 MAC secret，
    // SHA-256 为 32 字节，SHA-384 为 48 字节）；AEAD 套件不使用
    uint8_t client_write_mac[48], server_write_mac[48];
    uint8_t transcript_hash[48];         // 已计算的 transcript 哈希
    uint8_t session_id[32];              // 会话 ID (TLS 1.2 会话恢复)
    uint8_t session_id_len = 0;
    bool skip_verify = false;            // 客户端：跳过对端证书认证（链验证/主机名/CertificateVerify）
    uint8_t ks_priv[56];       // curveSM2(32) / X448(56) / X25519(32) / secp256r1(32) / secp384r1(48)
    uint8_t ks_pub[96];        // secp384r1(96) / curveSM2(64) / X448(56) / X25519(32) / secp256r1(64)
    // SM 套件客户端额外生成的 X25519 兜底临时对（RFC 8998 要求 curveSM2
    // 必须出现，但非 SM 服务器可能回落到 X25519）
    uint8_t ks_priv_x25519[32];
    uint8_t ks_pub_x25519[32];
    uint8_t tls12_psk_identity[128];     // identity 上限 128 字节（RFC 允许 2^16-1，实际足够）
    uint8_t tls12_psk_value[64];         // PSK 上限 64 字节
    uint8_t psk_identity[32];            // PSK 标识 (ticket)
    uint8_t psk_identity_len = 0;
    uint8_t psk_value[48];               // PSK 值 (resumption secret, hash_len bytes)
    uint8_t client_early_write_key[32];  // 0-RTT early data 密钥 (仅客户端发送)
    uint8_t client_early_write_iv[12];

    // 独立状态标志（bool 1 字节；互不相关故不做位域，保持可寻址）
    bool is_server = false;
    bool tls12_ems = false;              // TLS 1.2 Extended Master Secret (RFC 7627) 已协商
    bool tls12_ccs_received = false;     // ChangeCipherSpec 已接收
    bool tls12_ccs_sent = false;         // ChangeCipherSpec 已发送
    bool tls12_secure = false;           // 加密层已激活
    bool cipher_suite_pinned = false;    // 用户显式固定 cipher_suite
    bool transcript_ready = false;
    bool tls12_psk_valid = false;
    bool psk_valid = false;              // 客户端: 是否有可用 PSK
    bool early_data_accepted = false;    // 服务端: 是否接受了 early_data
    bool server_finished_received = false; // 客户端: 已解析到 Server Finished
    bool quic_mode = false;              // QUIC 模式（RFC 9001 / 9369）
    bool quic_peer_params_valid = false;
    bool quic_hs_secrets_ready = false;
    bool quic_app_secrets_ready = false;
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
        // TLS 1.2 SHA-384 套件（RFC 5289）：Finished/PRF 用 SHA-384
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
            return 48;
        default: return 32;
    }
}

// 判断 cipher suite 是否使用 SHA-384
inline bool tls_use_sha384(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_256_GCM_SHA384: return true;
        // TLS 1.2 SHA-384 套件（RFC 5289）
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
            return true;
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

// AEAD tag length per cipher suite (RFC 8446 B.4):
// TLS_AES_128_CCM_8_SHA256 uses an 8-byte tag, all others 16 bytes.
inline size_t tls_aead_tag_len(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_128_CCM_8_SHA256: return 8;
        default: return 16;
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

    // ── 服务端证书加载（直接读取 PEM / CSR + 私钥）────────────────────
    /// 从 PEM 证书 + PEM 私钥构造服务端证书（私钥支持 PKCS#8/PKCS#1/SEC1/RFC 8410）。
    /// 失败返回 nullptr；err 非空时写入错误描述。
    static std::unique_ptr<tls_certificate> from_pem(const std::string& cert_pem,
                                                     const std::string& key_pem,
                                                     std::string* err = nullptr);
    /// 从证书 PEM 文件 + 私钥 PEM 文件构造。
    static std::unique_ptr<tls_certificate> from_pem_file(const char* cert_path,
                                                          const char* key_path,
                                                          std::string* err = nullptr);
    /// 从 CSR + PEM 私钥构造服务端证书：subject 与公钥取自 CSR，私钥用于签名。
    /// 证书数据留空，握手时按 CSR 主体自动生成自签名证书。
    static std::unique_ptr<tls_certificate> from_csr_pem(const std::string& csr_pem,
                                                         const std::string& key_pem,
                                                         std::string* err = nullptr);
    /// 从 CSR PEM 文件 + 私钥 PEM 文件构造。
    static std::unique_ptr<tls_certificate> from_csr_pem_file(const char* csr_path,
                                                              const char* key_path,
                                                              std::string* err = nullptr);
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

/// TLS 1.2 PSK 凭据表（RFC 4279 / RFC 5487）：identity → PSK。
/// 服务端握手时传入 tls12_make_server_hello_flight / tls12_make_server_flight，
/// 在 ClientKeyExchange 阶段按客户端身份查表。
struct tls_psk_store {
    std::map<std::string, std::vector<uint8_t>> keys;

    void add(const std::string& identity, std::vector<uint8_t> key) {
        keys[identity] = std::move(key);
    }

    bool lookup(const std::string& identity, std::vector<uint8_t>& out) const {
        auto it = keys.find(identity);
        if (it == keys.end()) return false;
        out = it->second;
        return true;
    }

    size_t count() const { return keys.size(); }
};

/// KeyType → TLS 签名方案（from_pem / from_csr_pem 内部使用，也对外暴露）
SignatureAlgorithm tls_key_type_to_sig_alg(x509::KeyType kt);

// ═══════════════════════════════════════════════════════════════════════
//  客户端信任库（x509 链验证）
// ═══════════════════════════════════════════════════════════════════════
/// 持有 CA 根证书，客户端握手时对服务端证书链执行 x509_verify_chain。
struct tls_trust_store {
    std::vector<x509::x509_cert> ca_roots;
    /// 从 PEM 解析全部证书（可含多张 CA 根）。
    static tls_trust_store from_pem(const std::string& pem);
    /// 从 PEM 文件解析全部证书。
    static tls_trust_store from_pem_file(const char* path);
    /// 加载系统信任库（系统 CA bundle）：依次探测常见路径
    ///   SSL_CERT_FILE 环境变量、/etc/ssl/certs/ca-certificates.crt、
    ///   /etc/pki/tls/certs/ca-bundle.crt、/etc/ssl/ca-bundle.pem、
    ///   /etc/ssl/cert.pem（macOS）等；结果做进程内缓存。
    /// 未找到系统 bundle 时返回空 trust store。
    static tls_trust_store from_system();
    size_t count() const { return ca_roots.size(); }
    bool empty() const { return ca_roots.empty(); }
};

// ═══════════════════════════════════════════════════════════════════════
//  SNI 解析
// ═══════════════════════════════════════════════════════════════════════
std::string tls_parse_server_name(const uint8_t* extensions, size_t ext_len);

// ═══════════════════════════════════════════════════════════════════════
//  ALPN 工具 (RFC 7301, 扩展类型 0x0010)
// ═══════════════════════════════════════════════════════════════════════
// 解析 ProtocolNameList（2 字节总长 + 若干 1 字节长度前缀的协议名）。
// 数据格式非法时返回空列表。
std::vector<std::string> tls_parse_alpn_list(const uint8_t* data, size_t len);

// 按客户端偏好序选择双方共同支持的协议；无交集时返回空字符串。
// client_list 为 ClientHello 中携带的协议列表，server_list 为服务端本地支持列表。
std::string tls_select_alpn(const std::vector<std::string>& client_list,
                            const std::vector<std::string>& server_list);

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.3 完整握手 API
// ═══════════════════════════════════════════════════════════════════════

// 客户端: 生成 ClientHello（含 SNI 扩展）
// 密钥交换组由 s.ks_group 决定（默认 X25519，可设为 X448）
bool tls13_make_client_hello(tls_session& s, std::vector<uint8_t>& client_hello);

// 客户端: 处理服务端回包 (ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished)
// 返回生成的 Client Finished 消息
// cert_manager: 可选，按 SNI 名称查找预期服务器证书（兼容旧行为）。
// trust_store:  可选，提供 CA 根证书时对服务端证书链执行 x509 链验证
//               （x509_verify_chain + 叶子主机名匹配），失败则握手失败。
bool tls13_process_server_flight(tls_session& s, const uint8_t* data, size_t len,
                                  std::vector<uint8_t>& client_finished,
                                  const tls_certificate_manager* cert_manager = nullptr,
                                  const tls_trust_store* trust_store = nullptr);

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

// 客户端: 处理服务端回包 (ServerHello+Certificate+[ServerKeyExchange]+ServerHelloDone)
//        → 生成 ClientKeyExchange（可选）+ Finished
// pre_master_secret 为 nullptr 或 pms_len==0 时，ECDHE/DHE/PSK 套件的 premaster
// 由本函数从 ServerKeyExchange / 会话 PSK 内部计算（client_key_exchange 同时输出
// ClientKeyExchange 消息体）；此时按 RFC 5246 完整解析并校验服务端消息。
// 传入 pre_master_secret 且 client_key_exchange==nullptr 时保持旧的简化行为
// （仅解析 ServerHello，transcript = ClientHello + ServerHello），兼容旧调用。
bool tls12_process_server_flight(tls_session& s, const uint8_t* server_response, size_t resp_len,
                                  const uint8_t* pre_master_secret, size_t pms_len,
                                  std::vector<uint8_t>& client_finished,
                                  std::vector<uint8_t>* client_key_exchange = nullptr,
                                  const tls_certificate_manager* cert_manager = nullptr,
                                  const tls_trust_store* trust_store = nullptr);

// 服务端: 处理 ClientHello → 生成明文 hello flight（ServerHello+Certificate+SKX+ServerHelloDone）
// 保存服务端 ECDHE 私钥到 s.ks_priv；随后调用 tls12_process_client_key_exchange 处理 ClientKeyExchange
bool tls12_make_server_hello_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                                    std::vector<uint8_t>& server_response,
                                    const tls_certificate_manager& cert_manager,
                                    const tls_psk_store* psk_store = nullptr);

// 服务端: 处理 ClientHello → 生成 ServerHello+Certificate+ServerHelloDone
// 返回完整的 server_flight (不含加密部分，CCS+Finished 需要单独调用)
bool tls12_make_server_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                               std::vector<uint8_t>& server_response,
                               const uint8_t* encrypted_pms, size_t epms_len,
                               uint8_t pre_master_secret[48],
                               const tls_certificate_manager& cert_manager,
                               const tls_psk_store* psk_store = nullptr);

// 服务端: 处理 ClientKeyExchange → 生成 CCS + Finished (加密)
// encrypted_pms: ClientKeyExchange 消息体（ECDHE: 公钥；RSA: 加密 premaster；
//                DHE: 客户端 DH 公钥；PSK: identity [± DH 公钥]）
// 返回加密的 Finished 消息 (含 CCS 前缀)
bool tls12_process_client_key_exchange(tls_session& s, const uint8_t* encrypted_pms, size_t epms_len,
                                        std::vector<uint8_t>& server_ccs_finished,
                                        const tls_psk_store* psk_store = nullptr);

// 服务端: 处理客户端 Finished
bool tls12_process_client_finished(tls_session& s, const uint8_t* data, size_t len);

// 密钥派生（pms_len：ECDHE 共享密钥 32 字节，RSA premaster 48 字节；默认 48 兼容旧调用）
void tls12_derive_keys(tls_session& s, const uint8_t* pre_master, size_t pms_len = 48);

/// 从已派生的 master_secret 派生 key_block 与写密钥（会话恢复复用，RFC 5246 6.3）。
void tls12_derive_key_block(tls_session& s);

/// TLS 1.2 会话缓存条目（Session ID 恢复，RFC 5246 §7.3）
struct tls12_session_entry {
    uint8_t id[32];
    uint8_t id_len = 0;
    uint8_t master_secret[48];
    CipherSuite cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    bool ems = false;              // 原会话是否使用 Extended Master Secret
    uint64_t created = 0;          // 创建时间（内部维护，用于 TTL 淘汰）
};

/// 全局 TLS 1.2 服务端会话缓存（线程安全；上限 256 条，TTL 8 小时）。
bool tls12_session_cache_lookup(const uint8_t* id, size_t id_len, tls12_session_entry& out);
void tls12_session_cache_store(const tls12_session_entry& entry);

/// 判断 ClientHello 是否可恢复 entry 对应会话（session_id 匹配 + EMS 状态一致）。
bool tls12_session_can_resume(const uint8_t* client_hello, size_t ch_len,
                              const tls12_session_entry& entry);

/// TLS 1.2 缩写握手（会话恢复）：构建 ServerHello 并从缓存主密钥派生密钥。
/// 调用方随后发送 CCS + 加密的 Server Finished。
bool tls12_make_server_resumption_flight(tls_session& s, const uint8_t* client_hello,
                                         size_t ch_len, const tls12_session_entry& entry,
                                         std::vector<uint8_t>& server_hello_out);

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

/// ECDSA 原始签名 (r||s) 与 DER 编码 ECDSA-Sig-Value 互转（RFC 5246 §4.7）。
bool ecdsa_sign_to_der(const uint8_t* raw, size_t raw_len,
                       uint8_t* out, size_t out_cap, size_t& out_len);
bool ecdsa_sig_from_der(const uint8_t* der, size_t der_len,
                        uint8_t* raw, size_t raw_len);

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
} // namespace jpssl