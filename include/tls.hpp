#pragma once
/** tls.hpp — TLS 1.2/1.3 完整握手流程 + SNI 多域名证书切换 */
#include "aes.hpp"
#include "chacha20_poly1305.hpp"
#include "sha256.hpp"
#include "hkdf.hpp"
#include "hmac.hpp"
#include "x25519.hpp"
#include "ed25519.hpp"
#include "ecdsa.hpp"
#include "rsa.hpp"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <memory>
namespace jpssl::tls {

enum class TLSVersion { V12=0x0303, V13=0x0304 };
enum class ContentType { CHANGE_CIPHER_SPEC=20, ALERT=21, HANDSHAKE=22, APPLICATION_DATA=23 };
enum class HandshakeType { CLIENT_HELLO=1, SERVER_HELLO=2, ENCRYPTED_EXTENSIONS=8, CERTIFICATE=11, CERT_VERIFY=15, FINISHED=20 };
enum class ExtensionType { SERVER_NAME=0, SUPPORTED_VERSIONS=0x2b, KEY_SHARE=0x33, SUPPORTED_GROUPS=0x0a };
enum class SignatureAlgorithm { RSA_PKCS1_SHA256=0x0401, ECDSA_SECP256R1_SHA256=0x0403, ED25519=0x0807 };

struct tls_record { ContentType type; TLSVersion ver; std::vector<uint8_t> payload; };

// ═══════════════════════════════════════════════════════════════════════
//  TLS 会话状态
// ═══════════════════════════════════════════════════════════════════════
struct tls_session {
    TLSVersion ver;
    std::string server_name; // SNI: 客户端请求的服务器名称
    uint8_t client_random[32], server_random[32];
    uint8_t handshake_secret[32], master_secret[32];
    uint8_t client_write_key[32], server_write_key[32];
    uint8_t client_write_iv[12], server_write_iv[12];
    uint64_t client_seq, server_seq;
    aes_context aes_ctx;

    bool is_server = false;
    sha256_ctx transcript_ctx; // TLS 1.3 握手 transcript 哈希
    uint8_t transcript_hash[32]; // 已计算的 transcript 哈希
    bool transcript_ready = false;
};

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
        uint8_t ecdsa_p256[64];
    } pub;
    // 私钥
    union PrivateKey {
        PrivateKey() : rsa{} {}
        rsa_private_key rsa;
        uint8_t ed25519[64];
        uint8_t ecdsa_p256[32];
    } priv;
    SignatureAlgorithm sig_alg;

    bool sign(const uint8_t* data, size_t data_len, uint8_t* sig, size_t& sig_len) const;
    bool verify(const uint8_t* data, size_t data_len, const uint8_t* sig, size_t sig_len) const;
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
//  TLS 1.2 完整握手 API
// ═══════════════════════════════════════════════════════════════════════

// 客户端: 生成 ClientHello
bool tls12_make_client_hello(tls_session& s, std::vector<uint8_t>& client_hello);

// 客户端: 处理服务端回包，生成 Finished
bool tls12_process_server_flight(tls_session& s, const uint8_t* server_response, size_t resp_len,
                                  const uint8_t* pre_master_secret, size_t pms_len,
                                  std::vector<uint8_t>& client_finished);

// 服务端: 处理 ClientHello 并生成完整回包
// encrypted_pms: 客户端用 RSA 公钥加密的 pre_master_secret（RSA_PKCS1_SHA256 证书时使用）
// 若为 nullptr 则直接使用 pre_master_secret 中的明文（兼容旧测试）
bool tls12_make_server_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                               std::vector<uint8_t>& server_response,
                               const uint8_t* encrypted_pms, size_t epms_len,
                               uint8_t pre_master_secret[48],
                               const tls_certificate_manager& cert_manager);

// 服务端: 处理客户端 Finished
bool tls12_process_client_finished(tls_session& s, const uint8_t* data, size_t len);

// 简化版（兼容旧 API）
bool tls12_handshake_client(tls_session& s, std::vector<uint8_t>& client_hello,
                             const uint8_t* server_response, size_t resp_len,
                             const uint8_t* pre_master_secret, size_t pms_len);
bool tls12_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                             std::vector<uint8_t>& server_response,
                             const uint8_t* encrypted_pms, size_t epms_len,
                             uint8_t pre_master_secret[48],
                             const tls_certificate_manager& cert_manager);

void tls12_derive_keys(tls_session& s, const uint8_t pre_master[48]);

// ═══════════════════════════════════════════════════════════════════════
//  记录层加密/解密
// ═══════════════════════════════════════════════════════════════════════
std::vector<uint8_t> tls_encrypt(tls_session& s, ContentType ct, const uint8_t* data, size_t len);
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
//  辅助函数
// ═══════════════════════════════════════════════════════════════════════
void tls_transcript_update(tls_session& s, const uint8_t* data, size_t len);
void tls_transcript_finalize(tls_session& s);

}