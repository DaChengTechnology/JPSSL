#pragma once

/**
 * tls_quic.hpp — QUIC v1 / v2（RFC 9000 / RFC 9001 / RFC 9369）TLS 层 API
 *
 * QUIC 不使用 TLS 记录层：握手消息直接以原始 TLS Handshake 字节流交付，
 * 由 QUIC 层封装进 CRYPTO 帧并在 QUIC 数据包保护下传输；应用数据由 QUIC
 * 层（STREAM 帧）加密，不经过 TLS。本模块提供 QUIC 所需的全部 TLS 支持：
 *
 *   - quic_transport_parameters 扩展（RFC 9001 §8.2，TLS 扩展 0x0039）
 *   - 无记录层握手（ClientHello / ServerHello+EE+Cert+CV+Finished）
 *   - Initial / Handshake / 1-RTT 数据包保护密钥派生（RFC 9001 §5.1/§5.2）
 *   - 头部保护掩码（RFC 9001 §5.4）
 *   - QUIC varint（RFC 9000 §16）
 *
 * v1 与 v2 的 TLS 握手完全一致，区别仅在初始盐、密钥派生标签（RFC 9369
 * §3.3）与线格式版本号；`QuicVersion` 参数区分二者。
 *
 * 本头文件独立于 tls.hpp 的其余部分：包含 "tls.hpp" 以复用 tls_session、
 * quic_transport_parameters 等类型。
 */

#include "tls.hpp"

#include <cstdint>
#include <vector>

namespace jpssl::tls {

// QUIC varint 编解码（RFC 9000 §16），供传输参数解析及 QUIC 层复用。
size_t quic_varint_encoded_len(uint64_t v);
void   quic_varint_encode(std::vector<uint8_t>& out, uint64_t v);
bool   quic_varint_decode(const uint8_t* p, size_t len, uint64_t& v, size_t& consumed);

/// 派生 QUIC Initial 数据包保护密钥（RFC 9001 §5.2 / RFC 9369 §3.3）。
/// 恒用 SHA-256 + AEAD_AES_128_GCM；dst_conn_id 为客户端首个 Initial 包中的
/// Destination Connection ID（1..20 字节）。v1/v2 使用不同初始盐。
bool tls_quic_derive_initial_secrets(QuicVersion ver, const uint8_t* dst_conn_id,
                                     size_t cid_len, quic_initial_keys& out);

/// 由 QUIC traffic secret（handshake/application "client in"/"server in"）
/// 派生数据包保护 key/iv/hp（RFC 9001 §5.1）。v1 用 "quic key/iv/hp"，
/// v2 用 "quicv2 key/iv/hp"（RFC 9369 §3.3.2）。
bool tls_quic_derive_packet_keys(const uint8_t* secret, size_t secret_len,
                                 QuicVersion ver, CipherSuite cs, quic_packet_keys& out);

/// 取握手阶段数据包保护密钥（在服务端处理完 ClientHello、客户端处理完
/// ServerHello 之后调用）。
bool tls_quic_get_handshake_keys(tls_session& s, QuicVersion ver,
                                 quic_packet_keys& client, quic_packet_keys& server);
/// 取 1-RTT（应用数据）数据包保护密钥（握手完成后调用）。
bool tls_quic_get_application_keys(tls_session& s, QuicVersion ver,
                                   quic_packet_keys& client, quic_packet_keys& server);

/// 计算 QUIC 头部保护掩码（RFC 9001 §5.4）：
///   AES 套件：mask = AES-ECB(hp_key, sample)[0..mask_len]
///   ChaCha20 套件：counter = sample[0..3]（小端），nonce = sample[4..15]，
///     mask = ChaCha20(hp_key, counter, nonce)[0..mask_len]
/// mask_len 最长 5（短头包）。成功返回 true。
bool tls_quic_header_protection_mask(CipherSuite cs, const uint8_t* hp_key, size_t hp_len,
                                     const uint8_t* sample, size_t sample_len,
                                     uint8_t* mask, size_t mask_len);

/// 客户端：生成 QUIC 模式的 TLS 1.3 ClientHello（自动携带
/// quic_transport_parameters 扩展，RFC 9001 §8.2）。
/// 返回原始握手消息字节（无记录层），由 QUIC 层封装为 CRYPTO 帧。
/// 调用前设置 s.quic_mode = true、s.quic_version 并填充 s.quic_transport_params。
bool tls_quic_make_client_hello(tls_session& s, std::vector<uint8_t>& client_hello);

/// 服务端：处理 QUIC 客户端 ClientHello 并生成完整回包
/// （ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished）。
/// 返回原始握手消息字节（无记录层）；EncryptedExtensions 携带本端传输参数。
/// 客户端必须提供 quic_transport_parameters 扩展，否则握手失败（RFC 9001 §8.2）。
bool tls_quic_make_server_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                                 std::vector<uint8_t>& server_flight,
                                 const tls_certificate_manager& cert_manager);

/// 客户端：处理服务端回包并生成 Client Finished。
/// data 为原始握手消息字节（ServerHello 明文 + 加密握手消息明文，无记录层）。
/// trust_store 提供时对服务端证书链执行 x509 链验证。
bool tls_quic_process_server_flight(tls_session& s, const uint8_t* data, size_t len,
                                    std::vector<uint8_t>& client_finished,
                                    const tls_trust_store* trust_store = nullptr);

/// 服务端：验证客户端 Finished（data 为原始握手消息字节）。
bool tls_quic_process_client_finished(tls_session& s, const uint8_t* data, size_t len);

// QUIC 模式便捷包装（等价于 tls13_* 但强制 quic_mode）
inline bool tls13_make_quic_client_hello(tls_session& s, std::vector<uint8_t>& out) {
    s.quic_mode = true;
    return tls_quic_make_client_hello(s, out);
}
inline bool tls13_make_quic_server_flight(tls_session& s, const uint8_t* ch, size_t ch_len,
                                          std::vector<uint8_t>& out,
                                          const tls_certificate_manager& cert_mgr) {
    s.quic_mode = true;
    return tls_quic_make_server_flight(s, ch, ch_len, out, cert_mgr);
}
inline bool tls13_process_quic_server_flight(tls_session& s, const uint8_t* data, size_t len,
                                             std::vector<uint8_t>& cf,
                                             const tls_trust_store* trust_store = nullptr) {
    s.quic_mode = true;
    return tls_quic_process_server_flight(s, data, len, cf, trust_store);
}
inline bool tls13_process_quic_client_finished(tls_session& s, const uint8_t* data, size_t len) {
    s.quic_mode = true;
    return tls_quic_process_client_finished(s, data, len);
}

} // namespace jpssl::tls
