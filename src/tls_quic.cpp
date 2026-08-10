/**
 * tls_quic.cpp — QUIC v1 / v2（RFC 9000 / RFC 9001 / RFC 9369）TLS 层实现
 *
 * 覆盖：
 *   - QUIC varint（RFC 9000 §16）
 *   - quic_transport_parameters 编解码（RFC 9000 §18）
 *   - Initial 数据包保护密钥（RFC 9001 §5.2 / RFC 9369 §3.3）
 *   - Handshake / 1-RTT 数据包保护 key/iv/hp（RFC 9001 §5.1）
 *   - 头部保护掩码（RFC 9001 §5.4 / RFC 9369 §3.3.2）
 *   - 无记录层 TLS 1.3 握手包装（QUIC CRYPTO 帧承载）
 */

#include "tls_quic.hpp"

#include <cstring>
#include <utility>

namespace jpssl::tls {

// ═══════════════════════════════════════════════════════════════════════
//  QUIC varint（RFC 9000 §16）：前 2 bit 决定编码长度 1/2/4/8 字节
// ═══════════════════════════════════════════════════════════════════════
size_t quic_varint_encoded_len(uint64_t v) {
    if (v < 64) return 1;
    if (v < 16384) return 2;
    if (v < (1ull << 30)) return 4;
    return 8;
}

void quic_varint_encode(std::vector<uint8_t>& out, uint64_t v) {
    size_t n = quic_varint_encoded_len(v);
    switch (n) {
        case 1:
            out.push_back((uint8_t)v);
            break;
        case 2:
            out.push_back((uint8_t)(0x40 | (v >> 8)));
            out.push_back((uint8_t)v);
            break;
        case 4:
            out.push_back((uint8_t)(0x80 | (v >> 24)));
            out.push_back((uint8_t)(v >> 16));
            out.push_back((uint8_t)(v >> 8));
            out.push_back((uint8_t)v);
            break;
        default:
            out.push_back((uint8_t)(0xc0 | (v >> 56)));
            out.push_back((uint8_t)(v >> 48));
            out.push_back((uint8_t)(v >> 40));
            out.push_back((uint8_t)(v >> 32));
            out.push_back((uint8_t)(v >> 24));
            out.push_back((uint8_t)(v >> 16));
            out.push_back((uint8_t)(v >> 8));
            out.push_back((uint8_t)v);
            break;
    }
}

bool quic_varint_decode(const uint8_t* p, size_t len, uint64_t& v, size_t& consumed) {
    if (!p || len < 1) return false;
    size_t n = (size_t)(1ull << (p[0] >> 6));
    if (n > len) return false;
    uint64_t val = p[0] & 0x3f;
    for (size_t i = 1; i < n; ++i) val = (val << 8) | p[i];
    v = val;
    consumed = n;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  QUIC 传输参数编解码（RFC 9000 §18）
// ═══════════════════════════════════════════════════════════════════════
static void quic_tp_put_uint(std::vector<uint8_t>& out, uint64_t id, uint64_t val) {
    quic_varint_encode(out, id);
    quic_varint_encode(out, quic_varint_encoded_len(val));
    quic_varint_encode(out, val);
}

static void quic_tp_put_bytes(std::vector<uint8_t>& out, uint64_t id,
                              const std::vector<uint8_t>& val) {
    quic_varint_encode(out, id);
    quic_varint_encode(out, val.size());
    out.insert(out.end(), val.begin(), val.end());
}

static bool quic_tp_get_uint(const uint8_t* val, uint64_t vlen, uint64_t& out) {
    if (!vlen) { out = 0; return true; }
    size_t n;
    return quic_varint_decode(val, vlen, out, n) && n == vlen;
}

std::vector<uint8_t> quic_transport_parameters::encode() const {
    std::vector<uint8_t> out;
    if (!original_destination_connection_id.empty())
        quic_tp_put_bytes(out, 0x00, original_destination_connection_id);
    if (max_idle_timeout) quic_tp_put_uint(out, 0x01, max_idle_timeout);
    if (!stateless_reset_token.empty()) quic_tp_put_bytes(out, 0x02, stateless_reset_token);
    quic_tp_put_uint(out, 0x03, max_udp_payload_size);
    if (initial_max_data) quic_tp_put_uint(out, 0x04, initial_max_data);
    if (initial_max_stream_data_bidi_local)
        quic_tp_put_uint(out, 0x05, initial_max_stream_data_bidi_local);
    if (initial_max_stream_data_bidi_remote)
        quic_tp_put_uint(out, 0x06, initial_max_stream_data_bidi_remote);
    if (initial_max_stream_data_uni) quic_tp_put_uint(out, 0x07, initial_max_stream_data_uni);
    if (initial_max_streams_bidi) quic_tp_put_uint(out, 0x08, initial_max_streams_bidi);
    if (initial_max_streams_uni) quic_tp_put_uint(out, 0x09, initial_max_streams_uni);
    if (ack_delay_exponent != 3) quic_tp_put_uint(out, 0x0a, ack_delay_exponent);
    if (max_ack_delay != 25) quic_tp_put_uint(out, 0x0b, max_ack_delay);
    if (disable_active_migration) {
        quic_varint_encode(out, 0x0c);
        quic_varint_encode(out, 0);   // 零长度值
    }
    if (!preferred_address.empty()) quic_tp_put_bytes(out, 0x0d, preferred_address);
    if (active_connection_id_limit != 2) quic_tp_put_uint(out, 0x0e, active_connection_id_limit);
    // RFC 9000 §18.2：两端都必须发送 initial_source_connection_id（可为空值）
    quic_tp_put_bytes(out, 0x0f, initial_source_connection_id);
    if (!retry_source_connection_id.empty()) quic_tp_put_bytes(out, 0x10, retry_source_connection_id);
    for (const auto& kv : custom) quic_tp_put_bytes(out, kv.first, kv.second);
    return out;
}

bool quic_transport_parameters::decode(const uint8_t* data, size_t len,
                                       quic_transport_parameters& out) {
    out = quic_transport_parameters();
    if (!data && len) return false;
    size_t off = 0;
    while (off < len) {
        uint64_t id = 0, vlen = 0;
        size_t n = 0;
        if (!quic_varint_decode(data + off, len - off, id, n)) return false;
        off += n;
        if (!quic_varint_decode(data + off, len - off, vlen, n)) return false;
        off += n;
        if (vlen > len - off) return false;
        const uint8_t* val = data + off;
        uint64_t v = 0;
        switch (id) {
            case 0x00: out.original_destination_connection_id.assign(val, val + vlen); break;
            case 0x01: if (!quic_tp_get_uint(val, vlen, out.max_idle_timeout)) return false; break;
            case 0x02:
                if (vlen != 16) return false;
                out.stateless_reset_token.assign(val, val + vlen);
                break;
            case 0x03:
                if (!quic_tp_get_uint(val, vlen, v) || v < 1200) return false;
                out.max_udp_payload_size = v;
                break;
            case 0x04: if (!quic_tp_get_uint(val, vlen, out.initial_max_data)) return false; break;
            case 0x05:
                if (!quic_tp_get_uint(val, vlen, out.initial_max_stream_data_bidi_local)) return false;
                break;
            case 0x06:
                if (!quic_tp_get_uint(val, vlen, out.initial_max_stream_data_bidi_remote)) return false;
                break;
            case 0x07:
                if (!quic_tp_get_uint(val, vlen, out.initial_max_stream_data_uni)) return false;
                break;
            case 0x08:
                if (!quic_tp_get_uint(val, vlen, v) || v >= (1ull << 60)) return false;
                out.initial_max_streams_bidi = v;
                break;
            case 0x09:
                if (!quic_tp_get_uint(val, vlen, v) || v >= (1ull << 60)) return false;
                out.initial_max_streams_uni = v;
                break;
            case 0x0a:
                if (!quic_tp_get_uint(val, vlen, v) || v > 20) return false;
                out.ack_delay_exponent = v;
                break;
            case 0x0b:
                if (!quic_tp_get_uint(val, vlen, v) || v >= (1ull << 14)) return false;
                out.max_ack_delay = v;
                break;
            case 0x0c:
                if (vlen != 0) return false;
                out.disable_active_migration = true;
                break;
            case 0x0d: out.preferred_address.assign(val, val + vlen); break;
            case 0x0e:
                if (!quic_tp_get_uint(val, vlen, v) || v < 2) return false;
                out.active_connection_id_limit = v;
                break;
            case 0x0f: out.initial_source_connection_id.assign(val, val + vlen); break;
            case 0x10: out.retry_source_connection_id.assign(val, val + vlen); break;
            default:
                out.custom.push_back({id, std::vector<uint8_t>(val, val + vlen)});
                break;
        }
        off += vlen;
    }
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  QUIC 初始密钥（RFC 9001 §5.2 / RFC 9369 §3.3.1）
// ═══════════════════════════════════════════════════════════════════════
// v1 盐：0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
// v2 盐：0x0dede3def700a6db819381be6e269dcbf9bd2ed9
static const uint8_t QUIC_SALT_V1[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};
static const uint8_t QUIC_SALT_V2[20] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
};

bool tls_quic_derive_initial_secrets(QuicVersion ver, const uint8_t* dst_conn_id,
                                     size_t cid_len, quic_initial_keys& out) {
    if (!dst_conn_id || cid_len == 0 || cid_len > 20) return false;
    const uint8_t* salt = (ver == QuicVersion::V2) ? QUIC_SALT_V2 : QUIC_SALT_V1;
    // initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
    hkdf_extract(salt, 20, dst_conn_id, cid_len, out.initial_secret);
    uint8_t client_secret[32], server_secret[32];
    hkdf_expand_label(out.initial_secret, "client in", nullptr, 0, client_secret, 32);
    hkdf_expand_label(out.initial_secret, "server in", nullptr, 0, server_secret, 32);
    const char* key_label = (ver == QuicVersion::V2) ? "quicv2 key" : "quic key";
    const char* iv_label  = (ver == QuicVersion::V2) ? "quicv2 iv"  : "quic iv";
    const char* hp_label  = (ver == QuicVersion::V2) ? "quicv2 hp"  : "quic hp";
    // Initial 恒用 AEAD_AES_128_GCM + SHA-256：16 字节 key / 12 字节 iv / 16 字节 hp
    hkdf_expand_label(client_secret, key_label, nullptr, 0, out.client.key, 16);
    hkdf_expand_label(client_secret, iv_label,  nullptr, 0, out.client.iv,  12);
    hkdf_expand_label(client_secret, hp_label,  nullptr, 0, out.client.hp,  16);
    hkdf_expand_label(server_secret, key_label, nullptr, 0, out.server.key, 16);
    hkdf_expand_label(server_secret, iv_label,  nullptr, 0, out.server.iv,  12);
    hkdf_expand_label(server_secret, hp_label,  nullptr, 0, out.server.hp,  16);
    out.client.key_len = 16; out.client.hp_len = 16;
    out.server.key_len = 16; out.server.hp_len = 16;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  QUIC 数据包保护密钥（RFC 9001 §5.1 / RFC 9369 §3.3.2）
// ═══════════════════════════════════════════════════════════════════════
static size_t quic_aead_key_len(CipherSuite cs) {
    switch (cs) {
        case CipherSuite::TLS_AES_256_GCM_SHA384:
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            return 32;
        default:
            return 16;
    }
}

bool tls_quic_derive_packet_keys(const uint8_t* secret, size_t secret_len,
                                 QuicVersion ver, CipherSuite cs, quic_packet_keys& out) {
    if (!secret) return false;
    bool use384 = tls_use_sha384(cs);
    if (secret_len < (use384 ? 48 : 32)) return false;
    // v1 标签："quic key/iv/hp"；v2 标签："quicv2 key/iv/hp"（RFC 9369 §3.3.2）
    const char* key_label = (ver == QuicVersion::V2) ? "quicv2 key" : "quic key";
    const char* iv_label  = (ver == QuicVersion::V2) ? "quicv2 iv"  : "quic iv";
    const char* hp_label  = (ver == QuicVersion::V2) ? "quicv2 hp"  : "quic hp";
    size_t kl = quic_aead_key_len(cs);
    out.key_len = kl; out.hp_len = kl;
    bool use_sm3 = tls_use_sm3(cs);
    if (use384) {
        hkdf_expand_label_sha384(secret, key_label, nullptr, 0, out.key, kl);
        hkdf_expand_label_sha384(secret, iv_label,  nullptr, 0, out.iv,  12);
        hkdf_expand_label_sha384(secret, hp_label,  nullptr, 0, out.hp,  kl);
    } else if (use_sm3) {
        hkdf_expand_label_sm3(secret, key_label, nullptr, 0, out.key, kl);
        hkdf_expand_label_sm3(secret, iv_label,  nullptr, 0, out.iv,  12);
        hkdf_expand_label_sm3(secret, hp_label,  nullptr, 0, out.hp,  kl);
    } else {
        hkdf_expand_label(secret, key_label, nullptr, 0, out.key, kl);
        hkdf_expand_label(secret, iv_label,  nullptr, 0, out.iv,  12);
        hkdf_expand_label(secret, hp_label,  nullptr, 0, out.hp,  kl);
    }
    return true;
}

bool tls_quic_get_handshake_keys(tls_session& s, QuicVersion ver,
                                 quic_packet_keys& client, quic_packet_keys& server) {
    if (!s.quic_hs_secrets_ready || !s.quic_secrets) return false;
    size_t hl = tls_hash_len(s.cipher_suite);
    if (!tls_quic_derive_packet_keys(s.quic_secrets->client_hs, hl, ver, s.cipher_suite, client))
        return false;
    return tls_quic_derive_packet_keys(s.quic_secrets->server_hs, hl, ver, s.cipher_suite, server);
}

bool tls_quic_get_application_keys(tls_session& s, QuicVersion ver,
                                   quic_packet_keys& client, quic_packet_keys& server) {
    if (!s.quic_app_secrets_ready || !s.quic_secrets) return false;
    size_t hl = tls_hash_len(s.cipher_suite);
    if (!tls_quic_derive_packet_keys(s.quic_secrets->client_app, hl, ver, s.cipher_suite, client))
        return false;
    return tls_quic_derive_packet_keys(s.quic_secrets->server_app, hl, ver, s.cipher_suite, server);
}

// ═══════════════════════════════════════════════════════════════════════
//  QUIC 头部保护掩码（RFC 9001 §5.4）
// ═══════════════════════════════════════════════════════════════════════
bool tls_quic_header_protection_mask(CipherSuite cs, const uint8_t* hp_key, size_t hp_len,
                                     const uint8_t* sample, size_t sample_len,
                                     uint8_t* mask, size_t mask_len) {
    if (!hp_key || !sample || mask_len == 0 || mask_len > 5) return false;
    if (cs == CipherSuite::TLS_CHACHA20_POLY1305_SHA256) {
        // RFC 9001 §5.4.4：counter = sample[0..3]（小端），nonce = sample[4..15]
        if (hp_len != 32 || sample_len < 16) return false;
        uint32_t counter = (uint32_t)sample[0] | ((uint32_t)sample[1] << 8) |
                           ((uint32_t)sample[2] << 16) | ((uint32_t)sample[3] << 24);
        uint8_t nonce[12];
        memcpy(nonce, sample + 4, 12);
        uint8_t block[64];
        chacha20_block(hp_key, counter, nonce, block);
        memcpy(mask, block, mask_len);
        return true;
    }
    // AES 套件（AES-128/256）：mask = AES-ECB(hp_key, sample)[0..mask_len]
    if ((hp_len != 16 && hp_len != 32) || sample_len < 16) return false;
    aes_context ctx;
    if (hp_len == 32) ctx.init(std::span<const uint8_t, 32>(hp_key, 32));
    else ctx.init(std::span<const uint8_t, 16>(hp_key, 16));
    uint8_t cipher[16];
    aes_encrypt_block(ctx, sample, cipher);
    memcpy(mask, cipher, mask_len);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  QUIC TLS 1.3 握手（无记录层；消息经 CRYPTO 帧承载）
// ═══════════════════════════════════════════════════════════════════════
bool tls_quic_make_client_hello(tls_session& s, std::vector<uint8_t>& client_hello) {
    s.quic_mode = true;
    return tls13_make_client_hello(s, client_hello);
}

bool tls_quic_make_server_flight(tls_session& s, const uint8_t* ch, size_t ch_len,
                                 std::vector<uint8_t>& server_flight,
                                 const tls_certificate_manager& cert_manager) {
    s.quic_mode = true;
    return tls13_make_server_flight(s, ch, ch_len, server_flight, cert_manager);
}

bool tls_quic_process_server_flight(tls_session& s, const uint8_t* data, size_t len,
                                    std::vector<uint8_t>& client_finished,
                                    const tls_trust_store* trust_store) {
    s.quic_mode = true;
    return tls13_process_server_flight(s, data, len, client_finished, nullptr, trust_store);
}

bool tls_quic_process_client_finished(tls_session& s, const uint8_t* data, size_t len) {
    s.quic_mode = true;
    return tls13_process_client_finished(s, data, len);
}

} // namespace jpssl::tls
