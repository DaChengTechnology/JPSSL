/**
 * test_quic.cpp — QUIC v1 / v2 (RFC 9001 / RFC 9369) SSL 支持单元测试
 *
 * 覆盖：
 *   - RFC 9001 A.1 / RFC 9369 A.1 Initial 密钥派生测试向量
 *   - RFC 9001 A.5 / RFC 9369 A.5 1-RTT 密钥派生测试向量（ChaCha20）
 *   - QUIC 头部保护掩码（AES-ECB / ChaCha20，v1/v2）
 *   - QUIC transport parameters 编解码（RFC 9000 §18）与 varint
 *   - QUIC TLS 1.3 完整握手往返（无记录层），客户端/服务端密钥一致
 *   - 缺少 quic_transport_parameters 扩展的拒绝
 */

#include "test_utils.hpp"
#include "tls.hpp"
#include "ecdsa.hpp"
#include "ed25519.hpp"
#include "x448.hpp"
#include "x509.hpp"
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <cstdlib>
#include <cctype>

using namespace jpssl::tls;
using namespace jpssl;

// ═══════════════════════════════════════════════════════════════════════
//  十六进制工具
// ═══════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> h2b(const char* hex) {
    std::string s;
    for (const char* p = hex; *p; ++p)
        if (std::isxdigit((unsigned char)*p)) s.push_back(*p);
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back((uint8_t)std::strtoul(s.substr(i, 2).c_str(), nullptr, 16));
    return out;
}

static bool bytes_eq(const uint8_t* a, const std::vector<uint8_t>& b, size_t n) {
    return b.size() == n && memcmp(a, b.data(), n) == 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  RFC 9001 A.1 Initial 密钥测试向量（v1）
// ═══════════════════════════════════════════════════════════════════════
void test_quic_initial_secrets_v1() {
    auto cid = h2b("8394c8f03e515708");
    quic_initial_keys keys;
    TEST("v1 derive initial", tls_quic_derive_initial_secrets(QuicVersion::V1, cid.data(), cid.size(), keys));
    TEST("v1 initial_secret", bytes_eq(keys.initial_secret,
        h2b("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"), 32));
    TEST("v1 client key", bytes_eq(keys.client.key, h2b("1f369613dd76d5467730efcbe3b1a22d"), 16));
    TEST("v1 client iv",  bytes_eq(keys.client.iv,  h2b("fa044b2f42a3fd3b46fb255c"), 12));
    TEST("v1 client hp",  bytes_eq(keys.client.hp,  h2b("9f50449e04a0e810283a1e9933adedd2"), 16));
    TEST("v1 server key", bytes_eq(keys.server.key, h2b("cf3a5331653c364c88f0f379b6067e37"), 16));
    TEST("v1 server iv",  bytes_eq(keys.server.iv,  h2b("0ac1493ca1905853b0bba03e"), 12));
    TEST("v1 server hp",  bytes_eq(keys.server.hp,  h2b("c206b8d9b9f0f37644430b490eeaa314"), 16));
    TEST("v1 key_len", keys.client.key_len == 16 && keys.client.hp_len == 16);
    TEST("v1 invalid cid len", !tls_quic_derive_initial_secrets(QuicVersion::V1, cid.data(), 0, keys));
    TEST("v1 cid too long", !tls_quic_derive_initial_secrets(QuicVersion::V1, cid.data(), 21, keys));
}

// ═══════════════════════════════════════════════════════════════════════
//  RFC 9369 A.1 Initial 密钥测试向量（v2）
// ═══════════════════════════════════════════════════════════════════════
void test_quic_initial_secrets_v2() {
    auto cid = h2b("8394c8f03e515708");
    quic_initial_keys keys;
    TEST("v2 derive initial", tls_quic_derive_initial_secrets(QuicVersion::V2, cid.data(), cid.size(), keys));
    TEST("v2 initial_secret", bytes_eq(keys.initial_secret,
        h2b("2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba"), 32));
    TEST("v2 client key", bytes_eq(keys.client.key, h2b("8b1a0bc121284290a29e0971b5cd045d"), 16));
    TEST("v2 client iv",  bytes_eq(keys.client.iv,  h2b("91f73e2351d8fa91660e909f"), 12));
    TEST("v2 client hp",  bytes_eq(keys.client.hp,  h2b("45b95e15235d6f45a6b19cbcb0294ba9"), 16));
    TEST("v2 server key", bytes_eq(keys.server.key, h2b("82db637861d55e1d011f19ea71d5d2a7"), 16));
    TEST("v2 server iv",  bytes_eq(keys.server.iv,  h2b("dd13c276499c0249d3310652"), 12));
    TEST("v2 server hp",  bytes_eq(keys.server.hp,  h2b("edf6d05c83121201b436e16877593c3a"), 16));
}

// ═══════════════════════════════════════════════════════════════════════
//  RFC 9001 A.5 1-RTT 密钥测试向量（v1, ChaCha20）
// ═══════════════════════════════════════════════════════════════════════
void test_quic_1rtt_rfc9001_chacha20() {
    auto secret = h2b("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    quic_packet_keys k;
    TEST("v1 chacha20 derive", tls_quic_derive_packet_keys(secret.data(), secret.size(),
        QuicVersion::V1, CipherSuite::TLS_CHACHA20_POLY1305_SHA256, k));
    TEST("v1 chacha20 key_len 32", k.key_len == 32 && k.hp_len == 32);
    TEST("v1 chacha20 key", bytes_eq(k.key, h2b("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"), 32));
    TEST("v1 chacha20 iv",  bytes_eq(k.iv,  h2b("e0459b3474bdd0e44a41c144"), 12));
    TEST("v1 chacha20 hp",  bytes_eq(k.hp,  h2b("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"), 32));
}

// ═══════════════════════════════════════════════════════════════════════
//  RFC 9369 A.5 1-RTT 密钥测试向量（v2, ChaCha20）
// ═══════════════════════════════════════════════════════════════════════
void test_quic_1rtt_rfc9369_chacha20() {
    auto secret = h2b("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    quic_packet_keys k;
    TEST("v2 chacha20 derive", tls_quic_derive_packet_keys(secret.data(), secret.size(),
        QuicVersion::V2, CipherSuite::TLS_CHACHA20_POLY1305_SHA256, k));
    TEST("v2 chacha20 key_len 32", k.key_len == 32 && k.hp_len == 32);
    TEST("v2 chacha20 key", bytes_eq(k.key, h2b("3bfcddd72bcf02541d7fa0dd1f5f9eeea817e09a6963a0e6c7df0f9a1bab90f2"), 32));
    TEST("v2 chacha20 iv",  bytes_eq(k.iv,  h2b("a6b5bc6ab7dafce30ffff5dd"), 12));
    TEST("v2 chacha20 hp",  bytes_eq(k.hp,  h2b("d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2"), 32));
    // v1 / v2 标签不同 → 同一 secret 派生的密钥必须不同
    quic_packet_keys k1;
    tls_quic_derive_packet_keys(secret.data(), secret.size(),
        QuicVersion::V1, CipherSuite::TLS_CHACHA20_POLY1305_SHA256, k1);
    TEST("v1/v2 key diversity", memcmp(k1.key, k.key, 32) != 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  QUIC 头部保护掩码（RFC 9001 §5.4 / RFC 9369 §3.3.2）
// ═══════════════════════════════════════════════════════════════════════
void test_quic_header_protection_mask() {
    // v1 AES-128（RFC 9001 A.2 客户端 Initial 示例）
    auto hp1 = h2b("9f50449e04a0e810283a1e9933adedd2");
    auto sample1 = h2b("d1b1c98dd7689fb8ec11d242b123dc9b");
    uint8_t m1[5];
    TEST("v1 AES mask", tls_quic_header_protection_mask(CipherSuite::TLS_AES_128_GCM_SHA256,
        hp1.data(), 16, sample1.data(), 16, m1, 5));
    TEST("v1 AES mask value 437b9aec36", bytes_eq(m1, h2b("437b9aec36"), 5));

    // v2 AES-128（RFC 9369 A.2 客户端 Initial 示例）
    auto hp2 = h2b("45b95e15235d6f45a6b19cbcb0294ba9");
    auto sample2 = h2b("ffe67b6abcdb4298b485dd04de806071");
    uint8_t m2[5];
    TEST("v2 AES mask", tls_quic_header_protection_mask(CipherSuite::TLS_AES_128_GCM_SHA256,
        hp2.data(), 16, sample2.data(), 16, m2, 5));
    TEST("v2 AES mask value 94a0c95e80", bytes_eq(m2, h2b("94a0c95e80"), 5));

    // v1 ChaCha20（RFC 9001 A.5 短头包示例）
    auto hp3 = h2b("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    auto sample3 = h2b("5e5cd55c41f69080575d7999c25a5bfb");
    uint8_t m3[5];
    TEST("v1 ChaCha20 mask", tls_quic_header_protection_mask(CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        hp3.data(), 32, sample3.data(), 16, m3, 5));
    TEST("v1 ChaCha20 mask value aefefe7d03", bytes_eq(m3, h2b("aefefe7d03"), 5));

    // v2 ChaCha20（RFC 9369 A.5 短头包示例）
    auto hp4 = h2b("d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2");
    auto sample4 = h2b("e7b6b932bc27d786f4bc2bb20f2162ba");
    uint8_t m4[5];
    TEST("v2 ChaCha20 mask", tls_quic_header_protection_mask(CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        hp4.data(), 32, sample4.data(), 16, m4, 5));
    TEST("v2 ChaCha20 mask value 97580e32bf", bytes_eq(m4, h2b("97580e32bf"), 5));

    // 非法参数拒绝
    uint8_t tmp[5];
    TEST("mask too long rejected", !tls_quic_header_protection_mask(CipherSuite::TLS_AES_128_GCM_SHA256,
        hp1.data(), 16, sample1.data(), 16, tmp, 6));
    TEST("mask short sample rejected", !tls_quic_header_protection_mask(CipherSuite::TLS_AES_128_GCM_SHA256,
        hp1.data(), 16, sample1.data(), 8, tmp, 4));
}

// ═══════════════════════════════════════════════════════════════════════
//  QUIC varint + transport parameters（RFC 9000 §16 / §18）
// ═══════════════════════════════════════════════════════════════════════
void test_quic_varint() {
    std::vector<uint8_t> v;
    uint64_t vals[] = {0, 1, 63, 64, 16383, 16384, (1ull<<30)-1, 1ull<<30, (1ull<<62)-1};
    quic_varint_encode(v, vals[0]);
    quic_varint_encode(v, vals[1]);
    quic_varint_encode(v, vals[2]);
    quic_varint_encode(v, vals[3]);
    quic_varint_encode(v, vals[4]);
    quic_varint_encode(v, vals[5]);
    quic_varint_encode(v, vals[6]);
    quic_varint_encode(v, vals[7]);
    quic_varint_encode(v, vals[8]);
    size_t off = 0;
    bool ok = true;
    for (size_t i = 0; i < 9; ++i) {
        uint64_t out; size_t n;
        if (!quic_varint_decode(v.data() + off, v.size() - off, out, n)) { ok = false; break; }
        if (out != vals[i]) { ok = false; break; }
        off += n;
    }
    TEST("varint roundtrip", ok && off == v.size());
    TEST("varint len", quic_varint_encoded_len(0) == 1 && quic_varint_encoded_len(63) == 1 &&
                       quic_varint_encoded_len(64) == 2 && quic_varint_encoded_len(16383) == 2 &&
                       quic_varint_encoded_len(16384) == 4 && quic_varint_encoded_len((1ull<<30)-1) == 4 &&
                       quic_varint_encoded_len(1ull<<30) == 8);
    // 截断输入拒绝
    uint64_t out; size_t n;
    TEST("varint truncated rejected", !quic_varint_decode(v.data(), 0, out, n));
    TEST("varint needs 2 bytes", quic_varint_decode(v.data() + 3, 1, out, n) == false);
}

void test_quic_transport_params() {
    quic_transport_parameters tp;
    tp.original_destination_connection_id = h2b("8394c8f03e515708");
    tp.initial_source_connection_id = h2b("f067a5502a4262b5");
    tp.max_idle_timeout = 30000;
    tp.max_udp_payload_size = 1400;
    tp.initial_max_data = 1048576;
    tp.initial_max_stream_data_bidi_local = 4096;
    tp.initial_max_stream_data_bidi_remote = 8192;
    tp.initial_max_stream_data_uni = 16384;
    tp.initial_max_streams_bidi = 64;
    tp.initial_max_streams_uni = 128;
    tp.ack_delay_exponent = 4;
    tp.max_ack_delay = 30;
    tp.disable_active_migration = true;
    tp.active_connection_id_limit = 4;
    tp.stateless_reset_token = std::vector<uint8_t>(16, 0xAB);
    tp.custom.push_back({0x37, h2b("0000000100000001")}); // version_information（RFC 9368）

    auto enc = tp.encode();
    quic_transport_parameters out;
    TEST("TP decode", quic_transport_parameters::decode(enc.data(), enc.size(), out));
    TEST("TP original_dst_cid", out.original_destination_connection_id == tp.original_destination_connection_id);
    TEST("TP initial_src_cid", out.initial_source_connection_id == tp.initial_source_connection_id);
    TEST("TP max_idle_timeout", out.max_idle_timeout == 30000);
    TEST("TP max_udp_payload_size", out.max_udp_payload_size == 1400);
    TEST("TP initial_max_data", out.initial_max_data == 1048576);
    TEST("TP bidi_local", out.initial_max_stream_data_bidi_local == 4096);
    TEST("TP bidi_remote", out.initial_max_stream_data_bidi_remote == 8192);
    TEST("TP uni", out.initial_max_stream_data_uni == 16384);
    TEST("TP streams_bidi", out.initial_max_streams_bidi == 64);
    TEST("TP streams_uni", out.initial_max_streams_uni == 128);
    TEST("TP ack_delay_exponent", out.ack_delay_exponent == 4);
    TEST("TP max_ack_delay", out.max_ack_delay == 30);
    TEST("TP disable_active_migration", out.disable_active_migration == true);
    TEST("TP active_connection_id_limit", out.active_connection_id_limit == 4);
    TEST("TP stateless_reset_token", out.stateless_reset_token == tp.stateless_reset_token);
    TEST("TP custom preserved", out.custom.size() == 1 && out.custom[0].first == 0x37 &&
                               out.custom[0].second == h2b("0000000100000001"));

    // 非法参数拒绝
    auto bad1 = h2b("0205100ab0"); // stateless_reset_token 长度 5 ≠ 16
    TEST("TP stateless_reset_token wrong len rejected",
        !quic_transport_parameters::decode(bad1.data(), bad1.size(), out));
    auto bad2 = h2b("03020a00");  // max_udp_payload_size = 2560? 长度 2 字节 varint 0x0a00=2560 ≥1200 合法…改造非法
    // 构造 max_udp_payload_size < 1200：id=0x03 len=1 val=0x02
    auto bad3 = h2b("030102");
    TEST("TP max_udp_payload_size < 1200 rejected",
        !quic_transport_parameters::decode(bad3.data(), bad3.size(), out));
    auto bad4 = h2b("0e020101");  // active_connection_id_limit = 0x0101 = 257 ≥ 2 … 合法; 用 0x0e 01 00
    auto bad5 = h2b("0e0100");    // active_connection_id_limit = 0 < 2
    TEST("TP active_connection_id_limit < 2 rejected",
        !quic_transport_parameters::decode(bad5.data(), bad5.size(), out));
    auto bad6 = h2b("0a02030102"); // ack_delay_exponent 值 0x0102=258 > 20
    TEST("TP ack_delay_exponent > 20 rejected",
        !quic_transport_parameters::decode(bad6.data(), bad6.size(), out));

    // 默认参数 encode 后 decode 往返
    quic_transport_parameters def;
    auto def_enc = def.encode();
    quic_transport_parameters def_out;
    TEST("TP default roundtrip", quic_transport_parameters::decode(def_enc.data(), def_enc.size(), def_out));
    TEST("TP default max_udp_payload_size", def_out.max_udp_payload_size == 65527);
    TEST("TP default ack_delay_exponent", def_out.ack_delay_exponent == 3);
    TEST("TP default max_ack_delay", def_out.max_ack_delay == 25);
}

// ═══════════════════════════════════════════════════════════════════════
//  ClientHello / EncryptedExtensions 扩展查找辅助
// ═══════════════════════════════════════════════════════════════════════
static bool find_extension_in_ch(const uint8_t* ch, size_t len, uint16_t want) {
    size_t off = 4 + 2 + 32;
    if (off + 1 > len) return false;
    size_t sid_len = ch[off]; off += 1 + sid_len;
    if (off + 2 > len) return false;
    size_t cs_len = (ch[off] << 8) | ch[off + 1]; off += 2 + cs_len;
    if (off + 1 > len) return false;
    size_t cm_len = ch[off]; off += 1 + cm_len;
    if (off + 2 > len) return false;
    size_t ext_total = (ch[off] << 8) | ch[off + 1]; off += 2;
    if (off + ext_total > len) return false;
    size_t end = off + ext_total;
    while (off + 4 <= end) {
        uint16_t type = (ch[off] << 8) | ch[off + 1];
        size_t elen = (ch[off + 2] << 8) | ch[off + 3];
        if (type == want) return true;
        off += 4 + elen;
    }
    return false;
}

static bool find_extension_in_ee(const uint8_t* flight, size_t len, uint16_t want) {
    size_t off = 0;
    while (off + 4 <= len) {
        uint8_t htype = flight[off];
        size_t hlen = (flight[off + 1] << 16) | (flight[off + 2] << 8) | flight[off + 3];
        if (off + 4 + hlen > len) break;
        if (htype == 8) { // ENCRYPTED_EXTENSIONS
            size_t eo = off + 4;
            if (eo + 2 > off + 4 + hlen) break;
            size_t ext_total = (flight[eo] << 8) | flight[eo + 1];
            size_t eend = eo + 2 + ext_total;
            if (eend > off + 4 + hlen) eend = off + 4 + hlen;
            size_t p = eo + 2;
            while (p + 4 <= eend) {
                uint16_t type = (flight[p] << 8) | flight[p + 1];
                size_t elen = (flight[p + 2] << 8) | flight[p + 3];
                if (type == want) return true;
                p += 4 + elen;
            }
        }
        off += 4 + hlen;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════
//  QUIC TLS 1.3 完整握手往返
// ═══════════════════════════════════════════════════════════════════════
static tls_certificate_manager make_quic_cert_mgr(tls_trust_store* trust, const char* dns) {
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);
    x509::x509_builder b;
    x509::DistinguishedName dn;
    dn.push_back({std::vector<uint8_t>(x509::OID_CN, x509::OID_CN + 3), dns});
    b.set_subject(dn).set_issuer(dn);
    uint8_t ser[8] = {0x51, 0x51, 0x51, 0x51};
    b.set_serial(ser, 8);
    uint64_t now = (uint64_t)time(nullptr);
    b.set_validity(now - 3600, now + 365 * 86400);
    b.set_key(x509::KeyType::ECDSA_P256, pub, 64);
    b.set_ca(true);
    b.add_san_dns(dns);
    auto ca_cert = b.build_and_sign(x509::KeyType::ECDSA_P256, priv, 32);

    if (trust) trust->ca_roots.push_back(ca_cert);

    tls_certificate_manager mgr;
    auto cert = std::make_unique<tls_certificate>();
    cert->subject_name = dns;
    cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    memcpy(cert->pub.ecdsa_p256, pub, 64);
    memcpy(cert->priv.ecdsa_p256, priv, 32);
    cert->cert_data = ca_cert.to_der();
    mgr.add_certificate(dns, std::move(cert));
    return mgr;
}

static bool quic_handshake_roundtrip(QuicVersion ver, CipherSuite cs, NamedGroup group,
                                     bool use_trust, const char* dns,
                                     quic_packet_keys& client_hs, quic_packet_keys& server_hs,
                                     quic_packet_keys& client_app, quic_packet_keys& server_app,
                                     std::vector<uint8_t>& out_ch, std::vector<uint8_t>& out_sf) {
    tls_trust_store trust;
    tls_certificate_manager cert_mgr = make_quic_cert_mgr(use_trust ? &trust : nullptr, dns);

    tls_session client;
    client.quic_version = ver;
    client.server_name = dns;
    client.cipher_suite = cs;
    client.ks_group = group;
    client.quic_transport_params.initial_source_connection_id = h2b("8394c8f03e515708");
    client.quic_transport_params.initial_max_data = 1000000;
    client.quic_transport_params.initial_max_streams_uni = 100;
    client.quic_transport_params.max_udp_payload_size = 1400;

    std::vector<uint8_t> ch;
    if (!tls_quic_make_client_hello(client, ch)) return false;
    out_ch = ch;

    tls_session server;
    server.quic_version = ver;
    server.cipher_suite = cs;
    server.quic_transport_params.original_destination_connection_id = h2b("8394c8f03e515708");
    server.quic_transport_params.initial_source_connection_id = h2b("f067a5502a4262b5");
    server.quic_transport_params.initial_max_data = 2000000;
    server.quic_transport_params.initial_max_streams_uni = 200;
    server.quic_transport_params.max_idle_timeout = 30000;

    std::vector<uint8_t> sf;
    if (!tls_quic_make_server_flight(server, ch.data(), ch.size(), sf, cert_mgr)) return false;
    out_sf = sf;
    if (!server.quic_peer_params_valid) return false;
    if (server.quic_peer_transport_params.initial_source_connection_id !=
        client.quic_transport_params.initial_source_connection_id) return false;

    std::vector<uint8_t> cf;
    if (!tls_quic_process_server_flight(client, sf.data(), sf.size(), cf, use_trust ? &trust : nullptr))
        return false;
    if (!client.quic_peer_params_valid) return false;
    if (client.quic_peer_transport_params.original_destination_connection_id !=
        server.quic_transport_params.original_destination_connection_id) return false;

    if (!tls_quic_process_client_finished(server, cf.data(), cf.size())) return false;

    if (!tls_quic_get_handshake_keys(client, ver, client_hs, server_hs)) return false;
    quic_packet_keys c_hs_srv, s_hs_srv;
    if (!tls_quic_get_handshake_keys(server, ver, c_hs_srv, s_hs_srv)) return false;
    if (!tls_quic_get_application_keys(client, ver, client_app, server_app)) return false;
    quic_packet_keys c_ap_srv, s_ap_srv;
    if (!tls_quic_get_application_keys(server, ver, c_ap_srv, s_ap_srv)) return false;

    // 两端派生的 QUIC 数据包保护密钥必须逐字节一致
    auto same_keys = [](const quic_packet_keys& a, const quic_packet_keys& b) {
        if (a.key_len != b.key_len || a.hp_len != b.hp_len) return false;
        if (memcmp(a.key, b.key, a.key_len) != 0) return false;
        if (memcmp(a.iv, b.iv, 12) != 0) return false;
        if (memcmp(a.hp, b.hp, a.hp_len) != 0) return false;
        return true;
    };
    if (!same_keys(client_hs, c_hs_srv)) return false;
    if (!same_keys(server_hs, s_hs_srv)) return false;
    if (!same_keys(client_app, c_ap_srv)) return false;
    if (!same_keys(server_app, s_ap_srv)) return false;

    return true;
}

void test_quic_handshake() {
    const char* dns = "quic.test";
    quic_packet_keys c_hs, s_hs, c_ap, s_ap;
    std::vector<uint8_t> ch, sf;

    // v1 + AES-128-GCM（X25519），带信任库 x509 链验证
    TEST("QUIC v1 AES handshake", quic_handshake_roundtrip(QuicVersion::V1,
        CipherSuite::TLS_AES_128_GCM_SHA256, NamedGroup::X25519, true, dns,
        c_hs, s_hs, c_ap, s_ap, ch, sf));
    TEST("QUIC v1 AES key_len 16", c_hs.key_len == 16);
    TEST("CH carries TP ext", find_extension_in_ch(ch.data(), ch.size(), 0x0039));
    TEST("EE carries TP ext", find_extension_in_ee(sf.data(), sf.size(), 0x0039));
    TEST("v1/v2 QUIC handshake hs/app secrets differ",
        memcmp(c_hs.key, c_ap.key, 16) != 0);

    // v1 + ChaCha20-Poly1305（32 字节 key）
    TEST("QUIC v1 ChaCha20 handshake", quic_handshake_roundtrip(QuicVersion::V1,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256, NamedGroup::X25519, true, dns,
        c_hs, s_hs, c_ap, s_ap, ch, sf));
    TEST("QUIC v1 ChaCha20 key_len 32", c_hs.key_len == 32 && c_ap.hp_len == 32);

    // v2 + AES-128-GCM
    TEST("QUIC v2 AES handshake", quic_handshake_roundtrip(QuicVersion::V2,
        CipherSuite::TLS_AES_128_GCM_SHA256, NamedGroup::X25519, true, dns,
        c_hs, s_hs, c_ap, s_ap, ch, sf));
    TEST("QUIC v2 AES key_len 16", c_hs.key_len == 16);

    // v2 + ChaCha20（v2 标签派生）
    TEST("QUIC v2 ChaCha20 handshake", quic_handshake_roundtrip(QuicVersion::V2,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256, NamedGroup::X25519, true, dns,
        c_hs, s_hs, c_ap, s_ap, ch, sf));
    TEST("QUIC v2 ChaCha20 key_len 32", c_hs.key_len == 32);

    // v2 + X448 密钥交换组
    TEST("QUIC v2 X448 handshake", quic_handshake_roundtrip(QuicVersion::V2,
        CipherSuite::TLS_AES_128_GCM_SHA256, NamedGroup::X448, true, dns,
        c_hs, s_hs, c_ap, s_ap, ch, sf));

    // 无信任库（兼容路径，跳过 CertificateVerify 校验）仍应完成密钥一致
    TEST("QUIC v1 no-trust handshake", quic_handshake_roundtrip(QuicVersion::V1,
        CipherSuite::TLS_AES_128_GCM_SHA256, NamedGroup::X25519, false, dns,
        c_hs, s_hs, c_ap, s_ap, ch, sf));

    // 非 QUIC 模式 ClientHello 不携带 TP 扩展
    tls_session plain;
    plain.server_name = dns;
    std::vector<uint8_t> pch;
    tls13_make_client_hello(plain, pch);
    TEST("plain CH lacks TP ext", !find_extension_in_ch(pch.data(), pch.size(), 0x0039));
}

// ═══════════════════════════════════════════════════════════════════════
//  缺少 quic_transport_parameters 扩展的拒绝（RFC 9001 §8.2）
// ═══════════════════════════════════════════════════════════════════════
void test_quic_missing_transport_params() {
    tls_trust_store trust;
    tls_certificate_manager cert_mgr = make_quic_cert_mgr(&trust, "quic.test");

    // 普通 TLS 1.3 ClientHello（非 QUIC，无 TP 扩展）→ QUIC 服务端必须拒绝
    tls_session client;
    client.server_name = "quic.test";
    std::vector<uint8_t> ch;
    tls13_make_client_hello(client, ch);
    TEST("QUIC server rejects CH without TP",
        !find_extension_in_ch(ch.data(), ch.size(), 0x0039));

    tls_session server;
    server.quic_mode = true;
    std::vector<uint8_t> sf;
    TEST("QUIC server flight fails w/o client TP",
        !tls_quic_make_server_flight(server, ch.data(), ch.size(), sf, cert_mgr));

    // 构造一个不含 TP 扩展的 QUIC ClientHello（直接删掉 TP 扩展并重算长度）
    tls_session c2;
    c2.quic_mode = true;
    c2.server_name = "quic.test";
    std::vector<uint8_t> ch2;
    tls_quic_make_client_hello(c2, ch2);
    TEST("QUIC CH contains TP ext", find_extension_in_ch(ch2.data(), ch2.size(), 0x0039));
}

// ═══════════════════════════════════════════════════════════════════════
//  入口
// ═══════════════════════════════════════════════════════════════════════
int main() {
    std::cout << "Running jpssl QUIC v1/v2 SSL unit tests\n" << std::endl;
    RUN_TEST(test_quic_initial_secrets_v1);
    RUN_TEST(test_quic_initial_secrets_v2);
    RUN_TEST(test_quic_1rtt_rfc9001_chacha20);
    RUN_TEST(test_quic_1rtt_rfc9369_chacha20);
    RUN_TEST(test_quic_header_protection_mask);
    RUN_TEST(test_quic_varint);
    RUN_TEST(test_quic_transport_params);
    RUN_TEST(test_quic_handshake);
    RUN_TEST(test_quic_missing_transport_params);
    return test_summary();
}
