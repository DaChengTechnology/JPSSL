/**
 * test_quic_openssl_interop.cpp — jpssl QUIC v1 (RFC 9000/9001) 与 OpenSSL QUIC 互操作测试
 *
 *   方向 A: jpssl QUIC v1 客户端  -> OpenSSL QUIC 服务器 (OSSL_QUIC_server_method)
 *   方向 B: OpenSSL QUIC 客户端  -> jpssl QUIC v1 服务器
 *   自检:   OpenSSL QUIC 客户端 <-> OpenSSL QUIC 服务器（隔离传输/服务器配置问题）
 *
 * 本测试包含一个最小的 RFC 9000 报文层（仅测试用）：
 *   - 长包头 Initial / Handshake 与短包头 1-RTT 数据包（含 Fixed Bit）
 *   - RFC 9001 §5.3 AEAD（nonce = IV xor pn；AAD = 未保护头部，含未掩码 pn）
 *   - RFC 9001 §5.4 头部保护应用/移除（pn_len 1..4，发送固定 4）
 *   - CRYPTO / ACK / STREAM / PADDING / HANDSHAKE_DONE / CONNECTION_CLOSE 帧
 * TLS 握手字节与密钥派生全部走 tls_quic 模块。
 *
 * 平台：Windows (Winsock)。
 */
#include "test_utils.hpp"
// QUIC wire version numbers (RFC 9000 section 15 / RFC 9369 section 3.1)
constexpr uint32_t QUIC_VERSION_V1 = 0x00000001u;
constexpr uint32_t QUIC_VERSION_V2 = 0x6b3343cfu;
#include "tls.hpp"
#include "tls_quic.hpp"
#include "ecdsa.hpp"
#include "x25519.hpp"
#include "x509.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <chrono>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

// tls_quic 内部密钥派生（QUIC 模式会设置 quic_hs_secrets_ready），
// 供方向 A 在解密服务器 Handshake 包前先由 ServerHello 派生握手密钥。
namespace jpssl::tls {
void tls13_derive_handshake_keys(tls_session& s, const uint8_t* shared_secret, size_t shared_len);
}

// ============================================================
//  平台 socket 适配
// ============================================================
#ifdef _WIN32
using jp_sock_t = SOCKET;
static void sock_close(jp_sock_t fd) { closesocket(fd); }
#else
using jp_sock_t = int;
static void sock_close(jp_sock_t fd) { ::close(fd); }
#endif

// poll 驱动收包：可靠超时（Windows 上 fd_set 上限 64，句柄大时必须用 WSAPoll）
static int udp_recv_timeout(jp_sock_t fd, void* buf, int len, int ms) {
#ifdef _WIN32
    WSAPOLLFD pfd{};
    pfd.fd = (SOCKET)fd;
    pfd.events = POLLRDNORM;
    int pr = WSAPoll(&pfd, 1, ms);
    if (pr <= 0) return -1;
#else
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int pr = poll(&pfd, 1, ms);
    if (pr <= 0) return -1;
#endif
    return (int)recv(fd, (char*)buf, len, 0);
}

static int udp_recvfrom_timeout(jp_sock_t fd, void* buf, int len, int ms,
                                sockaddr_in& from) {
#ifdef _WIN32
    WSAPOLLFD pfd{};
    pfd.fd = (SOCKET)fd;
    pfd.events = POLLRDNORM;
    int pr = WSAPoll(&pfd, 1, ms);
    if (pr <= 0) return -1;
#else
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int pr = poll(&pfd, 1, ms);
    if (pr <= 0) return -1;
#endif
    socklen_t flen = sizeof(from);
    return (int)recvfrom(fd, (char*)buf, len, 0, (sockaddr*)&from, &flen);
}

static void fd_set_nonblock(jp_sock_t fd, int nb) {
#ifdef _WIN32
    u_long mode = (u_long)nb;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (nb) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
#endif
}

static uint16_t alloc_udp_port() {
    jp_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == (jp_sock_t)-1) return 0;
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (bind(fd, (sockaddr*)&sa, sizeof(sa)) != 0) { sock_close(fd); return 0; }
    socklen_t sl = sizeof(sa);
    getsockname(fd, (sockaddr*)&sa, &sl);
    uint16_t port = ntohs(sa.sin_port);
    sock_close(fd);
    return port;
}

// ============================================================
//  RFC 9000 最小报文层
// ============================================================

static void quic_aead_nonce(const uint8_t iv[12], uint64_t pn, uint8_t nonce[12]) {
    memcpy(nonce, iv, 12);
    uint64_t p = pn;
    for (int i = 11; i >= 4; --i) {
        nonce[i] ^= (uint8_t)(p & 0xff);
        p >>= 8;
    }
}

static void quic_aead_seal(CipherSuite cs, const quic_packet_keys& k, uint64_t pn,
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* pt, size_t pt_len,
                           std::vector<uint8_t>& out) {
    uint8_t nonce[12];
    quic_aead_nonce(k.iv, pn, nonce);
    if (cs == CipherSuite::TLS_CHACHA20_POLY1305_SHA256) {
        uint8_t tag[16];
        chacha20_poly1305_encrypt(k.key, nonce,
                                  std::span<const uint8_t>(pt, pt_len),
                                  std::span<const uint8_t>(aad, aad_len),
                                  out, tag);
        out.insert(out.end(), tag, tag + 16);
    } else {
        aes_context ctx;
        if (k.key_len == 32)
            ctx.init(std::span<const uint8_t, 32>(k.key, 32));
        else
            ctx.init(std::span<const uint8_t, 16>(k.key, 16));
        uint8_t tag[16];
        aes_gcm_encrypt(ctx, nonce, 12,
                        std::span<const uint8_t>(pt, pt_len),
                        std::span<const uint8_t>(aad, aad_len),
                        out, tag, 16);
        out.insert(out.end(), tag, tag + 16);
    }
}

static bool quic_aead_open(CipherSuite cs, const quic_packet_keys& k, uint64_t pn,
                           const uint8_t* aad, size_t aad_len,
                           const uint8_t* ct, size_t ct_len,
                           std::vector<uint8_t>& pt) {
    if (ct_len < 16) return false;
    uint8_t nonce[12];
    quic_aead_nonce(k.iv, pn, nonce);
    if (cs == CipherSuite::TLS_CHACHA20_POLY1305_SHA256) {
        return chacha20_poly1305_decrypt(k.key, nonce,
                                         std::span<const uint8_t>(ct, ct_len - 16),
                                         std::span<const uint8_t>(aad, aad_len),
                                         ct + ct_len - 16, pt);
    } else {
        aes_context ctx;
        if (k.key_len == 32)
            ctx.init(std::span<const uint8_t, 32>(k.key, 32));
        else
            ctx.init(std::span<const uint8_t, 16>(k.key, 16));
        return aes_gcm_decrypt(ctx, nonce, 12,
                               std::span<const uint8_t>(ct, ct_len - 16),
                               std::span<const uint8_t>(aad, aad_len),
                               ct + ct_len - 16, 16, pt);
    }
}

// 构建长包头数据包（Initial / Handshake），pn_len 固定 4
static void quic_build_long(uint8_t ptype, uint32_t version,
                            const std::vector<uint8_t>& dcid,
                            const std::vector<uint8_t>& scid,
                            const std::vector<uint8_t>* token,
                            uint64_t pn, const std::vector<uint8_t>& frames,
                            CipherSuite cs, const quic_packet_keys& keys,
                            std::vector<uint8_t>& out) {
    std::vector<uint8_t> hdr;
    const uint8_t pn_len = 4;
    // RFC 9000 §17.2：长包头 = Header Form(1) + Fixed Bit(1) + Type(2) + Reserved(2) + PNL(2)
    // RFC 9369 §3.2：v2 重映射长包头类型位
    // (Initial=0b01 / 0-RTT=0b10 / Handshake=0b11 / Retry=0b00)
    uint8_t type_bits = ptype;
    if (version == QUIC_VERSION_V2) {
        switch (ptype) {
            case 0: type_bits = 1; break;
            case 1: type_bits = 2; break;
            case 2: type_bits = 3; break;
            default: type_bits = 0; break;
        }
    }
    hdr.push_back((uint8_t)(0xc0 | (type_bits << 4) | (pn_len - 1)));
    hdr.push_back((uint8_t)(version >> 24));
    hdr.push_back((uint8_t)(version >> 16));
    hdr.push_back((uint8_t)(version >> 8));
    hdr.push_back((uint8_t)version);
    hdr.push_back((uint8_t)dcid.size());
    hdr.insert(hdr.end(), dcid.begin(), dcid.end());
    hdr.push_back((uint8_t)scid.size());
    hdr.insert(hdr.end(), scid.begin(), scid.end());
    // RFC 9000 §17.2.2：Initial 包始终携带 Token Length（可为 0）
    if (ptype == 0) {
        quic_varint_encode(hdr, token ? token->size() : 0);
        if (token)
            hdr.insert(hdr.end(), token->begin(), token->end());
    }
    quic_varint_encode(hdr, (uint64_t)(pn_len + frames.size() + 16));
    size_t pn_off = hdr.size();
    for (int i = pn_len - 1; i >= 0; --i)
        hdr.push_back((uint8_t)(pn >> (8 * i)));

    std::vector<uint8_t> ct;
    quic_aead_seal(cs, keys, pn, hdr.data(), hdr.size(),
                   frames.data(), frames.size(), ct);
    out = hdr;
    out.insert(out.end(), ct.begin(), ct.end());

    // RFC 9001 §5.4：sample 从 pn 起始 +4 处取 16 字节
    const uint8_t* sample = out.data() + pn_off + 4;
    uint8_t mask[5];
    if (!tls_quic_header_protection_mask(cs, keys.hp, keys.hp_len,
                                         sample, 16, mask, 5))
        return;
    out[0] ^= (mask[0] & 0x0f);
    for (int i = 0; i < pn_len; ++i)
        out[pn_off + i] ^= mask[1 + i];
}

// 构建短包头 1-RTT 数据包（DCID 定长，pn_len=4）
static void quic_build_short(const std::vector<uint8_t>& dcid, uint64_t pn,
                             uint8_t key_phase, const std::vector<uint8_t>& frames,
                             CipherSuite cs, const quic_packet_keys& keys,
                             std::vector<uint8_t>& out) {
    std::vector<uint8_t> hdr;
    const uint8_t pn_len = 4;
    hdr.push_back((uint8_t)(0x40 | ((key_phase & 1) << 2) | (pn_len - 1)));
    hdr.insert(hdr.end(), dcid.begin(), dcid.end());
    size_t pn_off = hdr.size();
    for (int i = pn_len - 1; i >= 0; --i)
        hdr.push_back((uint8_t)(pn >> (8 * i)));

    std::vector<uint8_t> ct;
    quic_aead_seal(cs, keys, pn, hdr.data(), hdr.size(),
                   frames.data(), frames.size(), ct);
    out = hdr;
    out.insert(out.end(), ct.begin(), ct.end());

    const uint8_t* sample = out.data() + pn_off + 4;
    uint8_t mask[5];
    if (!tls_quic_header_protection_mask(cs, keys.hp, keys.hp_len,
                                         sample, 16, mask, 5))
        return;
    out[0] ^= (mask[0] & 0x1f);
    for (int i = 0; i < pn_len; ++i)
        out[pn_off + i] ^= mask[1 + i];
}

struct quic_packet {
    bool is_long = false;
    uint8_t ptype = 0;          // 0=Initial 2=Handshake（长头）
    uint32_t version = 0;
    std::vector<uint8_t> dcid, scid, token;
    uint64_t pn = 0;
    std::vector<uint8_t> payload; // 解密后的帧
};

// 解析一个数据包：移除头部保护 + AEAD 解密。返回该包消耗的字节数。
static bool quic_parse_packet(const uint8_t* data, size_t len, size_t& consumed,
                              const std::vector<uint8_t>& short_dcid,
                              CipherSuite cs, const quic_packet_keys& keys,
                              quic_packet& out) {
    if (len < 1) return false;
    out.is_long = (data[0] & 0x80) != 0;
    size_t off = 0;
    size_t pn_off = 0;
    size_t pkt_end = len;
    if (out.is_long) {
        if (len < 7) return false;
        out.ptype = (data[0] >> 4) & 0x03;
        out.version = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
                      ((uint32_t)data[3] << 8) | data[4];
        off = 5;
        uint8_t dcid_len = data[off++];
        if (off + dcid_len > len) return false;
        out.dcid.assign(data + off, data + off + dcid_len);
        off += dcid_len;
        if (off >= len) return false;
        uint8_t scid_len = data[off++];
        if (off + scid_len > len) return false;
        out.scid.assign(data + off, data + off + scid_len);
        off += scid_len;
        if (out.ptype == 0) { // Initial 带 Token
            uint64_t tlen = 0;
            size_t n = 0;
            if (!quic_varint_decode(data + off, len - off, tlen, n)) return false;
            off += n;
            if (off + tlen > len) return false;
            out.token.assign(data + off, data + off + tlen);
            off += tlen;
        }
        uint64_t plen = 0;
        size_t n = 0;
        if (!quic_varint_decode(data + off, len - off, plen, n)) return false;
        off += n;
        pn_off = off;
        if (pn_off + plen > len) return false;
        pkt_end = pn_off + (size_t)plen;
    } else {
        if (len < 1 + short_dcid.size() + 4 + 16) return false;
        out.dcid.assign(data + 1, data + 1 + short_dcid.size());
        pn_off = 1 + short_dcid.size();
    }

    // 头部保护移除：mask 由 pn_off+4 处 16 字节 sample 决定（与 pn_len 无关）
    if (pn_off + 4 + 16 > pkt_end) return false;
    const uint8_t* sample = data + pn_off + 4;
    uint8_t mask[5];
    if (!tls_quic_header_protection_mask(cs, keys.hp, keys.hp_len, sample, 16, mask, 5))
        return false;
    uint8_t first = data[0] ^ (out.is_long ? (mask[0] & 0x0f) : (mask[0] & 0x1f));
    size_t pn_len = (first & 0x03) + 1;
    size_t ct_off = pn_off + pn_len;
    if (ct_off + 16 > pkt_end) return false;

    // 重建 AAD：RFC 9001 §5.3，需使用去保护后的首字节与 pn
    std::vector<uint8_t> aad(data, data + ct_off);
    aad[0] = first;
    uint64_t pn = 0;
    for (size_t i = 0; i < pn_len; ++i) {
        uint8_t b = data[pn_off + i] ^ mask[1 + i];
        aad[pn_off + i] = b;
        pn = (pn << 8) | b;
    }
    out.pn = pn;

    std::vector<uint8_t> pt;
    if (!quic_aead_open(cs, keys, pn, aad.data(), aad.size(),
                        data + ct_off, pkt_end - ct_off, pt))
        return false;
    out.payload = std::move(pt);
    consumed = pkt_end;
    return true;
}

// Parse a Version Negotiation packet (RFC 9000 section 17.2.1): long header,
// version field 0, then DCID/SCID, then supported versions (4 bytes each).
static bool quic_parse_vn(const uint8_t* data, size_t len,
                          std::vector<uint32_t>& versions) {
    if (len < 7 || (data[0] & 0x80) == 0) return false;
    uint32_t version = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
                       ((uint32_t)data[3] << 8) | data[4];
    if (version != 0) return false;
    size_t o = 5;
    if (o >= len) return false;
    size_t dlen = data[o++];
    if (o + dlen >= len) return false;
    o += dlen;
    if (o >= len) return false;
    size_t slen = data[o++];
    if (o + slen > len) return false;
    o += slen;
    if ((len - o) % 4 != 0 || len - o == 0) return false;
    versions.clear();
    while (o + 4 <= len) {
        uint32_t v = ((uint32_t)data[o] << 24) | ((uint32_t)data[o + 1] << 16) |
                     ((uint32_t)data[o + 2] << 8) | data[o + 3];
        versions.push_back(v);
        o += 4;
    }
    return true;
}

// 帧编码
static void quic_frame_crypto(std::vector<uint8_t>& out, const std::vector<uint8_t>& data,
                              uint64_t offset) {
    out.push_back(0x06);
    quic_varint_encode(out, offset);
    quic_varint_encode(out, data.size());
    out.insert(out.end(), data.begin(), data.end());
}

static void quic_frame_ack(std::vector<uint8_t>& out, uint64_t largest, uint64_t delay) {
    out.push_back(0x02);
    quic_varint_encode(out, largest);
    quic_varint_encode(out, delay);
    quic_varint_encode(out, 0);
    quic_varint_encode(out, 0);
}

static void quic_frame_stream(std::vector<uint8_t>& out, uint64_t stream_id,
                              uint64_t offset, const std::vector<uint8_t>& data, bool fin) {
    out.push_back((uint8_t)(0x08 | (fin ? 0x01 : 0) | 0x02 | 0x04));
    quic_varint_encode(out, stream_id);
    quic_varint_encode(out, offset);
    quic_varint_encode(out, data.size());
    out.insert(out.end(), data.begin(), data.end());
}

static void quic_frame_padding(std::vector<uint8_t>& out, size_t n) {
    out.insert(out.end(), n, 0x00);
}

static void quic_frame_handshake_done(std::vector<uint8_t>& out) {
    out.push_back(0x1e);
}

struct quic_frames_result {
    std::vector<uint8_t> crypto;
    std::vector<uint8_t> stream;
    bool handshake_done = false;
    bool has_conn_close = false;
    uint64_t conn_close_error = 0;
};

// 帧解析
static bool quic_parse_frames(const uint8_t* data, size_t len, quic_frames_result& out) {
    size_t off = 0;
    while (off < len) {
        uint8_t t = data[off];
        if (t == 0x00 || t == 0x01) { ++off; continue; }
        if (t == 0x02 || t == 0x03) {
            size_t pos = off + 1;
            uint64_t largest = 0, delay = 0, cnt = 0, n = 0;
            if (!quic_varint_decode(data + pos, len - pos, largest, n)) return false;
            pos += n;
            if (!quic_varint_decode(data + pos, len - pos, delay, n)) return false;
            pos += n;
            if (!quic_varint_decode(data + pos, len - pos, cnt, n)) return false;
            pos += n;
            uint64_t first_range = 0;
            if (!quic_varint_decode(data + pos, len - pos, first_range, n)) return false;
            pos += n;
            for (uint64_t i = 0; i < cnt; ++i) {
                uint64_t gap = 0, range = 0;
                if (!quic_varint_decode(data + pos, len - pos, gap, n)) return false;
                pos += n;
                if (!quic_varint_decode(data + pos, len - pos, range, n)) return false;
                pos += n;
            }
            off = pos;
            continue;
        }
        if (t == 0x06) {
            size_t pos = off + 1;
            uint64_t offset = 0, flen = 0, n = 0;
            if (!quic_varint_decode(data + pos, len - pos, offset, n)) return false;
            pos += n;
            if (!quic_varint_decode(data + pos, len - pos, flen, n)) return false;
            pos += n;
            if (pos + flen > len) return false;
            if (offset + flen > out.crypto.size())
                out.crypto.resize(offset + flen);
            memcpy(out.crypto.data() + offset, data + pos, flen);
            pos += flen;
            off = pos;
            continue;
        }
        if ((t & 0xf8) == 0x08) {
            bool fin = (t & 0x01) != 0;
            bool has_len = (t & 0x02) != 0;
            bool has_off = (t & 0x04) != 0;
            size_t pos = off + 1;
            uint64_t stream_id = 0, n = 0;
            if (!quic_varint_decode(data + pos, len - pos, stream_id, n)) return false;
            pos += n;
            uint64_t offset = 0;
            if (has_off) {
                if (!quic_varint_decode(data + pos, len - pos, offset, n)) return false;
                pos += n;
            }
            uint64_t slen = 0;
            if (has_len) {
                if (!quic_varint_decode(data + pos, len - pos, slen, n)) return false;
                pos += n;
            } else {
                slen = len - pos;
            }
            if (pos + slen > len) return false;
            if (offset + slen > out.stream.size())
                out.stream.resize(offset + slen);
            memcpy(out.stream.data() + offset, data + pos, slen);
            pos += slen;
            off = pos;
            continue;
        }
        if (t == 0x1e) { ++off; out.handshake_done = true; continue; }
        if (t == 0x1c || t == 0x1d) {
            uint64_t err = 0, n = 0;
            if (!quic_varint_decode(data + off + 1, len - off - 1, err, n)) return false;
            out.has_conn_close = true;
            out.conn_close_error = err;
            return false;
        }
        return false;
    }
    return true;
}

// ============================================================
//  jpssl 证书管理器（自签 ECDSA P-256，SAN=localhost）
// ============================================================
static tls_certificate_manager make_jpssl_cert_mgr(const char* dns) {
    uint8_t pub[64], priv[32];
    ecdsa_p256_keygen(pub, priv);
    x509::x509_builder b;
    x509::DistinguishedName dn;
    std::vector<uint8_t> cn_oid(x509::OID_CN, x509::OID_CN + 3);
    dn.push_back({cn_oid, dns});
    b.set_subject(dn).set_issuer(dn);
    uint8_t ser[8] = {0x51, 0x51, 0x51, 0x51};
    b.set_serial(ser, 8);
    uint64_t now = (uint64_t)time(nullptr);
    b.set_validity(now - 3600, now + 365 * 86400);
    b.set_key(x509::KeyType::ECDSA_P256, pub, 64);
    b.set_ca(true);
    b.add_san_dns(dns);
    auto ca_cert = b.build_and_sign(x509::KeyType::ECDSA_P256, priv, 32);

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

// ============================================================
//  OpenSSL 证书（服务器用，自签 ECDSA P-256）
// ============================================================
static EVP_PKEY* ossl_gen_ecdsa_p256() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) return nullptr;
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static X509* ossl_self_signed(EVP_PKEY* pkey, const char* dns) {
    X509* x = X509_new();
    if (!x) return nullptr;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0x2e);
    X509_gmtime_adj(X509_get_notBefore(x), -60);
    X509_gmtime_adj(X509_get_notAfter(x), 60L * 60 * 24 * 30);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = const_cast<X509_NAME*>(X509_get_subject_name(x));
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)dns, -1, -1, 0);
    X509_set_issuer_name(x, name);
    X509V3_CTX v3ctx;
    X509V3_set_ctx(&v3ctx, x, x, nullptr, nullptr, 0);
    std::string san = std::string("DNS:") + dns;
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_subject_alt_name,
                                              (char*)san.c_str());
    if (ext) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (X509_sign(x, pkey, EVP_sha256()) <= 0) {
        X509_free(x);
        return nullptr;
    }
    return x;
}

// ============================================================
//  OpenSSL QUIC 服务器（进程内，非阻塞轮询）
// ============================================================
static int alpn_select_cb(SSL* ssl, const unsigned char** out, unsigned char* outlen,
                          const unsigned char* in, unsigned int inlen, void* arg) {
    static const unsigned char h3[] = {2, 'h', '3'};
    if (SSL_select_next_proto((unsigned char**)out, outlen, h3, sizeof(h3), in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    return SSL_TLSEXT_ERR_OK;
}

struct ossl_server_result {
    bool ok = false;
    std::string got;
    std::string why;
};

static void run_ossl_quic_server(uint16_t port, ossl_server_result& res) {
    EVP_PKEY* pkey = ossl_gen_ecdsa_p256();
    X509* x = pkey ? ossl_self_signed(pkey, "localhost") : nullptr;
    if (!pkey || !x) {
        res.why = "ossl cert fail";
        if (x) X509_free(x);
        if (pkey) EVP_PKEY_free(pkey);
        return;
    }

    SSL_CTX* sctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!sctx) {
        res.why = "SSL_CTX_new fail";
        X509_free(x);
        EVP_PKEY_free(pkey);
        return;
    }
    if (SSL_CTX_use_certificate(sctx, x) != 1 || SSL_CTX_use_PrivateKey(sctx, pkey) != 1) {
        res.why = "cert use fail";
        SSL_CTX_free(sctx);
        X509_free(x);
        EVP_PKEY_free(pkey);
        return;
    }
    SSL_CTX_set_alpn_select_cb(sctx, alpn_select_cb, nullptr);

    jp_sock_t sfd = socket(AF_INET, SOCK_DGRAM, 0);
    fd_set_nonblock(sfd, 1);
    sockaddr_in saddr{};
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &saddr.sin_addr);
    if (bind(sfd, (sockaddr*)&saddr, sizeof(saddr)) != 0) {
        res.why = "bind fail";
        SSL_CTX_free(sctx);
        X509_free(x);
        EVP_PKEY_free(pkey);
        sock_close(sfd);
        return;
    }

    SSL* listener = SSL_new_listener(sctx, SSL_LISTENER_FLAG_NO_VALIDATE);
    if (!listener || !SSL_set_fd(listener, (int)sfd) || !SSL_listen(listener)) {
        res.why = "listener fail";
        if (listener) SSL_free(listener);
        SSL_CTX_free(sctx);
        X509_free(x);
        EVP_PKEY_free(pkey);
        sock_close(sfd);
        return;
    }

    auto accept_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(12);
    SSL* conn = nullptr;
    while (std::chrono::steady_clock::now() < accept_deadline) {
        SSL_handle_events(listener);
        conn = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
        if (conn) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!conn) {
        res.why = "accept timeout";
        SSL_free(listener);
        SSL_CTX_free(sctx);
        X509_free(x);
        EVP_PKEY_free(pkey);
        sock_close(sfd);
        return;
    }
    SSL_set_blocking_mode(conn, 0);
    char buf[1024];
    size_t nread = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline) {
        int rr = SSL_read_ex(conn, buf, sizeof(buf), &nread);
        if (rr > 0) break;
        int e = SSL_get_error(conn, rr);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            SSL_handle_events(conn);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        break;
    }
    if (nread == 0) {
        res.why = "server read timeout";
        SSL_free(conn);
        SSL_free(listener);
        SSL_CTX_free(sctx);
        X509_free(x);
        EVP_PKEY_free(pkey);
        sock_close(sfd);
        return;
    }
    res.got.assign(buf, nread);
    const char* reply = "pong-from-ossl";
    size_t nw = 0;
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline) {
        int wr = SSL_write_ex(conn, reply, strlen(reply), &nw);
        if (wr > 0) break;
        int e = SSL_get_error(conn, wr);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            SSL_handle_events(conn);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        res.why = "server write fail";
        break;
    }
    SSL_stream_conclude(conn, 0);
    res.ok = true;

    SSL_free(conn);
    SSL_free(listener);
    SSL_CTX_free(sctx);
    X509_free(x);
    EVP_PKEY_free(pkey);
    sock_close(sfd);
}

// ============================================================
//  OpenSSL QUIC 客户端（进程内，非阻塞）
// ============================================================
struct ossl_client_result {
    bool ok = false;
    std::string got;
    std::string why;
};

static void run_ossl_quic_client(uint16_t port, ossl_client_result& res) {
    SSL_CTX* cctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (!cctx) { res.why = "SSL_CTX_new fail"; return; }
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, nullptr);

    jp_sock_t cfd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in caddr{};
    caddr.sin_family = AF_INET;
    caddr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &caddr.sin_addr);
    if (connect(cfd, (sockaddr*)&caddr, sizeof(caddr)) != 0) {
        res.why = "connect fail";
        SSL_CTX_free(cctx);
        sock_close(cfd);
        return;
    }
    fd_set_nonblock(cfd, 1);

    BIO* cbio = BIO_new(BIO_s_datagram());
    if (!cbio) { res.why = "BIO fail"; SSL_CTX_free(cctx); sock_close(cfd); return; }
    BIO_set_fd(cbio, (int)cfd, BIO_CLOSE);
    SSL* ssl = SSL_new(cctx);
    if (!ssl) { res.why = "SSL_new fail"; SSL_CTX_free(cctx); sock_close(cfd); return; }
    SSL_set_bio(ssl, cbio, cbio);
    SSL_set_blocking_mode(ssl, 0);
    SSL_set_tlsext_host_name(ssl, "localhost");

    static const unsigned char h3_wire[] = {2, 'h', '3'};
    if (SSL_set_alpn_protos(ssl, h3_wire, sizeof(h3_wire)) != 0) {
        res.why = "alpn fail";
        SSL_free(ssl);
        SSL_CTX_free(cctx);
        sock_close(cfd);
        return;
    }
    BIO_ADDR* peer = BIO_ADDR_new();
    BIO_ADDR_rawmake(peer, AF_INET, &caddr.sin_addr, sizeof(caddr.sin_addr), caddr.sin_port);
    if (!SSL_set1_initial_peer_addr(ssl, peer)) {
        res.why = "peer addr fail";
        BIO_ADDR_free(peer);
        SSL_free(ssl);
        SSL_CTX_free(cctx);
        sock_close(cfd);
        return;
    }
    BIO_ADDR_free(peer);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(12);
    int rc = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        rc = SSL_connect(ssl);
        if (rc == 1) break;
        int e = SSL_get_error(ssl, rc);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            SSL_handle_events(ssl);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        break;
    }
    if (rc != 1) {
        res.why = "connect fail/timeout";
        SSL_free(ssl);
        SSL_CTX_free(cctx);
        sock_close(cfd);
        return;
    }
    const char* msg = "hello-from-ossl";
    size_t w = 0;
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline) {
        int wr = SSL_write_ex(ssl, msg, strlen(msg), &w);
        if (wr > 0) break;
        int e = SSL_get_error(ssl, wr);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            SSL_handle_events(ssl);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        break;
    }
    if (w == 0) {
        res.why = "write fail/timeout";
        SSL_free(ssl);
        SSL_CTX_free(cctx);
        sock_close(cfd);
        return;
    }
    char buf[1024];
    size_t n = 0;
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline) {
        int rr = SSL_read_ex(ssl, buf, sizeof(buf), &n);
        if (rr > 0) break;
        int e = SSL_get_error(ssl, rr);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            SSL_handle_events(ssl);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        break;
    }
    if (n == 0) {
        res.why = "read fail/timeout";
        SSL_free(ssl);
        SSL_CTX_free(cctx);
        sock_close(cfd);
        return;
    }
    res.got.assign(buf, n);
    res.ok = true;
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    sock_close(cfd);
}

// ============================================================
//  方向 A：jpssl QUIC 客户端 -> OpenSSL QUIC 服务器
// ============================================================

// 从 ServerHello 提取协商套件与 X25519 密钥分享
static bool parse_server_hello(const uint8_t* sh, size_t len,
                               CipherSuite& cs, uint8_t x25519_pub[32]) {
    size_t o = 4; // handshake header
    if (o + 2 + 32 > len) return false;
    o += 2 + 32;
    if (o >= len) return false;
    size_t sid_len = sh[o++];
    if (o + sid_len + 2 + 1 > len) return false;
    o += sid_len;
    uint16_t cipher = (uint16_t)((sh[o] << 8) | sh[o + 1]);
    o += 2;
    o += 1;
    switch (cipher) {
        case 0x1301: cs = CipherSuite::TLS_AES_128_GCM_SHA256; break;
        case 0x1302: cs = CipherSuite::TLS_AES_256_GCM_SHA384; break;
        case 0x1303: cs = CipherSuite::TLS_CHACHA20_POLY1305_SHA256; break;
        default: return false;
    }
    if (o + 2 > len) return false;
    size_t ext_total = (size_t)((sh[o] << 8) | sh[o + 1]);
    o += 2;
    size_t end = o + ext_total;
    if (end > len) return false;
    while (o + 4 <= end) {
        uint16_t type = (uint16_t)((sh[o] << 8) | sh[o + 1]);
        size_t elen = (size_t)((sh[o + 2] << 8) | sh[o + 3]);
        o += 4;
        if (o + elen > end) return false;
        if (type == 0x0033 && elen >= 4 + 2) { // key_share
            uint16_t group = (uint16_t)((sh[o] << 8) | sh[o + 1]);
            uint16_t kl = (uint16_t)((sh[o + 2] << 8) | sh[o + 3]);
            if (group == 0x001d && kl == 32 && 4 + 32 <= elen) {
                memcpy(x25519_pub, sh + o + 4, 32);
                return true;
            }
        }
        o += elen;
    }
    return false;
}

static bool jpssl_client_to_ossl_server(uint16_t server_port,
                                        std::string& reply, std::string& why,
                                        bool v2_first = false,
                                        std::vector<uint32_t>* vn_versions = nullptr) {
    jp_sock_t cfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (cfd == (jp_sock_t)-1) { why = "socket fail"; return false; }

    tls_session s;
    s.quic_mode = true;
    s.quic_version = QuicVersion::V1;
    s.server_name = "localhost";
    s.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    s.alpn_protos.push_back("h3");

    const std::vector<uint8_t> client_scid = {}; // 与 OpenSSL 客户端一致：空 SCID
    std::vector<uint8_t> client_dcid(8);
    for (auto& b : client_dcid) b = (uint8_t)(rand() & 0xff);
    s.quic_transport_params.initial_source_connection_id = client_scid;
    s.quic_transport_params.max_udp_payload_size = 1400;
    s.quic_transport_params.initial_max_data = 1u << 20;
    s.quic_transport_params.initial_max_stream_data_bidi_local = 1u << 20;
    s.quic_transport_params.initial_max_stream_data_bidi_remote = 1u << 20;
    s.quic_transport_params.initial_max_streams_bidi = 8;
    s.quic_transport_params.initial_max_streams_uni = 8;

    std::vector<uint8_t> ch;
    if (!tls_quic_make_client_hello(s, ch)) { why = "CH fail"; sock_close(cfd); return false; }

    // QUICv2 detection mode: first Initial uses RFC 9369 v2 salt and labels
    bool v2_initial = false;
    quic_initial_keys ik;
    if (v2_first) {
        if (!tls_quic_derive_initial_secrets(QuicVersion::V2, client_dcid.data(),
                                             client_dcid.size(), ik)) {
            why = "v2 initial keys fail";
            sock_close(cfd);
            return false;
        }
        v2_initial = true;
    } else if (!tls_quic_derive_initial_secrets(QuicVersion::V1, client_dcid.data(),
                                                client_dcid.size(), ik)) {
        why = "initial keys fail";
        sock_close(cfd);
        return false;
    }

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(server_port);
    inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr);
    connect(cfd, (sockaddr*)&srv, (int)sizeof(srv));

    // 发送 Initial（CRYPTO(CH) + PADDING，数据报总长 1200）
    std::vector<uint8_t> frames;
    quic_frame_crypto(frames, ch, 0);
    size_t pad = 1182 > frames.size() + 16 + 4 ? 1182 - frames.size() - 16 - 4 : 0;
    quic_frame_padding(frames, pad);
    std::vector<uint8_t> pkt;
    quic_build_long(0, v2_initial ? QUIC_VERSION_V2 : QUIC_VERSION_V1,
                    client_dcid, client_scid, nullptr, 0, frames,
                    CipherSuite::TLS_AES_128_GCM_SHA256, ik.client, pkt);

    // OpenSSL 4.0 supports only QUIC v1; a >=1200 byte v2 Initial gets a
    // Version Negotiation reply (RFC 9000 section 6.1). Validate the VN,
    // then fall back to v1 per RFC 9000 section 6.1 and continue the handshake.
    if (v2_initial) {
        auto vn_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        auto vn_next = std::chrono::steady_clock::now();
        bool vn_seen = false;
        std::vector<uint32_t> vn_list;
        while (!vn_seen && std::chrono::steady_clock::now() < vn_deadline) {
            if (std::chrono::steady_clock::now() >= vn_next) {
                sendto(cfd, (const char*)pkt.data(), (int)pkt.size(), 0,
                       (sockaddr*)&srv, (int)sizeof(srv));
                vn_next = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
            }
            uint8_t dat[2048];
            int n = udp_recv_timeout(cfd, dat, sizeof(dat), 200);
            if (n <= 0) continue;
            if (quic_parse_vn(dat, (size_t)n, vn_list)) {
                vn_seen = true;
                break;
            }
        }
        if (!vn_seen) {
            why = "no VN from OpenSSL 4.0";
            sock_close(cfd);
            return false;
        }
        if (vn_versions) *vn_versions = vn_list;
        if (!tls_quic_derive_initial_secrets(QuicVersion::V1, client_dcid.data(),
                                             client_dcid.size(), ik)) {
            why = "v1 fallback keys fail";
            sock_close(cfd);
            return false;
        }
        quic_build_long(0, QUIC_VERSION_V1,
                        client_dcid, client_scid, nullptr, 0, frames,
                        CipherSuite::TLS_AES_128_GCM_SHA256, ik.client, pkt);
        v2_initial = false;
    }

    // 接收服务器 flight（期间每 200ms 重传 Initial）
    std::vector<uint8_t> sh_bytes, hs_bytes;
    bool hs_keys_ready = false;
    quic_packet_keys client_hs, server_hs;
    CipherSuite neg_cs = CipherSuite::TLS_AES_128_GCM_SHA256;
    std::vector<uint8_t> server_scid;
    uint64_t server_init_pn = 0, server_hs_pn = 0;
    std::vector<uint8_t> cf;
    quic_packet_keys client_app, server_app;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    auto next_tx = std::chrono::steady_clock::now();
    bool got_sh = false, flight_done = false;
    while (std::chrono::steady_clock::now() < deadline && !flight_done) {
        if (std::chrono::steady_clock::now() >= next_tx) {
            sendto(cfd, (const char*)pkt.data(), (int)pkt.size(), 0,
                   (sockaddr*)&srv, (int)sizeof(srv));
            next_tx = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
        }
        uint8_t dat[4096];
        int n = udp_recv_timeout(cfd, dat, sizeof(dat), 200);
        if (n <= 0) continue;
        size_t off = 0;
        while (off < (size_t)n) {
            if ((dat[off] & 0x80) == 0) break;
            quic_packet p;
            size_t consumed = 0;
            uint8_t ptype = (dat[off] >> 4) & 0x03;
            bool ok = false;
            if (ptype == 0) {
                ok = quic_parse_packet(dat + off, (size_t)n - off, consumed,
                                       server_scid, CipherSuite::TLS_AES_128_GCM_SHA256,
                                       ik.server, p);
            } else if (ptype == 2 && hs_keys_ready) {
                ok = quic_parse_packet(dat + off, (size_t)n - off, consumed,
                                       server_scid, neg_cs, server_hs, p);
            } else {
                break;
            }
            if (!ok) break;
            quic_frames_result fr;
            if (!quic_parse_frames(p.payload.data(), p.payload.size(), fr)) break;
            if (ptype == 0) {
                server_init_pn = p.pn;
                if (server_scid.empty()) server_scid = p.scid;
                if (!got_sh && !fr.crypto.empty()) {
                    sh_bytes = fr.crypto;
                    got_sh = true;
                    uint8_t server_pub[32];
                    if (!parse_server_hello(sh_bytes.data(), sh_bytes.size(),
                                            neg_cs, server_pub)) {
                        why = "SH parse fail";
                        sock_close(cfd);
                        return false;
                    }
                    s.cipher_suite = neg_cs;
                    uint8_t shared[32];
                    x25519_scalar_mult(shared, s.ks_priv, server_pub);
                    // 用一次性会话副本派生握手密钥（SH 计入 transcript），不污染主会话
                    tls_session tmp_s = s;
                    tls_transcript_update(tmp_s, sh_bytes.data(), sh_bytes.size());
                    tls13_derive_handshake_keys(tmp_s, shared, 32);
                    if (!tls_quic_get_handshake_keys(tmp_s, QuicVersion::V1,
                                                     client_hs, server_hs)) {
                        why = "hs keys fail";
                        sock_close(cfd);
                        return false;
                    }
                    hs_keys_ready = true;
                }
            } else if (ptype == 2) {
                server_hs_pn = p.pn;
                hs_bytes.insert(hs_bytes.end(), fr.crypto.begin(), fr.crypto.end());
            }
            off += consumed;
        }
        if (got_sh && hs_keys_ready && !hs_bytes.empty()) {
            std::vector<uint8_t> full_flight = sh_bytes;
            full_flight.insert(full_flight.end(), hs_bytes.begin(), hs_bytes.end());
            if (tls_quic_process_server_flight(s, full_flight.data(), full_flight.size(),
                                               cf, nullptr)) {
                if (!tls_quic_get_application_keys(s, QuicVersion::V1,
                                                   client_app, server_app)) {
                    why = "app keys fail";
                    sock_close(cfd);
                    return false;
                }
                flight_done = true;
            }
        }
    }
    if (!flight_done) {
        why = "server flight incomplete";
        sock_close(cfd);
        return false;
    }

    // 发送 Handshake：CRYPTO(CF) + ACK(服务器 Initial)
    std::vector<uint8_t> hs_frames;
    quic_frame_crypto(hs_frames, cf, 0);
    quic_frame_ack(hs_frames, server_init_pn, 0);
    quic_build_long(2, QUIC_VERSION_V1, server_scid, client_scid, nullptr, 0,
                    hs_frames, neg_cs, client_hs, pkt);
    sendto(cfd, (const char*)pkt.data(), (int)pkt.size(), 0,
           (sockaddr*)&srv, (int)sizeof(srv));

    // 发送 1-RTT：STREAM(0, "ping-from-jpssl") + ACK
    const char* msg = "ping-from-jpssl";
    std::vector<uint8_t> app_frames;
    quic_frame_stream(app_frames, 0, 0,
                      std::vector<uint8_t>(msg, msg + strlen(msg)), true);
    quic_frame_ack(app_frames, server_hs_pn, 0);
    quic_build_short(server_scid, 0, 0, app_frames, neg_cs, client_app, pkt);
    sendto(cfd, (const char*)pkt.data(), (int)pkt.size(), 0,
           (sockaddr*)&srv, (int)sizeof(srv));

    // 接收 1-RTT 应答（短头 DCID = 本端 SCID）
    bool got_reply = false;
    while (std::chrono::steady_clock::now() < deadline && !got_reply) {
        uint8_t dat[4096];
        int n = udp_recv_timeout(cfd, dat, sizeof(dat), 200);
        if (n <= 0) continue;
        size_t off = 0;
        while (off < (size_t)n) {
            if ((dat[off] & 0x80)) { // 长头：跳过
                quic_packet p;
                size_t consumed = 0;
                uint8_t ptype = (dat[off] >> 4) & 0x03;
                bool ok = false;
                if (ptype == 0)
                    ok = quic_parse_packet(dat + off, (size_t)n - off, consumed,
                                           server_scid, CipherSuite::TLS_AES_128_GCM_SHA256,
                                           ik.server, p);
                else if (ptype == 2)
                    ok = quic_parse_packet(dat + off, (size_t)n - off, consumed,
                                           server_scid, neg_cs, server_hs, p);
                else
                    break;
                if (!ok) break;
                quic_frames_result fr;
                if (!quic_parse_frames(p.payload.data(), p.payload.size(), fr)) break;
                off += consumed;
                continue;
            }
            quic_packet p;
            size_t consumed = 0;
            if (!quic_parse_packet(dat + off, (size_t)n - off, consumed,
                                   client_scid, neg_cs, server_app, p))
                break;
            quic_frames_result fr;
            if (!quic_parse_frames(p.payload.data(), p.payload.size(), fr)) break;
            if (!fr.stream.empty()) {
                reply.assign(fr.stream.begin(), fr.stream.end());
                got_reply = true;
                break;
            }
            off += consumed;
        }
    }
    sock_close(cfd);
    if (!got_reply) { why = "no reply"; return false; }
    return true;
}

// ============================================================
//  方向 B：OpenSSL QUIC 客户端 -> jpssl QUIC 服务器
// ============================================================
static bool jpssl_server_from_ossl_client(uint16_t port, std::string& got,
                                          std::string& why) {
    jp_sock_t sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd == (jp_sock_t)-1) { why = "socket fail"; return false; }
    sockaddr_in saddr{};
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &saddr.sin_addr);
    if (bind(sfd, (sockaddr*)&saddr, sizeof(saddr)) != 0) {
        why = "bind fail";
        sock_close(sfd);
        return false;
    }

    // 1) 收集完整 CH（可能跨多个 Initial 数据报 / CRYPTO 帧）
    uint8_t dat[4096];
    sockaddr_in cli{};
    std::vector<uint8_t> client_dcid, client_scid;
    quic_initial_keys ik;
    bool ik_ready = false;
    std::vector<uint8_t> ch;
    uint64_t client_init_pn = 0;
    auto ch_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    bool ch_done = false;
    while (!ch_done && std::chrono::steady_clock::now() < ch_deadline) {
        int n = udp_recvfrom_timeout(sfd, dat, sizeof(dat), 200, cli);
        if (n <= 0) continue;
        if ((dat[0] & 0x80) == 0 || ((dat[0] >> 4) & 0x03) != 0) continue;
        if (!ik_ready) {
            size_t off = 5;
            if (off >= (size_t)n) continue;
            uint8_t dcid_len = dat[off++];
            if (off + dcid_len > (size_t)n) continue;
            client_dcid.assign(dat + off, dat + off + dcid_len);
            off += dcid_len;
            if (off >= (size_t)n) continue;
            uint8_t scid_len = dat[off++];
            if (off + scid_len > (size_t)n) continue;
            client_scid.assign(dat + off, dat + off + scid_len);
            if (!tls_quic_derive_initial_secrets(QuicVersion::V1, client_dcid.data(),
                                                 client_dcid.size(), ik))
                continue;
            ik_ready = true;
        }
        quic_packet p;
        size_t consumed = 0;
        if (!quic_parse_packet(dat, (size_t)n, consumed, {},
                               CipherSuite::TLS_AES_128_GCM_SHA256, ik.client, p))
            continue;
        quic_frames_result fr;
        if (!quic_parse_frames(p.payload.data(), p.payload.size(), fr)) continue;
        client_init_pn = p.pn;
        if (fr.crypto.size() > ch.size()) {
            size_t old = ch.size();
            ch.resize(fr.crypto.size());
            memcpy(ch.data() + old, fr.crypto.data() + old, fr.crypto.size() - old);
        }
        if (ch.size() >= 4 &&
            4 + ((size_t)(ch[1] << 16) | (ch[2] << 8) | ch[3]) <= ch.size())
            ch_done = true;
    }
    if (!ch_done || ch.size() < 4) {
        why = "no full CH";
        sock_close(sfd);
        return false;
    }

    // 2) 服务端会话 + flight
    tls_session s;
    s.quic_mode = true;
    s.quic_version = QuicVersion::V1;
    s.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    s.alpn_protos.push_back("h3"); // QUIC 要求 ALPN（RFC 9001 §8.1）
    const std::vector<uint8_t> server_scid = {0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5};
    s.quic_transport_params.original_destination_connection_id = client_dcid;
    s.quic_transport_params.initial_source_connection_id = server_scid;
    s.quic_transport_params.max_udp_payload_size = 1400;
    s.quic_transport_params.initial_max_data = 1u << 20;
    s.quic_transport_params.initial_max_stream_data_bidi_local = 1u << 20;
    s.quic_transport_params.initial_max_stream_data_bidi_remote = 1u << 20;
    s.quic_transport_params.initial_max_streams_bidi = 8;
    s.quic_transport_params.initial_max_streams_uni = 8;

    tls_certificate_manager cert_mgr = make_jpssl_cert_mgr("localhost");
    std::vector<uint8_t> flight;
    if (!tls_quic_make_server_flight(s, ch.data(), ch.size(), flight, cert_mgr)) {
        why = "server flight fail";
        sock_close(sfd);
        return false;
    }
    quic_packet_keys client_hs, server_hs;
    if (!tls_quic_get_handshake_keys(s, QuicVersion::V1, client_hs, server_hs)) {
        why = "hs keys fail";
        sock_close(sfd);
        return false;
    }

    std::vector<uint8_t> sh_part, hs_part;
    if (flight.size() >= 4) {
        size_t mlen = (size_t)((flight[1] << 16) | (flight[2] << 8) | flight[3]);
        if (4 + mlen <= flight.size()) {
            sh_part.assign(flight.begin(), flight.begin() + 4 + mlen);
            hs_part.assign(flight.begin() + 4 + mlen, flight.end());
        }
    }
    if (sh_part.empty() || hs_part.empty()) {
        why = "flight split fail";
        sock_close(sfd);
        return false;
    }

    // 3) 服务端 Initial（CRYPTO(SH) + ACK + PADDING，总长 1200）+ Handshake（单独数据报）
    std::vector<uint8_t> init_frames;
    quic_frame_crypto(init_frames, sh_part, 0);
    quic_frame_ack(init_frames, client_init_pn, 0);
    size_t pad = 1182 > init_frames.size() + 16 + 4 ? 1182 - init_frames.size() - 16 - 4 : 0;
    quic_frame_padding(init_frames, pad);
    std::vector<uint8_t> init_pkt, hs_pkt;
    quic_build_long(0, QUIC_VERSION_V1, client_scid, server_scid, nullptr, 0,
                    init_frames, CipherSuite::TLS_AES_128_GCM_SHA256,
                    ik.server, init_pkt);
    std::vector<uint8_t> hs_frames;
    quic_frame_crypto(hs_frames, hs_part, 0);
    quic_frame_ack(hs_frames, client_init_pn, 0);
    quic_build_long(2, QUIC_VERSION_V1, client_scid, server_scid, nullptr, 0,
                    hs_frames, s.cipher_suite, server_hs, hs_pkt);

    sendto(sfd, (const char*)init_pkt.data(), (int)init_pkt.size(), 0,
           (sockaddr*)&cli, (int)sizeof(cli));
    sendto(sfd, (const char*)hs_pkt.data(), (int)hs_pkt.size(), 0,
           (sockaddr*)&cli, (int)sizeof(cli));

    // 4) 等待客户端 Handshake（CF）与 1-RTT（数据）
    quic_packet_keys client_app, server_app;
    bool handshake_done = false;
    std::string client_msg;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(12);
    while (std::chrono::steady_clock::now() < deadline &&
           (!handshake_done || client_msg.empty())) {
        uint8_t dat2[4096];
        sockaddr_in from{};
        int rn = udp_recvfrom_timeout(sfd, dat2, sizeof(dat2), 200, from);
        if (rn <= 0) continue;
        size_t p_off = 0;
        while (p_off < (size_t)rn) {
            if ((dat2[p_off] & 0x80)) {
                uint8_t ptype = (dat2[p_off] >> 4) & 0x03;
                quic_packet p;
                size_t c2 = 0;
                bool ok = false;
                if (ptype == 0)
                    ok = quic_parse_packet(dat2 + p_off, (size_t)rn - p_off, c2,
                                           server_scid, CipherSuite::TLS_AES_128_GCM_SHA256,
                                           ik.client, p);
                else if (ptype == 2 && !handshake_done)
                    ok = quic_parse_packet(dat2 + p_off, (size_t)rn - p_off, c2,
                                           server_scid, s.cipher_suite, client_hs, p);
                else
                    break;
                if (!ok) break;
                quic_frames_result fr;
                if (!quic_parse_frames(p.payload.data(), p.payload.size(), fr)) break;
                if (ptype == 2 && !handshake_done && !fr.crypto.empty()) {
                    if (!tls_quic_process_client_finished(s, fr.crypto.data(),
                                                          fr.crypto.size())) {
                        why = "client finished fail";
                        sock_close(sfd);
                        return false;
                    }
                    if (!tls_quic_get_application_keys(s, QuicVersion::V1,
                                                       client_app, server_app)) {
                        why = "app keys fail";
                        sock_close(sfd);
                        return false;
                    }
                    handshake_done = true;
                }
                p_off += c2;
                continue;
            }
            if (!handshake_done) break;
            // 客户端 1-RTT 短头：DCID = 服务器 SCID
            quic_packet p;
            size_t c2 = 0;
            if (!quic_parse_packet(dat2 + p_off, (size_t)rn - p_off, c2,
                                   server_scid, s.cipher_suite, client_app, p))
                break;
            quic_frames_result fr;
            if (!quic_parse_frames(p.payload.data(), p.payload.size(), fr)) break;
            if (!fr.stream.empty())
                client_msg.assign(fr.stream.begin(), fr.stream.end());
            p_off += c2;
        }
    }
    if (!handshake_done) { why = "no client finished"; sock_close(sfd); return false; }
    if (client_msg.empty()) { why = "no stream data"; sock_close(sfd); return false; }
    got = client_msg;

    // 5) 回复 1-RTT：HANDSHAKE_DONE + STREAM("pong-from-jpssl")
    const char* reply = "pong-from-jpssl";
    std::vector<uint8_t> app_frames;
    quic_frame_handshake_done(app_frames);
    quic_frame_stream(app_frames, 0, 0,
                      std::vector<uint8_t>(reply, reply + strlen(reply)), true);
    std::vector<uint8_t> app_pkt;
    quic_build_short(client_scid, 0, 0, app_frames, s.cipher_suite, server_app, app_pkt);
    sendto(sfd, (const char*)app_pkt.data(), (int)app_pkt.size(), 0,
           (sockaddr*)&cli, (int)sizeof(cli));
    sock_close(sfd);
    return true;
}

// ============================================================
//  测试用例
// ============================================================

void test_quic_ossl_self() {
    // 隔离测试：OpenSSL 客户端 <-> OpenSSL 服务器（不涉及 jpssl 报文层）
    uint16_t port = alloc_udp_port();
    TEST("self: port allocated", port != 0);
    if (port == 0) return;
    ossl_server_result sres;
    std::thread srv([&] { run_ossl_quic_server(port, sres); });
    ossl_client_result cres;
    run_ossl_quic_client(port, cres);
    srv.join();
    TEST("self: OpenSSL QUIC client <-> OpenSSL QUIC server",
         cres.ok && sres.ok && cres.got == "pong-from-ossl");
}

void test_quic_ossl_direction_a() {
    uint16_t port = alloc_udp_port();
    TEST("A: port allocated", port != 0);
    if (port == 0) return;
    ossl_server_result sres;
    std::thread srv([&] { run_ossl_quic_server(port, sres); });
    std::string reply, why;
    bool ok = jpssl_client_to_ossl_server(port, reply, why);
    srv.join();
    TEST("A: jpssl QUIC client -> OpenSSL QUIC server handshake+data",
         ok && sres.ok && reply == "pong-from-ossl" && sres.got == "ping-from-jpssl");
    if (!ok || !sres.ok)
        std::cout << "  [A] why=" << why << " srv_why=" << sres.why
                  << " srv_got=" << sres.got << std::endl;
}

void test_quic_ossl_direction_b() {
    uint16_t port = alloc_udp_port();
    TEST("B: port allocated", port != 0);
    if (port == 0) return;
    std::string got, why;
    std::thread srv([&] { jpssl_server_from_ossl_client(port, got, why); });
    ossl_client_result cres;
    run_ossl_quic_client(port, cres);
    srv.join();
    TEST("B: OpenSSL QUIC client -> jpssl QUIC server handshake+data",
         cres.ok && got == "hello-from-ossl" && cres.got == "pong-from-jpssl");
    if (!cres.ok || got != "hello-from-ossl")
        std::cout << "  [B] why=" << why << " client_why=" << cres.why
                  << " client_got=" << cres.got << std::endl;
}

// QUICv2 <-> OpenSSL 4.0 interop detection:
//   OpenSSL 4.0 only supports QUIC v1, so a v2 data path cannot interoperate.
//   This test verifies that (1) a jpssl v2 Initial triggers an RFC 9000
//   section 6.1 Version Negotiation reply listing only v1, and (2) the client
//   falls back to v1 per RFC 9000 section 6.1 and completes handshake + data.
void test_quic_ossl_v2_detect() {
    uint16_t port = alloc_udp_port();
    TEST("v2: port allocated", port != 0);
    if (port == 0) return;
    ossl_server_result sres;
    std::thread srv([&] { run_ossl_quic_server(port, sres); });
    std::string got, why;
    std::vector<uint32_t> vn;
    bool ok = jpssl_client_to_ossl_server(port, got, why, true, &vn);
    srv.join();
    bool vn_ok = ok && vn.size() == 1 && vn[0] == QUIC_VERSION_V1;
    TEST("v2: OpenSSL 4.0 replies VN listing only v1 to a v2 Initial", vn_ok);
    TEST("v2: v1 fallback completes handshake and data with OpenSSL 4.0",
         ok && got == "pong-from-ossl" && sres.ok && sres.got == "ping-from-jpssl");
    if (!ok)
        std::cout << "  [v2] why=" << why << " srv_why=" << sres.why
                  << " srv_got=" << sres.got << std::endl;
}

int main() {
    std::cout << "Running jpssl QUIC v1/v2 <-> OpenSSL QUIC interop tests\n" << std::endl;
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    RUN_TEST(test_quic_ossl_self);
    RUN_TEST(test_quic_ossl_direction_a);
    RUN_TEST(test_quic_ossl_direction_b);
    RUN_TEST(test_quic_ossl_v2_detect);
#ifdef _WIN32
    WSACleanup();
#endif
    return test_summary();
}
