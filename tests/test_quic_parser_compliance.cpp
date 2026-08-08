/**
 * test_quic_parser_compliance.cpp — QUIC v1/v2 Initial 包合规性检测
 *
 * 用独立实现的 quic-parser（Rust crate，canmi21/quic-parser）校验 jpssl
 * tls_quic 生成的 QUIC Initial 数据包：
 *   1. 长包头解析：版本号、Fixed Bit、DCID/SCID、Token、长度字段；
 *   2. Initial 密钥派生（v1: RFC 9001 §5.2；v2: RFC 9369 §3.3）、头部保护
 *      移除与 AEAD 解密；
 *   3. CRYPTO 帧解析与重组：必须得到 TLS ClientHello（handshake type 0x01）。
 *
 * 用法：test_quic_parser_compliance <quic_parser_compliance 工具路径>
 * 工具未构建时输出 SKIP（与 DTLS 1.3 OpenSSL 互操作测试一致）。
 */
#include "test_utils.hpp"
#include "tls.hpp"
#include "tls_quic.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using namespace jpssl;
using namespace jpssl::tls;

namespace {

constexpr uint32_t QUIC_VERSION_V1 = 0x00000001u;
constexpr uint32_t QUIC_VERSION_V2 = 0x6b3343cfu;

std::string to_hex(const std::vector<uint8_t>& v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (uint8_t b : v) {
        s.push_back(d[b >> 4]);
        s.push_back(d[b & 0x0f]);
    }
    return s;
}

// 长包头类型位（RFC 9000 §17.2 / RFC 9369 §3.2）：
//   v1: Initial=0b00  0-RTT=0b01  Handshake=0b10  Retry=0b11
//   v2: Initial=0b01  0-RTT=0b10  Handshake=0b11  Retry=0b00
uint8_t long_type_bits(QuicVersion ver, uint8_t ptype) {
    if (ver == QuicVersion::V2) {
        switch (ptype) {
            case 0: return 1; // Initial
            case 1: return 2; // 0-RTT
            case 2: return 3; // Handshake
            default: return 0; // Retry
        }
    }
    return ptype;
}

void quic_varint_encode(std::vector<uint8_t>& out, uint64_t v) {
    if (v < (1ull << 6)) {
        out.push_back((uint8_t)v);
    } else if (v < (1ull << 14)) {
        out.push_back((uint8_t)(0x40 | (v >> 8)));
        out.push_back((uint8_t)v);
    } else if (v < (1ull << 30)) {
        out.push_back((uint8_t)(0x80 | (v >> 24)));
        out.push_back((uint8_t)(v >> 16));
        out.push_back((uint8_t)(v >> 8));
        out.push_back((uint8_t)v);
    } else {
        out.push_back((uint8_t)(0xc0 | (v >> 56)));
        out.push_back((uint8_t)(v >> 48));
        out.push_back((uint8_t)(v >> 40));
        out.push_back((uint8_t)(v >> 32));
        out.push_back((uint8_t)(v >> 24));
        out.push_back((uint8_t)(v >> 16));
        out.push_back((uint8_t)(v >> 8));
        out.push_back((uint8_t)v);
    }
}

void quic_aead_nonce(const uint8_t iv[12], uint64_t pn, uint8_t nonce[12]) {
    memcpy(nonce, iv, 12);
    uint64_t p = pn;
    for (int i = 11; i >= 4; --i) {
        nonce[i] ^= (uint8_t)(p & 0xff);
        p >>= 8;
    }
}

// Initial 包恒用 AEAD_AES_128_GCM（RFC 9001 §5.2 / RFC 9369 §3.3）
void quic_initial_aead_seal(const quic_packet_keys& k, uint64_t pn,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* pt, size_t pt_len,
                            std::vector<uint8_t>& out) {
    uint8_t nonce[12];
    quic_aead_nonce(k.iv, pn, nonce);
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

// 构造 QUIC Initial 数据报（CRYPTO(CH) + PADDING，总长 >=1200）
bool build_initial(QuicVersion ver, const std::vector<uint8_t>& dcid,
                   const std::vector<uint8_t>& scid,
                   const std::vector<uint8_t>& ch,
                   std::vector<uint8_t>& pkt, std::string& why) {
    quic_initial_keys ik;
    if (!tls_quic_derive_initial_secrets(ver, dcid.data(), dcid.size(), ik)) {
        why = "derive_initial_secrets failed";
        return false;
    }
    const CipherSuite cs = CipherSuite::TLS_AES_128_GCM_SHA256;
    const uint64_t pn = 0;
    const uint8_t pn_len = 4;

    std::vector<uint8_t> frames_base;
    frames_base.push_back(0x06); // CRYPTO frame type
    quic_varint_encode(frames_base, 0); // offset
    quic_varint_encode(frames_base, ch.size());
    frames_base.insert(frames_base.end(), ch.begin(), ch.end());

    // 两遍构造：数据报不足 1200 字节时补 PADDING 后重来（RFC 9000 §14.1）
    size_t pad = 0;
    size_t pn_off = 0;
    for (int attempt = 0; attempt < 3; ++attempt) {
        std::vector<uint8_t> frames = frames_base;
        frames.insert(frames.end(), pad, 0x00); // PADDING

        std::vector<uint8_t> hdr;
        hdr.push_back((uint8_t)(0xc0 | (long_type_bits(ver, 0) << 4) | (pn_len - 1)));
        uint32_t v = (ver == QuicVersion::V2) ? QUIC_VERSION_V2 : QUIC_VERSION_V1;
        hdr.push_back((uint8_t)(v >> 24));
        hdr.push_back((uint8_t)(v >> 16));
        hdr.push_back((uint8_t)(v >> 8));
        hdr.push_back((uint8_t)v);
        hdr.push_back((uint8_t)dcid.size());
        hdr.insert(hdr.end(), dcid.begin(), dcid.end());
        hdr.push_back((uint8_t)scid.size());
        hdr.insert(hdr.end(), scid.begin(), scid.end());
        quic_varint_encode(hdr, 0); // token length
        quic_varint_encode(hdr, (uint64_t)(pn_len + frames.size() + 16));
        pn_off = hdr.size();
        for (int i = pn_len - 1; i >= 0; --i)
            hdr.push_back((uint8_t)(pn >> (8 * i)));

        std::vector<uint8_t> ct;
        quic_initial_aead_seal(ik.client, pn, hdr.data(), hdr.size(),
                               frames.data(), frames.size(), ct);
        pkt = hdr; // 未保护头部 + 密文 = 数据报
        pkt.insert(pkt.end(), ct.begin(), ct.end());
        if (pkt.size() >= 1200) break;
        pad += 1200 - pkt.size();
    }

    // RFC 9001 §5.4 / RFC 9369 §3.3.3 头部保护
    const uint8_t* sample = pkt.data() + pn_off + 4;
    uint8_t mask[5];
    if (!tls_quic_header_protection_mask(cs, ik.client.hp, ik.client.hp_len,
                                         sample, 16, mask, 5)) {
        why = "header protection mask failed";
        return false;
    }
    pkt[0] ^= (mask[0] & 0x0f);
    for (int i = 0; i < pn_len; ++i)
        pkt[pn_off + i] ^= mask[1 + i];
    if (pkt.size() < 1200) {
        why = "datagram too short: " + std::to_string(pkt.size());
        return false;
    }
    return true;
}

bool make_client_hello(QuicVersion ver, const std::vector<uint8_t>& scid,
                       std::vector<uint8_t>& ch) {
    tls_session s;
    s.quic_mode = true;
    s.quic_version = ver;
    s.server_name = "localhost";
    s.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    s.alpn_protos.push_back("h3");
    s.quic_transport_params.initial_source_connection_id = scid;
    s.quic_transport_params.max_udp_payload_size = 1400;
    s.quic_transport_params.initial_max_data = 1u << 20;
    s.quic_transport_params.initial_max_stream_data_bidi_local = 1u << 20;
    s.quic_transport_params.initial_max_stream_data_bidi_remote = 1u << 20;
    s.quic_transport_params.initial_max_streams_bidi = 8;
    s.quic_transport_params.initial_max_streams_uni = 8;
    return tls_quic_make_client_hello(s, ch);
}

int run_tool(const std::string& tool, const std::string& args, std::string& output) {
    const char* outfile = "quic_parser_tool_out.txt";
    // cmd.exe /c 会剥掉首尾引号：整条命令再包一层引号，保留工具路径的引号
#ifdef _WIN32
    std::string cmd = "\"\"" + tool + "\" " + args + " > \"" + outfile + "\" 2>&1\"";
#else
    // POSIX sh: the whole command must not carry the extra outer quotes
    std::string cmd = "\"" + tool + "\" " + args + " > \"" + outfile + "\" 2>&1";
#endif
    int rc = std::system(cmd.c_str());
    std::ifstream f(outfile);
    output.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return rc;
}

void check_one(QuicVersion ver, const char* tag, const std::string& tool,
               const std::vector<uint8_t>& dcid,
               const std::vector<uint8_t>& scid,
               const std::vector<uint8_t>& ch) {
    std::vector<uint8_t> pkt;
    std::string why;
    bool ok = build_initial(ver, dcid, scid, ch, pkt, why);
    TEST_MSG(tag, ok, why);
    if (!ok) return;
    TEST_MSG(tag, pkt.size() >= 1200, "datagram < 1200 bytes");

    std::string file = (ver == QuicVersion::V2) ? "quic_parser_v2.initial"
                                                : "quic_parser_v1.initial";
    {
        std::ofstream of(file, std::ios::binary);
        of.write((const char*)pkt.data(), (std::streamsize)pkt.size());
    }
    std::string verhex = (ver == QuicVersion::V2) ? "6b3343cf" : "00000001";
    std::string output;
    int rc = run_tool(tool, "check " + file + " " + verhex + " " + to_hex(dcid), output);
    TEST_MSG(tag, rc == 0, output);
    if (rc != 0) std::cout << output << std::endl;
}

} // namespace

void test_quic_parser_compliance(const std::string& tool) {
    std::string output;
    int rc = run_tool(tool, "self-test", output);
    TEST_MSG("quic-parser 工具自检（RFC 9001 A.2 官方向量）", rc == 0, output);
    if (rc != 0) std::cout << output << std::endl;

    // 与 OpenSSL 互操作测试一致的客户端参数（空 SCID、随机 8 字节 DCID）
    std::vector<uint8_t> scid;
    std::vector<uint8_t> dcid(8);
    for (auto& b : dcid) b = (uint8_t)(rand() & 0xff);

    std::vector<uint8_t> ch_v1, ch_v2;
    TEST("ClientHello (v1) 生成", make_client_hello(QuicVersion::V1, scid, ch_v1));
    TEST("ClientHello (v2) 生成", make_client_hello(QuicVersion::V2, scid, ch_v2));

    check_one(QuicVersion::V1, "QUICv1 Initial：quic-parser 解析/解密/CRYPTO 重组",
              tool, dcid, scid, ch_v1);
    check_one(QuicVersion::V2, "QUICv2 Initial：quic-parser 解析/解密/CRYPTO 重组（RFC 9369）",
              tool, dcid, scid, ch_v2);
}

int main(int argc, char** argv) {
    std::cout << "Running jpssl QUIC v1/v2 compliance checks via quic-parser\n" << std::endl;
    if (argc < 2) {
        std::cout << "SKIP: usage: test_quic_parser_compliance <quic_parser_compliance-tool>"
                  << std::endl;
        return 0;
    }
    std::string tool = argv[1];
    std::ifstream probe(tool);
    if (!probe.good()) {
        std::cout << "SKIP: quic-parser tool not built: " << tool << std::endl;
        return 0;
    }
    std::cout << "\n=== test_quic_parser_compliance ===" << std::endl;
    test_quic_parser_compliance(tool);
    return test_summary();
}
