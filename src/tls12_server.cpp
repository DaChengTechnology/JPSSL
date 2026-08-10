/**
 * TLS 1.2 服务端握手实现（由原 tls.cpp 拆分而来）
 */

#include "tls.hpp"
#include "dh.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "sm3.hpp"
#include "rand_os.hpp"
#include "cipher_inplace.hpp"   // 内部：零拷贝 AEAD（仅记录层使用）
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <algorithm>
namespace jpssl::tls {

// ------------------------------------------------------------
// 内部辅助函数声明（定义见 tls_router.cpp）——tls.hpp 保持不变
// ------------------------------------------------------------
void rand32(uint8_t* buf);
CipherSuite select_cipher_suite(uint16_t id);
size_t client_hello_ext_offset(const uint8_t* ch, size_t ch_len);
bool client_hello_find_extension(const uint8_t* ch, size_t ch_len, uint16_t want, const uint8_t*& data, size_t& dlen);
bool parse_sig_alg_list(const uint8_t* p, size_t len, std::vector<uint16_t>& out);
bool scheme_in_list(const std::vector<uint16_t>& list, uint16_t scheme);
uint16_t select_signature_scheme(const std::vector<uint16_t>& peer_list, const tls_certificate& cert, const std::vector<uint16_t>& local_list, bool tls13);
uint16_t cert_chain_signature_scheme(const tls_certificate& cert);
bool tls12_is_dhe(CipherSuite cs);
bool tls12_is_dhe_psk(CipherSuite cs);
bool tls12_is_dhe_rsa(CipherSuite cs);
bool tls12_is_ecdhe(CipherSuite cs);
bool tls12_is_psk(CipherSuite cs);
void tls12_prf(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len, uint8_t* out, size_t out_len);
void tls12_prf_sha384(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len, uint8_t* out, size_t out_len);
std::vector<uint8_t> tls12_psk_premaster(const uint8_t* psk, size_t psk_len, const uint8_t* other, size_t other_len);


// ══════════════════════════════════════════════════════════════════════�?

// ── TLS 1.2 密码套件协商 ───────────────────────────────────────────────

// 服务端支持的 TLS 1.2 密码套件列表（按优先级排序）
// 优先�? ECDHE-ECDSA > ECDHE-RSA > DHE-RSA > RSA > DHE-PSK > PSK
static const uint16_t TLS12_SERVER_CIPHERS[] = {
    0xC02C, // 1st ECDHE-ECDSA+AES256+SHA384
    0xCCA9, // 2nd ECDHE-ECDSA+ChaCha20
    0xC030, // 3rd ECDHE-RSA+AES256+SHA384
    0xCCA8, // 4th ECDHE-RSA+ChaCha20
    0xC02B, // 5th ECDHE-ECDSA+AES128
    0xC02F, // 6th ECDHE-RSA+AES128
    0x009F, // 7th DHE-RSA+AES256-GCM
    0x009E, // 8th DHE-RSA+AES128-GCM
    0xCCAA, // 9th DHE-RSA+ChaCha20
    0x006B, // 10th DHE-RSA+AES256-CBC+SHA256
    0x0067, // 11th DHE-RSA+AES128-CBC+SHA256
    0x009D, // 12th RSA+AES256
    0x009C, // 13th RSA+AES128 (fallback)
    0x003D, // 14th RSA+AES256-CBC+SHA256
    0x003C, // 15th RSA+AES128-CBC+SHA256
    0x00AB, // 16th DHE-PSK+AES256-GCM
    0x00AA, // 17th DHE-PSK+AES128-GCM
    0xCCAD, // 18th DHE-PSK+ChaCha20
    0x00B3, // 19th DHE-PSK+AES256-CBC+SHA384
    0x00B2, // 20th DHE-PSK+AES128-CBC+SHA256
    0x00A9, // 21st PSK+AES256-GCM
    0x00A8, // 22nd PSK+AES128-GCM
    0xCCAB, // 23rd PSK+ChaCha20
    0x00AF, // 24th PSK+AES256-CBC+SHA384
    0x00AE, // 25th PSK+AES128-CBC+SHA256
};

// �?ClientHello 中解析密码套件列�?
// 返回解析出的套件数组和数�?
static std::vector<uint16_t> tls12_parse_client_cipher_suites(const uint8_t* ch, size_t ch_len){
    std::vector<uint16_t> suites;
    if(ch_len < 44) return suites; // min CH size: 1+3+2+32+1+2+2+1 = 44
    size_t off = 4 + 2 + 32; // after header, version, random
    uint8_t sid_len = ch[off]; off += 1 + sid_len;
    if(off + 2 > ch_len) return suites;
    uint16_t cs_len = (ch[off]<<8) | ch[off+1]; off += 2;
    if(off + cs_len > ch_len) return suites;
    for(size_t i=0; i+2 <= cs_len; i+=2)
        suites.push_back((ch[off+i]<<8) | ch[off+i+1]);
    return suites;
}

// 从客户端套件列表中选择服务端支持的最佳套�?
static uint16_t tls12_select_best_cipher_suite(const std::vector<uint16_t>& client_suites){
    for(size_t si=0; si < sizeof(TLS12_SERVER_CIPHERS)/sizeof(TLS12_SERVER_CIPHERS[0]); ++si){
        uint16_t srv_cs = TLS12_SERVER_CIPHERS[si];
        for(uint16_t cl_cs : client_suites)
            if(cl_cs == srv_cs) return srv_cs;
    }
    return 0; // no common suite
}

// ══════════════════════════════════════════════════════════════════════�?
//  TLS 1.2 完整握手 �?服务�?
// 客户端 supported_groups 扩展中的 FFDHE 通告（RFC 7919 §3/§4）
struct tls12_client_ffdhe {
    bool any_ffdhe = false;    // 客户端通告了任意 FFDHE 群（256..511）
    bool has_ffdhe2048 = false;
};

static tls12_client_ffdhe tls12_parse_client_ffdhe(const uint8_t* ch, size_t ch_len){
    tls12_client_ffdhe out;
    const uint8_t* ext_data = nullptr; size_t ext_dlen = 0;
    if (!client_hello_find_extension(ch, ch_len, 0x000a, ext_data, ext_dlen)) return out;
    if (ext_dlen < 2) return out;
    size_t list_len = (ext_data[0] << 8) | ext_data[1];
    if (2 + list_len > ext_dlen) return out;
    for (size_t i = 0; i + 2 <= list_len; i += 2) {
        uint16_t g = (ext_data[2+i] << 8) | ext_data[2+i+1];
        if (g >= 256 && g <= 511) {
            out.any_ffdhe = true;
            if (g == 256) out.has_ffdhe2048 = true;
        }
    }
    return out;
}

static bool tls12_cert_is_ecdsa(const tls_certificate* cert){
    return cert && (cert->sig_alg == SignatureAlgorithm::ECDSA_SECP256R1_SHA256 ||
                    cert->sig_alg == SignatureAlgorithm::ECDSA_SECP384R1_SHA384 ||
                    cert->sig_alg == SignatureAlgorithm::ECDSA_SECP521R1_SHA512 ||
                    cert->sig_alg == SignatureAlgorithm::SM2_SM3);
}

// 服务端套件选择：按 TLS12_SERVER_CIPHERS 优先级，考虑证书类型、PSK 可用性与
// 客户端 FFDHE 通告（RFC 7919 §4：客户端通告 FFDHE 群但未含 ffdhe2048 时不得选 DHE）
static uint16_t tls12_select_server_suite(const std::vector<uint16_t>& client_suites,
                                          const tls_certificate* cert,
                                          const tls_psk_store* psk_store,
                                          const tls12_client_ffdhe& ffdhe){
    bool cert_ecdsa = tls12_cert_is_ecdsa(cert);
    for (size_t si = 0; si < sizeof(TLS12_SERVER_CIPHERS)/sizeof(TLS12_SERVER_CIPHERS[0]); ++si) {
        uint16_t srv = TLS12_SERVER_CIPHERS[si];
        bool offered = false;
        for (uint16_t cl : client_suites) if (cl == srv) { offered = true; break; }
        if (!offered) continue;
        CipherSuite cs = select_cipher_suite(srv);
        if (cs == CipherSuite::UNKNOWN) continue;
        if (tls12_is_psk(cs)) {
            if (!psk_store || psk_store->count() == 0) continue;
            if (tls12_is_dhe(cs) && ffdhe.any_ffdhe && !ffdhe.has_ffdhe2048) continue;
            return srv;
        }
        if (!cert) continue;
        if (tls12_is_ecdhe(cs)) {
            bool suite_ecdsa =
                (cs == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
                 cs == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ||
                 cs == CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
            if (suite_ecdsa != cert_ecdsa) continue;
        } else if (cert_ecdsa) {
            continue; // ECDSA 证书不能用于 ECDHE-RSA / RSA / DHE-RSA 套件
        }
        if (tls12_is_dhe(cs) && ffdhe.any_ffdhe && !ffdhe.has_ffdhe2048) continue;
        return srv;
    }
    return 0;
}

// 旧版简化 API（tls12_make_server_flight / tls12_handshake_server）使用的套件选择：
// 不含 DHE/PSK，保持历史语义（ECDHE-ECDSA > ECDHE-RSA > RSA）
static uint16_t tls12_select_legacy_suite(const std::vector<uint16_t>& client_suites,
                                          const tls_certificate* cert){
    if(!cert) return 0;
    bool is_ecdsa = tls12_cert_is_ecdsa(cert);
    static const uint16_t ECDSA_SUITES[] = {0xC02C, 0xCCA9, 0xC02B};
    static const uint16_t RSA_SUITES[]    = {0xC030, 0xCCA8, 0xC02F, 0x009D, 0x009C,
                                             0x003D, 0x003C};
    const uint16_t* cands = is_ecdsa ? ECDSA_SUITES : RSA_SUITES;
    size_t n = is_ecdsa ? 3 : 7;
    for(size_t i = 0; i < n; ++i)
        for(uint16_t cl : client_suites)
            if(cl == cands[i]) return cands[i];
    return 0;
}

// DHE ServerDHParams（RFC 5246 7.4.3）：dh_p(2+len) || dh_g(2+len) || dh_Ys(2+len)
static void tls12_append_ffdhe2048_params(std::vector<uint8_t>& out,
                                          const uint8_t dh_pub[256]){
    out.push_back(0x01); out.push_back(0x00);
    out.insert(out.end(), jpssl::dh::ffdhe2048_p, jpssl::dh::ffdhe2048_p + 256);
    out.push_back(0x00); out.push_back(0x01);
    out.push_back(jpssl::dh::FFDHE2048_G);
    out.push_back(0x01); out.push_back(0x00);
    out.insert(out.end(), dh_pub, dh_pub + 256);
}

// DHE_RSA ServerKeyExchange：ServerDHParams + 签名（RFC 5246 7.4.3）
static std::vector<uint8_t> tls12_make_dhe_rsa_skx(const tls_session& s,
                                                   const tls_certificate& cert,
                                                   uint16_t sig_alg,
                                                   const uint8_t dh_pub[256]){
    std::vector<uint8_t> msg;
    std::vector<uint8_t> params;
    tls12_append_ffdhe2048_params(params, dh_pub);
    std::vector<uint8_t> signed_data;
    signed_data.insert(signed_data.end(), s.client_random, s.client_random + 32);
    signed_data.insert(signed_data.end(), s.server_random, s.server_random + 32);
    signed_data.insert(signed_data.end(), params.begin(), params.end());
    uint8_t sig_buf[512]; size_t sig_len = 0;
    if (!cert.sign_scheme(sig_alg, signed_data.data(), signed_data.size(),
                          sig_buf, sig_len))
        return {};
    msg.push_back((uint8_t)HandshakeType::SERVER_KEY_EXCHANGE);
    size_t body_len = params.size() + 2 + 2 + sig_len;
    msg.push_back((uint8_t)(body_len >> 16)); msg.push_back((uint8_t)(body_len >> 8));
    msg.push_back((uint8_t)body_len);
    msg.insert(msg.end(), params.begin(), params.end());
    msg.push_back((uint8_t)(sig_alg >> 8)); msg.push_back((uint8_t)sig_alg);
    msg.push_back((uint8_t)(sig_len >> 8)); msg.push_back((uint8_t)sig_len);
    msg.insert(msg.end(), sig_buf, sig_buf + sig_len);
    return msg;
}

// DHE_PSK ServerKeyExchange：空 psk_identity_hint + ServerDHParams（无签名，RFC 4279 §3）
static std::vector<uint8_t> tls12_make_dhe_psk_skx(const uint8_t dh_pub[256]){
    std::vector<uint8_t> msg;
    std::vector<uint8_t> body;
    body.push_back(0x00); body.push_back(0x00); // psk_identity_hint 空
    tls12_append_ffdhe2048_params(body, dh_pub);
    msg.push_back((uint8_t)HandshakeType::SERVER_KEY_EXCHANGE);
    msg.push_back((uint8_t)(body.size() >> 16)); msg.push_back((uint8_t)(body.size() >> 8));
    msg.push_back((uint8_t)body.size());
    msg.insert(msg.end(), body.begin(), body.end());
    return msg;
}

// ══════════════════════════════════════════════════════════════════════�?
// TLS 1.2 服务端：生成明文 hello flight（ServerHello + Certificate + SKX + ServerHelloDone�?
// 保存服务�?ECDHE 私钥�?s.ks_priv（供 ClientKeyExchange 阶段计算共享密钥�?
bool tls12_make_server_hello_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                                     std::vector<uint8_t>& server_response,
                                     const tls_certificate_manager& cert_manager,
                                     const tls_psk_store* psk_store){
    s.ver=TLSVersion::V12;s.is_server=true;
    s.transcript_ready=false;
    rand32(s.server_random);
    memcpy(s.client_random,client_hello+6,32);

    // 解析客户端密码套件列表并选择（证书类型 + PSK 可用性 + FFDHE 通告）
    auto client_suites = tls12_parse_client_cipher_suites(client_hello, ch_len);
    tls12_client_ffdhe ffdhe = tls12_parse_client_ffdhe(client_hello, ch_len);

    // 解析 SNI
    size_t ext_offset=client_hello_ext_offset(client_hello,ch_len);
    if(ext_offset+2<=ch_len){
        uint16_t ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);

    uint16_t selected_cs = tls12_select_server_suite(client_suites, cert, psk_store, ffdhe);
    if(selected_cs == 0) return false; // no common cipher suite
    s.cipher_suite = select_cipher_suite(selected_cs);
    if (s.cipher_suite == CipherSuite::UNKNOWN) return false;
    bool use_psk = tls12_is_psk(s.cipher_suite);
    bool use_dhe = tls12_is_dhe(s.cipher_suite);
    bool use_ecdhe = tls12_is_ecdhe(s.cipher_suite);

    // transcript 哈希算法（SHA-256 vs SHA-384）取决于 cipher_suite，
    // 必须在选定套件之后再加入 ClientHello，否则 SHA-384 套件会用
    // SHA-256 上下文初始化，导致 Finished verify_data 全部不匹配。
    tls_transcript_update(s,client_hello,ch_len);

    // ECDHE/DHE: generate ephemeral keypair（私钥保存到 session，供 CKE 阶段使用）
    uint8_t ecdhe_pub[32], ecdhe_priv[32];
    if(use_ecdhe){
        x25519_generate_keypair(ecdhe_pub, ecdhe_priv);
        memcpy(s.ks_priv, ecdhe_priv, 32);
    }
    if(use_dhe){
        s.dhe_keys = std::make_shared<tls12_dhe_keys>();
        jpssl::dh::ffdhe2048_keypair(s.dhe_keys->pub, s.dhe_keys->priv);
    }

    // 解析客户端 signature_algorithms / signature_algorithms_cert
    std::vector<uint16_t> client_sig_algs, client_sig_algs_cert;
    const uint8_t* ext_data = nullptr; size_t ext_dlen = 0;
    if (client_hello_find_extension(client_hello, ch_len, 0x000d, ext_data, ext_dlen))
        parse_sig_alg_list(ext_data, ext_dlen, client_sig_algs);
    if (client_hello_find_extension(client_hello, ch_len, 0x0032, ext_data, ext_dlen))
        parse_sig_alg_list(ext_data, ext_dlen, client_sig_algs_cert);
    for (uint16_t a : client_sig_algs_cert)
        if (!scheme_in_list(client_sig_algs, a)) return false;  // 必须是 signature_algorithms 的子集
    uint16_t skx_sig_alg = 0;
    if ((use_ecdhe || tls12_is_dhe_rsa(s.cipher_suite)) && cert) {
        if (!client_sig_algs.empty())
            skx_sig_alg = select_signature_scheme(client_sig_algs, *cert, s.sig_algs, false);
        else
            skx_sig_alg = (uint16_t)cert->sig_alg;   // TLS 1.2 未携带扩展时的缺省行为
        if (skx_sig_alg == 0) return false;
        if (!client_sig_algs_cert.empty()) {
            uint16_t chain_scheme = cert_chain_signature_scheme(*cert);
            if (chain_scheme == 0 || !scheme_in_list(client_sig_algs_cert, chain_scheme)) return false;
        }
        s.selected_sig_alg = skx_sig_alg;
    }
    // 保存 RSA 私钥：ECDHE/DHE-RSA 套件用于 SKX 签名；纯 RSA 套件用于
    // ClientKeyExchange premaster 解密。须与 use_ecdhe 无关，否则纯 RSA 套件
    // 在 tls12_process_client_key_exchange 中 rsa_decrypt 使用空密钥而失败。
    if (cert && (cert->sig_alg == SignatureAlgorithm::RSA_PKCS1_SHA256 ||
                 cert->sig_alg == SignatureAlgorithm::RSA_PSS_RSAE_SHA256 ||
                 cert->sig_alg == SignatureAlgorithm::RSA_PSS_RSAE_SHA384 ||
                 cert->sig_alg == SignatureAlgorithm::RSA_PSS_RSAE_SHA512)) {
        s.rsa_key = std::make_shared<jpssl::rsa_private_key>(cert->priv.rsa);
    }

    // ── ServerHello ──
    server_response.clear();
    server_response.push_back((uint8_t)HandshakeType::SERVER_HELLO);
    server_response.push_back(0);server_response.push_back(0);server_response.push_back(0);
    server_response.push_back(0x03);server_response.push_back(0x03);  // legacy_version = TLS 1.2
    server_response.insert(server_response.end(),s.server_random,s.server_random+32);
    // 回显客户端 session_id（RFC 5246 7.4.1.2：若客户端提供了 session_id 应回显）
    size_t ch_sid_off = 4 + 2 + 32;
    uint8_t sid_len = (ch_len > ch_sid_off) ? client_hello[ch_sid_off] : 0;
    if (sid_len > 32 || ch_sid_off + 1 + sid_len > ch_len) sid_len = 0;
    server_response.push_back(sid_len);
    if (sid_len > 0)
        server_response.insert(server_response.end(), client_hello + ch_sid_off + 1,
                               client_hello + ch_sid_off + 1 + sid_len);
    server_response.push_back((uint8_t)(selected_cs>>8));
    server_response.push_back((uint8_t)(selected_cs));
    server_response.push_back(0x00); // compression_method = null
    // 扩展：renegotiation_info (RFC 5746) —— OpenSSL 客户端默认拒绝无此扩展的 TLS 1.2 ServerHello
    //  renegotiated_connection 长度为 0（本次握手未重协商）
    server_response.push_back(0x00);server_response.push_back(0x05); // 扩展区总长 = 2+2+1
    server_response.push_back(0xff);server_response.push_back(0x01); // renegotiation_info
    server_response.push_back(0x00);server_response.push_back(0x01); // 扩展长度
    server_response.push_back(0x00);                                // renegotiated_connection len=0
    size_t sh_len=server_response.size()-4;
    server_response[1]=(uint8_t)(sh_len>>16);server_response[2]=(uint8_t)(sh_len>>8);server_response[3]=(uint8_t)sh_len;
    tls_transcript_update(s,server_response.data(),server_response.size());

    // ── Certificate（PSK 套件省略，RFC 4279 §2/§3）──
    std::vector<uint8_t> cert_msg;
    if(!use_psk){
        if(!cert) return false;
        cert_msg = tls12_make_certificate(*cert);
        tls_transcript_update(s, cert_msg.data(), cert_msg.size());
        server_response.insert(server_response.end(), cert_msg.begin(), cert_msg.end());
    }

    // ── ServerKeyExchange（ECDHE / DHE_RSA / DHE_PSK）──
    if(use_ecdhe && cert){
        std::vector<uint8_t> skx_msg;
        skx_msg.push_back((uint8_t)HandshakeType::SERVER_KEY_EXCHANGE);
        size_t params_len = 1 + 2 + 1 + 32; // curve_type + named_curve + pubkey_len + pubkey
        std::vector<uint8_t> signed_data;
        signed_data.insert(signed_data.end(), s.client_random, s.client_random+32);
        signed_data.insert(signed_data.end(), s.server_random, s.server_random+32);
        signed_data.push_back(0x03); // curve_type: named_curve
        signed_data.push_back(0x00); signed_data.push_back(0x1d); // X25519
        signed_data.push_back(32); // pubkey length
        signed_data.insert(signed_data.end(), ecdhe_pub, ecdhe_pub+32);
        uint8_t sig_buf[512]; size_t sig_len=0;
        if(cert->sign_scheme(skx_sig_alg, signed_data.data(), signed_data.size(), sig_buf, sig_len)){
            size_t body_len = params_len + 2 + 2 + sig_len;
            skx_msg.push_back((uint8_t)(body_len>>16)); skx_msg.push_back((uint8_t)(body_len>>8)); skx_msg.push_back((uint8_t)body_len);
            skx_msg.push_back(0x03); // curve_type: named_curve
            skx_msg.push_back(0x00); skx_msg.push_back(0x1d); // X25519
            skx_msg.push_back(32);
            skx_msg.insert(skx_msg.end(), ecdhe_pub, ecdhe_pub+32);
            skx_msg.push_back((uint8_t)(skx_sig_alg>>8)); skx_msg.push_back((uint8_t)skx_sig_alg);
            skx_msg.push_back((uint8_t)(sig_len>>8)); skx_msg.push_back((uint8_t)sig_len);
            skx_msg.insert(skx_msg.end(), sig_buf, sig_buf+sig_len);
        }
        if(skx_msg.size() > 4){
            tls_transcript_update(s, skx_msg.data(), skx_msg.size());
            server_response.insert(server_response.end(), skx_msg.begin(), skx_msg.end());
        }
    } else if (tls12_is_dhe_rsa(s.cipher_suite) && cert) {
        if (!s.dhe_keys) return false;  // use_dhe 分支必须已生成临时密钥对
        std::vector<uint8_t> skx_msg = tls12_make_dhe_rsa_skx(s, *cert, skx_sig_alg, s.dhe_keys->pub);
        if(skx_msg.size() <= 4) return false;
        tls_transcript_update(s, skx_msg.data(), skx_msg.size());
        server_response.insert(server_response.end(), skx_msg.begin(), skx_msg.end());
    } else if (tls12_is_dhe_psk(s.cipher_suite)) {
        if (!s.dhe_keys) return false;  // use_dhe 分支必须已生成临时密钥对
        std::vector<uint8_t> skx_msg = tls12_make_dhe_psk_skx(s.dhe_keys->pub);
        tls_transcript_update(s, skx_msg.data(), skx_msg.size());
        server_response.insert(server_response.end(), skx_msg.begin(), skx_msg.end());
    }

    // ── ServerHelloDone ──
    std::vector<uint8_t> shd = tls12_make_server_hello_done();
    tls_transcript_update(s, shd.data(), shd.size());
    server_response.insert(server_response.end(), shd.begin(), shd.end());
    return true;
}
bool tls12_make_server_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                               std::vector<uint8_t>& server_response,
                               const uint8_t* encrypted_pms, size_t epms_len,
                               uint8_t pre_master_secret[48],
                               const tls_certificate_manager& cert_manager,
                               const tls_psk_store* psk_store){
    s.ver=TLSVersion::V12;s.is_server=true;
    s.transcript_ready=false;
    rand32(s.server_random);
    memcpy(s.client_random,client_hello+6,32);

    // 解析客户端密码套件列表并选择（旧版简化 API：不含 DHE/PSK）
    auto client_suites = tls12_parse_client_cipher_suites(client_hello, ch_len);
    (void)psk_store;

    // 解析 SNI
    size_t ext_offset=client_hello_ext_offset(client_hello,ch_len);
    if(ext_offset+2<=ch_len){
        uint16_t ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);
    uint16_t selected_cs = tls12_select_legacy_suite(client_suites, cert);
    if(selected_cs == 0) return false; // no common cipher suite
    s.cipher_suite = select_cipher_suite(selected_cs);
    if (s.cipher_suite == CipherSuite::UNKNOWN) return false;

    // transcript 哈希算法（SHA-256 vs SHA-384）取决于 cipher_suite，
    // 须在选定套件后再加入 ClientHello（与 tls12_make_server_hello_flight 一致）
    tls_transcript_update(s,client_hello,ch_len);

    // ECDHE: generate ephemeral keypair
    uint8_t ecdhe_pub[32], ecdhe_priv[32];
    bool use_ecdhe = tls12_is_ecdhe(s.cipher_suite);
    if(use_ecdhe){
        x25519_generate_keypair(ecdhe_pub, ecdhe_priv);
    }

    // 解析客户�?signature_algorithms / signature_algorithms_cert（RFC 8446，TLS 1.2 亦适用�?
    std::vector<uint16_t> client_sig_algs, client_sig_algs_cert;
    const uint8_t* ext_data = nullptr; size_t ext_dlen = 0;
    if (client_hello_find_extension(client_hello, ch_len, 0x000d, ext_data, ext_dlen))
        parse_sig_alg_list(ext_data, ext_dlen, client_sig_algs);
    if (client_hello_find_extension(client_hello, ch_len, 0x0032, ext_data, ext_dlen))
        parse_sig_alg_list(ext_data, ext_dlen, client_sig_algs_cert);
    for (uint16_t a : client_sig_algs_cert)
        if (!scheme_in_list(client_sig_algs, a)) return false;  // 必须�?signature_algorithms 的子�?
    uint16_t skx_sig_alg = 0;
    if (use_ecdhe && cert) {
        if (!client_sig_algs.empty())
            skx_sig_alg = select_signature_scheme(client_sig_algs, *cert, s.sig_algs, false);
        else
            skx_sig_alg = (uint16_t)cert->sig_alg;   // TLS 1.2 未携带扩展时的缺省行�?
        if (skx_sig_alg == 0) return false;
        if (!client_sig_algs_cert.empty()) {
            uint16_t chain_scheme = cert_chain_signature_scheme(*cert);
            if (chain_scheme == 0 || !scheme_in_list(client_sig_algs_cert, chain_scheme)) return false;
        }
        s.selected_sig_alg = skx_sig_alg;
    }

    // ECDHE: sign the server params
    std::vector<uint8_t> skx_msg;
    if(use_ecdhe && cert){
        // ServerKeyExchange: CurveType(1) + NamedCurve(2) + pubkey_len(1) + pubkey(32)
        // + signature_algorithm(2) + signature_len(2) + signature
        skx_msg.push_back((uint8_t)HandshakeType::SERVER_KEY_EXCHANGE);
        size_t params_len = 1 + 2 + 1 + 32; // curve_type + named_curve + pubkey_len + pubkey
        // Sign: client_random + server_random + params (RFC 4492 §5.4)
        std::vector<uint8_t> signed_data;
        signed_data.insert(signed_data.end(), s.client_random, s.client_random+32);
        signed_data.insert(signed_data.end(), s.server_random, s.server_random+32);
        signed_data.push_back(0x03); // curve_type: named_curve
        signed_data.push_back(0x00); signed_data.push_back(0x1d); // X25519
        signed_data.push_back(32); // pubkey length
        signed_data.insert(signed_data.end(), ecdhe_pub, ecdhe_pub+32);
        uint8_t sig_buf[512]; size_t sig_len=0;
        if(cert->sign_scheme(skx_sig_alg, signed_data.data(), signed_data.size(), sig_buf, sig_len)){
            uint16_t sig_alg = skx_sig_alg;
            size_t body_len = params_len + 2 + 2 + sig_len;
            skx_msg.push_back((uint8_t)(body_len>>16)); skx_msg.push_back((uint8_t)(body_len>>8)); skx_msg.push_back((uint8_t)body_len);
            skx_msg.push_back(0x03); // curve_type: named_curve
            skx_msg.push_back(0x00); skx_msg.push_back(0x1d); // X25519
            skx_msg.push_back(32);
            skx_msg.insert(skx_msg.end(), ecdhe_pub, ecdhe_pub+32);
            skx_msg.push_back((uint8_t)(sig_alg>>8)); skx_msg.push_back((uint8_t)sig_alg);
            skx_msg.push_back((uint8_t)(sig_len>>8)); skx_msg.push_back((uint8_t)sig_len);
            skx_msg.insert(skx_msg.end(), sig_buf, sig_buf+sig_len);
        }
    }

    // RSA 解密 pre_master_secret
    if(encrypted_pms && epms_len > 0 && cert && cert->sig_alg == SignatureAlgorithm::RSA_PKCS1_SHA256){
        std::vector<uint8_t> pt;
        if(!rsa_decrypt(cert->priv.rsa, encrypted_pms, pt)) return false;
        size_t pms_len = pt.size() < 48 ? pt.size() : 48;
        memcpy(pre_master_secret, pt.data(), pms_len);
    }

    // ServerHello
    server_response.clear();
    server_response.push_back((uint8_t)HandshakeType::SERVER_HELLO);
    server_response.push_back(0);server_response.push_back(0);server_response.push_back(0);
    server_response.push_back(0x03);server_response.push_back(0x03);
    server_response.insert(server_response.end(),s.server_random,s.server_random+32);
    server_response.push_back(0); // session_id_len=0
    server_response.push_back((uint8_t)(selected_cs>>8));
    server_response.push_back((uint8_t)(selected_cs));
    server_response.push_back(0x00); // compression
    server_response.push_back(0x00);server_response.push_back(0x00); // no extensions
    size_t sh_len=server_response.size()-4;
    server_response[1]=(uint8_t)(sh_len>>16);server_response[2]=(uint8_t)(sh_len>>8);server_response[3]=(uint8_t)sh_len;
    tls_transcript_update(s,server_response.data(),server_response.size());

    // ECDHE: compute pre-master from server's ephemeral key
    if(tls12_is_ecdhe(s.cipher_suite)){
        // Generate client ephemeral keypair
        uint8_t client_eph_pub[32], client_eph_priv[32];
        x25519_generate_keypair(client_eph_pub, client_eph_priv);
        // Compute shared secret
        uint8_t shared[32];
        // Extract server's ephemeral pub from ServerKeyExchange (stored during parsing)
        // For now, use a simple approach: the server pubkey is passed via an out-of-band mechanism
        // In production, parse it from the SKX message
        (void)client_eph_pub; (void)client_eph_priv; (void)shared;
    }
    tls12_derive_keys(s,pre_master_secret);

    // Server Finished（PRF/transcript 哈希随套件：SHA-256 �?SHA-384�?
    tls_transcript_finalize(s);
    uint8_t verify_data[12];
    size_t hl = tls_hash_len(s.cipher_suite);
    if (tls_use_sha384(s.cipher_suite))
        tls12_prf_sha384(s.master_secret,48,"server finished",s.transcript_hash,hl,verify_data,12);
    else
        tls12_prf(s.master_secret,48,"server finished",s.transcript_hash,hl,verify_data,12);
    std::vector<uint8_t> sf;
    sf.push_back((uint8_t)HandshakeType::FINISHED);
    sf.push_back(0);sf.push_back(0);sf.push_back(12);
    sf.insert(sf.end(),verify_data,verify_data+12);
//    tls_transcript_update(s,sf.data(),sf.size());
    server_response.insert(server_response.end(),sf.begin(),sf.end());
    return true;
}

bool tls12_process_client_finished(tls_session& s, const uint8_t* data, size_t len){
    if(len<16 || data[0]!=(uint8_t)HandshakeType::FINISHED)return false;
//    tls_transcript_update(s,data,len);
    tls_transcript_finalize(s);
    uint8_t expected[12];
    size_t hl = tls_hash_len(s.cipher_suite);
    if (tls_use_sha384(s.cipher_suite))
        tls12_prf_sha384(s.master_secret,48,"client finished",s.transcript_hash,hl,expected,12);
    else
        tls12_prf(s.master_secret,48,"client finished",s.transcript_hash,hl,expected,12);
    return memcmp(expected,data+4,12)==0;
}

bool tls12_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                             std::vector<uint8_t>& server_response,
                             const uint8_t* encrypted_pms, size_t epms_len,
                             uint8_t pre_master_secret[48],
                             const tls_certificate_manager& cert_manager){
    s.ver=TLSVersion::V12;rand32(s.server_random);memcpy(s.client_random,client_hello+6,32);
    auto sim_suites = tls12_parse_client_cipher_suites(client_hello, ch_len);
    uint16_t sim_cs = tls12_select_best_cipher_suite(sim_suites);
    if(sim_cs == 0) return false;
    s.cipher_suite = select_cipher_suite(sim_cs);
    if (s.cipher_suite == CipherSuite::UNKNOWN) return false;
    // ECDHE: generate ephemeral keypair
    uint8_t ecdhe_pub[32], ecdhe_priv[32];
    bool use_ecdhe = tls12_is_ecdhe(s.cipher_suite);
    if(use_ecdhe){
        x25519_generate_keypair(ecdhe_pub, ecdhe_priv);
    }

    // 解析 SNI
    size_t ext_offset=client_hello_ext_offset(client_hello,ch_len);
    if(ext_offset+2<=ch_len){
        uint16_t ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);

    // 解析客户�?signature_algorithms / signature_algorithms_cert
    std::vector<uint16_t> client_sig_algs, client_sig_algs_cert;
    const uint8_t* ext_data = nullptr; size_t ext_dlen = 0;
    if (client_hello_find_extension(client_hello, ch_len, 0x000d, ext_data, ext_dlen))
        parse_sig_alg_list(ext_data, ext_dlen, client_sig_algs);
    if (client_hello_find_extension(client_hello, ch_len, 0x0032, ext_data, ext_dlen))
        parse_sig_alg_list(ext_data, ext_dlen, client_sig_algs_cert);
    for (uint16_t a : client_sig_algs_cert)
        if (!scheme_in_list(client_sig_algs, a)) return false;
    uint16_t skx_sig_alg = 0;
    if (use_ecdhe && cert) {
        if (!client_sig_algs.empty())
            skx_sig_alg = select_signature_scheme(client_sig_algs, *cert, s.sig_algs, false);
        else
            skx_sig_alg = (uint16_t)cert->sig_alg;
        if (skx_sig_alg == 0) return false;
        if (!client_sig_algs_cert.empty()) {
            uint16_t chain_scheme = cert_chain_signature_scheme(*cert);
            if (chain_scheme == 0 || !scheme_in_list(client_sig_algs_cert, chain_scheme)) return false;
        }
        s.selected_sig_alg = skx_sig_alg;
    }

    // ECDHE: sign the server params
    std::vector<uint8_t> skx_msg;
    if(use_ecdhe && cert){
        // ServerKeyExchange: CurveType(1) + NamedCurve(2) + pubkey_len(1) + pubkey(32)
        // + signature_algorithm(2) + signature_len(2) + signature
        skx_msg.push_back((uint8_t)HandshakeType::SERVER_KEY_EXCHANGE);
        size_t params_len = 1 + 2 + 1 + 32; // curve_type + named_curve + pubkey_len + pubkey
        // Sign: client_random + server_random + params (RFC 4492 §5.4)
        std::vector<uint8_t> signed_data;
        signed_data.insert(signed_data.end(), s.client_random, s.client_random+32);
        signed_data.insert(signed_data.end(), s.server_random, s.server_random+32);
        signed_data.push_back(0x03); // curve_type: named_curve
        signed_data.push_back(0x00); signed_data.push_back(0x1d); // X25519
        signed_data.push_back(32); // pubkey length
        signed_data.insert(signed_data.end(), ecdhe_pub, ecdhe_pub+32);
        uint8_t sig_buf[512]; size_t sig_len=0;
        if(cert->sign_scheme(skx_sig_alg, signed_data.data(), signed_data.size(), sig_buf, sig_len)){
            uint16_t sig_alg = skx_sig_alg;
            size_t body_len = params_len + 2 + 2 + sig_len;
            skx_msg.push_back((uint8_t)(body_len>>16)); skx_msg.push_back((uint8_t)(body_len>>8)); skx_msg.push_back((uint8_t)body_len);
            skx_msg.push_back(0x03); // curve_type: named_curve
            skx_msg.push_back(0x00); skx_msg.push_back(0x1d); // X25519
            skx_msg.push_back(32);
            skx_msg.insert(skx_msg.end(), ecdhe_pub, ecdhe_pub+32);
            skx_msg.push_back((uint8_t)(sig_alg>>8)); skx_msg.push_back((uint8_t)sig_alg);
            skx_msg.push_back((uint8_t)(sig_len>>8)); skx_msg.push_back((uint8_t)sig_len);
            skx_msg.insert(skx_msg.end(), sig_buf, sig_buf+sig_len);
        }
    }

    // RSA 解密 pre_master_secret
    if(encrypted_pms && epms_len > 0 && cert && cert->sig_alg == SignatureAlgorithm::RSA_PKCS1_SHA256){
        std::vector<uint8_t> pt;
        if(!rsa_decrypt(cert->priv.rsa, encrypted_pms, pt)) return false;
        size_t pms_len = pt.size() < 48 ? pt.size() : 48;
        memcpy(pre_master_secret, pt.data(), pms_len);
    }

    server_response.clear();
    server_response.push_back((uint8_t)HandshakeType::SERVER_HELLO);
    server_response.push_back(0);server_response.push_back(0);server_response.push_back(0);
    server_response.push_back(0x03);server_response.push_back(0x03);
    server_response.insert(server_response.end(),s.server_random,s.server_random+32);
    server_response.push_back(0); // session_id_len=0
    server_response.push_back((uint8_t)(sim_cs>>8));
    server_response.push_back((uint8_t)(sim_cs));
    server_response.push_back(0x00); // compression
    server_response.push_back(0x00);server_response.push_back(0x00); // no extensions
    size_t len=server_response.size()-4;
    server_response[1]=(uint8_t)(len>>16);server_response[2]=(uint8_t)(len>>8);server_response[3]=(uint8_t)len;
    // ECDHE: compute pre-master from server's ephemeral key
    if(tls12_is_ecdhe(s.cipher_suite)){
        // Generate client ephemeral keypair
        uint8_t client_eph_pub[32], client_eph_priv[32];
        x25519_generate_keypair(client_eph_pub, client_eph_priv);
        // Compute shared secret
        uint8_t shared[32];
        // Extract server's ephemeral pub from ServerKeyExchange (stored during parsing)
        // For now, use a simple approach: the server pubkey is passed via an out-of-band mechanism
        // In production, parse it from the SKX message
        (void)client_eph_pub; (void)client_eph_priv; (void)shared;
    }
    tls12_derive_keys(s,pre_master_secret);
    return true;
}

std::vector<uint8_t> tls12_make_certificate(const tls_certificate& cert) {
    auto der=cert.cert_data.empty()?tls_make_x509_self_signed(cert):cert.cert_data;
    std::vector<uint8_t> m;m.push_back(11);
    size_t el=3+der.size(),bl=3+el;
    m.push_back((uint8_t)(bl>>16));m.push_back((uint8_t)(bl>>8));m.push_back((uint8_t)bl);
    m.push_back((uint8_t)(el>>16));m.push_back((uint8_t)(el>>8));m.push_back((uint8_t)el);
    m.push_back((uint8_t)(der.size()>>16));m.push_back((uint8_t)(der.size()>>8));m.push_back((uint8_t)der.size());
    m.insert(m.end(),der.begin(),der.end());return m;
}

// ServerHelloDone 消息（type=14, �?body�?
std::vector<uint8_t> tls12_make_server_hello_done() {
    std::vector<uint8_t> m;
    m.push_back((uint8_t)HandshakeType::SERVER_HELLO_DONE);
    m.push_back(0); m.push_back(0); m.push_back(0);
    return m;
}

// 服务端处�?ClientKeyExchange�?
// - ECDHE: 解析客户端临时公�?�?x25519(server_priv, client_pub) �?32 字节共享密钥作为 premaster
// - RSA:   rsa_decrypt(server_priv, encrypted_pms) �?48 字节 premaster
// 随后 derive keys，生�?CCS 记录 + 加密�?Finished 记录（追加到 server_ccs_finished�?
bool tls12_process_client_key_exchange(tls_session& s, const uint8_t* encrypted_pms, size_t epms_len,
                                        std::vector<uint8_t>& server_ccs_finished,
                                        const tls_psk_store* psk_store) {
    (void)server_ccs_finished;
    std::vector<uint8_t> pre_master;

    if (tls12_is_ecdhe(s.cipher_suite)) {
        // ClientKeyExchange 结构（ECDHE，RFC 4492 5.7）：
        //   ECPoint: 1 字节长度 + 32 字节公钥（X25519）
        if (!encrypted_pms || epms_len < 33) return false;
        size_t pub_len = encrypted_pms[0];
        if (pub_len != 32 || 1 + pub_len > epms_len) return false;
        const uint8_t* client_pub = encrypted_pms + 1;
        // 服务端临时私钥保存在 s.ks_priv（tls12_make_server_flight 生成时写入）
        uint8_t shared[32];
        x25519_scalar_mult(shared, s.ks_priv, client_pub);
        pre_master.assign(shared, shared + 32);
    } else if (tls12_is_dhe_rsa(s.cipher_suite)) {
        // ClientKeyExchange（DHE，RFC 5246 7.4.7.2）：2 字节长度 + dh_Yc
        if (!encrypted_pms || epms_len < 2) return false;
        size_t pub_len = (encrypted_pms[0] << 8) | encrypted_pms[1];
        if (2 + pub_len > epms_len || pub_len != jpssl::dh::FFDHE2048_BYTES) return false;
        const uint8_t* client_pub = encrypted_pms + 2;
        if (!s.dhe_keys) return false;
        uint8_t shared256[256];
        if (!jpssl::dh::ffdhe2048_shared(shared256, s.dhe_keys->priv, client_pub))
            return false; // RFC 7919 §4：1 < dh_Yc < dh_p-1
        uint8_t minimal[256];
        size_t n = jpssl::dh::ffdhe2048_shared_minimal(shared256, minimal);
        pre_master.assign(minimal, minimal + n);
    } else if (tls12_is_psk(s.cipher_suite)) {
        // ClientKeyExchange（PSK，RFC 4279 §2）：2 字节长度 + psk_identity
        if (!encrypted_pms || epms_len < 2) return false;
        size_t id_len = (encrypted_pms[0] << 8) | encrypted_pms[1];
        if (2 + id_len > epms_len) return false;
        // 查表得到 PSK 值
        std::vector<uint8_t> psk;
        if (psk_store) {
            std::string ident((const char*)encrypted_pms + 2, id_len);
            if (!psk_store->lookup(ident, psk)) return false; // 未知身份
        } else if (s.tls12_psk_valid) {
            psk.assign(s.tls12_psk_value, s.tls12_psk_value + s.tls12_psk_value_len);
        } else {
            return false;
        }
        if (psk.size() > sizeof(s.tls12_psk_value)) return false;
        memcpy(s.tls12_psk_value, psk.data(), psk.size());
        s.tls12_psk_value_len = psk.size();
        s.tls12_psk_valid = true;
        if (tls12_is_dhe_psk(s.cipher_suite)) {
            // ClientKeyExchange（DHE_PSK，RFC 4279 §3）：
            //   identity(2+len) || dh_Yc(2+len)
            size_t off = 2 + id_len;
            if (off + 2 > epms_len) return false;
            size_t pub_len = (encrypted_pms[off] << 8) | encrypted_pms[off+1]; off += 2;
            if (off + pub_len > epms_len || pub_len != jpssl::dh::FFDHE2048_BYTES)
                return false;
            const uint8_t* client_pub = encrypted_pms + off;
            if (!s.dhe_keys) return false;
            uint8_t shared256[256];
            if (!jpssl::dh::ffdhe2048_shared(shared256, s.dhe_keys->priv, client_pub))
                return false; // RFC 7919 §4：1 < dh_Yc < dh_p-1
            uint8_t minimal[256];
            size_t n = jpssl::dh::ffdhe2048_shared_minimal(shared256, minimal);
            pre_master = tls12_psk_premaster(psk.data(), psk.size(), minimal, n);
        } else {
            // 纯 PSK：other_secret = psk_len 个零字节（OpenSSL 4.0 格式）
            pre_master = tls12_psk_premaster(psk.data(), psk.size(), nullptr, 0);
        }
    } else {
        // 纯 RSA 密钥交换（RFC 5246 7.4.7.1）：2 字节长度 + 加密 premaster
        // s.rsa_key 由握手流程注入（tls12_make_server_flight 填充）。
        if (!encrypted_pms || epms_len < 2) return false;
        size_t enc_len = (encrypted_pms[0] << 8) | encrypted_pms[1];
        if (2 + enc_len > epms_len) return false;
        std::vector<uint8_t> pt;
        if (!s.rsa_key || !rsa_decrypt(*s.rsa_key, encrypted_pms + 2, pt))
            return false;
        size_t n = pt.size() < 48 ? pt.size() : 48;
        pre_master.assign(pt.data(), pt.data() + n);
    }

    // derive master secret 与 key block
    if (pre_master.empty()) return false;
    tls12_derive_keys(s, pre_master.data(), pre_master.size());
    return true;
}


} // namespace jpssl::tls
