/**
 * TLS 1.2 客户端握手实现（由原 tls.cpp 拆分而来）
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
namespace jpssl {
namespace tls {

// ------------------------------------------------------------
// 内部辅助函数声明（定义见 tls_router.cpp）——tls.hpp 保持不变
// ------------------------------------------------------------
void rand32(uint8_t* buf);
CipherSuite select_cipher_suite(uint16_t id);
void append_sig_alg_extension(std::vector<uint8_t>& ext, uint16_t type, const std::vector<uint16_t>& algs);
std::vector<uint16_t> effective_sig_algs(const tls_session& s);
bool scheme_in_list(const std::vector<uint16_t>& list, uint16_t scheme);
uint16_t x509_key_type_chain_scheme(x509::KeyType kt);
bool tls12_is_ecdhe(CipherSuite cs);
bool tls12_is_dhe_psk(CipherSuite cs);
bool tls12_is_dhe_rsa(CipherSuite cs);
bool tls12_is_psk(CipherSuite cs);
void tls12_prf(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len, uint8_t* out, size_t out_len);
void tls12_prf_sha384(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len, uint8_t* out, size_t out_len);
std::vector<uint8_t> tls12_psk_premaster(const uint8_t* psk, size_t psk_len, const uint8_t* other, size_t other_len);
bool tls13_verify_server_chain(const std::vector<x509::x509_cert>& server_chain, const tls_trust_store& trust, const std::string& hostname);
std::unique_ptr<tls_certificate> tls_cert_from_x509_leaf(const x509::x509_cert& leaf);

// 客户端默认支持的 TLS 1.2 密码套件列表
static const uint16_t TLS12_CLIENT_CIPHERS[] = {
    0xC02C, 0xCCA9, 0xC030, 0xCCA8, 0xC02B, 0xC02F,
    0x009F, 0x009E, 0xCCAA, 0x006B, 0x0067,
    0x009D, 0x009C, 0x003D, 0x003C,
};

// 客户�?PSK 套件（仅当会话配置了 TLS 1.2 PSK 时加�?ClientHello�?
static const uint16_t TLS12_CLIENT_PSK_CIPHERS[] = {
    0x00AB, 0x00AA, 0xCCAD, 0x00B3, 0x00B2,
    0x00A9, 0x00A8, 0xCCAB, 0x00AF, 0x00AE,
};


// 判断 TLS 1.2 密码套件是否使用 ECDHE 密钥交换

// 客户端 ClientHello 套件列表：基础（证书类）+ 可选 PSK（仅配置了 TLS 1.2 PSK 时）
static std::vector<uint16_t> tls12_client_suite_list(const tls_session& s){
    std::vector<uint16_t> out;
    out.insert(out.end(), std::begin(TLS12_CLIENT_CIPHERS), std::end(TLS12_CLIENT_CIPHERS));
    if (s.tls12_psk_valid)
        out.insert(out.end(), std::begin(TLS12_CLIENT_PSK_CIPHERS), std::end(TLS12_CLIENT_PSK_CIPHERS));
    return out;
}

// supported_groups (0x000a) 扩展：X25519 + P-256/P-384 + ffdhe2048。
// OpenSSL 要求 ECDSA 证书的曲线必须出现在客户端通告的组里（否则 ECDHE-ECDSA
// 报 no shared cipher），因此除临时密钥组外还要通告证书曲线组。
static void tls12_append_supported_groups(std::vector<uint8_t>& ext){
    static const uint16_t groups[] = { 0x001d, 0x0017, 0x0019, 0x0100 }; // X25519, P-256, P-384, ffdhe2048
    // RFC 7919 §3 / RFC 4492 §5.1：supported_groups 扩展数据 =
    //   NamedGroupList（uint16 长度 + 各组 2 字节）
    size_t list_len = sizeof(groups);   // 2*count
    size_t ext_len = 2 + list_len;      // 内部长度字段 2 字节 + 组列表
    ext.push_back(0x00); ext.push_back(0x0a);            // 扩展类型
    ext.push_back((uint8_t)(ext_len >> 8)); ext.push_back((uint8_t)ext_len);
    ext.push_back((uint8_t)(list_len >> 8)); ext.push_back((uint8_t)list_len);
    for (uint16_t g : groups) {
        ext.push_back((uint8_t)(g >> 8));
        ext.push_back((uint8_t)g);
    }
}

// TLS 1.2 ServerKeyExchange 签名验证（RFC 5246 7.4.3 / RFC 4492 5.4）：
// 签名字节 = client_random || server_random || ServerDHParams
static bool tls12_verify_skx_signature(const tls_certificate& cert, uint16_t alg,
                                       const uint8_t* sig, size_t sig_len,
                                       const uint8_t* params, size_t params_len,
                                       const tls_session& s){
    if (alg == 0 || !sig || sig_len == 0) return false;
    std::vector<uint8_t> signed_data;
    signed_data.insert(signed_data.end(), s.client_random, s.client_random + 32);
    signed_data.insert(signed_data.end(), s.server_random, s.server_random + 32);
    signed_data.insert(signed_data.end(), params, params + params_len);
    return cert.verify_scheme(alg, signed_data.data(), signed_data.size(), sig, sig_len);
}

// 校验 ffdhe2048 群参数（RFC 7919 §3）：p/g 必须与命名群一致，且 1 < Ys < p-1
static bool tls12_check_ffdhe2048_params(const uint8_t* p, size_t p_len,
                                         const uint8_t* g, size_t g_len,
                                         const uint8_t* ys, size_t ys_len){
    using namespace jpssl::dh;
    if (p_len != FFDHE2048_BYTES || memcmp(p, ffdhe2048_p, FFDHE2048_BYTES) != 0) return false;
    if (g_len != 1 || g[0] != FFDHE2048_G) return false;
    if (ys_len != FFDHE2048_BYTES) return false;
    rsa_bignum one = rsa_bignum::from_uint64(1);
    rsa_bignum p_bn = ffdhe2048_bignum(ffdhe2048_p);
    rsa_bignum p_minus_1;
    bn_sub(p_minus_1, p_bn, one);
    rsa_bignum y = ffdhe2048_bignum(ys);
    return (one < y) && (y < p_minus_1);
}

// ══════════════════════════════════════════════════════════════════════�?
//  TLS 1.2 完整握手 �?客户�?
// ══════════════════════════════════════════════════════════════════════�?
bool tls12_make_client_hello(tls_session& s, std::vector<uint8_t>& client_hello){
    s.ver=TLSVersion::V12;s.is_server=false;
    s.transcript_ready=false;
    rand32(s.client_random);
    client_hello.clear();
    client_hello.push_back((uint8_t)HandshakeType::CLIENT_HELLO);
    client_hello.push_back(0);client_hello.push_back(0);client_hello.push_back(0);
    client_hello.push_back(0x03);client_hello.push_back(0x03);
    client_hello.insert(client_hello.end(),s.client_random,s.client_random+32);
    // Cipher suites: dynamic list（PSK 套件仅在配置了 TLS 1.2 PSK 时提供）
    std::vector<uint16_t> cs_list = tls12_client_suite_list(s);
    size_t cs_count = cs_list.size();
    client_hello.push_back(0); // session_id_len = 0
    client_hello.push_back((uint8_t)(cs_count*2 >> 8)); client_hello.push_back((uint8_t)(cs_count*2));
    for(size_t ci = 0; ci < cs_count; ++ci){
        uint16_t cs = cs_list[ci];
        client_hello.push_back((uint8_t)(cs>>8)); client_hello.push_back((uint8_t)cs);
    }
    client_hello.push_back(0x01); client_hello.push_back(0x00); // compression: null
    (void)cs_count;

    // extensions: SNI + supported_groups + signature_algorithms
    std::vector<uint8_t> ext;
    if(!s.server_name.empty()){
        ext.push_back(0x00);ext.push_back(0x00);
        uint16_t sni_len=5+s.server_name.size();
        ext.push_back(0x00);ext.push_back((uint8_t)sni_len);
        uint16_t nl_len=3+s.server_name.size();
        ext.push_back(0x00);ext.push_back((uint8_t)nl_len);
        ext.push_back(0x00);
        ext.push_back(0x00);ext.push_back((uint8_t)s.server_name.size());
        for(char c:s.server_name)ext.push_back((uint8_t)c);
    }
    // supported_groups：DHE 套件要求客户端通告 ffdhe2048（RFC 7919 §3）
    tls12_append_supported_groups(ext);
    // signature_algorithms + signature_algorithms_cert
    {
        const std::vector<uint16_t>& algs = effective_sig_algs(s);
        std::vector<uint16_t> cert_algs =
            s.sig_algs_cert.empty() ? tls_default_signature_algorithms() : s.sig_algs_cert;
        std::vector<uint16_t> cert_filtered;
        for (uint16_t a : cert_algs) if (scheme_in_list(algs, a)) cert_filtered.push_back(a);
        append_sig_alg_extension(ext, 0x000d, algs);
        append_sig_alg_extension(ext, 0x0032, cert_filtered);
    }
    uint16_t ext_total=ext.size();
    client_hello.push_back((uint8_t)(ext_total>>8));client_hello.push_back((uint8_t)ext_total);
    client_hello.insert(client_hello.end(),ext.begin(),ext.end());
    size_t len=client_hello.size()-4;
    client_hello[1]=(uint8_t)(len>>16);client_hello[2]=(uint8_t)(len>>8);client_hello[3]=(uint8_t)len;
    // ClientHello 暂不加入 transcript：此�?cipher_suite 尚未协商（服务端才会
    // 选定），transcript 哈希算法（SHA-256/SHA-384）依�?cipher_suite�?
    // 缓存原始字节，待 tls12_process_server_flight 解析出套件后再初始化�?
    s.tls12_client_hello_cache = client_hello;
    return true;
}

bool tls12_process_server_flight(tls_session& s, const uint8_t* server_response, size_t resp_len,
                                  const uint8_t* pre_master_secret, size_t pms_len,
                                  std::vector<uint8_t>& client_finished,
                                  std::vector<uint8_t>* client_key_exchange,
                                  const tls_certificate_manager* cert_manager,
                                  const tls_trust_store* trust_store){
    if(resp_len<4 || server_response[0]!=(uint8_t)HandshakeType::SERVER_HELLO)return false;
    size_t sh_len=(server_response[1]<<16)|(server_response[2]<<8)|server_response[3];
    if(4+sh_len>resp_len)return false;
    // Parse selected cipher suite from ServerHello body
    // ServerHello body: version(2) + random(32) + session_id_len(1) + session_id(sid_len)
    //                   + cipher_suite(2) + compression(1) + extensions...
    size_t sid_off = 4 + 2 + 32;  // after handshake header + version + random
    if (sid_off >= resp_len) return false;
    size_t sid_len = server_response[sid_off];
    size_t cs_off = sid_off + 1 + sid_len;
    if (cs_off + 2 > resp_len) return false;
    uint16_t sel_cs = (server_response[cs_off]<<8) | server_response[cs_off+1];
    CipherSuite cs = select_cipher_suite(sel_cs);
    if (cs == CipherSuite::UNKNOWN) return false;   // 未知套件直接拒绝
    s.cipher_suite = cs;
    // transcript hash depends on cipher_suite; ClientHello was cached in
    // tls12_make_client_hello and is replayed here after the suite is known.
    if (!s.tls12_client_hello_cache.empty())
        tls_transcript_update(s, s.tls12_client_hello_cache.data(), s.tls12_client_hello_cache.size());
    tls_transcript_update(s,server_response,4+sh_len);
    memcpy(s.server_random,server_response+6,32);

    // Legacy path (backward compatible): caller supplies the premaster and does
    // not request a ClientKeyExchange; only ServerHello is parsed and the
    // transcript stays ClientHello + ServerHello (historical behavior).
    if (pre_master_secret && pms_len > 0 && !client_key_exchange) {
        tls12_derive_keys(s, pre_master_secret, pms_len);
        tls_transcript_finalize(s);
        uint8_t verify_data[12];
        size_t hl = tls_hash_len(s.cipher_suite);
        if (tls_use_sha384(s.cipher_suite))
            tls12_prf_sha384(s.master_secret,48,"client finished",s.transcript_hash,hl,verify_data,12);
        else
            tls12_prf(s.master_secret,48,"client finished",s.transcript_hash,hl,verify_data,12);
        client_finished.clear();
        client_finished.push_back((uint8_t)HandshakeType::FINISHED);
        client_finished.push_back(0);client_finished.push_back(0);client_finished.push_back(12);
        client_finished.insert(client_finished.end(),verify_data,verify_data+12);
        tls_transcript_update(s,client_finished.data(),client_finished.size());
        return true;
    }

    // Full path: parse Certificate / ServerKeyExchange / ServerHelloDone,
    // compute the premaster per suite and build the ClientKeyExchange.
    std::vector<uint8_t> premaster;
    std::vector<uint8_t> cke;
    std::vector<x509::x509_cert> cert_chain;
    std::unique_ptr<tls_certificate> parsed_server_cert;
    const tls_certificate* server_cert = nullptr;
    const uint8_t* skx_sig = nullptr; size_t skx_sig_len = 0; uint16_t skx_sig_alg = 0;
    std::vector<uint8_t> skx_params;   // ServerDHParams (for signature and group checks)
    uint8_t server_ec_pub[96] = {0};   // ECDHE server ephemeral pubkey（X25519 32 / P-256 64 / P-384 96）
    int server_ec_type = 0;            // 1=X25519, 2=secp256r1, 3=secp384r1
    uint8_t server_dh_ys[256] = {0};   // DHE server ephemeral pubkey
    bool server_dh_ok = false;

    size_t off = 4 + sh_len;
    while (off + 4 <= resp_len) {
        uint8_t htype = server_response[off];
        size_t hlen = ((size_t)server_response[off+1] << 16) |
                      ((size_t)server_response[off+2] << 8) | server_response[off+3];
        if (off + 4 + hlen > resp_len) return false;
        const uint8_t* body = server_response + off + 4;
        switch (htype) {
            case (uint8_t)HandshakeType::CERTIFICATE: {
                tls_transcript_update(s, server_response + off, 4 + hlen);
                size_t list_len = ((size_t)body[0] << 16) | ((size_t)body[1] << 8) | body[2];
                size_t p = 3;
                size_t end = 3 + list_len;
                if (end > hlen) return false;
                const std::vector<uint16_t>& cert_algs =
                    s.sig_algs_cert.empty() ? tls_default_signature_algorithms() : s.sig_algs_cert;
                std::vector<x509::x509_cert> chain;
                while (p + 3 <= end) {
                    size_t clen = ((size_t)body[p] << 16) | ((size_t)body[p+1] << 8) | body[p+2];
                    p += 3;
                    if (p + clen > end) return false;
                    auto parsed = x509::x509_cert::from_der(body + p, clen);
                    if (!parsed) return false;
                    uint16_t chain_scheme = x509_key_type_chain_scheme(parsed->sign_key_type);
                    if (chain_scheme != 0 && !scheme_in_list(cert_algs, chain_scheme)) return false;
                    chain.push_back(std::move(*parsed));
                    p += clen;
                }
                if (chain.empty()) return false;
                if (trust_store) {
                    if (!tls13_verify_server_chain(chain, *trust_store, s.server_name)) return false;
                    if (chain.empty() ||
                        !(parsed_server_cert = tls_cert_from_x509_leaf(chain[0])))
                        return false;
                    server_cert = parsed_server_cert.get();
                }
                cert_chain = std::move(chain);
                break;
            }
            case (uint8_t)HandshakeType::SERVER_KEY_EXCHANGE: {
                tls_transcript_update(s, server_response + off, 4 + hlen);
                size_t p = 0;
                if (tls12_is_ecdhe(s.cipher_suite)) {
                    // curve_type(1)=3 + named_curve(2) + pub_len(1) + pub + [sig]
                    if (p + 4 > hlen) return false;
                    uint8_t curve_type = body[p++];
                    uint16_t named_curve = (body[p] << 8) | body[p+1]; p += 2;
                    if (curve_type != 3) return false;
                    uint8_t pub_len = body[p++];
                    size_t raw_len = 0;
                    if (named_curve == 0x001d) {        // X25519（RFC 8422 §5.1：裸 32 字节）
                        if (pub_len != 32) return false;
                        raw_len = 32;
                        server_ec_type = 1;
                    } else if (named_curve == 0x0017) { // secp256r1：uncompressed 0x04||x||y
                        if (pub_len != 65 || body[p] != 0x04) return false;
                        raw_len = 64;
                        server_ec_type = 2;
                    } else if (named_curve == 0x0019) { // secp384r1
                        if (pub_len != 97 || body[p] != 0x04) return false;
                        raw_len = 96;
                        server_ec_type = 3;
                    } else {
                        return false; // 不支持的命名曲线
                    }
                    if (p + pub_len > hlen) return false;
                    memcpy(server_ec_pub, body + p + (pub_len - raw_len), raw_len);
                    p += pub_len;
                    skx_params.assign(body, body + p);
                    if (p + 4 <= hlen) {
                        skx_sig_alg = (body[p] << 8) | body[p+1]; p += 2;
                        skx_sig_len = (body[p] << 8) | body[p+1]; p += 2;
                        if (p + skx_sig_len > hlen) return false;
                        skx_sig = body + p;
                    }
                } else {
                    // DHE-RSA / DHE-PSK: [psk_identity_hint] || ServerDHParams [|| signature]
                    if (tls12_is_dhe_psk(s.cipher_suite)) {
                        if (p + 2 > hlen) return false;
                        uint16_t hint_len = (body[p] << 8) | body[p+1]; p += 2;
                        if (p + hint_len > hlen) return false;
                        p += hint_len;
                    }
                    // ServerDHParams: dh_p(2+len) || dh_g(2+len) || dh_Ys(2+len)
                    const uint8_t* dp = nullptr; size_t dpl = 0;
                    const uint8_t* dg = nullptr; size_t dgl = 0;
                    const uint8_t* dys = nullptr; size_t dysl = 0;
                    auto read_par = [&](const uint8_t*& ptr, size_t& pl) -> bool {
                        if (p + 2 > hlen) return false;
                        pl = (body[p] << 8) | body[p+1]; p += 2;
                        if (p + pl > hlen) return false;
                        ptr = body + p; p += pl;
                        return true;
                    };
                    if (!read_par(dp, dpl) || !read_par(dg, dgl) || !read_par(dys, dysl))
                        return false;
                    // ffdhe2048: p(256) || g(1, =2) || Ys(256)
                    if (dpl != 256 || dgl != 1 || dysl != 256 || *dg != 2)
                        return false;
                    memcpy(server_dh_ys, dys, dysl);
                    server_dh_ok = true;
                    skx_params.assign(body, body + p);
                    if (tls12_is_dhe_rsa(s.cipher_suite) && p + 4 <= hlen) {
                        skx_sig_alg = (body[p] << 8) | body[p+1]; p += 2;
                        skx_sig_len = (body[p] << 8) | body[p+1]; p += 2;
                        if (p + skx_sig_len > hlen) return false;
                        skx_sig = body + p;
                    }
                }
                break;
            }
            case (uint8_t)HandshakeType::SERVER_HELLO_DONE:
                tls_transcript_update(s, server_response + off, 4 + hlen);
                break;
            case (uint8_t)HandshakeType::FINISHED:
                // Legacy simplified server flights may trail a Server Finished;
                // ignore it (not part of the client transcript).
                off = resp_len;
                continue;
            default:
                tls_transcript_update(s, server_response + off, 4 + hlen);
                break;
        }
        off += 4 + hlen;
    }

    // Server certificate source: trust_store parsed above; else cert_manager
    // (internal self-signed tests); else the leaf cert from the wire.
    if (!server_cert && cert_manager) {
        server_cert = cert_manager->get_certificate(s.server_name);
        if (!server_cert) server_cert = cert_manager->get_default_certificate();
    }
    if (!server_cert && !cert_chain.empty()) {
        if (!(parsed_server_cert = tls_cert_from_x509_leaf(cert_chain[0])))
            return false;
        server_cert = parsed_server_cert.get();
    }

    // Premaster computation and ClientKeyExchange construction
    uint8_t client_ec_pub[32], client_ec_priv[32];
    uint8_t client_dh_pub[256], client_dh_priv[32];
    if (tls12_is_ecdhe(s.cipher_suite)) {
        if (skx_params.empty() || !skx_sig || !server_cert) return false;
        if (!scheme_in_list(effective_sig_algs(s), skx_sig_alg)) return false;
        if (!tls12_verify_skx_signature(*server_cert, skx_sig_alg, skx_sig, skx_sig_len,
                                        skx_params.data(), skx_params.size(), s))
            return false;
        if (server_ec_type == 1) {
            x25519_generate_keypair(client_ec_pub, client_ec_priv);
            uint8_t shared[32];
            x25519_scalar_mult(shared, client_ec_priv, server_ec_pub);
            premaster.assign(shared, shared + 32);
            // ClientKeyExchange: 1-byte length + 32-byte pubkey (RFC 8422 §5.7)
            cke.push_back((uint8_t)HandshakeType::CLIENT_KEY_EXCHANGE);
            cke.push_back(0); cke.push_back(0); cke.push_back(33);
            cke.push_back(32);
            cke.insert(cke.end(), client_ec_pub, client_ec_pub + 32);
        } else if (server_ec_type == 2) {
            uint8_t pub[64], priv[32], shared[32];
            ecdsa_p256_keygen(pub, priv);
            if (!ecdsa_p256_ecdh(shared, priv, server_ec_pub)) return false;
            premaster.assign(shared, shared + 32);
            // ClientKeyExchange: 1-byte length + 0x04||x||y（RFC 4492 5.7）
            cke.push_back((uint8_t)HandshakeType::CLIENT_KEY_EXCHANGE);
            cke.push_back(0); cke.push_back(0); cke.push_back(66);
            cke.push_back(65);
            cke.push_back(0x04);
            cke.insert(cke.end(), pub, pub + 64);
        } else if (server_ec_type == 3) {
            uint8_t pub[96], priv[48], shared[48];
            ecdsa_p384_keygen(pub, priv);
            if (!ecdsa_p384_ecdh(shared, priv, server_ec_pub)) return false;
            premaster.assign(shared, shared + 48);
            cke.push_back((uint8_t)HandshakeType::CLIENT_KEY_EXCHANGE);
            cke.push_back(0); cke.push_back(0); cke.push_back(98);
            cke.push_back(97);
            cke.push_back(0x04);
            cke.insert(cke.end(), pub, pub + 96);
        } else {
            return false;
        }
    } else if (tls12_is_dhe_rsa(s.cipher_suite)) {
        if (!server_dh_ok || !skx_sig || !server_cert) return false;
        if (!scheme_in_list(effective_sig_algs(s), skx_sig_alg)) return false;
        if (!tls12_verify_skx_signature(*server_cert, skx_sig_alg, skx_sig, skx_sig_len,
                                        skx_params.data(), skx_params.size(), s))
            return false;
        jpssl::dh::ffdhe2048_keypair(client_dh_pub, client_dh_priv);
        uint8_t shared256[256];
        if (!jpssl::dh::ffdhe2048_shared(shared256, client_dh_priv, server_dh_ys))
            return false;
        uint8_t minimal[256];
        size_t n = jpssl::dh::ffdhe2048_shared_minimal(shared256, minimal);
        premaster.assign(minimal, minimal + n);
        // ClientKeyExchange: dh_Yc(2+len)
        cke.push_back((uint8_t)HandshakeType::CLIENT_KEY_EXCHANGE);
        cke.push_back(0); cke.push_back((uint8_t)(258 >> 8)); cke.push_back((uint8_t)258);
        cke.push_back(0x01); cke.push_back(0x00);
        cke.insert(cke.end(), client_dh_pub, client_dh_pub + 256);
    } else if (tls12_is_dhe_psk(s.cipher_suite)) {
        if (!server_dh_ok || !s.tls12_psk_valid) return false;
        jpssl::dh::ffdhe2048_keypair(client_dh_pub, client_dh_priv);
        uint8_t shared256[256];
        if (!jpssl::dh::ffdhe2048_shared(shared256, client_dh_priv, server_dh_ys))
            return false;
        uint8_t minimal[256];
        size_t n = jpssl::dh::ffdhe2048_shared_minimal(shared256, minimal);
        premaster = tls12_psk_premaster(s.tls12_psk_value, s.tls12_psk_value_len,
                                        minimal, n);
        // ClientKeyExchange: identity(2+len) || dh_Yc(2+len)
        size_t id_len = s.tls12_psk_identity_len;
        size_t cke_len = 2 + id_len + 2 + 256;
        cke.push_back((uint8_t)HandshakeType::CLIENT_KEY_EXCHANGE);
        cke.push_back((uint8_t)(cke_len >> 16)); cke.push_back((uint8_t)(cke_len >> 8));
        cke.push_back((uint8_t)cke_len);
        cke.push_back((uint8_t)(id_len >> 8)); cke.push_back((uint8_t)id_len);
        cke.insert(cke.end(), s.tls12_psk_identity, s.tls12_psk_identity + id_len);
        cke.push_back(0x01); cke.push_back(0x00);
        cke.insert(cke.end(), client_dh_pub, client_dh_pub + 256);
    } else if (tls12_is_psk(s.cipher_suite)) {
        if (!s.tls12_psk_valid) return false;
        premaster = tls12_psk_premaster(s.tls12_psk_value, s.tls12_psk_value_len,
                                        nullptr, 0);
        size_t id_len = s.tls12_psk_identity_len;
        size_t cke_len = 2 + id_len;
        cke.push_back((uint8_t)HandshakeType::CLIENT_KEY_EXCHANGE);
        cke.push_back((uint8_t)(cke_len >> 16)); cke.push_back((uint8_t)(cke_len >> 8));
        cke.push_back((uint8_t)cke_len);
        cke.push_back((uint8_t)(id_len >> 8)); cke.push_back((uint8_t)id_len);
        cke.insert(cke.end(), s.tls12_psk_identity, s.tls12_psk_identity + id_len);
    } else {
        // RSA: premaster supplied by the caller
        if (!pre_master_secret || pms_len == 0) return false;
        premaster.assign(pre_master_secret, pre_master_secret + pms_len);
        if (client_key_exchange && server_cert) {
            uint8_t encrypted[256];
            rsa_encrypt(server_cert->pub.rsa, jpssl::span<const uint8_t>(premaster), encrypted);
            cke.push_back((uint8_t)HandshakeType::CLIENT_KEY_EXCHANGE);
            cke.push_back(0); cke.push_back((uint8_t)(258 >> 8)); cke.push_back((uint8_t)258);
            cke.push_back(0x01); cke.push_back(0x00);
            cke.insert(cke.end(), encrypted, encrypted + 256);
        }
    }

    tls12_derive_keys(s, premaster.data(), premaster.size());
    if (!cke.empty())
        tls_transcript_update(s, cke.data(), cke.size());
    tls_transcript_finalize(s);
    uint8_t verify_data[12];
    size_t hl = tls_hash_len(s.cipher_suite);
    if (tls_use_sha384(s.cipher_suite))
        tls12_prf_sha384(s.master_secret,48,"client finished",s.transcript_hash,hl,verify_data,12);
    else
        tls12_prf(s.master_secret,48,"client finished",s.transcript_hash,hl,verify_data,12);
    client_finished.clear();
    client_finished.push_back((uint8_t)HandshakeType::FINISHED);
    client_finished.push_back(0);client_finished.push_back(0);client_finished.push_back(12);
    client_finished.insert(client_finished.end(),verify_data,verify_data+12);
    tls_transcript_update(s,client_finished.data(),client_finished.size());
    if (client_key_exchange) *client_key_exchange = std::move(cke);
    return true;
}

// ══════════════════════════════════════════════════════════════════════�?
//  TLS 1.2 简化版 API（兼容旧接口�?
// ══════════════════════════════════════════════════════════════════════�?
bool tls12_handshake_client(tls_session& s, std::vector<uint8_t>& client_hello,
                             const uint8_t* server_response, size_t resp_len,
                             const uint8_t* pre_master_secret, size_t pms_len){
    s.ver=TLSVersion::V12;rand32(s.client_random);
    client_hello.clear();
    client_hello.push_back((uint8_t)HandshakeType::CLIENT_HELLO);
    client_hello.push_back(0);client_hello.push_back(0);client_hello.push_back(0);
    client_hello.push_back(0x03);client_hello.push_back(0x03);
    client_hello.insert(client_hello.end(),s.client_random,s.client_random+32);
    // Cipher suites: dynamic list（PSK 套件仅在配置了 TLS 1.2 PSK 时提供）
    std::vector<uint16_t> cs_list = tls12_client_suite_list(s);
    size_t cs_n = cs_list.size();
    client_hello.push_back(0);
    client_hello.push_back((uint8_t)(cs_n*2>>8)); client_hello.push_back((uint8_t)(cs_n*2));
    for(size_t i=0; i<cs_n; ++i){
        uint16_t c = cs_list[i];
        client_hello.push_back((uint8_t)(c>>8)); client_hello.push_back((uint8_t)c);
    }
    client_hello.push_back(0x01); client_hello.push_back(0x00);
    // supported_groups：DHE 套件要求客户端通告 ffdhe2048（RFC 7919 §3）
    std::vector<uint8_t> ext;
    tls12_append_supported_groups(ext);
    // signature_algorithms + signature_algorithms_cert
    {
        const std::vector<uint16_t>& algs = effective_sig_algs(s);
        std::vector<uint16_t> cert_algs =
            s.sig_algs_cert.empty() ? tls_default_signature_algorithms() : s.sig_algs_cert;
        std::vector<uint16_t> cert_filtered;
        for (uint16_t a : cert_algs) if (scheme_in_list(algs, a)) cert_filtered.push_back(a);
        append_sig_alg_extension(ext, 0x000d, algs);
        append_sig_alg_extension(ext, 0x0032, cert_filtered);
    }
    uint16_t ext_total = (uint16_t)ext.size();
    client_hello.push_back((uint8_t)(ext_total >> 8)); client_hello.push_back((uint8_t)ext_total);
    client_hello.insert(client_hello.end(), ext.begin(), ext.end());
    size_t len=client_hello.size()-4;
    client_hello[1]=(uint8_t)(len>>16);client_hello[2]=(uint8_t)(len>>8);client_hello[3]=(uint8_t)len;
    (void)server_response;(void)resp_len;
    memcpy(s.server_random,server_response+6,32);
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

} // namespace tls
} // namespace jpssl
