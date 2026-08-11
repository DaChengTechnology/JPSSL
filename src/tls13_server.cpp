/**
 * TLS 1.3 服务端握手实现（由原 tls.cpp 拆分而来）
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
size_t client_hello_ext_offset(const uint8_t* ch, size_t ch_len);
bool client_hello_find_extension(const uint8_t* ch, size_t ch_len, uint16_t want, const uint8_t*& data, size_t& dlen);
bool parse_sig_alg_list(const uint8_t* p, size_t len, std::vector<uint16_t>& out);
bool scheme_in_list(const std::vector<uint16_t>& list, uint16_t scheme);
uint16_t select_signature_scheme(const std::vector<uint16_t>& peer_list, const tls_certificate& cert, const std::vector<uint16_t>& local_list, bool tls13);
uint16_t cert_chain_signature_scheme(const tls_certificate& cert);
size_t aes_key_len(CipherSuite cs);
void aes_ctx_init(aes_context& ctx, const uint8_t* key, size_t key_len);
void sm4_ctx_init_from_key(sm4_ctx& ctx, const uint8_t* key);
void init_cipher_ctx(tls_session& s, const uint8_t* key);
void tls13_derive_handshake_keys(tls_session& s, const uint8_t* shared_secret, size_t shared_len);
void tls13_derive_application_keys(tls_session& s);
std::vector<uint8_t> tls13_make_finished(tls_session& s, bool for_server);
bool tls13_verify_finished(tls_session& s, const uint8_t* hs_msg, size_t hs_len, bool for_server);
std::vector<uint8_t> tls13_cert_verify_content(tls_session& s, bool for_server);
bool tls13_decrypt_handshake(tls_session& s, const uint8_t* record, size_t record_len, std::vector<uint8_t>& hs_out);
void tls13_derive_resumption_secret(tls_session& s, uint8_t out[48]);
void tls13_derive_early_traffic_keys(tls_session& s, const uint8_t* psk);
void tls13_compute_binder(tls_session& s, const uint8_t* psk, const uint8_t* ch_truncated, size_t ch_trunc_len, uint8_t* binder);


// ══════════════════════════════════════════════════════════════════════�?
//  构建 Certificate + CertificateVerify 消息
// ══════════════════════════════════════════════════════════════════════�?
static std::vector<uint8_t> tls13_make_certificate(const tls_certificate& cert){
    // Auto-generate X.509 DER if cert_data is empty
    std::vector<uint8_t> der_data = cert.cert_data;
    if (der_data.empty()) {
        der_data = tls_make_x509_self_signed(cert);
    }

    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::CERTIFICATE);
    // TLS 1.3 Certificate: body = context_len(1) + context(0) + list_len(3) + [cert_len(3)+cert+ext_len(2)]
    size_t cert_entry_len=3+der_data.size()+2;
    size_t body_len=1+3+cert_entry_len;
    msg.push_back((uint8_t)(body_len>>16));msg.push_back((uint8_t)(body_len>>8));msg.push_back((uint8_t)body_len);
    msg.push_back(0); // certificate_request_context
    // certificate_list length
    msg.push_back((uint8_t)(cert_entry_len>>16));msg.push_back((uint8_t)(cert_entry_len>>8));msg.push_back((uint8_t)cert_entry_len);
    msg.push_back((uint8_t)(der_data.size()>>16));msg.push_back((uint8_t)(der_data.size()>>8));msg.push_back((uint8_t)der_data.size());
    msg.insert(msg.end(),der_data.begin(),der_data.end());
    // extensions: 0 length
    msg.push_back(0);msg.push_back(0);
    return msg;
}

static std::vector<uint8_t> tls13_make_cert_verify(const tls_certificate& cert, tls_session& s){
    // RSA-2048 PKCS#1 签名�?256 字节；缓冲区按最大签�?(512B) 预留�?
    // 避免 RSA 证书�?TLS 1.3 CertificateVerify 中发生栈溢出�?
    uint8_t sig[512];size_t sig_len=0;
    std::vector<uint8_t> content = tls13_cert_verify_content(s, true);
    // RFC 8998 3.2.1: handshake signature uses SM2 id "TLSv1.3+GM+Cipher+Suite"
    uint8_t za[32] = {};
    const uint8_t* za_ptr = nullptr;
    if (s.selected_sig_alg == (uint16_t)SignatureAlgorithm::SM2_SM3) {
        static const char kSm2TlsId[] = "TLSv1.3+GM+Cipher+Suite";
        sm2_compute_za((const uint8_t*)kSm2TlsId, sizeof(kSm2TlsId) - 1,
                       cert.pub.sm2, cert.pub.sm2 + 32, za);
        za_ptr = za;
    }
    if(!cert.sign_scheme(s.selected_sig_alg, content.data(), content.size(), sig, sig_len, za_ptr)) return {};

    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::CERT_VERIFY);
    uint16_t alg = s.selected_sig_alg;
    size_t body_len=2+2+sig_len;
    msg.push_back((uint8_t)(body_len>>16));msg.push_back((uint8_t)(body_len>>8));msg.push_back((uint8_t)body_len);
    msg.push_back((uint8_t)(alg>>8));msg.push_back((uint8_t)alg);
    msg.push_back((uint8_t)(sig_len>>8));msg.push_back((uint8_t)sig_len);
    msg.insert(msg.end(),sig,sig+sig_len);
    return msg;
}


// ══════════════════════════════════════════════════════════════════════�?
//  构建 EncryptedExtensions
// ══════════════════════════════════════════════════════════════════════�?
// alpn_selected 非空时携�?ALPN 扩展（RFC 7301：服务端只选择一个协议）�?
static std::vector<uint8_t> tls13_make_encrypted_extensions(
    const std::string& alpn_selected,
    const std::vector<uint8_t>* quic_transport_params = nullptr) {
    std::vector<uint8_t> msg;
    std::vector<uint8_t> ext;
    if (!alpn_selected.empty()) {
        ext.push_back(0x00);ext.push_back(0x10); // ALPN 扩展类型
        uint16_t list_len = (uint16_t)(1 + alpn_selected.size());
        ext.push_back((uint8_t)((2 + list_len) >> 8));
        ext.push_back((uint8_t)(2 + list_len));
        ext.push_back((uint8_t)(list_len >> 8));
        ext.push_back((uint8_t)list_len);
        ext.push_back((uint8_t)alpn_selected.size());
        ext.insert(ext.end(), alpn_selected.begin(), alpn_selected.end());
    }
    // QUIC (RFC 9001 §8.2)：EncryptedExtensions 必须携带 quic_transport_parameters
    if (quic_transport_params) {
        ext.push_back(0x00);ext.push_back(0x39);
        ext.push_back((uint8_t)(quic_transport_params->size() >> 8));
        ext.push_back((uint8_t)quic_transport_params->size());
        ext.insert(ext.end(), quic_transport_params->begin(), quic_transport_params->end());
    }
    uint16_t ext_total = (uint16_t)ext.size();
    msg.push_back((uint8_t)HandshakeType::ENCRYPTED_EXTENSIONS);
    msg.push_back(0);msg.push_back(0);
    msg.push_back((uint8_t)(2 + ext_total)); // extensions 区总长
    msg.push_back((uint8_t)(ext_total >> 8));msg.push_back((uint8_t)ext_total);
    msg.insert(msg.end(), ext.begin(), ext.end());
    return msg;
}

// ══════════════════════════════════════════════════════════════════════�?
//  TLS 1.3 完整握手 �?服务�?
// ══════════════════════════════════════════════════════════════════════�?
bool tls13_make_server_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                               std::vector<uint8_t>& server_flight,
                               const tls_certificate_manager& cert_manager){
    s.ver=TLSVersion::V13;s.is_server=true;
    s.transcript_ready=false;
    rand32(s.server_random);
    memcpy(s.client_random,client_hello+6,32);

    // RFC 8446 4.1.3：ServerHello 必须回显 ClientHello �?legacy_session_id
    // （OpenSSL 等客户端会严格校验，不一致报 "invalid session id"�?
    size_t ch_sid_len = 0;
    const uint8_t* ch_sid = nullptr;
    if (ch_len >= 4 + 2 + 32 + 1) {
        ch_sid_len = client_hello[4 + 2 + 32];
        if (ch_sid_len > 0 && 4 + 2 + 32 + 1 + ch_sid_len <= ch_len) {
            ch_sid = client_hello + 4 + 2 + 32 + 1;
        } else {
            ch_sid_len = 0;
        }
    }

    // 解析 SNI（须在 cipher_suite 选择前，供证书类型过滤使用）
    uint16_t ext_len_total=0;
    size_t ext_offset=client_hello_ext_offset(client_hello,ch_len);
    if(ext_offset+2<=ch_len){
        ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);
    if(!cert)return false;

    // ── 密码套件协商（RFC 8446 §4.1.3：只能从客户端通告列表中选；无交集即失败）──
    // 默认偏好：国密（RFC 8998）> ChaCha20-Poly1305 > AES-GCM/CCM。
    // 国密套件要求服务端 SM2 证书（RFC 8998），否则跳过。
    { size_t cs_off = 4+2+32; uint8_t sid_len = client_hello[cs_off]; cs_off += 1+sid_len;
      uint16_t cs_list_len = (client_hello[cs_off]<<8)|client_hello[cs_off+1]; cs_off += 2;
      std::vector<uint16_t> client_cs;
      for(size_t i=0; i+2<=cs_list_len; i+=2)
        client_cs.push_back((client_hello[cs_off+i]<<8)|client_hello[cs_off+i+1]);
      auto cs_has = [&](uint16_t id){ for (uint16_t c : client_cs) if (c==id) return true; return false; };
      bool cert_is_sm2 = (cert->sig_alg == SignatureAlgorithm::SM2_SM3);
      // QUIC 模式（RFC 9001 §5）的 AEAD 集合不含国密套件，服务端同样不得选择
      auto sm_ok = [&](uint16_t id){ return !s.quic_mode && cert_is_sm2 && cs_has(id); };
      bool pinned_ok = s.cipher_suite_pinned && cs_has((uint16_t)s.cipher_suite)
                       && (!tls_use_sm3(s.cipher_suite) || (cert_is_sm2 && !s.quic_mode));
      if (pinned_ok) {
          s.cipher_suite = s.cipher_suite;   // 保持显式固定套件
      } else if (sm_ok(0x00C6)) s.cipher_suite = CipherSuite::TLS_SM4_GCM_SM3;
      else if (sm_ok(0x00C7)) s.cipher_suite = CipherSuite::TLS_SM4_CCM_SM3;
      else if (cs_has(0x1303)) s.cipher_suite = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
      else if (cs_has(0x1301)) s.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
      else if (cs_has(0x1302)) s.cipher_suite = CipherSuite::TLS_AES_256_GCM_SHA384;
      else if (cs_has(0x1304)) s.cipher_suite = CipherSuite::TLS_AES_128_CCM_SHA256;
      else if (cs_has(0x1305)) s.cipher_suite = CipherSuite::TLS_AES_128_CCM_8_SHA256;
      else return false;   // 无共同套件（不再兜底选择客户端未通告的套件）
    }

    // 记录 ClientHello (须在 cipher_suite 确定�? 保证 transcript 哈希算法与客户端一�?
    tls_transcript_update(s,client_hello,ch_len);

    // ALPN (RFC 7301)：解析客户端协议列表并与本地支持列表匹配选择
    s.alpn_selected.clear();
    if (!s.alpn_protos.empty()) {
        const uint8_t* alpn_data = nullptr;
        size_t alpn_len = 0;
        if (client_hello_find_extension(client_hello, ch_len, 0x0010,
                                        alpn_data, alpn_len)) {
            std::vector<std::string> client_alpn =
                tls_parse_alpn_list(alpn_data, alpn_len);
            s.alpn_selected = tls_select_alpn(client_alpn, s.alpn_protos);
        }
    }

    // 提取 client_pub（支�?X25519、X448 �?curveSM2）和 supported_groups
    uint8_t client_pub_x25519[32]; bool found_x25519=false;
    uint8_t client_pub_x448[56]; bool found_x448=false;
    uint8_t client_pub_sm2[65]; size_t client_pub_sm2_len=0; bool found_sm2=false;
    uint8_t client_pub_p256[64]; bool found_p256=false;
    uint8_t client_pub_p384[96]; bool found_p384=false;
    bool client_supports_x448=false;    // 客户�?supported_groups 列表中是否包�?X448
    bool client_supports_curveSM2=false;
    bool client_supports_p256=false;
    bool client_supports_p384=false;
    std::vector<uint16_t> client_sig_algs, client_sig_algs_cert;
    size_t eo=ext_offset+2;
    while(eo+4<=ext_offset+2+ext_len_total){
        uint16_t etype=(client_hello[eo]<<8)|client_hello[eo+1];
        uint16_t elen=(client_hello[eo+2]<<8)|client_hello[eo+3];
        if(etype==0x0a && elen>=2){
            // supported_groups
            uint16_t gl=(client_hello[eo+4]<<8)|client_hello[eo+5];
            size_t goff=eo+6;
            for(size_t gi=0;gi+2<=gl && goff+2<=eo+4+elen;gi+=2){
                uint16_t g=(client_hello[goff]<<8)|client_hello[goff+1];
                if(g==(uint16_t)NamedGroup::X448) client_supports_x448=true;
                if(g==(uint16_t)NamedGroup::curveSM2) client_supports_curveSM2=true;
                if(g==(uint16_t)NamedGroup::secp256r1) client_supports_p256=true;
                if(g==(uint16_t)NamedGroup::secp384r1) client_supports_p384=true;
                goff+=2;
            }
        }
        else if(etype==0x33 && elen>=6){
            // RFC 8446 4.2.8：client_shares 为带 2 字节长度的向量，逐个扫描条目
            uint16_t ks_list_len=(client_hello[eo+4]<<8)|client_hello[eo+5];
            size_t ks_end = eo + 6 + ks_list_len;
            if (ks_end > eo + 4 + (size_t)elen) ks_end = eo + 4 + (size_t)elen;
            size_t kq = eo + 6;
            while (kq + 4 <= ks_end) {
                uint16_t group=(client_hello[kq]<<8)|client_hello[kq+1];
                uint16_t key_len=(client_hello[kq+2]<<8)|client_hello[kq+3];
                if(group==(uint16_t)NamedGroup::X25519 && key_len==32 && kq+4+32<=ks_end){
                    memcpy(client_pub_x25519,client_hello+kq+4,32);found_x25519=true;
                } else if(group==(uint16_t)NamedGroup::X448 && key_len==56 && kq+4+56<=ks_end){
                    memcpy(client_pub_x448,client_hello+kq+4,56);found_x448=true;
                } else if(group==(uint16_t)NamedGroup::curveSM2 && kq+4+64<=ks_end){
                    // curveSM2 采用 SEC1 非压�?65 字节；兼容裸 64 字节 x||y
                    if(key_len==65 && client_hello[kq+4]==0x04){
                        memcpy(client_pub_sm2,client_hello+kq+4,65);
                        client_pub_sm2_len=65;found_sm2=true;
                    } else if(key_len==64){
                        client_pub_sm2[0]=0x04;
                        memcpy(client_pub_sm2+1,client_hello+kq+4,64);
                        client_pub_sm2_len=65;found_sm2=true;
                    }
                } else if(group==(uint16_t)NamedGroup::secp256r1 && key_len==64 && kq+4+64<=ks_end){
                    memcpy(client_pub_p256,client_hello+kq+4,64);found_p256=true;
                } else if(group==(uint16_t)NamedGroup::secp384r1 && key_len==96 && kq+4+96<=ks_end){
                    memcpy(client_pub_p384,client_hello+kq+4,96);found_p384=true;
                }
                kq += 4 + key_len;
            }
        }
        else if(etype==0x000d){
            std::vector<uint16_t> tmp;
            if(parse_sig_alg_list(client_hello+eo+4, elen, tmp)) client_sig_algs=std::move(tmp);
        }
        else if(etype==0x0032){
            std::vector<uint16_t> tmp;
            if(parse_sig_alg_list(client_hello+eo+4, elen, tmp)) client_sig_algs_cert=std::move(tmp);
        }
        eo+=4+elen;
    }
    if(!found_x25519 && !found_x448 && !found_sm2 && !found_p256 && !found_p384){
        memcpy(client_pub_x25519,client_hello+50,32);found_x25519=true;
    }

    // signature_algorithms 协商（RFC 8446 §4.2.3�?
    if (client_sig_algs.empty()) return false;   // 客户端必须携带该扩展
    // signature_algorithms_cert 必须�?signature_algorithms 的子�?
    for (uint16_t a : client_sig_algs_cert)
        if (!scheme_in_list(client_sig_algs, a)) return false;
    // 选择双方共同支持且与证书密钥类型匹配的方案（TLS 1.3 不允�?rsa_pkcs1_*�?
    s.selected_sig_alg = select_signature_scheme(client_sig_algs, *cert, s.sig_algs, true);
    if (s.selected_sig_alg == 0) return false;
    // signature_algorithms_cert：证书链签名方案必须被客户端接受
    if (!client_sig_algs_cert.empty()) {
        uint16_t chain_scheme = cert_chain_signature_scheme(*cert);
        if (chain_scheme == 0 || !scheme_in_list(client_sig_algs_cert, chain_scheme)) return false;
    }

    // RFC 8998 3.3.1.1：SM 套件要求 supported_groups �?curveSM2 且必须提供其 key_share
    if (tls_use_sm3(s.cipher_suite) && (!found_sm2 || !client_supports_curveSM2)) return false;

    // 选择密钥交换组：SM 套件优先 curveSM2，其�?X448（如果客户端提供�?key_share�?
    bool use_sm2  = tls_use_sm3(s.cipher_suite) && found_sm2 && client_supports_curveSM2;
    bool use_p256 = !use_sm2 && found_p256 && client_supports_p256;
    bool use_p384 = !use_sm2 && !use_p256 && found_p384 && client_supports_p384;
    bool use_x448 = !use_sm2 && !use_p256 && !use_p384 && found_x448 && client_supports_x448;
    uint8_t shared_secret[56];
    size_t shared_len;

    server_flight.clear();
    server_flight.push_back((uint8_t)HandshakeType::SERVER_HELLO);
    server_flight.push_back(0);server_flight.push_back(0);server_flight.push_back(0);
    server_flight.push_back(0x03);server_flight.push_back(0x03);
    server_flight.insert(server_flight.end(),s.server_random,s.server_random+32);
    // 回显 ClientHello �?legacy_session_id（RFC 8446 4.1.3�?
    server_flight.push_back((uint8_t)ch_sid_len);
    if (ch_sid_len > 0 && ch_sid)
        server_flight.insert(server_flight.end(), ch_sid, ch_sid + ch_sid_len);
    uint16_t sel_cs = (uint16_t)s.cipher_suite;
    server_flight.push_back((uint8_t)(sel_cs>>8));server_flight.push_back((uint8_t)sel_cs);
    server_flight.push_back(0x00);

    if (use_sm2) {
        // curveSM2 密钥交换（RFC 8998 3.4：标�?ECDHE，共享密�?= X 坐标 32 字节�?
        uint8_t server_priv[SM2_KEY_SIZE], server_pub[SM2_PUB_SIZE];
        sm2_keygen(server_pub, server_priv);
        if (!sm2_ecdh(shared_secret, server_priv, client_pub_sm2, client_pub_sm2_len))
            return false;
        shared_len = 32;
        s.ks_group = NamedGroup::curveSM2;

        // ext_len = 6 (supported_versions) + 73 (key_share: 4 + 2 + 2 + 65)
        uint16_t ext_total = 6 + 73;
        server_flight.push_back((uint8_t)(ext_total>>8));server_flight.push_back((uint8_t)ext_total);
        // supported_versions
        server_flight.push_back(0x00);server_flight.push_back(0x2b);server_flight.push_back(0x00);server_flight.push_back(0x02);server_flight.push_back(0x03);server_flight.push_back(0x04);
        // key_share curveSM2（SEC1 非压�?65 字节�?
        server_flight.push_back(0x00);server_flight.push_back(0x33);
        server_flight.push_back(0x00);server_flight.push_back(0x45); // 69 = 2 + 2 + 65
        server_flight.push_back(0x00);server_flight.push_back(0x29); // curveSM2
        server_flight.push_back(0x00);server_flight.push_back(0x41); // 65
        server_flight.push_back(0x04);
        server_flight.insert(server_flight.end(), server_pub, server_pub + SM2_PUB_SIZE);
    } else if (use_p256) {
        // secp256r1 (P-256) ECDHE：key_exchange = x||y �?64 字节
        uint8_t server_priv[32], server_pub[64];
        ecdsa_p256_keygen(server_pub, server_priv);
        if (!ecdsa_p256_ecdh(shared_secret, server_priv, client_pub_p256))
            return false;
        shared_len = 32;
        s.ks_group = NamedGroup::secp256r1;

        uint16_t ext_total = 6 + 72; // supported_versions(6) + key_share(2+2+4+64)
        server_flight.push_back((uint8_t)(ext_total>>8));server_flight.push_back((uint8_t)ext_total);
        server_flight.push_back(0x00);server_flight.push_back(0x2b);server_flight.push_back(0x00);
        server_flight.push_back(0x02);server_flight.push_back(0x03);server_flight.push_back(0x04);
        server_flight.push_back(0x00);server_flight.push_back(0x33);
        server_flight.push_back(0x00);server_flight.push_back(0x44); // 68 = 2 + 2 + 64
        server_flight.push_back(0x00);server_flight.push_back(0x17); // secp256r1
        server_flight.push_back(0x00);server_flight.push_back(0x40); // 64
        server_flight.insert(server_flight.end(), server_pub, server_pub + 64);
    } else if (use_p384) {
        // secp384r1 (P-384) ECDHE：key_exchange = x||y �?96 字节
        uint8_t server_priv[48], server_pub[96];
        ecdsa_p384_keygen(server_pub, server_priv);
        if (!ecdsa_p384_ecdh(shared_secret, server_priv, client_pub_p384))
            return false;
        shared_len = 48;
        s.ks_group = NamedGroup::secp384r1;

        uint16_t ext_total = 6 + 104; // supported_versions(6) + key_share(2+2+4+96)
        server_flight.push_back((uint8_t)(ext_total>>8));server_flight.push_back((uint8_t)ext_total);
        server_flight.push_back(0x00);server_flight.push_back(0x2b);server_flight.push_back(0x00);
        server_flight.push_back(0x02);server_flight.push_back(0x03);server_flight.push_back(0x04);
        server_flight.push_back(0x00);server_flight.push_back(0x33);
        server_flight.push_back(0x00);server_flight.push_back(0x64); // 100 = 2 + 2 + 96
        server_flight.push_back(0x00);server_flight.push_back(0x18); // secp384r1
        server_flight.push_back(0x00);server_flight.push_back(0x60); // 96
        server_flight.insert(server_flight.end(), server_pub, server_pub + 96);
    } else if (use_x448) {
        // X448 密钥交换
        uint8_t server_priv[56], server_pub[56];
        x448_generate_keypair(server_pub, server_priv);
        x448_scalar_mult(shared_secret, server_priv, client_pub_x448);
        shared_len = 56;
        s.ks_group = NamedGroup::X448;

        // ext_len = 6 (supported_versions) + 64 (key_share: 4 + 2 + 2 + 56)
        uint16_t ext_total = 6 + 64;
        server_flight.push_back((uint8_t)(ext_total>>8));server_flight.push_back((uint8_t)ext_total);
        // supported_versions
        server_flight.push_back(0x00);server_flight.push_back(0x2b);server_flight.push_back(0x00);server_flight.push_back(0x02);server_flight.push_back(0x03);server_flight.push_back(0x04);
        // key_share X448
        server_flight.push_back(0x00);server_flight.push_back(0x33);
        server_flight.push_back(0x00);server_flight.push_back(0x3c); // 60 = 2 + 2 + 56
        server_flight.push_back(0x00);server_flight.push_back(0x1e); // X448
        server_flight.push_back(0x00);server_flight.push_back(0x38); // 56
        server_flight.insert(server_flight.end(), server_pub, server_pub+56);
    } else {
        // X25519 密钥交换（默认）
        uint8_t server_priv[32],server_pub[32];
        x25519_generate_keypair(server_pub,server_priv);
        x25519_scalar_mult(shared_secret,server_priv,client_pub_x25519);
        shared_len = 32;
        s.ks_group = NamedGroup::X25519;

        server_flight.push_back(0x00);server_flight.push_back(0x2e);
        // supported_versions
        server_flight.push_back(0x00);server_flight.push_back(0x2b);server_flight.push_back(0x00);server_flight.push_back(0x02);server_flight.push_back(0x03);server_flight.push_back(0x04);
        // key_share X25519
        server_flight.push_back(0x00);server_flight.push_back(0x33);server_flight.push_back(0x00);server_flight.push_back(0x24);server_flight.push_back(0x00);server_flight.push_back(0x1d);server_flight.push_back(0x00);server_flight.push_back(0x20);
        server_flight.insert(server_flight.end(),server_pub,server_pub+32);
    }

    size_t sh_len=server_flight.size()-4;
    server_flight[1]=(uint8_t)(sh_len>>16);server_flight[2]=(uint8_t)(sh_len>>8);server_flight[3]=(uint8_t)sh_len;

    // 记录 ServerHello
    tls_transcript_update(s,server_flight.data(),server_flight.size());

    // 派生握手密钥
    tls13_derive_handshake_keys(s,shared_secret,shared_len);
    init_cipher_ctx(s, s.server_write_key);

    // QUIC (RFC 9001 §8.2)：解析客户端 transport parameters（必须存在）
    std::vector<uint8_t> server_tp;
    const std::vector<uint8_t>* tp_ptr = nullptr;
    if (s.quic_mode) {
        const uint8_t* tp_data = nullptr;
        size_t tp_len = 0;
        if (!client_hello_find_extension(client_hello, ch_len, 0x0039, tp_data, tp_len))
            return false;
        if (!quic_transport_parameters::decode(tp_data, tp_len, s.quic_peer_transport_params))
            return false;
        s.quic_peer_params_valid = true;
        server_tp = s.quic_transport_params.encode();
        tp_ptr = &server_tp;
    }

    // 构建 EncryptedExtensions
    auto ee=tls13_make_encrypted_extensions(s.alpn_selected, tp_ptr);
    tls_transcript_update(s,ee.data(),ee.size());

    // 构建 Certificate
    auto cert_msg=tls13_make_certificate(*cert);
    tls_transcript_update(s,cert_msg.data(),cert_msg.size());

    // 构建 CertificateVerify
    auto cv=tls13_make_cert_verify(*cert,s);
    tls_transcript_update(s,cv.data(),cv.size());

    // 构建 Server Finished
    auto sf=tls13_make_finished(s,true);
    tls_transcript_update(s,sf.data(),sf.size());

    if (s.quic_mode) {
        // QUIC：握手消息以原始字节交付（QUIC CRYPTO 帧承载），不使用 TLS 记录层
        server_flight.insert(server_flight.end(),ee.begin(),ee.end());
        server_flight.insert(server_flight.end(),cert_msg.begin(),cert_msg.end());
        server_flight.insert(server_flight.end(),cv.begin(),cv.end());
        server_flight.insert(server_flight.end(),sf.begin(),sf.end());
    } else {
        // 加密所有握手消�?
        std::vector<uint8_t> hs_buf;
        hs_buf.insert(hs_buf.end(),ee.begin(),ee.end());
        hs_buf.insert(hs_buf.end(),cert_msg.begin(),cert_msg.end());
        hs_buf.insert(hs_buf.end(),cv.begin(),cv.end());
        hs_buf.insert(hs_buf.end(),sf.begin(),sf.end());

        auto encrypted=tls_encrypt_handshake(s,hs_buf.data(),hs_buf.size());
        server_flight.insert(server_flight.end(),encrypted.begin(),encrypted.end());
    }

    // 注意：应用密钥延迟到 tls13_process_client_finished 成功后派�?
    return true;
}

bool tls13_process_client_finished(tls_session& s, const uint8_t* data, size_t len){
    std::vector<uint8_t> hs;
    if (s.quic_mode) {
        // QUIC：Finished 以原始握手消息字节交付（CRYPTO 帧承载），无记录层
        hs.assign(data, data + len);
    } else if(!tls13_decrypt_handshake(s,data,len,hs)) {
        return false;
    }
    if(!tls13_verify_finished(s,hs.data(),hs.size(),false))return false;

    // 握手完成，派生应用密钥（�?transcript 更新前）
    tls13_derive_application_keys(s);
    tls_transcript_update(s,hs.data(),hs.size());
    init_cipher_ctx(s, s.server_write_key);
    return true;
}

bool tls13_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                             std::vector<uint8_t>& server_response,
                             const tls_certificate_manager& cert_manager){
    return tls13_make_server_flight(s, client_hello, ch_len, server_response, cert_manager);
}

// ══════════════════════════════════════════════════════════════════════�?
//  NewSessionTicket
// ══════════════════════════════════════════════════════════════════════�?

bool tls13_make_new_session_ticket(tls_session& s, std::vector<uint8_t>& ticket_msg,
                                   uint32_t ticket_lifetime){
    size_t hl=tls_hash_len(s.cipher_suite);
    uint8_t resumption_secret[48];
    tls13_derive_resumption_secret(s, resumption_secret);

    // Generate random ticket and nonce (use a 48-byte buffer to avoid rand32 overflow)
    uint8_t ticket_buf[48];
    rand32(ticket_buf);
    uint8_t ticket[32], ticket_nonce[16];
    memcpy(ticket, ticket_buf, 32);
    rand32(ticket_buf+16);
    memcpy(ticket_nonce, ticket_buf+16, 16);

    memcpy(s.psk_identity, ticket, 32);
    s.psk_identity_len = 32;
    s.ticket_issue_time = (uint64_t)time(nullptr);
    {
        // rand32 always writes 32 bytes; keep a full-size buffer and take 4.
        uint8_t rbuf[32];
        rand32(rbuf);
        memcpy(&s.ticket_age_add, rbuf, 4);
    }
    s.psk_valid = true;

    if(tls_use_sha384(s.cipher_suite))
        hkdf_expand_label_sha384(resumption_secret,"resumption",ticket_nonce,16,s.psk_value,hl);
    else
        hkdf_expand_label(resumption_secret,"resumption",ticket_nonce,16,s.psk_value,hl);

    // Build body
    std::vector<uint8_t> body;
    body.push_back((uint8_t)(ticket_lifetime>>24));
    body.push_back((uint8_t)(ticket_lifetime>>16));
    body.push_back((uint8_t)(ticket_lifetime>>8));
    body.push_back((uint8_t)(ticket_lifetime));
    body.push_back((uint8_t)(s.ticket_age_add>>24));
    body.push_back((uint8_t)(s.ticket_age_add>>16));
    body.push_back((uint8_t)(s.ticket_age_add>>8));
    body.push_back((uint8_t)(s.ticket_age_add));
    body.push_back(16);
    body.insert(body.end(), ticket_nonce, ticket_nonce+16);
    body.push_back(0x00); body.push_back(0x20);
    body.insert(body.end(), ticket, ticket+32);
    uint16_t ext_len = 2 + 4;
    body.push_back((uint8_t)(ext_len>>8));
    body.push_back((uint8_t)(ext_len));
    body.push_back(0x00); body.push_back(0x2a);
    body.push_back(0x00); body.push_back(0x04);
    body.push_back(0xFF); body.push_back(0xFF); body.push_back(0xFF); body.push_back(0xFF);

    ticket_msg.clear();
    ticket_msg.push_back((uint8_t)HandshakeType::NEW_SESSION_TICKET);
    size_t blen = body.size();
    ticket_msg.push_back((uint8_t)(blen>>16));
    ticket_msg.push_back((uint8_t)(blen>>8));
    ticket_msg.push_back((uint8_t)(blen));
    ticket_msg.insert(ticket_msg.end(), body.begin(), body.end());
    return true;
}

// ══════════════════════════════════════════════════════════════════════�?
//  Server: process PSK ClientHello
// ══════════════════════════════════════════════════════════════════════�?

bool tls13_process_psk_client_hello(tls_session& s, const uint8_t* ch, size_t ch_len,
                                    bool& accept_early_data){
    accept_early_data = false;
    if(ch_len<45) return false;

    size_t ext_offset = client_hello_ext_offset(ch, ch_len);
    if(ext_offset+2 > ch_len) return false;
    uint16_t ext_total = (ch[ext_offset]<<8)|ch[ext_offset+1];
    size_t eo = ext_offset+2;

    while(eo+4 <= ext_offset+2+ext_total && eo+4 <= ch_len){
        uint16_t etype = (ch[eo]<<8)|ch[eo+1];
        uint16_t elen = (ch[eo+2]<<8)|ch[eo+3];
        if(etype == 0x29 && elen >= 6){
            const uint8_t* edata = ch+eo+4;
            uint16_t ilen = (edata[0]<<8)|edata[1];
            if(2+ilen > elen) return false;
            uint16_t id_len = (edata[2]<<8)|edata[3];
            if(4+id_len > ilen) return false;
            const uint8_t* identity = edata+4;
            uint32_t obf_age = (edata[4+id_len]<<24)|(edata[4+id_len+1]<<16)|
                              (edata[4+id_len+2]<<8)|edata[4+id_len+3];

            if(id_len == s.psk_identity_len && memcmp(identity, s.psk_identity, id_len)==0){
                // Ticket age check
                uint64_t now = (uint64_t)time(nullptr);
                uint64_t real_age = (now - s.ticket_issue_time) * 1000;
                uint32_t claimed_age = obf_age - s.ticket_age_add;
                int64_t diff = (int64_t)claimed_age - (int64_t)real_age;
                if(diff < -10000 || diff > 10000) return false;

                // Binder verification
                size_t hl=tls_hash_len(s.cipher_suite);
                size_t binders_off = 2 + ilen;
                uint16_t blen = (edata[binders_off]<<8)|edata[binders_off+1];
                uint8_t bnd_len = edata[binders_off+2];
                const uint8_t* binder = edata + binders_off + 3;

                uint8_t expected[48];
                size_t trunc_len = eo + 4 + binders_off + 3;
                tls13_compute_binder(s, s.psk_value, ch, trunc_len, expected);
                if(memcmp(binder, expected, hl) != 0) return false;

                // Check for early_data
                size_t eo2 = ext_offset+2;
                while(eo2+4 <= ext_offset+2+ext_total){
                    if(((ch[eo2]<<8)|ch[eo2+1]) == 0x002a) {
                        accept_early_data = true;
                        s.early_data_accepted = true;
                        // Record ClientHello in transcript before deriving early keys
                        s.transcript_ready = false;
                        tls_transcript_update(s, ch, ch_len);
                        tls13_derive_early_traffic_keys(s, s.psk_value);
                        break;
                    }
                    eo2 += 4 + ((ch[eo2+2]<<8)|ch[eo2+3]);
                }
                return true;
            }
        }
        eo += 4 + elen;
    }
    return false;
}

bool tls13_decrypt_early_data(tls_session& s, const uint8_t* record, size_t record_len,
                              ContentType& ct, std::vector<uint8_t>& out){
    if(!s.early_data_accepted) return false;
    if(record_len < 5) return false;
    size_t rlen = (record[3]<<8)|record[4];
    size_t tag_len=tls_aead_tag_len(s.cipher_suite);
    if(5+rlen != record_len || rlen < tag_len) return false;
    const uint8_t* ciphertext = record+5;
    size_t ct_len = rlen - tag_len;
    const uint8_t* tag = record+5+ct_len;

    uint8_t nonce[12];
    memcpy(nonce, s.client_early_write_iv, 12);
    for(int i=0;i<8;++i) nonce[4+i] ^= (uint8_t)(s.client_early_seq>>(56-i*8));
    ++s.client_early_seq;

    std::vector<uint8_t> inner;
    bool ok = false;
    jpssl::span<const uint8_t> aad_span(record, 5);
    switch(s.cipher_suite){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384: {
            aes_context ctx;
            aes_ctx_init(ctx, s.client_early_write_key, aes_key_len(s.cipher_suite));
            ok = aes_gcm_decrypt_auto(ctx, nonce, 12, jpssl::span<const uint8_t>(ciphertext,ct_len),
                                 aad_span, tag, 16, inner);
            break;
        }
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            ok = chacha20_poly1305_decrypt(s.client_early_write_key, nonce,
                                           jpssl::span<const uint8_t>(ciphertext,ct_len),
                                           aad_span, tag, inner);
            break;
        case CipherSuite::TLS_AES_128_CCM_SHA256:
        case CipherSuite::TLS_AES_128_CCM_8_SHA256: {
            aes_context ctx;
            aes_ctx_init(ctx, s.client_early_write_key, aes_key_len(s.cipher_suite));
            ok = aes_ccm_decrypt(ctx, nonce, 12, jpssl::span<const uint8_t>(ciphertext,ct_len),
                                 aad_span, tag, tag_len, inner);
            break;
        }
        case CipherSuite::TLS_SM4_GCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, s.client_early_write_key);
            ok = sm4_gcm_decrypt(&s.sm4, nonce, 12,
                                 jpssl::span<const uint8_t>(ciphertext,ct_len),
                                 aad_span, tag, 16, inner);
            break;
        }
        case CipherSuite::TLS_SM4_CCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, s.client_early_write_key);
            ok = sm4_ccm_decrypt(&s.sm4, nonce, 12,
                                 jpssl::span<const uint8_t>(ciphertext,ct_len),
                                 aad_span, tag, 16, inner);
            break;
        }
    }
    if(!ok || inner.empty()) return false;
    ct = (ContentType)inner.back();
    out.assign(inner.begin(), inner.end()-1);
    return true;
}

// ══════════════════════════════════════════════════════════════════════�?
//  EndOfEarlyData
// ══════════════════════════════════════════════════════════════════════�?

std::vector<uint8_t> tls13_make_end_of_early_data(){
    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::END_OF_EARLY_DATA);
    msg.push_back(0); msg.push_back(0); msg.push_back(0);
    return msg;
}

} // namespace tls
} // namespace jpssl
