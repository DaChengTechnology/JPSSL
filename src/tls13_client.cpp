/**
 * TLS 1.3 客户端握手实现（由原 tls.cpp 拆分而来）
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
size_t aes_key_len(CipherSuite cs);
void aes_ctx_init(aes_context& ctx, const uint8_t* key, size_t key_len);
void sm4_ctx_init_from_key(sm4_ctx& ctx, const uint8_t* key);
void init_cipher_ctx(tls_session& s, const uint8_t* key);
size_t client_hello_ext_offset(const uint8_t* ch, size_t ch_len);
void append_sig_alg_extension(std::vector<uint8_t>& ext, uint16_t type, const std::vector<uint16_t>& algs);
std::vector<uint16_t> effective_sig_algs(const tls_session& s);
bool scheme_in_list(const std::vector<uint16_t>& list, uint16_t scheme);
uint16_t x509_key_type_chain_scheme(x509::KeyType kt);
void tls13_derive_handshake_keys(tls_session& s, const uint8_t* shared_secret, size_t shared_len);
void tls13_derive_application_keys(tls_session& s);
void tls13_derive_keys(tls_session& s, const uint8_t* shared_secret, size_t shared_len);
std::vector<uint8_t> tls13_make_finished(tls_session& s, bool for_server);
bool tls13_verify_finished(tls_session& s, const uint8_t* hs_msg, size_t hs_len, bool for_server);
std::vector<uint8_t> tls13_cert_verify_content(tls_session& s, bool for_server);
bool tls13_decrypt_handshake(tls_session& s, const uint8_t* record, size_t record_len, std::vector<uint8_t>& hs_out);
bool tls13_verify_server_chain(const std::vector<x509::x509_cert>& server_chain, const tls_trust_store& trust, const std::string& hostname);
std::unique_ptr<tls_certificate> tls_cert_from_x509_leaf(const x509::x509_cert& leaf);
void tls13_derive_resumption_secret(tls_session& s, uint8_t out[48]);
void tls13_derive_early_traffic_keys(tls_session& s, const uint8_t* psk);
void tls13_compute_binder(tls_session& s, const uint8_t* psk, const uint8_t* ch_truncated, size_t ch_trunc_len, uint8_t* binder);


static bool tls13_verify_cert_verify(const tls_certificate& cert, tls_session& s, const uint8_t* hs_msg, size_t hs_len){
    if(hs_len<8 || hs_msg[0]!=(uint8_t)HandshakeType::CERT_VERIFY)return false;
    uint16_t alg=(hs_msg[4]<<8)|hs_msg[5];
    // 服务端必须使用客户端 signature_algorithms 中广告的方案
    if(!scheme_in_list(effective_sig_algs(s), alg)) return false;
    if(!tls_scheme_allowed_for_cert_verify(alg)) return false;
    uint16_t sig_len=(hs_msg[6]<<8)|hs_msg[7];
    if(4+2+2+sig_len!=hs_len)return false;
    std::vector<uint8_t> content = tls13_cert_verify_content(s, true);
    // RFC 8998 3.2.1: handshake signature uses SM2 id "TLSv1.3+GM+Cipher+Suite"
    uint8_t za[32] = {};
    const uint8_t* za_ptr = nullptr;
    if (alg == (uint16_t)SignatureAlgorithm::SM2_SM3) {
        static const char kSm2TlsId[] = "TLSv1.3+GM+Cipher+Suite";
        sm2_compute_za((const uint8_t*)kSm2TlsId, sizeof(kSm2TlsId) - 1,
                       cert.pub.sm2, cert.pub.sm2 + 32, za);
        za_ptr = za;
    }
    return cert.verify_scheme(alg, content.data(), content.size(), hs_msg+8, sig_len, za_ptr);
}

// ════════════════════════════════════════════════════════════════════════════
//  TLS 1.3 完整握手 — 客户端
// ════════════════════════════════════════════════════════════════════════════
bool tls13_make_client_hello(tls_session& s, std::vector<uint8_t>& client_hello){
    s.ver=TLSVersion::V13;s.is_server=false;
    s.transcript_ready=false;
    rand32(s.client_random);

    client_hello.clear();
    client_hello.push_back((uint8_t)HandshakeType::CLIENT_HELLO);
    client_hello.push_back(0);client_hello.push_back(0);client_hello.push_back(0);
    client_hello.push_back(0x03);client_hello.push_back(0x03);
    client_hello.insert(client_hello.end(),s.client_random,s.client_random+32);
    std::vector<uint16_t> cs_list;
    auto cs_push = [&](uint16_t id){ for (uint16_t c : cs_list) if (c==id) return; cs_list.push_back(id); };
    // 默认偏好：国密（RFC 8998）> ChaCha20-Poly1305 > AES-GCM/CCM。
    // 显式指定非 SM 密钥交换组（X448/P-256/P-384）时不默认通告国密套件：
    // RFC 8998 要求 SM 套件配 curveSM2 key_share，没有该 share 时通告会被服务端拒绝。
    // QUIC 模式（RFC 9001 §5）不使用国密套件，一律不通告。
    bool non_sm_ks_group = (s.ks_group == NamedGroup::X448 ||
                            s.ks_group == NamedGroup::secp256r1 ||
                            s.ks_group == NamedGroup::secp384r1);
    bool sm_allowed = !s.quic_mode && !non_sm_ks_group;
    bool offer_sm = sm_allowed && (!s.cipher_suite_pinned || tls_use_sm3(s.cipher_suite));
    if (s.cipher_suite_pinned && !(s.quic_mode && tls_use_sm3(s.cipher_suite)))
        cs_push((uint16_t)s.cipher_suite);
    if (offer_sm) { cs_push(0x00C6); cs_push(0x00C7); }   // TLS_SM4_GCM_SM3 / TLS_SM4_CCM_SM3
    cs_push(0x1303);   // TLS_CHACHA20_POLY1305_SHA256
    cs_push(0x1301);   // TLS_AES_128_GCM_SHA256
    cs_push(0x1302);   // TLS_AES_256_GCM_SHA384
    cs_push(0x1304);   // TLS_AES_128_CCM_SHA256
    cs_push(0x1305);   // TLS_AES_128_CCM_8_SHA256
    uint16_t cs_len = (uint16_t)(cs_list.size() * 2);
    client_hello.push_back(0);
    client_hello.push_back((uint8_t)(cs_len>>8));client_hello.push_back((uint8_t)cs_len);
    for(auto cs_id : cs_list){
        client_hello.push_back((uint8_t)(cs_id>>8));client_hello.push_back((uint8_t)cs_id);
    }
    client_hello.push_back(0x01);client_hello.push_back(0x00);

    std::vector<uint8_t> ext;
    if(!s.server_name.empty()){
        ext.push_back(0x00);ext.push_back(0x00);
        uint16_t sni_payload_len=5+s.server_name.size();
        ext.push_back(0x00);ext.push_back((uint8_t)sni_payload_len);
        uint16_t name_list_len=3+s.server_name.size();
        ext.push_back(0x00);ext.push_back((uint8_t)name_list_len);
        ext.push_back(0x00);
        ext.push_back(0x00);ext.push_back((uint8_t)s.server_name.size());
        for(char c:s.server_name)ext.push_back((uint8_t)c);
    }
    ext.push_back(0x00);ext.push_back(0x2b);ext.push_back(0x00);ext.push_back(0x03);ext.push_back(0x02);ext.push_back(0x03);ext.push_back(0x04);
    // supported_groups: 根据会话配置提供 X25519 或 X448
    {
        std::vector<uint16_t> groups;
        // SM 套件必须包含 curveSM2（RFC 8998 3.3.1.1）；同时保留 X25519 兜底
        if (offer_sm) {
            groups.push_back((uint16_t)NamedGroup::curveSM2);
            groups.push_back((uint16_t)NamedGroup::X25519);
        } else if (s.ks_group == NamedGroup::X448) {
            groups.push_back((uint16_t)NamedGroup::X448);
            groups.push_back((uint16_t)NamedGroup::X25519);
        } else if (s.ks_group == NamedGroup::secp256r1) {
            groups.push_back((uint16_t)NamedGroup::secp256r1);
            groups.push_back((uint16_t)NamedGroup::X25519);
        } else if (s.ks_group == NamedGroup::secp384r1) {
            groups.push_back((uint16_t)NamedGroup::secp384r1);
            groups.push_back((uint16_t)NamedGroup::X25519);
        } else {
            groups.push_back((uint16_t)NamedGroup::X25519);
        }
        uint16_t groups_list_len = (uint16_t)(groups.size() * 2);
        uint16_t groups_ext_len = 2 + groups_list_len;
        ext.push_back(0x00);ext.push_back(0x0a); // supported_groups
        ext.push_back((uint8_t)(groups_ext_len>>8));ext.push_back((uint8_t)groups_ext_len);
        ext.push_back((uint8_t)(groups_list_len>>8));ext.push_back((uint8_t)groups_list_len);
        for (uint16_t g : groups) {
            ext.push_back((uint8_t)(g>>8));ext.push_back((uint8_t)g);
        }
    }
    // signature_algorithms + signature_algorithms_cert（RFC 8446 §4.2.3）
    {
        const std::vector<uint16_t>& algs = effective_sig_algs(s);
        std::vector<uint16_t> cert_algs =
            s.sig_algs_cert.empty() ? tls_default_signature_algorithms() : s.sig_algs_cert;
        // RFC 8446: signature_algorithms_cert 必须为 signature_algorithms 的子集
        std::vector<uint16_t> cert_filtered;
        for (uint16_t a : cert_algs) if (scheme_in_list(algs, a)) cert_filtered.push_back(a);
        append_sig_alg_extension(ext, 0x000d, algs);
        append_sig_alg_extension(ext, 0x0032, cert_filtered);
    }
    // key_share: 根据 ks_group 生成对应密钥对
    if (offer_sm) {
        // curveSM2（RFC 8998 3.3.1.1 必须提供，key_exchange 用 SEC1 非压缩 65 字节）
        uint8_t sm2_pub[SM2_PUB_SIZE], sm2_priv[SM2_KEY_SIZE];
        sm2_keygen(sm2_pub, sm2_priv);
        memcpy(s.ks_priv, sm2_priv, SM2_KEY_SIZE);
        memcpy(s.ks_pub, sm2_pub, SM2_PUB_SIZE);
        s.ks_group = NamedGroup::curveSM2;
        // X25519 兜底临时对（服务器不支持 curveSM2 时回退）
        uint8_t x_priv[32], x_pub[32];
        x25519_generate_keypair(x_pub, x_priv);
        memcpy(s.ks_priv_x25519, x_priv, 32);
        memcpy(s.ks_pub_x25519, x_pub, 32);

        std::vector<uint8_t> shares;
        // curveSM2 entry: group(2) + key_len(2) + 0x04 + x||y
        shares.push_back(0x00);shares.push_back(0x29);
        shares.push_back(0x00);shares.push_back(0x41); // 65
        shares.push_back(0x04);
        shares.insert(shares.end(), sm2_pub, sm2_pub + SM2_PUB_SIZE);
        // X25519 entry
        shares.push_back(0x00);shares.push_back(0x1d);
        shares.push_back(0x00);shares.push_back(0x20);
        shares.insert(shares.end(), x_pub, x_pub + 32);
        // key_share 扩展：RFC 8446 4.2.8，client_shares 为带 2 字节长度的向量
        ext.push_back(0x00);ext.push_back(0x33);
        uint16_t ks_ext_len = (uint16_t)(shares.size() + 2);
        ext.push_back((uint8_t)(ks_ext_len >> 8));ext.push_back((uint8_t)ks_ext_len);
        ext.push_back((uint8_t)(shares.size() >> 8));ext.push_back((uint8_t)shares.size());
        ext.insert(ext.end(), shares.begin(), shares.end());
    } else if (s.ks_group == NamedGroup::X448) {
        // X448
        uint8_t client_priv[56], client_pub[56];
        x448_generate_keypair(client_pub, client_priv);
        memcpy(s.ks_priv, client_priv, 56);
        memcpy(s.ks_pub, client_pub, 56);
        uint16_t ks_ext_len = 2 + 2 + 2 + 56; // 向量长度(2) + group(2) + key_len(2) + key(56)
        ext.push_back(0x00);ext.push_back(0x33); // key_share
        ext.push_back((uint8_t)(ks_ext_len>>8));ext.push_back((uint8_t)ks_ext_len);
        ext.push_back(0x00);ext.push_back(0x3c); // client_shares 向量长度 = 60
        ext.push_back(0x00);ext.push_back(0x1e); // X448
        ext.push_back(0x00);ext.push_back(0x38); // 56
        ext.insert(ext.end(), client_pub, client_pub + 56);
        // 暂存私钥到 client_write_key（仅 32 字节不够，改用 ks_priv）
        // 注意：后续 derive_keys 时使用 ks_priv
    } else if (s.ks_group == NamedGroup::secp256r1) {
        // secp256r1 (P-256) ECDHE：key_exchange = x||y 共 64 字节（RFC 8446 4.2.8.2）
        uint8_t ecdh_pub[64], ecdh_priv[32];
        ecdsa_p256_keygen(ecdh_pub, ecdh_priv);
        memcpy(s.ks_priv, ecdh_priv, 32);
        memcpy(s.ks_pub, ecdh_pub, 64);
        ext.push_back(0x00);ext.push_back(0x33); // key_share
        ext.push_back(0x00);ext.push_back(0x47); // 71 = 2 + 69
        ext.push_back(0x00);ext.push_back(0x45); // client_shares 69
        ext.push_back(0x00);ext.push_back(0x17); // secp256r1
        ext.push_back(0x00);ext.push_back(0x41); // 65（SEC1 非压缩点）
        ext.push_back(0x04);
        ext.insert(ext.end(), ecdh_pub, ecdh_pub + 64);
    } else if (s.ks_group == NamedGroup::secp384r1) {
        // secp384r1 (P-384) ECDHE：key_exchange = x||y 共 96 字节
        uint8_t ecdh_pub[96], ecdh_priv[48];
        ecdsa_p384_keygen(ecdh_pub, ecdh_priv);
        memcpy(s.ks_priv, ecdh_priv, 48);
        memcpy(s.ks_pub, ecdh_pub, 96);
        ext.push_back(0x00);ext.push_back(0x33); // key_share
        ext.push_back(0x00);ext.push_back(0x67); // 103 = 2 + 101
        ext.push_back(0x00);ext.push_back(0x65); // client_shares 101
        ext.push_back(0x00);ext.push_back(0x18); // secp384r1
        ext.push_back(0x00);ext.push_back(0x61); // 97（SEC1 非压缩点）
        ext.push_back(0x04);
        ext.insert(ext.end(), ecdh_pub, ecdh_pub + 96);
    } else {
        // X25519 (默认)
        uint8_t client_priv[32],client_pub[32];
        x25519_generate_keypair(client_pub,client_priv);
        memcpy(s.ks_priv, client_priv, 32);
        memcpy(s.ks_pub, client_pub, 32);
        ext.push_back(0x00);ext.push_back(0x33);ext.push_back(0x00);ext.push_back(0x26); // 38 = 2 + 2 + 2 + 32
        ext.push_back(0x00);ext.push_back(0x24); // client_shares 向量长度 = 36
        ext.push_back(0x00);ext.push_back(0x1d);ext.push_back(0x00);ext.push_back(0x20);
        ext.insert(ext.end(),client_pub,client_pub+32);
    }

    // ALPN (RFC 7301)：客户端按偏好序发送协议列表
    if (!s.alpn_protos.empty()) {
        size_t list_len = 0;
        for (const auto& p : s.alpn_protos) list_len += 1 + p.size();
        if (list_len <= 65535) {
            ext.push_back(0x00);ext.push_back(0x10); // ALPN 扩展类型
            ext.push_back((uint8_t)((2 + list_len) >> 8));
            ext.push_back((uint8_t)(2 + list_len));
            ext.push_back((uint8_t)(list_len >> 8));
            ext.push_back((uint8_t)list_len);
            for (const auto& p : s.alpn_protos) {
                ext.push_back((uint8_t)p.size());
                ext.insert(ext.end(), p.begin(), p.end());
            }
        }
    }

    // QUIC (RFC 9001 §8.2)：ClientHello 必须携带 quic_transport_parameters 扩展
    if (s.quic_mode) {
        std::vector<uint8_t> tp = s.quic_transport_params.encode();
        ext.push_back(0x00);ext.push_back(0x39);
        ext.push_back((uint8_t)(tp.size() >> 8));ext.push_back((uint8_t)tp.size());
        ext.insert(ext.end(), tp.begin(), tp.end());
    }

    uint16_t ext_len_total=ext.size();
    client_hello.push_back((uint8_t)(ext_len_total>>8));client_hello.push_back((uint8_t)ext_len_total);
    client_hello.insert(client_hello.end(),ext.begin(),ext.end());

    size_t len=client_hello.size()-4;
    client_hello[1]=(uint8_t)(len>>16);client_hello[2]=(uint8_t)(len>>8);client_hello[3]=(uint8_t)len;

    tls_transcript_update(s,client_hello.data(),client_hello.size());
    // 私钥已暂存到 s.ks_priv（支持 X25519 或 X448）
    // 兼容旧 API：将 X25519 私钥复制到 client_write_key 的 32 字节
    if (s.ks_group == NamedGroup::X25519) {
        memcpy(s.client_write_key, s.ks_priv, 32);
    }
    return true;
}

bool tls13_process_server_flight(tls_session& s, const uint8_t* data, size_t len,
                                  std::vector<uint8_t>& client_finished,
                                  const tls_certificate_manager* cert_manager,
                                  const tls_trust_store* trust_store){
    if(len<5)return false;
    size_t offset=0;
    const tls_certificate* server_cert=nullptr;
    std::unique_ptr<tls_certificate> parsed_server_cert;  // x509 验证路径下持有叶子证书

    // 解析 ServerHello（明文）
    if(data[offset]!=(uint8_t)HandshakeType::SERVER_HELLO)return false;
    size_t sh_len=(data[offset+1]<<16)|(data[offset+2]<<8)|data[offset+3];
    size_t sh_start=offset;
    offset+=4+sh_len;if(offset>len)return false;
    // RFC 8446 ServerHello 最小长度 40：ver(2)+random(32)+sid_len(1)+cipher(2)+
    // compression(1)+ext_len(2)。下方按固定偏移读取 random/cipher/ext_len，
    // sh_len<40 时这些读取会越过消息边界（fuzz 发现的越界读）。
    if(4+sh_len < 40) return false;
    memcpy(s.server_random,data+sh_start+10,32);

    { size_t cs_off_in_sh = 4+2+32+1; uint16_t sel_cs = (data[sh_start+cs_off_in_sh]<<8)|data[sh_start+cs_off_in_sh+1];
      CipherSuite cs = select_cipher_suite(sel_cs);
      if (cs == CipherSuite::UNKNOWN) return false;   // 未知套件直接拒绝
      s.cipher_suite = cs;
    }

    tls_transcript_update(s,data+sh_start,4+sh_len);

    // 提取 server_pub 从 key_share（支持 X25519、X448 或 curveSM2）
    size_t ext_start=sh_start+4+2+32+1+2+1;
    uint16_t ext_total=(data[ext_start]<<8)|data[ext_start+1];
    size_t ext_off=ext_start+2;
    uint8_t server_pub_x25519[32];
    uint8_t server_pub_x448[56];
    uint8_t server_pub_sm2[65];
    size_t server_pub_sm2_len = 0;
    bool found_ks_x25519=false, found_ks_x448=false, found_ks_sm2=false;
    uint8_t server_pub_p256[64];
    uint8_t server_pub_p384[96];
    bool found_ks_p256=false, found_ks_p384=false;
    while(ext_off+4<=ext_start+2+ext_total && ext_off+4<=sh_start+4+sh_len){
        // 防御：ext_total/elen 来自输入，循环必须同时受消息末尾约束，
        // 否则声称的大长度会让 ext_off 越过 ServerHello 边界读取（fuzz 发现）。
        uint16_t etype=(data[ext_off]<<8)|data[ext_off+1];
        uint16_t elen=(data[ext_off+2]<<8)|data[ext_off+3];
        if(etype==0x33 && elen>=4){
            uint16_t group=(data[ext_off+4]<<8)|data[ext_off+5];
            uint16_t key_len=(data[ext_off+6]<<8)|data[ext_off+7];
            if(group==(uint16_t)NamedGroup::X25519 && key_len==32 && elen>=4+32){
                memcpy(server_pub_x25519,data+ext_off+8,32);found_ks_x25519=true;
            } else if(group==(uint16_t)NamedGroup::X448 && key_len==56 && elen>=4+56){
                memcpy(server_pub_x448,data+ext_off+8,56);found_ks_x448=true;
            } else if(group==(uint16_t)NamedGroup::curveSM2 && elen>=4+64){
                // curveSM2 采用 SEC1 非压缩 65 字节；兼容部分实现裸 64 字节 x||y
                if(key_len==65 && data[ext_off+8]==0x04){
                    memcpy(server_pub_sm2,data+ext_off+8,65);
                    server_pub_sm2_len=65;
                    found_ks_sm2=true;
                } else if(key_len==64){
                    server_pub_sm2[0]=0x04;
                    memcpy(server_pub_sm2+1,data+ext_off+8,64);
                    server_pub_sm2_len=65;
                    found_ks_sm2=true;
                }
            } else if(group==(uint16_t)NamedGroup::secp256r1 && elen>=4+64){
                // RFC 8446 §4.2.8.2：P-256 key_exchange 为 SEC1 非压缩点（0x04||x||y，65 字节）
                if(key_len==65 && data[ext_off+8]==0x04){
                    memcpy(server_pub_p256,data+ext_off+9,64);found_ks_p256=true;
                } else if(key_len==64){
                    memcpy(server_pub_p256,data+ext_off+8,64);found_ks_p256=true;
                }
            } else if(group==(uint16_t)NamedGroup::secp384r1 && elen>=4+96){
                if(key_len==97 && data[ext_off+8]==0x04){
                    memcpy(server_pub_p384,data+ext_off+9,96);found_ks_p384=true;
                } else if(key_len==96){
                    memcpy(server_pub_p384,data+ext_off+8,96);found_ks_p384=true;
                }
            }
        }
        ext_off+=4+elen;
    }
    // 默认回退到索引 50（旧 API 兼容）：X25519 情况下
    if(!found_ks_x25519 && !found_ks_x448 && !found_ks_sm2 && !found_ks_p256 && !found_ks_p384){
        // 防御：回退偏移 50..81 必须在 ServerHello 消息内（sh_len>=78），
        // 否则读取越过消息边界（fuzz 发现的越界读路径）。
        if (4 + sh_len >= 82) {
            memcpy(server_pub_x25519,data+sh_start+50,32);
            found_ks_x25519=true;
        }
    }

    // 计算共享密钥（根据会话配置或找到的组选择算法）
    uint8_t shared_secret[56];  // X448 输出 56 字节；但 TLS 1.3 HKDF 使用 32 字节
    size_t shared_len = 32;
    if (found_ks_sm2 && s.ks_group == NamedGroup::curveSM2) {
        // curveSM2 ECDH：共享密钥 = 32 字节 X 坐标（RFC 8998 3.4）
        if (!sm2_ecdh(shared_secret, s.ks_priv, server_pub_sm2, server_pub_sm2_len))
            return false;
        shared_len = 32;
        s.ks_group = NamedGroup::curveSM2;
    } else if (found_ks_p256 && s.ks_group == NamedGroup::secp256r1) {
        if (!ecdsa_p256_ecdh(shared_secret, s.ks_priv, server_pub_p256))
            return false;
        shared_len = 32;
        s.ks_group = NamedGroup::secp256r1;
    } else if (found_ks_p384 && s.ks_group == NamedGroup::secp384r1) {
        if (!ecdsa_p384_ecdh(shared_secret, s.ks_priv, server_pub_p384))
            return false;
        shared_len = 48;
        s.ks_group = NamedGroup::secp384r1;
    } else if (found_ks_x448 && s.ks_group == NamedGroup::X448) {
        // 使用 X448 计算
        uint8_t client_priv[56]; memcpy(client_priv, s.ks_priv, 56);
        x448_scalar_mult(shared_secret, client_priv, server_pub_x448);
        shared_len = 56;
        s.ks_group = NamedGroup::X448;
    } else {
        // 使用 X25519
        uint8_t client_priv[32];
        if (s.ks_group == NamedGroup::X448) {
            // 客户端请求 X448 但服务端只支持 X25519，回退
            memcpy(client_priv, s.client_write_key, 32);  // 旧 API 路径
        } else if (s.ks_group == NamedGroup::curveSM2) {
            // 客户端请求 SM 套件但服务端回退 X25519，使用兜底临时私钥
            memcpy(client_priv, s.ks_priv_x25519, 32);
        } else {
            memcpy(client_priv, s.ks_priv, 32);
        }
        x25519_scalar_mult(shared_secret, client_priv, server_pub_x25519);
        shared_len = 32;
        s.ks_group = NamedGroup::X25519;
    }

    tls13_derive_handshake_keys(s, shared_secret, shared_len);
    init_cipher_ctx(s, s.is_server?s.server_write_key:s.client_write_key);

    // 解析加密的握手消息
    std::vector<uint8_t> hs_msgs;
    while(offset<len){
        if(!s.quic_mode && (data[offset]==0x17 || data[offset]==0x16)){
            // 防御：读取 record 头长度字段前确保 5 字节头完整（offset 可能
            // 落在输入末尾附近，data[offset+3..4] 会越界——fuzz 发现）。
            if(offset+5>len)return false;
            size_t rlen=(data[offset+3]<<8)|data[offset+4];
            if(offset+5+rlen>len)return false;
            std::vector<uint8_t> hs;
            if(!tls13_decrypt_handshake(s,data+offset,5+rlen,hs))return false;
            hs_msgs.insert(hs_msgs.end(),hs.begin(),hs.end());
            offset+=5+rlen;
        }else{
            size_t hs_len=(data[offset+1]<<16)|(data[offset+2]<<8)|data[offset+3];
            if (offset + 4 > len || hs_len > len - offset - 4) return false;
            hs_msgs.insert(hs_msgs.end(), data + offset, data + offset + 4 + hs_len);
            offset += 4 + hs_len;
        }
    }

    // 解析握手消息
    size_t ho=0;
    while(ho<hs_msgs.size()){
        if(ho+4>hs_msgs.size())return false;
        size_t hlen=(hs_msgs[ho+1]<<16)|(hs_msgs[ho+2]<<8)|hs_msgs[ho+3];
        if(ho+4+hlen>hs_msgs.size())return false;
        uint8_t htype=hs_msgs[ho];
        const uint8_t* hmsg=hs_msgs.data()+ho;

        switch(htype){
            case (uint8_t)HandshakeType::ENCRYPTED_EXTENSIONS:
                tls_transcript_update(s,hmsg,4+hlen);
                // ALPN (RFC 7301)：EncryptedExtensions 中服务端返回的 ALPN 扩展
                // （ProtocolNameList 必须恰好包含一个协议，且必须属于客户端提议列表）
                s.alpn_selected.clear();
                {
                    size_t eo = 4; // 跳过握手头
                    if (eo + 2 <= 4 + hlen) {
                        size_t ee_ext_total = ((size_t)hmsg[eo] << 8) | hmsg[eo + 1];
                        size_t off = eo + 2;
                        size_t end = off + ee_ext_total;
                        if (end <= 4 + hlen) {
                            while (off + 4 <= end) {
                                uint16_t etype =
                                    (uint16_t)((hmsg[off] << 8) | hmsg[off + 1]);
                                size_t elen = ((size_t)hmsg[off + 2] << 8) | hmsg[off + 3];
                                if (off + 4 + elen > end) break;
                                if (etype == 0x0010) {
                                    auto list = tls_parse_alpn_list(hmsg + off + 4, elen);
                                    if (list.size() == 1) s.alpn_selected = list[0];
                                } else if (s.quic_mode && etype == 0x0039) {
                                    // QUIC (RFC 9001 §8.2)：解析服务端 transport parameters
                                    if (!quic_transport_parameters::decode(hmsg + off + 4, elen,
                                                                           s.quic_peer_transport_params))
                                        return false;
                                    s.quic_peer_params_valid = true;
                                }
                                off += 4 + elen;
                            }
                        }
                    }
                    // QUIC：EncryptedExtensions 必须携带 quic_transport_parameters（RFC 9001 §8.2）
                    if (s.quic_mode && !s.quic_peer_params_valid) return false;
                    if (!s.alpn_protos.empty() && !s.alpn_selected.empty()) {
                        bool ok = false;
                        for (const auto& p : s.alpn_protos)
                            if (p == s.alpn_selected) { ok = true; break; }
                        if (!ok) return false; // 服务端选择了客户端未提议的协议
                    }
                }
                break;
            case (uint8_t)HandshakeType::CERTIFICATE: {
                tls_transcript_update(s,hmsg,4+hlen);
                // signature_algorithms_cert: 校验对端证书链签名算法是否在客户端允许列表内
                const std::vector<uint16_t>& cert_algs =
                    s.sig_algs_cert.empty() ? tls_default_signature_algorithms() : s.sig_algs_cert;
                size_t bo = 4; // 跳过握手头
                // TLS 1.3 Certificate: context_len(1) + list_len(3) + [cert_len(3)+cert+ext_len(2)]*
                size_t ctx_len = (bo < 4 + hlen) ? hmsg[bo] : 0;
                size_t list_off = bo + 1 + ctx_len;
                if (list_off + 3 <= 4 + hlen) {
                    size_t list_len = ((size_t)hmsg[list_off] << 16) |
                                      ((size_t)hmsg[list_off + 1] << 8) | hmsg[list_off + 2];
                    size_t p = list_off + 3;
                    size_t list_end = list_off + 3 + list_len;
                    if (list_end > 4 + hlen) list_end = 4 + hlen;
                    std::vector<x509::x509_cert> chain;
                    while (p + 3 <= list_end) {
                        size_t cert_len = ((size_t)hmsg[p] << 16) |
                                          ((size_t)hmsg[p + 1] << 8) | hmsg[p + 2];
                        p += 3;
                        if (p + cert_len > list_end) break;
                        auto parsed = x509::x509_cert::from_der(hmsg + p, cert_len);
                        if (!parsed) break;
                        uint16_t chain_scheme = x509_key_type_chain_scheme(parsed->sign_key_type);
                        if (chain_scheme != 0 && !scheme_in_list(cert_algs, chain_scheme)) return false;
                        chain.push_back(std::move(*parsed));
                        p += cert_len;
                        if (p + 2 <= list_end) p += 2 + ((size_t)hmsg[p] << 8 | hmsg[p + 1]); // 跳过证书扩展
                        else break;
                    }
                    // 客户端 x509 验证：trust_store 提供 CA 根时，验证整条链 + 主机名
                    if (trust_store) {
                        if (!tls13_verify_server_chain(chain, *trust_store, s.server_name)) return false;
                        // 链验证通过后必须能用叶子证书构造 server_cert 验证 CertificateVerify
                        // 否则（如 RSA-4096 对端证书）不能静默跳过 CV 校验，直接判失败
                        if (chain.empty() ||
                            !(parsed_server_cert = tls_cert_from_x509_leaf(chain[0])))
                            return false;
                        server_cert = parsed_server_cert.get();
                    }
                }
                // 旧行为：cert_manager 按 SNI 查找预期服务器证书（trust_store 未提供时使用）
                if (!server_cert && cert_manager) {
                    server_cert = cert_manager->get_certificate(s.server_name);
                    if (!server_cert) server_cert = cert_manager->get_default_certificate();
                }
                break;
            }
            case (uint8_t)HandshakeType::CERT_VERIFY:
                if(server_cert){
                    if(!tls13_verify_cert_verify(*server_cert,s,hmsg,4+hlen))return false;
                }
                tls_transcript_update(s,hmsg,4+hlen);
                break;
            case (uint8_t)HandshakeType::FINISHED:
                if(!tls13_verify_finished(s,hmsg,4+hlen,true))return false;
                tls_transcript_update(s,hmsg,4+hlen);
                s.server_finished_received = true;
                break;
            default:break;
        }
        ho+=4+hlen;
    }

    // 生成 Client Finished
    client_finished=tls13_make_finished(s,false);

    if (!s.quic_mode) {
        // 加密 Client Finished（使用握手密钥）
        auto encrypted=tls_encrypt_handshake(s,client_finished.data(),client_finished.size());
        client_finished=encrypted;
    }
    // QUIC 模式：client_finished 为原始握手消息字节，直接交由 CRYPTO 帧发送

    // 派生应用密钥（在 transcript 更新前，与简化版保持一致）
    tls13_derive_application_keys(s);

    tls_transcript_update(s,client_finished.data(),client_finished.size());
    init_cipher_ctx(s, s.is_server?s.server_write_key:s.client_write_key);
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
//  简化版 API（兼容旧接口）
// ════════════════════════════════════════════════════════════════════════════
bool tls13_handshake_client(tls_session& s, std::vector<uint8_t>& client_hello,
                             const uint8_t* server_response, size_t resp_len){
    tls13_make_client_hello(s,client_hello);
    std::vector<uint8_t> cf;
    s.ver=TLSVersion::V13;
    memcpy(s.server_random,server_response+6,32);
    tls_transcript_update(s,server_response,resp_len);
    uint8_t server_pub[32];
    memcpy(server_pub,server_response+50,32);
    uint8_t client_priv[32];memcpy(client_priv,s.client_write_key,32);
    uint8_t shared_secret[32];
    x25519_scalar_mult(shared_secret,client_priv,server_pub);
    tls13_derive_keys(s,shared_secret,32);
    init_cipher_ctx(s, s.client_write_key);
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
//  PSK storage (client side)
// ════════════════════════════════════════════════════════════════════════════

bool tls13_store_psk(tls_session& s, const uint8_t* ticket_msg, size_t ticket_len){
    if(ticket_len<8) return false;
    if(ticket_msg[0]!=(uint8_t)HandshakeType::NEW_SESSION_TICKET) return false;
    size_t blen = (ticket_msg[1]<<16)|(ticket_msg[2]<<8)|ticket_msg[3];
    if(4+blen > ticket_len) return false;

    const uint8_t* body = ticket_msg+4;
    size_t off = 0;
    off += 4; // ticket_lifetime
    s.ticket_age_add = (body[off]<<24)|(body[off+1]<<16)|(body[off+2]<<8)|body[off+3];
    off += 4;
    uint8_t nonce_len = body[off++];
    if(off + nonce_len > blen) return false;
    const uint8_t* ticket_nonce = body + off;
    off += nonce_len;
    uint16_t tkt_len = (body[off]<<8)|body[off+1];
    off += 2;
    if(off + tkt_len > blen) return false;
    const uint8_t* ticket = body + off;

    if(tkt_len > sizeof(s.psk_identity)) tkt_len = sizeof(s.psk_identity);
    memcpy(s.psk_identity, ticket, tkt_len);
    s.psk_identity_len = (uint8_t)tkt_len;
    s.ticket_issue_time = (uint64_t)time(nullptr);

    uint8_t resumption_secret[48];
    tls13_derive_resumption_secret(s, resumption_secret);
    size_t hl=tls_hash_len(s.cipher_suite);
    if(tls_use_sha384(s.cipher_suite))
        hkdf_expand_label_sha384(resumption_secret,"resumption",ticket_nonce,nonce_len,s.psk_value,hl);
    else
        hkdf_expand_label(resumption_secret,"resumption",ticket_nonce,nonce_len,s.psk_value,hl);

    s.psk_valid = true;
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
//  PSK ClientHello
// ════════════════════════════════════════════════════════════════════════════

bool tls13_make_psk_client_hello(tls_session& s, std::vector<uint8_t>& client_hello){
    if(!s.psk_valid) return false;
    s.transcript_ready = false;
    s.is_server = false;
    s.ver = TLSVersion::V13;
    rand32(s.client_random);

    size_t hl=tls_hash_len(s.cipher_suite);
    std::vector<uint8_t> all_ext;

    // SNI
    if(!s.server_name.empty()){
        all_ext.push_back(0x00);all_ext.push_back(0x00);
        uint16_t sni_len=5+s.server_name.size();
        all_ext.push_back(0x00);all_ext.push_back((uint8_t)sni_len);
        uint16_t nl_len=3+s.server_name.size();
        all_ext.push_back(0x00);all_ext.push_back((uint8_t)nl_len);
        all_ext.push_back(0x00);
        all_ext.push_back(0x00);all_ext.push_back((uint8_t)s.server_name.size());
        for(char c:s.server_name)all_ext.push_back((uint8_t)c);
    }
    // supported_versions
    all_ext.push_back(0x00);all_ext.push_back(0x2b);all_ext.push_back(0x00);all_ext.push_back(0x03);
    all_ext.push_back(0x02);all_ext.push_back(0x03);all_ext.push_back(0x04);
    // supported_groups
    all_ext.push_back(0x00);all_ext.push_back(0x0a);all_ext.push_back(0x00);all_ext.push_back(0x04);
    all_ext.push_back(0x00);all_ext.push_back(0x02);all_ext.push_back(0x00);all_ext.push_back(0x1d);
    // signature_algorithms + signature_algorithms_cert
    {
        const std::vector<uint16_t>& algs = effective_sig_algs(s);
        std::vector<uint16_t> cert_algs =
            s.sig_algs_cert.empty() ? tls_default_signature_algorithms() : s.sig_algs_cert;
        std::vector<uint16_t> cert_filtered;
        for (uint16_t a : cert_algs) if (scheme_in_list(algs, a)) cert_filtered.push_back(a);
        append_sig_alg_extension(all_ext, 0x000d, algs);
        append_sig_alg_extension(all_ext, 0x0032, cert_filtered);
    }
    // key_share X25519
    {
        uint8_t cpriv[32],cpub[32];
        x25519_generate_keypair(cpub,cpriv);
        memcpy(s.ks_priv, cpriv, 32);
        all_ext.push_back(0x00);all_ext.push_back(0x33);all_ext.push_back(0x00);all_ext.push_back(0x26);
        all_ext.push_back(0x00);all_ext.push_back(0x24);
        all_ext.push_back(0x00);all_ext.push_back(0x1d);all_ext.push_back(0x00);all_ext.push_back(0x20);
        all_ext.insert(all_ext.end(),cpub,cpub+32);
    }
    // psk_key_exchange_modes
    all_ext.push_back(0x00);all_ext.push_back(0x2d);all_ext.push_back(0x00);all_ext.push_back(0x02);
    all_ext.push_back(0x01);all_ext.push_back(0x01);
    // early_data
    all_ext.push_back(0x00);all_ext.push_back(0x2a);all_ext.push_back(0x00);all_ext.push_back(0x00);

    // PSK extension
    uint16_t id_len = s.psk_identity_len;
    uint64_t now = (uint64_t)time(nullptr);
    uint64_t age_ms = (now - s.ticket_issue_time) * 1000;
    uint32_t obf_age = (uint32_t)(age_ms + s.ticket_age_add);
    size_t identities_len = 2 + id_len + 4;
    size_t binders_len = 1 + hl;
    size_t psk_ext_data_len = 2 + identities_len + 2 + binders_len;

    all_ext.push_back(0x00);all_ext.push_back(0x29);
    all_ext.push_back((uint8_t)(psk_ext_data_len>>8));all_ext.push_back((uint8_t)(psk_ext_data_len));
    all_ext.push_back((uint8_t)(identities_len>>8));all_ext.push_back((uint8_t)(identities_len));
    all_ext.push_back((uint8_t)(id_len>>8));all_ext.push_back((uint8_t)(id_len));
    all_ext.insert(all_ext.end(), s.psk_identity, s.psk_identity + id_len);
    all_ext.push_back((uint8_t)(obf_age>>24));all_ext.push_back((uint8_t)(obf_age>>16));
    all_ext.push_back((uint8_t)(obf_age>>8));all_ext.push_back((uint8_t)(obf_age));
    all_ext.push_back((uint8_t)(binders_len>>8));all_ext.push_back((uint8_t)(binders_len));
    all_ext.push_back((uint8_t)(hl));
    size_t binder_pos = all_ext.size();
    for(size_t i=0;i<hl;i++) all_ext.push_back(0);

    // Build ClientHello
    client_hello.clear();
    client_hello.push_back((uint8_t)HandshakeType::CLIENT_HELLO);
    client_hello.push_back(0);client_hello.push_back(0);client_hello.push_back(0);
    client_hello.push_back(0x03);client_hello.push_back(0x03);
    client_hello.insert(client_hello.end(),s.client_random,s.client_random+32);
    std::vector<uint16_t> psk_cs;
    auto psk_push = [&](uint16_t id){ for (uint16_t c : psk_cs) if (c==id) return; psk_cs.push_back(id); };
    // 与完整握手相同的默认偏好：国密 > ChaCha20 > AES（QUIC 模式不通告国密）
    bool psk_offer_sm = !s.quic_mode && (!s.cipher_suite_pinned || tls_use_sm3(s.cipher_suite));
    if (s.cipher_suite_pinned && !(s.quic_mode && tls_use_sm3(s.cipher_suite)))
        psk_push((uint16_t)s.cipher_suite);
    if (psk_offer_sm) { psk_push(0x00C6); psk_push(0x00C7); }
    psk_push(0x1303);
    psk_push(0x1301); psk_push(0x1302);
    psk_push(0x1304); psk_push(0x1305);
    uint16_t psk_cs_len = (uint16_t)(psk_cs.size() * 2);
    client_hello.push_back(0);
    client_hello.push_back((uint8_t)(psk_cs_len>>8));client_hello.push_back((uint8_t)psk_cs_len);
    for (uint16_t psk_cs_id : psk_cs) {
        client_hello.push_back((uint8_t)(psk_cs_id>>8));client_hello.push_back((uint8_t)psk_cs_id);
    }
    client_hello.push_back(0x01);client_hello.push_back(0x00);

    uint16_t ext_total = (uint16_t)all_ext.size();
    client_hello.push_back((uint8_t)(ext_total>>8));
    client_hello.push_back((uint8_t)(ext_total));
    client_hello.insert(client_hello.end(), all_ext.begin(), all_ext.end());

    // Update CH length BEFORE computing binder (binder covers CH length header)
    size_t ch_len = client_hello.size() - 4;
    client_hello[1] = (uint8_t)(ch_len>>16);
    client_hello[2] = (uint8_t)(ch_len>>8);
    client_hello[3] = (uint8_t)(ch_len);

    // Compute and write binder
    size_t ch_trunc_len = client_hello_ext_offset(client_hello.data(), client_hello.size()) + 2 + binder_pos;
    uint8_t binder[48];
    tls13_compute_binder(s, s.psk_value, client_hello.data(), ch_trunc_len, binder);
    size_t binder_off = ch_trunc_len;
    for(size_t i=0;i<hl;i++) client_hello[binder_off + i] = binder[i];

    tls_transcript_update(s, client_hello.data(), client_hello.size());
    tls13_derive_early_traffic_keys(s, s.psk_value);
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
//  Early data encrypt/decrypt
// ════════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> tls13_encrypt_early_data(tls_session& s,
                                              const uint8_t* data, size_t len){
    std::vector<uint8_t> inner;
    inner.insert(inner.end(), data, data+len);
    inner.push_back((uint8_t)ContentType::APPLICATION_DATA);

    uint8_t nonce[12];
    memcpy(nonce, s.client_early_write_iv, 12);
    for(int i=0;i<8;++i) nonce[4+i] ^= (uint8_t)(s.client_early_seq>>(56-i*8));
    ++s.client_early_seq;

    std::vector<uint8_t> ciphertext;
    uint8_t tag[16];
    size_t tag_len=tls_aead_tag_len(s.cipher_suite);
    // RFC 8446 5.2：AAD = record 头 5 字节（early data record 同样适用）
    uint8_t aad[5]={0x17,0x03,0x03,(uint8_t)((inner.size()+tag_len)>>8),(uint8_t)(inner.size()+tag_len)};
    std::span<const uint8_t> aad_span(aad,5);
    // Inline AEAD dispatch
    switch(s.cipher_suite){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384: {
            aes_context ctx;
            aes_ctx_init(ctx, s.client_early_write_key, aes_key_len(s.cipher_suite));
            aes_gcm_encrypt_auto(ctx, nonce, 12, inner, aad_span, ciphertext, tag, 16);
            break;
        }
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            chacha20_poly1305_encrypt(s.client_early_write_key, nonce, inner, aad_span, ciphertext, tag);
            break;
        case CipherSuite::TLS_AES_128_CCM_SHA256:
        case CipherSuite::TLS_AES_128_CCM_8_SHA256: {
            aes_context ctx;
            aes_ctx_init(ctx, s.client_early_write_key, aes_key_len(s.cipher_suite));
            aes_ccm_encrypt(ctx, nonce, 12, inner, aad_span, ciphertext, tag, tag_len);
            break;
        }
        case CipherSuite::TLS_SM4_GCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, s.client_early_write_key);
            sm4_gcm_encrypt_auto(&s.sm4, nonce, 12, inner, aad_span, ciphertext, tag, 16);
            break;
        }
        case CipherSuite::TLS_SM4_CCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, s.client_early_write_key);
            sm4_ccm_encrypt_auto(&s.sm4, nonce, 12, inner, aad_span, ciphertext, tag, 16);
            break;
        }
    }

    std::vector<uint8_t> record;
    record.push_back(0x17);
    record.push_back(0x03); record.push_back(0x03);
    size_t rlen = ciphertext.size() + tag_len;
    record.push_back((uint8_t)(rlen>>8)); record.push_back((uint8_t)(rlen));
    record.insert(record.end(), ciphertext.begin(), ciphertext.end());
    record.insert(record.end(), tag, tag+tag_len);
    return record;
}

bool tls13_process_end_of_early_data(tls_session& s, const uint8_t* data, size_t len){
    (void)s;
    if(len < 4) return false;
    if(data[0] != (uint8_t)HandshakeType::END_OF_EARLY_DATA) return false;
    return true;
}

} // namespace jpssl::tls
