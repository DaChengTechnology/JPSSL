#include "tls.hpp"
#include <cstring>
#include <random>
#include <algorithm>
namespace jpssl::tls {

static void rand32(uint8_t* buf){static std::mt19937_64 g(std::random_device{}());for(int i=0;i<4;++i){uint64_t v=g();memcpy(buf+i*8,&v,8);}}

// ═══════════════════════════════════════════════════════════════════════
//  transcript 辅助
// ═══════════════════════════════════════════════════════════════════════
void tls_transcript_update(tls_session& s, const uint8_t* data, size_t len){
    if(!s.transcript_ready){sha256_init(&s.transcript_ctx);s.transcript_ready=true;}
    sha256_update(&s.transcript_ctx,data,len);
}
void tls_transcript_finalize(tls_session& s){
    if(s.transcript_ready){sha256_ctx copy=s.transcript_ctx;sha256_final(&copy,s.transcript_hash);}
}

// ═══════════════════════════════════════════════════════════════════════
//  证书签名/验证
// ═══════════════════════════════════════════════════════════════════════
bool tls_certificate::sign(const uint8_t* data, size_t data_len, uint8_t* sig, size_t& sig_len) const {
    switch(sig_alg){
        case SignatureAlgorithm::ED25519:
            sig_len=64;ed25519_sign(priv.ed25519,data,data_len,sig);return true;
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256:
            sig_len=64;ecdsa_p256_sign(priv.ecdsa_p256,data,data_len,sig);return true;
        case SignatureAlgorithm::RSA_PKCS1_SHA256:
            sig_len=0;return true; // 简化
        default:return false;
    }
}
bool tls_certificate::verify(const uint8_t* data, size_t data_len, const uint8_t* sig, size_t sig_len) const {
    switch(sig_alg){
        case SignatureAlgorithm::ED25519:
            if(sig_len!=64)return false;
            return ed25519_verify(pub.ed25519,data,data_len,sig);
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256:
            if(sig_len!=64)return false;
            return ecdsa_p256_verify(pub.ecdsa_p256,data,data_len,sig);
        case SignatureAlgorithm::RSA_PKCS1_SHA256:
            return true;
        default:return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  证书管理器
// ═══════════════════════════════════════════════════════════════════════
void tls_certificate_manager::add_certificate(const std::string& domain, std::unique_ptr<tls_certificate> cert){
    if(default_domain.empty())default_domain=domain;
    certificates[domain]=std::move(cert);
}
const tls_certificate* tls_certificate_manager::get_certificate(const std::string& domain) const {
    auto it=certificates.find(domain);
    if(it!=certificates.end())return it->second.get();
    return get_default_certificate();
}
const tls_certificate* tls_certificate_manager::get_default_certificate() const {
    if(default_domain.empty())return nullptr;
    auto it=certificates.find(default_domain);
    return it!=certificates.end()?it->second.get():nullptr;
}

// ═══════════════════════════════════════════════════════════════════════
//  SNI 解析
// ═══════════════════════════════════════════════════════════════════════
std::string tls_parse_server_name(const uint8_t* extensions, size_t ext_len){
    if(ext_len<2)return "";
    size_t offset=0;
    while(offset+4<=ext_len){
        uint16_t ext_type=(extensions[offset]<<8)|extensions[offset+1];
        uint16_t ext_len2=(extensions[offset+2]<<8)|extensions[offset+3];
        offset+=4;
        if(offset+ext_len2>ext_len)break;
        if(ext_type==0 && ext_len2>=5){
            offset+=2;
            uint8_t name_type=extensions[offset++];
            uint16_t name_len=(extensions[offset]<<8)|extensions[offset+1];
            offset+=2;
            if(name_type==0 && offset+name_len<=ext_len)
                return std::string((const char*)extensions+offset,name_len);
        }
        offset+=ext_len2;
    }
    return "";
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.3 密钥派生
// ═══════════════════════════════════════════════════════════════════════
static void tls13_derive_handshake_keys(tls_session& s, const uint8_t shared_secret[32]){
    uint8_t zero[32]={},early_secret[32],empty_hash[32];
    sha256_ctx ctx;sha256_init(&ctx);sha256_final(&ctx,empty_hash);
    hkdf_extract(zero,32,zero,32,early_secret);
    hkdf_extract(early_secret,32,shared_secret,32,s.handshake_secret);

    uint8_t hello_hash[32];
    sha256_init(&ctx);sha256_update(&ctx,s.client_random,32);sha256_update(&ctx,s.server_random,32);sha256_final(&ctx,hello_hash);
    uint8_t ch_ts[32],sh_ts[32];
    hkdf_expand_label(s.handshake_secret,"c hs traffic",hello_hash,32,ch_ts,32);
    hkdf_expand_label(s.handshake_secret,"s hs traffic",hello_hash,32,sh_ts,32);

    memcpy(s.client_write_key,ch_ts,32);memcpy(s.server_write_key,sh_ts,32);
    hkdf_expand_label(s.handshake_secret,"c hs traffic",hello_hash,32,s.client_write_iv,12);
    hkdf_expand_label(s.handshake_secret,"s hs traffic",hello_hash,32,s.server_write_iv,12);
    s.client_seq=0;s.server_seq=0;
}

static void tls13_derive_application_keys(tls_session& s){
    uint8_t zero[32]={};
    hkdf_extract(s.handshake_secret,32,zero,32,s.master_secret);
    uint8_t ap_hash[32];sha256_ctx ctx;
    sha256_init(&ctx);sha256_update(&ctx,s.transcript_hash,32);sha256_final(&ctx,ap_hash);
    hkdf_expand_label(s.master_secret,"c ap traffic",ap_hash,32,s.client_write_key,32);
    hkdf_expand_label(s.master_secret,"s ap traffic",ap_hash,32,s.server_write_key,32);
    hkdf_expand_label(s.master_secret,"c ap traffic",ap_hash,32,s.client_write_iv,12);
    hkdf_expand_label(s.master_secret,"s ap traffic",ap_hash,32,s.server_write_iv,12);
    s.client_seq=0;s.server_seq=0;
}

static void tls13_derive_keys(tls_session& s, const uint8_t shared_secret[32]){
    uint8_t early_secret[32],empty_hash[32];
    sha256_ctx ctx;sha256_init(&ctx);sha256_final(&ctx,empty_hash);
    uint8_t zero[32]={};
    hkdf_extract(zero,32,zero,32,early_secret);
    hkdf_extract(early_secret,32,shared_secret,32,s.handshake_secret);
    uint8_t hello_hash[32];
    sha256_init(&ctx);sha256_update(&ctx,s.client_random,32);sha256_update(&ctx,s.server_random,32);sha256_final(&ctx,hello_hash);
    hkdf_expand_label(s.handshake_secret,"c hs traffic",hello_hash,32,s.client_write_key,32);
    hkdf_expand_label(s.handshake_secret,"s hs traffic",hello_hash,32,s.server_write_key,32);
    hkdf_expand_label(s.handshake_secret,"c hs traffic",hello_hash,32,s.client_write_iv,12);
    hkdf_expand_label(s.handshake_secret,"s hs traffic",hello_hash,32,s.server_write_iv,12);
    hkdf_extract(s.handshake_secret,32,zero,32,s.master_secret);
    uint8_t ap_hash[32];sha256_init(&ctx);sha256_update(&ctx,hello_hash,32);sha256_final(&ctx,ap_hash);
    hkdf_expand_label(s.master_secret,"c ap traffic",ap_hash,32,s.client_write_key,32);
    hkdf_expand_label(s.master_secret,"s ap traffic",ap_hash,32,s.server_write_key,32);
    hkdf_expand_label(s.master_secret,"c ap traffic",ap_hash,32,s.client_write_iv,12);
    hkdf_expand_label(s.master_secret,"s ap traffic",ap_hash,32,s.server_write_iv,12);
    s.client_seq=0;s.server_seq=0;
}

// ═══════════════════════════════════════════════════════════════════════
//  构建 Finished 消息
// ═══════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> tls13_make_finished(tls_session& s, bool for_server){
    const uint8_t* base_key=for_server?s.server_write_key:s.client_write_key;
    uint8_t finished_key[32];
    hkdf_expand_label(s.handshake_secret,"finished",nullptr,0,finished_key,32);

    tls_transcript_finalize(s);
    uint8_t verify_data[32];
    hmac_sha256(finished_key,32,s.transcript_hash,32,verify_data);

    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::FINISHED);
    msg.push_back(0);msg.push_back(0);msg.push_back(32);
    msg.insert(msg.end(),verify_data,verify_data+32);
    return msg;
}

static bool tls13_verify_finished(tls_session& s, const uint8_t* hs_msg, size_t hs_len, bool for_server){
    if(hs_len<4 || hs_msg[0]!=(uint8_t)HandshakeType::FINISHED)return false;
    size_t vd_len=(hs_msg[1]<<16)|(hs_msg[2]<<8)|hs_msg[3];
    if(vd_len!=32 || hs_len!=4+vd_len)return false;

    const uint8_t* base_key=for_server?s.server_write_key:s.client_write_key;
    uint8_t finished_key[32];
    hkdf_expand_label(s.handshake_secret,"finished",nullptr,0,finished_key,32);

    tls_transcript_finalize(s);
    uint8_t expected[32];
    hmac_sha256(finished_key,32,s.transcript_hash,32,expected);

    return memcmp(expected,hs_msg+4,32)==0;
}

// ═══════════════════════════════════════════════════════════════════════
//  构建 Certificate + CertificateVerify 消息
// ═══════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> tls13_make_certificate(const tls_certificate& cert){
    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::CERTIFICATE);
    // 简化: cert_data 作为证书内容
    size_t body_len=1+cert.cert_data.size()+2;
    msg.push_back((uint8_t)(body_len>>16));msg.push_back((uint8_t)(body_len>>8));msg.push_back((uint8_t)body_len);
    msg.push_back(0); // certificate_request_context
    // certificate_list length
    size_t clen=cert.cert_data.size()+3;
    msg.push_back((uint8_t)(clen>>16));msg.push_back((uint8_t)(clen>>8));msg.push_back((uint8_t)clen);
    msg.push_back((uint8_t)(cert.cert_data.size()>>16));msg.push_back((uint8_t)(cert.cert_data.size()>>8));msg.push_back((uint8_t)cert.cert_data.size());
    msg.insert(msg.end(),cert.cert_data.begin(),cert.cert_data.end());
    // extensions: 0 length
    msg.push_back(0);msg.push_back(0);
    return msg;
}

static std::vector<uint8_t> tls13_make_cert_verify(const tls_certificate& cert, tls_session& s){
    tls_transcript_finalize(s);
    uint8_t sig[128];size_t sig_len=0;
    if(!cert.sign(s.transcript_hash,32,sig,sig_len))return {};

    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::CERT_VERIFY);
    uint16_t alg=(uint16_t)cert.sig_alg;
    size_t body_len=2+2+sig_len;
    msg.push_back((uint8_t)(body_len>>16));msg.push_back((uint8_t)(body_len>>8));msg.push_back((uint8_t)body_len);
    msg.push_back((uint8_t)(alg>>8));msg.push_back((uint8_t)alg);
    msg.push_back((uint8_t)(sig_len>>8));msg.push_back((uint8_t)sig_len);
    msg.insert(msg.end(),sig,sig+sig_len);
    return msg;
}

static bool tls13_verify_cert_verify(const tls_certificate& cert, tls_session& s, const uint8_t* hs_msg, size_t hs_len){
    if(hs_len<8 || hs_msg[0]!=(uint8_t)HandshakeType::CERT_VERIFY)return false;
    uint16_t alg=(hs_msg[4]<<8)|hs_msg[5];
    if(alg!=(uint16_t)cert.sig_alg)return false;
    uint16_t sig_len=(hs_msg[6]<<8)|hs_msg[7];
    if(4+2+2+sig_len!=hs_len)return false;
    tls_transcript_finalize(s);
    return cert.verify(s.transcript_hash,32,hs_msg+8,sig_len);
}

// ═══════════════════════════════════════════════════════════════════════
//  构建 EncryptedExtensions
// ═══════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> tls13_make_encrypted_extensions(){
    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::ENCRYPTED_EXTENSIONS);
    msg.push_back(0);msg.push_back(0);msg.push_back(2); // extensions length
    msg.push_back(0);msg.push_back(0); // empty extensions
    return msg;
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.3 加密握手消息（用于 EncryptedExtensions 之后的所有消息）
// ═══════════════════════════════════════════════════════════════════════
std::vector<uint8_t> tls_encrypt_handshake(tls_session& s, const uint8_t* hs_msg, size_t hs_len){
    bool is_svr=s.is_server;
    const uint8_t* write_key=is_svr?s.server_write_key:s.client_write_key;
    const uint8_t* write_iv=is_svr?s.server_write_iv:s.client_write_iv;
    uint64_t& seq=is_svr?s.server_seq:s.client_seq;

    std::vector<uint8_t> inner;inner.push_back((uint8_t)ContentType::HANDSHAKE);
    inner.insert(inner.end(),hs_msg,hs_msg+hs_len);
    inner.push_back((uint8_t)ContentType::HANDSHAKE);

    uint8_t nonce[12];memcpy(nonce,write_iv,12);
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(seq>>(56-i*8));
    ++seq;

    aes_context ctx;ctx.init(std::span<const uint8_t,16>(write_key,16));
    std::vector<uint8_t> ciphertext;uint8_t tag[16];
    aes_gcm_encrypt(ctx,nonce,12,inner,std::span<const uint8_t>(),ciphertext,tag,16);

    std::vector<uint8_t> record;
    record.push_back(0x17); // application_data (TLS 1.3 统一使用)
    record.push_back(0x03);record.push_back(0x03);
    size_t rlen=ciphertext.size()+16;
    record.push_back((uint8_t)(rlen>>8));record.push_back((uint8_t)rlen);
    record.insert(record.end(),ciphertext.begin(),ciphertext.end());
    record.insert(record.end(),tag,tag+16);
    return record;
}

// 解密握手消息，返回内部 handshake 数据
static bool tls13_decrypt_handshake(tls_session& s, const uint8_t* record, size_t record_len, std::vector<uint8_t>& hs_out){
    if(record_len<5)return false;
    bool is_svr=s.is_server;
    const uint8_t* read_key=is_svr?s.client_write_key:s.server_write_key;
    const uint8_t* read_iv=is_svr?s.client_write_iv:s.server_write_iv;
    uint64_t& seq=is_svr?s.client_seq:s.server_seq;

    size_t rlen=(record[3]<<8)|record[4];
    if(5+rlen!=record_len)return false;
    const uint8_t* ciphertext=record+5;
    size_t ct_len=rlen-16;
    const uint8_t* tag=record+5+ct_len;

    uint8_t nonce[12];memcpy(nonce,read_iv,12);
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(seq>>(56-i*8));
    ++seq;

    aes_context ctx;ctx.init(std::span<const uint8_t,16>(read_key,16));
    std::vector<uint8_t> inner;
    if(!aes_gcm_decrypt(ctx,nonce,12,std::span<const uint8_t>(ciphertext,ct_len),std::span<const uint8_t>(),tag,16,inner))
        return false;

    if(inner.size()<2 || inner[0]!=(uint8_t)ContentType::HANDSHAKE)return false;
    if(inner.back()!=(uint8_t)ContentType::HANDSHAKE)return false;
    hs_out.assign(inner.begin()+1,inner.end()-1);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.3 完整握手 — 客户端
// ═══════════════════════════════════════════════════════════════════════
bool tls13_make_client_hello(tls_session& s, std::vector<uint8_t>& client_hello){
    s.ver=TLSVersion::V13;s.is_server=false;
    s.transcript_ready=false;
    rand32(s.client_random);

    client_hello.clear();
    client_hello.push_back((uint8_t)HandshakeType::CLIENT_HELLO);
    client_hello.push_back(0);client_hello.push_back(0);client_hello.push_back(0);
    client_hello.push_back(0x03);client_hello.push_back(0x03);
    client_hello.insert(client_hello.end(),s.client_random,s.client_random+32);
    client_hello.push_back(0);
    client_hello.push_back(0);client_hello.push_back(2);
    client_hello.push_back(0x13);client_hello.push_back(0x01);
    client_hello.push_back(0x01);client_hello.push_back(0x00);

    std::vector<uint8_t> ext;
    if(!s.server_name.empty()){
        ext.push_back(0x00);ext.push_back(0x00);
        uint16_t sni_payload_len=3+s.server_name.size();
        ext.push_back(0x00);ext.push_back((uint8_t)sni_payload_len);
        uint16_t name_list_len=1+s.server_name.size();
        ext.push_back(0x00);ext.push_back((uint8_t)name_list_len);
        ext.push_back(0x00);
        ext.push_back(0x00);ext.push_back((uint8_t)s.server_name.size());
        for(char c:s.server_name)ext.push_back((uint8_t)c);
    }
    ext.push_back(0x00);ext.push_back(0x2b);ext.push_back(0x00);ext.push_back(0x03);ext.push_back(0x02);ext.push_back(0x03);ext.push_back(0x04);
    ext.push_back(0x00);ext.push_back(0x0a);ext.push_back(0x00);ext.push_back(0x04);ext.push_back(0x00);ext.push_back(0x02);ext.push_back(0x00);ext.push_back(0x1d);
    ext.push_back(0x00);ext.push_back(0x0d);ext.push_back(0x00);ext.push_back(0x06);ext.push_back(0x00);ext.push_back(0x04);ext.push_back(0x08);ext.push_back(0x07);ext.push_back(0x04);ext.push_back(0x03);
    // key_share: x25519
    uint8_t client_priv[32],client_pub[32];
    x25519_generate_keypair(client_pub,client_priv);
    ext.push_back(0x00);ext.push_back(0x33);ext.push_back(0x00);ext.push_back(0x24);ext.push_back(0x00);ext.push_back(0x1d);ext.push_back(0x00);ext.push_back(0x20);
    ext.insert(ext.end(),client_pub,client_pub+32);

    uint16_t ext_len_total=ext.size();
    client_hello.push_back((uint8_t)(ext_len_total>>8));client_hello.push_back((uint8_t)ext_len_total);
    client_hello.insert(client_hello.end(),ext.begin(),ext.end());

    size_t len=client_hello.size()-4;
    client_hello[1]=(uint8_t)(len>>16);client_hello[2]=(uint8_t)(len>>8);client_hello[3]=(uint8_t)len;

    tls_transcript_update(s,client_hello.data(),client_hello.size());
    memcpy(s.client_write_key,client_priv,32);
    return true;
}

bool tls13_process_server_flight(tls_session& s, const uint8_t* data, size_t len,
                                  std::vector<uint8_t>& client_finished,
                                  const tls_certificate_manager* cert_manager){
    if(len<5)return false;
    size_t offset=0;
    const tls_certificate* server_cert=nullptr;

    // 解析 ServerHello（明文）
    if(data[offset]!=(uint8_t)HandshakeType::SERVER_HELLO)return false;
    size_t sh_len=(data[offset+1]<<16)|(data[offset+2]<<8)|data[offset+3];
    size_t sh_start=offset;
    offset+=4+sh_len;if(offset>len)return false;
    memcpy(s.server_random,data+sh_start+10,32);

    tls_transcript_update(s,data+sh_start,4+sh_len);

    // 提取 server_pub 从 key_share
    size_t ext_start=sh_start+4+2+32+1+2+1;
    uint16_t ext_total=(data[ext_start]<<8)|data[ext_start+1];
    size_t ext_off=ext_start+2;
    uint8_t server_pub[32];
    bool found_ks=false;
    while(ext_off+4<=ext_start+2+ext_total){
        uint16_t etype=(data[ext_off]<<8)|data[ext_off+1];
        uint16_t elen=(data[ext_off+2]<<8)|data[ext_off+3];
        if(etype==0x33 && elen>=4){
            if(data[ext_off+4]==0x00 && data[ext_off+5]==0x1d && data[ext_off+6]==0x00 && data[ext_off+7]==0x20){
                memcpy(server_pub,data+ext_off+8,32);found_ks=true;break;
            }
        }
        ext_off+=4+elen;
    }
    if(!found_ks){memcpy(server_pub,data+sh_start+50,32);}

    uint8_t client_priv[32];memcpy(client_priv,s.client_write_key,32);
    uint8_t shared_secret[32];
    x25519_scalar_mult(shared_secret,client_priv,server_pub);

    tls13_derive_handshake_keys(s,shared_secret);
    s.aes_ctx.init(std::span<const uint8_t,16>(s.is_server?s.server_write_key:s.client_write_key,16));

    // 解析加密的握手消息
    std::vector<uint8_t> hs_msgs;
    while(offset<len){
        if(data[offset]==0x17 || data[offset]==0x16){
            size_t rlen=(data[offset+3]<<8)|data[offset+4];
            if(offset+5+rlen>len)return false;
            std::vector<uint8_t> hs;
            if(!tls13_decrypt_handshake(s,data+offset,5+rlen,hs))return false;
            hs_msgs.insert(hs_msgs.end(),hs.begin(),hs.end());
            offset+=5+rlen;
        }else{
            size_t hs_len=(data[offset+1]<<16)|(data[offset+2]<<8)|data[offset+3];
            if(offset+4+hs_len>len)return false;
            hs_msgs.insert(hs_msgs.end(),data+offset,data+offset+4+hs_len);
            offset+=4+hs_len;
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
                break;
            case (uint8_t)HandshakeType::CERTIFICATE:
                tls_transcript_update(s,hmsg,4+hlen);
                if(cert_manager){
                    server_cert=cert_manager->get_certificate(s.server_name);
                    if(!server_cert)server_cert=cert_manager->get_default_certificate();
                }
                break;
            case (uint8_t)HandshakeType::CERT_VERIFY:
                if(server_cert){
                    if(!tls13_verify_cert_verify(*server_cert,s,hmsg,4+hlen))return false;
                }
                tls_transcript_update(s,hmsg,4+hlen);
                break;
            case (uint8_t)HandshakeType::FINISHED:
                if(!tls13_verify_finished(s,hmsg,4+hlen,true))return false;
                tls_transcript_update(s,hmsg,4+hlen);
                break;
            default:break;
        }
        ho+=4+hlen;
    }

    // 派生应用密钥
    tls13_derive_application_keys(s);

    // 生成 Client Finished
    client_finished=tls13_make_finished(s,false);
    tls_transcript_update(s,client_finished.data(),client_finished.size());

    // 加密 Client Finished
    auto encrypted=tls_encrypt_handshake(s,client_finished.data(),client_finished.size());
    client_finished=encrypted;

    s.aes_ctx.init(std::span<const uint8_t,16>(s.is_server?s.server_write_key:s.client_write_key,16));
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.3 完整握手 — 服务端
// ═══════════════════════════════════════════════════════════════════════
bool tls13_make_server_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                               std::vector<uint8_t>& server_flight,
                               const tls_certificate_manager& cert_manager){
    s.ver=TLSVersion::V13;s.is_server=true;
    s.transcript_ready=false;
    rand32(s.server_random);
    memcpy(s.client_random,client_hello+11,32);

    // 记录 ClientHello
    tls_transcript_update(s,client_hello,ch_len);

    // 解析 SNI
    uint16_t ext_len_total=0;
    size_t ext_offset=11+32+1+2+1;
    if(ext_offset+2<=ch_len){
        ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);
    if(!cert)return false;

    // 提取 client_pub
    uint8_t client_pub[32];bool found=false;
    size_t eo=ext_offset+2;
    while(eo+4<=ext_offset+2+ext_len_total){
        uint16_t etype=(client_hello[eo]<<8)|client_hello[eo+1];
        uint16_t elen=(client_hello[eo+2]<<8)|client_hello[eo+3];
        if(etype==0x33 && elen>=4 && client_hello[eo+4]==0x00 && client_hello[eo+5]==0x1d && client_hello[eo+6]==0x00 && client_hello[eo+7]==0x20){
            memcpy(client_pub,client_hello+eo+8,32);found=true;break;
        }
        eo+=4+elen;
    }
    if(!found){memcpy(client_pub,client_hello+50,32);}

    // 生成 ServerHello
    uint8_t server_priv[32],server_pub[32],shared_secret[32];
    x25519_generate_keypair(server_pub,server_priv);
    x25519_scalar_mult(shared_secret,server_priv,client_pub);

    server_flight.clear();
    server_flight.push_back((uint8_t)HandshakeType::SERVER_HELLO);
    server_flight.push_back(0);server_flight.push_back(0);server_flight.push_back(0);
    server_flight.push_back(0x03);server_flight.push_back(0x03);
    server_flight.insert(server_flight.end(),s.server_random,s.server_random+32);
    server_flight.push_back(0);
    server_flight.push_back(0x13);server_flight.push_back(0x01);
    server_flight.push_back(0x00);
    server_flight.push_back(0x00);server_flight.push_back(0x2e);
    // supported_versions
    server_flight.push_back(0x00);server_flight.push_back(0x2b);server_flight.push_back(0x00);server_flight.push_back(0x02);server_flight.push_back(0x03);server_flight.push_back(0x04);
    // key_share
    server_flight.push_back(0x00);server_flight.push_back(0x33);server_flight.push_back(0x00);server_flight.push_back(0x24);server_flight.push_back(0x00);server_flight.push_back(0x1d);server_flight.push_back(0x00);server_flight.push_back(0x20);
    server_flight.insert(server_flight.end(),server_pub,server_pub+32);

    size_t sh_len=server_flight.size()-4;
    server_flight[1]=(uint8_t)(sh_len>>16);server_flight[2]=(uint8_t)(sh_len>>8);server_flight[3]=(uint8_t)sh_len;

    // 记录 ServerHello
    tls_transcript_update(s,server_flight.data(),server_flight.size());

    // 派生握手密钥
    tls13_derive_handshake_keys(s,shared_secret);
    s.aes_ctx.init(std::span<const uint8_t,16>(s.server_write_key,16));

    // 构建 EncryptedExtensions
    auto ee=tls13_make_encrypted_extensions();
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

    // 加密所有握手消息
    std::vector<uint8_t> hs_buf;
    hs_buf.insert(hs_buf.end(),ee.begin(),ee.end());
    hs_buf.insert(hs_buf.end(),cert_msg.begin(),cert_msg.end());
    hs_buf.insert(hs_buf.end(),cv.begin(),cv.end());
    hs_buf.insert(hs_buf.end(),sf.begin(),sf.end());

    auto encrypted=tls_encrypt_handshake(s,hs_buf.data(),hs_buf.size());
    server_flight.insert(server_flight.end(),encrypted.begin(),encrypted.end());

    // 派生应用密钥（服务端）
    tls13_derive_application_keys(s);
    s.aes_ctx.init(std::span<const uint8_t,16>(s.server_write_key,16));
    return true;
}

bool tls13_process_client_finished(tls_session& s, const uint8_t* data, size_t len){
    std::vector<uint8_t> hs;
    if(!tls13_decrypt_handshake(s,data,len,hs))return false;
    if(!tls13_verify_finished(s,hs.data(),hs.size(),false))return false;
    tls_transcript_update(s,hs.data(),hs.size());
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  简化版 API（兼容旧接口）
// ═══════════════════════════════════════════════════════════════════════
bool tls13_handshake_client(tls_session& s, std::vector<uint8_t>& client_hello,
                             const uint8_t* server_response, size_t resp_len){
    tls13_make_client_hello(s,client_hello);
    std::vector<uint8_t> cf;
    // 简化版：直接解析 ServerHello 明文
    s.ver=TLSVersion::V13;
    memcpy(s.server_random,server_response+6,32);
    uint8_t server_pub[32];
    memcpy(server_pub,server_response+50,32);
    uint8_t client_priv[32];memcpy(client_priv,s.client_write_key,32);
    uint8_t shared_secret[32];
    x25519_scalar_mult(shared_secret,client_priv,server_pub);
    tls13_derive_keys(s,shared_secret);
    s.aes_ctx.init(std::span<const uint8_t,16>(s.client_write_key,16));
    return true;
}

bool tls13_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                             std::vector<uint8_t>& server_response,
                             const tls_certificate_manager& cert_manager){
    s.ver=TLSVersion::V13;s.is_server=true;rand32(s.server_random);memcpy(s.client_random,client_hello+11,32);
    size_t ext_offset=11+32+1+2+1;
    if(ext_offset+2<=ch_len){
        uint16_t ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);
    (void)cert;

    server_response.clear();
    server_response.push_back((uint8_t)HandshakeType::SERVER_HELLO);
    server_response.push_back(0);server_response.push_back(0);server_response.push_back(0);
    server_response.push_back(0x03);server_response.push_back(0x03);
    server_response.insert(server_response.end(),s.server_random,s.server_random+32);
    server_response.push_back(0);
    server_response.push_back(0x13);server_response.push_back(0x01);
    server_response.push_back(0x00);
    server_response.push_back(0x00);server_response.push_back(0x2b);server_response.push_back(0x00);server_response.push_back(0x02);server_response.push_back(0x03);server_response.push_back(0x04);
    uint8_t server_priv[32],server_pub[32],client_pub[32],shared_secret[32];
    x25519_generate_keypair(server_pub,server_priv);
    memcpy(client_pub,client_hello+50,32);
    x25519_scalar_mult(shared_secret,server_priv,client_pub);
    server_response.push_back(0x00);server_response.push_back(0x33);server_response.push_back(0x00);server_response.push_back(0x22);
    server_response.push_back(0x00);server_response.push_back(0x1d);
    server_response.push_back(0x00);server_response.push_back(0x20);
    server_response.insert(server_response.end(),server_pub,server_pub+32);
    size_t len=server_response.size()-4;
    server_response[1]=(uint8_t)(len>>16);server_response[2]=(uint8_t)(len>>8);server_response[3]=(uint8_t)len;
    tls13_derive_keys(s,shared_secret);
    s.aes_ctx.init(std::span<const uint8_t,16>(s.server_write_key,16));
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.2 PRF (P_SHA256)
// ═══════════════════════════════════════════════════════════════════════
static void tls12_prf(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len, uint8_t* out, size_t out_len){
    size_t label_len=strlen(label);
    std::vector<uint8_t> full_seed(label_len+seed_len);
    memcpy(full_seed.data(),label,label_len);
    memcpy(full_seed.data()+label_len,seed,seed_len);
    uint8_t a[32],tmp[32];
    hmac_sha256(secret,secret_len,full_seed.data(),full_seed.size(),a);
    size_t generated=0;
    while(generated<out_len){
        uint8_t buf[32+full_seed.size()];memcpy(buf,a,32);memcpy(buf+32,full_seed.data(),full_seed.size());
        hmac_sha256(secret,secret_len,buf,32+full_seed.size(),tmp);
        size_t n=(out_len-generated<32)?out_len-generated:32;
        memcpy(out+generated,tmp,n);generated+=n;
        hmac_sha256(secret,secret_len,a,32,a);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.2 密钥派生
// ═══════════════════════════════════════════════════════════════════════
void tls12_derive_keys(tls_session& s, const uint8_t pre_master[48]){
    s.ver=TLSVersion::V12;
    uint8_t seed[64];memcpy(seed,s.client_random,32);memcpy(seed+32,s.server_random,32);
    tls12_prf(pre_master,48,"master secret",seed,64,s.master_secret,48);
    uint8_t key_block[72];
    uint8_t exp_seed[64];memcpy(exp_seed,s.server_random,32);memcpy(exp_seed+32,s.client_random,32);
    tls12_prf(s.master_secret,48,"key expansion",exp_seed,64,key_block,72);
    memcpy(s.client_write_key,key_block,16);
    memcpy(s.server_write_key,key_block+16,16);
    memcpy(s.client_write_iv,key_block+32,4);
    memcpy(s.server_write_iv,key_block+36,4);
    memset(s.client_write_iv+4,0,8);
    memset(s.server_write_iv+4,0,8);
    s.client_seq=0;s.server_seq=0;
    s.aes_ctx.init(std::span<const uint8_t,16>(s.client_write_key,16));
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.2 完整握手 — 客户端
// ═══════════════════════════════════════════════════════════════════════
bool tls12_make_client_hello(tls_session& s, std::vector<uint8_t>& client_hello){
    s.ver=TLSVersion::V12;s.is_server=false;
    s.transcript_ready=false;
    rand32(s.client_random);
    client_hello.clear();
    client_hello.push_back((uint8_t)HandshakeType::CLIENT_HELLO);
    client_hello.push_back(0);client_hello.push_back(0);client_hello.push_back(0);
    client_hello.push_back(0x03);client_hello.push_back(0x03);
    client_hello.insert(client_hello.end(),s.client_random,s.client_random+32);
    client_hello.push_back(0);
    client_hello.push_back(0);client_hello.push_back(2);
    client_hello.push_back(0x00);client_hello.push_back(0x9c);
    client_hello.push_back(0x01);client_hello.push_back(0x00);
    // extensions: SNI
    std::vector<uint8_t> ext;
    if(!s.server_name.empty()){
        ext.push_back(0x00);ext.push_back(0x00);
        uint16_t sni_len=3+s.server_name.size();
        ext.push_back(0x00);ext.push_back((uint8_t)sni_len);
        uint16_t nl_len=1+s.server_name.size();
        ext.push_back(0x00);ext.push_back((uint8_t)nl_len);
        ext.push_back(0x00);
        ext.push_back(0x00);ext.push_back((uint8_t)s.server_name.size());
        for(char c:s.server_name)ext.push_back((uint8_t)c);
    }
    uint16_t ext_total=ext.size();
    client_hello.push_back((uint8_t)(ext_total>>8));client_hello.push_back((uint8_t)ext_total);
    client_hello.insert(client_hello.end(),ext.begin(),ext.end());
    size_t len=client_hello.size()-4;
    client_hello[1]=(uint8_t)(len>>16);client_hello[2]=(uint8_t)(len>>8);client_hello[3]=(uint8_t)len;
    tls_transcript_update(s,client_hello.data(),client_hello.size());
    return true;
}

bool tls12_process_server_flight(tls_session& s, const uint8_t* server_response, size_t resp_len,
                                  const uint8_t* pre_master_secret, size_t pms_len,
                                  std::vector<uint8_t>& client_finished){
    if(resp_len<4 || server_response[0]!=(uint8_t)HandshakeType::SERVER_HELLO)return false;
    size_t sh_len=(server_response[1]<<16)|(server_response[2]<<8)|server_response[3];
    if(4+sh_len>resp_len)return false;
    tls_transcript_update(s,server_response,4+sh_len);
    memcpy(s.server_random,server_response+6,32);
    tls12_derive_keys(s,pre_master_secret);
    // TLS 1.2 Finished: PRF(master_secret, "client finished", MD5+SHA1 hash of handshake)
    tls_transcript_finalize(s);
    uint8_t verify_data[12];
    tls12_prf(s.master_secret,48,"client finished",s.transcript_hash,32,verify_data,12);
    client_finished.clear();
    client_finished.push_back((uint8_t)HandshakeType::FINISHED);
    client_finished.push_back(0);client_finished.push_back(0);client_finished.push_back(12);
    client_finished.insert(client_finished.end(),verify_data,verify_data+12);
    tls_transcript_update(s,client_finished.data(),client_finished.size());
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.2 完整握手 — 服务端
// ═══════════════════════════════════════════════════════════════════════
bool tls12_make_server_flight(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                               std::vector<uint8_t>& server_response,
                               uint8_t pre_master_secret[48],
                               const tls_certificate_manager& cert_manager){
    s.ver=TLSVersion::V12;s.is_server=true;
    s.transcript_ready=false;
    rand32(s.server_random);
    memcpy(s.client_random,client_hello+11,32);
    tls_transcript_update(s,client_hello,ch_len);
    // 解析 SNI
    size_t ext_offset=11+32+1+2+1;
    if(ext_offset+2<=ch_len){
        uint16_t ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);
    (void)cert;

    // ServerHello
    server_response.clear();
    server_response.push_back((uint8_t)HandshakeType::SERVER_HELLO);
    server_response.push_back(0);server_response.push_back(0);server_response.push_back(0);
    server_response.push_back(0x03);server_response.push_back(0x03);
    server_response.insert(server_response.end(),s.server_random,s.server_random+32);
    server_response.push_back(0);
    server_response.push_back(0x00);server_response.push_back(0x9c);
    server_response.push_back(0x00);
    server_response.push_back(0x00);server_response.push_back(0x00);
    size_t sh_len=server_response.size()-4;
    server_response[1]=(uint8_t)(sh_len>>16);server_response[2]=(uint8_t)(sh_len>>8);server_response[3]=(uint8_t)sh_len;
    tls_transcript_update(s,server_response.data(),server_response.size());

    tls12_derive_keys(s,pre_master_secret);

    // Server Finished
    tls_transcript_finalize(s);
    uint8_t verify_data[12];
    tls12_prf(s.master_secret,48,"server finished",s.transcript_hash,32,verify_data,12);
    std::vector<uint8_t> sf;
    sf.push_back((uint8_t)HandshakeType::FINISHED);
    sf.push_back(0);sf.push_back(0);sf.push_back(12);
    sf.insert(sf.end(),verify_data,verify_data+12);
    tls_transcript_update(s,sf.data(),sf.size());
    server_response.insert(server_response.end(),sf.begin(),sf.end());
    return true;
}

bool tls12_process_client_finished(tls_session& s, const uint8_t* data, size_t len){
    if(len<16 || data[0]!=(uint8_t)HandshakeType::FINISHED)return false;
    tls_transcript_update(s,data,len);
    tls_transcript_finalize(s);
    uint8_t expected[12];
    tls12_prf(s.master_secret,48,"client finished",s.transcript_hash,32,expected,12);
    return memcmp(expected,data+4,12)==0;
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.2 简化版 API（兼容旧接口）
// ═══════════════════════════════════════════════════════════════════════
bool tls12_handshake_client(tls_session& s, std::vector<uint8_t>& client_hello,
                             const uint8_t* server_response, size_t resp_len,
                             const uint8_t* pre_master_secret, size_t pms_len){
    s.ver=TLSVersion::V12;rand32(s.client_random);
    client_hello.clear();
    client_hello.push_back((uint8_t)HandshakeType::CLIENT_HELLO);
    client_hello.push_back(0);client_hello.push_back(0);client_hello.push_back(0);
    client_hello.push_back(0x03);client_hello.push_back(0x03);
    client_hello.insert(client_hello.end(),s.client_random,s.client_random+32);
    client_hello.push_back(0);
    client_hello.push_back(0);client_hello.push_back(2);
    client_hello.push_back(0x00);client_hello.push_back(0x9c);
    client_hello.push_back(0x01);client_hello.push_back(0x00);
    client_hello.push_back(0x00);client_hello.push_back(0x00);
    size_t len=client_hello.size()-4;
    client_hello[1]=(uint8_t)(len>>16);client_hello[2]=(uint8_t)(len>>8);client_hello[3]=(uint8_t)len;
    (void)server_response;(void)resp_len;
    memcpy(s.server_random,server_response+6,32);
    tls12_derive_keys(s,pre_master_secret);
    return true;
}

bool tls12_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                             std::vector<uint8_t>& server_response,
                             uint8_t pre_master_secret[48],
                             const tls_certificate_manager& cert_manager){
    s.ver=TLSVersion::V12;rand32(s.server_random);memcpy(s.client_random,client_hello+11,32);
    // 解析 SNI
    size_t ext_offset=11+32+1+2+1;
    if(ext_offset+2<=ch_len){
        uint16_t ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);
    (void)cert;
    server_response.clear();
    server_response.push_back((uint8_t)HandshakeType::SERVER_HELLO);
    server_response.push_back(0);server_response.push_back(0);server_response.push_back(0);
    server_response.push_back(0x03);server_response.push_back(0x03);
    server_response.insert(server_response.end(),s.server_random,s.server_random+32);
    server_response.push_back(0);
    server_response.push_back(0x00);server_response.push_back(0x9c);
    server_response.push_back(0x00);
    server_response.push_back(0x00);server_response.push_back(0x00);
    size_t len=server_response.size()-4;
    server_response[1]=(uint8_t)(len>>16);server_response[2]=(uint8_t)(len>>8);server_response[3]=(uint8_t)len;
    tls12_derive_keys(s,pre_master_secret);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  记录层加密
// ═══════════════════════════════════════════════════════════════════════
std::vector<uint8_t> tls_encrypt(tls_session& s, ContentType ct, const uint8_t* data, size_t len){
    if(s.ver==TLSVersion::V12){
        uint8_t explicit_nonce[8]={};
        uint64_t seq=s.client_seq;
        for(int i=0;i<8;++i)explicit_nonce[7-i]=(uint8_t)(seq>>(i*8));
        ++s.client_seq;
        uint8_t nonce[12];
        memcpy(nonce,s.client_write_iv,4);
        memcpy(nonce+4,explicit_nonce,8);
        std::vector<uint8_t> inner;inner.push_back((uint8_t)ct);
        inner.insert(inner.end(),data,data+len);
        uint8_t aad[13];
        for(int i=0;i<8;++i)aad[7-i]=(uint8_t)(seq>>(i*8));
        aad[8]=(uint8_t)ct;
        aad[9]=0x03;aad[10]=0x03;
        size_t inner_len=inner.size();
        aad[11]=(uint8_t)(inner_len>>8);aad[12]=(uint8_t)inner_len;
        std::vector<uint8_t> ciphertext;
        uint8_t tag[16];
        aes_gcm_encrypt(s.aes_ctx,nonce,12,inner,std::span<const uint8_t>(aad,13),ciphertext,tag,16);
        std::vector<uint8_t> record;
        record.push_back((uint8_t)ct);
        record.push_back(0x03);record.push_back(0x03);
        size_t rlen=8+ciphertext.size()+16;
        record.push_back((uint8_t)(rlen>>8));record.push_back((uint8_t)rlen);
        record.insert(record.end(),explicit_nonce,explicit_nonce+8);
        record.insert(record.end(),ciphertext.begin(),ciphertext.end());
        record.insert(record.end(),tag,tag+16);
        return record;
    }
    std::vector<uint8_t> inner;inner.push_back((uint8_t)ct);
    inner.insert(inner.end(),data,data+len);
    inner.push_back((uint8_t)ct);
    uint8_t nonce[12];memcpy(nonce,s.client_write_iv,12);
    uint64_t seq=s.client_seq;
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(seq>>(56-i*8));
    ++s.client_seq;
    std::vector<uint8_t> ciphertext;
    uint8_t tag[16];
    aes_gcm_encrypt(s.aes_ctx,nonce,12,inner,std::span<const uint8_t>(),ciphertext,tag,16);
    std::vector<uint8_t> record;
    record.push_back(0x17);
    record.push_back(0x03);record.push_back(0x03);
    size_t rlen=ciphertext.size()+16;
    record.push_back((uint8_t)(rlen>>8));record.push_back((uint8_t)rlen);
    record.insert(record.end(),ciphertext.begin(),ciphertext.end());
    record.insert(record.end(),tag,tag+16);
    return record;
}

bool tls_decrypt(tls_session& s, const uint8_t* record, size_t record_len, ContentType& ct, std::vector<uint8_t>& out){
    if(record_len<5)return false;
    if(s.ver==TLSVersion::V12){
        size_t rlen=(record[3]<<8)|record[4];
        if(5+rlen!=record_len||rlen<24)return false;
        const uint8_t* explicit_nonce=record+5;
        const uint8_t* ciphertext=record+13;
        size_t ct_len=rlen-24;
        const uint8_t* tag=record+13+ct_len;
        uint8_t nonce[12];
        memcpy(nonce,s.server_write_iv,4);
        memcpy(nonce+4,explicit_nonce,8);
        uint8_t aad[13];
        uint64_t seq=s.server_seq;
        for(int i=0;i<8;++i)aad[7-i]=(uint8_t)(seq>>(i*8));
        aad[8]=record[0];
        aad[9]=0x03;aad[10]=0x03;
        aad[11]=(uint8_t)(ct_len>>8);aad[12]=(uint8_t)ct_len;
        ++s.server_seq;
        std::vector<uint8_t> inner;
        if(!aes_gcm_decrypt(s.aes_ctx,nonce,12,std::span<const uint8_t>(ciphertext,ct_len),std::span<const uint8_t>(aad,13),tag,16,inner))
            return false;
        if(inner.empty())return false;
        ct=(ContentType)inner[0];
        out.assign(inner.begin()+1,inner.end());
        return true;
    }
    size_t rlen=(record[3]<<8)|record[4];
    if(5+rlen!=record_len||rlen<16)return false;
    const uint8_t* ciphertext=record+5;
    size_t ct_len=rlen-16;
    const uint8_t* tag=record+5+ct_len;
    uint8_t nonce[12];memcpy(nonce,s.server_write_iv,12);
    uint64_t seq=s.server_seq;
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(seq>>(56-i*8));
    ++s.server_seq;
    std::vector<uint8_t> inner;
    if(!aes_gcm_decrypt(s.aes_ctx,nonce,12,std::span<const uint8_t>(ciphertext,ct_len),std::span<const uint8_t>(),tag,16,inner))
        return false;
    if(inner.empty())return false;
    ct=(ContentType)inner[0];
    out.assign(inner.begin()+1,inner.end()-1);
    return true;
}

}