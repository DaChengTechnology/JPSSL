#include "tls.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include <cstring>
#include <random>
#include <algorithm>
namespace jpssl::tls {

static const uint8_t RSA_SHA256_DIGEST_INFO[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

static void rand32(uint8_t* buf){static std::mt19937_64 g(std::random_device{}());for(int i=0;i<4;++i){uint64_t v=g();memcpy(buf+i*8,&v,8);}}

static CipherSuite select_cipher_suite(uint16_t id){
    switch(id){
        case 0x1301: return CipherSuite::TLS_AES_128_GCM_SHA256;
        case 0x1302: return CipherSuite::TLS_AES_256_GCM_SHA384;
        case 0x1303: return CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
        case 0x1304: return CipherSuite::TLS_AES_128_CCM_SHA256;
        default: return CipherSuite::TLS_AES_128_GCM_SHA256;
    }
}

static bool cipher_needs_aes_ctx(CipherSuite cs){
    switch(cs){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384:
        case CipherSuite::TLS_AES_128_CCM_SHA256:
            return true;
        default: return false;
    }
}

static size_t aes_key_len(CipherSuite cs){
    switch(cs){
        case CipherSuite::TLS_AES_256_GCM_SHA384: return 32;
        default: return 16;
    }
}

static void aes_ctx_init(aes_context& ctx, const uint8_t* key, size_t key_len){
    if(key_len==32) ctx.init(std::span<const uint8_t,32>(key,32));
    else ctx.init(std::span<const uint8_t,16>(key,16));
}

static size_t client_hello_ext_offset(const uint8_t* ch, size_t ch_len){
    if(ch_len<45)return ch_len;
    size_t off=4+2+32;
    if(off>=ch_len)return ch_len;
    uint8_t sid_len=ch[off++];off+=sid_len;
    if(off+2>ch_len)return ch_len;
    uint16_t cs_len=(ch[off]<<8)|ch[off+1];off+=2;off+=cs_len;
    if(off>=ch_len)return ch_len;
    uint8_t cm_len=ch[off++];off+=cm_len;
    return off;
}

// ═══════════════════════════════════════════════════════════════════════
//  transcript 辅助
// ═══════════════════════════════════════════════════════════════════════
void tls_transcript_update(tls_session& s, const uint8_t* data, size_t len){
    if(!s.transcript_ready){
        if(tls_use_sha384(s.cipher_suite)) sha384_init(&s.transcript_ctx.sha512);
        else sha256_init(&s.transcript_ctx.sha256);
        s.transcript_ready=true;
    }
    if(tls_use_sha384(s.cipher_suite)) sha512_update(&s.transcript_ctx.sha512,data,len);
    else sha256_update(&s.transcript_ctx.sha256,data,len);
}
void tls_transcript_finalize(tls_session& s){
    if(s.transcript_ready){
        if(tls_use_sha384(s.cipher_suite)){
            sha512_ctx copy=s.transcript_ctx.sha512;
            sha512_final(&copy,s.transcript_hash);
        }else{
            sha256_ctx copy=s.transcript_ctx.sha256;
            sha256_final(&copy,s.transcript_hash);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  证书签名/验证
// ═══════════════════════════════════════════════════════════════════════
bool tls_certificate::sign(const uint8_t* data, size_t data_len, uint8_t* sig, size_t& sig_len) const {
    switch(sig_alg){
        case SignatureAlgorithm::ED25519:
            sig_len=64;ed25519_sign(priv.ed25519,data,data_len,sig);return true;
        case SignatureAlgorithm::ED448:
            sig_len=114;ed448_sign(priv.ed448,data,data_len,sig);return true;
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256:
            sig_len=64;ecdsa_p256_sign(priv.ecdsa_p256,data,data_len,sig);return true;
        case SignatureAlgorithm::RSA_PKCS1_SHA256: {
            sig_len=256;
            uint8_t hash[32];
            sha256_ctx ctx; sha256_init(&ctx);
            sha256_update(&ctx, data, data_len);
            sha256_final(&ctx, hash);

            size_t di_len = sizeof(RSA_SHA256_DIGEST_INFO);
            size_t pad_len = 256 - 3 - di_len - 32;
            uint8_t padded[256];
            padded[0] = 0x00; padded[1] = 0x01;
            memset(padded + 2, 0xFF, pad_len);
            padded[2 + pad_len] = 0x00;
            memcpy(padded + 2 + pad_len + 1, RSA_SHA256_DIGEST_INFO, di_len);
            memcpy(padded + 2 + pad_len + 1 + di_len, hash, 32);

            rsa_bignum m = rsa_bignum::from_bytes(padded, 256);
            rsa_bignum s;
            bn_modpow(s, m, priv.rsa.d, priv.rsa.n);
            s.to_bytes(sig);
            return true;
        }
        default:return false;
    }
}
bool tls_certificate::verify(const uint8_t* data, size_t data_len, const uint8_t* sig, size_t sig_len) const {
    switch(sig_alg){
        case SignatureAlgorithm::ED25519:
            if(sig_len!=64)return false;
            return ed25519_verify(pub.ed25519,data,data_len,sig);
        case SignatureAlgorithm::ED448:
            if(sig_len!=114)return false;
            return ed448_verify(pub.ed448,data,data_len,sig);
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256:
            if(sig_len!=64)return false;
            return ecdsa_p256_verify(pub.ecdsa_p256,data,data_len,sig);
        case SignatureAlgorithm::RSA_PKCS1_SHA256: {
            if(sig_len != 256) return false;
            uint8_t hash[32];
            sha256_ctx ctx; sha256_init(&ctx);
            sha256_update(&ctx, data, data_len);
            sha256_final(&ctx, hash);

            rsa_bignum s = rsa_bignum::from_bytes(sig, 256);
            rsa_bignum m;
            bn_modpow(m, s, pub.rsa.e, pub.rsa.n);
            uint8_t padded[256];
            m.to_bytes(padded);

            if(padded[0] != 0x00 || padded[1] != 0x01) return false;
            size_t pos = 2;
            while(pos < 256 && padded[pos] == 0xFF) ++pos;
            if(pos >= 256 || padded[pos] != 0x00) return false;
            ++pos;
            size_t di_len = sizeof(RSA_SHA256_DIGEST_INFO);
            if(pos + di_len + 32 > 256) return false;
            if(memcmp(padded + pos, RSA_SHA256_DIGEST_INFO, di_len) != 0) return false;
            if(memcmp(padded + pos + di_len, hash, 32) != 0) return false;
            return true;
        }
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
static void tls13_derive_handshake_keys(tls_session& s, const uint8_t* shared_secret, size_t shared_len){
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    uint8_t zero[48]={},early_secret[48],empty_hash[48];
    if(use384){
        sha512_ctx ctx;sha384_init(&ctx);sha512_final(&ctx,empty_hash);
        hkdf_extract_sha384(zero,48,zero,48,early_secret);
        hkdf_extract_sha384(early_secret,48,shared_secret,shared_len,s.handshake_secret);
    }else{
        sha256_ctx ctx;sha256_init(&ctx);sha256_final(&ctx,empty_hash);
        hkdf_extract(zero,32,zero,32,early_secret);
        hkdf_extract(early_secret,32,shared_secret,shared_len,s.handshake_secret);
    }

    tls_transcript_finalize(s);
    uint8_t ch_ts[48],sh_ts[48];
    if(use384){
        hkdf_expand_label_sha384(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,ch_ts,hl);
        hkdf_expand_label_sha384(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,sh_ts,hl);
    }else{
        hkdf_expand_label(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,ch_ts,hl);
        hkdf_expand_label(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,sh_ts,hl);
    }

    memcpy(s.client_write_key,ch_ts,hl);memcpy(s.server_write_key,sh_ts,hl);
    if(use384){
        hkdf_expand_label_sha384(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label_sha384(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }else{
        hkdf_expand_label(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }
    s.client_seq=0;s.server_seq=0;
}

static void tls13_derive_application_keys(tls_session& s){
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    uint8_t zero[48]={};
    if(use384) hkdf_extract_sha384(s.handshake_secret,48,zero,48,s.master_secret);
    else hkdf_extract(s.handshake_secret,32,zero,32,s.master_secret);
    tls_transcript_finalize(s);
    if(use384){
        hkdf_expand_label_sha384(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_key,hl);
        hkdf_expand_label_sha384(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_key,hl);
        hkdf_expand_label_sha384(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label_sha384(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }else{
        hkdf_expand_label(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_key,hl);
        hkdf_expand_label(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_key,hl);
        hkdf_expand_label(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }
    s.client_seq=0;s.server_seq=0;
}

static void tls13_derive_keys(tls_session& s, const uint8_t* shared_secret, size_t shared_len){
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    uint8_t early_secret[48],empty_hash[48];
    uint8_t zero[48]={};
    if(use384){
        sha512_ctx ctx;sha384_init(&ctx);sha512_final(&ctx,empty_hash);
        hkdf_extract_sha384(zero,48,zero,48,early_secret);
        hkdf_extract_sha384(early_secret,48,shared_secret,shared_len,s.handshake_secret);
    }else{
        sha256_ctx ctx;sha256_init(&ctx);sha256_final(&ctx,empty_hash);
        hkdf_extract(zero,32,zero,32,early_secret);
        hkdf_extract(early_secret,32,shared_secret,shared_len,s.handshake_secret);
    }
    tls_transcript_finalize(s);
    if(use384){
        hkdf_expand_label_sha384(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,s.client_write_key,hl);
        hkdf_expand_label_sha384(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,s.server_write_key,hl);
        hkdf_expand_label_sha384(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label_sha384(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,s.server_write_iv,12);
        hkdf_extract_sha384(s.handshake_secret,48,zero,48,s.master_secret);
    }else{
        hkdf_expand_label(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,s.client_write_key,hl);
        hkdf_expand_label(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,s.server_write_key,hl);
        hkdf_expand_label(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,s.server_write_iv,12);
        hkdf_extract(s.handshake_secret,32,zero,32,s.master_secret);
    }
    tls_transcript_finalize(s);
    if(use384){
        hkdf_expand_label_sha384(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_key,hl);
        hkdf_expand_label_sha384(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_key,hl);
        hkdf_expand_label_sha384(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label_sha384(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }else{
        hkdf_expand_label(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_key,hl);
        hkdf_expand_label(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_key,hl);
        hkdf_expand_label(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }
    s.client_seq=0;s.server_seq=0;
}

// ═══════════════════════════════════════════════════════════════════════
//  构建 Finished 消息
// ═══════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> tls13_make_finished(tls_session& s, bool for_server){
    (void)for_server;
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    uint8_t finished_key[48];
    if(use384) hkdf_expand_label_sha384(s.handshake_secret,"finished",nullptr,0,finished_key,hl);
    else hkdf_expand_label(s.handshake_secret,"finished",nullptr,0,finished_key,hl);

    tls_transcript_finalize(s);
    uint8_t verify_data[48];
    if(use384) hmac_sha384(finished_key,hl,s.transcript_hash,hl,verify_data);
    else hmac_sha256(finished_key,hl,s.transcript_hash,hl,verify_data);

    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::FINISHED);
    msg.push_back(0);msg.push_back(0);msg.push_back((uint8_t)hl);
    msg.insert(msg.end(),verify_data,verify_data+hl);
    return msg;
}

static bool tls13_verify_finished(tls_session& s, const uint8_t* hs_msg, size_t hs_len, bool for_server){
    (void)for_server;
    if(hs_len<4 || hs_msg[0]!=(uint8_t)HandshakeType::FINISHED)return false;
    size_t hl=tls_hash_len(s.cipher_suite);
    size_t vd_len=(hs_msg[1]<<16)|(hs_msg[2]<<8)|hs_msg[3];
    if(vd_len!=hl || hs_len!=4+vd_len)return false;

    bool use384=tls_use_sha384(s.cipher_suite);
    uint8_t finished_key[48];
    if(use384) hkdf_expand_label_sha384(s.handshake_secret,"finished",nullptr,0,finished_key,hl);
    else hkdf_expand_label(s.handshake_secret,"finished",nullptr,0,finished_key,hl);

    tls_transcript_finalize(s);
    uint8_t expected[48];
    if(use384) hmac_sha384(finished_key,hl,s.transcript_hash,hl,expected);
    else hmac_sha256(finished_key,hl,s.transcript_hash,hl,expected);

    return memcmp(expected,hs_msg+4,hl)==0;
}

// ═══════════════════════════════════════════════════════════════════════
//  构建 Certificate + CertificateVerify 消息
// ═══════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> tls13_make_certificate(const tls_certificate& cert){
    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::CERTIFICATE);
    // TLS 1.3 Certificate: body = context_len(1) + context(0) + list_len(3) + [cert_len(3)+cert+ext_len(2)]
    size_t cert_entry_len=3+cert.cert_data.size()+2;
    size_t body_len=1+3+cert_entry_len;
    msg.push_back((uint8_t)(body_len>>16));msg.push_back((uint8_t)(body_len>>8));msg.push_back((uint8_t)body_len);
    msg.push_back(0); // certificate_request_context
    // certificate_list length
    msg.push_back((uint8_t)(cert_entry_len>>16));msg.push_back((uint8_t)(cert_entry_len>>8));msg.push_back((uint8_t)cert_entry_len);
    msg.push_back((uint8_t)(cert.cert_data.size()>>16));msg.push_back((uint8_t)(cert.cert_data.size()>>8));msg.push_back((uint8_t)cert.cert_data.size());
    msg.insert(msg.end(),cert.cert_data.begin(),cert.cert_data.end());
    // extensions: 0 length
    msg.push_back(0);msg.push_back(0);
    return msg;
}

static std::vector<uint8_t> tls13_make_cert_verify(const tls_certificate& cert, tls_session& s){
    tls_transcript_finalize(s);
    size_t hl=tls_hash_len(s.cipher_suite);
    uint8_t sig[128];size_t sig_len=0;
    if(!cert.sign(s.transcript_hash,hl,sig,sig_len))return {};

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
    size_t hl=tls_hash_len(s.cipher_suite);
    tls_transcript_finalize(s);
    return cert.verify(s.transcript_hash,hl,hs_msg+8,sig_len);
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

    aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
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

    aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
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
    client_hello.push_back(0);client_hello.push_back(4);
    client_hello.push_back(0x13);client_hello.push_back(0x01);
    client_hello.push_back(0x13);client_hello.push_back(0x02);
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
    // supported_groups: 根据会话配置提供 X25519 和/或 X448
    {
        std::vector<uint16_t> groups;
        // 总是包含 X25519，如果会话要求 X448 则也列出 X448
        if (s.ks_group == NamedGroup::X448) {
            groups.push_back((uint16_t)NamedGroup::X448);
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
    // signature_algorithms: 包含 Ed448 (0x0808) 如果使用 Ed448 证书
    {
        // 默认提供 ed25519, ecdsa
        ext.push_back(0x00);ext.push_back(0x0d);
        // 总是提供 ed25519 和 ecdsa
        ext.push_back(0x00);ext.push_back(0x08); // ext data length
        ext.push_back(0x00);ext.push_back(0x06); // sig alg list length
        ext.push_back(0x08);ext.push_back(0x07); // ed25519
        ext.push_back(0x04);ext.push_back(0x03); // ecdsa
        ext.push_back(0x08);ext.push_back(0x08); // ed448
    }
    // key_share: 根据 ks_group 生成对应密钥对
    if (s.ks_group == NamedGroup::X448) {
        // X448
        uint8_t client_priv[56], client_pub[56];
        x448_generate_keypair(client_pub, client_priv);
        memcpy(s.ks_priv, client_priv, 56);
        memcpy(s.ks_pub, client_pub, 56);
        uint16_t ks_entry_len = 4 + 56; // group(2) + key_len(2) + key(56)
        ext.push_back(0x00);ext.push_back(0x33); // key_share
        ext.push_back((uint8_t)(ks_entry_len>>8));ext.push_back((uint8_t)ks_entry_len);
        ext.push_back(0x00);ext.push_back(0x1e); // X448
        ext.push_back(0x00);ext.push_back(0x38); // 56
        ext.insert(ext.end(), client_pub, client_pub + 56);
        // 暂存私钥到 client_write_key（仅前 32 字节不够，改用 ks_priv）
        // 注意：后续 derive_keys 时使用 ks_priv
    } else {
        // X25519 (默认)
        uint8_t client_priv[32],client_pub[32];
        x25519_generate_keypair(client_pub,client_priv);
        memcpy(s.ks_priv, client_priv, 32);
        memcpy(s.ks_pub, client_pub, 32);
        ext.push_back(0x00);ext.push_back(0x33);ext.push_back(0x00);ext.push_back(0x24);ext.push_back(0x00);ext.push_back(0x1d);ext.push_back(0x00);ext.push_back(0x20);
        ext.insert(ext.end(),client_pub,client_pub+32);
    }

    uint16_t ext_len_total=ext.size();
    client_hello.push_back((uint8_t)(ext_len_total>>8));client_hello.push_back((uint8_t)ext_len_total);
    client_hello.insert(client_hello.end(),ext.begin(),ext.end());

    size_t len=client_hello.size()-4;
    client_hello[1]=(uint8_t)(len>>16);client_hello[2]=(uint8_t)(len>>8);client_hello[3]=(uint8_t)len;

    tls_transcript_update(s,client_hello.data(),client_hello.size());
    // 私钥已暂存到 s.ks_priv（支持 X25519 和 X448）
    // 兼容旧 API：将 X25519 私钥复制到 client_write_key 前 32 字节
    if (s.ks_group == NamedGroup::X25519) {
        memcpy(s.client_write_key, s.ks_priv, 32);
    }
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

    // 提取 server_pub 从 key_share（支持 X25519 和 X448）
    size_t ext_start=sh_start+4+2+32+1+2+1;
    uint16_t ext_total=(data[ext_start]<<8)|data[ext_start+1];
    size_t ext_off=ext_start+2;
    uint8_t server_pub_x25519[32];
    uint8_t server_pub_x448[56];
    bool found_ks_x25519=false, found_ks_x448=false;
    while(ext_off+4<=ext_start+2+ext_total){
        uint16_t etype=(data[ext_off]<<8)|data[ext_off+1];
        uint16_t elen=(data[ext_off+2]<<8)|data[ext_off+3];
        if(etype==0x33 && elen>=4){
            uint16_t group=(data[ext_off+4]<<8)|data[ext_off+5];
            uint16_t key_len=(data[ext_off+6]<<8)|data[ext_off+7];
            if(group==(uint16_t)NamedGroup::X25519 && key_len==32 && elen>=4+32){
                memcpy(server_pub_x25519,data+ext_off+8,32);found_ks_x25519=true;
            } else if(group==(uint16_t)NamedGroup::X448 && key_len==56 && elen>=4+56){
                memcpy(server_pub_x448,data+ext_off+8,56);found_ks_x448=true;
            }
        }
        ext_off+=4+elen;
    }
    // 默认回退到偏移 50（旧 API 兼容）：X25519 情况下
    if(!found_ks_x25519 && !found_ks_x448){
        memcpy(server_pub_x25519,data+sh_start+50,32);
        found_ks_x25519=true;
    }

    // 计算共享密钥（根据会话配置或找到的组选择算法）
    uint8_t shared_secret[56];  // X448 输出 56 字节；但 TLS 1.3 HKDF 使用 32 字节
    size_t shared_len = 32;
    if (found_ks_x448 && s.ks_group == NamedGroup::X448) {
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
        } else {
            memcpy(client_priv, s.ks_priv, 32);
        }
        x25519_scalar_mult(shared_secret, client_priv, server_pub_x25519);
        shared_len = 32;
        s.ks_group = NamedGroup::X25519;
    }

    tls13_derive_handshake_keys(s, shared_secret, shared_len);
    aes_ctx_init(s.aes_ctx, s.is_server?s.server_write_key:s.client_write_key, aes_key_len(s.cipher_suite));

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

    // 生成 Client Finished
    client_finished=tls13_make_finished(s,false);

    // 加密 Client Finished（使用握手密钥）
    auto encrypted=tls_encrypt_handshake(s,client_finished.data(),client_finished.size());
    client_finished=encrypted;

    // 派生应用密钥（在 transcript 更新前，与简化版保持一致）
    tls13_derive_application_keys(s);

    tls_transcript_update(s,client_finished.data(),client_finished.size());
    aes_ctx_init(s.aes_ctx, s.is_server?s.server_write_key:s.client_write_key, aes_key_len(s.cipher_suite));
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
    memcpy(s.client_random,client_hello+6,32);

    // 记录 ClientHello
    tls_transcript_update(s,client_hello,ch_len);

    // 解析 SNI
    uint16_t ext_len_total=0;
    size_t ext_offset=client_hello_ext_offset(client_hello,ch_len);
    if(ext_offset+2<=ch_len){
        ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);
    if(!cert)return false;

    // 提取 client_pub（支持 X25519 和 X448）和 supported_groups
    uint8_t client_pub_x25519[32]; bool found_x25519=false;
    uint8_t client_pub_x448[56]; bool found_x448=false;
    bool client_supports_x448=false;  // 客户端 supported_groups 列表中是否包含 X448
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
                goff+=2;
            }
        }
        else if(etype==0x33 && elen>=4){
            uint16_t group=(client_hello[eo+4]<<8)|client_hello[eo+5];
            uint16_t key_len=(client_hello[eo+6]<<8)|client_hello[eo+7];
            if(group==(uint16_t)NamedGroup::X25519 && key_len==32 && elen>=4+32){
                memcpy(client_pub_x25519,client_hello+eo+8,32);found_x25519=true;
            } else if(group==(uint16_t)NamedGroup::X448 && key_len==56 && elen>=4+56){
                memcpy(client_pub_x448,client_hello+eo+8,56);found_x448=true;
            }
        }
        eo+=4+elen;
    }
    if(!found_x25519 && !found_x448){memcpy(client_pub_x25519,client_hello+50,32);found_x25519=true;}

    // 选择密钥交换组：优先 X448（如果客户端提供了 X448 key_share）
    bool use_x448 = found_x448 && client_supports_x448;
    uint8_t shared_secret[56];
    size_t shared_len;

    server_flight.clear();
    server_flight.push_back((uint8_t)HandshakeType::SERVER_HELLO);
    server_flight.push_back(0);server_flight.push_back(0);server_flight.push_back(0);
    server_flight.push_back(0x03);server_flight.push_back(0x03);
    server_flight.insert(server_flight.end(),s.server_random,s.server_random+32);
    server_flight.push_back(0);
    server_flight.push_back(0x13);server_flight.push_back(0x01);
    server_flight.push_back(0x00);

    if (use_x448) {
        // X448 密钥交换
        uint8_t server_priv[56], server_pub[56];
        x448_generate_keypair(server_pub, server_priv);
        x448_scalar_mult(shared_secret, server_priv, client_pub_x448);
        shared_len = 56;
        s.ks_group = NamedGroup::X448;

        // ext_len = 6 (supported_versions) + 62 (key_share: 4+2+2+56)
        uint16_t ext_total = 6 + 62;
        server_flight.push_back((uint8_t)(ext_total>>8));server_flight.push_back((uint8_t)ext_total);
        // supported_versions
        server_flight.push_back(0x00);server_flight.push_back(0x2b);server_flight.push_back(0x00);server_flight.push_back(0x02);server_flight.push_back(0x03);server_flight.push_back(0x04);
        // key_share X448
        server_flight.push_back(0x00);server_flight.push_back(0x33);
        server_flight.push_back(0x00);server_flight.push_back(0x3e); // 62 = 4 + 2 + 2 + 56
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
    aes_ctx_init(s.aes_ctx, s.server_write_key, aes_key_len(s.cipher_suite));

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

    // 注意：应用密钥延迟到 tls13_process_client_finished 成功后派生
    return true;
}

bool tls13_process_client_finished(tls_session& s, const uint8_t* data, size_t len){
    std::vector<uint8_t> hs;
    if(!tls13_decrypt_handshake(s,data,len,hs))return false;
    if(!tls13_verify_finished(s,hs.data(),hs.size(),false))return false;

    // 握手完成，派生应用密钥（在 transcript 更新前）
    tls13_derive_application_keys(s);
    tls_transcript_update(s,hs.data(),hs.size());
    aes_ctx_init(s.aes_ctx, s.server_write_key, aes_key_len(s.cipher_suite));
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  简化版 API（兼容旧接口）
// ═══════════════════════════════════════════════════════════════════════
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
    aes_ctx_init(s.aes_ctx, s.client_write_key, aes_key_len(s.cipher_suite));
    return true;
}

bool tls13_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                             std::vector<uint8_t>& server_response,
                             const tls_certificate_manager& cert_manager){
    s.ver=TLSVersion::V13;s.is_server=true;rand32(s.server_random);memcpy(s.client_random,client_hello+6,32);
    s.transcript_ready=false;
    tls_transcript_update(s,client_hello,ch_len);
    size_t ext_offset=client_hello_ext_offset(client_hello,ch_len);
    uint16_t ext_len_total=0;
    if(ext_offset+2<=ch_len){
        ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
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
    // Detect key share group from ClientHello
    bool use_x448=false, found_ks=false;
    size_t eo=ext_offset+2;
    while(eo+4<=ext_offset+2+ext_len_total){
        uint16_t et=(client_hello[eo]<<8)|client_hello[eo+1];
        uint16_t el=(client_hello[eo+2]<<8)|client_hello[eo+3];
        if(et==0x33 && el>=4){
            uint16_t g=(client_hello[eo+4]<<8)|client_hello[eo+5];
            if(g==(uint16_t)NamedGroup::X448 && !found_ks){use_x448=true;found_ks=true;}
            else if(g==(uint16_t)NamedGroup::X25519 && !found_ks){found_ks=true;}
        }
        eo+=4+el;
    }
    if(use_x448){
        // X448 key exchange
        uint8_t server_priv[56],server_pub[56],client_pub[56],shared_secret[56];
        x448_generate_keypair(server_pub,server_priv);
        // extract client_pub
        {bool _f=false;size_t eo2=ext_offset+2;
        while(eo2+4<=ext_offset+2+ext_len_total){
            uint16_t et=(client_hello[eo2]<<8)|client_hello[eo2+1];
            uint16_t el=(client_hello[eo2+2]<<8)|client_hello[eo2+3];
            if(et==0x33&&el>=4+56&&client_hello[eo2+4]==0x00&&client_hello[eo2+5]==0x1e&&client_hello[eo2+6]==0x00&&client_hello[eo2+7]==0x38)
                {memcpy(client_pub,client_hello+eo2+8,56);_f=true;break;}
            eo2+=4+el;
        }if(!_f)memcpy(client_pub,client_hello+50,56);}
        x448_scalar_mult(shared_secret,server_priv,client_pub);
        uint16_t ext_total=6+62; // supported_versions + key_share
        server_response.push_back((uint8_t)(ext_total>>8));server_response.push_back((uint8_t)ext_total);
        server_response.push_back(0x00);server_response.push_back(0x2b);server_response.push_back(0x00);server_response.push_back(0x02);server_response.push_back(0x03);server_response.push_back(0x04);
        server_response.push_back(0x00);server_response.push_back(0x33);
        server_response.push_back(0x00);server_response.push_back(0x3e); // 62
        server_response.push_back(0x00);server_response.push_back(0x1e); // X448
        server_response.push_back(0x00);server_response.push_back(0x38); // 56
        server_response.insert(server_response.end(),server_pub,server_pub+56);
        size_t len=server_response.size()-4;
        server_response[1]=(uint8_t)(len>>16);server_response[2]=(uint8_t)(len>>8);server_response[3]=(uint8_t)len;
        tls_transcript_update(s,server_response.data(),server_response.size());
        tls13_derive_keys(s,shared_secret,56);
        aes_ctx_init(s.aes_ctx, s.server_write_key, aes_key_len(s.cipher_suite));
    } else {
        // X25519 (default)
        uint8_t server_priv[32],server_pub[32],client_pub[32],shared_secret[32];
        x25519_generate_keypair(server_pub,server_priv);
        {bool _f=false;size_t eo2=ext_offset+2;
        while(eo2+4<=ext_offset+2+ext_len_total){
            uint16_t et=(client_hello[eo2]<<8)|client_hello[eo2+1];
            uint16_t el=(client_hello[eo2+2]<<8)|client_hello[eo2+3];
            if(et==0x33&&el>=4&&client_hello[eo2+4]==0x00&&client_hello[eo2+5]==0x1d&&client_hello[eo2+6]==0x00&&client_hello[eo2+7]==0x20)
                {memcpy(client_pub,client_hello+eo2+8,32);_f=true;break;}
            eo2+=4+el;
        }if(!_f)memcpy(client_pub,client_hello+50,32);}
        x25519_scalar_mult(shared_secret,server_priv,client_pub);
        server_response.push_back(0x00);server_response.push_back(0x2e);
        server_response.push_back(0x00);server_response.push_back(0x2b);server_response.push_back(0x00);server_response.push_back(0x02);server_response.push_back(0x03);server_response.push_back(0x04);
        server_response.push_back(0x00);server_response.push_back(0x33);server_response.push_back(0x00);server_response.push_back(0x22);
        server_response.push_back(0x00);server_response.push_back(0x1d);
        server_response.push_back(0x00);server_response.push_back(0x20);
        server_response.insert(server_response.end(),server_pub,server_pub+32);
        size_t len=server_response.size()-4;
        server_response[1]=(uint8_t)(len>>16);server_response[2]=(uint8_t)(len>>8);server_response[3]=(uint8_t)len;
        tls_transcript_update(s,server_response.data(),server_response.size());
        tls13_derive_keys(s,shared_secret,32);
        aes_ctx_init(s.aes_ctx, s.server_write_key, aes_key_len(s.cipher_suite));
    }
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
    aes_ctx_init(s.aes_ctx, s.client_write_key, aes_key_len(s.cipher_suite));
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
        uint16_t sni_len=5+s.server_name.size();
        ext.push_back(0x00);ext.push_back((uint8_t)sni_len);
        uint16_t nl_len=3+s.server_name.size();
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
                               const uint8_t* encrypted_pms, size_t epms_len,
                               uint8_t pre_master_secret[48],
                               const tls_certificate_manager& cert_manager){
    s.ver=TLSVersion::V12;s.is_server=true;
    s.transcript_ready=false;
    rand32(s.server_random);
    memcpy(s.client_random,client_hello+6,32);
    tls_transcript_update(s,client_hello,ch_len);
    // 解析 SNI
    size_t ext_offset=client_hello_ext_offset(client_hello,ch_len);
    if(ext_offset+2<=ch_len){
        uint16_t ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);

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
//    tls_transcript_update(s,sf.data(),sf.size());
    server_response.insert(server_response.end(),sf.begin(),sf.end());
    return true;
}

bool tls12_process_client_finished(tls_session& s, const uint8_t* data, size_t len){
    if(len<16 || data[0]!=(uint8_t)HandshakeType::FINISHED)return false;
//    tls_transcript_update(s,data,len);
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
                             const uint8_t* encrypted_pms, size_t epms_len,
                             uint8_t pre_master_secret[48],
                             const tls_certificate_manager& cert_manager){
    s.ver=TLSVersion::V12;rand32(s.server_random);memcpy(s.client_random,client_hello+6,32);
    // 解析 SNI
    size_t ext_offset=client_hello_ext_offset(client_hello,ch_len);
    if(ext_offset+2<=ch_len){
        uint16_t ext_len_total=(client_hello[ext_offset]<<8)|client_hello[ext_offset+1];
        if(ext_offset+2+ext_len_total<=ch_len)
            s.server_name=tls_parse_server_name(client_hello+ext_offset+2,ext_len_total);
    }
    const tls_certificate* cert=cert_manager.get_certificate(s.server_name);

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
    bool is_svr=s.is_server;
    if(s.ver==TLSVersion::V12){
        uint8_t explicit_nonce[8]={};
        uint64_t seq=is_svr?s.server_seq:s.client_seq;
        for(int i=0;i<8;++i)explicit_nonce[7-i]=(uint8_t)(seq>>(i*8));
        if(is_svr)++s.server_seq;else ++s.client_seq;
        uint8_t nonce[12];
        const uint8_t* write_iv=is_svr?s.server_write_iv:s.client_write_iv;
        const uint8_t* write_key=is_svr?s.server_write_key:s.client_write_key;
        memcpy(nonce,write_iv,4);
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
        aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
        aes_gcm_encrypt(ctx,nonce,12,inner,std::span<const uint8_t>(aad,13),ciphertext,tag,16);
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
    const uint8_t* write_iv=is_svr?s.server_write_iv:s.client_write_iv;
    const uint8_t* write_key=is_svr?s.server_write_key:s.client_write_key;
    uint8_t nonce[12];memcpy(nonce,write_iv,12);
    uint64_t seq=is_svr?s.server_seq:s.client_seq;
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(seq>>(56-i*8));
    if(is_svr)++s.server_seq;else ++s.client_seq;
    std::vector<uint8_t> ciphertext;
    uint8_t tag[16];
    aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
    aes_gcm_encrypt(ctx,nonce,12,inner,std::span<const uint8_t>(),ciphertext,tag,16);
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
    bool is_svr=s.is_server;
    if(record_len<5)return false;
    if(s.ver==TLSVersion::V12){
        size_t rlen=(record[3]<<8)|record[4];
        if(5+rlen!=record_len||rlen<24)return false;
        const uint8_t* explicit_nonce=record+5;
        const uint8_t* ciphertext=record+13;
        size_t ct_len=rlen-24;
        const uint8_t* tag=record+13+ct_len;
        const uint8_t* read_iv=is_svr?s.client_write_iv:s.server_write_iv;
        const uint8_t* read_key=is_svr?s.client_write_key:s.server_write_key;
        uint8_t nonce[12];
        memcpy(nonce,read_iv,4);
        memcpy(nonce+4,explicit_nonce,8);
        uint8_t aad[13];
        uint64_t seq=is_svr?s.client_seq:s.server_seq;
        for(int i=0;i<8;++i)aad[7-i]=(uint8_t)(seq>>(i*8));
        aad[8]=record[0];
        aad[9]=0x03;aad[10]=0x03;
        aad[11]=(uint8_t)(ct_len>>8);aad[12]=(uint8_t)ct_len;
        if(is_svr)++s.client_seq;else ++s.server_seq;
        std::vector<uint8_t> inner;
        aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
        if(!aes_gcm_decrypt(ctx,nonce,12,std::span<const uint8_t>(ciphertext,ct_len),std::span<const uint8_t>(aad,13),tag,16,inner))
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
    const uint8_t* read_iv=is_svr?s.client_write_iv:s.server_write_iv;
    const uint8_t* read_key=is_svr?s.client_write_key:s.server_write_key;
    uint8_t nonce[12];memcpy(nonce,read_iv,12);
    uint64_t seq=is_svr?s.client_seq:s.server_seq;
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(seq>>(56-i*8));
    if(is_svr)++s.client_seq;else ++s.server_seq;
    std::vector<uint8_t> inner;
    aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
    if(!aes_gcm_decrypt(ctx,nonce,12,std::span<const uint8_t>(ciphertext,ct_len),std::span<const uint8_t>(),tag,16,inner))
        return false;
    if(inner.empty())return false;
    ct=(ContentType)inner[0];
    out.assign(inner.begin()+1,inner.end()-1);
    return true;
}



// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.3 0-RTT — PSK, Early Data, NewSessionTicket
// ═══════════════════════════════════════════════════════════════════════

static void tls13_derive_resumption_secret(tls_session& s, uint8_t out[48]){
    size_t hl=tls_hash_len(s.cipher_suite);
    uint8_t zero[48]={};
    if(tls_use_sha384(s.cipher_suite))
        hkdf_extract_sha384(s.master_secret,48,zero,48,out);
    else
        hkdf_extract(s.master_secret,32,zero,32,out);
}

static void tls13_derive_early_secret_from_psk(tls_session& s, const uint8_t* psk,
                                                uint8_t early_secret[48]){
    size_t hl=tls_hash_len(s.cipher_suite);
    uint8_t zero[48]={};
    if(tls_use_sha384(s.cipher_suite))
        hkdf_extract_sha384(zero,48,psk,48,early_secret);
    else
        hkdf_extract(zero,32,psk,32,early_secret);
}

static void tls13_derive_early_traffic_keys(tls_session& s, const uint8_t* psk){
    size_t hl=tls_hash_len(s.cipher_suite);
    uint8_t early_secret[48];
    tls13_derive_early_secret_from_psk(s, psk, early_secret);
    tls_transcript_finalize(s);
    size_t key_len = aes_key_len(s.cipher_suite);
    if(tls_use_sha384(s.cipher_suite)){
        hkdf_expand_label_sha384(early_secret,"c e traffic",s.transcript_hash,hl,
                                 s.client_early_write_key, key_len);
        hkdf_expand_label_sha384(early_secret,"c e traffic",s.transcript_hash,hl,
                                 s.client_early_write_iv, 12);
    }else{
        hkdf_expand_label(early_secret,"c e traffic",s.transcript_hash,hl,
                          s.client_early_write_key, key_len);
        hkdf_expand_label(early_secret,"c e traffic",s.transcript_hash,hl,
                          s.client_early_write_iv, 12);
    }
    s.client_early_seq=0;
}

static void tls13_compute_binder(tls_session& s, const uint8_t* psk,
                                  const uint8_t* ch_truncated, size_t ch_trunc_len,
                                  uint8_t* binder){
    size_t hl=tls_hash_len(s.cipher_suite);
    uint8_t early_secret[48];
    tls13_derive_early_secret_from_psk(s, psk, early_secret);

    uint8_t binder_key[48];
    if(tls_use_sha384(s.cipher_suite))
        hkdf_expand_label_sha384(early_secret,"ext binder",(const uint8_t*)"",0,binder_key,hl);
    else
        hkdf_expand_label(early_secret,"ext binder",(const uint8_t*)"",0,binder_key,hl);

    uint8_t ch_hash[48];
    if(tls_use_sha384(s.cipher_suite)){
        sha512_ctx ctx; sha384_init(&ctx);
        sha512_update(&ctx,ch_truncated,ch_trunc_len);
        sha512_final(&ctx,ch_hash);
    }else{
        sha256_ctx ctx; sha256_init(&ctx);
        sha256_update(&ctx,ch_truncated,ch_trunc_len);
        sha256_final(&ctx,ch_hash);
    }

    if(tls_use_sha384(s.cipher_suite))
        hmac_sha384(binder_key,hl,ch_hash,hl,binder);
    else
        hmac_sha256(binder_key,hl,ch_hash,hl,binder);
}

// ═══════════════════════════════════════════════════════════════════════
//  NewSessionTicket
// ═══════════════════════════════════════════════════════════════════════

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
    s.ticket_age_add = (uint32_t)(rand() & 0xFFFFFFFF);
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

// ═══════════════════════════════════════════════════════════════════════
//  PSK storage (client side)
// ═══════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════
//  PSK ClientHello
// ═══════════════════════════════════════════════════════════════════════

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
    // signature_algorithms
    all_ext.push_back(0x00);all_ext.push_back(0x0d);all_ext.push_back(0x00);all_ext.push_back(0x08);
    all_ext.push_back(0x00);all_ext.push_back(0x06);
    all_ext.push_back(0x08);all_ext.push_back(0x07);all_ext.push_back(0x04);all_ext.push_back(0x03);
    all_ext.push_back(0x08);all_ext.push_back(0x08);
    // key_share X25519
    {
        uint8_t cpriv[32],cpub[32];
        x25519_generate_keypair(cpub,cpriv);
        memcpy(s.ks_priv, cpriv, 32);
        all_ext.push_back(0x00);all_ext.push_back(0x33);all_ext.push_back(0x00);all_ext.push_back(0x24);
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
    client_hello.push_back(0);
    client_hello.push_back(0x00);client_hello.push_back(0x08);
    client_hello.push_back(0x13);client_hello.push_back(0x01);
    client_hello.push_back(0x13);client_hello.push_back(0x02);
    client_hello.push_back(0x13);client_hello.push_back(0x03);
    client_hello.push_back(0x13);client_hello.push_back(0x04);
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
    size_t ch_trunc_len = 4 + 47 + 2 + binder_pos;
    uint8_t binder[48];
    tls13_compute_binder(s, s.psk_value, client_hello.data(), ch_trunc_len, binder);
    size_t binder_off = 4 + 47 + 2 + binder_pos;
    for(size_t i=0;i<hl;i++) client_hello[binder_off + i] = binder[i];

    tls_transcript_update(s, client_hello.data(), client_hello.size());
    tls13_derive_early_traffic_keys(s, s.psk_value);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  Server: process PSK ClientHello
// ═══════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════
//  Early data encrypt/decrypt
// ═══════════════════════════════════════════════════════════════════════

std::vector<uint8_t> tls13_encrypt_early_data(tls_session& s,
                                              const uint8_t* data, size_t len){
    std::vector<uint8_t> inner;
    inner.push_back((uint8_t)ContentType::APPLICATION_DATA);
    inner.insert(inner.end(), data, data+len);
    inner.push_back((uint8_t)ContentType::APPLICATION_DATA);

    uint8_t nonce[12];
    memcpy(nonce, s.client_early_write_iv, 12);
    for(int i=0;i<8;++i) nonce[4+i] ^= (uint8_t)(s.client_early_seq>>(56-i*8));
    ++s.client_early_seq;

    std::vector<uint8_t> ciphertext;
    uint8_t tag[16];
    // Inline AEAD dispatch
    switch(s.cipher_suite){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384: {
            aes_context ctx;
            aes_ctx_init(ctx, s.client_early_write_key, aes_key_len(s.cipher_suite));
            aes_gcm_encrypt(ctx, nonce, 12, inner, std::span<const uint8_t>(), ciphertext, tag, 16);
            break;
        }
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            chacha20_poly1305_encrypt(s.client_early_write_key, nonce, inner, std::span<const uint8_t>(), ciphertext, tag);
            break;
        case CipherSuite::TLS_AES_128_CCM_SHA256: {
            aes_context ctx;
            aes_ctx_init(ctx, s.client_early_write_key, aes_key_len(s.cipher_suite));
            aes_ccm_encrypt(ctx, nonce, 12, inner, std::span<const uint8_t>(), ciphertext, tag, 16);
            break;
        }
    }

    std::vector<uint8_t> record;
    record.push_back(0x17);
    record.push_back(0x03); record.push_back(0x03);
    size_t rlen = ciphertext.size() + 16;
    record.push_back((uint8_t)(rlen>>8)); record.push_back((uint8_t)(rlen));
    record.insert(record.end(), ciphertext.begin(), ciphertext.end());
    record.insert(record.end(), tag, tag+16);
    return record;
}

bool tls13_decrypt_early_data(tls_session& s, const uint8_t* record, size_t record_len,
                              ContentType& ct, std::vector<uint8_t>& out){
    if(!s.early_data_accepted) return false;
    if(record_len < 5) return false;
    size_t rlen = (record[3]<<8)|record[4];
    if(5+rlen != record_len || rlen < 16) return false;
    const uint8_t* ciphertext = record+5;
    size_t ct_len = rlen - 16;
    const uint8_t* tag = record+5+ct_len;

    uint8_t nonce[12];
    memcpy(nonce, s.client_early_write_iv, 12);
    for(int i=0;i<8;++i) nonce[4+i] ^= (uint8_t)(s.client_early_seq>>(56-i*8));
    ++s.client_early_seq;

    std::vector<uint8_t> inner;
    bool ok = false;
    switch(s.cipher_suite){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384: {
            aes_context ctx;
            aes_ctx_init(ctx, s.client_early_write_key, aes_key_len(s.cipher_suite));
            ok = aes_gcm_decrypt(ctx, nonce, 12, std::span<const uint8_t>(ciphertext,ct_len),
                                 std::span<const uint8_t>(), tag, 16, inner);
            break;
        }
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            ok = chacha20_poly1305_decrypt(s.client_early_write_key, nonce,
                                           std::span<const uint8_t>(ciphertext,ct_len),
                                           std::span<const uint8_t>(), tag, inner);
            break;
        case CipherSuite::TLS_AES_128_CCM_SHA256: {
            aes_context ctx;
            aes_ctx_init(ctx, s.client_early_write_key, aes_key_len(s.cipher_suite));
            ok = aes_ccm_decrypt(ctx, nonce, 12, std::span<const uint8_t>(ciphertext,ct_len),
                                 std::span<const uint8_t>(), tag, 16, inner);
            break;
        }
    }
    if(!ok || inner.empty()) return false;
    ct = (ContentType)inner[0];
    out.assign(inner.begin()+1, inner.end()-1);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  EndOfEarlyData
// ═══════════════════════════════════════════════════════════════════════

std::vector<uint8_t> tls13_make_end_of_early_data(){
    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::END_OF_EARLY_DATA);
    msg.push_back(0); msg.push_back(0); msg.push_back(0);
    return msg;
}

bool tls13_process_end_of_early_data(tls_session& s, const uint8_t* data, size_t len){
    (void)s;
    if(len < 4) return false;
    if(data[0] != (uint8_t)HandshakeType::END_OF_EARLY_DATA) return false;
    return true;
}


}