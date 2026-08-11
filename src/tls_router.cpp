/**
 * TLS 公共基座 + 版本选择（router）
 *
 * 由原 tls.cpp 拆分而来：存放与具体协议端点无关的公共代码——
 * 密码套件/签名方案辅助、证书与信任库、transcript、记录层加解密、
 * TLS 1.2/1.3 两端共享的密钥派生与 Finished/消息构造，以及版本选择。
 */

#include "jpssl_memory.hpp"
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


static const uint8_t RSA_SHA256_DIGEST_INFO[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

// 从系�?CSPRNG 读取 32 字节密码学安全随机数（Windows BCrypt / Linux urandom�?
void rand32(uint8_t* buf){
    if (!jpssl::os_rand_bytes(buf, 32))
        std::memset(buf, 0, 32);
}

CipherSuite select_cipher_suite(uint16_t id){
    switch(id){
        case 0x1301: return CipherSuite::TLS_AES_128_GCM_SHA256;
        case 0x1302: return CipherSuite::TLS_AES_256_GCM_SHA384;
        case 0x1303: return CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
        case 0x1304: return CipherSuite::TLS_AES_128_CCM_SHA256;
        case 0x1305: return CipherSuite::TLS_AES_128_CCM_8_SHA256;
        case 0x00C6: return CipherSuite::TLS_SM4_GCM_SM3;
        case 0x00C7: return CipherSuite::TLS_SM4_CCM_SM3;
        case 0x009C: return CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256;
        case 0x009D: return CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384;
        case 0x003C: return CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256;
        case 0x003D: return CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256;
        case 0x009E: return CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
        case 0x009F: return CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
        case 0x0067: return CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
        case 0x006B: return CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
        case 0xCCAA: return CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
        case 0x00A8: return CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256;
        case 0x00A9: return CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384;
        case 0x00AE: return CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256;
        case 0x00AF: return CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384;
        case 0xCCAB: return CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256;
        case 0x00AA: return CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256;
        case 0x00AB: return CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384;
        case 0x00B2: return CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256;
        case 0x00B3: return CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384;
        case 0xCCAD: return CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256;
        case 0xC02B: return CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        case 0xC02C: return CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
        case 0xC02F: return CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        case 0xC030: return CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
        case 0xCCA8: return CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
        case 0xCCA9: return CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
        default: return CipherSuite::UNKNOWN;
    }
}

static bool cipher_needs_aes_ctx(CipherSuite cs){
    switch(cs){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384:
        case CipherSuite::TLS_AES_128_CCM_SHA256:
        case CipherSuite::TLS_AES_128_CCM_8_SHA256:
        case CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
            return true;
        default: return false;
    }
}

// TLS 1.2 CBC 套件（RFC 5246 6.2.3.2）：显式 IV + HMAC + PKCS7 填充
static bool tls12_is_cbc(CipherSuite cs){
    return cs == CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256
        || cs == CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256
        || cs == CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        || cs == CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        || cs == CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256
        || cs == CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384
        || cs == CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
        || cs == CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384;
}

size_t aes_key_len(CipherSuite cs){
    switch(cs){
        case CipherSuite::TLS_AES_256_GCM_SHA384: return 32;
        // TLS 1.2 AES-256 套件：AES-256 需�?32 字节 key
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
            return 32;
        // ChaCha20-Poly1305 密钥恒为 32 字节（RFC 8439 §2.3 / RFC 7905 §2）：
        // 若按 16 字节派生，后 16 字节为未初始化内存，early data 与记录层会间歇性解密失�?        
case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return 32;
        default: return 16;
    }
}

void aes_ctx_init(aes_context& ctx, const uint8_t* key, size_t key_len){
    if(key_len==32) ctx.init(jpssl::span<const uint8_t,32>(key,32));
    else ctx.init(jpssl::span<const uint8_t,16>(key,16));
}

// raw CBC encrypt/decrypt (no padding), used for TLS 1.2 record layer
static void tls_cbc_encrypt_blocks(aes_context& ctx, const uint8_t iv[16],
                                   const uint8_t* in, size_t nblocks, uint8_t* out){
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for(size_t i=0;i<nblocks;++i){
        uint8_t xored[16];
        for(int j=0;j<16;++j) xored[j]=in[i*16+j]^prev[j];
        aes_encrypt_block(ctx, xored, out+i*16);
        memcpy(prev, out+i*16, 16);
    }
}

static void tls_cbc_decrypt_blocks(aes_context& ctx, const uint8_t iv[16],
                                   const uint8_t* in, size_t nblocks, uint8_t* out){
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for(size_t i=0;i<nblocks;++i){
        uint8_t d[16];
        aes_decrypt_block(ctx, in+i*16, d);
        for(int j=0;j<16;++j) out[i*16+j]=d[j]^prev[j];
        memcpy(prev, in+i*16, 16);
    }
}

static bool cipher_needs_sm4_ctx(CipherSuite cs){ return tls_use_sm4(cs); }
void sm4_ctx_init_from_key(sm4_ctx& ctx, const uint8_t* key){ sm4_init(&ctx, key); }
void init_cipher_ctx(tls_session& s, const uint8_t* key){
    if(cipher_needs_sm4_ctx(s.cipher_suite)) sm4_ctx_init_from_key(s.sm4, key);
    else aes_ctx_init(s.aes_ctx, key, aes_key_len(s.cipher_suite));
}

size_t client_hello_ext_offset(const uint8_t* ch, size_t ch_len){
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

// 追加 signature_algorithms (0x000d) / signature_algorithms_cert (0x0032) 扩展
void append_sig_alg_extension(std::vector<uint8_t>& ext, uint16_t type,
                                     const std::vector<uint16_t>& algs) {
    if (algs.empty()) return;
    size_t list_len = algs.size() * 2;
    ext.push_back((uint8_t)(type >> 8));
    ext.push_back((uint8_t)type);
    ext.push_back((uint8_t)((2 + list_len) >> 8));
    ext.push_back((uint8_t)(2 + list_len));
    ext.push_back((uint8_t)(list_len >> 8));
    ext.push_back((uint8_t)list_len);
    for (uint16_t a : algs) {
        ext.push_back((uint8_t)(a >> 8));
        ext.push_back((uint8_t)a);
    }
}

// 解析 SignatureSchemeList�? 字节长度 + 2*count 字节方案编码�?
bool parse_sig_alg_list(const uint8_t* p, size_t len, std::vector<uint16_t>& out) {
    if (len < 2) return false;
    size_t list_len = ((size_t)p[0] << 8) | p[1];
    if (2 + list_len != len || (list_len & 1)) return false;
    out.clear();
    for (size_t i = 0; i < list_len; i += 2)
        out.push_back((uint16_t)((p[2 + i] << 8) | p[2 + i + 1]));
    return true;
}

// �?ClientHello 扩展区查找指定扩�?
bool client_hello_find_extension(const uint8_t* ch, size_t ch_len, uint16_t want,
                                        const uint8_t*& data, size_t& dlen) {
    size_t ext_offset = client_hello_ext_offset(ch, ch_len);
    if (ext_offset + 2 > ch_len) return false;
    size_t total = ((size_t)ch[ext_offset] << 8) | ch[ext_offset + 1];
    size_t off = ext_offset + 2;
    size_t end = off + total;
    if (end > ch_len) return false;
    while (off + 4 <= end) {
        uint16_t type = (uint16_t)((ch[off] << 8) | ch[off + 1]);
        size_t elen = ((size_t)ch[off + 2] << 8) | ch[off + 3];
        if (off + 4 + elen > end) return false;
        if (type == want) { data = ch + off + 4; dlen = elen; return true; }
        off += 4 + elen;
    }
    return false;
}

// 客户端应广告�?signature_algorithms 列表（配置为空时用全量默认）
std::vector<uint16_t> effective_sig_algs(const tls_session& s) {
    if (s.sig_algs.empty()) return tls_default_signature_algorithms();
    return s.sig_algs;
}

enum class SigKeyFamily { NONE, RSA, ECDSA_P256, ECDSA_P384, ECDSA_P521, ED25519, ED448, SM2 };

static SigKeyFamily sig_key_family(SignatureAlgorithm sa) {
    switch (sa) {
        case SignatureAlgorithm::RSA_PKCS1_SHA256:
        case SignatureAlgorithm::RSA_PKCS1_SHA384:
        case SignatureAlgorithm::RSA_PKCS1_SHA512:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA256:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA384:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA512:
            return SigKeyFamily::RSA;
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256: return SigKeyFamily::ECDSA_P256;
        case SignatureAlgorithm::ECDSA_SECP384R1_SHA384: return SigKeyFamily::ECDSA_P384;
        case SignatureAlgorithm::ECDSA_SECP521R1_SHA512: return SigKeyFamily::ECDSA_P521;
        case SignatureAlgorithm::ED25519: return SigKeyFamily::ED25519;
        case SignatureAlgorithm::ED448: return SigKeyFamily::ED448;
        case SignatureAlgorithm::SM2_SM3: return SigKeyFamily::SM2;
        default: return SigKeyFamily::NONE;
    }
}

bool scheme_in_list(const std::vector<uint16_t>& list, uint16_t scheme) {
    for (uint16_t s : list) if (s == scheme) return true;
    return false;
}

// 服务端协商签名方案：按对端偏好序选择双方都支持且与证书密钥类型匹配的方案
uint16_t select_signature_scheme(const std::vector<uint16_t>& peer_list,
                                        const tls_certificate& cert,
                                        const std::vector<uint16_t>& local_list,
                                        bool tls13) {
    const std::vector<uint16_t>& supported =
        local_list.empty() ? tls_default_signature_algorithms() : local_list;
    SigKeyFamily fam = sig_key_family(cert.sig_alg);
    if (fam == SigKeyFamily::NONE) return 0;
    for (uint16_t s : peer_list) {
        if (!scheme_in_list(supported, s)) continue;
        if (sig_key_family((SignatureAlgorithm)s) != fam) continue;
        if (tls13 && !tls_scheme_allowed_for_cert_verify(s)) continue;
        return s;
    }
    return 0;
}

// 证书链签名方案（用于 signature_algorithms_cert 校验�?
// 优先解析证书 DER 中的签名算法；自签名证书回退�?sig_alg 映射
uint16_t x509_key_type_chain_scheme(x509::KeyType kt) {
    switch (kt) {
        case x509::KeyType::RSA_2048:
        case x509::KeyType::RSA_4096:
            return (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256;
        case x509::KeyType::ECDSA_P256:
            return (uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
        case x509::KeyType::ECDSA_P384:
            return (uint16_t)SignatureAlgorithm::ECDSA_SECP384R1_SHA384;
        case x509::KeyType::ECDSA_P521:
            return (uint16_t)SignatureAlgorithm::ECDSA_SECP521R1_SHA512;
        case x509::KeyType::Ed25519:
            return (uint16_t)SignatureAlgorithm::ED25519;
        case x509::KeyType::Ed448:
            return (uint16_t)SignatureAlgorithm::ED448;
        case x509::KeyType::SM2:
            return (uint16_t)SignatureAlgorithm::SM2_SM3;
        default:
            return 0;
    }
}

uint16_t cert_chain_signature_scheme(const tls_certificate& cert) {
    if (!cert.cert_data.empty()) {
        auto parsed = x509::x509_cert::from_der(cert.cert_data);
        if (parsed) return x509_key_type_chain_scheme(parsed->sign_key_type);
    }
    switch (cert.sig_alg) {
        case SignatureAlgorithm::RSA_PKCS1_SHA256:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA256:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA384:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA512:
            return (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256;
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256:
            return (uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
        case SignatureAlgorithm::ECDSA_SECP384R1_SHA384:
            return (uint16_t)SignatureAlgorithm::ECDSA_SECP384R1_SHA384;
        case SignatureAlgorithm::ECDSA_SECP521R1_SHA512:
            return (uint16_t)SignatureAlgorithm::ECDSA_SECP521R1_SHA512;
        case SignatureAlgorithm::ED25519: return (uint16_t)SignatureAlgorithm::ED25519;
        case SignatureAlgorithm::ED448: return (uint16_t)SignatureAlgorithm::ED448;
        case SignatureAlgorithm::SM2_SM3: return (uint16_t)SignatureAlgorithm::SM2_SM3;
        default: return 0;
    }
}

// ══════════════════════════════════════════════════════════════════════�?
//  transcript 辅助
// ══════════════════════════════════════════════════════════════════════�?
void tls_transcript_update(tls_session& s, const uint8_t* data, size_t len){
    if(!s.transcript_ready){
        if(tls_use_sha384(s.cipher_suite)) sha384_init(&s.transcript_ctx.sha512);
        else if(tls_use_sm3(s.cipher_suite)) sm3_init(&s.transcript_ctx.sm3);
        else sha256_init(&s.transcript_ctx.sha256);
        s.transcript_ready=true;
    }
    if(tls_use_sha384(s.cipher_suite)) sha512_update(&s.transcript_ctx.sha512,data,len);
    else if(tls_use_sm3(s.cipher_suite)) sm3_update(&s.transcript_ctx.sm3,data,len);
    else sha256_update(&s.transcript_ctx.sha256,data,len);
}
void tls_transcript_finalize(tls_session& s){
    if(s.transcript_ready){
        if(tls_use_sha384(s.cipher_suite)){
            sha512_ctx copy=s.transcript_ctx.sha512;
            sha512_final(&copy,s.transcript_hash);
        }else if(tls_use_sm3(s.cipher_suite)){
            sm3_ctx copy=s.transcript_ctx.sm3;
            sm3_final(&copy,s.transcript_hash);
        }else{
            sha256_ctx copy=s.transcript_ctx.sha256;
            sha256_final(&copy,s.transcript_hash);
        }
    }
}

// ══════════════════════════════════════════════════════════════════════�?
//  证书签名/验证
// ══════════════════════════════════════════════════════════════════════�?
// ══════════════════════════════════════════════════════════════════════�?
//  签名方案辅助（RFC 8446 §4.2.3 / RFC 8998�?
// ══════════════════════════════════════════════════════════════════════�?
static const uint8_t RSA_SHA384_DIGEST_INFO[] = {
    0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,
    0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,
    0x00,0x04,0x30
};
static const uint8_t RSA_SHA512_DIGEST_INFO[] = {
    0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,
    0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,
    0x00,0x04,0x40
};

// 哈希类方案对应的摘要长度�? 表示未知/非哈希类方案
static size_t scheme_hash_len(uint16_t scheme) {
    switch (scheme) {
        case (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256:
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256:
        case (uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256:
            return 32;
        case (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA384:
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384:
        case (uint16_t)SignatureAlgorithm::ECDSA_SECP384R1_SHA384:
            return 48;
        case (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA512:
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA512:
        case (uint16_t)SignatureAlgorithm::ECDSA_SECP521R1_SHA512:
            return 64;
        default: return 0;
    }
}

static bool hash_scheme(uint16_t scheme, const uint8_t* data, size_t len, uint8_t* out) {
    switch (scheme) {
        case (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256:
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256:
        case (uint16_t)SignatureAlgorithm::ECDSA_SECP256R1_SHA256: {
            sha256_ctx c; sha256_init(&c);
            sha256_update(&c, data, len); sha256_final(&c, out); return true;
        }
        case (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA384:
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384:
        case (uint16_t)SignatureAlgorithm::ECDSA_SECP384R1_SHA384: {
            sha512_ctx c; sha384_init(&c);
            sha512_update(&c, data, len); sha512_final(&c, out); return true;
        }
        case (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA512:
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA512: {
            sha512_ctx c; sha512_init(&c);
            sha512_update(&c, data, len); sha512_final(&c, out); return true;
        }
        case (uint16_t)SignatureAlgorithm::ECDSA_SECP521R1_SHA512: {
            sha512_ctx c; sha512_init(&c);
            sha512_update(&c, data, len); sha512_final(&c, out); return true;
        }
        default: return false;
    }
}

static const uint8_t* digest_info_for_scheme(uint16_t scheme, size_t& di_len) {
    switch (scheme) {
        case (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA256:
            di_len = sizeof(RSA_SHA256_DIGEST_INFO); return RSA_SHA256_DIGEST_INFO;
        case (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA384:
            di_len = sizeof(RSA_SHA384_DIGEST_INFO); return RSA_SHA384_DIGEST_INFO;
        case (uint16_t)SignatureAlgorithm::RSA_PKCS1_SHA512:
            di_len = sizeof(RSA_SHA512_DIGEST_INFO); return RSA_SHA512_DIGEST_INFO;
        default: di_len = 0; return nullptr;
    }
}

// RSASSA-PKCS1-v1_5 签名（RSA-2048�?
static bool rsa_pkcs1_sign(const rsa_private_key& key, uint16_t scheme,
                           const uint8_t* data, size_t len, uint8_t* sig, size_t& sig_len) {
    size_t hl = scheme_hash_len(scheme);
    size_t di_len = 0;
    const uint8_t* di = digest_info_for_scheme(scheme, di_len);
    if (hl == 0 || !di) return false;
    uint8_t hash[64];
    if (!hash_scheme(scheme, data, len, hash)) return false;
    size_t pad_len = 256 - 3 - di_len - hl;
    if (pad_len == 0) return false;
    uint8_t padded[256];
    padded[0] = 0x00; padded[1] = 0x01;
    memset(padded + 2, 0xFF, pad_len);
    padded[2 + pad_len] = 0x00;
    memcpy(padded + 2 + pad_len + 1, di, di_len);
    memcpy(padded + 2 + pad_len + 1 + di_len, hash, hl);
    rsa_bignum m = rsa_bignum::from_bytes(padded, 256);
    rsa_bignum s;
    bn_modpow(s, m, key.d, key.n);
    s.to_bytes(sig);
    sig_len = 256;
    return true;
}

// RSASSA-PSS 签名（RSA-2048，saltLen = hLen，RFC 8446 要求�?
static bool rsa_pss_sign(const rsa_private_key& key, uint16_t scheme,
                         const uint8_t* data, size_t len, uint8_t* sig, size_t& sig_len) {
    PssHash hash;
    switch (scheme) {
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256: hash = PssHash::SHA256; break;
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384: hash = PssHash::SHA384; break;
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA512: hash = PssHash::SHA512; break;
        default: return false;
    }
    rsa_crt_key crt{key.n, key.e, key.d, key.p, key.q, key.dP, key.dQ, key.qInv};
    if (!rsassa_pss_sign(crt, data, len, sig, 0, hash)) return false;
    sig_len = 256;
    return true;
}

static bool rsa_pss_verify(const rsa_public_key& pub, uint16_t scheme,
                           const uint8_t* data, size_t len, const uint8_t* sig, size_t sig_len) {
    if (sig_len != 256) return false;
    PssHash hash;
    switch (scheme) {
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256: hash = PssHash::SHA256; break;
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA384: hash = PssHash::SHA384; break;
        case (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA512: hash = PssHash::SHA512; break;
        default: return false;
    }
    return rsassa_pss_verify(pub, data, len, sig, 0, hash);
}

// ══════════════════════════════════════════════════════════════════════�?
//  证书签名/验证
// ══════════════════════════════════════════════════════════════════════�?
// ECDSA 签名 DER 编解码（RFC 8446 §4.4.3 / RFC 8422 §5.5�?
static bool ecdsa_sign_to_der(const uint8_t* raw, size_t raw_len,
                              uint8_t* out, size_t out_cap, size_t& out_len) {
    size_t half = raw_len / 2;
    if (half == 0 || half * 2 != raw_len) return false;
    const uint8_t* r = raw;
    const uint8_t* s = raw + half;
    auto int_der_len = [](const uint8_t* p, size_t n) -> size_t {
        size_t i = 0;
        while (i < n - 1 && p[i] == 0) ++i;
        return (p[i] & 0x80) ? (n - i + 1) : (n - i);
    };
    size_t rl = int_der_len(r, half), sl = int_der_len(s, half);
    size_t content = 2 + rl + 2 + sl;
    size_t total = 2 + content;
    if (total > out_cap || content > 127) return false;
    size_t off = 0;
    out[off++] = 0x30; out[off++] = (uint8_t)content;
    auto put_int = [&](const uint8_t* p, size_t n, size_t ilen) {
        size_t i = 0;
        while (i < n - 1 && p[i] == 0) ++i;
        out[off++] = 0x02; out[off++] = (uint8_t)ilen;
        if (p[i] & 0x80) out[off++] = 0x00;
        for (size_t k = i; k < n; ++k) out[off++] = p[k];
    };
    put_int(r, half, rl);
    put_int(s, half, sl);
    out_len = off;
    return true;
}

static bool ecdsa_sig_from_der(const uint8_t* der, size_t der_len,
                               uint8_t* raw, size_t raw_len) {
    size_t half = raw_len / 2;
    size_t off = 0;
    if (der_len < 8 || der[off++] != 0x30) return false;
    size_t seq_len = der[off++];
    if (seq_len > 127 || off + seq_len != der_len) return false;
    size_t end = off + seq_len;
    auto parse_int = [&](uint8_t* out, size_t cap) -> bool {
        if (off + 2 > end || der[off++] != 0x02) return false;
        size_t ilen = der[off++];
        if (ilen == 0 || off + ilen > end) return false;
        if (der[off] & 0x80) return false;
        size_t skip = (der[off] == 0) ? 1 : 0;
        size_t n = ilen - skip;
        if (n > cap) return false;
        std::memset(out, 0, cap - n);
        std::memcpy(out + cap - n, der + off + skip, n);
        off += ilen;
        return true;
    };
    if (!parse_int(raw, half)) return false;
    if (!parse_int(raw + half, half)) return false;
    return off == end;
}

bool tls_certificate::sign_scheme(uint16_t scheme, const uint8_t* data, size_t data_len,
                                   uint8_t* sig, size_t& sig_len,
                                   const uint8_t za[32]) const {
    switch ((SignatureAlgorithm)scheme) {
        case SignatureAlgorithm::ED25519:
            sig_len = 64; ed25519_sign(priv.ed25519, data, data_len, sig); return true;
        case SignatureAlgorithm::ED448:
            sig_len = 114; ed448_sign(priv.ed448, data, data_len, sig); return true;
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256: {
            uint8_t raw[64], der[160];
            ecdsa_p256_sign(priv.ecdsa_p256, data, data_len, raw);
            size_t dl = sizeof(der);
            if (!ecdsa_sign_to_der(raw, sizeof(raw), der, sizeof(der), dl)) return false;
            std::memcpy(sig, der, dl); sig_len = dl; return true;
        }
        case SignatureAlgorithm::ECDSA_SECP384R1_SHA384: {
            uint8_t raw[96], der[200];
            ecdsa_p384_sign(priv.ecdsa_p384, data, data_len, raw);
            size_t dl = sizeof(der);
            if (!ecdsa_sign_to_der(raw, sizeof(raw), der, sizeof(der), dl)) return false;
            std::memcpy(sig, der, dl); sig_len = dl; return true;
        }
        case SignatureAlgorithm::ECDSA_SECP521R1_SHA512: {
            uint8_t raw[132], der[256];
            ecdsa_p521_sign(priv.ecdsa_p521, data, data_len, raw);
            size_t dl = sizeof(der);
            if (!ecdsa_sign_to_der(raw, sizeof(raw), der, sizeof(der), dl)) return false;
            std::memcpy(sig, der, dl); sig_len = dl; return true;
        }
        case SignatureAlgorithm::SM2_SM3: {
            // RFC 8998/OpenSSL 实测：TLS 1.3 CertificateVerify �?SM2 签名
            // 采用 DER 编码�?0 45 02 21 ... 02 20 ...），而非�?64 字节 r||s�?            
            uint8_t raw[64], der[160];
            sm2_sign(priv.sm2, data, data_len, raw, za);
            size_t dl = sizeof(der);
            if (!ecdsa_sign_to_der(raw, sizeof(raw), der, sizeof(der), dl)) return false;
            std::memcpy(sig, der, dl); sig_len = dl; return true;
        }
        case SignatureAlgorithm::RSA_PKCS1_SHA256:
        case SignatureAlgorithm::RSA_PKCS1_SHA384:
        case SignatureAlgorithm::RSA_PKCS1_SHA512:
            return rsa_pkcs1_sign(priv.rsa, scheme, data, data_len, sig, sig_len);
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA256:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA384:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA512:
            return rsa_pss_sign(priv.rsa, scheme, data, data_len, sig, sig_len);
        default:
            return false;
    }
}

bool tls_certificate::sign(const uint8_t* data, size_t data_len, uint8_t* sig, size_t& sig_len) const {
    return sign_scheme((uint16_t)sig_alg, data, data_len, sig, sig_len);
}

bool tls_certificate::verify_scheme(uint16_t scheme, const uint8_t* data, size_t data_len,
                                    const uint8_t* sig, size_t sig_len,
                                    const uint8_t za[32]) const {
    if (sig_key_family((SignatureAlgorithm)scheme) != sig_key_family(sig_alg)) return false;
    switch ((SignatureAlgorithm)scheme) {
        case SignatureAlgorithm::ED25519:
            if (sig_len != 64) return false;
            return ed25519_verify(pub.ed25519, data, data_len, sig);
        case SignatureAlgorithm::ED448:
            if (sig_len != 114) return false;
            return ed448_verify(pub.ed448, data, data_len, sig);
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256: {
            uint8_t raw[64];
            if (sig_len == 64) std::memcpy(raw, sig, 64);
            else if (!ecdsa_sig_from_der(sig, sig_len, raw, sizeof(raw))) return false;
            return ecdsa_p256_verify(pub.ecdsa_p256, data, data_len, raw);
        }
        case SignatureAlgorithm::ECDSA_SECP384R1_SHA384: {
            uint8_t raw[96];
            if (sig_len == 96) std::memcpy(raw, sig, 96);
            else if (!ecdsa_sig_from_der(sig, sig_len, raw, sizeof(raw))) return false;
            return ecdsa_p384_verify(pub.ecdsa_p384, data, data_len, raw);
        }
        case SignatureAlgorithm::ECDSA_SECP521R1_SHA512: {
            uint8_t raw[132];
            if (sig_len == 132) std::memcpy(raw, sig, 132);
            else if (!ecdsa_sig_from_der(sig, sig_len, raw, sizeof(raw))) return false;
            return ecdsa_p521_verify(pub.ecdsa_p521, data, data_len, raw);
        }
        case SignatureAlgorithm::SM2_SM3: {
            uint8_t raw[64];
            if (sig_len == 64) std::memcpy(raw, sig, 64);
            else if (!ecdsa_sig_from_der(sig, sig_len, raw, sizeof(raw))) return false;
            return sm2_verify(pub.sm2, data, data_len, raw, za);
        }
        case SignatureAlgorithm::RSA_PKCS1_SHA256:
        case SignatureAlgorithm::RSA_PKCS1_SHA384:
        case SignatureAlgorithm::RSA_PKCS1_SHA512: {
            if (sig_len != 256) return false;
            size_t hl = scheme_hash_len(scheme);
            size_t di_len = 0;
            const uint8_t* di = digest_info_for_scheme(scheme, di_len);
            uint8_t hash[64];
            if (hl == 0 || !di || !hash_scheme(scheme, data, data_len, hash)) return false;
            rsa_bignum s = rsa_bignum::from_bytes(sig, 256);
            rsa_bignum m;
            bn_modpow(m, s, pub.rsa.e, pub.rsa.n);
            uint8_t padded[256];
            m.to_bytes(padded);
            if (padded[0] != 0x00 || padded[1] != 0x01) return false;
            size_t pos = 2;
            while (pos < 256 && padded[pos] == 0xFF) ++pos;
            if (pos >= 256 || padded[pos] != 0x00) return false;
            ++pos;
            if (pos + di_len + hl > 256) return false;
            if (memcmp(padded + pos, di, di_len) != 0) return false;
            return memcmp(padded + pos + di_len, hash, hl) == 0;
        }
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA256:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA384:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA512:
            return rsa_pss_verify(pub.rsa, scheme, data, data_len, sig, sig_len);
        default:
            return false;
    }
}

bool tls_certificate::verify(const uint8_t* data, size_t data_len, const uint8_t* sig, size_t sig_len) const {
    return verify_scheme((uint16_t)sig_alg, data, data_len, sig, sig_len);
}

// ══════════════════════════════════════════════════════════════════════�?
//  证书管理�?
// ══════════════════════════════════════════════════════════════════════�?
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

// ══════════════════════════════════════════════════════════════════════�?
//  服务端证书加载（PEM / CSR + 私钥�?
// ══════════════════════════════════════════════════════════════════════�?
SignatureAlgorithm tls_key_type_to_sig_alg(x509::KeyType kt) {
    switch (kt) {
        case x509::KeyType::RSA_2048: case x509::KeyType::RSA_4096:
            return SignatureAlgorithm::RSA_PKCS1_SHA256;
        case x509::KeyType::Ed25519:  return SignatureAlgorithm::ED25519;
        case x509::KeyType::Ed448:    return SignatureAlgorithm::ED448;
        case x509::KeyType::ECDSA_P256: return SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
        case x509::KeyType::ECDSA_P384: return SignatureAlgorithm::ECDSA_SECP384R1_SHA384;
        case x509::KeyType::ECDSA_P521: return SignatureAlgorithm::ECDSA_SECP521R1_SHA512;
        case x509::KeyType::SM2:      return SignatureAlgorithm::SM2_SM3;
        default: return SignatureAlgorithm::ED25519;
    }
}

namespace {

// �?x509 公钥 raw bytes 填充 tls_certificate.pub
bool fill_pub(tls_certificate& out, x509::KeyType kt, const std::vector<uint8_t>& pub) {
    switch (kt) {
        case x509::KeyType::RSA_2048: {
            if (pub.size() < 256 + 3) return false;
            out.pub.rsa.n = rsa_bignum::from_bytes(pub.data(), 256);
            out.pub.rsa.e = rsa_bignum::from_bytes(pub.data() + 256, 3);
            return true;
        }
        case x509::KeyType::Ed25519:
            if (pub.size() < 32) return false;
            std::memcpy(out.pub.ed25519, pub.data(), 32);
            return true;
        case x509::KeyType::Ed448:
            if (pub.size() < 57) return false;
            std::memcpy(out.pub.ed448, pub.data(), 57);
            return true;
        case x509::KeyType::ECDSA_P256:
            if (pub.size() < 64) return false;
            std::memcpy(out.pub.ecdsa_p256, pub.data(), 64);
            return true;
        case x509::KeyType::ECDSA_P384:
            if (pub.size() < 96) return false;
            std::memcpy(out.pub.ecdsa_p384, pub.data(), 96);
            return true;
        case x509::KeyType::ECDSA_P521:
            if (pub.size() < 132) return false;
            std::memcpy(out.pub.ecdsa_p521, pub.data(), 132);
            return true;
        case x509::KeyType::SM2:
            if (pub.size() < 64) return false;
            std::memcpy(out.pub.sm2, pub.data(), 64);
            return true;
        default:
            return false;
    }
}

// �?x509 私钥 raw bytes 填充 tls_certificate.priv（RSA 需要私钥的 n||e 公钥�?
bool fill_priv(tls_certificate& out, x509::KeyType kt,
               const std::vector<uint8_t>& priv, const std::vector<uint8_t>& pub) {
    switch (kt) {
        case x509::KeyType::RSA_2048: {
            if (priv.size() < 256 || pub.size() < 256 + 3) return false;
            out.priv.rsa.d = rsa_bignum::from_bytes(priv.data(), 256);
            out.priv.rsa.n = rsa_bignum::from_bytes(pub.data(), 256);
            out.priv.rsa.e = rsa_bignum::from_bytes(pub.data() + 256, 3);
            return true;
        }
        case x509::KeyType::Ed25519:
            if (priv.size() < 64) return false;
            std::memcpy(out.priv.ed25519, priv.data(), 64);
            return true;
        case x509::KeyType::Ed448:
            if (priv.size() < 57) return false;
            std::memcpy(out.priv.ed448, priv.data(), 57);
            return true;
        case x509::KeyType::ECDSA_P256:
            if (priv.size() < 32) return false;
            std::memcpy(out.priv.ecdsa_p256, priv.data(), 32);
            return true;
        case x509::KeyType::ECDSA_P384:
            if (priv.size() < 48) return false;
            std::memcpy(out.priv.ecdsa_p384, priv.data(), 48);
            return true;
        case x509::KeyType::ECDSA_P521:
            if (priv.size() < 66) return false;
            std::memcpy(out.priv.ecdsa_p521, priv.data(), 66);
            return true;
        case x509::KeyType::SM2:
            if (priv.size() < 32) return false;
            std::memcpy(out.priv.sm2, priv.data(), 32);
            return true;
        default:
            return false;
    }
}

// �?CSR subject 提取 CN 作为证书主体�?
std::string csr_common_name(const x509::csr& req) {
    for (const auto& attr : req.subject) {
        if (attr.oid.size() == 3 &&
            std::memcmp(attr.oid.data(), x509::OID_CN, 3) == 0)
            return attr.value;
    }
    if (!req.subject.empty()) return req.subject[0].value;
    return "localhost";
}

// 读取整个文件为字符串（失败返回空串）
std::string read_file_string(const char* path) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return {};
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::string s;
    if (sz > 0) {
        s.resize((size_t)sz);
        size_t rd = std::fread(&s[0], 1, (size_t)sz, f);
        s.resize(rd);
    }
    std::fclose(f);
    return s;
}

// 解析 PEM 中全部证书块（CA bundle 可含多张�?
std::vector<x509::x509_cert> parse_all_pem_certs(const std::string& pem) {
    std::vector<x509::x509_cert> out;
    size_t pos = 0;
    while (true) {
        size_t b = pem.find("-----BEGIN CERTIFICATE-----", pos);
        if (b == std::string::npos) break;
        size_t e = pem.find("-----END CERTIFICATE-----", b);
        if (e == std::string::npos) break;
        std::string block = pem.substr(b, e - b + std::string("-----END CERTIFICATE-----").size());
        if (auto c = x509::x509_cert::from_pem(block)) out.push_back(std::move(*c));
        pos = e;
    }
    return out;
}

void set_err(std::string* err, const std::string& msg) { if (err) *err = msg; }

} // anonymous namespace

std::unique_ptr<tls_certificate> tls_certificate::from_pem(const std::string& cert_pem,
                                                           const std::string& key_pem,
                                                           std::string* err) {
    auto c = x509::x509_cert::from_pem(cert_pem);
    if (!c) { set_err(err, "certificate PEM parse failed"); return nullptr; }
    auto k = x509::private_key::from_pem(key_pem);
    if (!k) { set_err(err, "private key PEM parse failed"); return nullptr; }
    if (c->key_type == x509::KeyType::RSA_4096) {
        set_err(err, "RSA-4096 private key is not supported in tls_certificate (use RSA-2048)");
        return nullptr;
    }
    if (k->key_type != c->key_type) {
        set_err(err, "certificate/private key key-type mismatch");
        return nullptr;
    }
    auto out = jpssl::make_unique<tls_certificate>();
    out->subject_name = c->common_name();
    out->cert_data = c->to_der();
    out->sig_alg = tls_key_type_to_sig_alg(c->key_type);
    if (!fill_pub(*out, c->key_type, c->public_key)) {
        set_err(err, "failed to import certificate public key");
        return nullptr;
    }
    if (!fill_priv(*out, k->key_type, k->priv, k->pub)) {
        set_err(err, "failed to import private key");
        return nullptr;
    }
    return out;
}

std::unique_ptr<tls_certificate> tls_certificate::from_pem_file(const char* cert_path,
                                                                const char* key_path,
                                                                std::string* err) {
    std::string cp = read_file_string(cert_path);
    if (cp.empty()) { set_err(err, "cannot read cert file"); return nullptr; }
    std::string kp = read_file_string(key_path);
    if (kp.empty()) { set_err(err, "cannot read key file"); return nullptr; }
    return from_pem(cp, kp, err);
}

std::unique_ptr<tls_certificate> tls_certificate::from_csr_pem(const std::string& csr_pem,
                                                               const std::string& key_pem,
                                                               std::string* err) {
    auto req = x509::csr::from_pem(csr_pem);
    if (!req) { set_err(err, "CSR PEM parse failed"); return nullptr; }
    auto k = x509::private_key::from_pem(key_pem);
    if (!k) { set_err(err, "private key PEM parse failed"); return nullptr; }
    if (k->key_type != req->key_type) {
        set_err(err, "CSR/private key key-type mismatch");
        return nullptr;
    }
    if (req->key_type == x509::KeyType::RSA_4096) {
        set_err(err, "RSA-4096 private key is not supported in tls_certificate (use RSA-2048)");
        return nullptr;
    }
    auto out = jpssl::make_unique<tls_certificate>();
    out->subject_name = csr_common_name(*req);
    // cert_data 留空：握手时�?CSR 主体自动生成自签名证�?
    out->sig_alg = tls_key_type_to_sig_alg(req->key_type);
    if (!fill_pub(*out, req->key_type, req->public_key)) {
        set_err(err, "failed to import CSR public key");
        return nullptr;
    }
    if (!fill_priv(*out, k->key_type, k->priv, k->pub)) {
        set_err(err, "failed to import private key");
        return nullptr;
    }
    return out;
}

std::unique_ptr<tls_certificate> tls_certificate::from_csr_pem_file(const char* csr_path,
                                                                    const char* key_path,
                                                                    std::string* err) {
    std::string cp = read_file_string(csr_path);
    if (cp.empty()) { set_err(err, "cannot read CSR file"); return nullptr; }
    std::string kp = read_file_string(key_path);
    if (kp.empty()) { set_err(err, "cannot read key file"); return nullptr; }
    return from_csr_pem(cp, kp, err);
}

tls_trust_store tls_trust_store::from_pem(const std::string& pem) {
    tls_trust_store ts;
    ts.ca_roots = parse_all_pem_certs(pem);
    return ts;
}

tls_trust_store tls_trust_store::from_pem_file(const char* path) {
    return from_pem(read_file_string(path));
}

// 常见系统 CA bundle 路径（按优先级顺序探测）
static const char* const kSystemCaPaths[] = {
    "/etc/ssl/certs/ca-certificates.crt",   // Debian / Ubuntu / Arch / Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",     // RHEL / Fedora / CentOS
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  // RHEL 备�?
    "/etc/ssl/ca-bundle.pem",               // SUSE
    "/etc/ssl/cert.pem",                    // macOS (brew) / OpenBSD
    "/etc/ssl/certs/ca-bundle.crt",         // 部分发行�?
    nullptr,
};

tls_trust_store tls_trust_store::from_system() {
    static tls_trust_store cached;
    static bool loaded = false;
    static std::mutex mtx;
    std::lock_guard<std::mutex> lock(mtx);
    if (loaded) return cached;

    // 1) SSL_CERT_FILE 环境变量优先
    const char* env = std::getenv("SSL_CERT_FILE");
    if (env && env[0]) {
        auto ts = from_pem_file(env);
        if (!ts.empty()) { cached = std::move(ts); loaded = true; return cached; }
    }
    // 2) 常见系统路径
    for (const char* const* p = kSystemCaPaths; *p; ++p) {
        auto ts = from_pem_file(*p);
        if (!ts.empty()) { cached = std::move(ts); loaded = true; return cached; }
    }
    loaded = true;  // 缓存"未找�?结果，避免每次连接都探测
    return cached;
}

// ══════════════════════════════════════════════════════════════════════�?
//  SNI 解析
// ══════════════════════════════════════════════════════════════════════�?
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

// ══════════════════════════════════════════════════════════════════════�?
//  ALPN 解析与选择 (RFC 7301, 扩展类型 0x0010)
// ══════════════════════════════════════════════════════════════════════�?
std::vector<std::string> tls_parse_alpn_list(const uint8_t* data, size_t len) {
    std::vector<std::string> out;
    if (len < 2) return out;
    size_t list_len = ((size_t)data[0] << 8) | data[1];
    if (2 + list_len > len) return out;
    size_t off = 2;
    size_t end = 2 + list_len;
    while (off < end) {
        uint8_t plen = data[off++];
        if (off + plen > end) { out.clear(); return out; }
        out.emplace_back((const char*)data + off, plen);
        off += plen;
    }
    return out;
}

std::string tls_select_alpn(const std::vector<std::string>& client_list,
                            const std::vector<std::string>& server_list) {
    for (const auto& c : client_list)
        for (const auto& s : server_list)
            if (c == s) return c;
    return {};
}

// ══════════════════════════════════════════════════════════════════════�?
//  TLS 1.3 密钥派生
// ══════════════════════════════════════════════════════════════════════�?
void tls13_derive_handshake_keys(tls_session& s, const uint8_t* shared_secret, size_t shared_len){
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    bool use_sm3=tls_use_sm3(s.cipher_suite);
    uint8_t zero[48]={},early_secret[48],empty_hash[48];
    if(use384){
        sha512_ctx ctx;sha384_init(&ctx);sha512_final(&ctx,empty_hash);
        hkdf_extract_sha384(zero,48,zero,48,early_secret);
        // RFC 8446 7.1：Handshake Secret = HKDF-Extract(Derive-Secret(Early Secret, "derived", ""), ECDHE)
        uint8_t derived[48];
        hkdf_expand_label_sha384(early_secret,"derived",empty_hash,hl,derived,hl);
        hkdf_extract_sha384(derived,48,shared_secret,shared_len,s.handshake_secret);
    }else if(use_sm3){
        sm3_ctx ctx;sm3_init(&ctx);sm3_final(&ctx,empty_hash);
        hkdf_extract_sm3(zero,32,zero,32,early_secret);
        uint8_t derived[32];
        hkdf_expand_label_sm3(early_secret,"derived",empty_hash,hl,derived,hl);
        hkdf_extract_sm3(derived,32,shared_secret,shared_len,s.handshake_secret);
    }else{
        sha256_ctx ctx;sha256_init(&ctx);sha256_final(&ctx,empty_hash);
        hkdf_extract(zero,32,zero,32,early_secret);
        uint8_t derived[32];
        hkdf_expand_label(early_secret,"derived",empty_hash,hl,derived,hl);
        hkdf_extract(derived,32,shared_secret,shared_len,s.handshake_secret);
    }

    tls_transcript_finalize(s);
    uint8_t ch_ts[48],sh_ts[48];
    if(use384){
        hkdf_expand_label_sha384(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,ch_ts,hl);
        hkdf_expand_label_sha384(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,sh_ts,hl);
    }else if(use_sm3){
        hkdf_expand_label_sm3(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,ch_ts,hl);
        hkdf_expand_label_sm3(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,sh_ts,hl);
    }else{
        hkdf_expand_label(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,ch_ts,hl);
        hkdf_expand_label(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,sh_ts,hl);
    }

    // 保存 handshake traffic secrets（Finished 密钥�?BaseKey，RFC 8446 7.1�?
    memcpy(s.client_hs_traffic, ch_ts, hl);
    memcpy(s.server_hs_traffic, sh_ts, hl);

    // RFC 8446 7.1：Traffic Key = HKDF-Expand-Label(Traffic Secret, "key", "", key_len)
    //                Traffic IV  = HKDF-Expand-Label(Traffic Secret, "iv", "", 12)
    size_t key_len = aes_key_len(s.cipher_suite);
    if(use384){
        hkdf_expand_label_sha384(ch_ts,"key",nullptr,0,s.client_write_key,key_len);
        hkdf_expand_label_sha384(ch_ts,"iv",nullptr,0,s.client_write_iv,12);
        hkdf_expand_label_sha384(sh_ts,"key",nullptr,0,s.server_write_key,key_len);
        hkdf_expand_label_sha384(sh_ts,"iv",nullptr,0,s.server_write_iv,12);
    }else if(use_sm3){
        hkdf_expand_label_sm3(ch_ts,"key",nullptr,0,s.client_write_key,key_len);
        hkdf_expand_label_sm3(ch_ts,"iv",nullptr,0,s.client_write_iv,12);
        hkdf_expand_label_sm3(sh_ts,"key",nullptr,0,s.server_write_key,key_len);
        hkdf_expand_label_sm3(sh_ts,"iv",nullptr,0,s.server_write_iv,12);
    }else{
        hkdf_expand_label(ch_ts,"key",nullptr,0,s.client_write_key,key_len);
        hkdf_expand_label(ch_ts,"iv",nullptr,0,s.client_write_iv,12);
        hkdf_expand_label(sh_ts,"key",nullptr,0,s.server_write_key,key_len);
        hkdf_expand_label(sh_ts,"iv",nullptr,0,s.server_write_iv,12);
    }
    s.client_seq=0;s.server_seq=0;

    // QUIC mode (RFC 9001 §5.1)：Handshake 数据包保护 secret = TLS 1.3 "c/s hs traffic" 流量密钥
    if (s.quic_mode) {
        if (!s.quic_secrets)
            s.quic_secrets = std::make_shared<quic_secrets_block>();
        memcpy(s.quic_secrets->client_hs, ch_ts, hl);
        memcpy(s.quic_secrets->server_hs, sh_ts, hl);
        s.quic_hs_secrets_ready = true;
    }
}

void tls13_derive_application_keys(tls_session& s){
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    bool use_sm3=tls_use_sm3(s.cipher_suite);
    uint8_t zero[48]={};
    if(use384){
        // RFC 8446 7.1：Master Secret = HKDF-Extract(Derive-Secret(Handshake Secret, "derived", ""), 0)
        uint8_t empty_hash[48]={};sha512_ctx ec;sha384_init(&ec);sha512_final(&ec,empty_hash);
        uint8_t derived[48];
        hkdf_expand_label_sha384(s.handshake_secret,"derived",empty_hash,hl,derived,hl);
        hkdf_extract_sha384(derived,48,zero,48,s.master_secret);
    }else if(use_sm3){
        uint8_t empty_hash[32]={};sm3_ctx ec;sm3_init(&ec);sm3_final(&ec,empty_hash);
        uint8_t derived[32];
        hkdf_expand_label_sm3(s.handshake_secret,"derived",empty_hash,hl,derived,hl);
        hkdf_extract_sm3(derived,32,zero,32,s.master_secret);
    }else{
        uint8_t empty_hash[32]={};sha256_ctx ec;sha256_init(&ec);sha256_final(&ec,empty_hash);
        uint8_t derived[32];
        hkdf_expand_label(s.handshake_secret,"derived",empty_hash,hl,derived,hl);
        hkdf_extract(derived,32,zero,32,s.master_secret);
    }
    tls_transcript_finalize(s);
    uint8_t c_ap_ts[48],s_ap_ts[48];
    if(use384){
        hkdf_expand_label_sha384(s.master_secret,"c ap traffic",s.transcript_hash,hl,c_ap_ts,hl);
        hkdf_expand_label_sha384(s.master_secret,"s ap traffic",s.transcript_hash,hl,s_ap_ts,hl);
    }else if(use_sm3){
        hkdf_expand_label_sm3(s.master_secret,"c ap traffic",s.transcript_hash,hl,c_ap_ts,hl);
        hkdf_expand_label_sm3(s.master_secret,"s ap traffic",s.transcript_hash,hl,s_ap_ts,hl);
    }else{
        hkdf_expand_label(s.master_secret,"c ap traffic",s.transcript_hash,hl,c_ap_ts,hl);
        hkdf_expand_label(s.master_secret,"s ap traffic",s.transcript_hash,hl,s_ap_ts,hl);
    }
    // RFC 8446 7.1：Traffic Key/IV �?Application Traffic Secret 派生
    size_t key_len = aes_key_len(s.cipher_suite);
    if(use384){
        hkdf_expand_label_sha384(c_ap_ts,"key",nullptr,0,s.client_write_key,key_len);
        hkdf_expand_label_sha384(c_ap_ts,"iv",nullptr,0,s.client_write_iv,12);
        hkdf_expand_label_sha384(s_ap_ts,"key",nullptr,0,s.server_write_key,key_len);
        hkdf_expand_label_sha384(s_ap_ts,"iv",nullptr,0,s.server_write_iv,12);
    }else if(use_sm3){
        hkdf_expand_label_sm3(c_ap_ts,"key",nullptr,0,s.client_write_key,key_len);
        hkdf_expand_label_sm3(c_ap_ts,"iv",nullptr,0,s.client_write_iv,12);
        hkdf_expand_label_sm3(s_ap_ts,"key",nullptr,0,s.server_write_key,key_len);
        hkdf_expand_label_sm3(s_ap_ts,"iv",nullptr,0,s.server_write_iv,12);
    }else{
        hkdf_expand_label(c_ap_ts,"key",nullptr,0,s.client_write_key,key_len);
        hkdf_expand_label(c_ap_ts,"iv",nullptr,0,s.client_write_iv,12);
        hkdf_expand_label(s_ap_ts,"key",nullptr,0,s.server_write_key,key_len);
        hkdf_expand_label(s_ap_ts,"iv",nullptr,0,s.server_write_iv,12);
    }
    s.client_seq=0;s.server_seq=0;

    // QUIC mode (RFC 9001 §5.1)：1-RTT 数据包保护 secret = TLS 1.3 "c/s ap traffic" 流量密钥
    if (s.quic_mode) {
        if (!s.quic_secrets)
            s.quic_secrets = std::make_shared<quic_secrets_block>();
        memcpy(s.quic_secrets->client_app, c_ap_ts, hl);
        memcpy(s.quic_secrets->server_app, s_ap_ts, hl);
        s.quic_app_secrets_ready = true;
    }
}

void tls13_derive_keys(tls_session& s, const uint8_t* shared_secret, size_t shared_len){
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    bool use_sm3=tls_use_sm3(s.cipher_suite);
    uint8_t early_secret[48],empty_hash[48];
    uint8_t zero[48]={};
    if(use384){
        sha512_ctx ctx;sha384_init(&ctx);sha512_final(&ctx,empty_hash);
        hkdf_extract_sha384(zero,48,zero,48,early_secret);
        hkdf_extract_sha384(early_secret,48,shared_secret,shared_len,s.handshake_secret);
    }else if(use_sm3){
        sm3_ctx ctx;sm3_init(&ctx);sm3_final(&ctx,empty_hash);
        hkdf_extract_sm3(zero,32,zero,32,early_secret);
        hkdf_extract_sm3(early_secret,32,shared_secret,shared_len,s.handshake_secret);
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
    }else if(use_sm3){
        hkdf_expand_label_sm3(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_key,hl);
        hkdf_expand_label_sm3(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_key,hl);
        hkdf_expand_label_sm3(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label_sm3(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }else{
        hkdf_expand_label(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_key,hl);
        hkdf_expand_label(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_key,hl);
        hkdf_expand_label(s.master_secret,"c ap traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label(s.master_secret,"s ap traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }
    s.client_seq=0;s.server_seq=0;
}

// ══════════════════════════════════════════════════════════════════════�?
//  构建 Finished 消息
// ══════════════════════════════════════════════════════════════════════�?
std::vector<uint8_t> tls13_make_finished(tls_session& s, bool for_server){
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    bool use_sm3=tls_use_sm3(s.cipher_suite);
    uint8_t finished_key[48];
    // RFC 8446 4.4.4：finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    // BaseKey = 对应�?handshake traffic secret（服务端�?Finished �?server 侧）
    const uint8_t* base_key = for_server ? s.server_hs_traffic : s.client_hs_traffic;
    if(use384) hkdf_expand_label_sha384(base_key,"finished",nullptr,0,finished_key,hl);
    else if(use_sm3) hkdf_expand_label_sm3(base_key,"finished",nullptr,0,finished_key,hl);
    else hkdf_expand_label(base_key,"finished",nullptr,0,finished_key,hl);

    tls_transcript_finalize(s);
    uint8_t verify_data[48];
    if(use384) hmac_sha384(finished_key,hl,s.transcript_hash,hl,verify_data);
    else if(use_sm3) hmac_sm3(finished_key,hl,s.transcript_hash,hl,verify_data);
    else hmac_sha256(finished_key,hl,s.transcript_hash,hl,verify_data);

    std::vector<uint8_t> msg;
    msg.push_back((uint8_t)HandshakeType::FINISHED);
    msg.push_back(0);msg.push_back(0);msg.push_back((uint8_t)hl);
    msg.insert(msg.end(),verify_data,verify_data+hl);
    return msg;
}

bool tls13_verify_finished(tls_session& s, const uint8_t* hs_msg, size_t hs_len, bool for_server){
    if(hs_len<4 || hs_msg[0]!=(uint8_t)HandshakeType::FINISHED)return false;
    size_t hl=tls_hash_len(s.cipher_suite);
    size_t vd_len=(hs_msg[1]<<16)|(hs_msg[2]<<8)|hs_msg[3];
    if(vd_len!=hl || hs_len!=4+vd_len)return false;

    bool use384=tls_use_sha384(s.cipher_suite);
    bool use_sm3=tls_use_sm3(s.cipher_suite);
    uint8_t finished_key[48];
    // RFC 8446 4.4.4：finished_key �?handshake traffic secret 派生
    const uint8_t* base_key = for_server ? s.server_hs_traffic : s.client_hs_traffic;
    if(use384) hkdf_expand_label_sha384(base_key,"finished",nullptr,0,finished_key,hl);
    else if(use_sm3) hkdf_expand_label_sm3(base_key,"finished",nullptr,0,finished_key,hl);
    else hkdf_expand_label(base_key,"finished",nullptr,0,finished_key,hl);

    tls_transcript_finalize(s);
    uint8_t expected[48];
    if(use384) hmac_sha384(finished_key,hl,s.transcript_hash,hl,expected);
    else if(use_sm3) hmac_sm3(finished_key,hl,s.transcript_hash,hl,expected);
    else hmac_sha256(finished_key,hl,s.transcript_hash,hl,expected);

    return memcmp(expected,hs_msg+4,hl)==0;
}

// RFC 8446 §4.4.3: CertificateVerify 签名内容 =
//   64 �?0x20（空格）|| 上下文串 ("TLS 1.3, server/client CertificateVerify")
//   || 0x00（单个分隔符）|| Transcript-Hash
std::vector<uint8_t> tls13_cert_verify_content(tls_session& s, bool for_server) {
    static const char* server_ctx = "TLS 1.3, server CertificateVerify";
    static const char* client_ctx = "TLS 1.3, client CertificateVerify";
    tls_transcript_finalize(s);
    size_t hl = tls_hash_len(s.cipher_suite);
    const char* ctx = for_server ? server_ctx : client_ctx;
    std::vector<uint8_t> content;
    content.insert(content.end(), 64, 0x20);  // 64 个空�?
    content.insert(content.end(), ctx, ctx + strlen(ctx));
    content.push_back(0x00);                  // 单个 0x00 分隔�?
    content.insert(content.end(), s.transcript_hash, s.transcript_hash + hl);
    return content;
}

// ══════════════════════════════════════════════════════════════════════�?
//  客户�?x509 链验证辅�?
// ══════════════════════════════════════════════════════════════════════�?

// 叶子证书主机名匹配（SAN DNS 优先，其�?CN；支�?*.example.com 通配�?
bool tls13_hostname_matches(const x509::x509_cert& leaf, const std::string& host) {
    if (host.empty()) return true;
    for (const auto& dns : leaf.dns_names()) {
        if (dns == host) return true;
        if (dns.size() > 2 && dns[0] == '*' && dns[1] == '.') {
            std::string suffix = dns.substr(1); // ".example.com"
            if (host.size() > suffix.size() &&
                host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0)
                return true;
        }
    }
    if (leaf.common_name() == host) return true;
    return false;
}

// 服务端证书链 + 信任库验证：
//   1) 服务端链自身可通过（链已含自签根）�?
//   2) 否则逐个尝试把信任库中的 CA 根追加到链尾后验证�?
// 通过后还需叶子主机名匹�?server_name�?
bool tls13_verify_server_chain(const std::vector<x509::x509_cert>& server_chain,
                               const tls_trust_store& trust,
                               const std::string& hostname) {
    if (server_chain.empty()) return false;
    auto r = x509::x509_verify_chain(server_chain);
    if (!r.success) {
        for (const auto& root : trust.ca_roots) {
            std::vector<x509::x509_cert> full = server_chain;
            full.push_back(root);
            r = x509::x509_verify_chain(full);
            if (r.success) break;
        }
    }
    if (!r.success) return false;
    return tls13_hostname_matches(server_chain.front(), hostname);
}

// 用解析出�?x509 叶子证书构�?tls_certificate（只填公钥，用于 CertificateVerify 验证�?
std::unique_ptr<tls_certificate> tls_cert_from_x509_leaf(const x509::x509_cert& leaf) {
    auto out = jpssl::make_unique<tls_certificate>();
    out->subject_name = leaf.common_name();
    out->sig_alg = tls_key_type_to_sig_alg(leaf.key_type);
    if (!fill_pub(*out, leaf.key_type, leaf.public_key)) return nullptr;
    return out;
}

// ══════════════════════════════════════════════════════════════════════�?
//  TLS 1.3 加密握手消息（用�?EncryptedExtensions 之后的所有消息）
// ══════════════════════════════════════════════════════════════════════�?
std::vector<uint8_t> tls_encrypt_handshake(tls_session& s, const uint8_t* hs_msg, size_t hs_len){
    bool is_svr=s.is_server;
    const uint8_t* write_key=is_svr?s.server_write_key:s.client_write_key;
    const uint8_t* write_iv=is_svr?s.server_write_iv:s.client_write_iv;
    uint64_t& seq=is_svr?s.server_seq:s.client_seq;

    // RFC 8446 5.2：TLSInnerPlaintext = content || padding || type（type 只在末尾�?
    std::vector<uint8_t> inner;
    inner.insert(inner.end(),hs_msg,hs_msg+hs_len);
    inner.push_back((uint8_t)ContentType::HANDSHAKE);

    uint8_t nonce[12];memcpy(nonce,write_iv,12);
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(seq>>(56-i*8));
    ++seq;

    std::vector<uint8_t> record;
    record.push_back(0x17); // application_data (TLS 1.3 统一使用)
    record.push_back(0x03);record.push_back(0x03);
    size_t tag_len=tls_aead_tag_len(s.cipher_suite);
    size_t rlen=inner.size()+tag_len;
    record.push_back((uint8_t)(rlen>>8));record.push_back((uint8_t)rlen);

    // RFC 8446 5.2：TLS 1.3 AEAD �?additional_data (AAD) = record �?5 字节
    uint8_t aad[5]={0x17,0x03,0x03,(uint8_t)(rlen>>8),(uint8_t)rlen};
    jpssl::span<const uint8_t> aad_span(aad,5);

    std::vector<uint8_t> ciphertext;uint8_t tag[16];
    // RFC 8446 5.2：TLS 1.3 握手记录与应用程序记录使用相同的 AEAD 构造，
    // 必须按套件分发（此前 ChaCha20/CCM 误走 AES-GCM/SM4-GCM 分支）�?    
switch(s.cipher_suite){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384: {
            aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
            aes_gcm_encrypt_auto(ctx,nonce,12,inner,aad_span,ciphertext,tag,16);
            break;
        }
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            chacha20_poly1305_encrypt(write_key, nonce, inner, aad_span, ciphertext, tag);
            break;
        case CipherSuite::TLS_AES_128_CCM_SHA256:
        case CipherSuite::TLS_AES_128_CCM_8_SHA256: {
            aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
            aes_ccm_encrypt(ctx, nonce, 12, inner, aad_span, ciphertext, tag, tag_len);
            break;
        }
        case CipherSuite::TLS_SM4_GCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, write_key);
            sm4_gcm_encrypt(&s.sm4,nonce,12,inner,aad_span,ciphertext,tag,16);
            break;
        }
        case CipherSuite::TLS_SM4_CCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, write_key);
            sm4_ccm_encrypt(&s.sm4, nonce, 12, inner, aad_span, ciphertext, tag, 16);
            break;
        }
    }
    record.insert(record.end(),ciphertext.begin(),ciphertext.end());
    record.insert(record.end(),tag,tag+tag_len);
    return record;
}

// 解密握手消息，返回内�?handshake 数据
bool tls13_decrypt_handshake(tls_session& s, const uint8_t* record, size_t record_len, std::vector<uint8_t>& hs_out){
    if(record_len<5)return false;
    bool is_svr=s.is_server;
    const uint8_t* read_key=is_svr?s.client_write_key:s.server_write_key;
    const uint8_t* read_iv=is_svr?s.client_write_iv:s.server_write_iv;
    uint64_t& seq=is_svr?s.client_seq:s.server_seq;

    size_t rlen=(record[3]<<8)|record[4];
    if(5+rlen!=record_len)return false;
    const uint8_t* ciphertext=record+5;
    size_t tag_len=tls_aead_tag_len(s.cipher_suite);
    if(rlen<tag_len)return false;
    size_t ct_len=rlen-tag_len;
    const uint8_t* tag=record+5+ct_len;

    uint8_t nonce[12];memcpy(nonce,read_iv,12);
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(seq>>(56-i*8));
    ++seq;

    std::vector<uint8_t> inner;
    bool ok = false;
    // RFC 8446 5.2：AAD = record �?5 字节
    jpssl::span<const uint8_t> aad_span(record,5);
    switch(s.cipher_suite){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384: {
            aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
            ok = aes_gcm_decrypt_auto(ctx,nonce,12,jpssl::span<const uint8_t>(ciphertext,ct_len),aad_span,tag,16,inner);
            break;
        }
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            ok = chacha20_poly1305_decrypt(read_key, nonce,
                                           jpssl::span<const uint8_t>(ciphertext,ct_len),
                                           aad_span, tag, inner);
            break;
        case CipherSuite::TLS_AES_128_CCM_SHA256:
        case CipherSuite::TLS_AES_128_CCM_8_SHA256: {
            aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
            ok = aes_ccm_decrypt(ctx, nonce, 12,
                                 jpssl::span<const uint8_t>(ciphertext,ct_len),
                                 aad_span, tag, tag_len, inner);
            break;
        }
        case CipherSuite::TLS_SM4_GCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, read_key);
            ok = sm4_gcm_decrypt(&s.sm4,nonce,12,jpssl::span<const uint8_t>(ciphertext,ct_len),aad_span,tag,16,inner);
            break;
        }
        case CipherSuite::TLS_SM4_CCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, read_key);
            ok = sm4_ccm_decrypt(&s.sm4, nonce, 12,
                                 jpssl::span<const uint8_t>(ciphertext,ct_len),
                                 aad_span, tag, 16, inner);
            break;
        }
    }
    if(!ok) return false;

    if(inner.empty() || inner.back()!=(uint8_t)ContentType::HANDSHAKE)return false;
    hs_out.assign(inner.begin(),inner.end()-1);
    return true;
}
bool tls12_is_ecdhe(CipherSuite cs){
    switch(cs){
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return true;
        default: return false;
    }
}

// 判断是否 DHE（DHE_RSA / DHE_PSK�?
bool tls12_is_dhe(CipherSuite cs){
    switch(cs){
        case CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return true;
        default: return false;
    }
}

// 是否 PSK 套件（PSK / DHE_PSK�?
bool tls12_is_psk(CipherSuite cs){
    switch(cs){
        case CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite::TLS_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
        case CipherSuite::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
        case CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return true;
        default: return false;
    }
}

// 是否�?PSK（无 DHE�?
static bool tls12_is_psk_only(CipherSuite cs){
    return tls12_is_psk(cs) && !tls12_is_dhe(cs);
}

// 是否 DHE_PSK
bool tls12_is_dhe_psk(CipherSuite cs){
    return tls12_is_psk(cs) && tls12_is_dhe(cs);
}

// 是否 DHE_RSA（证书签名的 DHE�?
bool tls12_is_dhe_rsa(CipherSuite cs){
    return tls12_is_dhe(cs) && !tls12_is_psk(cs);
}

// 需�?ServerKeyExchange 的套�?
static bool tls12_needs_skx(CipherSuite cs){
    return tls12_is_ecdhe(cs) || tls12_is_dhe(cs);
}

// 是否 TLS 1.2 ChaCha20-Poly1305 套件（RFC 7905：fixed_iv_length=12，无显式 nonce）
static bool tls12_is_chacha(CipherSuite cs){
    return cs == CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        || cs == CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        || cs == CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        || cs == CipherSuite::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
        || cs == CipherSuite::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256;
}

//  TLS 1.2 PRF (P_SHA256)
// ══════════════════════════════════════════════════════════════════════�?
void tls12_prf(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len, uint8_t* out, size_t out_len){
    size_t label_len=strlen(label);
    std::vector<uint8_t> full_seed(label_len+seed_len);
    memcpy(full_seed.data(),label,label_len);
    memcpy(full_seed.data()+label_len,seed,seed_len);
    uint8_t a[32],tmp[32];
    hmac_sha256(secret,secret_len,full_seed.data(),full_seed.size(),a);
    size_t generated=0;
    while(generated<out_len){
        std::vector<uint8_t> buf(32+full_seed.size());memcpy(buf.data(),a,32);memcpy(buf.data()+32,full_seed.data(),full_seed.size());
        hmac_sha256(secret,secret_len,buf.data(),32+full_seed.size(),tmp);
        size_t n=(out_len-generated<32)?out_len-generated:32;
        memcpy(out+generated,tmp,n);generated+=n;
        hmac_sha256(secret,secret_len,a,32,a);
    }
}


// TLS 1.2 PRF (P_SHA384) �?for SHA-384 based cipher suites
void tls12_prf_sha384(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len, uint8_t* out, size_t out_len){
    size_t label_len=strlen(label);
    std::vector<uint8_t> full_seed(label_len+seed_len);
    memcpy(full_seed.data(),label,label_len);
    memcpy(full_seed.data()+label_len,seed,seed_len);
    uint8_t a[48],tmp[48];
    hmac_sha384(secret,secret_len,full_seed.data(),full_seed.size(),a);
    size_t generated=0;
    while(generated<out_len){
        std::vector<uint8_t> buf(48+full_seed.size());memcpy(buf.data(),a,48);memcpy(buf.data()+48,full_seed.data(),full_seed.size());
        hmac_sha384(secret,secret_len,buf.data(),48+full_seed.size(),tmp);
        size_t n=(out_len-generated<48)?out_len-generated:48;
        memcpy(out+generated,tmp,n);generated+=n;
        hmac_sha384(secret,secret_len,a,48,a);
    }
}
// ══════════════════════════════════════════════════════════════════════�?
//  TLS 1.2 密钥派生
// ══════════════════════════════════════════════════════════════════════�?
void tls12_derive_keys(tls_session& s, const uint8_t* pre_master, size_t pms_len){
    s.ver=TLSVersion::V12;
    bool use_sha384 = tls_use_sha384(s.cipher_suite);
    if (pms_len == 0) pms_len = 48;  // 兼容旧调用（RSA premaster 48 字节�?
    uint8_t seed[64];memcpy(seed,s.client_random,32);memcpy(seed+32,s.server_random,32);
    if(use_sha384) tls12_prf_sha384(pre_master,pms_len,"master secret",seed,64,s.master_secret,48);
    else tls12_prf(pre_master,pms_len,"master secret",seed,64,s.master_secret,48);
    // RFC 5288/7905：AES-128-GCM 16 字节 key、AES-256-GCM �?ChaCha20-Poly1305 32 字节 key
    size_t key_len = aes_key_len(s.cipher_suite);
    bool is_chacha = tls12_is_chacha(s.cipher_suite);
    bool is_cbc = tls12_is_cbc(s.cipher_suite);
    // key_block 布局（RFC 5246 6.3 / RFC 5288 / RFC 7905）：
    //   AES-CBC：c_mac||s_mac||c_key||s_key||c_iv(16)||s_iv(16)
    //     （MAC secret 长度 = hash 长度：SHA-256 32 / SHA-384 48）
    //   AES-GCM（RFC 5288）：c_key||s_key||c_iv(4)||s_iv(4)
    //   ChaCha20-Poly1305（RFC 7905）：c_key(32)||s_key(32)||c_iv(12)||s_iv(12)
    // CBC SHA-384 最大需要 48+48+32+32+16+16 = 192 字节
    uint8_t key_block[192];
    size_t mac_len = use_sha384 ? 48 : 32;
    size_t kb_len = is_chacha ? 88 : (is_cbc ? 2*mac_len + 2*key_len + 32 : 72);
    uint8_t exp_seed[64];memcpy(exp_seed,s.server_random,32);memcpy(exp_seed+32,s.client_random,32);
    if(use_sha384) tls12_prf_sha384(s.master_secret,48,"key expansion",exp_seed,64,key_block,kb_len);
    else tls12_prf(s.master_secret,48,"key expansion",exp_seed,64,key_block,kb_len);
    if(is_chacha){
        memcpy(s.client_write_key,key_block,key_len);
        memcpy(s.server_write_key,key_block+key_len,key_len);
        // RFC 7905：fixed_iv_length=12，record_iv_length=0（nonce 隐式，无显式部分）
        memcpy(s.client_write_iv,key_block+key_len*2,12);
        memcpy(s.server_write_iv,key_block+key_len*2+12,12);
    }else if(is_cbc){
        // RFC 5246 6.3：key_block 先排 client/server MAC secret，
        // 再排 client/server 加密 key，最后是 16 字节 CBC IV
        memcpy(s.client_write_mac,key_block,mac_len);
        memcpy(s.server_write_mac,key_block+mac_len,mac_len);
        memcpy(s.client_write_key,key_block+2*mac_len,key_len);
        memcpy(s.server_write_key,key_block+2*mac_len+key_len,key_len);
        memcpy(s.client_write_iv,key_block+2*mac_len+2*key_len,16);
        memcpy(s.server_write_iv,key_block+2*mac_len+2*key_len+16,16);
    }else{
        memcpy(s.client_write_key,key_block,key_len);
        memcpy(s.server_write_key,key_block+key_len,key_len);
        // RFC 5288：fixed_iv_length=4，后 8 字节为逐记录显式 nonce 占位（置零）
        memcpy(s.client_write_iv,key_block+key_len*2,4);
        memcpy(s.server_write_iv,key_block+key_len*2+4,4);
        memset(s.client_write_iv+4,0,8);
        memset(s.server_write_iv+4,0,8);
    }
    s.client_seq=0;s.server_seq=0;
    init_cipher_ctx(s, s.client_write_key);
}

// PSK premaster：uint16(other_len) || other || uint16(psk_len) || psk
// 纯 PSK 时 other=nullptr：OpenSSL 4.0 在 ssl_generate_master_secret 中规定
// "For plain PSK 'other_secret' is psklen zeroes"，即 other_len=psk_len 且
// other 为 psk_len 个零字节（RFC 4279 原义是零长度 other_secret，但为与
// OpenSSL 互操作必须采用 psklen 个零字节的格式）。
std::vector<uint8_t> tls12_psk_premaster(const uint8_t* psk, size_t psk_len,
                                                const uint8_t* other, size_t other_len){
    std::vector<uint8_t> pms;
    if (other == nullptr) {
        // 纯 PSK：other_secret = psk_len 个零字节（OpenSSL 4.0 格式）
        pms.push_back((uint8_t)(psk_len >> 8)); pms.push_back((uint8_t)psk_len);
        pms.insert(pms.end(), psk_len, 0);
    } else {
        pms.push_back((uint8_t)(other_len >> 8)); pms.push_back((uint8_t)other_len);
        pms.insert(pms.end(), other, other + other_len);
    }
    pms.push_back((uint8_t)(psk_len >> 8)); pms.push_back((uint8_t)psk_len);
    pms.insert(pms.end(), psk, psk + psk_len);
    return pms;
}

// ══════════════════════════════════════════════════════════════════════�?
//  记录层加�?
// ══════════════════════════════════════════════════════════════════════�?
static void tls_encrypt_record(tls_session& s, ContentType ct,
                               const uint8_t* data, size_t len,
                               std::vector<uint8_t>& out);

std::vector<uint8_t> tls_encrypt(tls_session& s, ContentType ct, const uint8_t* data, size_t len){
    // 大消息自动分片：len > TLS_MAX_RECORD_PLAINTEXT 时拆分为多条 record�?
    // 拼接后一次性返回（对端可用 tls_decrypt / tls_connection::recv 合并还原）�?
    std::vector<uint8_t> out;
    // 预预留：每条 record �?5 字节�?+ 2 内容类型 + 16 tag（TLS 1.2 另有 8 显式 nonce），
    // �?len + records*32 上界，避免输出向量反复扩容拷�?
    size_t records = (len + TLS_MAX_RECORD_PLAINTEXT - 1) / TLS_MAX_RECORD_PLAINTEXT;
    out.reserve(len + records * 32);
    size_t off = 0;
    do {
        size_t n = std::min(TLS_MAX_RECORD_PLAINTEXT, len - off);
        tls_encrypt_record(s, ct, data + off, n, out);
        if (out.empty()) return {};
        off += n;
    } while (off < len);
    return out;
}

// 加密单条 record（len 必须 <= TLS_MAX_RECORD_PLAINTEXT�?
static void tls_encrypt_record(tls_session& s, ContentType ct, const uint8_t* data, size_t len,
                               std::vector<uint8_t>& out){
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
        uint8_t aad[13];
        for(int i=0;i<8;++i)aad[7-i]=(uint8_t)(seq>>(i*8));
        aad[8]=(uint8_t)ct;
        aad[9]=0x03;aad[10]=0x03;
        // RFC 5246 6.2.3.3：TLS 1.2 AEAD 明文 = �?content（content type �?record 头明文传输）
        // AAD = seq(8) || type(1) || version(2) || length(2)，length 为明文长�?len
        size_t inner_len=len;
        aad[11]=(uint8_t)(inner_len>>8);aad[12]=(uint8_t)inner_len;
        bool is_chacha_tls12 = tls12_is_chacha(s.cipher_suite);
        bool is_cbc = tls12_is_cbc(s.cipher_suite);
        if(is_chacha_tls12){
            // ChaCha20-Poly1305 in TLS 1.2（RFC 7905）：fixed_iv_length=12，record_iv_length=0�?            // nonce = client/server_write_IV(12) XOR 序列号（�?4 字节 0x00 + 8 字节大端序列号）�?
            // 记录中不携带显式 nonce —�?�?AES-GCM�? 字节显式 nonce）结构不同�?
            uint8_t cha_nonce[12];
            memcpy(cha_nonce, write_iv, 12);
            for (int i = 0; i < 8; ++i) cha_nonce[4+i] ^= explicit_nonce[i]; // explicit_nonce 携带序列�?
            out.push_back((uint8_t)ct);
            out.push_back(0x03);out.push_back(0x03);
            size_t inner_len=len;
            size_t rlen=inner_len+16;
            out.push_back((uint8_t)(rlen>>8));out.push_back((uint8_t)rlen);
            size_t body=out.size();
            out.resize(body+inner_len+16);
            std::memcpy(out.data()+body, data, len);
            chacha20_poly1305_encrypt_inplace(write_key, cha_nonce, out.data()+body,
                                              inner_len, jpssl::span<const uint8_t>(aad, 13),
                                              out.data()+body+inner_len);
        }else if(is_cbc){
            // RFC 5246 6.2.3.2 CBC suite:
            //   MAC = HMAC(mac_secret, seq(8) || type(1) || ver(2) || length(2) || content)
            //   length = content length only (RFC 5246 6.2.3.1), MAC/padding excluded
            //   plaintext = content || MAC || padding(N x N) || padding_length(N)
            //   record = header || explicit_IV(16) || AES-CBC(plaintext)
            size_t MAC_LEN = tls_use_sha384(s.cipher_suite) ? 48 : 32;
            const uint8_t* mac_key = is_svr ? s.server_write_mac : s.client_write_mac;
            aad[11] = (uint8_t)(len >> 8); aad[12] = (uint8_t)len;
            std::vector<uint8_t> mac_input(13 + len);
            memcpy(mac_input.data(), aad, 13);
            memcpy(mac_input.data() + 13, data, len);
            uint8_t mac[48];
            if (tls_use_sha384(s.cipher_suite))
                hmac_sha384(mac_key, MAC_LEN, mac_input.data(), mac_input.size(), mac);
            else
                hmac_sha256(mac_key, MAC_LEN, mac_input.data(), mac_input.size(), mac);
            // explicit IV: random 16 bytes per record (TLS 1.1+)
            uint8_t explicit_iv[16];
            uint8_t rnd32[32];
            rand32(rnd32);
            memcpy(explicit_iv, rnd32, 16);
            // TLS 1.2 padding: pad_len bytes of value pad_len plus a final pad_len byte,
            // so that content || MAC || padding is a multiple of the block size
            size_t mac_total = len + MAC_LEN;
            size_t pad_len = (16 - ((mac_total + 1) % 16)) % 16;
            std::vector<uint8_t> plaintext;
            plaintext.reserve(mac_total + pad_len + 1);
            plaintext.insert(plaintext.end(), data, data + len);
            plaintext.insert(plaintext.end(), mac, mac + MAC_LEN);
            plaintext.insert(plaintext.end(), pad_len, (uint8_t)pad_len);
            plaintext.push_back((uint8_t)pad_len);
            aes_context ctx;
            aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
            std::vector<uint8_t> ciphertext;
            if(plaintext.size() % 16 != 0) return;
            ciphertext.resize(plaintext.size());
            tls_cbc_encrypt_blocks(ctx, explicit_iv, plaintext.data(),
                                   plaintext.size() / 16, ciphertext.data());
            out.push_back((uint8_t)ct);
            out.push_back(0x03); out.push_back(0x03);
            size_t rlen = 16 + ciphertext.size();
            out.push_back((uint8_t)(rlen >> 8)); out.push_back((uint8_t)rlen);
            out.insert(out.end(), explicit_iv, explicit_iv + 16);
            out.insert(out.end(), ciphertext.begin(), ciphertext.end());

        }else{
            aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
            out.push_back((uint8_t)ct);
            out.push_back(0x03);out.push_back(0x03);
            size_t rlen=8+inner_len+16;
            out.push_back((uint8_t)(rlen>>8));out.push_back((uint8_t)rlen);
            out.insert(out.end(),explicit_nonce,explicit_nonce+8);
            size_t body=out.size();
            out.resize(body+inner_len+16);
            std::memcpy(out.data()+body, data, len);
            aes_gcm_encrypt_inplace(ctx, nonce, 12, out.data()+body, inner_len,
                                    jpssl::span<const uint8_t>(aad, 13),
                                    out.data()+body+inner_len, 16);
        }
        return;
    }
    const uint8_t* write_iv=is_svr?s.server_write_iv:s.client_write_iv;
    const uint8_t* write_key=is_svr?s.server_write_key:s.client_write_key;
    uint8_t nonce[12];memcpy(nonce,write_iv,12);
    uint64_t seq=is_svr?s.server_seq:s.client_seq;
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(seq>>(56-i*8));
    if(is_svr)++s.server_seq;else ++s.client_seq;
    size_t tag_len=tls_aead_tag_len(s.cipher_suite);
    switch(s.cipher_suite){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384: {
            aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
            size_t inner_len=len+1;  // content || type
            size_t rlen=inner_len+tag_len;
            out.push_back(0x17);out.push_back(0x03);out.push_back(0x03);
            out.push_back((uint8_t)(rlen>>8));out.push_back((uint8_t)rlen);
            size_t body=out.size();
            out.resize(body+inner_len+tag_len);
            std::memcpy(out.data()+body, data, len);
            out[body+len]=(uint8_t)ct;
            uint8_t aad[5]={0x17,0x03,0x03,(uint8_t)(rlen>>8),(uint8_t)rlen};
            aes_gcm_encrypt_inplace(ctx, nonce, 12, out.data()+body, inner_len,
                                    jpssl::span<const uint8_t>(aad,5),
                                    out.data()+body+inner_len, 16);
            return;
        }
        default: {
            size_t inner_len=len+1;  // content || type
            size_t rlen=inner_len+tag_len;
            out.push_back(0x17);out.push_back(0x03);out.push_back(0x03);
            out.push_back((uint8_t)(rlen>>8));out.push_back((uint8_t)rlen);
            size_t body=out.size();
            out.resize(body+inner_len+tag_len);
            std::memcpy(out.data()+body, data, len);
            out[body+len]=(uint8_t)ct;
            uint8_t* inner=out.data()+body;
            uint8_t* tag=out.data()+body+inner_len;
            uint8_t aad[5]={0x17,0x03,0x03,(uint8_t)(rlen>>8),(uint8_t)rlen};
            jpssl::span<const uint8_t> aad_span(aad,5);
            switch(s.cipher_suite){
                case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
                    chacha20_poly1305_encrypt_inplace(write_key, nonce, inner, inner_len,
                                                      aad_span, tag);
                    break;
                case CipherSuite::TLS_AES_128_CCM_SHA256:
                case CipherSuite::TLS_AES_128_CCM_8_SHA256: {
                    aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
                    aes_ccm_encrypt_inplace(ctx, nonce, 12, inner, inner_len,
                                            aad_span, tag, tag_len);
                    break;
                }
                case CipherSuite::TLS_SM4_GCM_SM3: {
                    sm4_ctx_init_from_key(s.sm4, write_key);
                    sm4_gcm_encrypt_inplace(&s.sm4, nonce, 12, inner, inner_len,
                                            aad_span, tag, 16);
                    break;
                }
                case CipherSuite::TLS_SM4_CCM_SM3: {
                    sm4_ctx_init_from_key(s.sm4, write_key);
                    sm4_ccm_encrypt_inplace(&s.sm4, nonce, 12, inner, inner_len,
                                            aad_span, tag, 16);
                    break;
                }
            }
            return;
        }
    }
    return;
}

// decrypt a single record (record buffer is exactly one record: 5-byte header + payload)
static bool tls_decrypt_one(tls_session& s, const uint8_t* record, size_t record_len,
                            ContentType& ct, std::vector<uint8_t>& out){
    bool is_svr=s.is_server;
    if(record_len<5)return false;
    if(s.ver==TLSVersion::V12){
        size_t rlen=(record[3]<<8)|record[4];
        const uint8_t* read_iv=is_svr?s.client_write_iv:s.server_write_iv;
        const uint8_t* read_key=is_svr?s.client_write_key:s.server_write_key;
        bool is_chacha_tls12 = tls12_is_chacha(s.cipher_suite);
        bool is_cbc = tls12_is_cbc(s.cipher_suite);
        // RFC 7905: ChaCha20-Poly1305 records carry no explicit nonce (record_iv_length=0),
        // payload = ciphertext || tag(16), unlike AES-GCM which uses an 8-byte explicit nonce
        const uint8_t* ciphertext = is_chacha_tls12 ? record+5 : (is_cbc ? record+21 : record+13);
        size_t ct_len = is_chacha_tls12 ? rlen-16 : (is_cbc ? rlen-16 : rlen-24);
        const uint8_t* tag = ciphertext + ct_len;
        if(5+rlen!=record_len)return false;
        if(is_cbc){
            if(ct_len<16 || (ct_len % 16) != 0) return false;
        }else if(ct_len<1){
            return false;
        }
        uint64_t seq=is_svr?s.client_seq:s.server_seq;
        uint8_t aad[13];
        for(int i=0;i<8;++i)aad[7-i]=(uint8_t)(seq>>(i*8));
        aad[8]=record[0];
        aad[9]=0x03;aad[10]=0x03;
        aad[11]=(uint8_t)(ct_len>>8);
        aad[12]=(uint8_t)ct_len;
        if(is_svr)++s.client_seq;else ++s.server_seq;
        std::vector<uint8_t> inner;
        if(is_chacha_tls12){
            // nonce = write_IV(12) XOR sequence number (RFC 7905 4.1)
            uint8_t cha_nonce[12];
            memcpy(cha_nonce, read_iv, 12);
            for (int i = 0; i < 8; ++i) cha_nonce[4+i] ^= (uint8_t)(seq >> (56 - i*8));
            if(!chacha20_poly1305_decrypt(read_key, cha_nonce,
                    jpssl::span<const uint8_t>(ciphertext,ct_len),
                    jpssl::span<const uint8_t>(aad,13), tag, inner)) return false;
        }else if(is_cbc){
            // RFC 5246 6.2.3.2: explicit IV(16) || AES-CBC(content || MAC || padding)
            const uint8_t* explicit_iv = record + 5;
            aes_context ctx;
            aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
            if(ct_len < 16 || (ct_len % 16) != 0) return false;
            std::vector<uint8_t> raw(ct_len);
            tls_cbc_decrypt_blocks(ctx, explicit_iv, ciphertext, ct_len / 16, raw.data());
            size_t mac_len = tls_use_sha384(s.cipher_suite) ? 48 : 32;
            const uint8_t* mac_key = is_svr ? s.client_write_mac : s.server_write_mac;
            uint8_t pad_n = raw.back();
            // TLS 1.2 padding: pad_n bytes of value pad_n plus a final pad_n byte;
            // at least 1 content byte must remain after MAC + padding removal
            if(pad_n > 15 || raw.size() < (size_t)pad_n + 1 + mac_len + 1) return false;
            size_t inner_len = raw.size() - pad_n - 1 - mac_len;
            // RFC 5246 6.2.3.1: MAC length field = content length (excl. MAC/padding)
            aad[11] = (uint8_t)(inner_len >> 8); aad[12] = (uint8_t)inner_len;
            std::vector<uint8_t> mac_input(13 + inner_len);
            memcpy(mac_input.data(), aad, 13);
            memcpy(mac_input.data() + 13, raw.data(), inner_len);
            uint8_t mac[48];
            if (tls_use_sha384(s.cipher_suite))
                hmac_sha384(mac_key, mac_len, mac_input.data(), mac_input.size(), mac);
            else
                hmac_sha256(mac_key, mac_len, mac_input.data(), mac_input.size(), mac);
            if(std::memcmp(mac, raw.data() + inner_len, mac_len) != 0) return false;
            inner.assign(raw.begin(), raw.begin() + inner_len);
        }else{
            uint8_t nonce[12];
            memcpy(nonce,read_iv,4);
            memcpy(nonce+4,record+5,8);  // GCM explicit nonce
            aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
            if(!aes_gcm_decrypt_auto(ctx,nonce,12,jpssl::span<const uint8_t>(ciphertext,ct_len),jpssl::span<const uint8_t>(aad,13),tag,16,inner))
                return false;
        }
        if(inner.empty())return false;
        // RFC 5246: content type is in the record header; AEAD plaintext is pure content
        ct=(ContentType)record[0];
        out.swap(inner);
        return true;
    }
    size_t rlen=(record[3]<<8)|record[4];
    size_t tag_len=tls_aead_tag_len(s.cipher_suite);
    if(5+rlen!=record_len||rlen<tag_len)return false;
    const uint8_t* ciphertext=record+5;
    size_t ct_len=rlen-tag_len;
    const uint8_t* tag=record+5+ct_len;
    const uint8_t* read_iv=is_svr?s.client_write_iv:s.server_write_iv;
    const uint8_t* read_key=is_svr?s.client_write_key:s.server_write_key;
    uint8_t nonce[12];memcpy(nonce,read_iv,12);
    uint64_t seq=is_svr?s.client_seq:s.server_seq;
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(seq>>(56-i*8));
    if(is_svr)++s.client_seq;else ++s.server_seq;
    std::vector<uint8_t> inner;
    bool ok = false;
    // RFC 8446 5.2：TLS 1.3 AEAD AAD = record �?5 字节
    jpssl::span<const uint8_t> aad_span(record,5);
    switch(s.cipher_suite){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384: {
            aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
            ok = aes_gcm_decrypt_auto(ctx,nonce,12,jpssl::span<const uint8_t>(ciphertext,ct_len),aad_span,tag,16,inner);
            break;
        }
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            ok = chacha20_poly1305_decrypt(read_key, nonce,
                                           jpssl::span<const uint8_t>(ciphertext,ct_len),
                                           aad_span, tag, inner);
            break;
        case CipherSuite::TLS_AES_128_CCM_SHA256:
        case CipherSuite::TLS_AES_128_CCM_8_SHA256: {
            aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
            ok = aes_ccm_decrypt(ctx, nonce, 12,
                                 jpssl::span<const uint8_t>(ciphertext,ct_len),
                                 aad_span, tag, tag_len, inner);
            break;
        }
        case CipherSuite::TLS_SM4_GCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, read_key);
            ok = sm4_gcm_decrypt(&s.sm4, nonce, 12,
                                 jpssl::span<const uint8_t>(ciphertext,ct_len),
                                 aad_span, tag, 16, inner);
            break;
        }
        case CipherSuite::TLS_SM4_CCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, read_key);
            ok = sm4_ccm_decrypt(&s.sm4, nonce, 12,
                                 jpssl::span<const uint8_t>(ciphertext,ct_len),
                                 aad_span, tag, 16, inner);
            break;
        }
    }
    if(!ok) return false;
    if(inner.empty())return false;
    // RFC 8446 5.2：type 在末�?
    ct=(ContentType)inner.back();
    out.assign(inner.begin(),inner.end()-1);
    return true;
}

bool tls_decrypt(tls_session& s, const uint8_t* record, size_t record_len,
                 ContentType& ct, std::vector<uint8_t>& out){
    // 大消息合并：逐条解析 record，明文追加到 out（单�?record 同样支持�?
    out.clear();
    out.reserve(record_len);  // 明文总长 �?密文总长，预预留避免反复扩容
    size_t off = 0;
    bool any = false;
    ContentType first_ct = ContentType::APPLICATION_DATA;
    while (off < record_len) {
        if (record_len - off < 5) return false;  // 尾部残留不完�?record
        size_t rlen = ((size_t)record[off + 3] << 8) | record[off + 4];
        if (rlen < tls_aead_tag_len(s.cipher_suite) || 5 + rlen > record_len - off) return false;
        ContentType rec_ct;
        std::vector<uint8_t> plain;
        if (!tls_decrypt_one(s, record + off, 5 + rlen, rec_ct, plain)) return false;
        if (!any) first_ct = rec_ct;
        any = true;
        out.insert(out.end(), plain.begin(), plain.end());
        off += 5 + rlen;
    }
    ct = first_ct;
    return any;
}



// ══════════════════════════════════════════════════════════════════════�?
//  TLS 1.3 0-RTT �?PSK, Early Data, NewSessionTicket
// ══════════════════════════════════════════════════════════════════════�?

void tls13_derive_resumption_secret(tls_session& s, uint8_t out[48]){
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

void tls13_derive_early_traffic_keys(tls_session& s, const uint8_t* psk){
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

void tls13_compute_binder(tls_session& s, const uint8_t* psk,
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

// ══�?X.509 v3 Integration ══�?
using namespace jpssl::x509;

x509::KeyType tls_sig_alg_to_key_type(SignatureAlgorithm sa) {
    switch (sa) {
        case SignatureAlgorithm::RSA_PKCS1_SHA256:
        case SignatureAlgorithm::RSA_PKCS1_SHA384:
        case SignatureAlgorithm::RSA_PKCS1_SHA512:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA256:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA384:
        case SignatureAlgorithm::RSA_PSS_RSAE_SHA512:
            return KeyType::RSA_2048;
        case SignatureAlgorithm::ED25519: return KeyType::Ed25519;
        case SignatureAlgorithm::ED448: return KeyType::Ed448;
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256: return KeyType::ECDSA_P256;
        case SignatureAlgorithm::ECDSA_SECP384R1_SHA384: return KeyType::ECDSA_P384;
        case SignatureAlgorithm::ECDSA_SECP521R1_SHA512: return KeyType::ECDSA_P521;
        case SignatureAlgorithm::SM2_SM3: return KeyType::SM2;
        default: return KeyType::Ed25519;
    }
}
static x509::KeyType kt(SignatureAlgorithm sa) { return tls_sig_alg_to_key_type(sa); }

std::vector<uint8_t> tls_make_x509_self_signed(const tls_certificate& cert, uint32_t days) {
    x509_builder b; auto k = kt(cert.sig_alg);
    DistinguishedName dn; dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + 3), cert.subject_name});
    b.set_subject(dn).set_issuer(dn);
    uint8_t ser[8]={}; for(size_t i=0;i<cert.subject_name.size()&&i<8;++i)ser[i]=(uint8_t)cert.subject_name[i];
    ser[0]|=0x01; b.set_serial(ser,8);
    uint64_t now=(uint64_t)time(nullptr); b.set_validity(now, now+(uint64_t)days*86400);
    switch(k){
        case KeyType::RSA_2048:{uint8_t p[259];cert.pub.rsa.n.to_bytes(p);p[256]=1;p[257]=0;p[258]=1;b.set_key(k,p,259);break;}
        case KeyType::RSA_4096:{uint8_t p[515];cert.pub.rsa.n.to_bytes(p);p[512]=1;p[513]=0;p[514]=1;b.set_key(k,p,515);break;}
        case KeyType::Ed25519:b.set_key(k,cert.pub.ed25519,32);break;
        case KeyType::Ed448:b.set_key(k,cert.pub.ed448,57);break;
        case KeyType::ECDSA_P256:b.set_key(k,cert.pub.ecdsa_p256,64);break;
        case KeyType::ECDSA_P384:b.set_key(k,cert.pub.ecdsa_p384,96);break;
        case KeyType::ECDSA_P521:b.set_key(k,cert.pub.ecdsa_p521,132);break;
        case KeyType::SM2:b.set_key(k,cert.pub.sm2,64);break;
    }
    b.set_ca(false).set_key_usage(KU_DIGITAL_SIGNATURE).set_server_auth().add_san_dns(cert.subject_name);
    x509_cert x;
    switch(k){
        case KeyType::RSA_2048:case KeyType::RSA_4096:{uint8_t d[512];cert.priv.rsa.d.to_bytes(d);x=b.build_and_sign(k,d,k==KeyType::RSA_4096?512:256);break;}
        case KeyType::Ed25519:x=b.build_and_sign(k,cert.priv.ed25519,64);break;
        case KeyType::Ed448:x=b.build_and_sign(k,cert.priv.ed448,57);break;
        case KeyType::ECDSA_P256:x=b.build_and_sign(k,cert.priv.ecdsa_p256,32);break;
        case KeyType::ECDSA_P384:x=b.build_and_sign(k,cert.priv.ecdsa_p384,48);break;
        case KeyType::ECDSA_P521:x=b.build_and_sign(k,cert.priv.ecdsa_p521,66);break;
        case KeyType::SM2:x=b.build_and_sign(k,cert.priv.sm2,32);break;
    }
    return x.to_der();
}

// ══════════════════════════════════════════════════════════════════════�?
//  TLS 1.2 消息构造辅助（服务端握手）
// ══════════════════════════════════════════════════════════════════════�?

// ChangeCipherSpec 记录（type=20, payload={0x01}），明文发�?
std::vector<uint8_t> tls_make_change_cipher_spec() {
    std::vector<uint8_t> m;
    m.push_back(20);            // ContentType::CHANGE_CIPHER_SPEC
    m.push_back(0x03); m.push_back(0x03);
    m.push_back(0); m.push_back(1);
    m.push_back(0x01);          // CCS payload
    return m;
}

// 生成 Finished 明文消息（verify_data 12 字节，RFC 5246 7.4.9�?
std::vector<uint8_t> tls12_make_finished(tls_session& s, bool for_server) {
    tls_transcript_finalize(s);
    uint8_t verify_data[12];
    size_t hl = tls_hash_len(s.cipher_suite);
    const char* label = for_server ? "server finished" : "client finished";
    if (tls_use_sha384(s.cipher_suite))
        tls12_prf_sha384(s.master_secret, 48, label, s.transcript_hash, hl, verify_data, 12);
    else
        tls12_prf(s.master_secret, 48, label, s.transcript_hash, hl, verify_data, 12);
    std::vector<uint8_t> m;
    m.push_back((uint8_t)HandshakeType::FINISHED);
    m.push_back(0); m.push_back(0); m.push_back(12);
    m.insert(m.end(), verify_data, verify_data + 12);
    return m;
}

// 验证 Finished 消息（对�?verify_data 12 字节�?
bool tls12_verify_finished(tls_session& s, const uint8_t* data, size_t len, bool for_server) {
    if (len < 16 || data[0] != (uint8_t)HandshakeType::FINISHED) return false;
    tls_transcript_finalize(s);
    uint8_t expected[12];
    size_t hl = tls_hash_len(s.cipher_suite);
    const char* label = for_server ? "server finished" : "client finished";
    if (tls_use_sha384(s.cipher_suite))
        tls12_prf_sha384(s.master_secret, 48, label, s.transcript_hash, hl, expected, 12);
    else
        tls12_prf(s.master_secret, 48, label, s.transcript_hash, hl, expected, 12);
    return memcmp(expected, data + 4, 12) == 0;
}

// ============================================================
//  版本选择（router）
// ============================================================
// 客户端：由 tls_connection::do_client_handshake 调用，根据调用方配置
// （set_tls_version）决定 TLS 1.2 / TLS 1.3 握手路径。
bool tls_router_client_use_tls12(TLSVersion configured) {
    return configured == TLSVersion::V12;
}

// 服务端：解析 ClientHello（含 4 字节 handshake 头）中的 supported_versions
// (0x002b) 扩展，判断客户端是否宣告支持 TLS 1.3（0x0304）。
// 仅支持 TLS 1.2 的客户端 legacy_version=0x0303 且无 supported_versions
// 或列表中只有 0x0303。
bool tls_router_server_supports_tls13(const uint8_t* client_hello, size_t ch_len) {
    // ClientHello 布局（RFC 5246/8446）：
    //   type(1)+len(3) | legacy_version(2) + random(32) + session_id_len(1)+session_id
    //   + cipher_suites_len(2)+cipher_suites + compression_len(1)+compression
    //   + extensions_len(2)+extensions
    if (!client_hello || ch_len < 4 + 2 + 32) return false;
    size_t o = 4 + 2 + 32;  // 跳过 version + random
    if (o + 1 > ch_len) return false;
    uint8_t sid_len = client_hello[o]; o += 1 + sid_len;
    if (o + 2 > ch_len) return false;
    uint16_t cs_len = (client_hello[o] << 8) | client_hello[o + 1]; o += 2 + cs_len;
    if (o + 1 > ch_len) return false;
    uint8_t comp_len = client_hello[o]; o += 1 + comp_len;
    if (o + 2 > ch_len) return false;
    uint16_t ext_total = (client_hello[o] << 8) | client_hello[o + 1]; o += 2;
    size_t ext_end = o + ext_total;
    if (ext_end > ch_len) return false;
    while (o + 4 <= ext_end) {
        uint16_t etype = (client_hello[o] << 8) | client_hello[o + 1];
        uint16_t elen = (client_hello[o + 2] << 8) | client_hello[o + 3];
        if (etype == 0x002b && elen >= 2 && o + 4 + elen <= ext_end) {
            uint8_t vlen = client_hello[o + 4];  // 版本列表字节数
            // 版本从 o+5 开始，每个 2 字节；vlen 首字节后还有 elen-1 字节
            for (uint8_t i = 0; i + 2 <= vlen && i + 3 <= elen; i += 2) {
                uint16_t v = (client_hello[o + 5 + i] << 8) | client_hello[o + 5 + i + 1];
                if (v == 0x0304) return true;
            }
        }
        o += 4 + elen;
    }
    return false;
}

} // namespace tls
} // namespace jpssl
