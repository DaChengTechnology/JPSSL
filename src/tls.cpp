#include "tls.hpp"
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

static const uint8_t RSA_SHA256_DIGEST_INFO[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

// 从系统 CSPRNG 读取 32 字节密码学安全随机数（Windows BCrypt / Linux urandom）
static void rand32(uint8_t* buf){
    if (!jpssl::os_rand_bytes(buf, 32))
        std::memset(buf, 0, 32);
}

static CipherSuite select_cipher_suite(uint16_t id){
    switch(id){
        case 0x1301: return CipherSuite::TLS_AES_128_GCM_SHA256;
        case 0x1302: return CipherSuite::TLS_AES_256_GCM_SHA384;
        case 0x1303: return CipherSuite::TLS_CHACHA20_POLY1305_SHA256;
        case 0x1304: return CipherSuite::TLS_AES_128_CCM_SHA256;
        case 0x00C6: return CipherSuite::TLS_SM4_GCM_SM3;
        case 0x00C7: return CipherSuite::TLS_SM4_CCM_SM3;
        case 0x009C: return CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256;
        case 0x009D: return CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384;
        case 0x003D: return CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256;
        case 0x003E: return CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256;
        case 0xC02B: return CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        case 0xC02C: return CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
        case 0xC02F: return CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        case 0xC030: return CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
        case 0xCCA8: return CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
        case 0xCCA9: return CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
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

static bool cipher_needs_sm4_ctx(CipherSuite cs){ return tls_use_sm4(cs); }
static void sm4_ctx_init_from_key(sm4_ctx& ctx, const uint8_t* key){ sm4_init(&ctx, key); }
static void init_cipher_ctx(tls_session& s, const uint8_t* key){
    if(cipher_needs_sm4_ctx(s.cipher_suite)) sm4_ctx_init_from_key(s.sm4, key);
    else aes_ctx_init(s.aes_ctx, key, aes_key_len(s.cipher_suite));
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

// 追加 signature_algorithms (0x000d) / signature_algorithms_cert (0x0032) 扩展
static void append_sig_alg_extension(std::vector<uint8_t>& ext, uint16_t type,
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

// 解析 SignatureSchemeList（2 字节长度 + 2*count 字节方案编码）
static bool parse_sig_alg_list(const uint8_t* p, size_t len, std::vector<uint16_t>& out) {
    if (len < 2) return false;
    size_t list_len = ((size_t)p[0] << 8) | p[1];
    if (2 + list_len != len || (list_len & 1)) return false;
    out.clear();
    for (size_t i = 0; i < list_len; i += 2)
        out.push_back((uint16_t)((p[2 + i] << 8) | p[2 + i + 1]));
    return true;
}

// 在 ClientHello 扩展区查找指定扩展
static bool client_hello_find_extension(const uint8_t* ch, size_t ch_len, uint16_t want,
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

// 客户端应广告的 signature_algorithms 列表（配置为空时用全量默认）
static std::vector<uint16_t> effective_sig_algs(const tls_session& s) {
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

static bool scheme_in_list(const std::vector<uint16_t>& list, uint16_t scheme) {
    for (uint16_t s : list) if (s == scheme) return true;
    return false;
}

// 服务端协商签名方案：按对端偏好序选择双方都支持且与证书密钥类型匹配的方案
static uint16_t select_signature_scheme(const std::vector<uint16_t>& peer_list,
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

// 证书链签名方案（用于 signature_algorithms_cert 校验）
// 优先解析证书 DER 中的签名算法；自签名证书回退到 sig_alg 映射
static uint16_t x509_key_type_chain_scheme(x509::KeyType kt) {
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

static uint16_t cert_chain_signature_scheme(const tls_certificate& cert) {
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

// ═══════════════════════════════════════════════════════════════════════
//  transcript 辅助
// ═══════════════════════════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════════════════════════
//  证书签名/验证
// ═══════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════
//  签名方案辅助（RFC 8446 §4.2.3 / RFC 8998）
// ═══════════════════════════════════════════════════════════════════════
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

// 哈希类方案对应的摘要长度；0 表示未知/非哈希类方案
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

// RSASSA-PKCS1-v1_5 签名（RSA-2048）
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

// RSASSA-PSS 签名（RSA-2048，saltLen = hLen，RFC 8446 要求）
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

// ═══════════════════════════════════════════════════════════════════════
//  证书签名/验证
// ═══════════════════════════════════════════════════════════════════════
bool tls_certificate::sign_scheme(uint16_t scheme, const uint8_t* data, size_t data_len,
                                   uint8_t* sig, size_t& sig_len,
                                   const uint8_t za[32]) const {
    switch ((SignatureAlgorithm)scheme) {
        case SignatureAlgorithm::ED25519:
            sig_len = 64; ed25519_sign(priv.ed25519, data, data_len, sig); return true;
        case SignatureAlgorithm::ED448:
            sig_len = 114; ed448_sign(priv.ed448, data, data_len, sig); return true;
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256:
            sig_len = 64; ecdsa_p256_sign(priv.ecdsa_p256, data, data_len, sig); return true;
        case SignatureAlgorithm::ECDSA_SECP384R1_SHA384:
            sig_len = 96; ecdsa_p384_sign(priv.ecdsa_p384, data, data_len, sig); return true;
        case SignatureAlgorithm::ECDSA_SECP521R1_SHA512:
            sig_len = 132; ecdsa_p521_sign(priv.ecdsa_p521, data, data_len, sig); return true;
        case SignatureAlgorithm::SM2_SM3:
            sig_len = 64; sm2_sign(priv.sm2, data, data_len, sig, za); return true;
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
        case SignatureAlgorithm::ECDSA_SECP256R1_SHA256:
            if (sig_len != 64) return false;
            return ecdsa_p256_verify(pub.ecdsa_p256, data, data_len, sig);
        case SignatureAlgorithm::ECDSA_SECP384R1_SHA384:
            if (sig_len != 96) return false;
            return ecdsa_p384_verify(pub.ecdsa_p384, data, data_len, sig);
        case SignatureAlgorithm::ECDSA_SECP521R1_SHA512:
            if (sig_len != 132) return false;
            return ecdsa_p521_verify(pub.ecdsa_p521, data, data_len, sig);
        case SignatureAlgorithm::SM2_SM3:
            if (sig_len != 64) return false;
            return sm2_verify(pub.sm2, data, data_len, sig, za);
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
//  服务端证书加载（PEM / CSR + 私钥）
// ═══════════════════════════════════════════════════════════════════════
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

// 用 x509 公钥 raw bytes 填充 tls_certificate.pub
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

// 用 x509 私钥 raw bytes 填充 tls_certificate.priv（RSA 需要私钥的 n||e 公钥）
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

// 从 CSR subject 提取 CN 作为证书主体名
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

// 解析 PEM 中全部证书块（CA bundle 可含多张）
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
    auto out = std::make_unique<tls_certificate>();
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
    auto out = std::make_unique<tls_certificate>();
    out->subject_name = csr_common_name(*req);
    // cert_data 留空：握手时按 CSR 主体自动生成自签名证书
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
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  // RHEL 备选
    "/etc/ssl/ca-bundle.pem",               // SUSE
    "/etc/ssl/cert.pem",                    // macOS (brew) / OpenBSD
    "/etc/ssl/certs/ca-bundle.crt",         // 部分发行版
    nullptr,
};

tls_trust_store tls_trust_store::from_system() {
    static tls_trust_store cached;
    static bool loaded = false;
    static std::mutex mtx;
    std::lock_guard<std::mutex> lock(mtx);
    if (loaded) return cached;

    // 1) SSL_CERT_FILE 环境变量优先
    if (const char* env = std::getenv("SSL_CERT_FILE"); env && env[0]) {
        auto ts = from_pem_file(env);
        if (!ts.empty()) { cached = std::move(ts); loaded = true; return cached; }
    }
    // 2) 常见系统路径
    for (const char* const* p = kSystemCaPaths; *p; ++p) {
        auto ts = from_pem_file(*p);
        if (!ts.empty()) { cached = std::move(ts); loaded = true; return cached; }
    }
    loaded = true;  // 缓存"未找到"结果，避免每次连接都探测
    return cached;
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
//  ALPN 解析与选择 (RFC 7301, 扩展类型 0x0010)
// ═══════════════════════════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.3 密钥派生
// ═══════════════════════════════════════════════════════════════════════
static void tls13_derive_handshake_keys(tls_session& s, const uint8_t* shared_secret, size_t shared_len){
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    bool use_sm3=tls_use_sm3(s.cipher_suite);
    uint8_t zero[48]={},early_secret[48],empty_hash[48];
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

    memcpy(s.client_write_key,ch_ts,hl);memcpy(s.server_write_key,sh_ts,hl);
    if(use384){
        hkdf_expand_label_sha384(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label_sha384(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }else if(use_sm3){
        hkdf_expand_label_sm3(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label_sm3(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }else{
        hkdf_expand_label(s.handshake_secret,"c hs traffic",s.transcript_hash,hl,s.client_write_iv,12);
        hkdf_expand_label(s.handshake_secret,"s hs traffic",s.transcript_hash,hl,s.server_write_iv,12);
    }
    s.client_seq=0;s.server_seq=0;
}

static void tls13_derive_application_keys(tls_session& s){
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    bool use_sm3=tls_use_sm3(s.cipher_suite);
    uint8_t zero[48]={};
    if(use384) hkdf_extract_sha384(s.handshake_secret,48,zero,48,s.master_secret);
    else if(use_sm3) hkdf_extract_sm3(s.handshake_secret,32,zero,32,s.master_secret);
    else hkdf_extract(s.handshake_secret,32,zero,32,s.master_secret);
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

static void tls13_derive_keys(tls_session& s, const uint8_t* shared_secret, size_t shared_len){
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

// ═══════════════════════════════════════════════════════════════════════
//  构建 Finished 消息
// ═══════════════════════════════════════════════════════════════════════
static std::vector<uint8_t> tls13_make_finished(tls_session& s, bool for_server){
    size_t hl=tls_hash_len(s.cipher_suite);
    bool use384=tls_use_sha384(s.cipher_suite);
    bool use_sm3=tls_use_sm3(s.cipher_suite);
    uint8_t finished_key[48];
    const char* label = for_server ? "s finished" : "c finished";
    if(use384) hkdf_expand_label_sha384(s.handshake_secret,label,nullptr,0,finished_key,hl);
    else if(use_sm3) hkdf_expand_label_sm3(s.handshake_secret,label,nullptr,0,finished_key,hl);
    else hkdf_expand_label(s.handshake_secret,label,nullptr,0,finished_key,hl);

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

static bool tls13_verify_finished(tls_session& s, const uint8_t* hs_msg, size_t hs_len, bool for_server){
    if(hs_len<4 || hs_msg[0]!=(uint8_t)HandshakeType::FINISHED)return false;
    size_t hl=tls_hash_len(s.cipher_suite);
    size_t vd_len=(hs_msg[1]<<16)|(hs_msg[2]<<8)|hs_msg[3];
    if(vd_len!=hl || hs_len!=4+vd_len)return false;

    const char* label = for_server ? "s finished" : "c finished";
    bool use384=tls_use_sha384(s.cipher_suite);
    bool use_sm3=tls_use_sm3(s.cipher_suite);
    uint8_t finished_key[48];
    if(use384) hkdf_expand_label_sha384(s.handshake_secret,label,nullptr,0,finished_key,hl);
    else if(use_sm3) hkdf_expand_label_sm3(s.handshake_secret,label,nullptr,0,finished_key,hl);
    else hkdf_expand_label(s.handshake_secret,label,nullptr,0,finished_key,hl);

    tls_transcript_finalize(s);
    uint8_t expected[48];
    if(use384) hmac_sha384(finished_key,hl,s.transcript_hash,hl,expected);
    else if(use_sm3) hmac_sm3(finished_key,hl,s.transcript_hash,hl,expected);
    else hmac_sha256(finished_key,hl,s.transcript_hash,hl,expected);

    return memcmp(expected,hs_msg+4,hl)==0;
}

// ═══════════════════════════════════════════════════════════════════════
//  构建 Certificate + CertificateVerify 消息
// ═══════════════════════════════════════════════════════════════════════
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

// RFC 8446 §4.4.3: CertificateVerify 签名内容 =
// 上下文串 ("TLS 1.3, server/client CertificateVerify") + 64 个 0x00 + Transcript-Hash
static std::vector<uint8_t> tls13_cert_verify_content(tls_session& s, bool for_server) {
    static const char* server_ctx = "TLS 1.3, server CertificateVerify";
    static const char* client_ctx = "TLS 1.3, client CertificateVerify";
    tls_transcript_finalize(s);
    size_t hl = tls_hash_len(s.cipher_suite);
    const char* ctx = for_server ? server_ctx : client_ctx;
    std::vector<uint8_t> content;
    content.insert(content.end(), ctx, ctx + strlen(ctx));
    content.insert(content.end(), 64, 0);
    content.insert(content.end(), s.transcript_hash, s.transcript_hash + hl);
    return content;
}

static std::vector<uint8_t> tls13_make_cert_verify(const tls_certificate& cert, tls_session& s){
    // RSA-2048 PKCS#1 签名为 256 字节；缓冲区按最大签名 (512B) 预留，
    // 避免 RSA 证书在 TLS 1.3 CertificateVerify 中发生栈溢出。
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

// ═══════════════════════════════════════════════════════════════════════
//  客户端 x509 链验证辅助
// ═══════════════════════════════════════════════════════════════════════
namespace {

// 叶子证书主机名匹配（SAN DNS 优先，其次 CN；支持 *.example.com 通配）
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
//   1) 服务端链自身可通过（链已含自签根）；
//   2) 否则逐个尝试把信任库中的 CA 根追加到链尾后验证。
// 通过后还需叶子主机名匹配 server_name。
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

// 用解析出的 x509 叶子证书构造 tls_certificate（只填公钥，用于 CertificateVerify 验证）
std::unique_ptr<tls_certificate> tls_cert_from_x509_leaf(const x509::x509_cert& leaf) {
    auto out = std::make_unique<tls_certificate>();
    out->subject_name = leaf.common_name();
    out->sig_alg = tls_key_type_to_sig_alg(leaf.key_type);
    if (!fill_pub(*out, leaf.key_type, leaf.public_key)) return nullptr;
    return out;
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════
//  构建 EncryptedExtensions
// ═══════════════════════════════════════════════════════════════════════
// alpn_selected 非空时携带 ALPN 扩展（RFC 7301：服务端只选择一个协议）。
static std::vector<uint8_t> tls13_make_encrypted_extensions(
    const std::string& alpn_selected) {
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
    uint16_t ext_total = (uint16_t)ext.size();
    msg.push_back((uint8_t)HandshakeType::ENCRYPTED_EXTENSIONS);
    msg.push_back(0);msg.push_back(0);
    msg.push_back((uint8_t)(2 + ext_total)); // extensions 区总长
    msg.push_back((uint8_t)(ext_total >> 8));msg.push_back((uint8_t)ext_total);
    msg.insert(msg.end(), ext.begin(), ext.end());
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

    std::vector<uint8_t> ciphertext;uint8_t tag[16];
    if(cipher_needs_sm4_ctx(s.cipher_suite)){
        sm4_ctx_init_from_key(s.sm4, write_key);
        sm4_gcm_encrypt(&s.sm4,nonce,12,inner,std::span<const uint8_t>(),ciphertext,tag,16);
    }else{
        aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
        aes_gcm_encrypt_auto(ctx,nonce,12,inner,std::span<const uint8_t>(),ciphertext,tag,16);
    }

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

    std::vector<uint8_t> inner;
    bool ok = false;
    if(cipher_needs_sm4_ctx(s.cipher_suite)){
        sm4_ctx_init_from_key(s.sm4, read_key);
        ok = sm4_gcm_decrypt(&s.sm4,nonce,12,std::span<const uint8_t>(ciphertext,ct_len),std::span<const uint8_t>(),tag,16,inner);
    }else{
        aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
        ok = aes_gcm_decrypt_auto(ctx,nonce,12,std::span<const uint8_t>(ciphertext,ct_len),std::span<const uint8_t>(),tag,16,inner);
    }
    if(!ok) return false;

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
    std::vector<uint16_t> cs_list;
    if(tls_use_sm3(s.cipher_suite)) cs_list.push_back(0x00C6);
    cs_list.push_back(0x1301);
    cs_list.push_back(0x1302);
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
    // supported_groups: 根据会话配置提供 X25519 和/或 X448
    {
        std::vector<uint16_t> groups;
        // SM 套件必须包含 curveSM2（RFC 8998 3.3.1.1）；同时保留 X25519 兜底
        if (tls_use_sm3(s.cipher_suite)) {
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
        // RFC 8446: signature_algorithms_cert 必须是 signature_algorithms 的子集
        std::vector<uint16_t> cert_filtered;
        for (uint16_t a : cert_algs) if (scheme_in_list(algs, a)) cert_filtered.push_back(a);
        append_sig_alg_extension(ext, 0x000d, algs);
        append_sig_alg_extension(ext, 0x0032, cert_filtered);
    }
    // key_share: 根据 ks_group 生成对应密钥对
    if (tls_use_sm3(s.cipher_suite)) {
        // curveSM2（RFC 8998 3.3.1.1 必须提供，key_exchange 为 SEC1 非压缩 65 字节）
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
        // 暂存私钥到 client_write_key（仅前 32 字节不够，改用 ks_priv）
        // 注意：后续 derive_keys 时使用 ks_priv
    } else if (s.ks_group == NamedGroup::secp256r1) {
        // secp256r1 (P-256) ECDHE：key_exchange = x||y 裸 64 字节（RFC 8446 4.2.8.2）
        uint8_t ecdh_pub[64], ecdh_priv[32];
        ecdsa_p256_keygen(ecdh_pub, ecdh_priv);
        memcpy(s.ks_priv, ecdh_priv, 32);
        memcpy(s.ks_pub, ecdh_pub, 64);
        ext.push_back(0x00);ext.push_back(0x33); // key_share
        ext.push_back(0x00);ext.push_back(0x46); // 70 = 2 + 68
        ext.push_back(0x00);ext.push_back(0x44); // client_shares 68
        ext.push_back(0x00);ext.push_back(0x17); // secp256r1
        ext.push_back(0x00);ext.push_back(0x40); // 64
        ext.insert(ext.end(), ecdh_pub, ecdh_pub + 64);
    } else if (s.ks_group == NamedGroup::secp384r1) {
        // secp384r1 (P-384) ECDHE：key_exchange = x||y 裸 96 字节
        uint8_t ecdh_pub[96], ecdh_priv[48];
        ecdsa_p384_keygen(ecdh_pub, ecdh_priv);
        memcpy(s.ks_priv, ecdh_priv, 48);
        memcpy(s.ks_pub, ecdh_pub, 96);
        ext.push_back(0x00);ext.push_back(0x33); // key_share
        ext.push_back(0x00);ext.push_back(0x66); // 102 = 2 + 100
        ext.push_back(0x00);ext.push_back(0x64); // client_shares 100
        ext.push_back(0x00);ext.push_back(0x18); // secp384r1
        ext.push_back(0x00);ext.push_back(0x60); // 96
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
    memcpy(s.server_random,data+sh_start+10,32);

    { size_t cs_off_in_sh = 4+2+32+1; uint16_t sel_cs = (data[sh_start+cs_off_in_sh]<<8)|data[sh_start+cs_off_in_sh+1]; s.cipher_suite = select_cipher_suite(sel_cs); }

    tls_transcript_update(s,data+sh_start,4+sh_len);

    // 提取 server_pub 从 key_share（支持 X25519、X448 和 curveSM2）
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
            } else if(group==(uint16_t)NamedGroup::secp256r1 && key_len==64 && elen>=4+64){
                memcpy(server_pub_p256,data+ext_off+8,64);found_ks_p256=true;
            } else if(group==(uint16_t)NamedGroup::secp384r1 && key_len==96 && elen>=4+96){
                memcpy(server_pub_p384,data+ext_off+8,96);found_ks_p384=true;
            }
        }
        ext_off+=4+elen;
    }
    // 默认回退到偏移 50（旧 API 兼容）：X25519 情况下
    if(!found_ks_x25519 && !found_ks_x448 && !found_ks_sm2 && !found_ks_p256 && !found_ks_p384){
        memcpy(server_pub_x25519,data+sh_start+50,32);
        found_ks_x25519=true;
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
                                }
                                off += 4 + elen;
                            }
                        }
                    }
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
                        // 链验证通过后必须能用叶子证书构造 server_cert 验证 CertificateVerify，
                        // 否则（如 RSA-4096 对端证书）不能静默跳过 CV 校验，直接判失败。
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
    init_cipher_ctx(s, s.is_server?s.server_write_key:s.client_write_key);
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

    // ClientHello transcript 更新已移至 cipher_suite 选择之后

    { size_t cs_off = 4+2+32; uint8_t sid_len = client_hello[cs_off]; cs_off += 1+sid_len;
      uint16_t cs_list_len = (client_hello[cs_off]<<8)|client_hello[cs_off+1]; cs_off += 2;
      for(size_t i=0; i+2<=cs_list_len; i+=2){
        uint16_t cs_id = (client_hello[cs_off+i]<<8)|client_hello[cs_off+i+1];
        if(cs_id == 0x00C6){ s.cipher_suite = CipherSuite::TLS_SM4_GCM_SM3; break; }
      }
    }

    // 记录 ClientHello (须在 cipher_suite 确定后, 保证 transcript 哈希算法与客户端一致)
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

    // 提取 client_pub（支持 X25519、X448 和 curveSM2）和 supported_groups
    uint8_t client_pub_x25519[32]; bool found_x25519=false;
    uint8_t client_pub_x448[56]; bool found_x448=false;
    uint8_t client_pub_sm2[65]; size_t client_pub_sm2_len=0; bool found_sm2=false;
    uint8_t client_pub_p256[64]; bool found_p256=false;
    uint8_t client_pub_p384[96]; bool found_p384=false;
    bool client_supports_x448=false;    // 客户端 supported_groups 列表中是否包含 X448
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
                    // curveSM2 采用 SEC1 非压缩 65 字节；兼容裸 64 字节 x||y
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

    // signature_algorithms 协商（RFC 8446 §4.2.3）
    if (client_sig_algs.empty()) return false;   // 客户端必须携带该扩展
    // signature_algorithms_cert 必须是 signature_algorithms 的子集
    for (uint16_t a : client_sig_algs_cert)
        if (!scheme_in_list(client_sig_algs, a)) return false;
    // 选择双方共同支持且与证书密钥类型匹配的方案（TLS 1.3 不允许 rsa_pkcs1_*）
    s.selected_sig_alg = select_signature_scheme(client_sig_algs, *cert, s.sig_algs, true);
    if (s.selected_sig_alg == 0) return false;
    // signature_algorithms_cert：证书链签名方案必须被客户端接受
    if (!client_sig_algs_cert.empty()) {
        uint16_t chain_scheme = cert_chain_signature_scheme(*cert);
        if (chain_scheme == 0 || !scheme_in_list(client_sig_algs_cert, chain_scheme)) return false;
    }

    // RFC 8998 3.3.1.1：SM 套件要求 supported_groups 含 curveSM2 且必须提供其 key_share
    if (tls_use_sm3(s.cipher_suite) && (!found_sm2 || !client_supports_curveSM2)) return false;

    // 选择密钥交换组：SM 套件优先 curveSM2，其次 X448（如果客户端提供了 key_share）
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
    server_flight.push_back(0);
    uint16_t sel_cs = (uint16_t)s.cipher_suite;
    server_flight.push_back((uint8_t)(sel_cs>>8));server_flight.push_back((uint8_t)sel_cs);
    server_flight.push_back(0x00);

    if (use_sm2) {
        // curveSM2 密钥交换（RFC 8998 3.4：标准 ECDHE，共享密钥 = X 坐标 32 字节）
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
        // key_share curveSM2（SEC1 非压缩 65 字节）
        server_flight.push_back(0x00);server_flight.push_back(0x33);
        server_flight.push_back(0x00);server_flight.push_back(0x45); // 69 = 2 + 2 + 65
        server_flight.push_back(0x00);server_flight.push_back(0x29); // curveSM2
        server_flight.push_back(0x00);server_flight.push_back(0x41); // 65
        server_flight.push_back(0x04);
        server_flight.insert(server_flight.end(), server_pub, server_pub + SM2_PUB_SIZE);
    } else if (use_p256) {
        // secp256r1 (P-256) ECDHE：key_exchange = x||y 裸 64 字节
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
        // secp384r1 (P-384) ECDHE：key_exchange = x||y 裸 96 字节
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

    // 构建 EncryptedExtensions
    auto ee=tls13_make_encrypted_extensions(s.alpn_selected);
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
    init_cipher_ctx(s, s.server_write_key);
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
    init_cipher_ctx(s, s.client_write_key);
    return true;
}

bool tls13_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len,
                             std::vector<uint8_t>& server_response,
                             const tls_certificate_manager& cert_manager){
    return tls13_make_server_flight(s, client_hello, ch_len, server_response, cert_manager);
}

// ═══════════════════════════════════════════════════════════════════════

// ── TLS 1.2 密码套件协商 ───────────────────────────────────────────────

// 服务端支持的 TLS 1.2 密码套件列表（按优先级排序）
// 优先级: ECDHE-ECDSA > ECDHE-RSA > RSA | ChaCha20 > AES-256 > AES-128
static const uint16_t TLS12_SERVER_CIPHERS[] = {
    0xC02C, // 1st ECDHE-ECDSA+AES256+SHA384
    0xCCA9, // 2nd ECDHE-ECDSA+ChaCha20
    0xC030, // 3rd ECDHE-RSA+AES256+SHA384
    0xCCA8, // 4th ECDHE-RSA+ChaCha20
    0xC02B, // 5th ECDHE-ECDSA+AES128
    0xC02F, // 6th ECDHE-RSA+AES128
    0x009D, // 7th RSA+AES256
    0x009C, // 8th RSA+AES128 (fallback)
};

// 客户端默认支持的 TLS 1.2 密码套件列表
static const uint16_t TLS12_CLIENT_CIPHERS[] = {
    0xC02C, 0xCCA9, 0xC030, 0xCCA8, 0xC02B, 0xC02F, 0x009D, 0x009C,
};


// 判断 TLS 1.2 密码套件是否使用 ECDHE 密钥交换
static bool tls12_is_ecdhe(CipherSuite cs){
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
// 从 ClientHello 中解析密码套件列表
// 返回解析出的套件数组和数量
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

// 从客户端套件列表中选择服务端支持的最佳套件
static uint16_t tls12_select_best_cipher_suite(const std::vector<uint16_t>& client_suites){
    for(size_t si=0; si < sizeof(TLS12_SERVER_CIPHERS)/sizeof(TLS12_SERVER_CIPHERS[0]); ++si){
        uint16_t srv_cs = TLS12_SERVER_CIPHERS[si];
        for(uint16_t cl_cs : client_suites)
            if(cl_cs == srv_cs) return srv_cs;
    }
    return 0; // no common suite
}

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
        std::vector<uint8_t> buf(32+full_seed.size());memcpy(buf.data(),a,32);memcpy(buf.data()+32,full_seed.data(),full_seed.size());
        hmac_sha256(secret,secret_len,buf.data(),32+full_seed.size(),tmp);
        size_t n=(out_len-generated<32)?out_len-generated:32;
        memcpy(out+generated,tmp,n);generated+=n;
        hmac_sha256(secret,secret_len,a,32,a);
    }
}


// TLS 1.2 PRF (P_SHA384) — for SHA-384 based cipher suites
static void tls12_prf_sha384(const uint8_t* secret, size_t secret_len, const char* label, const uint8_t* seed, size_t seed_len, uint8_t* out, size_t out_len){
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
// ═══════════════════════════════════════════════════════════════════════
//  TLS 1.2 密钥派生
// ═══════════════════════════════════════════════════════════════════════
void tls12_derive_keys(tls_session& s, const uint8_t pre_master[48]){
    s.ver=TLSVersion::V12;
    bool use_sha384 = (s.cipher_suite == CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    || s.cipher_suite == CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    || s.cipher_suite == CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384);
    uint8_t seed[64];memcpy(seed,s.client_random,32);memcpy(seed+32,s.server_random,32);
    if(use_sha384) tls12_prf_sha384(pre_master,48,"master secret",seed,64,s.master_secret,48);
    else tls12_prf(pre_master,48,"master secret",seed,64,s.master_secret,48);
    size_t key_len = 16;
    bool is_chacha = (s.cipher_suite == CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                   || s.cipher_suite == CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
    if(is_chacha) key_len = 32;
    uint8_t key_block[72];
    uint8_t exp_seed[64];memcpy(exp_seed,s.server_random,32);memcpy(exp_seed+32,s.client_random,32);
    if(use_sha384) tls12_prf_sha384(s.master_secret,48,"key expansion",exp_seed,64,key_block,72);
    else tls12_prf(s.master_secret,48,"key expansion",exp_seed,64,key_block,72);
    memcpy(s.client_write_key,key_block,key_len);
    memcpy(s.server_write_key,key_block+key_len,key_len);
    if(is_chacha){
        memcpy(s.client_write_iv,key_block+key_len*2,12);
        memcpy(s.server_write_iv,key_block+key_len*2+12,12);
    }else{
        memcpy(s.client_write_iv,key_block+32,4);
        memcpy(s.server_write_iv,key_block+36,4);
        memset(s.client_write_iv+4,0,8);
        memset(s.server_write_iv+4,0,8);
    }
    s.client_seq=0;s.server_seq=0;
    init_cipher_ctx(s, s.client_write_key);
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
    // Cipher suites: dynamic list
    size_t cs_count = sizeof(TLS12_CLIENT_CIPHERS) / sizeof(TLS12_CLIENT_CIPHERS[0]);
    client_hello.push_back(0); // session_id_len = 0
    client_hello.push_back((uint8_t)(cs_count*2 >> 8)); client_hello.push_back((uint8_t)(cs_count*2));
    for(size_t ci = 0; ci < cs_count; ++ci){
        uint16_t cs = TLS12_CLIENT_CIPHERS[ci];
        client_hello.push_back((uint8_t)(cs>>8)); client_hello.push_back((uint8_t)cs);
    }
    client_hello.push_back(0x01); client_hello.push_back(0x00); // compression: null
    (void)cs_count;

    // extensions: SNI + signature_algorithms
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
    tls_transcript_update(s,client_hello.data(),client_hello.size());
    return true;
}

bool tls12_process_server_flight(tls_session& s, const uint8_t* server_response, size_t resp_len,
                                  const uint8_t* pre_master_secret, size_t pms_len,
                                  std::vector<uint8_t>& client_finished){
    if(resp_len<4 || server_response[0]!=(uint8_t)HandshakeType::SERVER_HELLO)return false;
    size_t sh_len=(server_response[1]<<16)|(server_response[2]<<8)|server_response[3];
    if(4+sh_len>resp_len)return false;
    // Parse selected cipher suite from ServerHello body
    // ServerHello body: version(2) + random(32) + session_id_len(1) + cipher_suite(2) + compression(1)
    size_t cs_off = 4 + 2 + 32 + 1; // after header + version + random + sid_len
    uint16_t sel_cs = (server_response[cs_off]<<8) | server_response[cs_off+1];
    s.cipher_suite = select_cipher_suite(sel_cs);
    tls_transcript_update(s,server_response,4+sh_len);
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

    // 解析客户端密码套件列表并选择
    auto client_suites = tls12_parse_client_cipher_suites(client_hello, ch_len);
    uint16_t selected_cs = tls12_select_best_cipher_suite(client_suites);
    if(selected_cs == 0) return false; // no common cipher suite
    s.cipher_suite = select_cipher_suite(selected_cs);

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

    // 解析客户端 signature_algorithms / signature_algorithms_cert（RFC 8446，TLS 1.2 亦适用）
    std::vector<uint16_t> client_sig_algs, client_sig_algs_cert;
    const uint8_t* ext_data = nullptr; size_t ext_dlen = 0;
    if (client_hello_find_extension(client_hello, ch_len, 0x000d, ext_data, ext_dlen))
        parse_sig_alg_list(ext_data, ext_dlen, client_sig_algs);
    if (client_hello_find_extension(client_hello, ch_len, 0x0032, ext_data, ext_dlen))
        parse_sig_alg_list(ext_data, ext_dlen, client_sig_algs_cert);
    for (uint16_t a : client_sig_algs_cert)
        if (!scheme_in_list(client_sig_algs, a)) return false;  // 必须是 signature_algorithms 的子集
    uint16_t skx_sig_alg = 0;
    if (use_ecdhe && cert) {
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
    // Cipher suites: multiple
    size_t cs_n = sizeof(TLS12_CLIENT_CIPHERS) / sizeof(TLS12_CLIENT_CIPHERS[0]);
    client_hello.push_back(0);
    client_hello.push_back((uint8_t)(cs_n*2>>8)); client_hello.push_back((uint8_t)(cs_n*2));
    for(size_t i=0; i<cs_n; ++i){
        uint16_t c = TLS12_CLIENT_CIPHERS[i];
        client_hello.push_back((uint8_t)(c>>8)); client_hello.push_back((uint8_t)c);
    }
    client_hello.push_back(0x01); client_hello.push_back(0x00);
    // signature_algorithms + signature_algorithms_cert
    std::vector<uint8_t> ext;
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

    // 解析客户端 signature_algorithms / signature_algorithms_cert
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

// ═══════════════════════════════════════════════════════════════════════
//  记录层加密
// ═══════════════════════════════════════════════════════════════════════
static void tls_encrypt_record(tls_session& s, ContentType ct,
                               const uint8_t* data, size_t len,
                               std::vector<uint8_t>& out);

std::vector<uint8_t> tls_encrypt(tls_session& s, ContentType ct, const uint8_t* data, size_t len){
    // 大消息自动分片：len > TLS_MAX_RECORD_PLAINTEXT 时拆分为多条 record，
    // 拼接后一次性返回（对端可用 tls_decrypt / tls_connection::recv 合并还原）。
    std::vector<uint8_t> out;
    // 预预留：每条 record ≈ 5 字节头 + 2 内容类型 + 16 tag（TLS 1.2 另有 8 显式 nonce），
    // 取 len + records*32 上界，避免输出向量反复扩容拷贝
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

// 加密单条 record（len 必须 <= TLS_MAX_RECORD_PLAINTEXT）
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
        size_t inner_len=len+1;   // TLS 1.2 inner = type || data（无尾随 type）
        aad[11]=(uint8_t)(inner_len>>8);aad[12]=(uint8_t)inner_len;
        bool is_chacha_tls12 = (s.cipher_suite == CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                             || s.cipher_suite == CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        if(is_chacha_tls12){
            // ChaCha20-Poly1305 in TLS 1.2: explicit nonce is prepended
            uint8_t cha_nonce[12];
            memcpy(cha_nonce, write_iv, 4);
            memcpy(cha_nonce+4, explicit_nonce, 8);
            // 零拷贝：直接构建记录缓冲（显式 nonce + inner 帧 + tag 占位）后就地加密
            out.push_back((uint8_t)ct);
            out.push_back(0x03);out.push_back(0x03);
            size_t inner_len=len+1;
            size_t rlen=8+inner_len+16;
            out.push_back((uint8_t)(rlen>>8));out.push_back((uint8_t)rlen);
            out.insert(out.end(),explicit_nonce,explicit_nonce+8);
            size_t body=out.size();
            out.resize(body+inner_len+16);
            out[body]=(uint8_t)ct;
            std::memcpy(out.data()+body+1, data, len);
            chacha20_poly1305_encrypt_inplace(write_key, cha_nonce, out.data()+body,
                                              inner_len, std::span<const uint8_t>(aad, 13),
                                              out.data()+body+inner_len);
        }else{
            // GCM 零拷贝：直接构建记录缓冲并就地加密（无 inner/ciphertext 中间向量）
            aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
            out.push_back((uint8_t)ct);
            out.push_back(0x03);out.push_back(0x03);
            size_t rlen=8+inner_len+16;
            out.push_back((uint8_t)(rlen>>8));out.push_back((uint8_t)rlen);
            out.insert(out.end(),explicit_nonce,explicit_nonce+8);
            size_t body=out.size();
            out.resize(body+inner_len+16);
            out[body]=(uint8_t)ct;
            std::memcpy(out.data()+body+1, data, len);
            aes_gcm_encrypt_inplace(ctx, nonce, 12, out.data()+body, inner_len,
                                    std::span<const uint8_t>(aad, 13),
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
    switch(s.cipher_suite){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384: {
            // GCM 零拷贝：直接构建记录缓冲并就地加密（无 inner/ciphertext 中间向量）
            aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
            size_t inner_len=len+2;
            size_t rlen=inner_len+16;
            out.push_back(0x17);out.push_back(0x03);out.push_back(0x03);
            out.push_back((uint8_t)(rlen>>8));out.push_back((uint8_t)rlen);
            size_t body=out.size();
            out.resize(body+inner_len+16);
            out[body]=(uint8_t)ct;
            std::memcpy(out.data()+body+1, data, len);
            out[body+len+1]=(uint8_t)ct;
            aes_gcm_encrypt_inplace(ctx, nonce, 12, out.data()+body, inner_len,
                                    std::span<const uint8_t>(),
                                    out.data()+body+inner_len, 16);
            return;
        }
        default: {
            // 零拷贝：直接构建记录缓冲（inner 帧 + tag 占位）后就地加密
            size_t inner_len=len+2;
            size_t rlen=inner_len+16;
            out.push_back(0x17);out.push_back(0x03);out.push_back(0x03);
            out.push_back((uint8_t)(rlen>>8));out.push_back((uint8_t)rlen);
            size_t body=out.size();
            out.resize(body+inner_len+16);
            out[body]=(uint8_t)ct;
            std::memcpy(out.data()+body+1, data, len);
            out[body+len+1]=(uint8_t)ct;
            uint8_t* inner=out.data()+body;
            uint8_t* tag=out.data()+body+inner_len;
            switch(s.cipher_suite){
                case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
                    chacha20_poly1305_encrypt_inplace(write_key, nonce, inner, inner_len,
                                                      std::span<const uint8_t>(), tag);
                    break;
                case CipherSuite::TLS_AES_128_CCM_SHA256: {
                    aes_context ctx;aes_ctx_init(ctx, write_key, aes_key_len(s.cipher_suite));
                    aes_ccm_encrypt_inplace(ctx, nonce, 12, inner, inner_len,
                                            std::span<const uint8_t>(), tag, 16);
                    break;
                }
                case CipherSuite::TLS_SM4_GCM_SM3:
                case CipherSuite::TLS_SM4_CCM_SM3: {
                    sm4_ctx_init_from_key(s.sm4, write_key);
                    sm4_gcm_encrypt_inplace(&s.sm4, nonce, 12, inner, inner_len,
                                            std::span<const uint8_t>(), tag, 16);
                    break;
                }
            }
            return;
        }
    }
    return;
}

// 解密单条 record（record 缓冲区恰好为一条：5 字节头 + payload）
static bool tls_decrypt_one(tls_session& s, const uint8_t* record, size_t record_len,
                            ContentType& ct, std::vector<uint8_t>& out){
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
        bool is_chacha_tls12 = (s.cipher_suite == CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                             || s.cipher_suite == CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        if(is_chacha_tls12){
            uint8_t cha_nonce[12];
            memcpy(cha_nonce, read_iv, 4);
            memcpy(cha_nonce+4, explicit_nonce, 8);
            if(!chacha20_poly1305_decrypt(read_key, cha_nonce,
                    std::span<const uint8_t>(ciphertext,ct_len),
                    std::span<const uint8_t>(aad,13), tag, inner)) return false;
        }else{
            aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
            if(!aes_gcm_decrypt_auto(ctx,nonce,12,std::span<const uint8_t>(ciphertext,ct_len),std::span<const uint8_t>(aad,13),tag,16,inner))
                return false;
        }
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
    bool ok = false;
    switch(s.cipher_suite){
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_AES_256_GCM_SHA384: {
            aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
            ok = aes_gcm_decrypt_auto(ctx,nonce,12,std::span<const uint8_t>(ciphertext,ct_len),std::span<const uint8_t>(),tag,16,inner);
            break;
        }
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            ok = chacha20_poly1305_decrypt(read_key, nonce,
                                           std::span<const uint8_t>(ciphertext,ct_len),
                                           std::span<const uint8_t>(), tag, inner);
            break;
        case CipherSuite::TLS_AES_128_CCM_SHA256: {
            aes_context ctx;aes_ctx_init(ctx, read_key, aes_key_len(s.cipher_suite));
            ok = aes_ccm_decrypt(ctx, nonce, 12,
                                 std::span<const uint8_t>(ciphertext,ct_len),
                                 std::span<const uint8_t>(), tag, 16, inner);
            break;
        }
        case CipherSuite::TLS_SM4_GCM_SM3:
        case CipherSuite::TLS_SM4_CCM_SM3: {
            sm4_ctx_init_from_key(s.sm4, read_key);
            ok = sm4_gcm_decrypt(&s.sm4, nonce, 12,
                                 std::span<const uint8_t>(ciphertext,ct_len),
                                 std::span<const uint8_t>(), tag, 16, inner);
            break;
        }
    }
    if(!ok) return false;
    if(inner.empty())return false;
    ct=(ContentType)inner[0];
    out.assign(inner.begin()+1,inner.end()-1);
    return true;
}

bool tls_decrypt(tls_session& s, const uint8_t* record, size_t record_len,
                 ContentType& ct, std::vector<uint8_t>& out){
    // 大消息合并：逐条解析 record，明文追加到 out（单条 record 同样支持）
    out.clear();
    out.reserve(record_len);  // 明文总长 ≤ 密文总长，预预留避免反复扩容
    size_t off = 0;
    bool any = false;
    ContentType first_ct = ContentType::APPLICATION_DATA;
    while (off < record_len) {
        if (record_len - off < 5) return false;  // 尾部残留不完整 record
        size_t rlen = ((size_t)record[off + 3] << 8) | record[off + 4];
        if (rlen < 16 || 5 + rlen > record_len - off) return false;
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
            aes_gcm_encrypt_auto(ctx, nonce, 12, inner, std::span<const uint8_t>(), ciphertext, tag, 16);
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
            ok = aes_gcm_decrypt_auto(ctx, nonce, 12, std::span<const uint8_t>(ciphertext,ct_len),
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

// ═══ X.509 v3 Integration ═══
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

std::vector<uint8_t> tls12_make_certificate(const tls_certificate& cert) {
    auto der=cert.cert_data.empty()?tls_make_x509_self_signed(cert):cert.cert_data;
    std::vector<uint8_t> m;m.push_back(11);
    size_t el=3+der.size(),bl=3+el;
    m.push_back((uint8_t)(bl>>16));m.push_back((uint8_t)(bl>>8));m.push_back((uint8_t)bl);
    m.push_back((uint8_t)(el>>16));m.push_back((uint8_t)(el>>8));m.push_back((uint8_t)el);
    m.push_back((uint8_t)(der.size()>>16));m.push_back((uint8_t)(der.size()>>8));m.push_back((uint8_t)der.size());
    m.insert(m.end(),der.begin(),der.end());return m;
}

}
