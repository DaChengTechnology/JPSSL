#include "tls.hpp"
#include <cstring>
#include <random>
namespace jpssl::tls {

static void rand32(uint8_t* buf){static std::mt19937_64 g(std::random_device{}());for(int i=0;i<4;++i){uint64_t v=g();memcpy(buf+i*8,&v,8);}}

// ── TLS 1.3 密钥调度 ──
static void tls13_derive_keys(tls_session& s, const uint8_t shared_secret[32]){
    uint8_t early_secret[32],empty_hash[32];
    sha256_ctx ctx;sha256_init(&ctx);sha256_final(&ctx,empty_hash);

    // early_secret = HKDF-Extract(0, 0)
    uint8_t zero[32]={};
    hkdf_extract(zero,32,zero,32,early_secret);

    // handshake_secret = HKDF-Extract(early_secret, shared_secret)
    hkdf_extract(early_secret,32,shared_secret,32,s.handshake_secret);

    // client_handshake_traffic_secret = HKDF-Expand-Label(handshake_secret, "c hs traffic", ClientHello...ServerHello)
    uint8_t ch_ts[32];uint8_t sh_ts[32];
    uint8_t hello_hash[32];
    sha256_init(&ctx);sha256_update(&ctx,s.client_random,32);sha256_update(&ctx,s.server_random,32);sha256_final(&ctx,hello_hash);
    hkdf_expand_label(s.handshake_secret,"c hs traffic",hello_hash,32,ch_ts,32);
    hkdf_expand_label(s.handshake_secret,"s hs traffic",hello_hash,32,sh_ts,32);

    // master_secret = HKDF-Extract(handshake_secret, 0)
    hkdf_extract(s.handshake_secret,32,zero,32,s.master_secret);

    // client_application_traffic_secret = HKDF-Expand-Label(master_secret, "c ap traffic", hash)
    uint8_t ap_hash[32];sha256_init(&ctx);sha256_update(&ctx,hello_hash,32);sha256_final(&ctx,ap_hash);
    hkdf_expand_label(s.master_secret,"c ap traffic",ap_hash,32,s.client_write_key,32);
    hkdf_expand_label(s.master_secret,"s ap traffic",ap_hash,32,s.server_write_key,32);
    hkdf_expand_label(s.master_secret,"c ap traffic",ap_hash,32,s.client_write_iv,12);
    hkdf_expand_label(s.master_secret,"s ap traffic",ap_hash,32,s.server_write_iv,12);
    s.client_seq=0;s.server_seq=0;
}

// ── 握手 ──
bool tls13_handshake_client(tls_session& s, std::vector<uint8_t>& client_hello, const uint8_t* server_response, size_t resp_len){
    s.ver=TLSVersion::V13;rand32(s.client_random);
    // 构建 ClientHello
    client_hello.clear();
    client_hello.push_back((uint8_t)HandshakeType::CLIENT_HELLO);
    client_hello.push_back(0);client_hello.push_back(0);client_hello.push_back(0); // length placeholder
    client_hello.push_back(0x03);client_hello.push_back(0x03); // TLS 1.2 in legacy
    client_hello.insert(client_hello.end(),s.client_random,s.client_random+32);
    client_hello.push_back(0); // session_id length
    client_hello.push_back(0);client_hello.push_back(2); // cipher suites length
    client_hello.push_back(0x13);client_hello.push_back(0x01); // TLS_AES_128_GCM_SHA256
    client_hello.push_back(0x01);client_hello.push_back(0x00); // 1 compression method
    // extensions: supported_versions(TLS 1.3), key_share(X25519), supported_groups
    uint8_t ext[64];size_t ep=0;
    // supported_versions
    ext[ep++]=0x00;ext[ep++]=0x2b;ext[ep++]=0x00;ext[ep++]=0x03;ext[ep++]=0x02;ext[ep++]=0x03;ext[ep++]=0x04;
    // key_share (placeholder)
    ext[ep++]=0x00;ext[ep++]=0x33;ext[ep++]=0x00;ext[ep++]=0x00; // empty for now
    client_hello.insert(client_hello.end(),ext,ext+ep);
    // fix length
    size_t len=client_hello.size()-4;
    client_hello[1]=(uint8_t)(len>>16);client_hello[2]=(uint8_t)(len>>8);client_hello[3]=(uint8_t)len;

    // 解析 ServerHello（简化）
    (void)server_response;(void)resp_len;
    memcpy(s.server_random,server_response+6,32);
    // 读取 key_share
    uint8_t server_pub[32];
    memcpy(server_pub,server_response+50,32); // 简化偏移

    uint8_t client_priv[32],client_pub[32],shared_secret[32];
    x25519_generate_keypair(client_pub,client_priv);
    x25519_scalar_mult(shared_secret,client_priv,server_pub);

    s.aes_ctx.init(std::span<const uint8_t,16>(s.client_write_key,16));
    tls13_derive_keys(s,shared_secret);
    return true;
}

bool tls13_handshake_server(tls_session& s, const uint8_t* client_hello, size_t ch_len, std::vector<uint8_t>& server_response){
    s.ver=TLSVersion::V13;rand32(s.server_random);memcpy(s.client_random,client_hello+11,32);
    // 生成 ServerHello
    server_response.clear();
    server_response.push_back((uint8_t)HandshakeType::SERVER_HELLO);
    server_response.push_back(0);server_response.push_back(0);server_response.push_back(0);
    server_response.push_back(0x03);server_response.push_back(0x03);
    server_response.insert(server_response.end(),s.server_random,s.server_random+32);
    server_response.push_back(0); // session_id
    server_response.push_back(0x13);server_response.push_back(0x01); // cipher suite
    server_response.push_back(0x00); // compression
    // extensions: supported_versions
    server_response.push_back(0x00);server_response.push_back(0x2b);server_response.push_back(0x00);server_response.push_back(0x02);server_response.push_back(0x03);server_response.push_back(0x04);
    // key_share
    uint8_t server_priv[32],server_pub[32],client_pub[32],shared_secret[32];
    x25519_generate_keypair(server_pub,server_priv);
    memcpy(client_pub,client_hello+50,32); // 简化
    x25519_scalar_mult(shared_secret,server_priv,client_pub);
    server_response.push_back(0x00);server_response.push_back(0x33);server_response.push_back(0x00);server_response.push_back(0x22);
    server_response.push_back(0x00);server_response.push_back(0x1d); // x25519
    server_response.push_back(0x00);server_response.push_back(0x20); // key length
    server_response.insert(server_response.end(),server_pub,server_pub+32);

    size_t len=server_response.size()-4;
    server_response[1]=(uint8_t)(len>>16);server_response[2]=(uint8_t)(len>>8);server_response[3]=(uint8_t)len;

    tls13_derive_keys(s,shared_secret);
    s.aes_ctx.init(std::span<const uint8_t,16>(s.server_write_key,16));
    return true;
}

// ── 记录层加密 ──
std::vector<uint8_t> tls_encrypt(tls_session& s, ContentType ct, const uint8_t* data, size_t len){
    // TLS 1.3: 加密为 TLSCiphertext 结构
    // opaque_type || legacy_version || length || encrypted_record
    std::vector<uint8_t> inner;inner.push_back((uint8_t)ct);
    inner.insert(inner.end(),data,data+len);
    // 添加 content type suffix (TLS 1.3 inner content type)
    inner.push_back((uint8_t)ct);

    // AES-GCM 加密
    uint8_t nonce[12];memcpy(nonce,s.client_write_iv,12);
    // XOR sequence number into last 8 bytes of IV
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(s.client_seq>>(56-i*8));
    ++s.client_seq;

    std::vector<uint8_t> ciphertext;
    uint8_t tag[16];
    aes_gcm_encrypt(s.aes_ctx,nonce,12,inner,std::span<const uint8_t>{},ciphertext,tag,16);

    // Build record: type=23(app data), version=0x0303, length, ciphertext+tag
    std::vector<uint8_t> record;
    record.push_back(23); // application_data
    record.push_back(0x03);record.push_back(0x03);
    size_t rlen=ciphertext.size()+16;
    record.push_back((uint8_t)(rlen>>8));record.push_back((uint8_t)rlen);
    record.insert(record.end(),ciphertext.begin(),ciphertext.end());
    record.insert(record.end(),tag,tag+16);
    return record;
}

bool tls_decrypt(tls_session& s, const uint8_t* record, size_t len, ContentType& ct, std::vector<uint8_t>& out){
    if(len<5)return 0;
    size_t rlen=((size_t)record[3]<<8)|record[4];
    if(len<5+rlen)return 0;

    uint8_t nonce[12];memcpy(nonce,s.server_write_iv,12);
    for(int i=0;i<8;++i)nonce[4+i]^=(uint8_t)(s.server_seq>>(56-i*8));
    ++s.server_seq;

    size_t ct_len=rlen-16;
    std::vector<uint8_t> pt;
    if(!aes_gcm_decrypt(s.aes_ctx,nonce,12,std::span<const uint8_t>(record+5,ct_len),std::span<const uint8_t>{},record+5+ct_len,16,pt))return 0;
    if(pt.empty())return 0;
    ct=(ContentType)pt.back();
    out.assign(pt.begin()+1,pt.end()-1);
    return true;
}
}
