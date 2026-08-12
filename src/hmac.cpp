#include "hmac.hpp"
#include "cpu_features.hpp"
#include <cstring>
#include <vector>
namespace jpssl {
void hmac_sha256(const uint8_t* key,size_t key_len,const uint8_t* msg,size_t msg_len,uint8_t mac[32]){
    uint8_t ikey[64],okey[64],tk[32];
#if defined(__x86_64__) || defined(_M_X64)
    // SHA-NI 快速路径（仅 x86-64 且运行时检测到 Intel SHA Extensions）。
    // sha256_sha_ni 是一次性 API：inner = SHA256(ikey || msg)、outer = SHA256(okey || tk)，
    // 均拼成连续缓冲后单次调用；无 SHA-NI 的机器回退下方 scalar 路径（行为不变）。
    if (cpu_has_sha_ni()) {
        if(key_len>64){sha256_sha_ni(tk,key,key_len);key=tk;key_len=32;}
        memset(ikey,0,64);memset(okey,0,64);
        memcpy(ikey,key,key_len);memcpy(okey,key,key_len);
        for(int i=0;i<64;++i){ikey[i]^=0x36;okey[i]^=0x5c;}
        std::vector<uint8_t> inner;
        inner.reserve(64+msg_len);
        inner.insert(inner.end(),ikey,ikey+64);
        if(msg_len)inner.insert(inner.end(),msg,msg+msg_len);
        sha256_sha_ni(tk,inner.data(),inner.size());
        uint8_t outer[96];
        memcpy(outer,okey,64);memcpy(outer+64,tk,32);
        sha256_sha_ni(mac,outer,96);
        return;
    }
#endif
    sha256_ctx ctx;
    if(key_len>64){sha256_init(&ctx);sha256_update(&ctx,key,key_len);sha256_final(&ctx,tk);key=tk;key_len=32;}
    memset(ikey,0,64);memset(okey,0,64);
    memcpy(ikey,key,key_len);memcpy(okey,key,key_len);
    for(int i=0;i<64;++i){ikey[i]^=0x36;okey[i]^=0x5c;}
    sha256_init(&ctx);sha256_update(&ctx,ikey,64);sha256_update(&ctx,msg,msg_len);sha256_final(&ctx,tk);
    sha256_init(&ctx);sha256_update(&ctx,okey,64);sha256_update(&ctx,tk,32);sha256_final(&ctx,mac);
}

void hmac_sha384(const uint8_t* key,size_t key_len,const uint8_t* msg,size_t msg_len,uint8_t mac[48]){
    uint8_t ikey[128],okey[128],tk[48];
    sha512_ctx ctx;
    if(key_len>128){
        sha384_init(&ctx);sha512_update(&ctx,key,key_len);sha512_final(&ctx,tk);
        key=tk;key_len=48;
    }
    memset(ikey,0,128);memset(okey,0,128);
    memcpy(ikey,key,key_len);memcpy(okey,key,key_len);
    for(int i=0;i<128;++i){ikey[i]^=0x36;okey[i]^=0x5c;}
    sha384_init(&ctx);sha512_update(&ctx,ikey,128);
    sha512_update(&ctx,msg,msg_len);sha512_final(&ctx,tk);
    sha384_init(&ctx);sha512_update(&ctx,okey,128);
    sha512_update(&ctx,tk,48);sha512_final(&ctx,mac);
}

void hmac_sm3(const uint8_t* key,size_t key_len,const uint8_t* msg,size_t msg_len,uint8_t mac[32]){
    uint8_t ikey[64],okey[64],tk[32];
    sm3_ctx ctx;
    if(key_len>64){sm3_init(&ctx);sm3_update(&ctx,key,key_len);sm3_final(&ctx,tk);key=tk;key_len=32;}
    memset(ikey,0,64);memset(okey,0,64);
    memcpy(ikey,key,key_len);memcpy(okey,key,key_len);
    for(int i=0;i<64;++i){ikey[i]^=0x36;okey[i]^=0x5c;}
    sm3_init(&ctx);sm3_update(&ctx,ikey,64);sm3_update(&ctx,msg,msg_len);sm3_final(&ctx,tk);
    sm3_init(&ctx);sm3_update(&ctx,okey,64);sm3_update(&ctx,tk,32);sm3_final(&ctx,mac);
}
}