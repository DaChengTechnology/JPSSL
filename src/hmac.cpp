#include "hmac.hpp"
#include <cstring>
namespace jpssl {
void hmac_sha256(const uint8_t* key,size_t key_len,const uint8_t* msg,size_t msg_len,uint8_t mac[32]){
    uint8_t ikey[64],okey[64],tk[32];
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