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
}
