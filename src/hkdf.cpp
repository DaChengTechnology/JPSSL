#include "hkdf.hpp"
#include "hmac.hpp"
#include <cstring>
namespace jpssl {
void hkdf_extract(const uint8_t* salt,size_t salt_len,const uint8_t* ikm,size_t ikm_len,uint8_t prk[32]){
    if(!salt||salt_len==0){uint8_t z[32]={};hmac_sha256(z,32,ikm,ikm_len,prk);}
    else hmac_sha256(salt,salt_len,ikm,ikm_len,prk);
}
void hkdf_expand(const uint8_t prk[32],const uint8_t* info,size_t info_len,uint8_t* out,size_t out_len){
    uint8_t t[32];size_t t_len=0;
    uint8_t counter=1;
    while(out_len>0){
        sha256_ctx ctx;sha256_init(&ctx);
        if(t_len>0)sha256_update(&ctx,t,t_len);
        sha256_update(&ctx,info,info_len);sha256_update(&ctx,&counter,1);sha256_final(&ctx,t);
        size_t n=(out_len<32)?out_len:32;
        memcpy(out,t,n);out+=n;out_len-=n;t_len=32;++counter;
    }
}
}
