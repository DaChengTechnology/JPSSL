#include "hkdf.hpp"
#include "hmac.hpp"
#include <cstring>
#include <vector>
namespace jpssl {

// ── HKDF-SHA256 ──
void hkdf_extract(const uint8_t* salt,size_t salt_len,const uint8_t* ikm,size_t ikm_len,uint8_t prk[32]){
    if(!salt||salt_len==0){uint8_t z[32]={};hmac_sha256(z,32,ikm,ikm_len,prk);}
    else hmac_sha256(salt,salt_len,ikm,ikm_len,prk);
}
void hkdf_expand(const uint8_t prk[32],const uint8_t* info,size_t info_len,uint8_t* out,size_t out_len){
    uint8_t t[32];size_t t_len=0;
    uint8_t counter=1;
    while(out_len>0){
        std::vector<uint8_t> hmac_in;
        if(t_len>0)hmac_in.insert(hmac_in.end(),t,t+32);
        hmac_in.insert(hmac_in.end(),info,info+info_len);
        hmac_in.push_back(counter);
        hmac_sha256(prk,32,hmac_in.data(),hmac_in.size(),t);
        size_t n=(out_len<32)?out_len:32;
        memcpy(out,t,n);out+=n;out_len-=n;t_len=32;++counter;
    }
}

// ── HKDF-SHA384 ──
void hkdf_extract_sha384(const uint8_t* salt,size_t salt_len,const uint8_t* ikm,size_t ikm_len,uint8_t prk[48]){
    if(!salt||salt_len==0){uint8_t z[48]={};hmac_sha384(z,48,ikm,ikm_len,prk);}
    else hmac_sha384(salt,salt_len,ikm,ikm_len,prk);
}
void hkdf_expand_sha384(const uint8_t prk[48],const uint8_t* info,size_t info_len,uint8_t* out,size_t out_len){
    uint8_t t[48];size_t t_len=0;
    uint8_t counter=1;
    while(out_len>0){
        std::vector<uint8_t> hmac_in;
        if(t_len>0)hmac_in.insert(hmac_in.end(),t,t+48);
        hmac_in.insert(hmac_in.end(),info,info+info_len);
        hmac_in.push_back(counter);
        hmac_sha384(prk,48,hmac_in.data(),hmac_in.size(),t);
        size_t n=(out_len<48)?out_len:48;
        memcpy(out,t,n);out+=n;out_len-=n;t_len=48;++counter;
    }
}

}