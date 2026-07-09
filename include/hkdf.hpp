#pragma once
/** hkdf.hpp — HKDF-SHA256（RFC 5869, TLS 1.3 密钥派生核心） */
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
namespace jpssl {
void hkdf_extract(const uint8_t* salt,size_t salt_len,const uint8_t* ikm,size_t ikm_len,uint8_t prk[32]);
void hkdf_expand(const uint8_t prk[32],const uint8_t* info,size_t info_len,uint8_t* out,size_t out_len);
inline void hkdf_expand_label(const uint8_t secret[32],const char* label,const uint8_t* ctx,size_t ctx_len,uint8_t* out,size_t out_len){
  /* TLS 1.3 HkdfLabel: length || "tls13 " || label || ctx_len || ctx */
  uint8_t info[256];size_t pos=0;
  info[pos++]=(uint8_t)(out_len>>8);info[pos++]=(uint8_t)(out_len);
  const char* prefix="tls13 ";size_t pl=strlen(prefix)+strlen(label);
  info[pos++]=(uint8_t)pl;memcpy(info+pos,prefix,strlen(prefix));pos+=strlen(prefix);
  memcpy(info+pos,label,strlen(label));pos+=strlen(label);
  info[pos++]=(uint8_t)ctx_len;if(ctx_len)memcpy(info+pos,ctx,ctx_len);pos+=ctx_len;
  hkdf_expand(secret,info,pos,out,out_len);
}
}
