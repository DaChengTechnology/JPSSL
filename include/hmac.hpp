#pragma once
/** hmac.hpp — HMAC-SHA256 / HMAC-SHA384（RFC 2104） */
#include "sha256.hpp"
#include "sha512.hpp"
namespace jpssl {
void hmac_sha256(const uint8_t* key,size_t key_len,const uint8_t* msg,size_t msg_len,uint8_t mac[32]);
void hmac_sha384(const uint8_t* key,size_t key_len,const uint8_t* msg,size_t msg_len,uint8_t mac[48]);
}
