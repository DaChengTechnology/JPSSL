#pragma once
/** hmac.hpp — HMAC-SHA256（RFC 2104） */
#include "sha256.hpp"
namespace jpssl {
void hmac_sha256(const uint8_t* key,size_t key_len,const uint8_t* msg,size_t msg_len,uint8_t mac[32]);
}
