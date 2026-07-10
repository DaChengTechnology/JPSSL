#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
namespace jpssl {
inline constexpr size_t SHA3_256_DIGEST_SIZE=32, SHA3_384_DIGEST_SIZE=48, SHA3_512_DIGEST_SIZE=64;
struct sha3_ctx{uint64_t state[25];uint8_t buf[200];size_t rate_bytes,output_len,buf_len;};
void sha3_256_init(sha3_ctx*);
void sha3_384_init(sha3_ctx*);
void sha3_512_init(sha3_ctx*);
void sha3_update(sha3_ctx*,const uint8_t*,size_t);
void sha3_final(sha3_ctx*,uint8_t digest[SHA3_512_DIGEST_SIZE]);
inline std::string sha3_hex(const uint8_t d[],size_t n){char b[129];for(size_t i=0;i<n;++i)sprintf(b+i*2,"%02x",d[i]);return{b};}
}
