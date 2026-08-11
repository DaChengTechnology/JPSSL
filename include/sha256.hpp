#pragma once
/** sha256.hpp — SHA-256 哈希（FIPS 180-4） */
#include <cstddef>
#include <cstdint>
#include "jpssl_span.hpp"
#include <string>
namespace jpssl {
inline constexpr size_t SHA256_DIGEST_SIZE=32, SHA256_BLOCK_SIZE=64;
struct sha256_ctx { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t buf_len; };
void sha256_init(sha256_ctx*);
void sha256_update(sha256_ctx*,const uint8_t*,size_t);
void sha256_final(sha256_ctx*,uint8_t digest[32]);
#if defined(JP_NEON) && defined(__aarch64__)
/// ARMv8 SHA-256 扩展加速的单块变换（sha256_neon.cpp）
void sha256_transform_neon(uint32_t h[8], const uint8_t data[64]);
#endif
inline std::string sha256_hex(const uint8_t d[32]){char b[65];for(int i=0;i<32;++i)sprintf(b+i*2,"%02x",d[i]);return{b};}
void sha256_sha_ni(uint8_t digest[32], const uint8_t* data, size_t len);
// 便捷单次 SHA-256
inline void sha256(const uint8_t* data, size_t len, uint8_t out[32]){
    sha256_ctx ctx; sha256_init(&ctx);
    if(len) sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}
}
