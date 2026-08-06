#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
namespace jpssl {
inline constexpr size_t SHA512_DIGEST_SIZE=64, SHA384_DIGEST_SIZE=48, SHA512_BLOCK_SIZE=128;
struct sha512_ctx{uint64_t h[8];uint64_t len;uint8_t buf[128];size_t buf_len;bool is_384;};
void sha512_init(sha512_ctx*);
void sha384_init(sha512_ctx*);
void sha512_update(sha512_ctx*,const uint8_t*,size_t);
void sha512_final(sha512_ctx*,uint8_t*);
#if defined(JP_NEON) && defined(__aarch64__) && defined(__ARM_FEATURE_SHA512)
/// ARMv8.2 SHA-512 扩展加速的单块变换（sha512_neon.cpp，FEAT_SHA512）
void sha512_transform_neon(uint64_t h[8], const uint8_t data[128]);
#endif
inline std::string sha512_hex(const uint8_t d[64]){char b[129];for(int i=0;i<64;++i)sprintf(b+i*2,"%02x",d[i]);return{b};}
inline std::string sha384_hex(const uint8_t d[48]){char b[97];for(int i=0;i<48;++i)sprintf(b+i*2,"%02x",d[i]);return{b};}

// One-shot 便捷接口：输入 data + len，直接输出摘要
inline void sha512(const uint8_t* data, size_t len, uint8_t out[64]){
    sha512_ctx ctx; sha512_init(&ctx);
    if(len) sha512_update(&ctx,data,len);
    sha512_final(&ctx,out);
}
inline void sha384(const uint8_t* data, size_t len, uint8_t out[48]){
    sha512_ctx ctx; sha384_init(&ctx);
    if(len) sha512_update(&ctx,data,len);
    sha512_final(&ctx,out);
}
// MUSA GPU SHA-512 host API
void musa_sha512_init();
void musa_sha512_cleanup();
void musa_sha512_compute(const uint8_t* input, size_t input_len, uint8_t* output, bool is_384);
void musa_sha512_batch(const uint8_t* inputs, size_t input_len, uint8_t* outputs, int num_msgs, bool is_384);
}
