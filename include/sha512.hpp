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
inline std::string sha512_hex(const uint8_t d[64]){char b[129];for(int i=0;i<64;++i)sprintf(b+i*2,"%02x",d[i]);return{b};}
inline std::string sha384_hex(const uint8_t d[48]){char b[97];for(int i=0;i<48;++i)sprintf(b+i*2,"%02x",d[i]);return{b};}

// MUSA GPU SHA-512 host API
void musa_sha512_init();
void musa_sha512_cleanup();
void musa_sha512_compute(const uint8_t* input, size_t input_len, uint8_t* output, bool is_384);
void musa_sha512_batch(const uint8_t* inputs, size_t input_len, uint8_t* outputs, int num_msgs, bool is_384);
}
