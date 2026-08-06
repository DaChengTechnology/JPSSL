#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
namespace jpssl {
inline constexpr size_t SHA3_256_DIGEST_SIZE=32, SHA3_384_DIGEST_SIZE=48, SHA3_512_DIGEST_SIZE=64;
inline constexpr size_t SHAKE128_RATE=168, SHAKE256_RATE=136;
struct sha3_ctx{uint64_t state[25];uint8_t buf[200];size_t rate_bytes,output_len,buf_len;};

#if defined(JP_NEON) && defined(__aarch64__)
/// ARMv8.2 SHA-3 扩展加速的 Keccak-f[1600] 置换（sha3_neon.cpp，FEAT_SHA3）
void keccak_f1600_neon(uint64_t s[25]);
#endif

// 固定输出 SHA3 (FIPS 202 §6.1)
void sha3_256_init(sha3_ctx*);
void sha3_384_init(sha3_ctx*);
void sha3_512_init(sha3_ctx*);
void sha3_update(sha3_ctx*,const uint8_t*,size_t);
void sha3_final(sha3_ctx*,uint8_t digest[SHA3_512_DIGEST_SIZE]);

// 可扩展输出函数 SHAKE (FIPS 202 §6.2)
// SHAKE 使用同一 sha3_ctx，domain separation 在 squeeze 时处理。
// 用法：shakeN_init -> shake_update (可多次) -> shake_squeeze(out, outlen)
void shake128_init(sha3_ctx*);
void shake256_init(sha3_ctx*);
void shake_update(sha3_ctx*,const uint8_t*,size_t);
// 吸收完成后调用，可多次 squeeze 获取更多字节
void shake_squeeze(sha3_ctx*,uint8_t* out,size_t outlen);
// 便捷封装：直接从输入计算 outlen 字节
void shake128(const uint8_t* in,size_t inlen,uint8_t* out,size_t outlen);
void shake256(const uint8_t* in,size_t inlen,uint8_t* out,size_t outlen);

inline std::string sha3_hex(const uint8_t d[],size_t n){char b[129];for(size_t i=0;i<n;++i)sprintf(b+i*2,"%02x",d[i]);return{b};}
}
