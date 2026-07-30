#pragma once
/** sm3.hpp — SM3 密码杂凑算法（GM/T 0004-2012） */
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <cstdio>

namespace jpssl {

inline constexpr size_t SM3_DIGEST_SIZE = 32;  // 256-bit
inline constexpr size_t SM3_BLOCK_SIZE  = 64;  // 512-bit

struct sm3_ctx {
    uint32_t  h[8];       // 8 个 32 位字，256-bit 状态
    uint64_t  len;        // 已处理的 bit 数
    uint8_t   buf[64];    // 未处理的块数据缓冲区
    size_t    buf_len;    // 缓冲区中已写入的字节数
};

void sm3_init(sm3_ctx* ctx);
void sm3_update(sm3_ctx* ctx, const uint8_t* data, size_t len);
void sm3_final(sm3_ctx* ctx, uint8_t digest[SM3_DIGEST_SIZE]);

/// 一次性哈希便捷函数
inline void sm3_hash(uint8_t digest[SM3_DIGEST_SIZE], const uint8_t* data, size_t len) {
    sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}

/// 返回十六进制字符串
inline std::string sm3_hex(const uint8_t d[SM3_DIGEST_SIZE]) {
    char b[65];
    for (int i = 0; i < 32; ++i) std::sprintf(b + i * 2, "%02x", d[i]);
    return {b};
}

} // namespace jpssl
