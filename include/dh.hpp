#pragma once
/** dh.hpp — RFC 7919 ffdhe2048 有限域 Diffie-Hellman（TLS 1.2 DHE / DHE_PSK） */
#include "rsa.hpp"
#include <cstddef>
#include <cstdint>

namespace jpssl::dh {

constexpr size_t  FFDHE2048_BYTES      = 256;   // 2048-bit
constexpr uint16_t FFDHE2048_NAMED_GROUP = 256; // 0x0100（RFC 7919 §2 supported_groups 编码）
constexpr uint8_t  FFDHE2048_G         = 2;     // 生成元

/// ffdhe2048 素数 p（RFC 7919 A.1，256 字节大端；与 RFC 3526 的 pi 素数不同）
extern const uint8_t ffdhe2048_p[FFDHE2048_BYTES];

/// 生成临时密钥对：priv 为 32 字节（256-bit）随机指数（RFC 7919 §5.2 建议 >= 225 bit），
/// pub = g^priv mod p（256 字节大端）。
void ffdhe2048_keypair(uint8_t pub[FFDHE2048_BYTES], uint8_t priv[32]);

/// 计算共享秘密（256 字节大端）。校验 1 < peer_pub < p-1（RFC 7919 §5.1，防小群攻击）。
/// 返回 false 表示 peer_pub 越界。
bool ffdhe2048_shared(uint8_t shared[FFDHE2048_BYTES],
                      const uint8_t priv[32],
                      const uint8_t peer_pub[FFDHE2048_BYTES]);

/// 共享秘密的最小长度大端表示（剥离前导零字节）。
/// TLS 1.2 premaster 与 DHE_PSK other_secret 使用此编码（RFC 4279 §3）。
/// 返回长度（1..256），写入 out（out 容量须 >= 256）。
size_t ffdhe2048_shared_minimal(const uint8_t shared[FFDHE2048_BYTES], uint8_t* out);

/// 便捷：把 256 字节大端值解析为 rsa_bignum（零填充）
rsa_bignum ffdhe2048_bignum(const uint8_t bytes[FFDHE2048_BYTES]);

} // namespace jpssl::dh
