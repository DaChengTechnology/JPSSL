#pragma once
/** sm2.hpp — SM2 椭圆曲线公钥密码算法（GM/T 0003-2012）
 *
 *  基于 SM2 推荐曲线 sm2p256v1。
 *  提供：
 *    - 密钥生成
 *    - 数字签名/验证（使用 SM3 杂凑）
 *    - ZA 计算（用户标识杂凑值）
 */
#include <cstddef>
#include <cstdint>

namespace jpssl {

constexpr size_t SM2_KEY_SIZE   = 32;   // 私钥长度
constexpr size_t SM2_PUB_SIZE   = 64;   // 未压缩公钥 (x||y)
constexpr size_t SM2_SIG_SIZE   = 64;   // 签名 (r||s)
constexpr size_t SM2_ZA_SIZE    = 32;   // SM3 杂凑值

/// 生成 SM2 密钥对
/// @param pub  输出：64 字节未压缩公钥 (x||y, 大端)
/// @param priv 输出：32 字节私钥 (大端)
void sm2_keygen(uint8_t pub[SM2_PUB_SIZE], uint8_t priv[SM2_KEY_SIZE]);

/// SM2 数字签名（使用 SM3 杂凑）
/// @param priv   32 字节私钥 (大端)
/// @param msg    消息
/// @param msg_len 消息长度
/// @param sig   输出：64 字节签名 (r||s, 大端)
/// @param za    可选：用户标识杂凑值 ZA（32 字节），设为 nullptr 则使用空标识
void sm2_sign(const uint8_t priv[SM2_KEY_SIZE],
              const uint8_t* msg, size_t msg_len,
              uint8_t sig[SM2_SIG_SIZE],
              const uint8_t za[SM2_ZA_SIZE] = nullptr);

/// SM2 签名验证
/// @param pub    64 字节公钥 (x||y, 大端)
/// @param msg    消息
/// @param msg_len 消息长度
/// @param sig   64 字节签名 (r||s, 大端)
/// @param za    可选：用户标识杂凑值 ZA（32 字节），设为 nullptr 则使用空标识
/// @return true 表示签名有效
bool sm2_verify(const uint8_t pub[SM2_PUB_SIZE],
                const uint8_t* msg, size_t msg_len,
                const uint8_t sig[SM2_SIG_SIZE],
                const uint8_t za[SM2_ZA_SIZE] = nullptr);

/// 计算用户标识杂凑值 ZA
/// @param id      用户标识字符串（如 "1234567812345678"）
/// @param id_len  用户标识长度
/// @param pub_x   公钥 X 坐标（32 字节，大端）
/// @param pub_y   公钥 Y 坐标（32 字节，大端）
/// @param za      输出：32 字节 ZA = SM3(ENTL||ID||a||b||Gx||Gy||xA||yA)
void sm2_compute_za(const uint8_t* id, size_t id_len,
                    const uint8_t pub_x[SM2_KEY_SIZE],
                    const uint8_t pub_y[SM2_KEY_SIZE],
                    uint8_t za[SM2_ZA_SIZE]);

/// 从私钥派生公钥
/// @param priv 32 字节私钥 (大端)
/// @param pub  输出：64 字节公钥 (x||y, 大端)
void sm2_pub_from_priv(const uint8_t priv[SM2_KEY_SIZE],
                       uint8_t pub[SM2_PUB_SIZE]);

/// SM2 ECDH 共享密钥算法（TLS 1.3 / RFC 8998 使用）
/// 对任意公钥点做标量乘，取结果 X 坐标作为共享密钥（32 字节）
/// @param shared 输出：32 字节共享密钥 (X 坐标, 大端)
/// @param priv   32 字节私钥 (大端，必须满足 0 < d < n)
/// @param peer_pub 对端公钥，支持 64 字节 (x||y) 或 65 字节 (0x04||x||y)
/// @param peer_pub_len 对端公钥长度 (64 或 65)
/// @return true 成功；私钥越界或公钥不在曲线上时返回 false
bool sm2_ecdh(uint8_t shared[SM2_KEY_SIZE],
              const uint8_t priv[SM2_KEY_SIZE],
              const uint8_t* peer_pub, size_t peer_pub_len);

} // namespace jpssl
