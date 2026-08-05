#pragma once
/**
 * ed25519_batch.hpp — Ed25519 批量验证 + SIMD 后端分派
 *
 * 批量验证使用随机盲化的多标量乘法（共享倍点链），与指令集无关；
 * 单块批大小见 ed25519_batch_size()（当前 128 条/块）。
 */
#include "ed25519.hpp"
#include <cstddef>
#include <cstdint>

namespace jpssl {

// ──────────── 批量验证 ────────────

/// 返回当前批量后端的分块大小（128 条签名/块）
int ed25519_batch_size();

/**
 * 批量验证多个 Ed25519 签名（全部必须有效）
 *
 * @param pubs    公钥数组，pubs[i] 指向 32 字节公钥
 * @param msgs    消息数组，msgs[i] 指向消息数据
 * @param msg_lens 消息长度数组
 * @param sigs    签名数组，sigs[i] 指向 64 字节签名
 * @param count   签名数量
 * @return        全部有效返回 true，任一无效返回 false
 */
bool ed25519_batch_verify(
    const uint8_t* const* pubs,
    const uint8_t* const* msgs,
    const size_t* msg_lens,
    const uint8_t* const* sigs,
    int count);

// ──────────── 后端内部接口（分派用）────────────

namespace detail {

/// 单次批验证（count <= batch_size）
bool ed25519_batch_verify_cpu(
    const uint8_t* const* pubs, const uint8_t* const* msgs,
    const size_t* msg_lens, const uint8_t* const* sigs, int count);

#ifdef JP_AVX512
bool ed25519_batch_verify_avx512(
    const uint8_t* const* pubs, const uint8_t* const* msgs,
    const size_t* msg_lens, const uint8_t* const* sigs, int count);
#endif

} // namespace detail

} // namespace jpssl
