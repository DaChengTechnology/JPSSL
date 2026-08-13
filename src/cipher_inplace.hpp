/**
 * cipher_inplace.hpp — 内部头文件：零拷贝（就地）AEAD 接口
 *
 * 仅供 TLS 记录层使用（src/tls.cpp）。就地接口把密文/明文直接写回输入
 * 缓冲（buf 同时作为输入与输出，容量 >= data_len），避免中间向量拷贝。
 *
 * 库外（公共头文件 include/*.hpp）只暴露非零拷贝的 vector/span API；
 * 本文件不随库安装。
 */
#pragma once

#include "aes.hpp"
#include "chacha20_poly1305.hpp"
#include "sm4_gcm.hpp"
#include "sm4_ccm.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace jpssl {

// ── AES-GCM（自动分派：AVX512 > VAES > AVX2 > 软件）──

/// 就地加密：buf 同时作为明文输入与密文输出（容量 >= data_len）
void aes_gcm_encrypt_inplace(const aes_context& ctx,
                             const uint8_t* iv, size_t iv_len,
                             uint8_t* buf, size_t data_len,
                             std::span<const uint8_t> aad,
                             uint8_t* tag, size_t tag_len = 16);

/// 就地解密：buf 同时作为密文输入与明文输出（容量 >= data_len）
bool aes_gcm_decrypt_inplace(const aes_context& ctx,
                             const uint8_t* iv, size_t iv_len,
                             uint8_t* buf, size_t data_len,
                             std::span<const uint8_t> aad,
                             const uint8_t* tag, size_t tag_len);

// ── AES-CCM ──

void aes_ccm_encrypt_inplace(const aes_context& ctx,
                             const uint8_t* nonce, size_t nonce_len,
                             uint8_t* buf, size_t data_len,
                             std::span<const uint8_t> aad,
                             uint8_t* tag, size_t tag_len);

bool aes_ccm_decrypt_inplace(const aes_context& ctx,
                             const uint8_t* nonce, size_t nonce_len,
                             uint8_t* buf, size_t data_len,
                             std::span<const uint8_t> aad,
                             const uint8_t* tag, size_t tag_len);

// ── ChaCha20-Poly1305 ──

void chacha20_poly1305_encrypt_inplace(const uint8_t key[32], const uint8_t nonce[12],
                                       uint8_t* buf, size_t data_len,
                                       std::span<const uint8_t> aad,
                                       uint8_t tag[16]);

bool chacha20_poly1305_decrypt_inplace(const uint8_t key[32], const uint8_t nonce[12],
                                       uint8_t* buf, size_t data_len,
                                       std::span<const uint8_t> aad,
                                       const uint8_t tag[16]);

// ── SM4-GCM ──

void sm4_gcm_encrypt_inplace(const sm4_ctx* ctx,
                             const uint8_t* iv, size_t iv_len,
                             uint8_t* buf, size_t data_len,
                             std::span<const uint8_t> aad,
                             uint8_t* tag, size_t tag_len = 16);

bool sm4_gcm_decrypt_inplace(const sm4_ctx* ctx,
                             const uint8_t* iv, size_t iv_len,
                             uint8_t* buf, size_t data_len,
                             std::span<const uint8_t> aad,
                             const uint8_t* tag, size_t tag_len);

// Auto-dispatched in-place variants (GFNI > AVX2 > scalar CPU), used by
// the TLS record layer. SM4 cipher suites are TLS 1.3 only (RFC 8998);
// TLS 1.2 has no standardized SM4 suite and rejects it at the client.
void sm4_gcm_encrypt_inplace_auto(const sm4_ctx* ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len = 16);

bool sm4_gcm_decrypt_inplace_auto(const sm4_ctx* ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len);

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
void sm4_gcm_encrypt_avx2_inplace(const sm4_ctx* ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len = 16);
bool sm4_gcm_decrypt_avx2_inplace(const sm4_ctx* ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len);
#endif // (__x86_64__ || _M_X64) && JP_AVX2

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
void sm4_gcm_encrypt_gfni_inplace(const sm4_ctx* ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len = 16);
bool sm4_gcm_decrypt_gfni_inplace(const sm4_ctx* ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len);
#endif // (__x86_64__ || _M_X64) && JP_GFNI

// ── SM4-CCM ──

void sm4_ccm_encrypt_inplace(const sm4_ctx* ctx,
                             const uint8_t* nonce, size_t nonce_len,
                             uint8_t* buf, size_t data_len,
                             std::span<const uint8_t> aad,
                             uint8_t* tag, size_t tag_len);

bool sm4_ccm_decrypt_inplace(const sm4_ctx* ctx,
                             const uint8_t* nonce, size_t nonce_len,
                             uint8_t* buf, size_t data_len,
                             std::span<const uint8_t> aad,
                             const uint8_t* tag, size_t tag_len);

// Auto-dispatched in-place variants (GFNI > scalar CPU), used by the TLS
// record layer.
void sm4_ccm_encrypt_inplace_auto(const sm4_ctx* ctx,
                                  const uint8_t* nonce, size_t nonce_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len);

bool sm4_ccm_decrypt_inplace_auto(const sm4_ctx* ctx,
                                  const uint8_t* nonce, size_t nonce_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len);

#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_GFNI)
void sm4_ccm_encrypt_gfni_inplace(const sm4_ctx* ctx,
                                  const uint8_t* nonce, size_t nonce_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len);
bool sm4_ccm_decrypt_gfni_inplace(const sm4_ctx* ctx,
                                  const uint8_t* nonce, size_t nonce_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len);
#endif // (__x86_64__ || _M_X64) && JP_GFNI

// ── GCM 后端就地入口（aes_gcm_auto 分派内部使用，不对外）──

void aes_gcm_encrypt_avx2_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len = 16);
bool aes_gcm_decrypt_avx2_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len);

void aes_gcm_encrypt_vaes_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len = 16);
bool aes_gcm_decrypt_vaes_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len);

void aes_gcm_encrypt_avx512_inplace(const aes_context& ctx,
                                    const uint8_t* iv, size_t iv_len,
                                    uint8_t* buf, size_t data_len,
                                    std::span<const uint8_t> aad,
                                    uint8_t* tag, size_t tag_len = 16);
bool aes_gcm_decrypt_avx512_inplace(const aes_context& ctx,
                                    const uint8_t* iv, size_t iv_len,
                                    uint8_t* buf, size_t data_len,
                                    std::span<const uint8_t> aad,
                                    const uint8_t* tag, size_t tag_len);

#if defined(JP_NEON) && defined(__aarch64__)
// ARM NEON AES-GCM 就地后端（aes_gcm_neon.cpp）
void aes_gcm_encrypt_neon_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  uint8_t* tag, size_t tag_len = 16);
bool aes_gcm_decrypt_neon_inplace(const aes_context& ctx,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* buf, size_t data_len,
                                  std::span<const uint8_t> aad,
                                  const uint8_t* tag, size_t tag_len);
#endif

} // namespace jpssl
