#pragma once
/**
 * sm4_gcm_internal.hpp - SM4-GCM internal shared helpers.
 *
 * Not installed / not part of the public API. Shared between the scalar
 * backend (sm4_gcm.cpp), the AVX2 backend (sm4_gcm_avx2.cpp) and the
 * AVX2 CTR engine (sm4_avx2.cpp).
 */
#include "sm4.hpp"

#include <cstddef>
#include <cstdint>

namespace jpssl {

/// Build J0 from IV (NIST SP 800-38D 7.1). IV length 12 -> IV || 0^31 || 1,
/// otherwise J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64).
void sm4_gcm_make_j0(const uint8_t H[16],
                     const uint8_t* iv, size_t iv_len,
                     uint8_t j0[16]);

/// GHASH(AAD || 0-pad || C || 0-pad || len(A)_64 || len(C)_64).
/// Uses the PCLMULQDQ fast path when available, software fallback otherwise.
void sm4_gcm_ghash(const uint8_t H[16],
                   const uint8_t* aad, size_t aad_len,
                   const uint8_t* ct, size_t ct_len,
                   uint8_t out[16]);

/// AVX2 8-way parallel SM4-CTR (keystream generation, GCM inc32 semantics).
#if (defined(__x86_64__) || defined(_M_X64)) && defined(JP_AVX2)
void sm4_ctr_avx2(const sm4_ctx* ctx, const uint8_t* ctr_block,
                  const uint8_t* input, uint8_t* output, size_t len);
#endif

} // namespace jpssl
