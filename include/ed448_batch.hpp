#pragma once
/**
 * ed448_batch.hpp — Ed448 batch verification + SIMD backend dispatch
 *
 * Backend priority: AVX512 (8-way) > AVX2 (4-way) > Scalar (1-way)
 */
#include "ed448.hpp"
#include <cstddef>
#include <cstdint>

namespace jpssl {

// ──────────── Batch verification ────────────

/// Return the batch size of the best available backend (AVX512=8, AVX2=4, CPU=1)
int ed448_batch_size();

/**
 * Batch verify multiple Ed448 signatures (all must be valid)
 *
 * @param pubs     Public key array, pubs[i] points to 57-byte public key
 * @param msgs     Message array, msgs[i] points to message data
 * @param msg_lens Message length array
 * @param sigs     Signature array, sigs[i] points to 114-byte signature
 * @param count    Number of signatures
 * @return         true if all valid, false otherwise
 */
bool ed448_batch_verify(
    const uint8_t* const* pubs,
    const uint8_t* const* msgs,
    const size_t* msg_lens,
    const uint8_t* const* sigs,
    int count);

// ──────────── Backend internal interfaces (dispatch) ────────────

namespace detail {

bool ed448_batch_verify_cpu(
    const uint8_t* const* pubs, const uint8_t* const* msgs,
    const size_t* msg_lens, const uint8_t* const* sigs, int count);

#ifdef JP_AVX2
bool ed448_batch_verify_avx2(
    const uint8_t* const* pubs, const uint8_t* const* msgs,
    const size_t* msg_lens, const uint8_t* const* sigs, int count);
#endif

#ifdef JP_AVX512
bool ed448_batch_verify_avx512(
    const uint8_t* const* pubs, const uint8_t* const* msgs,
    const size_t* msg_lens, const uint8_t* const* sigs, int count);
#endif

} // namespace detail

} // namespace jpssl
