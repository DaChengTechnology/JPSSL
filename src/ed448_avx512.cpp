/**
 * ed448_avx512.cpp - Ed448 batch verification, AVX512 8-way vectorized backend
 *
 * Compiled with /arch:AVX512 (MSVC) or -mavx512f.  Verifies 8 independent
 * signatures per batch with lane-wise SIMD field/point arithmetic.
 */
#include "ed448.hpp"
#include "ed448_batch.hpp"
#include "fe_448.hpp"
#include "sha3.hpp"
#include "fe_448_simd.hpp"
#include <cstring>

namespace jpssl { namespace ed448_avx512_impl {
#include "ed448_simd_body.inc"
} }

namespace jpssl { namespace detail {

bool ed448_batch_verify_avx512(
    const uint8_t* const* pubs, const uint8_t* const* msgs,
    const size_t* msg_lens, const uint8_t* const* sigs, int count)
{
    for (int off = 0; off < count; off += JF448_LANES) {
        int n = (off + JF448_LANES <= count) ? JF448_LANES : (count - off);
        if (!ed448_avx512_impl::ed448_batch_verify_simd(
                pubs + off, msgs + off, msg_lens + off, sigs + off, n))
            return false;
    }
    return true;
}

} } // namespace jpssl::detail
