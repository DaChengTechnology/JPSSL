/**
 * ed448_avx2.cpp — AVX2 backend (compiled with -mavx2)
 */
#include "ed448.hpp"
#include "fe_448.hpp"
#include "sha3.hpp"
#include "rsa.hpp"
#include <cstring>

namespace jpssl { namespace ed448_avx2_impl {
#include "ed448_body.inc"
} }

#include "ed448_batch.hpp"

namespace jpssl { namespace detail {
bool ed448_batch_verify_avx2(
    const uint8_t* const* pubs, const uint8_t* const* msgs,
    const size_t* msg_lens, const uint8_t* const* sigs, int count)
{
    for (int i = 0; i < count; i++)
        if (!ed448_avx2_impl::ed448_verify_impl(pubs[i], msgs[i], msg_lens[i], sigs[i]))
            return false;
    return true;
}
} } // namespace jpssl::detail
