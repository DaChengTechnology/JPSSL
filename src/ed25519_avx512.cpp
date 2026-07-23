/**
 * ed25519_avx512.cpp — AVX512 批量验证后端（编译器自动向量化）
 *
 * 编译标志: -mavx512f -mavx512dq
 */
#include "ed25519.hpp"
#include "fe_25519.hpp"
#include "sha512.hpp"
#include <cstring>
#include <random>

namespace jpssl { namespace avx512_impl { namespace {
#include "ed25519_body.inc"
} }

#include "ed25519_batch.hpp"

namespace jpssl {
namespace detail {

bool ed25519_batch_verify_avx512(
    const uint8_t* const* pubs,
    const uint8_t* const* msgs,
    const size_t* msg_lens,
    const uint8_t* const* sigs,
    int count)
{
    for (int i = 0; i < count; i++) {
        if (!avx512_impl::ed25519_verify(pubs[i], msgs[i], msg_lens[i], sigs[i]))
            return false;
    }
    return true;
}

} // namespace detail
} // namespace jpssl
