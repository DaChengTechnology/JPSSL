/**
 * ed25519_batch_cpu.cpp — CPU 标量批量验证后端
 *
 * 实现：循环调用 ed25519_verify 逐条验证
 */
#include "ed25519_batch.hpp"

namespace jpssl {
namespace detail {

bool ed25519_batch_verify_cpu(
    const uint8_t* const* pubs,
    const uint8_t* const* msgs,
    const size_t* msg_lens,
    const uint8_t* const* sigs,
    int count)
{
    for (int i = 0; i < count; i++) {
        if (!ed25519_verify(pubs[i], msgs[i], msg_lens[i], sigs[i]))
            return false;
    }
    return true;
}

} // namespace detail
} // namespace jpssl
