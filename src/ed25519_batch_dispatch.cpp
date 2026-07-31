/**
 * ed25519_batch_dispatch.cpp — Ed25519 批量验证自动分派
 *
 * 优先级：AVX512 > CPU 标量
 */
#include "ed25519_batch.hpp"
#include "cpu_features.hpp"

namespace jpssl {

static int g_batch_size = 0;

int ed25519_batch_size() {
    if (g_batch_size == 0) {
        auto feats = cpu_features::detect();
        if (feats.avx512) {
            g_batch_size = 8;
        } else {
            g_batch_size = 1;
        }
    }
    return g_batch_size;
}

bool ed25519_batch_verify(
    const uint8_t* const* pubs,
    const uint8_t* const* msgs,
    const size_t* msg_lens,
    const uint8_t* const* sigs,
    int count)
{
    if (count <= 0) return true;

    int bs = ed25519_batch_size();

    for (int offset = 0; offset < count; offset += bs) {
        int n = (offset + bs <= count) ? bs : (count - offset);

#ifdef JP_AVX512
        auto feats = cpu_features::detect();
        if (feats.avx512) {
            if (!detail::ed25519_batch_verify_avx512(
                    pubs + offset, msgs + offset, msg_lens + offset, sigs + offset, n))
                return false;
            continue;
        }
#endif

        if (!detail::ed25519_batch_verify_cpu(
                pubs + offset, msgs + offset, msg_lens + offset, sigs + offset, n))
            return false;
    }

    return true;
}

} // namespace jpssl
