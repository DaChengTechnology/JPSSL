/**
 * ed448_batch_dispatch.cpp — Ed448 batch verification auto-dispatch
 *
 * Priority: AVX512 > AVX2 > CPU scalar
 */
#include "ed448_batch.hpp"
#include "cpu_features.hpp"

namespace jpssl {

static int g_batch_size = 0;

int ed448_batch_size() {
    if (g_batch_size == 0) {
        auto feats = cpu_features::detect();
        if (feats.avx512) {
            g_batch_size = 8;
        } else if (feats.avx2) {
            g_batch_size = 4;
        } else {
            g_batch_size = 1;
        }
    }
    return g_batch_size;
}

bool ed448_batch_verify(
    const uint8_t* const* pubs,
    const uint8_t* const* msgs,
    const size_t* msg_lens,
    const uint8_t* const* sigs,
    int count)
{
    if (count <= 0) return true;

    int bs = ed448_batch_size();

    for (int offset = 0; offset < count; offset += bs) {
        int n = (offset + bs <= count) ? bs : (count - offset);

#ifdef JP_AVX512
        auto feats = cpu_features::detect();
        if (feats.avx512) {
            if (!detail::ed448_batch_verify_avx512(
                    pubs + offset, msgs + offset, msg_lens + offset, sigs + offset, n))
                return false;
            continue;
        }
#endif

#ifdef JP_AVX2
        if (cpu_has_avx2()) {
            if (!detail::ed448_batch_verify_avx2(
                    pubs + offset, msgs + offset, msg_lens + offset, sigs + offset, n))
                return false;
            continue;
        }
#endif

        if (!detail::ed448_batch_verify_cpu(
                pubs + offset, msgs + offset, msg_lens + offset, sigs + offset, n))
            return false;
    }

    return true;
}

} // namespace jpssl
