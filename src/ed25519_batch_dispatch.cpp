/**
 * ed25519_batch_dispatch.cpp — Ed25519 批量验证自动分派
 *
 * 真·多标量批验证对指令集不敏感（共享倍点链的收益来自算法而非 SIMD），
 * 所有机器统一走 CPU 批量后端，每块最多 kBatchChunk 条签名。
 */
#include "ed25519_batch.hpp"

namespace jpssl {

/// CPU 批量后端的单块签名数（对应 ed25519_batch_cpu.cpp 的 kBatchChunk）
static constexpr int kScalarBatchSize = 128;

static int g_batch_size = 0;

int ed25519_batch_size() {
    if (g_batch_size == 0) {
        g_batch_size = kScalarBatchSize;
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

        if (!detail::ed25519_batch_verify_cpu(
                pubs + offset, msgs + offset, msg_lens + offset, sigs + offset, n))
            return false;
    }

    return true;
}

} // namespace jpssl
