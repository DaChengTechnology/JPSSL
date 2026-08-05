#pragma once
/** sha1.hpp -- SHA-1 hash (FIPS 180-4). */
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

namespace jpssl {

inline constexpr size_t SHA1_DIGEST_SIZE = 20, SHA1_BLOCK_SIZE = 64;

struct sha1_ctx {
    uint32_t h[5];
    uint64_t len;
    uint8_t  buf[64];
    size_t   buf_len;
};

void sha1_init(sha1_ctx*);
void sha1_update(sha1_ctx*, const uint8_t*, size_t);
void sha1_final(sha1_ctx*, uint8_t digest[20]);

inline std::string sha1_hex(const uint8_t d[20]) {
    char b[41];
    for (int i = 0; i < 20; ++i) std::sprintf(b + i * 2, "%02x", d[i]);
    return {b};
}

/// One-shot SHA-1.
inline void sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
    sha1_ctx ctx;
    sha1_init(&ctx);
    if (len) sha1_update(&ctx, data, len);
    sha1_final(&ctx, out);
}

/// AVX2 multi-buffer SHA-1: hashes 8 equal-length messages in parallel.
/// `out` is 8 x 20 bytes.  Guarded by compile flags on x86-64; a scalar
/// fallback keeps the symbol available on every platform.
void sha1_multi_avx2(const uint8_t* const msgs[8], size_t len, uint8_t out[8][20]);

/// AVX-512 multi-buffer SHA-1: hashes 16 equal-length messages in parallel.
void sha1_multi_avx512(const uint8_t* const msgs[16], size_t len, uint8_t out[16][20]);

/// Runtime-dispatched batch SHA-1 for `count` equal-length messages
/// (AVX-512 16-way > AVX2 8-way > scalar).  `outs` must hold count * 20 bytes.
void sha1_batch(const uint8_t* const* msgs, size_t len, uint8_t* outs, size_t count);

} // namespace jpssl
