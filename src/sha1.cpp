/**
 * sha1.cpp -- SHA-1 scalar implementation (FIPS 180-4) plus the runtime
 * dispatch for the multi-buffer batch API.
 */
#include "sha1.hpp"

#include "cpu_features.hpp"

#include <cstring>

namespace jpssl {
namespace {

const uint32_t K[80] = {
    0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,
    0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,
    0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,
    0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,
    0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,
    0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,
    0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,
    0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,
    0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,
    0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6};

inline uint32_t ROL(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void sha1_transform_scalar(uint32_t h[5], const uint8_t data[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | data[i * 4 + 3];
    for (int i = 16; i < 80; ++i)
        w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f;
        if (i < 20)      f = (b & c) | (~b & d);
        else if (i < 40) f = b ^ c ^ d;
        else if (i < 60) f = (b & c) | (b & d) | (c & d);
        else             f = b ^ c ^ d;
        const uint32_t t = ROL(a, 5) + f + e + K[i] + w[i];
        e = d; d = c; c = ROL(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

/// 单块压缩分派：ARMv8 SHA-1 扩展可用时走 NEON，否则标量
void sha1_transform(uint32_t h[5], const uint8_t data[64]) {
#if defined(JP_NEON) && defined(__aarch64__)
    if (cpu_has_arm_sha1()) {
        sha1_transform_neon(h, data);
        return;
    }
#endif
    sha1_transform_scalar(h, data);
}

void sha1_finalize_tail(sha1_ctx* ctx) {
    const uint64_t bits = ctx->len * 8;
    ctx->buf[ctx->buf_len++] = 0x80;
    if (ctx->buf_len > 56) {
        while (ctx->buf_len < 64) ctx->buf[ctx->buf_len++] = 0;
        sha1_transform(ctx->h, ctx->buf);
        ctx->buf_len = 0;
    }
    while (ctx->buf_len < 56) ctx->buf[ctx->buf_len++] = 0;
    for (int i = 7; i >= 0; --i) ctx->buf[ctx->buf_len++] = (uint8_t)(bits >> (i * 8));
    sha1_transform(ctx->h, ctx->buf);
}

} // namespace

void sha1_init(sha1_ctx* ctx) {
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xEFCDAB89;
    ctx->h[2] = 0x98BADCFE;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xC3D2E1F0;
    ctx->len = 0;
    ctx->buf_len = 0;
}

void sha1_update(sha1_ctx* ctx, const uint8_t* data, size_t len) {
    ctx->len += len;
    if (ctx->buf_len + len < 64) {
        std::memcpy(ctx->buf + ctx->buf_len, data, len);
        ctx->buf_len += len;
        return;
    }
    size_t off = 64 - ctx->buf_len;
    std::memcpy(ctx->buf + ctx->buf_len, data, off);
    sha1_transform(ctx->h, ctx->buf);
    while (off + 64 <= len) {
        sha1_transform(ctx->h, data + off);
        off += 64;
    }
    ctx->buf_len = len - off;
    std::memcpy(ctx->buf, data + off, ctx->buf_len);
}

void sha1_final(sha1_ctx* ctx, uint8_t digest[20]) {
    sha1_finalize_tail(ctx);
    for (int i = 0; i < 5; ++i) {
        digest[i * 4]     = (uint8_t)(ctx->h[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)ctx->h[i];
    }
}

void sha1_batch(const uint8_t* const* msgs, size_t len, uint8_t* outs, size_t count) {
    size_t i = 0;
#if defined(__x86_64__) || defined(_M_X64)
    if (cpu_has_avx512bw() && count >= 16) {
        for (; i + 16 <= count; i += 16) {
            const uint8_t* g[16];
            for (int m = 0; m < 16; ++m) g[m] = msgs[i + m];
            sha1_multi_avx512(g, len, reinterpret_cast<uint8_t(*)[20]>(outs + i * 20));
        }
    }
    if (cpu_has_avx2() && count - i >= 8) {
        for (; i + 8 <= count; i += 8) {
            const uint8_t* g[8];
            for (int m = 0; m < 8; ++m) g[m] = msgs[i + m];
            sha1_multi_avx2(g, len, reinterpret_cast<uint8_t(*)[20]>(outs + i * 20));
        }
    }
#endif
    for (; i < count; ++i) sha1(msgs[i], len, outs + i * 20);
}

} // namespace jpssl
