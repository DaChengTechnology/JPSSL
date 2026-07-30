/** sm3.cpp — SM3 密码杂凑算法（GM/T 0004-2012） */
#include "sm3.hpp"
#include <cstring>

namespace jpssl {

// ── 常量 ────────────────────────────────────────────────────────────────

// 初始值 IV（大端序）
static const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// T_j 常量
// T_j = 0x79cc4519 for 0 ≤ j ≤ 15
// T_j = 0x7a879d8a for 16 ≤ j ≤ 63
static inline uint32_t T(int j) {
    return (j < 16) ? 0x79cc4519u : 0x7a879d8au;
}

// ── 基本操作 ────────────────────────────────────────────────────────────

// 循环左移
static inline uint32_t ROTL(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// P0 置换：P0(X) = X ⊕ (X <<< 9) ⊕ (X <<< 17)
static inline uint32_t P0(uint32_t x) {
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

// P1 置换：P1(X) = X ⊕ (X <<< 15) ⊕ (X <<< 23)
static inline uint32_t P1(uint32_t x) {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

// FF_j 布尔函数
// 0 ≤ j ≤ 15: FF_j(X,Y,Z) = X ⊕ Y ⊕ Z
// 16 ≤ j ≤ 63: FF_j(X,Y,Z) = (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z)
static inline uint32_t FF(int j, uint32_t x, uint32_t y, uint32_t z) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}

// GG_j 布尔函数
// 0 ≤ j ≤ 15: GG_j(X,Y,Z) = X ⊕ Y ⊕ Z
// 16 ≤ j ≤ 63: GG_j(X,Y,Z) = (X ∧ Y) ∨ (¬X ∧ Z)
static inline uint32_t GG(int j, uint32_t x, uint32_t y, uint32_t z) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | (~x & z);
}

// ── 压缩函数 ────────────────────────────────────────────────────────────

// CF(V, B) — 压缩函数
static void sm3_cf(uint32_t v[8], const uint32_t block[16]) {
    uint32_t w[68];      // W_0 .. W_67
    uint32_t wp[64];     // W'_0 .. W'_63

    // 消息扩展 — 第一阶段
    for (int j = 0; j < 16; ++j) {
        w[j] = block[j];
    }
    for (int j = 16; j < 68; ++j) {
        w[j] = P1(w[j-16] ^ w[j-9] ^ ROTL(w[j-3], 15))
             ^ ROTL(w[j-13], 7) ^ w[j-6];
    }
    for (int j = 0; j < 64; ++j) {
        wp[j] = w[j] ^ w[j+4];
    }

    // 压缩 — 64 轮
    uint32_t a = v[0], b = v[1], c = v[2], d = v[3];
    uint32_t e = v[4], f = v[5], g = v[6], h = v[7];

    for (int j = 0; j < 64; ++j) {
        uint32_t ss1 = ROTL(ROTL(a, 12) + e + ROTL(T(j), (j % 32)), 7);
        uint32_t ss2 = ss1 ^ ROTL(a, 12);
        uint32_t tt1 = FF(j, a, b, c) + d + ss2 + wp[j];
        uint32_t tt2 = GG(j, e, f, g) + h + ss1 + w[j];

        d = c;
        c = ROTL(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = ROTL(f, 19);
        f = e;
        e = P0(tt2);
    }

    v[0] ^= a; v[1] ^= b; v[2] ^= c; v[3] ^= d;
    v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
}

// ── 大端读写 ────────────────────────────────────────────────────────────

static void load_be32(uint32_t dst[16], const uint8_t src[64]) {
    for (int i = 0; i < 16; ++i) {
        dst[i] = ((uint32_t)src[i*4]   << 24)
               | ((uint32_t)src[i*4+1] << 16)
               | ((uint32_t)src[i*4+2] << 8)
               |  (uint32_t)src[i*4+3];
    }
}

static void store_be32(uint8_t dst[32], const uint32_t h[8]) {
    for (int i = 0; i < 8; ++i) {
        dst[i*4]   = (uint8_t)(h[i] >> 24);
        dst[i*4+1] = (uint8_t)(h[i] >> 16);
        dst[i*4+2] = (uint8_t)(h[i] >> 8);
        dst[i*4+3] = (uint8_t)(h[i]);
    }
}

// ── 公开 API ────────────────────────────────────────────────────────────

void sm3_init(sm3_ctx* ctx) {
    std::memcpy(ctx->h, IV, sizeof(IV));
    ctx->len     = 0;
    ctx->buf_len = 0;
}

void sm3_update(sm3_ctx* ctx, const uint8_t* data, size_t len) {
    ctx->len += len;

    // 如果缓冲区有数据且新数据能填满一个块
    if (ctx->buf_len > 0) {
        size_t copy = SM3_BLOCK_SIZE - ctx->buf_len;
        if (copy > len) copy = len;
        std::memcpy(ctx->buf + ctx->buf_len, data, copy);
        ctx->buf_len += copy;
        data  += copy;
        len   -= copy;

        if (ctx->buf_len == SM3_BLOCK_SIZE) {
            uint32_t bb[16];
            load_be32(bb, ctx->buf);
            sm3_cf(ctx->h, bb);
            ctx->buf_len = 0;
        }
    }

    // 处理完整块
    while (len >= SM3_BLOCK_SIZE) {
        uint32_t bb[16];
        load_be32(bb, data);
        sm3_cf(ctx->h, bb);
        data += SM3_BLOCK_SIZE;
        len  -= SM3_BLOCK_SIZE;
    }

    // 剩余不足一个块的放入缓冲区
    if (len > 0) {
        std::memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

void sm3_final(sm3_ctx* ctx, uint8_t digest[SM3_DIGEST_SIZE]) {
    // 计算总 bit 数
    uint64_t bits = ctx->len * 8;

    // 填充：先加 0x80
    ctx->buf[ctx->buf_len++] = 0x80;

    // 如果缓冲区放不下 64-bit 长度（即需要 56 字节但 buf_len > 56）
    if (ctx->buf_len > 56) {
        while (ctx->buf_len < SM3_BLOCK_SIZE)
            ctx->buf[ctx->buf_len++] = 0;
        uint32_t bb[16];
        load_be32(bb, ctx->buf);
        sm3_cf(ctx->h, bb);
        ctx->buf_len = 0;
    }

    while (ctx->buf_len < 56)
        ctx->buf[ctx->buf_len++] = 0;

    // 以 big-endian 写入 64-bit 消息长度
    for (int i = 7; i >= 0; --i)
        ctx->buf[ctx->buf_len++] = (uint8_t)(bits >> (i * 8));

    uint32_t bb[16];
    load_be32(bb, ctx->buf);
    sm3_cf(ctx->h, bb);

    store_be32(digest, ctx->h);
}

} // namespace jpssl
