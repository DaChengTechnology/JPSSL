/** sm3.cpp — SM3 密码杂凑算法（GM/T 0004-2012）
 *
 *  优化：
 *   - 压缩函数按 8 轮一组展开（64 轮共 8 组），T/FF/GG 均编译期为常量，
 *     消除按轮的分支与函数调用；
 *   - W'_j = W_j ^ W_{j+4} 在轮内即时计算，省去 64 字中间数组；
 *   - 消息扩展、填充路径均无逐字节热点。
 */
#include "sm3.hpp"
#include <cstring>

#if defined(JP_HAVE_SM3_ASM)
// Windows x64 (MSVC): scalar asm compression, src/sm3_win.asm
extern "C" void sm3_compress_asm(uint32_t h[8], const uint8_t block[64]);
#endif

namespace jpssl {

// ARM NEON (FEAT_SM3) 压缩函数入口；默认 nullptr（标量）。
// 由 src/sm3_neon.cpp 在支持 SM3 指令的机器上静态接管。
void (*sm3_cf_ptr)(uint32_t[8], const uint8_t[64]) = nullptr;

// ─── 常量 ──────────────────────────────────────────────────────────────

// 初始值 IV（大端序）
static const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// T_j 常量：j=0..15 → 0x79cc4519；j=16..63 → 0x7a879d8a

// ─── 基本操作 ──────────────────────────────────────────────────────────

static inline uint32_t ROTL(uint32_t x, int n) {
    return (x << n) | (x >> ((32 - n) & 31));
}

// P0(X) = X ^ (X <<< 9) ^ (X <<< 17)
static inline uint32_t P0(uint32_t x) {
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

// P1(X) = X ^ (X <<< 15) ^ (X <<< 23)
static inline uint32_t P1(uint32_t x) {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

// FF_j / GG_j（0..15 与 16..63 两组，编译期为常量选择）
static inline uint32_t FF0(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static inline uint32_t FF1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (x & z) | (y & z);
}
static inline uint32_t GG0(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static inline uint32_t GG1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}

static void load_be32(uint32_t dst[16], const uint8_t src[64]);

// ─── 压缩函数 ───────────────────────────────────────────────────────────

// CF(V, B)：消息扩展 + 64 轮（8 轮/组展开）
static void sm3_cf(uint32_t v[8], const uint8_t block[64]) {
    if (sm3_cf_ptr) {
        sm3_cf_ptr(v, block);
        return;
    }
#if defined(JP_HAVE_SM3_ASM)
    sm3_compress_asm(v, block);
#else
    uint32_t w[68];  // W_0 .. W_67

    uint32_t be[16];
    load_be32(be, block);
    for (int j = 0; j < 16; ++j) w[j] = be[j];
    for (int j = 16; j < 68; ++j) {
        w[j] = P1(w[j-16] ^ w[j-9] ^ ROTL(w[j-3], 15))
             ^ ROTL(w[j-13], 7) ^ w[j-6];
    }

    uint32_t a = v[0], b = v[1], c = v[2], d = v[3];
    uint32_t e = v[4], f = v[5], g = v[6], h = v[7];

#define SM3_ROUND(FF, GG, TJ, J) do {                                      \
    uint32_t ss1 = ROTL(ROTL(a, 12) + e + ROTL(TJ, (J) & 31), 7);          \
    uint32_t ss2 = ss1 ^ ROTL(a, 12);                                      \
    uint32_t tt1 = FF(a, b, c) + d + ss2 + (w[J] ^ w[J + 4]);              \
    uint32_t tt2 = GG(e, f, g) + h + ss1 + w[J];                           \
    d = c; c = ROTL(b, 9); b = a; a = tt1;                                 \
    h = g; g = ROTL(f, 19); f = e; e = P0(tt2);                            \
} while (0)

#define SM3_R8(FF, GG, TJ, J) do {       \
    SM3_ROUND(FF, GG, TJ, J);            \
    SM3_ROUND(FF, GG, TJ, (J) + 1);      \
    SM3_ROUND(FF, GG, TJ, (J) + 2);      \
    SM3_ROUND(FF, GG, TJ, (J) + 3);      \
    SM3_ROUND(FF, GG, TJ, (J) + 4);      \
    SM3_ROUND(FF, GG, TJ, (J) + 5);      \
    SM3_ROUND(FF, GG, TJ, (J) + 6);      \
    SM3_ROUND(FF, GG, TJ, (J) + 7);      \
} while (0)

    for (int j = 0; j < 16; j += 8) SM3_R8(FF0, GG0, 0x79cc4519u, j);
    for (int j = 16; j < 64; j += 8) SM3_R8(FF1, GG1, 0x7a879d8au, j);

#undef SM3_ROUND
#undef SM3_R8

    v[0] ^= a; v[1] ^= b; v[2] ^= c; v[3] ^= d;
    v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
#endif
}

// ─── 大端读写 ───────────────────────────────────────────────────────────

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

// ─── 公开 API ───────────────────────────────────────────────────────────

void sm3_init(sm3_ctx* ctx) {
    std::memcpy(ctx->h, IV, sizeof(IV));
    ctx->len     = 0;
    ctx->buf_len = 0;
}

void sm3_update(sm3_ctx* ctx, const uint8_t* data, size_t len) {
    if (len == 0) return;
    ctx->len += len;

    // 缓冲区内已有数据：先补齐一个块
    if (ctx->buf_len > 0) {
        size_t copy = SM3_BLOCK_SIZE - ctx->buf_len;
        if (copy > len) copy = len;
        std::memcpy(ctx->buf + ctx->buf_len, data, copy);
        ctx->buf_len += copy;
        data += copy;
        len  -= copy;

        if (ctx->buf_len == SM3_BLOCK_SIZE) {
            sm3_cf(ctx->h, ctx->buf);
            ctx->buf_len = 0;
        }
    }

    // 整块处理
    while (len >= SM3_BLOCK_SIZE) {
        sm3_cf(ctx->h, data);
        data += SM3_BLOCK_SIZE;
        len  -= SM3_BLOCK_SIZE;
    }

    if (len > 0) {
        std::memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

void sm3_final(sm3_ctx* ctx, uint8_t digest[SM3_DIGEST_SIZE]) {
    uint64_t bits = ctx->len * 8;

    ctx->buf[ctx->buf_len++] = 0x80;

    if (ctx->buf_len > 56) {
        std::memset(ctx->buf + ctx->buf_len, 0, SM3_BLOCK_SIZE - ctx->buf_len);
        ctx->buf_len = SM3_BLOCK_SIZE;
        sm3_cf(ctx->h, ctx->buf);
        ctx->buf_len = 0;
    }

    std::memset(ctx->buf + ctx->buf_len, 0, 56 - ctx->buf_len);
    ctx->buf_len = 56;

    // 64-bit 消息长度（bit 数），大端
    for (int i = 7; i >= 0; --i)
        ctx->buf[ctx->buf_len++] = (uint8_t)(bits >> (i * 8));

    sm3_cf(ctx->h, ctx->buf);

    store_be32(digest, ctx->h);
}

} // namespace jpssl
