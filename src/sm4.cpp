/** sm4.cpp — SM4 分组密码算法（GM/T 0002-2012）
 *
 *  128 位分组，128 位密钥，32 轮 Feistel 结构。
 *  提供块加密/解密、ECB、CBC（PKCS#7）模式。
 */
#include "sm4.hpp"
#include <cstring>
#include <stdexcept>

namespace jpssl {

// ── S-Box（256 字节） ────────────────────────────────────────────────────

static constexpr uint8_t SM4_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// ── 系统参数 ────────────────────────────────────────────────────────────

static const uint32_t FK[4] = {
    0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu
};

static const uint32_t CK[32] = {
    0x00070e15u, 0x1c232a31u, 0x383f464du, 0x545b6269u,
    0x70777e85u, 0x8c939aa1u, 0xa8afb6bdu, 0xc4cbd2d9u,
    0xe0e7eef5u, 0xfc030a11u, 0x181f262du, 0x343b4249u,
    0x50575e65u, 0x6c737a81u, 0x888f969du, 0xa4abb2b9u,
    0xc0c7ced5u, 0xdce3eaf1u, 0xf8ff060du, 0x141b2229u,
    0x30373e45u, 0x4c535a61u, 0x686f767du, 0x848b9299u,
    0xa0a7aeb5u, 0xbcc3cad1u, 0xd8dfe6edu, 0xf4fb0209u,
    0x10171e25u, 0x2c333a41u, 0x484f565du, 0x646b7279u
};

// ── 基本操作 ────────────────────────────────────────────────────────────

static constexpr uint32_t ROTL(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// τ: 对 32 位字的每个字节应用 S-Box
static constexpr uint32_t sm4_tau(uint32_t a) {
    return ((uint32_t)SM4_SBOX[(a >> 24) & 0xFF] << 24)
         | ((uint32_t)SM4_SBOX[(a >> 16) & 0xFF] << 16)
         | ((uint32_t)SM4_SBOX[(a >>  8) & 0xFF] <<  8)
         |  (uint32_t)SM4_SBOX[ a        & 0xFF];
}

// L(B): 线性变换（加密/解密用）
static constexpr uint32_t sm4_L(uint32_t b) {
    return b ^ ROTL(b, 2) ^ ROTL(b, 10) ^ ROTL(b, 18) ^ ROTL(b, 24);
}

// L'(B): 线性变换（密钥扩展用）
static constexpr uint32_t sm4_Lp(uint32_t b) {
    return b ^ ROTL(b, 13) ^ ROTL(b, 23);
}

// T'(A) = L'(τ(A))
static uint32_t sm4_Tp(uint32_t a) {
    return sm4_Lp(sm4_tau(a));
}

// ── T 表：S-box 与 L 线性变换合并（加密/解密共用）──
//   T(a) = L(τ(a)) = TE0[a>>24] ^ TE1[(a>>16)&0xff] ^ TE2[(a>>8)&0xff] ^ TE3[a&0xff]
struct Sm4TBox {
    uint32_t te0[256], te1[256], te2[256], te3[256];
    constexpr Sm4TBox() : te0{}, te1{}, te2{}, te3{} {
        for (int i = 0; i < 256; ++i) {
            const uint32_t s = SM4_SBOX[i];
            te0[i] = sm4_L(s << 24);
            te1[i] = sm4_L(s << 16);
            te2[i] = sm4_L(s <<  8);
            te3[i] = sm4_L(s);
        }
    }
};
static constexpr Sm4TBox SM4_TBOX{};

static inline uint32_t sm4_TT(uint32_t a) {
    return SM4_TBOX.te0[(a >> 24) & 0xFF]
         ^ SM4_TBOX.te1[(a >> 16) & 0xFF]
         ^ SM4_TBOX.te2[(a >>  8) & 0xFF]
         ^ SM4_TBOX.te3[a & 0xFF];
}

// ── 大端读写 ────────────────────────────────────────────────────────────

static void load_be32_x4(uint32_t x[4], const uint8_t in[SM4_BLOCK_SIZE]) {
    for (int i = 0; i < 4; ++i) {
        x[i] = ((uint32_t)in[i*4]   << 24)
             | ((uint32_t)in[i*4+1] << 16)
             | ((uint32_t)in[i*4+2] <<  8)
             |  (uint32_t)in[i*4+3];
    }
}

static void store_be32_x4(uint8_t out[SM4_BLOCK_SIZE], const uint32_t x[4]) {
    for (int i = 0; i < 4; ++i) {
        out[i*4]   = (uint8_t)(x[i] >> 24);
        out[i*4+1] = (uint8_t)(x[i] >> 16);
        out[i*4+2] = (uint8_t)(x[i] >>  8);
        out[i*4+3] = (uint8_t)(x[i]);
    }
}

// ── 轮函数：F(X0, X1, X2, X3, rk) = X0 ⊕ T(X1 ⊕ X2 ⊕ X3 ⊕ rk) ───────────

// ── 密钥扩展 ────────────────────────────────────────────────────────────

void sm4_init(sm4_ctx* ctx, const uint8_t key[SM4_KEY_SIZE]) {
    // 加载 MK
    uint32_t mk[4];
    load_be32_x4(mk, key);

    // K_i = MK_i ⊕ FK_i
    uint32_t k[36];  // K_0..K_35
    k[0] = mk[0] ^ FK[0];
    k[1] = mk[1] ^ FK[1];
    k[2] = mk[2] ^ FK[2];
    k[3] = mk[3] ^ FK[3];

    // rk_i = K_{i+4} = K_i ⊕ T'(K_{i+1} ⊕ K_{i+2} ⊕ K_{i+3} ⊕ CK_i)
    for (int i = 0; i < 32; ++i) {
        k[i + 4] = k[i] ^ sm4_Tp(k[i+1] ^ k[i+2] ^ k[i+3] ^ CK[i]);
        ctx->rk[i] = k[i + 4];
    }
}

// ── 块加密/解密 ─────────────────────────────────────────────────────────

// ARM NEON (FEAT_SM4) 加速入口；默认 nullptr（标量）。
// 由 src/sm4_neon.cpp 在支持 SM4 指令的机器上静态接管。
void (*sm4_encrypt_fn)(const uint32_t rk[32], const uint8_t[16], uint8_t[16]) = nullptr;
void (*sm4_decrypt_fn)(const uint32_t rk[32], const uint8_t[16], uint8_t[16]) = nullptr;

// 核心变换（加密：正向轮密钥；解密：反向轮密钥）
static void sm4_transform(const uint32_t rk[32], const uint8_t in[SM4_BLOCK_SIZE],
                           uint8_t out[SM4_BLOCK_SIZE]) {
    uint32_t x[4];
    load_be32_x4(x, in);
    uint32_t x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];

    for (int i = 0; i < 32; ++i) {
        uint32_t t = x0 ^ sm4_TT(x1 ^ x2 ^ x3 ^ rk[i]);
        x0 = x1; x1 = x2; x2 = x3; x3 = t;
    }

    // 输出为反序：X_35, X_34, X_33, X_32
    uint32_t y[4] = { x3, x2, x1, x0 };
    store_be32_x4(out, y);
}

void sm4_encrypt_block(const sm4_ctx* ctx, const uint8_t plain[SM4_BLOCK_SIZE],
                        uint8_t cipher[SM4_BLOCK_SIZE]) {
    if (sm4_encrypt_fn) {
        sm4_encrypt_fn(ctx->rk, plain, cipher);
        return;
    }
    sm4_transform(ctx->rk, plain, cipher);
}

// 解密变换：直接以 rk[31-i] 索引反向轮密钥，避免每块复制 rk_rev 数组。
static void sm4_transform_decrypt(const uint32_t rk[32], const uint8_t in[SM4_BLOCK_SIZE],
                                  uint8_t out[SM4_BLOCK_SIZE]) {
    uint32_t x[4];
    load_be32_x4(x, in);
    uint32_t x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];

    for (int i = 0; i < 32; ++i) {
        uint32_t t = x0 ^ sm4_TT(x1 ^ x2 ^ x3 ^ rk[31 - i]);
        x0 = x1; x1 = x2; x2 = x3; x3 = t;
    }

    uint32_t y[4] = { x3, x2, x1, x0 };
    store_be32_x4(out, y);
}

void sm4_decrypt_block(const sm4_ctx* ctx, const uint8_t cipher[SM4_BLOCK_SIZE],
                        uint8_t plain[SM4_BLOCK_SIZE]) {
    if (sm4_decrypt_fn) {
        sm4_decrypt_fn(ctx->rk, cipher, plain);
        return;
    }
    sm4_transform_decrypt(ctx->rk, cipher, plain);
}

// ── CBC 模式 ────────────────────────────────────────────────────────────

std::vector<uint8_t> sm4_cbc_encrypt(const sm4_ctx* ctx,
                                     const uint8_t iv[SM4_BLOCK_SIZE],
                                     jpssl::span<const uint8_t> plain) {
    size_t n = plain.size();
    // PKCS#7 填充
    size_t pad = SM4_BLOCK_SIZE - (n % SM4_BLOCK_SIZE);
    std::vector<uint8_t> result(n + pad);

    uint8_t prev[SM4_BLOCK_SIZE];
    std::memcpy(prev, iv, SM4_BLOCK_SIZE);

    size_t blocks = (n + pad) / SM4_BLOCK_SIZE;
    for (size_t b = 0; b < blocks; ++b) {
        uint8_t block[SM4_BLOCK_SIZE];
        size_t off = b * SM4_BLOCK_SIZE;

        if (b < blocks - 1) {
            std::memcpy(block, &plain[off], SM4_BLOCK_SIZE);
        } else {
            // 最后一个块：复制剩余数据 + PKCS#7 填充
            size_t rem = n - off;
            std::memcpy(block, &plain[off], rem);
            std::memset(block + rem, (int)pad, (int)(SM4_BLOCK_SIZE - rem));
        }

        // XOR with previous ciphertext (or IV for first block)
        for (int i = 0; i < SM4_BLOCK_SIZE; ++i)
            block[i] ^= prev[i];

        sm4_encrypt_block(ctx, block, &result[off]);
        std::memcpy(prev, &result[off], SM4_BLOCK_SIZE);
    }
    return result;
}

std::vector<uint8_t> sm4_cbc_decrypt(const sm4_ctx* ctx,
                                     const uint8_t iv[SM4_BLOCK_SIZE],
                                     jpssl::span<const uint8_t> cipher) {
    size_t n = cipher.size();
    if (n == 0 || n % SM4_BLOCK_SIZE != 0)
        throw std::runtime_error("sm4_cbc_decrypt: ciphertext length must be multiple of 16");

    std::vector<uint8_t> plain(n);
    uint8_t prev[SM4_BLOCK_SIZE];
    std::memcpy(prev, iv, SM4_BLOCK_SIZE);

    for (size_t off = 0; off < n; off += SM4_BLOCK_SIZE) {
        uint8_t decrypted[SM4_BLOCK_SIZE];
        sm4_decrypt_block(ctx, &cipher[off], decrypted);

        for (int i = 0; i < SM4_BLOCK_SIZE; ++i)
            plain[off + i] = decrypted[i] ^ prev[i];

        std::memcpy(prev, &cipher[off], SM4_BLOCK_SIZE);
    }

    // 去除 PKCS#7 填充
    if (plain.empty()) return plain;
    uint8_t pad = plain.back();
    if (pad == 0 || pad > SM4_BLOCK_SIZE)
        throw std::runtime_error("sm4_cbc_decrypt: invalid PKCS#7 padding");
    for (size_t i = n - pad; i < n; ++i) {
        if (plain[i] != pad)
            throw std::runtime_error("sm4_cbc_decrypt: invalid PKCS#7 padding");
    }
    plain.resize(n - pad);
    return plain;
}

} // namespace jpssl
