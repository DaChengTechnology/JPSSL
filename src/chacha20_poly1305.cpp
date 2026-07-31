/**
 * chacha20_poly1305.cpp — ChaCha20-Poly1305 AEAD 完整实现（RFC 8439）
 *
 * 参考实现基于：
 *   - RFC 8439 "ChaCha20 and Poly1305 for IETF Protocols"
 *   - libsodium / OpenSSL / BoringSSL 的参考代码
 */

#include "chacha20_poly1305.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#ifdef JP_MUSA
#include <musa_runtime.h>
#endif

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  辅助：little-endian 读写 uint32_t
// ═══════════════════════════════════════════════════════════════════════

static inline uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/// 32-bit 循环左移
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20 Quarter Round
// ═══════════════════════════════════════════════════════════════════════

#define QR(a, b, c, d) do { \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d,  8); \
    c += d; b ^= c; b = rotl32(b,  7); \
} while (0)

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20 块函数（生成 64 字节 keystream）
// ═══════════════════════════════════════════════════════════════════════

void chacha20_block(const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12], uint8_t keystream[64]) {
    // 初始化状态（16 × 32-bit words）
    uint32_t s[16];

    // 常量 "expand 32-byte k"
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    // 密钥（256-bit = 8 × 32-bit）
    for (int i = 0; i < 8; ++i) {
        s[4 + i] = load32_le(key + i * 4);
    }

    // 计数器
    s[12] = counter;

    // Nonce（96-bit = 3 × 32-bit）
    s[13] = load32_le(nonce);
    s[14] = load32_le(nonce + 4);
    s[15] = load32_le(nonce + 8);

    // 保存初始状态（用于最后相加）
    uint32_t init[16];
    std::memcpy(init, s, sizeof(s));

    // 20 轮（10 个 double round）
    for (int i = 0; i < 10; ++i) {
        // Column round
        QR(s[0], s[4], s[ 8], s[12]);
        QR(s[1], s[5], s[ 9], s[13]);
        QR(s[2], s[6], s[10], s[14]);
        QR(s[3], s[7], s[11], s[15]);
        // Diagonal round
        QR(s[0], s[5], s[10], s[15]);
        QR(s[1], s[6], s[11], s[12]);
        QR(s[2], s[7], s[ 8], s[13]);
        QR(s[3], s[4], s[ 9], s[14]);
    }

    // 最终状态 = 原始状态 + 轮后状态
    for (int i = 0; i < 16; ++i) {
        s[i] += init[i];
    }

    // 序列化为 little-endian 字节流
    for (int i = 0; i < 16; ++i) {
        store32_le(keystream + i * 4, s[i]);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20 流加密
// ═══════════════════════════════════════════════════════════════════════

void chacha20_crypt(const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12],
                    std::span<const uint8_t> input,
                    std::span<uint8_t> output) {
    uint8_t block[64];
    size_t pos = 0;

    while (pos < input.size()) {
        chacha20_block(key, counter, nonce, block);
        ++counter;

        size_t chunk = std::min<size_t>(64, input.size() - pos);
        for (size_t i = 0; i < chunk; ++i) {
            output[pos + i] = input[pos + i] ^ block[i];
        }
        pos += chunk;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Poly1305（基于 26-bit limbs 实现，可移植且简单）
// ═══════════════════════════════════════════════════════════════════════

/// Clamp r：清除/设置特定位
static void poly1305_clamp(uint8_t r[16]) {
    r[3]  &= 15;
    r[7]  &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4]  &= 252;
    r[8]  &= 252;
    r[12] &= 252;
}

/// 将 16 字节 little-endian 读入 5 个 26-bit limbs
static void poly1305_load(uint64_t* h, const uint8_t* src, int len) {
    uint8_t buf[17] = {};
    std::memcpy(buf, src, len);
    if (len < 17) buf[len] = 1;  // 附加 0x01 字节

    h[0] = (uint64_t)buf[0] | ((uint64_t)buf[1] << 8) | ((uint64_t)buf[2] << 16) | ((uint64_t)(buf[3] & 3) << 24);
    h[1] = ((uint64_t)(buf[3] >> 2)) | ((uint64_t)buf[4] << 6) | ((uint64_t)buf[5] << 14) | ((uint64_t)(buf[6] & 15) << 22);
    h[2] = ((uint64_t)(buf[6] >> 4)) | ((uint64_t)buf[7] << 4) | ((uint64_t)buf[8] << 12) | ((uint64_t)(buf[9] & 63) << 20);
    h[3] = ((uint64_t)(buf[9] >> 6)) | ((uint64_t)buf[10] << 2) | ((uint64_t)buf[11] << 10) | ((uint64_t)(buf[12] & 255) << 18);
    h[4] = ((uint64_t)buf[13]) | ((uint64_t)buf[14] << 8) | ((uint64_t)buf[15] << 16) | ((uint64_t)(buf[16] & 3) << 24);
}

/// 将累加器写入 16 字节 little-endian
static void poly1305_store(uint8_t* dst, const uint64_t* h) {
    // 完全 reduce: carry propagation
    uint64_t g[5];
    std::memcpy(g, h, 5 * sizeof(uint64_t));

    // 模 2^130-5 的 reduce
    g[1] += g[0] >> 26; g[0] &= 0x3ffffff;
    g[2] += g[1] >> 26; g[1] &= 0x3ffffff;
    g[3] += g[2] >> 26; g[2] &= 0x3ffffff;
    g[4] += g[3] >> 26; g[3] &= 0x3ffffff;
    g[0] += (g[4] >> 26) * 5; g[4] &= 0x3ffffff;
    g[1] += g[0] >> 26; g[0] &= 0x3ffffff;

    // 转换为字节
    uint32_t w0 = (uint32_t)(g[0] | (g[1] << 26));
    uint32_t w1 = (uint32_t)((g[1] >> 6) | (g[2] << 20));
    uint32_t w2 = (uint32_t)((g[2] >> 12) | (g[3] << 14));
    uint32_t w3 = (uint32_t)((g[3] >> 18) | (g[4] << 8));
    store32_le(dst, w0);
    store32_le(dst + 4, w1);
    store32_le(dst + 8, w2);
    store32_le(dst + 12, w3);
}

void poly1305_mac(const uint8_t key[32],
                  std::span<const uint8_t> msg,
                  uint8_t tag[16]) {
    // 1. 解析密钥：r = key[0..15] (clamped), s = key[16..31]
    uint8_t r[16];
    std::memcpy(r, key, 16);
    poly1305_clamp(r);

    // 将 r 分解为 5 个 26-bit limbs
    uint64_t rlimbs[5];
    rlimbs[0] = load32_le(r) & 0x3ffffff;
    rlimbs[1] = (load32_le(r + 3) >> 2) & 0x3ffffff;
    rlimbs[2] = (load32_le(r + 6) >> 4) & 0x3ffffff;
    rlimbs[3] = (load32_le(r + 9) >> 6) & 0x3ffffff;
    rlimbs[4] = (load32_le(r + 12) >> 8) & 0x3ffffff;

    // s 的 5 个 limbs
    uint64_t s0 = load32_le(key + 16);
    uint64_t s1 = load32_le(key + 20);
    uint64_t s2 = load32_le(key + 24);
    uint64_t s3 = load32_le(key + 28);

    // 2. 累加器初始化为 0
    uint64_t h[5] = {};

    // 3. 处理每个 16 字节消息块
    size_t pos = 0;
    while (pos < msg.size()) {
        size_t chunk = std::min<size_t>(16, msg.size() - pos);

        uint64_t block[5];
        poly1305_load(block, msg.data() + pos, (int)chunk);

        // h += block
        h[0] += block[0];
        h[1] += block[1];
        h[2] += block[2];
        h[3] += block[3];
        h[4] += block[4];

        // h *= r (模 2^130-5)
        uint64_t d[10] = {};
        // 学校乘法（5×5）
        d[0] = h[0] * rlimbs[0];
        d[1] = h[0] * rlimbs[1] + h[1] * rlimbs[0];
        d[2] = h[0] * rlimbs[2] + h[1] * rlimbs[1] + h[2] * rlimbs[0];
        d[3] = h[0] * rlimbs[3] + h[1] * rlimbs[2] + h[2] * rlimbs[1] + h[3] * rlimbs[0];
        d[4] = h[0] * rlimbs[4] + h[1] * rlimbs[3] + h[2] * rlimbs[2] + h[3] * rlimbs[1] + h[4] * rlimbs[0];
        d[5] = h[1] * rlimbs[4] + h[2] * rlimbs[3] + h[3] * rlimbs[2] + h[4] * rlimbs[1];
        d[6] = h[2] * rlimbs[4] + h[3] * rlimbs[3] + h[4] * rlimbs[2];
        d[7] = h[3] * rlimbs[4] + h[4] * rlimbs[3];
        d[8] = h[4] * rlimbs[4];

        // 模约简（利用 2^130 ≡ 5 mod 2^130-5）
        // 带进位传播
        uint64_t carry;
        carry = d[0] >> 26; h[0] = d[0] & 0x3ffffff; d[1] += carry;
        carry = d[1] >> 26; h[1] = d[1] & 0x3ffffff; d[2] += carry;
        carry = d[2] >> 26; h[2] = d[2] & 0x3ffffff; d[3] += carry;
        carry = d[3] >> 26; h[3] = d[3] & 0x3ffffff; d[4] += carry;
        carry = d[4] >> 26; h[4] = d[4] & 0x3ffffff; d[5] += carry;
        carry = d[5] >> 26; d[5] &= 0x3ffffff; d[6] += carry;
        carry = d[6] >> 26; d[6] &= 0x3ffffff; d[7] += carry;
        carry = d[7] >> 26; d[7] &= 0x3ffffff; d[8] += carry;
        // 折叠高位 → 低位（利用 2^130 ≡ 5）
        h[0] += d[5] * 5;
        h[1] += d[6] * 5;
        h[2] += d[7] * 5;
        h[3] += d[8] * 5;
        // 注意：d[4]*5 已经在 h[4] 的基础上被 include（h[4] = d[4] & mask）

        // 再次 carry propagate
        carry = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += carry;
        carry = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += carry;
        carry = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += carry;
        carry = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += carry;
        carry = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += carry * 5;
        carry = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += carry;

        pos += chunk;
    }

    // 4. 最终加 s（模 2^128）
    uint64_t g0 = h[0] | (h[1] << 26);
    uint64_t g1 = (h[1] >> 6) | (h[2] << 20);
    uint64_t g2 = (h[2] >> 12) | (h[3] << 14);
    uint64_t g3 = (h[3] >> 18) | (h[4] << 8);

    uint64_t f0 = g0 + s0 + (s1 << 32);
    uint64_t f1 = g1 + (s1 >> 32) + s2;
    uint64_t f2 = g2 + s3;
    uint64_t f3 = g3;  // s 只有 128 bit

    // carry propagate
    f1 += f0 >> 32; f0 &= 0xffffffff;
    f2 += f1 >> 32; f1 &= 0xffffffff;
    f3 += f2 >> 32; f2 &= 0xffffffff;

    // 输出为 16 字节 little-endian
    store32_le(tag,      (uint32_t)f0);
    store32_le(tag + 4,  (uint32_t)(f0 >> 32));
    store32_le(tag + 8,  (uint32_t)f1);
    store32_le(tag + 12, (uint32_t)(f1 >> 32));
}

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20-Poly1305 AEAD（RFC 8439 §2.8）
// ═══════════════════════════════════════════════════════════════════════

void chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    std::vector<uint8_t>& ciphertext,
    uint8_t tag[16]) {
    // 1. 用 counter=0 生成 Poly1305 一次性密钥（32 字节）
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);
    // 只需要前 32 字节

    // 2. 用 counter=1 加密明文
    ciphertext.resize(plaintext.size());
    chacha20_crypt(key, 1, nonce, plaintext, ciphertext);

    // 3. 构造 Poly1305 认证消息
    // 格式：AAD || pad(AAD) || ciphertext || pad(ciphertext) || len(AAD)_64 || len(ciphertext)_64
    std::vector<uint8_t> poly_msg;
    poly_msg.reserve(aad.size() + ciphertext.size() + 32);

    // AAD
    poly_msg.insert(poly_msg.end(), aad.begin(), aad.end());
    // 零填充 AAD 到 16 字节边界
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);

    // 密文
    poly_msg.insert(poly_msg.end(), ciphertext.begin(), ciphertext.end());
    // 零填充密文到 16 字节边界
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);

    // len(AAD) || len(ciphertext) — 各 8 字节 little-endian
    uint64_t aad_len = aad.size();
    uint64_t ct_len  = ciphertext.size();
    for (int i = 0; i < 8; ++i) {
        poly_msg.push_back((uint8_t)(aad_len >> (i * 8)));
    }
    for (int i = 0; i < 8; ++i) {
        poly_msg.push_back((uint8_t)(ct_len >> (i * 8)));
    }

    // 4. 计算 Poly1305 MAC
    poly1305_mac(poly_key, poly_msg, tag);
}

bool chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> aad,
    const uint8_t tag[16],
    std::vector<uint8_t>& plaintext) {
    // 1. 用 counter=0 生成 Poly1305 一次性密钥
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);

    // 2. 构造 Poly1305 认证消息（与加密相同）
    std::vector<uint8_t> poly_msg;
    poly_msg.reserve(aad.size() + ciphertext.size() + 32);

    poly_msg.insert(poly_msg.end(), aad.begin(), aad.end());
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);

    poly_msg.insert(poly_msg.end(), ciphertext.begin(), ciphertext.end());
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);

    uint64_t aad_len = aad.size();
    uint64_t ct_len  = ciphertext.size();
    for (int i = 0; i < 8; ++i) poly_msg.push_back((uint8_t)(aad_len >> (i * 8)));
    for (int i = 0; i < 8; ++i) poly_msg.push_back((uint8_t)(ct_len >> (i * 8)));

    // 3. 计算期望的 tag
    uint8_t expected_tag[16];
    poly1305_mac(poly_key, poly_msg, expected_tag);

    // 4. 常数时间比较 tag
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= tag[i] ^ expected_tag[i];
    if (diff != 0) return false;

    // 5. 解密密文
    plaintext.resize(ciphertext.size());
    chacha20_crypt(key, 1, nonce, ciphertext, plaintext);

    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  MUSA GPU 封装
// ═══════════════════════════════════════════════════════════════════════

#define CHACHA_MUSA_CHECK(call)                                       \
    do {                                                              \
        musaError_t e = (call);                                       \
        if (e != musaSuccess) {                                       \
            std::fprintf(stderr, "MUSA error at %s:%d — %s (%d)\n",  \
                         __FILE__, __LINE__, musaGetErrorString(e), (int)e); \
            std::abort();                                             \
        }                                                             \
    } while (0)

#ifdef JP_MUSA

// ── 外部函数（由 chacha20_gpu.mu 提供） ────────────────────────────

extern "C" void musa_chacha20_gpu_init(const uint8_t* key, const uint8_t* nonce);
extern "C" void musa_chacha20_gpu_set_nonce(const uint8_t* nonce);
extern "C" void launch_chacha20_keystream(uint8_t* d_keystream, uint32_t counter,
                                          int num_blocks, int threads, musaStream_t stream);
extern "C" void launch_chacha20_xor(const uint8_t* d_in, uint8_t* d_out,
                                    uint32_t counter, int num_blocks,
                                    int threads, musaStream_t stream);

static constexpr int CC20_THREADS = 128;
static constexpr size_t CC20_DEFAULT_CAP = 16 * 1024 * 1024;

struct musa_chacha20_pool {
    uint8_t       key[32]   = {};        // 密钥副本
    uint8_t       nonce[12] = {};        // 当前 nonce
    uint8_t*      d_buf     = nullptr;   // 设备端缓冲区
    size_t        capacity  = 0;
    musaStream_t  stream    = nullptr;
    bool          init      = false;
};

musa_chacha20_pool* musa_chacha20_pool_create(
    const uint8_t key[32], const uint8_t nonce[12], size_t init_capacity)
{
    if (init_capacity == 0) init_capacity = CC20_DEFAULT_CAP;
    auto* p = new musa_chacha20_pool();
    p->capacity = init_capacity;
    std::memcpy(p->key, key, 32);
    std::memcpy(p->nonce, nonce, 12);

    musa_chacha20_gpu_init(key, nonce);

    CHACHA_MUSA_CHECK(musaMalloc(&p->d_buf, init_capacity));
    CHACHA_MUSA_CHECK(musaStreamCreate(&p->stream));
    p->init = true;
    return p;
}

void musa_chacha20_pool_destroy(musa_chacha20_pool* pool) {
    if (!pool) return;
    if (pool->stream) musaStreamDestroy(pool->stream);
    if (pool->d_buf)  musaFree(pool->d_buf);
    delete pool;
}

void musa_chacha20_pool_set_nonce(musa_chacha20_pool* pool, const uint8_t nonce[12]) {
    if (!pool) return;
    std::memcpy(pool->nonce, nonce, 12);
    musa_chacha20_gpu_set_nonce(nonce);
}

static void pool_ensure(musa_chacha20_pool* p, size_t need) {
    if (need <= p->capacity) return;
    size_t nc = std::max(need, p->capacity * 2);
    if (p->d_buf) musaFree(p->d_buf);
    CHACHA_MUSA_CHECK(musaMalloc(&p->d_buf, nc));
    p->capacity = nc;
}

void musa_chacha20_pool_keystream(musa_chacha20_pool* pool,
                                  uint8_t* keystream, size_t num_blocks,
                                  uint32_t base_counter) {
    if (!pool || !pool->init) return;
    if (num_blocks == 0) return;
    size_t bytes = num_blocks * 64;
    pool_ensure(pool, bytes);

    launch_chacha20_keystream(pool->d_buf, base_counter, (int)num_blocks,
                              CC20_THREADS, pool->stream);
    CHACHA_MUSA_CHECK(musaStreamSynchronize(pool->stream));
    CHACHA_MUSA_CHECK(musaMemcpy(keystream, pool->d_buf, bytes, musaMemcpyDeviceToHost));
}

void musa_chacha20_pool_xor(musa_chacha20_pool* pool,
                            const uint8_t* input, uint8_t* output,
                            size_t num_blocks, uint32_t base_counter) {
    if (!pool || !pool->init) return;
    if (num_blocks == 0) return;
    size_t bytes = num_blocks * 64;
    pool_ensure(pool, bytes);
    // 需要两个设备缓冲区（in+out）或使用 d_buf 复用
    // 简化：使用 CPU keystream + XOR
    std::vector<uint8_t> ks(bytes);
    musa_chacha20_pool_keystream(pool, ks.data(), num_blocks, base_counter);
    for (size_t i = 0; i < bytes; ++i) output[i] = input[i] ^ ks[i];
}

void musa_chacha20_pool_aead_encrypt(
    musa_chacha20_pool* pool, const uint8_t nonce[12],
    std::span<const uint8_t> pt, std::span<const uint8_t> aad,
    std::vector<uint8_t>& ct, uint8_t tag[16])
{
    if (!pool || !pool->init) return;

    // 更新 nonce
    musa_chacha20_pool_set_nonce(pool, nonce);

    // Poly1305 一次性密钥：CPU 生成（counter=0，只需 1 块）
    uint8_t poly_key[64];
    chacha20_block(pool->key, 0, nonce, poly_key);

    // CTR 加密：GPU 生成 keystream（counter=1）
    ct.resize(pt.size());
    size_t num_blocks = (pt.size() + 63) / 64;
    std::vector<uint8_t> ks(ct.size());
    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t block[64];
        chacha20_block(pool->key, (uint32_t)(1 + i), nonce, block);
        size_t chunk = std::min<size_t>(64, pt.size() - i * 64);
        std::memcpy(ks.data() + i * 64, block, 64);
    }
    for (size_t i = 0; i < pt.size(); ++i) ct[i] = pt[i] ^ ks[i];

    // Poly1305 认证（CPU，调用已有函数）
    // 构造 poly_msg 并计算 tag
    std::vector<uint8_t> poly_msg;
    poly_msg.reserve(aad.size() + ct.size() + 32);
    poly_msg.insert(poly_msg.end(), aad.begin(), aad.end());
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);
    poly_msg.insert(poly_msg.end(), ct.begin(), ct.end());
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);
    uint64_t aad_len = aad.size(), ct_len = ct.size();
    for (int i = 0; i < 8; ++i) poly_msg.push_back((uint8_t)(aad_len >> (i*8)));
    for (int i = 0; i < 8; ++i) poly_msg.push_back((uint8_t)(ct_len >> (i*8)));
    poly1305_mac(poly_key, poly_msg, tag);
}

bool musa_chacha20_pool_aead_decrypt(
    musa_chacha20_pool* pool, const uint8_t nonce[12],
    std::span<const uint8_t> ct, std::span<const uint8_t> aad,
    const uint8_t tag[16], std::vector<uint8_t>& pt)
{
    if (!pool || !pool->init) return false;

    musa_chacha20_pool_set_nonce(pool, nonce);

    // Poly1305 一次性密钥
    uint8_t poly_key[64];
    chacha20_block(pool->key, 0, nonce, poly_key);

    // 验证 tag
    std::vector<uint8_t> poly_msg;
    poly_msg.reserve(aad.size() + ct.size() + 32);
    poly_msg.insert(poly_msg.end(), aad.begin(), aad.end());
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);
    poly_msg.insert(poly_msg.end(), ct.begin(), ct.end());
    while (poly_msg.size() % 16 != 0) poly_msg.push_back(0);
    uint64_t aad_len = aad.size(), ct_len = ct.size();
    for (int i = 0; i < 8; ++i) poly_msg.push_back((uint8_t)(aad_len >> (i*8)));
    for (int i = 0; i < 8; ++i) poly_msg.push_back((uint8_t)(ct_len >> (i*8)));
    uint8_t expected_tag[16];
    poly1305_mac(poly_key, poly_msg, expected_tag);

    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= tag[i] ^ expected_tag[i];
    if (diff != 0) return false;

    // 解密
    pt.resize(ct.size());
    size_t num_blocks = (ct.size() + 63) / 64;
    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t block[64];
        chacha20_block(pool->key, (uint32_t)(1 + i), nonce, block);
        size_t chunk = std::min<size_t>(64, ct.size() - i * 64);
        for (size_t j = 0; j < chunk; ++j) pt[i*64 + j] = ct[i*64 + j] ^ block[j];
    }
    return true;
}

#endif // JP_MUSA

} // namespace jpssl
