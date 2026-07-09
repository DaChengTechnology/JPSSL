/**
 * chacha20_gpu.mu — MUSA GPU ChaCha20 keystream 生成 kernel
 *
 * 设计：
 *   - 每线程处理一个 64 字节 ChaCha20 块（独立并行）
 *   - 每 block 128 个线程（平衡寄存器压力和占用率）
 *   - Key/Nonce 存储在 __constant__ 内存（缓存友好）
 *   - 提供纯 keystream 和 XOR 两种 kernel
 */

#include <musa_runtime.h>
#include <stdint.h>

// ═══════════════════════════════════════════════════════════════════════
//  GPU 常量内存（由主机端设置，单次初始化）
// ═══════════════════════════════════════════════════════════════════════

/// 256-bit ChaCha20 密钥（8 × uint32_t，32 字节）
__constant__ uint32_t d_key[8];

/// 96-bit nonce（3 × uint32_t，12 字节）
__constant__ uint32_t d_nonce[3];

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20 常量（"expand 32-byte k"）
// ═══════════════════════════════════════════════════════════════════════

__device__ inline void chacha20_init_state(
    uint32_t s[16], uint32_t counter)
{
    s[0]  = 0x61707865;  // "expa"
    s[1]  = 0x3320646e;  // "nd 3"
    s[2]  = 0x79622d32;  // "2-by"
    s[3]  = 0x6b206574;  // "te k"

    // Key（8 words）
    #pragma unroll
    for (int i = 0; i < 8; ++i) {
        s[4 + i] = d_key[i];
    }

    // Counter
    s[12] = counter;

    // Nonce（3 words）
    s[13] = d_nonce[0];
    s[14] = d_nonce[1];
    s[15] = d_nonce[2];
}

// ═══════════════════════════════════════════════════════════════════════
//  Quarter round（完全展开为内联操作）
// ═══════════════════════════════════════════════════════════════════════

#define GPU_QR(a, b, c, d) do {           \
    a += b;  d ^= a;  d = (d << 16) | (d >> 16); \
    c += d;  b ^= c;  b = (b << 12) | (b >> 20); \
    a += b;  d ^= a;  d = (d <<  8) | (d >> 24); \
    c += d;  b ^= c;  b = (b <<  7) | (b >> 25); \
} while (0)

/// Double round（column + diagonal rounds）
__device__ inline void chacha20_double_round(uint32_t s[16]) {
    // Column round
    GPU_QR(s[0], s[4], s[ 8], s[12]);
    GPU_QR(s[1], s[5], s[ 9], s[13]);
    GPU_QR(s[2], s[6], s[10], s[14]);
    GPU_QR(s[3], s[7], s[11], s[15]);
    // Diagonal round
    GPU_QR(s[0], s[5], s[10], s[15]);
    GPU_QR(s[1], s[6], s[11], s[12]);
    GPU_QR(s[2], s[7], s[ 8], s[13]);
    GPU_QR(s[3], s[4], s[ 9], s[14]);
}

/// 将 16 × uint32_t 状态序列化为 64 字节 little-endian 输出
__device__ inline void chacha20_serialize(const uint32_t s[16], uint8_t* out) {
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        uint32_t w = s[i];
        out[i * 4 + 0] = (uint8_t)(w);
        out[i * 4 + 1] = (uint8_t)(w >> 8);
        out[i * 4 + 2] = (uint8_t)(w >> 16);
        out[i * 4 + 3] = (uint8_t)(w >> 24);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Kernel 1：纯 keystream 生成
// ═══════════════════════════════════════════════════════════════════════

extern "C" __global__ void chacha20_keystream_kernel(
    uint8_t* __restrict__ keystream,   // output: num_blocks × 64 bytes
    uint32_t   base_counter,           // starting counter
    int        num_blocks)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    // 初始化状态
    uint32_t s[16];
    uint32_t counter = base_counter + (uint32_t)idx;
    chacha20_init_state(s, counter);

    // 保存初始状态
    uint32_t init[16];
    #pragma unroll
    for (int i = 0; i < 16; ++i) init[i] = s[i];

    // 10 次 double round = 20 轮
    #pragma unroll
    for (int r = 0; r < 10; ++r) {
        chacha20_double_round(s);
    }

    // 最终状态 = 初始 + 轮后
    #pragma unroll
    for (int i = 0; i < 16; ++i) s[i] += init[i];

    // 序列化输出
    uint8_t* out = keystream + idx * 64;
    chacha20_serialize(s, out);
}

// ═══════════════════════════════════════════════════════════════════════
//  Kernel 2：XOR 加密（keystream ⊕ input → output，避免二次拷贝）
// ═══════════════════════════════════════════════════════════════════════

extern "C" __global__ void chacha20_xor_kernel(
    const uint8_t* __restrict__ input,   // plaintext / ciphertext
    uint8_t*       __restrict__ output,  // ciphertext / plaintext
    uint32_t       base_counter,
    int            num_blocks)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    uint32_t s[16];
    uint32_t counter = base_counter + (uint32_t)idx;
    chacha20_init_state(s, counter);

    uint32_t init[16];
    #pragma unroll
    for (int i = 0; i < 16; ++i) init[i] = s[i];

    #pragma unroll
    for (int r = 0; r < 10; ++r) {
        chacha20_double_round(s);
    }
    #pragma unroll
    for (int i = 0; i < 16; ++i) s[i] += init[i];

    // 序列化 + XOR 合并为一步
    const uint8_t* in  = input  + idx * 64;
    uint8_t*       out = output + idx * 64;
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        uint32_t w = s[i];
        out[i * 4 + 0] = in[i * 4 + 0] ^ (uint8_t)(w);
        out[i * 4 + 1] = in[i * 4 + 1] ^ (uint8_t)(w >> 8);
        out[i * 4 + 2] = in[i * 4 + 2] ^ (uint8_t)(w >> 16);
        out[i * 4 + 3] = in[i * 4 + 3] ^ (uint8_t)(w >> 24);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  主机端可调用初始化函数
// ═══════════════════════════════════════════════════════════════════════

/// 将 key 和 nonce 从主机拷贝到 GPU __constant__ 内存
extern "C" void musa_chacha20_gpu_init(
    const uint8_t* host_key,
    const uint8_t* host_nonce)
{
    uint32_t key_words[8], nonce_words[3];

    // 转换为 little-endian uint32_t
    for (int i = 0; i < 8; ++i) {
        key_words[i] = (uint32_t)host_key[i*4]
                     | ((uint32_t)host_key[i*4+1] << 8)
                     | ((uint32_t)host_key[i*4+2] << 16)
                     | ((uint32_t)host_key[i*4+3] << 24);
    }
    for (int i = 0; i < 3; ++i) {
        nonce_words[i] = (uint32_t)host_nonce[i*4]
                       | ((uint32_t)host_nonce[i*4+1] << 8)
                       | ((uint32_t)host_nonce[i*4+2] << 16)
                       | ((uint32_t)host_nonce[i*4+3] << 24);
    }

    musaMemcpyToSymbol(d_key, key_words, sizeof(key_words),
                        0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_nonce, nonce_words, sizeof(nonce_words),
                        0, musaMemcpyHostToDevice);
}

/// 单独更新 nonce（不改变 key）
extern "C" void musa_chacha20_gpu_set_nonce(const uint8_t* host_nonce) {
    uint32_t nonce_words[3];
    for (int i = 0; i < 3; ++i) {
        nonce_words[i] = (uint32_t)host_nonce[i*4]
                       | ((uint32_t)host_nonce[i*4+1] << 8)
                       | ((uint32_t)host_nonce[i*4+2] << 16)
                       | ((uint32_t)host_nonce[i*4+3] << 24);
    }
    musaMemcpyToSymbol(d_nonce, nonce_words, sizeof(nonce_words),
                        0, musaMemcpyHostToDevice);
}

/// 主机端 launch 包装
extern "C" void launch_chacha20_keystream(
    uint8_t* d_keystream, uint32_t base_counter, int num_blocks,
    int threads_per_block, musaStream_t stream)
{
    int grid = (num_blocks + threads_per_block - 1) / threads_per_block;
    chacha20_keystream_kernel<<<grid, threads_per_block, 0, stream>>>(
        d_keystream, base_counter, num_blocks);
}

extern "C" void launch_chacha20_xor(
    const uint8_t* d_input, uint8_t* d_output,
    uint32_t base_counter, int num_blocks,
    int threads_per_block, musaStream_t stream)
{
    int grid = (num_blocks + threads_per_block - 1) / threads_per_block;
    chacha20_xor_kernel<<<grid, threads_per_block, 0, stream>>>(
        d_input, d_output, base_counter, num_blocks);
}
