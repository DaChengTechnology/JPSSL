/**
 * aes_gpu.mu — MUSA GPU AES-128 加密/解密 kernel
 *
 * 设计：
 *   - 每线程处理一个 16 字节的 AES 块
 *   - 每 block 256 个线程（最大化 GPU 占用率）
 *   - S-Box / InvSBox 和轮密钥存储在 __constant__ 内存中
 *   - 使用 uchar4 向量化加载/存储
 */

#include <musa_runtime.h>
#include <stdint.h>

// ═══════════════════════════════════════════════════════════════════════
//  GPU 常量内存（由主机端设置）
// ═══════════════════════════════════════════════════════════════════════

/// AES-128 轮数（10）、AES-192（12）、AES-256（14）
__constant__ int d_rounds;

/// S-Box（256 字节）
__constant__ uint8_t d_sbox[256];

/// 逆 S-Box（256 字节）
__constant__ uint8_t d_inv_sbox[256];

/// 加密轮密钥（最多 240 字节 = 15 × 16）
__constant__ uint8_t d_enc_rk[240];

/// 解密轮密钥（最多 240 字节）
__constant__ uint8_t d_dec_rk[240];

// ═══════════════════════════════════════════════════════════════════════
//  GPU 设备函数
// ═══════════════════════════════════════════════════════════════════════

/// SubBytes — 对 16 字节状态应用 S-Box
__device__ inline void gpu_sub_bytes(uint8_t state[16]) {
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        state[i] = d_sbox[state[i]];
    }
}

/// InvSubBytes
__device__ inline void gpu_inv_sub_bytes(uint8_t state[16]) {
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        state[i] = d_inv_sbox[state[i]];
    }
}

/// ShiftRows
__device__ inline void gpu_shift_rows(uint8_t state[16]) {
    uint8_t t;
    // Row 1: left shift 1
    t = state[1];  state[1]  = state[5];
                   state[5]  = state[9];
                   state[9]  = state[13];
                   state[13] = t;
    // Row 2: left shift 2
    t = state[2];  state[2]  = state[10];  state[10] = t;
    t = state[6];  state[6]  = state[14];  state[14] = t;
    // Row 3: left shift 3 (= right shift 1)
    t = state[15]; state[15] = state[11];
                   state[11] = state[7];
                   state[7]  = state[3];
                   state[3]  = t;
}

/// InvShiftRows
__device__ inline void gpu_inv_shift_rows(uint8_t state[16]) {
    uint8_t t;
    // Row 1: right shift 1
    t = state[13]; state[13] = state[9];
                   state[9]  = state[5];
                   state[5]  = state[1];
                   state[1]  = t;
    // Row 2: right shift 2
    t = state[2];  state[2]  = state[10];  state[10] = t;
    t = state[6];  state[6]  = state[14];  state[14] = t;
    // Row 3: right shift 3 (= left shift 1)
    t = state[3];  state[3]  = state[7];
                   state[7]  = state[11];
                   state[11] = state[15];
                   state[15] = t;
}

/// GF(2^8) 乘以 2（用于 MixColumns）
__device__ inline uint8_t gpu_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1B));
}

/// GF(2^8) 乘法
__device__ inline uint8_t gpu_gf28_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    #pragma unroll
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = (uint8_t)(a & 0x80);
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

/// MixColumns — 对整个状态
__device__ inline void gpu_mix_columns(uint8_t state[16]) {
    #pragma unroll
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = state + c * 4;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = gpu_xtime(a0) ^ (gpu_xtime(a1) ^ a1) ^ a2 ^ a3;
        col[1] = a0 ^ gpu_xtime(a1) ^ (gpu_xtime(a2) ^ a2) ^ a3;
        col[2] = a0 ^ a1 ^ gpu_xtime(a2) ^ (gpu_xtime(a3) ^ a3);
        col[3] = (gpu_xtime(a0) ^ a0) ^ a1 ^ a2 ^ gpu_xtime(a3);
    }
}

/// InvMixColumns — 对整个状态
__device__ inline void gpu_inv_mix_columns(uint8_t state[16]) {
    #pragma unroll
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = state + c * 4;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = gpu_gf28_mul(a0, 0x0E) ^ gpu_gf28_mul(a1, 0x0B) ^
                 gpu_gf28_mul(a2, 0x0D) ^ gpu_gf28_mul(a3, 0x09);
        col[1] = gpu_gf28_mul(a0, 0x09) ^ gpu_gf28_mul(a1, 0x0E) ^
                 gpu_gf28_mul(a2, 0x0B) ^ gpu_gf28_mul(a3, 0x0D);
        col[2] = gpu_gf28_mul(a0, 0x0D) ^ gpu_gf28_mul(a1, 0x09) ^
                 gpu_gf28_mul(a2, 0x0E) ^ gpu_gf28_mul(a3, 0x0B);
        col[3] = gpu_gf28_mul(a0, 0x0B) ^ gpu_gf28_mul(a1, 0x0D) ^
                 gpu_gf28_mul(a2, 0x09) ^ gpu_gf28_mul(a3, 0x0E);
    }
}

/// AddRoundKey
__device__ inline void gpu_add_round_key(uint8_t state[16], const uint8_t* rk) {
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        state[i] ^= rk[i];
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  AES 加密 Kernel（每线程一个块）
// ═══════════════════════════════════════════════════════════════════════

extern "C" __global__ void aes_encrypt_kernel(
    const uint8_t* __restrict__ input,
    uint8_t* __restrict__ output,
    int num_blocks)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    // 加载 16 字节到寄存器
    const uint8_t* in_ptr = input + idx * 16;
    uint8_t state[16];
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        state[i] = in_ptr[i];
    }

    const uint8_t* rk = d_enc_rk;

    // 初始 AddRoundKey
    gpu_add_round_key(state, rk);
    rk += 16;

    // 中间轮
    for (int r = 1; r < d_rounds; ++r) {
        gpu_sub_bytes(state);
        gpu_shift_rows(state);
        gpu_mix_columns(state);
        gpu_add_round_key(state, rk);
        rk += 16;
    }

    // 最后一轮（无 MixColumns）
    gpu_sub_bytes(state);
    gpu_shift_rows(state);
    gpu_add_round_key(state, rk);

    // 写回
    uint8_t* out_ptr = output + idx * 16;
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        out_ptr[i] = state[i];
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  AES 解密 Kernel（每线程一个块）
// ═══════════════════════════════════════════════════════════════════════

extern "C" __global__ void aes_decrypt_kernel(
    const uint8_t* __restrict__ input,
    uint8_t* __restrict__ output,
    int num_blocks)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    // 加载 16 字节到寄存器
    const uint8_t* in_ptr = input + idx * 16;
    uint8_t state[16];
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        state[i] = in_ptr[i];
    }

    const uint8_t* rk = d_dec_rk;

    // 初始 AddRoundKey
    gpu_add_round_key(state, rk);
    rk += 16;

    // 中间轮
    for (int r = 1; r < d_rounds; ++r) {
        gpu_inv_shift_rows(state);
        gpu_inv_sub_bytes(state);
        gpu_add_round_key(state, rk);
        gpu_inv_mix_columns(state);
        rk += 16;
    }

    // 最后一轮（无 InvMixColumns）
    gpu_inv_shift_rows(state);
    gpu_inv_sub_bytes(state);
    gpu_add_round_key(state, rk);

    // 写回
    uint8_t* out_ptr = output + idx * 16;
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        out_ptr[i] = state[i];
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  主机端可调用的初始化和 launch 包装函数
//  这些函数必须放在 .mu 文件中，因为：
//    1. __constant__ 符号引用只在 .mu 编译单元中可用
//    2. kernel 启动语法 <<<>>> 需要 mcc 编译
// ═══════════════════════════════════════════════════════════════════════

/// 将 S-Box 和轮密钥从主机拷贝到 GPU __constant__ 内存
extern "C" void musa_aes_gpu_init(
    const uint8_t* host_sbox,
    const uint8_t* host_inv_sbox,
    const uint8_t* host_enc_rk,
    const uint8_t* host_dec_rk,
    int rounds)
{
    musaMemcpyToSymbol(d_rounds, &rounds, sizeof(int), 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_sbox, host_sbox, 256, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_inv_sbox, host_inv_sbox, 256, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_enc_rk, host_enc_rk, (rounds + 1) * 16, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_dec_rk, host_dec_rk, (rounds + 1) * 16, 0, musaMemcpyHostToDevice);
}

extern "C" void launch_aes_encrypt(
    const uint8_t* d_input, uint8_t* d_output, int num_blocks,
    int threads_per_block, musaStream_t stream)
{
    int grid_size = (num_blocks + threads_per_block - 1) / threads_per_block;
    aes_encrypt_kernel<<<grid_size, threads_per_block, 0, stream>>>(
        d_input, d_output, num_blocks);
}

extern "C" void launch_aes_decrypt(
    const uint8_t* d_input, uint8_t* d_output, int num_blocks,
    int threads_per_block, musaStream_t stream)
{
    int grid_size = (num_blocks + threads_per_block - 1) / threads_per_block;
    aes_decrypt_kernel<<<grid_size, threads_per_block, 0, stream>>>(
        d_input, d_output, num_blocks);
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 模式：GF(2^128) 乘法 & GHASH kernel
// ═══════════════════════════════════════════════════════════════════════

/// GF(2^128) 右移 1 位（小端序，bit-reflected）
__device__ inline void gpu_gf128_shr(uint8_t x[16]) {
    uint8_t carry = 0;
    for (int i = 0; i < 16; ++i) {
        uint8_t new_carry = x[i] & 1;
        x[i] = (x[i] >> 1) | (carry << 7);
        carry = new_carry;
    }
}

/// XOR 两个 128-bit 值: dst ^= src
__device__ inline void gpu_gf128_xor(uint8_t* dst, const uint8_t* src) {
    for (int i = 0; i < 16; ++i) dst[i] ^= src[i];
}

/// GF(2^128) 乘法（bit-reflected，不可约多项式 x^128+x^7+x^2+x+1）
/// Bit-reflected (little-endian): byte 0 bit 0 = x^0, right-shift = multiply by x.
/// Reduction: x^128 = x^7 + x^2 + x + 1 -> 0x80|0x04|0x02|0x01 = 0x87 in byte 0.
__device__ void gpu_gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
    uint8_t V[16];
    uint8_t Z[16] = {};

    for (int i = 0; i < 16; ++i) V[i] = y[i];

    for (int i = 0; i < 128; ++i) {
        int byte_idx = i / 8;
        int bit_idx  = i % 8;
        if (x[byte_idx] & (1 << bit_idx)) {
            gpu_gf128_xor(Z, V);
        }

        bool lsb = V[0] & 1;
        gpu_gf128_shr(V);
        if (lsb) {
            V[0] ^= 0x87;
        }
    }

    for (int i = 0; i < 16; ++i) out[i] = Z[i];
}

/// GHASH 单步：state = (state ^ block) * H
__device__ void gpu_ghash_step(uint8_t state[16], const uint8_t block[16], const uint8_t H[16]) {
    gpu_gf128_xor(state, block);
    uint8_t tmp[16];
    gpu_gf128_mul(state, H, tmp);
    for (int i = 0; i < 16; ++i) state[i] = tmp[i];
}

/// 递增 counter：最后 32-bit 大端序递增
__device__ inline void gpu_inc_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 12; --i) {
        if (++counter[i] != 0) break;
    }
}

/// 大端序存储 64-bit 值
__device__ inline void gpu_store_be64(uint8_t* buf, uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        buf[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 加密 Kernel（每线程一个块：CTR + GHASH 全部在 GPU 完成）
// ═══════════════════════════════════════════════════════════════════════

extern "C" __global__ void aes_gcm_encrypt_kernel(
    const uint8_t* __restrict__ plaintext,
    uint8_t* __restrict__ ciphertext,
    uint8_t* __restrict__ ghash_out,
    int num_blocks,
    const uint8_t* __restrict__ J0,
    const uint8_t* __restrict__ H)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    // 加载 counter = J0 + idx + 1
    uint8_t counter[16];
    for (int i = 0; i < 16; ++i) counter[i] = J0[i];
    for (int k = 0; k <= idx; ++k) gpu_inc_counter(counter);

    // AES 加密 counter = keystream
    uint8_t keystream[16];
    for (int i = 0; i < 16; ++i) keystream[i] = counter[i];

    const uint8_t* rk = d_enc_rk;
    gpu_add_round_key(keystream, rk);
    rk += 16;
    for (int r = 1; r < d_rounds; ++r) {
        gpu_sub_bytes(keystream);
        gpu_shift_rows(keystream);
        gpu_mix_columns(keystream);
        gpu_add_round_key(keystream, rk);
        rk += 16;
    }
    gpu_sub_bytes(keystream);
    gpu_shift_rows(keystream);
    gpu_add_round_key(keystream, rk);

    // 密文 = 明文 XOR keystream
    const uint8_t* pt = plaintext + idx * 16;
    uint8_t* ct = ciphertext + idx * 16;
    for (int i = 0; i < 16; ++i) ct[i] = pt[i] ^ keystream[i];

    // GHASH 输出：初始化为密文块（host 端会做完整的 GHASH 累积）
    for (int i = 0; i < 16; ++i) ghash_out[idx * 16 + i] = ct[i];
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 解密 Kernel（CTR + 标签验证）
// ═══════════════════════════════════════════════════════════════════════

extern "C" __global__ void aes_gcm_decrypt_kernel(
    const uint8_t* __restrict__ ciphertext,
    uint8_t* __restrict__ plaintext,
    uint8_t* __restrict__ ghash_out,
    int num_blocks,
    const uint8_t* __restrict__ J0,
    const uint8_t* __restrict__ H)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    // 加载 counter = J0 + idx + 1
    uint8_t counter[16];
    for (int i = 0; i < 16; ++i) counter[i] = J0[i];
    for (int k = 0; k <= idx; ++k) gpu_inc_counter(counter);

    // AES 加密 counter = keystream
    uint8_t keystream[16];
    for (int i = 0; i < 16; ++i) keystream[i] = counter[i];

    const uint8_t* rk = d_enc_rk;
    gpu_add_round_key(keystream, rk);
    rk += 16;
    for (int r = 1; r < d_rounds; ++r) {
        gpu_sub_bytes(keystream);
        gpu_shift_rows(keystream);
        gpu_mix_columns(keystream);
        gpu_add_round_key(keystream, rk);
        rk += 16;
    }
    gpu_sub_bytes(keystream);
    gpu_shift_rows(keystream);
    gpu_add_round_key(keystream, rk);

    // 明文 = 密文 XOR keystream
    const uint8_t* ct = ciphertext + idx * 16;
    uint8_t* pt = plaintext + idx * 16;
    for (int i = 0; i < 16; ++i) pt[i] = ct[i] ^ keystream[i];

    // GHASH 输出：密文块（host 端做完整 GHASH）
    for (int i = 0; i < 16; ++i) ghash_out[idx * 16 + i] = ct[i];
}

// ═══════════════════════════════════════════════════════════════════════
//  GCM 主机端 launch 包装函数
// ═══════════════════════════════════════════════════════════════════════

extern "C" void musa_aes_gcm_gpu_init(
    const uint8_t* host_sbox,
    const uint8_t* host_inv_sbox,
    const uint8_t* host_enc_rk,
    const uint8_t* host_dec_rk,
    int rounds)
{
    musaMemcpyToSymbol(d_rounds, &rounds, sizeof(int), 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_sbox, host_sbox, 256, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_inv_sbox, host_inv_sbox, 256, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_enc_rk, host_enc_rk, (rounds + 1) * 16, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_dec_rk, host_dec_rk, (rounds + 1) * 16, 0, musaMemcpyHostToDevice);
}

extern "C" void launch_aes_gcm_encrypt(
    const uint8_t* d_plaintext, uint8_t* d_ciphertext, uint8_t* d_ghash_out,
    int num_blocks, const uint8_t* d_J0, const uint8_t* d_H,
    int threads_per_block, musaStream_t stream)
{
    int grid_size = (num_blocks + threads_per_block - 1) / threads_per_block;
    aes_gcm_encrypt_kernel<<<grid_size, threads_per_block, 0, stream>>>(
        d_plaintext, d_ciphertext, d_ghash_out, num_blocks, d_J0, d_H);
}

extern "C" void launch_aes_gcm_decrypt(
    const uint8_t* d_ciphertext, uint8_t* d_plaintext, uint8_t* d_ghash_out,
    int num_blocks, const uint8_t* d_J0, const uint8_t* d_H,
    int threads_per_block, musaStream_t stream)
{
    int grid_size = (num_blocks + threads_per_block - 1) / threads_per_block;
    aes_gcm_decrypt_kernel<<<grid_size, threads_per_block, 0, stream>>>(
        d_ciphertext, d_plaintext, d_ghash_out, num_blocks, d_J0, d_H);
}