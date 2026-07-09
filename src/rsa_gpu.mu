/**
 * rsa_gpu.mu — MUSA GPU RSA 批量模幂 kernel
 *
 * 每线程处理一个独立的 Montgomery 模幂（RSA 解密）
 * 使用 CIOS Montgomery multiplication，消除除法
 *
 * 限制：整个模数必须适合寄存器（32 × uint64_t = 256 bytes/线程）
 * MTT S80 每 SM 约 256KB 寄存器空间，约可同时运行 256 线程
 */

#include <musa_runtime.h>
#include <stdint.h>

// ═══════════════════════════════════════════════════════════════════════
//  GPU 常量内存（由主机端设置）
// ═══════════════════════════════════════════════════════════════════════

static constexpr int RSA_WORDS = 32;  // 2048 / 64

/// 模数 n（2048-bit = 32 × uint64_t）
__constant__ uint64_t d_mod[RSA_WORDS];

/// 私钥指数 d（2048-bit）
__constant__ uint64_t d_exp[RSA_WORDS];

/// Montgomery m_prime = -n^(-1) mod 2^64
__constant__ uint64_t d_m_prime;

/// Montgomery R2 mod n = R^2 mod n
__constant__ uint64_t d_R2[RSA_WORDS];

// ═══════════════════════════════════════════════════════════════════════
//  Montgomery 乘法（GPU CIOS，无除法）
// ═══════════════════════════════════════════════════════════════════════

/// GPU Montgomery multiply: r = a * b * R^(-1) mod n
/// r, a, b 各为 RSA_WORDS 个 uint64_t
__device__ void gpu_mont_mul(
    uint64_t* r, const uint64_t* a, const uint64_t* b)
{
    uint64_t t[2 * RSA_WORDS + 1] = {};
    const uint64_t m_prime = d_m_prime;

    for (int i = 0; i < RSA_WORDS; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < RSA_WORDS; ++j) {
            // 64×64→128: 用两个 32-bit 乘法模拟
            uint32_t a_lo = (uint32_t)a[i];
            uint32_t a_hi = (uint32_t)(a[i] >> 32);
            uint32_t b_lo = (uint32_t)b[j];
            uint32_t b_hi = (uint32_t)(b[j] >> 32);

            uint64_t p0 = (uint64_t)a_lo * b_lo;
            uint64_t p1 = (uint64_t)a_lo * b_hi;
            uint64_t p2 = (uint64_t)a_hi * b_lo;
            uint64_t p3 = (uint64_t)a_hi * b_hi;

            uint64_t mid = (p0 >> 32) + (uint32_t)p1 + (uint32_t)p2;
            uint64_t prod_lo = (mid << 32) | (uint32_t)p0;
            uint64_t prod_hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);

            // t[i+j] += prod_lo + carry
            uint64_t sum = t[i + j] + prod_lo;
            carry += prod_hi + (sum < t[i + j] ? 1 : 0);
            t[i + j] = sum + carry;
            carry = (sum + carry < sum ? 1 : 0) | (carry >> 63);
            // Simplified carry handling
        }
        // t += u * m
        uint64_t u = t[i] * m_prime;
        carry = 0;
        for (int j = 0; j < RSA_WORDS; ++j) {
            uint32_t u_lo = (uint32_t)u;
            uint32_t u_hi = (uint32_t)(u >> 32);
            uint32_t m_lo = (uint32_t)d_mod[j];
            uint32_t m_hi = (uint32_t)(d_mod[j] >> 32);

            uint64_t p0 = (uint64_t)u_lo * m_lo;
            uint64_t p1 = (uint64_t)u_lo * m_hi;
            uint64_t p2 = (uint64_t)u_hi * m_lo;
            uint64_t p3 = (uint64_t)u_hi * m_hi;

            uint64_t mid = (p0 >> 32) + (uint32_t)p1 + (uint32_t)p2;
            uint64_t prod_lo = (mid << 32) | (uint32_t)p0;
            uint64_t prod_hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);

            carry += prod_hi;
            t[i + j] += prod_lo;
            if (t[i + j] < prod_lo) ++carry;
        }
    }

    for (int i = 0; i < RSA_WORDS; ++i) r[i] = t[i + RSA_WORDS];

    // 最终约简
    bool ge = false;
    for (int i = RSA_WORDS - 1; i >= 0; --i) {
        if (r[i] > d_mod[i]) { ge = true; break; }
        if (r[i] < d_mod[i]) break;
    }
    if (ge) {
        uint64_t borrow = 0;
        for (int i = 0; i < RSA_WORDS; ++i) {
            uint64_t diff = r[i] - d_mod[i] - borrow;
            borrow = (r[i] < d_mod[i] + borrow) ? 1 : 0;
            r[i] = diff;
        }
    }
}

/// GPU Montgomery 域转换
__device__ void gpu_to_mont(uint64_t* r, const uint64_t* a) {
    gpu_mont_mul(r, a, d_R2);
}

__device__ void gpu_from_mont(uint64_t* r, const uint64_t* a) {
    uint64_t one[RSA_WORDS] = {1};
    gpu_mont_mul(r, a, one);
}

// ═══════════════════════════════════════════════════════════════════════
//  Kernel：批量 RSA 解密
// ═══════════════════════════════════════════════════════════════════════

extern "C" __global__ void rsa_batch_decrypt_kernel(
    const uint64_t* __restrict__ ciphers,  // count × RSA_WORDS
    uint64_t*       __restrict__ plains,   // count × RSA_WORDS
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    const uint64_t* c = ciphers + idx * RSA_WORDS;
    uint64_t*       p = plains  + idx * RSA_WORDS;

    // 将密文转换到 Montgomery 域
    uint64_t c_mont[RSA_WORDS];
    gpu_to_mont(c_mont, c);

    // r_mont = R mod n（Montgomery 域中的 1）
    uint64_t r_mont[RSA_WORDS];
    gpu_to_mont(r_mont, d_R2);  // 1 * R^2 * R^(-1) = R

    // Square-and-multiply（从最高位开始）
    for (int bit = RSA_WORDS * 64 - 1; bit >= 0; --bit) {
        // 跳过前导零：找到 d_exp 的最高有效位
        // （简化：始终循环，后续可优化）
    }

    // 简化版：使用固定指数长度（2048 bits）
    for (int i = RSA_WORDS - 1; i >= 0; --i) {
        uint64_t word = d_exp[i];
        for (int b = 63; b >= 0; --b) {
            // r_mont = r_mont^2
            uint64_t tmp[RSA_WORDS];
            gpu_mont_mul(tmp, r_mont, r_mont);
            for (int k = 0; k < RSA_WORDS; ++k) r_mont[k] = tmp[k];

            if ((word >> b) & 1) {
                gpu_mont_mul(tmp, r_mont, c_mont);
                for (int k = 0; k < RSA_WORDS; ++k) r_mont[k] = tmp[k];
            }
        }
    }

    // 转出 Montgomery 域
    gpu_from_mont(p, r_mont);
}

// ═══════════════════════════════════════════════════════════════════════
//  主机端 launch + 初始化
// ═══════════════════════════════════════════════════════════════════════

extern "C" void musa_rsa_gpu_init(
    const uint64_t* host_mod, const uint64_t* host_exp,
    uint64_t host_m_prime, const uint64_t* host_R2)
{
    musaMemcpyToSymbol(d_mod, host_mod, RSA_WORDS * 8, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_exp, host_exp, RSA_WORDS * 8, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_m_prime, &host_m_prime, 8, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_R2, host_R2, RSA_WORDS * 8, 0, musaMemcpyHostToDevice);
}

extern "C" void launch_rsa_batch_decrypt(
    const uint64_t* d_ciphers, uint64_t* d_plains, int count,
    int threads_per_block, musaStream_t stream)
{
    int grid = (count + threads_per_block - 1) / threads_per_block;
    rsa_batch_decrypt_kernel<<<grid, threads_per_block, 0, stream>>>(
        d_ciphers, d_plains, count);
}
