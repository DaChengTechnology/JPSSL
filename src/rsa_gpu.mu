/**
 * rsa_gpu.mu — MUSA GPU RSA 批量模幂 kernel（32 位 limb 拆分版）
 *
 * 采用 32-bit limb CIOS Montgomery 乘法：
 *   - 每次 32×32→64 乘法都是 GPU 原生指令，无需 __int128 仿真
 *   - 进位累加均用 64-bit 加法，全程原生类型
 *   - 2048-bit 模数 = 64 × uint32_t
 *
 * 正确性修复（与 CPU 端一致）：
 *   - t[i+K] 累加进位而非覆盖（ADD 语义），保留上一轮 u*m 约减的传播值
 *   - 最终约减处理 t[2K] 溢出位
 *
 * 限制：RSA-2048 专用；批量消息级并行（每线程一个模幂）
 */

#include <musa_runtime.h>
#include <stdint.h>

// ═══════════════════════════════════════════════════════════════════════
//  常量
// ═══════════════════════════════════════════════════════════════════════

static constexpr int RSA_WORDS = 32;       // 2048-bit / 64
static constexpr int RSA_LIMBS = 64;       // 2048-bit / 32
// 每线程共享内存工作区：核心 2K+2，额外 +8 溢出保护（carry 传播缓冲）
#define RSA_T_PER_THREAD   (2 * RSA_LIMBS + 8)  // 136

// ═══════════════════════════════════════════════════════════════════════
//  GPU 常量内存（32-bit limbs，由主机端 musa_rsa_gpu_init 设置）
// ═══════════════════════════════════════════════════════════════════════

/// 模数 n（64 × uint32_t，limb[0]=LSW）
__constant__ uint32_t d_mod[RSA_LIMBS];

/// 私钥指数 d（仍为 64-bit word，仅做位测试）
__constant__ uint64_t d_exp[RSA_WORDS];

/// Montgomery m_prime = -n^(-1) mod 2^32
__constant__ uint32_t d_m_prime;

/// Montgomery R^2 mod n（32-bit limbs）
__constant__ uint32_t d_R2[RSA_LIMBS];

/// Montgomery R mod n（32-bit limbs，Montgomery 域中 1 的表示）
__constant__ uint32_t d_R_mod[RSA_LIMBS];

/// 指数的有效 bit 数（跳过前导零）
__constant__ int d_exp_bits;

// ═══════════════════════════════════════════════════════════════════════
//  Montgomery 乘法（32-bit CIOS，全原生 64-bit 运算）
// ═══════════════════════════════════════════════════════════════════════

/**
 * r = a * b * R^(-1) mod n,  R = 2^(32*64)
 *
 * @param r  输出（RSA_LIMBS 个 uint32_t）
 * @param a  输入 A（RSA_LIMBS 个 uint32_t）
 * @param b  输入 B（RSA_LIMBS 个 uint32_t）
 * @param t  临时工作区（共享内存，RSA_T_PER_THREAD 个 uint32_t）
 */
__device__ void gpu_mont_mul32(
    uint32_t* __restrict__ r,
    const uint32_t* __restrict__ a,
    const uint32_t* __restrict__ b,
    uint32_t* __restrict__ t)
{
    // 清零临时数组
    #pragma unroll
    for (int i = 0; i < RSA_T_PER_THREAD; ++i)
        t[i] = 0;

    const uint32_t m_prime = d_m_prime;

    for (int i = 0; i < RSA_LIMBS; ++i) {
        const uint32_t ai = a[i];

        // ── 第 1 步：t += a[i] * b[0..63]，进位累加（ADD）──
        {
            uint32_t carry = 0;
            #pragma unroll
            for (int j = 0; j < RSA_LIMBS; ++j) {
                uint64_t sum = (uint64_t)ai * b[j] + t[i + j] + carry;
                t[i + j] = (uint32_t)sum;
                carry    = (uint32_t)(sum >> 32);
            }
            // 累加进位而非覆盖（上一轮 u*m 约减的传播值必须保留）
            uint32_t sc = t[i + RSA_LIMBS] + carry;
            t[i + RSA_LIMBS] = sc;
            if (sc < carry) {
                for (int j = i + RSA_LIMBS + 1;; ++j) {
                    uint32_t s2 = t[j] + 1;
                    t[j] = s2;
                    if (s2) break;
                }
            }
        }

        // ── 第 2 步：u = t[i] * m_prime (低32位); t += u * mod ──
        const uint32_t u = t[i] * m_prime;  // 只取低 32 位
        {
            uint32_t carry = 0;
            #pragma unroll
            for (int j = 0; j < RSA_LIMBS; ++j) {
                uint64_t sum = (uint64_t)u * d_mod[j] + t[i + j] + carry;
                t[i + j] = (uint32_t)sum;
                carry    = (uint32_t)(sum >> 32);
            }
            // 传播进位（累加到后续位置）
            int idx = i + RSA_LIMBS;
            while (carry) {
                uint64_t sum = (uint64_t)t[idx] + carry;
                t[idx] = (uint32_t)sum;
                carry  = (uint32_t)(sum >> 32);
                ++idx;
            }
        }
    }

    // ── 提取结果：r = t[K .. 2K-1] ──
    #pragma unroll
    for (int i = 0; i < RSA_LIMBS; ++i)
        r[i] = t[i + RSA_LIMBS];

    // ── 最终条件减法：检查 t[2K] 溢出位，可能需减两次 ──
    if (t[2 * RSA_LIMBS]) {
        // 减一次（r < mod 由 CIOS 界保证，wrap 减法即 r + 2^(32K) - mod）
        uint32_t borrow = 0;
        #pragma unroll
        for (int i = 0; i < RSA_LIMBS; ++i) {
            uint32_t diff = r[i] - d_mod[i] - borrow;
            borrow = (r[i] < d_mod[i] + borrow) ? 1 : 0;
            r[i] = diff;
        }
        // 若仍 >= mod，再减一次
        bool still_ge = false;
        for (int i = RSA_LIMBS - 1; i >= 0; --i) {
            if (r[i] > d_mod[i]) { still_ge = true; break; }
            if (r[i] < d_mod[i]) break;
        }
        if (still_ge) {
            borrow = 0;
            #pragma unroll
            for (int i = 0; i < RSA_LIMBS; ++i) {
                uint32_t diff = r[i] - d_mod[i] - borrow;
                borrow = (r[i] < d_mod[i] + borrow) ? 1 : 0;
                r[i] = diff;
            }
        }
    }
    // while r >= mod: r -= mod（处理罕见边缘情况）
    while (true) {
        bool ge = false;
        for (int i = RSA_LIMBS - 1; i >= 0; --i) {
            if (r[i] > d_mod[i]) { ge = true; break; }
            if (r[i] < d_mod[i]) break;
        }
        if (!ge) break;
        uint32_t borrow = 0;
        for (int i = 0; i < RSA_LIMBS; ++i) {
            uint32_t diff = r[i] - d_mod[i] - borrow;
            borrow = (r[i] < d_mod[i] + borrow) ? 1 : 0;
            r[i] = diff;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Kernel：批量 RSA 解密（Square-and-Multiply，Montgomery 域内）
//  ciphers/plains 均为 native uint64_t[32]（d[0]=LSW），kernel 内拆分为
//  32-bit limbs：limb[2k]=low32(d[k]), limb[2k+1]=high32(d[k])
// ═══════════════════════════════════════════════════════════════════════

extern "C" __global__ void rsa_batch_decrypt_kernel(
    const uint64_t* __restrict__ ciphers,  // count × RSA_WORDS
    uint64_t*       __restrict__ plains,   // count × RSA_WORDS
    int count)
{
    // 共享内存：每线程 RSA_T_PER_THREAD 个 uint32_t 工作区（避免 local memory 溢出）
    extern __shared__ uint32_t s_t[];

    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint32_t* t = &s_t[threadIdx.x * RSA_T_PER_THREAD];

    // ── 0. 拆分模数/预计算到寄存器不必要：d_mod/R2/R_mod 在常量内存（缓存）──

    // ── 1. 密文拆分：uint64_t → 32-bit limbs ──
    uint32_t c[RSA_LIMBS];
    {
        const uint64_t* src = ciphers + (size_t)idx * RSA_WORDS;
        #pragma unroll
        for (int k = 0; k < RSA_WORDS; ++k) {
            uint64_t v = src[k];
            c[2 * k]     = (uint32_t)v;
            c[2 * k + 1] = (uint32_t)(v >> 32);
        }
    }

    // ── 2. 密文转入 Montgomery 域：c_mont = mont_mul(c, R^2)（就地覆盖 c）──
    gpu_mont_mul32(c, c, d_R2, t);

    // ── 3. 双缓冲累加器：r_cur = R mod n（Montgomery 域中的 1） ──
    uint32_t r_buf[2][RSA_LIMBS];
    #pragma unroll
    for (int k = 0; k < RSA_LIMBS; ++k)
        r_buf[0][k] = d_R_mod[k];

    uint32_t* r_cur = r_buf[0];
    uint32_t* r_nxt = r_buf[1];

    // ── 4. Square-and-multiply exponentiation ──
    for (int bit = d_exp_bits - 1; bit >= 0; --bit) {
        // Squaring: r_nxt = mont_mul(r_cur, r_cur)
        gpu_mont_mul32(r_nxt, r_cur, r_cur, t);
        // 指针交换（避免 elem-wise copy）
        { uint32_t* tmp = r_cur; r_cur = r_nxt; r_nxt = tmp; }

        // 检查指数该 bit 是否为 1
        const int w = bit >> 6;   // bit / 64
        const int b = bit & 63;   // bit % 64
        if ((d_exp[w] >> b) & 1) {
            // 乘法：r_nxt = mont_mul(r_cur, c_mont)
            gpu_mont_mul32(r_nxt, r_cur, c, t);
            { uint32_t* tmp = r_cur; r_cur = r_nxt; r_nxt = tmp; }
        }
    }

    // ── 5. 转出 Montgomery 域：result = mont_mul(r_cur, 1) ──
    {
        static constexpr uint32_t one[RSA_LIMBS] = {1};  // 其余为 0
        gpu_mont_mul32(r_nxt, r_cur, one, t);
    }

    // ── 6. 打包回 uint64_t ──
    {
        uint64_t* dst = plains + (size_t)idx * RSA_WORDS;
        #pragma unroll
        for (int k = 0; k < RSA_WORDS; ++k) {
            uint64_t v = (uint64_t)r_nxt[2 * k] | ((uint64_t)r_nxt[2 * k + 1] << 32);
            dst[k] = v;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  主机端初始化 + Launch
// ═══════════════════════════════════════════════════════════════════════

/// 设置 GPU 常量内存（每次换密钥时调用一次）
/// 输入均为 native uint64_t[32]（d[0]=LSW），此处拆分为 32-bit limbs
extern "C" void musa_rsa_gpu_init(
    const uint64_t* host_mod,
    const uint64_t* host_exp,
    uint64_t        host_m_prime,
    const uint64_t* host_R2,
    const uint64_t* host_R_mod,   // R mod n（Montgomery 域中 1 的表示）
    int             host_exp_bits) // 指数有效 bit 数
{
    // 拆分到 32-bit limbs
    uint32_t mod32[RSA_LIMBS], r2_32[RSA_LIMBS], rm_32[RSA_LIMBS];
    for (int k = 0; k < RSA_WORDS; ++k) {
        mod32[2*k]     = (uint32_t)host_mod[k];
        mod32[2*k + 1] = (uint32_t)(host_mod[k] >> 32);
        r2_32[2*k]     = (uint32_t)host_R2[k];
        r2_32[2*k + 1] = (uint32_t)(host_R2[k] >> 32);
        rm_32[2*k]     = (uint32_t)host_R_mod[k];
        rm_32[2*k + 1] = (uint32_t)(host_R_mod[k] >> 32);
    }
    uint32_t mp32 = (uint32_t)host_m_prime;  // -n^-1 mod 2^64 → 低32位即 mod 2^32

    musaMemcpyToSymbol(d_mod,     mod32,   RSA_LIMBS * 4, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_exp,     host_exp, RSA_WORDS * 8, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_m_prime, &mp32,   4,             0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_R2,      r2_32,   RSA_LIMBS * 4, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_R_mod,   rm_32,   RSA_LIMBS * 4, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_exp_bits,&host_exp_bits, 4,      0, musaMemcpyHostToDevice);
}

/// Launch RSA 批量解密 kernel
extern "C" void launch_rsa_batch_decrypt(
    const uint64_t* d_ciphers,
    uint64_t*       d_plains,
    int             count,
    int             threads_per_block,
    musaStream_t    stream)
{
    const int grid  = (count + threads_per_block - 1) / threads_per_block;
    const size_t smem = threads_per_block * RSA_T_PER_THREAD * sizeof(uint32_t);

    rsa_batch_decrypt_kernel<<<grid, threads_per_block, smem, stream>>>(
        d_ciphers, d_plains, count);
}

// ═══════════════════════════════════════════════════════════════════════
//  RSA-4096 变体（128 × uint32_t limbs）
//  共享内存约束: 264 words × 4B × tpb ≤ 32KB → tpb ≤ 16（主机端固定 16）
// ═══════════════════════════════════════════════════════════════════════

static constexpr int RSA4096_WORDS = 64;      // 4096-bit / 64
static constexpr int RSA4096_LIMBS = 128;     // 4096-bit / 32
#define RSA4096_T_PER_THREAD   (2 * RSA4096_LIMBS + 8)  // 264

/// 4096-bit 模数 n
__constant__ uint32_t d_mod4096[RSA4096_LIMBS];
/// 4096-bit 私钥指数 d
__constant__ uint64_t d_exp4096[RSA4096_WORDS];
/// m_prime = -n^(-1) mod 2^32
__constant__ uint32_t d_m_prime4096;
/// R^2 mod n
__constant__ uint32_t d_R2_4096[RSA4096_LIMBS];
/// R mod n
__constant__ uint32_t d_R_mod4096[RSA4096_LIMBS];
/// 指数有效 bit 数
__constant__ int d_exp_bits4096;

/**
 * 4096-bit Montgomery 乘法（32-bit CIOS，与 2048 版本算法一致）
 */
__device__ void gpu_mont_mul32_4096(
    uint32_t* __restrict__ r,
    const uint32_t* __restrict__ a,
    const uint32_t* __restrict__ b,
    uint32_t* __restrict__ t)
{
    #pragma unroll
    for (int i = 0; i < RSA4096_T_PER_THREAD; ++i)
        t[i] = 0;

    const uint32_t m_prime = d_m_prime4096;

    for (int i = 0; i < RSA4096_LIMBS; ++i) {
        const uint32_t ai = a[i];

        // ── 第 1 步：t += a[i] * b[0..127]，进位累加（ADD）──
        {
            uint32_t carry = 0;
            #pragma unroll
            for (int j = 0; j < RSA4096_LIMBS; ++j) {
                uint64_t sum = (uint64_t)ai * b[j] + t[i + j] + carry;
                t[i + j] = (uint32_t)sum;
                carry    = (uint32_t)(sum >> 32);
            }
            uint32_t sc = t[i + RSA4096_LIMBS] + carry;
            t[i + RSA4096_LIMBS] = sc;
            if (sc < carry) {
                for (int j = i + RSA4096_LIMBS + 1;; ++j) {
                    uint32_t s2 = t[j] + 1;
                    t[j] = s2;
                    if (s2) break;
                }
            }
        }

        // ── 第 2 步：u = t[i] * m_prime (低32位); t += u * mod ──
        const uint32_t u = t[i] * m_prime;
        {
            uint32_t carry = 0;
            #pragma unroll
            for (int j = 0; j < RSA4096_LIMBS; ++j) {
                uint64_t sum = (uint64_t)u * d_mod4096[j] + t[i + j] + carry;
                t[i + j] = (uint32_t)sum;
                carry    = (uint32_t)(sum >> 32);
            }
            int idx = i + RSA4096_LIMBS;
            while (carry) {
                uint64_t sum = (uint64_t)t[idx] + carry;
                t[idx] = (uint32_t)sum;
                carry  = (uint32_t)(sum >> 32);
                ++idx;
            }
        }
    }

    #pragma unroll
    for (int i = 0; i < RSA4096_LIMBS; ++i)
        r[i] = t[i + RSA4096_LIMBS];

    // ── 最终条件减法 ──
    if (t[2 * RSA4096_LIMBS]) {
        uint32_t borrow = 0;
        #pragma unroll
        for (int i = 0; i < RSA4096_LIMBS; ++i) {
            uint32_t diff = r[i] - d_mod4096[i] - borrow;
            borrow = (r[i] < d_mod4096[i] + borrow) ? 1 : 0;
            r[i] = diff;
        }
        bool still_ge = false;
        for (int i = RSA4096_LIMBS - 1; i >= 0; --i) {
            if (r[i] > d_mod4096[i]) { still_ge = true; break; }
            if (r[i] < d_mod4096[i]) break;
        }
        if (still_ge) {
            borrow = 0;
            #pragma unroll
            for (int i = 0; i < RSA4096_LIMBS; ++i) {
                uint32_t diff = r[i] - d_mod4096[i] - borrow;
                borrow = (r[i] < d_mod4096[i] + borrow) ? 1 : 0;
                r[i] = diff;
            }
        }
    }
    while (true) {
        bool ge = false;
        for (int i = RSA4096_LIMBS - 1; i >= 0; --i) {
            if (r[i] > d_mod4096[i]) { ge = true; break; }
            if (r[i] < d_mod4096[i]) break;
        }
        if (!ge) break;
        uint32_t borrow = 0;
        for (int i = 0; i < RSA4096_LIMBS; ++i) {
            uint32_t diff = r[i] - d_mod4096[i] - borrow;
            borrow = (r[i] < d_mod4096[i] + borrow) ? 1 : 0;
            r[i] = diff;
        }
    }
}

/**
 * 4096-bit 批量解密 kernel
 * ciphers/plains: native uint64_t[64] (d[0]=LSW)，拆分为 128 个 32-bit limbs
 */
extern "C" __global__ void rsa_batch_decrypt_kernel4096(
    const uint64_t* __restrict__ ciphers,  // count × 64
    uint64_t*       __restrict__ plains,   // count × 64
    int count)
{
    extern __shared__ uint32_t s_t[];

    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint32_t* t = &s_t[threadIdx.x * RSA4096_T_PER_THREAD];

    // 1. 密文拆分: uint64_t[64] → 128 个 32-bit limbs
    uint32_t c[RSA4096_LIMBS];
    {
        const uint64_t* src = ciphers + (size_t)idx * RSA4096_WORDS;
        #pragma unroll
        for (int k = 0; k < RSA4096_WORDS; ++k) {
            uint64_t v = src[k];
            c[2 * k]     = (uint32_t)v;
            c[2 * k + 1] = (uint32_t)(v >> 32);
        }
    }

    // 2. 转入 Montgomery 域（就地覆盖 c）
    gpu_mont_mul32_4096(c, c, d_R2_4096, t);

    // 3. 双缓冲累加器
    uint32_t r_buf[2][RSA4096_LIMBS];
    #pragma unroll
    for (int k = 0; k < RSA4096_LIMBS; ++k)
        r_buf[0][k] = d_R_mod4096[k];

    uint32_t* r_cur = r_buf[0];
    uint32_t* r_nxt = r_buf[1];

    // 4. Square-and-multiply
    for (int bit = d_exp_bits4096 - 1; bit >= 0; --bit) {
        gpu_mont_mul32_4096(r_nxt, r_cur, r_cur, t);
        { uint32_t* tmp = r_cur; r_cur = r_nxt; r_nxt = tmp; }
        const int w = bit >> 6;
        const int b = bit & 63;
        if ((d_exp4096[w] >> b) & 1) {
            gpu_mont_mul32_4096(r_nxt, r_cur, c, t);
            { uint32_t* tmp = r_cur; r_cur = r_nxt; r_nxt = tmp; }
        }
    }

    // 5. 转出 Montgomery 域
    {
        static constexpr uint32_t one[RSA4096_LIMBS] = {1};
        gpu_mont_mul32_4096(r_nxt, r_cur, one, t);
    }

    // 6. 打包回 uint64_t[64]
    {
        uint64_t* dst = plains + (size_t)idx * RSA4096_WORDS;
        #pragma unroll
        for (int k = 0; k < RSA4096_WORDS; ++k) {
            uint64_t v = (uint64_t)r_nxt[2 * k] | ((uint64_t)r_nxt[2 * k + 1] << 32);
            dst[k] = v;
        }
    }
}

/// 设置 4096-bit GPU 常量内存
extern "C" void musa_rsa_gpu_init4096(
    const uint64_t* host_mod,
    const uint64_t* host_exp,
    uint64_t        host_m_prime,
    const uint64_t* host_R2,
    const uint64_t* host_R_mod,
    int             host_exp_bits)
{
    uint32_t mod32[RSA4096_LIMBS], r2_32[RSA4096_LIMBS], rm_32[RSA4096_LIMBS];
    for (int k = 0; k < RSA4096_WORDS; ++k) {
        mod32[2*k]     = (uint32_t)host_mod[k];
        mod32[2*k + 1] = (uint32_t)(host_mod[k] >> 32);
        r2_32[2*k]     = (uint32_t)host_R2[k];
        r2_32[2*k + 1] = (uint32_t)(host_R2[k] >> 32);
        rm_32[2*k]     = (uint32_t)host_R_mod[k];
        rm_32[2*k + 1] = (uint32_t)(host_R_mod[k] >> 32);
    }
    uint32_t mp32 = (uint32_t)host_m_prime;

    musaMemcpyToSymbol(d_mod4096,     mod32,   RSA4096_LIMBS * 4, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_exp4096,     host_exp, RSA4096_WORDS * 8, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_m_prime4096, &mp32,   4,                 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_R2_4096,     r2_32,   RSA4096_LIMBS * 4, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_R_mod4096,   rm_32,   RSA4096_LIMBS * 4, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_exp_bits4096,&host_exp_bits, 4,         0, musaMemcpyHostToDevice);
}

/// Launch 4096-bit RSA 批量解密 kernel
/// 注意: 共享内存 264×4B×tpb ≤ 32KB → tpb 必须 ≤ 16
extern "C" void launch_rsa_batch_decrypt4096(
    const uint64_t* d_ciphers,
    uint64_t*       d_plains,
    int             count,
    int             threads_per_block,
    musaStream_t    stream)
{
    const int grid  = (count + threads_per_block - 1) / threads_per_block;
    const size_t smem = threads_per_block * RSA4096_T_PER_THREAD * sizeof(uint32_t);

    rsa_batch_decrypt_kernel4096<<<grid, threads_per_block, smem, stream>>>(
        d_ciphers, d_plains, count);
}

// ═══════════════════════════════════════════════════════════════════════
//  RSA-1024 变体（CRT 用: p/q ≈ 1024 位, 32 × uint32_t limbs）
//  共享内存: 72 × 4B × tpb=32 = 9.2KB, 远小于 32KB
// ═══════════════════════════════════════════════════════════════════════

static constexpr int RSA1024_WORDS = 16;      // 1024-bit / 64
static constexpr int RSA1024_LIMBS = 32;      // 1024-bit / 32
#define RSA1024_T_PER_THREAD   (2 * RSA1024_LIMBS + 8)  // 72

/// 1024-bit 模数（p 或 q）
__constant__ uint32_t d_mod_half[RSA1024_LIMBS];
/// 1024-bit 指数（dP 或 dQ）
__constant__ uint64_t d_exp_half[RSA1024_WORDS];
/// m_prime = -n^(-1) mod 2^32
__constant__ uint32_t d_m_prime_half;
/// R^2 mod n
__constant__ uint32_t d_R2_half[RSA1024_LIMBS];
/// R mod n
__constant__ uint32_t d_R_mod_half[RSA1024_LIMBS];
/// 指数有效 bit 数
__constant__ int d_exp_bits_half;

/**
 * 1024-bit Montgomery 乘法（32-bit CIOS, 与 2048 算法一致）
 */
__device__ void gpu_mont_mul32_half(
    uint32_t* __restrict__ r,
    const uint32_t* __restrict__ a,
    const uint32_t* __restrict__ b,
    uint32_t* __restrict__ t)
{
    #pragma unroll
    for (int i = 0; i < RSA1024_T_PER_THREAD; ++i)
        t[i] = 0;
    const uint32_t m_prime = d_m_prime_half;
    for (int i = 0; i < RSA1024_LIMBS; ++i) {
        const uint32_t ai = a[i];
        {
            uint32_t carry = 0;
            #pragma unroll
            for (int j = 0; j < RSA1024_LIMBS; ++j) {
                uint64_t sum = (uint64_t)ai * b[j] + t[i + j] + carry;
                t[i + j] = (uint32_t)sum;
                carry    = (uint32_t)(sum >> 32);
            }
            uint32_t sc = t[i + RSA1024_LIMBS] + carry;
            t[i + RSA1024_LIMBS] = sc;
            if (sc < carry) {
                for (int j = i + RSA1024_LIMBS + 1;; ++j) {
                    uint32_t s2 = t[j] + 1;
                    t[j] = s2;
                    if (s2) break;
                }
            }
        }
        const uint32_t u = t[i] * m_prime;
        {
            uint32_t carry = 0;
            #pragma unroll
            for (int j = 0; j < RSA1024_LIMBS; ++j) {
                uint64_t sum = (uint64_t)u * d_mod_half[j] + t[i + j] + carry;
                t[i + j] = (uint32_t)sum;
                carry    = (uint32_t)(sum >> 32);
            }
            int idx = i + RSA1024_LIMBS;
            while (carry) {
                uint64_t sum = (uint64_t)t[idx] + carry;
                t[idx] = (uint32_t)sum;
                carry  = (uint32_t)(sum >> 32);
                ++idx;
            }
        }
    }
    #pragma unroll
    for (int i = 0; i < RSA1024_LIMBS; ++i)
        r[i] = t[i + RSA1024_LIMBS];
    if (t[2 * RSA1024_LIMBS]) {
        uint32_t borrow = 0;
        #pragma unroll
        for (int i = 0; i < RSA1024_LIMBS; ++i) {
            uint32_t diff = r[i] - d_mod_half[i] - borrow;
            borrow = (r[i] < d_mod_half[i] + borrow) ? 1 : 0;
            r[i] = diff;
        }
        bool still_ge = false;
        for (int i = RSA1024_LIMBS - 1; i >= 0; --i) {
            if (r[i] > d_mod_half[i]) { still_ge = true; break; }
            if (r[i] < d_mod_half[i]) break;
        }
        if (still_ge) {
            borrow = 0;
            #pragma unroll
            for (int i = 0; i < RSA1024_LIMBS; ++i) {
                uint32_t diff = r[i] - d_mod_half[i] - borrow;
                borrow = (r[i] < d_mod_half[i] + borrow) ? 1 : 0;
                r[i] = diff;
            }
        }
    }
    while (true) {
        bool ge = false;
        for (int i = RSA1024_LIMBS - 1; i >= 0; --i) {
            if (r[i] > d_mod_half[i]) { ge = true; break; }
            if (r[i] < d_mod_half[i]) break;
        }
        if (!ge) break;
        uint32_t borrow = 0;
        for (int i = 0; i < RSA1024_LIMBS; ++i) {
            uint32_t diff = r[i] - d_mod_half[i] - borrow;
            borrow = (r[i] < d_mod_half[i] + borrow) ? 1 : 0;
            r[i] = diff;
        }
    }
}

/**
 * 1024-bit 批量 CRT 解密 kernel
 * 输入: 已对 p（或 q）取模的 base，每个 16 个 uint64_t
 */
extern "C" __global__ void rsa_batch_decrypt_kernel_half(
    const uint64_t* __restrict__ ciphers,  // count × 16
    uint64_t*       __restrict__ plains,   // count × 16
    int count)
{
    extern __shared__ uint32_t s_t[];
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    uint32_t* t = &s_t[threadIdx.x * RSA1024_T_PER_THREAD];

    // 拆分: uint64_t[16] → 32-bit limbs[32]
    uint32_t c[RSA1024_LIMBS];
    const uint64_t* src = ciphers + (size_t)idx * RSA1024_WORDS;
    #pragma unroll
    for (int k = 0; k < RSA1024_WORDS; ++k) {
        uint64_t v = src[k];
        c[2 * k]     = (uint32_t)v;
        c[2 * k + 1] = (uint32_t)(v >> 32);
    }

    // 转入 Montgomery 域（就地覆盖 c）
    gpu_mont_mul32_half(c, c, d_R2_half, t);

    // 双缓冲
    uint32_t r_buf[2][RSA1024_LIMBS];
    #pragma unroll
    for (int k = 0; k < RSA1024_LIMBS; ++k)
        r_buf[0][k] = d_R_mod_half[k];
    uint32_t* r_cur = r_buf[0];
    uint32_t* r_nxt = r_buf[1];

    // Square-and-multiply
    for (int bit = d_exp_bits_half - 1; bit >= 0; --bit) {
        gpu_mont_mul32_half(r_nxt, r_cur, r_cur, t);
        { uint32_t* tmp = r_cur; r_cur = r_nxt; r_nxt = tmp; }
        const int w = bit >> 6;
        const int b = bit & 63;
        if ((d_exp_half[w] >> b) & 1) {
            gpu_mont_mul32_half(r_nxt, r_cur, c, t);
            { uint32_t* tmp = r_cur; r_cur = r_nxt; r_nxt = tmp; }
        }
    }

    // 转出 Montgomery 域
    static constexpr uint32_t one[RSA1024_LIMBS] = {1};
    gpu_mont_mul32_half(r_nxt, r_cur, one, t);

    // 打包: 32-bit limbs → uint64_t[16]
    uint64_t* dst = plains + (size_t)idx * RSA1024_WORDS;
    #pragma unroll
    for (int k = 0; k < RSA1024_WORDS; ++k) {
        dst[k] = (uint64_t)r_nxt[2 * k] | ((uint64_t)r_nxt[2 * k + 1] << 32);
    }
}

/// 设置 1024-bit GPU 常量内存
extern "C" void musa_rsa_gpu_init_half(
    const uint64_t* host_mod,
    const uint64_t* host_exp,
    uint64_t        host_m_prime,
    const uint64_t* host_R2,
    const uint64_t* host_R_mod,
    int             host_exp_bits)
{
    uint32_t mod32[RSA1024_LIMBS], r2_32[RSA1024_LIMBS], rm_32[RSA1024_LIMBS];
    for (int k = 0; k < RSA1024_WORDS; ++k) {
        mod32[2*k]     = (uint32_t)host_mod[k];
        mod32[2*k + 1] = (uint32_t)(host_mod[k] >> 32);
        r2_32[2*k]     = (uint32_t)host_R2[k];
        r2_32[2*k + 1] = (uint32_t)(host_R2[k] >> 32);
        rm_32[2*k]     = (uint32_t)host_R_mod[k];
        rm_32[2*k + 1] = (uint32_t)(host_R_mod[k] >> 32);
    }
    uint32_t mp32 = (uint32_t)host_m_prime;
    musaMemcpyToSymbol(d_mod_half,     mod32,   RSA1024_LIMBS * 4, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_exp_half,     host_exp, RSA1024_WORDS * 8, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_m_prime_half, &mp32,   4,                 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_R2_half,      r2_32,   RSA1024_LIMBS * 4, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_R_mod_half,   rm_32,   RSA1024_LIMBS * 4, 0, musaMemcpyHostToDevice);
    musaMemcpyToSymbol(d_exp_bits_half,&host_exp_bits, 4,         0, musaMemcpyHostToDevice);
}

/// Launch 1024-bit CRT 批量解密 kernel
extern "C" void launch_rsa_batch_decrypt_half(
    const uint64_t* d_ciphers,
    uint64_t*       d_plains,
    int             count,
    int             threads_per_block,
    musaStream_t    stream)
{
    const int grid  = (count + threads_per_block - 1) / threads_per_block;
    const size_t smem = threads_per_block * RSA1024_T_PER_THREAD * sizeof(uint32_t);
    rsa_batch_decrypt_kernel_half<<<grid, threads_per_block, smem, stream>>>(
        d_ciphers, d_plains, count);
}
