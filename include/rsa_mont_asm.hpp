#pragma once
/**
 * rsa_mont_asm.hpp — x86-64 汇编优化的 Montgomery 乘法调度层
 *
 * 为 RSA-2048 (K=32) 和 RSA-4096 (K=64) 提供手写汇编核心，
 * 利用 MULX (BMI2) + ADCX/ADOX (ADX) 双进位链加速 CIOS 循环。
 *
 * 平台覆盖:
 *   Linux   (GCC/Clang): 内联汇编 (Intel 语法), 需要 -madx -mbmi2
 *   Windows (MSVC)     : _mulx_u64/_addcarryx_u64 intrinsics
 *                        (需 /arch:AVX2, 由 CMake 按文件启用)
 *
 * 其他 K 值自动 fallback 到 rsa_body.inc 中的标量 C 实现。
 */

#include <cstdint>
#include <cstddef>

namespace jpssl {

/**
 * @brief Montgomery 乘法 r = a * b * R^{-1} mod m (CIOS 算法)
 *
 * @param r   输出, K 个 uint64_t
 * @param a   输入, K 个 uint64_t
 * @param b   输入, K 个 uint64_t
 * @param m   模数, K 个 uint64_t (奇数)
 * @param mp  预计算: -m[0]^{-1} mod 2^64
 * @param K   limb 数 (32 = 2048-bit, 64 = 4096-bit)
 *
 * 约束: m 必须为奇数; K ∈ {32, 64} 时走汇编快速路径,
 *       其他值由调用方 fallback 到标量 CIOS。
 */
void mont_mul_asm(uint64_t* r,
                  const uint64_t* a,
                  const uint64_t* b,
                  const uint64_t* m,
                  uint64_t mp,
                  int K);

/**
 * @brief 半尺寸 Montgomery 乘法 r = a * b * R_half^{-1} mod m
 *        (CRT 的 p/q 模幂专用, 只处理前 HK = K/2 个 limb)
 *
 * @param r   输出, K 个 uint64_t; 只写低 HK 位, 高位 HK 位清零
 * @param a   输入, K 个 uint64_t (低 HK 位有效, 高位必须为 0)
 * @param b   输入, K 个 uint64_t (低 HK 位有效, 高位必须为 0)
 * @param m   模数 p 或 q, K 个 uint64_t (低 HK 位有效, 奇数)
 * @param mp  预计算: -m[0]^{-1} mod 2^64
 * @param HK  limb 数 (16 = 1024-bit, 32 = 2048-bit)
 *
 * 约束: m 必须为奇数; HK ∈ {16, 32} 时走汇编快速路径,
 *       其他值由调用方 fallback 到 rsa_body.inc 标量 CIOS。
 */
void mont_mul_half_asm(uint64_t* r,
                       const uint64_t* a,
                       const uint64_t* b,
                       const uint64_t* m,
                       uint64_t mp,
                       int HK);

/**
 * @brief 检测当前 CPU 是否支持所需的 x86 指令集
 * @return true 如果 BMI2 (MULX) + ADX (ADCX/ADOX) 可用
 *         (Intel Haswell+/Broadwell+, AMD Excavator+);
 *         结果缓存, 进程内只检测一次
 */
bool mont_mul_asm_available();

} // namespace jpssl
