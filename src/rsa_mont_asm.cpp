/**
 * rsa_mont_asm.cpp — x86-64 汇编优化的 CIOS Montgomery 乘法
 *
 * 利用 MULX (BMI2) + 手写进位链加速 RSA-2048/4096 核心热点。
 * GCC/Clang: 内联汇编; MSVC: _mulx_u64/_addcarryx_u64 intrinsics。
 * 两者生成的指令序列等价 (MULX + ADCX/ADOX 双进位链)。
 *
 * 寄存器分配 (System V AMD64 ABI):
 *   入口: rdi=r, rsi=a, rdx=b, rcx=m, r8=mp, r9=K
 *   callee-saved: rbx, rbp, r12-r15 → 用于保存关键指针和循环变量
 *   MULX 隐式: rdx 作为乘数之一, 结果在 r64a:r64b = dst_hi:dst_lo
 *
 * 参考:
 *   - Kocher, "Montgomery Multiplication"
 *   - Intel ADX 白皮书, "New Instructions Supporting Large Integer Arithmetic"
 */

#include "rsa_mont_asm.hpp"
#include "cpu_features.hpp"
#include <cstring>

#if defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h>   // __cpuidex (运行时检测)
#endif

namespace jpssl {

// ─────────────────────────────────────────────────────────────────────────
//  运行时检测
// ─────────────────────────────────────────────────────────────────────────

bool mont_mul_asm_available() {
    // 结果缓存: mont_mul 在每次模幂中会被调用上千次, CPUID 约 100+ 周期,
    // 缓存后每次调用只付出一次 static 分支判断的代价 (C++11 保证线程安全)
    static const bool available = []() -> bool {
#if defined(_MSC_VER) && defined(_M_X64)
        // MULX 需要 BMI2 (CPUID.7.0.EBX bit 8); ADCX/ADOX 需要 ADX (bit 19)
        int r[4];
        __cpuidex(r, 7, 0);
        const unsigned ebx = (unsigned)r[1];
        return ((ebx >> 8) & 1u) != 0 && ((ebx >> 19) & 1u) != 0;
#elif defined(__GNUC__) && defined(__x86_64__)
        auto feat = cpu_features::detect();
        // AVX2 → Haswell → BMI2 (MULX); ADX 从 Broadwell 开始, 广泛可用
        return feat.avx2;
#else
        return false;
#endif
    }();
    return available;
}

// ─────────────────────────────────────────────────────────────────────────
//  GCC/Clang x86-64 内联汇编实现
// ─────────────────────────────────────────────────────────────────────────

#if defined(__GNUC__) && defined(__x86_64__)

/**
 * @brief K=32 (2048-bit) CIOS Montgomery 乘法
 *
 * 核心循环: 32 次外迭代 × (32 step1 + 32 step2) 次 MULX
 * 总乘法次数: 2048 次 64×64→128
 *
 * 栈帧布局 (自顶向下):
 *   [rsp + 0x000]  t[0..31]    256B   (低半, i+j where j<32)
 *   [rsp + 0x100]  t[32..63]   256B   (高半, i+j where j>=32)
 *   [rsp + 0x200]  t[64..71]    64B   (溢出, 进位传播用)
 */
__attribute__((noinline, target("adx,bmi2")))
static void mont_mul_k32_asm(uint64_t* r,
                              const uint64_t* a,
                              const uint64_t* b,
                              const uint64_t* m,
                              uint64_t mp) {
    // t[2K+2] = t[66], 对齐到 512B
    alignas(64) uint64_t t[66];

    __asm__ __volatile__(
        ".intel_syntax noprefix\n\t"

        // ── 保存 callee-saved ──
        "push rbx\n\t"
        "push rbp\n\t"
        "push r12\n\t"
        "push r13\n\t"
        "push r14\n\t"
        "push r15\n\t"

        // ── 加载参数 ──
        "mov r12, %[r_out]\n\t"    // r12 = r
        "mov r13, %[a_ptr]\n\t"    // r13 = a
        "mov r14, %[b_ptr]\n\t"    // r14 = b
        "mov r15, %[m_ptr]\n\t"    // r15 = m
        "mov rbp, %[t_ptr]\n\t"    // rbp = &t[0]

        // ── 清零 t[0..65] ──
        "xor eax, eax\n\t"
        "mov ecx, 66\n\t"
        "mov rdi, rbp\n\t"
        "rep stosq\n\t"

        // ── 外循环 i = 0..31 ──
        "xor ebx, ebx\n\t"         // ebx = i (循环变量)
        "mov r9d, 32\n\t"          // 外循环上限

    ".L32_outer:\n\t"

        // ══════════════════ Step 1: a[i] * b[0..31] ══════════════════
        "mov rdx, [r13 + rbx*8]\n\t"  // rdx = a[i]
        "xor r11d, r11d\n\t"           // r11 = carry
        "xor ecx, ecx\n\t"             // ecx = j
        "lea r8, [rbp + rbx*8]\n\t"  // r8 = &t[i]

    ".L32_s1_loop:\n\t"
        "mulx r10, rax, [r14 + rcx*8]\n\t"  // r10:rax = a[i]*b[j]
        "add rax, [r8 + rcx*8]\n\t" // += t[i+j]
        "adc r10, 0\n\t"
        "add rax, r11\n\t"                     // += carry
        "adc r10, 0\n\t"
        "mov [r8 + rcx*8], rax\n\t"  // t[i+j] = lo
        "mov r11, r10\n\t"                      // carry = hi
        "inc ecx\n\t"
        "cmp ecx, 32\n\t"
        "jl .L32_s1_loop\n\t"

        // t[i+32] += carry (累加, 不能覆盖: 前一轮 step2 进位传播可能已写
        // t[i+32]); 溢出向高位传播, 与标量 CIOS (rsa_body.inc) 一致
        "lea rdi, [rbp + rbx*8 + 256]\n\t"
        "add [rdi], r11\n\t"
        "jnc .L32_s2_start\n\t"
        "mov r11d, 1\n\t"
        ".L32_s1_prop:\n\t"
        "add rdi, 8\n\t"
        "add [rdi], r11\n\t"
        "jc .L32_s1_prop\n\t"

    ".L32_s2_start:\n\t"
        // ══════════════════ Step 2: u * m[0..31] ══════════════════
        // u = t[i] * mp  (只需要低64位)
        "mov rax, [rbp + rbx*8]\n\t"   // rax = t[i]
        "mul QWORD PTR %[mp_val]\n\t"   // rdx:rax = t[i] * mp
        "mov rdx, rax\n\t"             // rdx = u (MULX 隐式操作数)
        "xor r11d, r11d\n\t"           // r11 = carry
        "xor ecx, ecx\n\t"             // ecx = j
        "lea r8, [rbp + rbx*8]\n\t"  // r8 = &t[i]

    ".L32_s2_loop:\n\t"
        "mulx r10, rax, [r15 + rcx*8]\n\t"   // r10:rax = u*m[j]
        "add rax, [r8 + rcx*8]\n\t" // += t[i+j]
        "adc r10, 0\n\t"
        "add rax, r11\n\t"                     // += carry
        "adc r10, 0\n\t"
        "mov [r8 + rcx*8], rax\n\t"  // t[i+j] = lo
        "mov r11, r10\n\t"                      // carry = hi
        "inc ecx\n\t"
        "cmp ecx, 32\n\t"
        "jl .L32_s2_loop\n\t"

        // ── 进位传播 t[i+32 + k] ──
        "lea rdi, [rbp + rbx*8 + 256]\n\t"  // rdi = &t[i+32]
    ".L32_carry_prop:\n\t"
        "add [rdi], r11\n\t"
        "jnc .L32_carry_done\n\t"
        "mov r11d, 1\n\t"
        "add rdi, 8\n\t"
        "jmp .L32_carry_prop\n\t"
    ".L32_carry_done:\n\t"

        "inc ebx\n\t"
        "cmp ebx, 32\n\t"
        "jl .L32_outer\n\t"

        // ══════════════════ 写入结果: r = t[32..63] ══════════════════
        "xor ecx, ecx\n\t"
    ".L32_copy:\n\t"
        "mov rax, [rbp + rcx*8 + 256]\n\t"    // rax = t[K + i]
        "mov [r12 + rcx*8], rax\n\t"
        "inc ecx\n\t"
        "cmp ecx, 32\n\t"
        "jl .L32_copy\n\t"

        // ══════════════════ 条件减法: if (r >= m) r -= m ══════════════════
        // 检查 t[64] (第65个limb) 或 r >= m
        "mov r8, [rbp + 512]\n\t"    // t[2K] = t[64]
        "test r8, r8\n\t"
        "jnz .L32_do_sub1\n\t"

        // 比较 r 和 m (从高位到低位)
        "mov ecx, 31\n\t"
    ".L32_cmp_loop:\n\t"
        "mov rax, [r12 + rcx*8]\n\t"
        "cmp rax, [r15 + rcx*8]\n\t"
        "ja .L32_do_sub1\n\t"
        "jb .L32_done\n\t"
        "dec ecx\n\t"
        "jns .L32_cmp_loop\n\t"
        // 全部相等 → r == m → 减法
        // (实际上 r < m 不应该发生, 但安全起见)
        "jmp .L32_done\n\t"

    ".L32_do_sub1:\n\t"
        "xor r11d, r11d\n\t"        // borrow = 0 (CF=0)
        "mov r9d, 32\n\t"
        "xor ecx, ecx\n\t"
    ".L32_sub_loop:\n\t"
        "mov rax, [r12 + rcx*8]\n\t"
        "sbb rax, [r15 + rcx*8]\n\t"
        "mov [r12 + rcx*8], rax\n\t"
        "inc ecx\n\t"
        "dec r9d\n\t"               // 不修改 CF (cmp 会破坏借位!)
        "jnz .L32_sub_loop\n\t"

        // 二次检查: 如果仍然 r >= m, 再减一次 (处理进位传播)
        "mov r9, [r12 + 31*8]\n\t"
        "cmp r9, [r15 + 31*8]\n\t"
        "jb .L32_done\n\t"
        "xor r11d, r11d\n\t"
        "mov r9d, 32\n\t"
        "xor ecx, ecx\n\t"
    ".L32_sub2_loop:\n\t"
        "mov rax, [r12 + rcx*8]\n\t"
        "sbb rax, [r15 + rcx*8]\n\t"
        "mov [r12 + rcx*8], rax\n\t"
        "inc ecx\n\t"
        "dec r9d\n\t"               // 不修改 CF
        "jnz .L32_sub2_loop\n\t"

    ".L32_done:\n\t"

        // ── 恢复 callee-saved ──
        "pop r15\n\t"
        "pop r14\n\t"
        "pop r13\n\t"
        "pop r12\n\t"
        "pop rbp\n\t"
        "pop rbx\n\t"

        ".att_syntax prefix"
        :
        : [r_out]  "r" (r),
          [a_ptr]  "r" (a),
          [b_ptr]  "r" (b),
          [m_ptr]  "r" (m),
          [mp_val] "m" (mp),
          [t_ptr]  "r" (t)
        : "rax", "rcx", "rdx", "rdi", "rsi",
          "r8", "r9", "r10", "r11", "memory"
    );
}

/**
 * @brief K=64 (4096-bit) CIOS Montgomery 乘法
 *
 * 与 K=32 相同的结构, 外循环 64 次, t 数组 (2*64+2)=130 limbs。
 */
__attribute__((noinline, target("adx,bmi2")))
static void mont_mul_k64_asm(uint64_t* r,
                              const uint64_t* a,
                              const uint64_t* b,
                              const uint64_t* m,
                              uint64_t mp) {
    // t[2K+2] = t[130], 对齐到 64B
    alignas(64) uint64_t t[130];

    __asm__ __volatile__(
        ".intel_syntax noprefix\n\t"

        // ── 保存 callee-saved ──
        "push rbx\n\t"
        "push rbp\n\t"
        "push r12\n\t"
        "push r13\n\t"
        "push r14\n\t"
        "push r15\n\t"

        // ── 加载参数 ──
        "mov r12, %[r_out]\n\t"
        "mov r13, %[a_ptr]\n\t"
        "mov r14, %[b_ptr]\n\t"
        "mov r15, %[m_ptr]\n\t"
        "mov rbp, %[t_ptr]\n\t"

        // ── 清零 t (130 limbs) ──
        "xor eax, eax\n\t"
        "mov ecx, 130\n\t"
        "mov rdi, rbp\n\t"
        "rep stosq\n\t"

        // ── 外循环 i = 0..63 ──
        "xor ebx, ebx\n\t"

    ".L64_outer:\n\t"

        // ══════════════════ Step 1: a[i] * b[0..63] ══════════════════
        "mov rdx, [r13 + rbx*8]\n\t"
        "xor r11d, r11d\n\t"
        "xor ecx, ecx\n\t"
        "lea r8, [rbp + rbx*8]\n\t"  // r8 = &t[i]

    ".L64_s1_loop:\n\t"
        "mulx r10, rax, [r14 + rcx*8]\n\t"
        "add rax, [r8 + rcx*8]\n\t"
        "adc r10, 0\n\t"
        "add rax, r11\n\t"
        "adc r10, 0\n\t"
        "mov [r8 + rcx*8], rax\n\t"
        "mov r11, r10\n\t"
        "inc ecx\n\t"
        "cmp ecx, 64\n\t"
        "jl .L64_s1_loop\n\t"

        // t[i+64] += carry (累加, 不能覆盖), 溢出向高位传播
        "lea rdi, [rbp + rbx*8 + 512]\n\t"
        "add [rdi], r11\n\t"
        "jnc .L64_s2_start\n\t"
        "mov r11d, 1\n\t"
        ".L64_s1_prop:\n\t"
        "add rdi, 8\n\t"
        "add [rdi], r11\n\t"
        "jc .L64_s1_prop\n\t"

    ".L64_s2_start:\n\t"
        // ══════════════════ Step 2: u * m[0..63] ══════════════════
        "mov rax, [rbp + rbx*8]\n\t"
        "mul QWORD PTR %[mp_val]\n\t"
        "mov rdx, rax\n\t"
        "xor r11d, r11d\n\t"
        "xor ecx, ecx\n\t"
        "lea r8, [rbp + rbx*8]\n\t"  // r8 = &t[i]

    ".L64_s2_loop:\n\t"
        "mulx r10, rax, [r15 + rcx*8]\n\t"
        "add rax, [r8 + rcx*8]\n\t"
        "adc r10, 0\n\t"
        "add rax, r11\n\t"
        "adc r10, 0\n\t"
        "mov [r8 + rcx*8], rax\n\t"
        "mov r11, r10\n\t"
        "inc ecx\n\t"
        "cmp ecx, 64\n\t"
        "jl .L64_s2_loop\n\t"

        // 进位传播
        "lea rdi, [rbp + rbx*8 + 512]\n\t"
    ".L64_carry_prop:\n\t"
        "add [rdi], r11\n\t"
        "jnc .L64_carry_done\n\t"
        "mov r11d, 1\n\t"
        "add rdi, 8\n\t"
        "jmp .L64_carry_prop\n\t"
    ".L64_carry_done:\n\t"

        "inc ebx\n\t"
        "cmp ebx, 64\n\t"
        "jl .L64_outer\n\t"

        // ══════════════════ 写入结果: r = t[64..127] ══════════════════
        "xor ecx, ecx\n\t"
    ".L64_copy:\n\t"
        "mov rax, [rbp + rcx*8 + 512]\n\t"
        "mov [r12 + rcx*8], rax\n\t"
        "inc ecx\n\t"
        "cmp ecx, 64\n\t"
        "jl .L64_copy\n\t"

        // ══════════════════ 条件减法 ══════════════════
        "mov r8, [rbp + 1024]\n\t"    // t[2K] = t[128]
        "test r8, r8\n\t"
        "jnz .L64_do_sub1\n\t"

        "mov ecx, 63\n\t"
    ".L64_cmp_loop:\n\t"
        "mov rax, [r12 + rcx*8]\n\t"
        "cmp rax, [r15 + rcx*8]\n\t"
        "ja .L64_do_sub1\n\t"
        "jb .L64_done\n\t"
        "dec ecx\n\t"
        "jns .L64_cmp_loop\n\t"
        "jmp .L64_done\n\t"

    ".L64_do_sub1:\n\t"
        "xor r11d, r11d\n\t"        // borrow = 0 (CF=0)
        "mov r9d, 64\n\t"
        "xor ecx, ecx\n\t"
    ".L64_sub_loop:\n\t"
        "mov rax, [r12 + rcx*8]\n\t"
        "sbb rax, [r15 + rcx*8]\n\t"
        "mov [r12 + rcx*8], rax\n\t"
        "inc ecx\n\t"
        "dec r9d\n\t"               // 不修改 CF (cmp 会破坏借位!)
        "jnz .L64_sub_loop\n\t"

        // 二次检查
        "mov r9, [r12 + 63*8]\n\t"
        "cmp r9, [r15 + 63*8]\n\t"
        "jb .L64_done\n\t"
        "xor r11d, r11d\n\t"
        "mov r9d, 64\n\t"
        "xor ecx, ecx\n\t"
    ".L64_sub2_loop:\n\t"
        "mov rax, [r12 + rcx*8]\n\t"
        "sbb rax, [r15 + rcx*8]\n\t"
        "mov [r12 + rcx*8], rax\n\t"
        "inc ecx\n\t"
        "dec r9d\n\t"               // 不修改 CF
        "jnz .L64_sub2_loop\n\t"

    ".L64_done:\n\t"

        // ── 恢复 callee-saved ──
        "pop r15\n\t"
        "pop r14\n\t"
        "pop r13\n\t"
        "pop r12\n\t"
        "pop rbp\n\t"
        "pop rbx\n\t"

        ".att_syntax prefix"
        :
        : [r_out]  "r" (r),
          [a_ptr]  "r" (a),
          [b_ptr]  "r" (b),
          [m_ptr]  "r" (m),
          [mp_val] "m" (mp),
          [t_ptr]  "r" (t)
        : "rax", "rcx", "rdx", "rdi", "rsi",
          "r8", "r9", "r10", "r11", "memory"
    );
}

/**
 * @brief 半尺寸 CIOS Montgomery 乘法 (CRT 的 p/q 模幂专用)
 *
 * 与 mont_mul_k32/k64_asm 同构, 但只处理前 HK = K/2 个 limb:
 *   - 外循环 HK 次, 内循环 (step1+step2) 各 HK 次 MULX
 *   - t 数组 (2*HK+2) 个 limb, HK<=32 时分配 66 个
 *   - 结果 r[0..HK-1] = t[HK..2HK-1], 高 HK 位清零 (半尺寸语义)
 *   - 条件减法为半尺寸 (HK-limb) 减法, 借位丢弃
 *
 * HK 为运行时参数 (存 r9d): 16 (RSA-2048 的 p/q) 或 32 (RSA-4096 的 p/q)。
 * 循环上界从寄存器读与立即数比较延迟相当, 单实例代码量减半。
 */
__attribute__((noinline, target("adx,bmi2")))
static void mont_mul_half_asm_impl(uint64_t* r,
                                   const uint64_t* a,
                                   const uint64_t* b,
                                   const uint64_t* m,
                                   uint64_t mp,
                                   int HK) {
    // t[2*HK+2] <= t[66] (HK <= 32), 对齐到 64B
    alignas(64) uint64_t t[66];

    __asm__ __volatile__(
        ".intel_syntax noprefix\n\t"

        // ── 保存 callee-saved ──
        "push rbx\n\t"
        "push rbp\n\t"
        "push r12\n\t"
        "push r13\n\t"
        "push r14\n\t"
        "push r15\n\t"

        // ── 加载参数 ──
        "mov r12, %[r_out]\n\t"    // r12 = r
        "mov r13, %[a_ptr]\n\t"    // r13 = a
        "mov r14, %[b_ptr]\n\t"    // r14 = b
        "mov r15, %[m_ptr]\n\t"    // r15 = m
        "mov rbp, %[t_ptr]\n\t"    // rbp = &t[0]
        "mov r9d, %[hk_val]\n\t"   // r9d = HK (外循环/内循环上限)

        // ── 清零 t[0 .. 2*HK+1] ──
        "xor eax, eax\n\t"
        "lea ecx, [r9*2 + 2]\n\t"
        "mov rdi, rbp\n\t"
        "rep stosq\n\t"

        // ── 外循环 i = 0..HK-1 ──
        "xor ebx, ebx\n\t"         // ebx = i

    ".Lh_outer:\n\t"

        // ══════════════════ Step 1: a[i] * b[0..HK-1] ══════════════════
        "mov rdx, [r13 + rbx*8]\n\t"  // rdx = a[i]
        "xor r11d, r11d\n\t"          // r11 = carry
        "xor ecx, ecx\n\t"            // ecx = j
        "lea r8, [rbp + rbx*8]\n\t"   // r8 = &t[i]

    ".Lh_s1_loop:\n\t"
        "mulx r10, rax, [r14 + rcx*8]\n\t"  // r10:rax = a[i]*b[j]
        "add rax, [r8 + rcx*8]\n\t"         // += t[i+j]
        "adc r10, 0\n\t"
        "add rax, r11\n\t"                  // += carry
        "adc r10, 0\n\t"
        "mov [r8 + rcx*8], rax\n\t"         // t[i+j] = lo
        "mov r11, r10\n\t"                  // carry = hi
        "inc ecx\n\t"
        "cmp ecx, r9d\n\t"
        "jl .Lh_s1_loop\n\t"

        // t[i+HK] += carry (累加), 溢出向高位传播
        "lea rdi, [rbp + rbx*8]\n\t"
        "lea rdi, [rdi + r9*8]\n\t"
        "add [rdi], r11\n\t"
        "jnc .Lh_s2_start\n\t"
        "mov r11d, 1\n\t"
    ".Lh_s1_prop:\n\t"
        "add rdi, 8\n\t"
        "add [rdi], r11\n\t"
        "jc .Lh_s1_prop\n\t"

    ".Lh_s2_start:\n\t"
        // ══════════════════ Step 2: u * m[0..HK-1] ══════════════════
        // u = t[i] * mp (只需要低64位)
        "mov rax, [rbp + rbx*8]\n\t"    // rax = t[i]
        "mul QWORD PTR %[mp_val]\n\t"  // rdx:rax = t[i] * mp
        "mov rdx, rax\n\t"             // rdx = u (MULX 隐式操作数)
        "xor r11d, r11d\n\t"           // r11 = carry
        "xor ecx, ecx\n\t"             // ecx = j
        "lea r8, [rbp + rbx*8]\n\t"    // r8 = &t[i]

    ".Lh_s2_loop:\n\t"
        "mulx r10, rax, [r15 + rcx*8]\n\t"  // r10:rax = u*m[j]
        "add rax, [r8 + rcx*8]\n\t"         // += t[i+j]
        "adc r10, 0\n\t"
        "add rax, r11\n\t"                  // += carry
        "adc r10, 0\n\t"
        "mov [r8 + rcx*8], rax\n\t"         // t[i+j] = lo
        "mov r11, r10\n\t"                  // carry = hi
        "inc ecx\n\t"
        "cmp ecx, r9d\n\t"
        "jl .Lh_s2_loop\n\t"

        // ── 进位传播 t[i+HK + k] ──
        "lea rdi, [rbp + rbx*8]\n\t"
        "lea rdi, [rdi + r9*8]\n\t"   // rdi = &t[i+HK]
    ".Lh_carry_prop:\n\t"
        "add [rdi], r11\n\t"
        "jnc .Lh_carry_done\n\t"
        "mov r11d, 1\n\t"
        "add rdi, 8\n\t"
        "jmp .Lh_carry_prop\n\t"
    ".Lh_carry_done:\n\t"

        "inc ebx\n\t"
        "cmp ebx, r9d\n\t"
        "jl .Lh_outer\n\t"

        // ══════════════════ 写入结果: r[0..HK-1] = t[HK..2HK-1] ══════════════════
        "lea rdi, [rbp + r9*8]\n\t"   // rdi = &t[HK]
        "xor ecx, ecx\n\t"
    ".Lh_copy:\n\t"
        "mov rax, [rdi + rcx*8]\n\t"
        "mov [r12 + rcx*8], rax\n\t"
        "inc ecx\n\t"
        "cmp ecx, r9d\n\t"
        "jl .Lh_copy\n\t"

        // 半尺寸输出要求: 高位 r[HK..2HK-1] 清零
        "lea rdi, [r12 + r9*8]\n\t"
        "xor eax, eax\n\t"
        "mov ecx, r9d\n\t"
        "rep stosq\n\t"

        // ══════════════════ 条件减法 (半尺寸, HK-limb) ══════════════════
        // t[2*HK] 非零 → 至少减一次; 否则完整比较 r 与 m (高位优先)
        "lea rdi, [rbp + r9*8]\n\t"
        "mov r8, [rdi + r9*8]\n\t"   // r8 = t[2*HK]
        "test r8, r8\n\t"
        "jnz .Lh_do_sub\n\t"

        "lea ecx, [r9 - 1]\n\t"
    ".Lh_cmp:\n\t"
        "mov rax, [r12 + rcx*8]\n\t"
        "cmp rax, [r15 + rcx*8]\n\t"
        "ja .Lh_do_sub\n\t"
        "jb .Lh_done\n\t"
        "dec ecx\n\t"
        "jns .Lh_cmp\n\t"
        // 全部相等 → r == m → 减一次 (结果为 0)

    ".Lh_do_sub:\n\t"
        "xor r11d, r11d\n\t"        // CF = 0
        "xor ecx, ecx\n\t"
        "mov r10d, r9d\n\t"         // HK 次
    ".Lh_sub_loop:\n\t"
        "mov rax, [r12 + rcx*8]\n\t"
        "sbb rax, [r15 + rcx*8]\n\t"
        "mov [r12 + rcx*8], rax\n\t"
        "inc ecx\n\t"
        "dec r10d\n\t"              // 不修改 CF
        "jnz .Lh_sub_loop\n\t"

        // 二次检查 (CIOS 保证输出 < 2m, 最多再减一次)
        "lea ecx, [r9 - 1]\n\t"
    ".Lh_cmp2:\n\t"
        "mov rax, [r12 + rcx*8]\n\t"
        "cmp rax, [r15 + rcx*8]\n\t"
        "ja .Lh_do_sub2\n\t"
        "jb .Lh_done\n\t"
        "dec ecx\n\t"
        "jns .Lh_cmp2\n\t"
        // 全部相等 → r == m → 再减一次 (结果为 0)

    ".Lh_do_sub2:\n\t"
        "xor r11d, r11d\n\t"
        "xor ecx, ecx\n\t"
        "mov r10d, r9d\n\t"
    ".Lh_sub2_loop:\n\t"
        "mov rax, [r12 + rcx*8]\n\t"
        "sbb rax, [r15 + rcx*8]\n\t"
        "mov [r12 + rcx*8], rax\n\t"
        "inc ecx\n\t"
        "dec r10d\n\t"
        "jnz .Lh_sub2_loop\n\t"

    ".Lh_done:\n\t"

        // ── 恢复 callee-saved ──
        "pop r15\n\t"
        "pop r14\n\t"
        "pop r13\n\t"
        "pop r12\n\t"
        "pop rbp\n\t"
        "pop rbx\n\t"

        ".att_syntax prefix"
        :
        : [r_out]  "r" (r),
          [a_ptr]  "r" (a),
          [b_ptr]  "r" (b),
          [m_ptr]  "r" (m),
          [mp_val] "m" (mp),
          [hk_val] "r" (HK),
          [t_ptr]  "r" (t)
        : "rax", "rcx", "rdx", "rdi", "rsi",
          "r8", "r9", "r10", "r11", "memory"
    );
}

#endif // defined(__GNUC__) && defined(__x86_64__)

// ─────────────────────────────────────────────────────────────────────────
//  MSVC x64: 手写 MASM 汇编 (rsa_mont_asm_win.asm)
//  实测 MSVC 无法把 _addcarryx_u64 优化成 ADCX/ADOX 双链 (降级为
//  add+setb+movzx, 每轮 ~9 条指令), 因此 Windows 走与 Linux 等价的
//  手写汇编路径 (每轮 ~5 条指令, 理论快 ~1.8x)。
// ─────────────────────────────────────────────────────────────────────────

#if defined(_MSC_VER) && defined(_M_X64)
extern "C" void mont_mul_k32_asm(uint64_t* r, const uint64_t* a,
                                 const uint64_t* b, const uint64_t* m,
                                 uint64_t mp);
extern "C" void mont_mul_k64_asm(uint64_t* r, const uint64_t* a,
                                 const uint64_t* b, const uint64_t* m,
                                 uint64_t mp);
// 半尺寸 (CRT p/q 模幂): HK = K/2, 宏生成两个静态实例 (立即数循环上限)
extern "C" void mont_mul_half_k16_asm(uint64_t* r, const uint64_t* a,
                                      const uint64_t* b, const uint64_t* m,
                                      uint64_t mp);
extern "C" void mont_mul_half_k32_asm(uint64_t* r, const uint64_t* a,
                                      const uint64_t* b, const uint64_t* m,
                                      uint64_t mp);
#endif // defined(_MSC_VER) && defined(_M_X64)

// ─────────────────────────────────────────────────────────────────────────
//  公共调度入口
// ─────────────────────────────────────────────────────────────────────────

void mont_mul_asm(uint64_t* r,
                  const uint64_t* a,
                  const uint64_t* b,
                  const uint64_t* m,
                  uint64_t mp,
                  int K) {
#if defined(__GNUC__) && defined(__x86_64__)
    if (K == 32) {
        mont_mul_k32_asm(r, a, b, m, mp);
        return;
    }
    if (K == 64) {
        mont_mul_k64_asm(r, a, b, m, mp);
        return;
    }
#elif defined(_MSC_VER) && defined(_M_X64)
    if (K == 32) {
        mont_mul_k32_asm(r, a, b, m, mp);
        return;
    }
    if (K == 64) {
        mont_mul_k64_asm(r, a, b, m, mp);
        return;
    }
#endif
    // K 值不支持 → 调用方 fallback 到 rsa_body.inc 标量 CIOS
    // (调用方应在调用前检查 mont_mul_asm_available() 和 K 值)
    (void)r; (void)a; (void)b; (void)m; (void)mp; (void)K;
}

// ─────────────────────────────────────────────────────────────────────────
//  Half-size Montgomery multiplication dispatch (CRT p/q modpow)
// ─────────────────────────────────────────────────────────────────────────

void mont_mul_half_asm(uint64_t* r,
                       const uint64_t* a,
                       const uint64_t* b,
                       const uint64_t* m,
                       uint64_t mp,
                       int HK) {
#if defined(__GNUC__) && defined(__x86_64__)
    // dynamic HK single instance (HK in r9d, loop bound from register)
    mont_mul_half_asm_impl(r, a, b, m, mp, HK);
#elif defined(_MSC_VER) && defined(_M_X64)
    if (HK == 16) {
        mont_mul_half_k16_asm(r, a, b, m, mp);
        return;
    }
    if (HK == 32) {
        mont_mul_half_k32_asm(r, a, b, m, mp);
        return;
    }
    (void)r; (void)a; (void)b; (void)m; (void)mp;
#else
    // unsupported platform -> caller falls back to scalar CIOS
    (void)r; (void)a; (void)b; (void)m; (void)mp; (void)HK;
#endif
}

} // namespace jpssl
