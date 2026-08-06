/**
 * sm2_mont_asm.cpp - SM2 256-bit Montgomery multiplication, ADX fast path
 *
 * r = a*b*R^{-1} mod m, R = 2^256, a,b in [0,m), result in [0,m).
 * Same CIOS semantics as the portable path in src/sm2.cpp.
 *
 * - MSVC x64: hand-written MASM (sm2_mont_asm_win.asm), fully unrolled
 *   4-limb CIOS with MULX + ADCX/ADOX dual carry chains.
 * - GCC/Clang x86-64: equivalent inline assembly (target("adx,bmi2")).
 * - The fast path is enabled at runtime by CPUID: BMI2 (MULX, bit 8) and
 *   ADX (ADCX/ADOX, bit 19). Otherwise sm2.cpp keeps its C path.
 */
#include "sm2_mont_asm.hpp"

#include <cstdint>

#if defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h>
// Hand-written MASM (sm2_mont_asm_win.asm), MULX + ADCX/ADOX dual chains.
extern "C" void sm2_mont_mul_adx(uint64_t* r, const uint64_t* a,
                                 const uint64_t* b, const uint64_t* m,
                                 uint64_t mp);
#endif

namespace jpssl {

// ---------------------------------------------------------------------------
// Runtime detection: BMI2 (MULX) + ADX (ADCX/ADOX)
// ---------------------------------------------------------------------------
bool sm2_mont_asm_available() {
    static const bool available = []() -> bool {
#if defined(_MSC_VER) && defined(_M_X64)
        int r[4];
        __cpuidex(r, 7, 0);
        const unsigned ebx = (unsigned)r[1];
        return ((ebx >> 8) & 1u) != 0 && ((ebx >> 19) & 1u) != 0;
#elif defined(__GNUC__) && defined(__x86_64__)
        return __builtin_cpu_supports("bmi2") && __builtin_cpu_supports("adx");
#else
        return false;
#endif
    }();
    return available;
}

// ---------------------------------------------------------------------------
// GCC/Clang x86-64: inline assembly, identical instruction sequence to
// sm2_mont_asm_win.asm (MULX + ADCX/ADOX dual carry chains).
// ---------------------------------------------------------------------------
#if defined(__GNUC__) && defined(__x86_64__)

__attribute__((noinline, target("adx,bmi2")))
static void sm2_mont_mul_impl(uint64_t* r, const uint64_t* a, const uint64_t* b,
                              const uint64_t* m, uint64_t mp) {
    // t[0..8] is the working area; [rsi+80] caches mp (t[9]/t[10] are padding).
    alignas(64) uint64_t t[11];
    __asm__ __volatile__(
        ".intel_syntax noprefix\n\t"

        "lea rsi, %[t_mem]\n\t"
        "xor eax, eax\n\t"
        "mov ecx, 10\n\t"
        "mov rdi, rsi\n\t"
        "rep stosq\n\t"                     // t[0..9] = 0
        "mov rbx, %[a_ptr]\n\t"
        "mov rdi, %[m_ptr]\n\t"
        "mov rcx, %[r_out]\n\t"
        "mov rax, %[mp_val]\n\t"
        "mov QWORD PTR [rsi+80], rax\n\t"   // cache mp
        "xor r15d, r15d\n\t"

        // ========== i = 0: step 1, t[0..4] += a0 * b[0..3] ==========
        "mov rdx, QWORD PTR [rbx]\n\t"
        "mov r8,  QWORD PTR [rsi]\n\t"
        "mov r9,  QWORD PTR [rsi+8]\n\t"
        "mov r10, QWORD PTR [rsi+16]\n\t"
        "mov r11, QWORD PTR [rsi+24]\n\t"
        "mov r12, QWORD PTR [rsi+32]\n\t"
        "xor eax, eax\n\t"
        "mov r14, %[b_ptr]\n\t"
        "mulx r13, rax, QWORD PTR [r14]\n\t"
        "adcx r8, rax\n\t"
        "adox r9, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+8]\n\t"
        "adcx r9, rax\n\t"
        "adox r10, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+16]\n\t"
        "adcx r10, rax\n\t"
        "adox r11, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+24]\n\t"
        "adcx r11, rax\n\t"
        "adox r12, r13\n\t"
        "adcx r12, r15\n\t"
        "mov r14, QWORD PTR [rsi+40]\n\t"
        "mov r13, QWORD PTR [rsi+48]\n\t"
        "adox r14, r15\n\t"
        "adcx r14, r15\n\t"
        "mov rax, QWORD PTR [rsi+56]\n\t"
        "adox r13, r15\n\t"
        "adcx r13, r15\n\t"
        "mov rdx, QWORD PTR [rsi+64]\n\t"
        "adox rax, r15\n\t"
        "adcx rax, r15\n\t"
        "adox rdx, r15\n\t"
        "adcx rdx, r15\n\t"
        "mov QWORD PTR [rsi+40], r14\n\t"
        "mov QWORD PTR [rsi+48], r13\n\t"
        "mov QWORD PTR [rsi+56], rax\n\t"
        "mov QWORD PTR [rsi+64], rdx\n\t"

        // ========== i = 0: step 2, u = t0*mp, t[0..4] += u*m[0..3] ==========
        "mov rax, QWORD PTR [rsi+80]\n\t"
        "imul rax, r8\n\t"
        "mov rdx, rax\n\t"
        "xor eax, eax\n\t"
        "mulx r13, rax, QWORD PTR [rdi]\n\t"
        "adcx r8, rax\n\t"
        "adox r9, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+8]\n\t"
        "adcx r9, rax\n\t"
        "adox r10, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+16]\n\t"
        "adcx r10, rax\n\t"
        "adox r11, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+24]\n\t"
        "adcx r11, rax\n\t"
        "adox r12, r13\n\t"
        "adcx r12, r15\n\t"
        "mov r14, QWORD PTR [rsi+40]\n\t"
        "mov r13, QWORD PTR [rsi+48]\n\t"
        "adox r14, r15\n\t"
        "adcx r14, r15\n\t"
        "mov rax, QWORD PTR [rsi+56]\n\t"
        "adox r13, r15\n\t"
        "adcx r13, r15\n\t"
        "mov rdx, QWORD PTR [rsi+64]\n\t"
        "adox rax, r15\n\t"
        "adcx rax, r15\n\t"
        "adox rdx, r15\n\t"
        "adcx rdx, r15\n\t"
        "mov QWORD PTR [rsi], r8\n\t"
        "mov QWORD PTR [rsi+8], r9\n\t"
        "mov QWORD PTR [rsi+16], r10\n\t"
        "mov QWORD PTR [rsi+24], r11\n\t"
        "mov QWORD PTR [rsi+32], r12\n\t"
        "mov QWORD PTR [rsi+40], r14\n\t"
        "mov QWORD PTR [rsi+48], r13\n\t"
        "mov QWORD PTR [rsi+56], rax\n\t"
        "mov QWORD PTR [rsi+64], rdx\n\t"

        // ========== i = 1: step 1, t[1..5] += a1 * b[0..3] ==========
        "mov rdx, QWORD PTR [rbx+8]\n\t"
        "mov r8,  QWORD PTR [rsi+8]\n\t"
        "mov r9,  QWORD PTR [rsi+16]\n\t"
        "mov r10, QWORD PTR [rsi+24]\n\t"
        "mov r11, QWORD PTR [rsi+32]\n\t"
        "mov r12, QWORD PTR [rsi+40]\n\t"
        "xor eax, eax\n\t"
        "mov r14, %[b_ptr]\n\t"
        "mulx r13, rax, QWORD PTR [r14]\n\t"
        "adcx r8, rax\n\t"
        "adox r9, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+8]\n\t"
        "adcx r9, rax\n\t"
        "adox r10, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+16]\n\t"
        "adcx r10, rax\n\t"
        "adox r11, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+24]\n\t"
        "adcx r11, rax\n\t"
        "adox r12, r13\n\t"
        "adcx r12, r15\n\t"
        "mov r14, QWORD PTR [rsi+48]\n\t"
        "mov r13, QWORD PTR [rsi+56]\n\t"
        "adox r14, r15\n\t"
        "adcx r14, r15\n\t"
        "mov rax, QWORD PTR [rsi+64]\n\t"
        "adox r13, r15\n\t"
        "adcx r13, r15\n\t"
        "adox rax, r15\n\t"
        "adcx rax, r15\n\t"
        "mov QWORD PTR [rsi+48], r14\n\t"
        "mov QWORD PTR [rsi+56], r13\n\t"
        "mov QWORD PTR [rsi+64], rax\n\t"

        // ========== i = 1: step 2, u = t1*mp, t[1..5] += u*m[0..3] ==========
        "mov rax, QWORD PTR [rsi+80]\n\t"
        "imul rax, r8\n\t"
        "mov rdx, rax\n\t"
        "xor eax, eax\n\t"
        "mulx r13, rax, QWORD PTR [rdi]\n\t"
        "adcx r8, rax\n\t"
        "adox r9, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+8]\n\t"
        "adcx r9, rax\n\t"
        "adox r10, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+16]\n\t"
        "adcx r10, rax\n\t"
        "adox r11, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+24]\n\t"
        "adcx r11, rax\n\t"
        "adox r12, r13\n\t"
        "adcx r12, r15\n\t"
        "mov r14, QWORD PTR [rsi+48]\n\t"
        "mov r13, QWORD PTR [rsi+56]\n\t"
        "adox r14, r15\n\t"
        "adcx r14, r15\n\t"
        "mov rax, QWORD PTR [rsi+64]\n\t"
        "adox r13, r15\n\t"
        "adcx r13, r15\n\t"
        "adox rax, r15\n\t"
        "adcx rax, r15\n\t"
        "mov QWORD PTR [rsi+8], r8\n\t"
        "mov QWORD PTR [rsi+16], r9\n\t"
        "mov QWORD PTR [rsi+24], r10\n\t"
        "mov QWORD PTR [rsi+32], r11\n\t"
        "mov QWORD PTR [rsi+40], r12\n\t"
        "mov QWORD PTR [rsi+48], r14\n\t"
        "mov QWORD PTR [rsi+56], r13\n\t"
        "mov QWORD PTR [rsi+64], rax\n\t"

        // ========== i = 2: step 1, t[2..6] += a2 * b[0..3] ==========
        "mov rdx, QWORD PTR [rbx+16]\n\t"
        "mov r8,  QWORD PTR [rsi+16]\n\t"
        "mov r9,  QWORD PTR [rsi+24]\n\t"
        "mov r10, QWORD PTR [rsi+32]\n\t"
        "mov r11, QWORD PTR [rsi+40]\n\t"
        "mov r12, QWORD PTR [rsi+48]\n\t"
        "xor eax, eax\n\t"
        "mov r14, %[b_ptr]\n\t"
        "mulx r13, rax, QWORD PTR [r14]\n\t"
        "adcx r8, rax\n\t"
        "adox r9, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+8]\n\t"
        "adcx r9, rax\n\t"
        "adox r10, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+16]\n\t"
        "adcx r10, rax\n\t"
        "adox r11, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+24]\n\t"
        "adcx r11, rax\n\t"
        "adox r12, r13\n\t"
        "adcx r12, r15\n\t"
        "mov r14, QWORD PTR [rsi+56]\n\t"
        "mov r13, QWORD PTR [rsi+64]\n\t"
        "adox r14, r15\n\t"
        "adcx r14, r15\n\t"
        "adox r13, r15\n\t"
        "adcx r13, r15\n\t"
        "mov QWORD PTR [rsi+56], r14\n\t"
        "mov QWORD PTR [rsi+64], r13\n\t"

        // ========== i = 2: step 2, u = t2*mp, t[2..6] += u*m[0..3] ==========
        "mov rax, QWORD PTR [rsi+80]\n\t"
        "imul rax, r8\n\t"
        "mov rdx, rax\n\t"
        "xor eax, eax\n\t"
        "mulx r13, rax, QWORD PTR [rdi]\n\t"
        "adcx r8, rax\n\t"
        "adox r9, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+8]\n\t"
        "adcx r9, rax\n\t"
        "adox r10, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+16]\n\t"
        "adcx r10, rax\n\t"
        "adox r11, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+24]\n\t"
        "adcx r11, rax\n\t"
        "adox r12, r13\n\t"
        "adcx r12, r15\n\t"
        "mov r14, QWORD PTR [rsi+56]\n\t"
        "mov r13, QWORD PTR [rsi+64]\n\t"
        "adox r14, r15\n\t"
        "adcx r14, r15\n\t"
        "adox r13, r15\n\t"
        "adcx r13, r15\n\t"
        "mov QWORD PTR [rsi+16], r8\n\t"
        "mov QWORD PTR [rsi+24], r9\n\t"
        "mov QWORD PTR [rsi+32], r10\n\t"
        "mov QWORD PTR [rsi+40], r11\n\t"
        "mov QWORD PTR [rsi+48], r12\n\t"
        "mov QWORD PTR [rsi+56], r14\n\t"
        "mov QWORD PTR [rsi+64], r13\n\t"

        // ========== i = 3: step 1, t[3..7] += a3 * b[0..3] ==========
        "mov rdx, QWORD PTR [rbx+24]\n\t"
        "mov r8,  QWORD PTR [rsi+24]\n\t"
        "mov r9,  QWORD PTR [rsi+32]\n\t"
        "mov r10, QWORD PTR [rsi+40]\n\t"
        "mov r11, QWORD PTR [rsi+48]\n\t"
        "mov r12, QWORD PTR [rsi+56]\n\t"
        "xor eax, eax\n\t"
        "mov r14, %[b_ptr]\n\t"
        "mulx r13, rax, QWORD PTR [r14]\n\t"
        "adcx r8, rax\n\t"
        "adox r9, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+8]\n\t"
        "adcx r9, rax\n\t"
        "adox r10, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+16]\n\t"
        "adcx r10, rax\n\t"
        "adox r11, r13\n\t"
        "mulx r13, rax, QWORD PTR [r14+24]\n\t"
        "adcx r11, rax\n\t"
        "adox r12, r13\n\t"
        "adcx r12, r15\n\t"
        "mov r14, QWORD PTR [rsi+64]\n\t"
        "adox r14, r15\n\t"
        "adcx r14, r15\n\t"
        "mov QWORD PTR [rsi+64], r14\n\t"

        // ========== i = 3: step 2, u = t3*mp, t[3..7] += u*m[0..3] ==========
        "mov rax, QWORD PTR [rsi+80]\n\t"
        "imul rax, r8\n\t"
        "mov rdx, rax\n\t"
        "xor eax, eax\n\t"
        "mulx r13, rax, QWORD PTR [rdi]\n\t"
        "adcx r8, rax\n\t"
        "adox r9, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+8]\n\t"
        "adcx r9, rax\n\t"
        "adox r10, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+16]\n\t"
        "adcx r10, rax\n\t"
        "adox r11, r13\n\t"
        "mulx r13, rax, QWORD PTR [rdi+24]\n\t"
        "adcx r11, rax\n\t"
        "adox r12, r13\n\t"
        "adcx r12, r15\n\t"
        "mov r14, QWORD PTR [rsi+64]\n\t"
        "adox r14, r15\n\t"
        "adcx r14, r15\n\t"
        "mov QWORD PTR [rsi+24], r8\n\t"
        "mov QWORD PTR [rsi+32], r9\n\t"
        "mov QWORD PTR [rsi+40], r10\n\t"
        "mov QWORD PTR [rsi+48], r11\n\t"
        "mov QWORD PTR [rsi+56], r12\n\t"
        "mov QWORD PTR [rsi+64], r14\n\t"

        // ========== result = t[4..7]; conditional subtract if t[8] or r >= m ==========
        "mov r8,  QWORD PTR [rsi+32]\n\t"
        "mov r9,  QWORD PTR [rsi+40]\n\t"
        "mov r10, QWORD PTR [rsi+48]\n\t"
        "mov r11, QWORD PTR [rsi+56]\n\t"
        "mov rax, QWORD PTR [rsi+64]\n\t"
        "test rax, rax\n\t"
        "jnz .Lsm2_sub\n\t"
        "cmp r11, QWORD PTR [rdi+24]\n\t"
        "ja .Lsm2_sub\n\t"
        "jb .Lsm2_done\n\t"
        "cmp r10, QWORD PTR [rdi+16]\n\t"
        "ja .Lsm2_sub\n\t"
        "jb .Lsm2_done\n\t"
        "cmp r9, QWORD PTR [rdi+8]\n\t"
        "ja .Lsm2_sub\n\t"
        "jb .Lsm2_done\n\t"
        "cmp r8, QWORD PTR [rdi]\n\t"
        "jb .Lsm2_done\n\t"
        ".Lsm2_sub:\n\t"
        "xor eax, eax\n\t"
        "sbb r8, QWORD PTR [rdi]\n\t"
        "sbb r9, QWORD PTR [rdi+8]\n\t"
        "sbb r10, QWORD PTR [rdi+16]\n\t"
        "sbb r11, QWORD PTR [rdi+24]\n\t"
        ".Lsm2_done:\n\t"
        "mov QWORD PTR [rcx], r8\n\t"
        "mov QWORD PTR [rcx+8], r9\n\t"
        "mov QWORD PTR [rcx+16], r10\n\t"
        "mov QWORD PTR [rcx+24], r11\n\t"
        :
        : [r_out] "m" (r), [a_ptr] "m" (a), [b_ptr] "m" (b),
          [m_ptr] "m" (m), [mp_val] "m" (mp), [t_mem] "m" (t)
        : "rax", "rcx", "rdx", "rbx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "memory");
}

#endif // defined(__GNUC__) && defined(__x86_64__)

// ---------------------------------------------------------------------------
// Public dispatch
// ---------------------------------------------------------------------------

void sm2_mont_mul(uint64_t* r, const uint64_t* a, const uint64_t* b,
                  const uint64_t* m, uint64_t mp) {
    if (!sm2_mont_asm_available()) {
        // Caller falls back to the portable C path in sm2.cpp.
        return;
    }
#if defined(_MSC_VER) && defined(_M_X64)
    sm2_mont_mul_adx(r, a, b, m, mp);
#elif defined(__GNUC__) && defined(__x86_64__)
    sm2_mont_mul_impl(r, a, b, m, mp);
#endif
}

void sm2_mont_sqr(uint64_t* r, const uint64_t* a, const uint64_t* m,
                  uint64_t mp) {
    // Squaring currently shares the multiplication path (b = a). A dedicated
    // 10-MULX symmetric squaring can be added later.
    sm2_mont_mul(r, a, a, m, mp);
}

} // namespace jpssl
