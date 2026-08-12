/* ecdsa_p256_adx.S — Linux x86-64 (GNU as) P-256 ADX 快速路径
 *
 * 从 src/ecdsa_p256_adx.asm（Windows x64 MASM 版）移植，供 GCC/Clang 平台使用。
 * 依赖 CPU 特性：BMI2 (MULX/SHLX/SHRX) + ADX (ADCX/ADOX)，调用方须先用
 * cpu_has_adx() 检测（Haswell 及以后 ADX 与 BMI2 同时存在）。
 *
 * ABI：System V x86-64（参数顺序 rdi, rsi, rdx, rcx, r8, r9），与 Windows
 * 版（rcx, rdx, r8, r9）不同。
 *
 * 域运算均为 Montgomery 形式：r = a*b*R^{-1} mod m, R = 2^256。
 *   jpssl_p256_mul_adx      mod p（CIOS + nistz256 特殊归约）
 *   jpssl_p256_sqr_adx      mod p（对称平方 + 特殊归约）
 *   jpssl_p256_ord_mul_adx  mod n（CIOS + 通用归约, K0 = -n^{-1} mod 2^64）
 *   jpssl_p256_neg          mod p 取负（常数时间）
 *
 * p  = ffffffff00000001000000000000000000000000ffffffffffffffffffffffff
 * n  = ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
 */

#if defined(__x86_64__)

.intel_syntax noprefix

.section .rodata
.p2align 3
.Lord:
    .quad 0xf3b9cac2fc632551        /* n[0] */
    .quad 0xbce6faada7179e84        /* n[1] */
    .quad 0xffffffffffffffff        /* n[2] */
    .quad 0xffffffff00000000        /* n[3] */
.LordK:
    .quad 0xccd1c8aaee00bc4f        /* K0 = -n^{-1} mod 2^64 */
.Lpoly:
    .quad 0xffffffffffffffff        /* p[0] */
    .quad 0x00000000ffffffff        /* p[1] */
    .quad 0x0000000000000000        /* p[2] */
    .quad 0xffffffff00000001        /* p[3] */
.p2align 4                    /* pand 要求 16 字节对齐 */
.LONE_mont:
    .quad 0x0000000000000001        /* 1 的 Montgomery 表示（mod p） */
    .quad 0xffffffff00000000
    .quad 0xffffffffffffffff
    .quad 0x00000000fffffffe

.text

/* ─────────────────────────────────────────────────────────────
 * jpssl_p256_mul_adx(r[4], a[4], b[4])
 *   r = a*b*R^-1 mod p；a, b < p；结果 < p。
 * 5 轮 CIOS（第 5 轮只做归约）+ 分支无关的条件减 p。
 * ───────────────────────────────────────────────────────────── */
.p2align 5
.globl jpssl_p256_mul_adx
.type   jpssl_p256_mul_adx, @function
jpssl_p256_mul_adx:
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi

    /* SysV: rdi = r, rsi = a, rdx = b */
    mov     rbx, rdx                    /* b_ptr = b */

    /* ---- 载入 a[0..3] -> acc1..acc4 ---- */
    mov     r9,  QWORD PTR [rsi]        /* acc1 = a[0] */
    mov     r10, QWORD PTR [rsi+8]      /* acc2 = a[1] */
    mov     r11, QWORD PTR [rsi+16]     /* acc3 = a[2] */
    mov     r12, QWORD PTR [rsi+24]     /* acc4 = a[3] */

    /* ---- Multiply by b[0] ---- */
    mov     rdx, QWORD PTR [rbx]        /* rdx = b[0] */
    mulx    r9, r8, r9                  /* b0*a0: hi=acc1, lo=acc0 */
    mulx    r10, rcx, r10               /* b0*a1: hi=acc2, lo=t0 */
    mov     r14, 32                     /* poly1 = 移位计数 32 */
    xor     r13, r13
    mulx    r11, rbp, r11               /* b0*a2: hi=acc3, lo=t1 */
    mov     r15, 0xffffffff00000001     /* poly3 */
    adc     r9, rcx                     /* acc1 += t0 */
    mulx    r12, rcx, r12               /* b0*a3: hi=acc4, lo=t0 */
    mov     rdx, r8                     /* rdx = acc0 */
    adc     r10, rbp                    /* acc2 += t1 */
    shlx    rbp, r8, r14                /* t1 = acc0 << 32 */
    adc     r11, rcx                    /* acc3 += t0 */
    shrx    rcx, r8, r14                /* t0 = acc0 >> 32 */
    adc     r12, 0                      /* acc4 += carry */

    /* ---- First reduction step ---- */
    add     r9, rbp                     /* acc1 += acc0<<32 */
    adc     r10, rcx                    /* acc2 += acc0>>32 */
    mulx    rbp, rcx, r15               /* acc0 * poly3: hi=t1, lo=t0 */
    mov     rdx, QWORD PTR [rbx+8]      /* rdx = b[1] */
    adc     r11, rcx                    /* acc3 += t0 */
    adc     r12, rbp                    /* acc4 += t1 */
    adc     r13, 0                      /* acc5 += carry */
    xor     r8, r8                      /* acc0 = 0（清 CF=0, OF=0） */

    /* ---- Multiply by b[1] ---- */
    mulx    rbp, rcx, QWORD PTR [rsi]   /* b1*a0: hi=t1, lo=t0 */
    adcx    r9, rcx                     /* acc1 += t0 */
    adox    r10, rbp                    /* acc2 += t1 */
    mulx    rbp, rcx, QWORD PTR [rsi+8] /* b1*a1 */
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+16]/* b1*a2 */
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+24]/* b1*a3 */
    mov     rdx, r9                     /* rdx = acc1 */
    adcx    r12, rcx
    shlx    rcx, r9, r14                /* t0 = acc1 << 32 */
    adox    r13, rbp
    shrx    rbp, r9, r14                /* t1 = acc1 >> 32 */
    adcx    r13, r8                     /* acc5 += acc0 */
    adox    r8, r8
    adc     r8, 0                       /* acc0 = 进位 */

    /* ---- Second reduction step ---- */
    add     r10, rcx                    /* acc2 += acc1<<32 */
    adc     r11, rbp                    /* acc3 += acc1>>32 */
    mulx    rbp, rcx, r15               /* acc1 * poly3: hi=t1, lo=t0 */
    mov     rdx, QWORD PTR [rbx+16]     /* rdx = b[2] */
    adc     r12, rcx                    /* acc4 += t0 */
    adc     r13, rbp                    /* acc5 += t1 */
    adc     r8, 0                       /* acc0 += carry */
    xor     r9, r9                      /* acc1 = 0（清 CF=0, OF=0） */

    /* ---- Multiply by b[2] ---- */
    mulx    rbp, rcx, QWORD PTR [rsi]   /* b2*a0 */
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+8] /* b2*a1 */
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+16]/* b2*a2 */
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+24]/* b2*a3 */
    mov     rdx, r10                    /* rdx = acc2 */
    adcx    r13, rcx
    shlx    rcx, r10, r14               /* t0 = acc2 << 32 */
    adox    r8, rbp                     /* acc0 += t1 */
    shrx    rbp, r10, r14               /* t1 = acc2 >> 32 */
    adcx    r8, r9                      /* acc0 += acc1 */
    adox    r9, r9
    adc     r9, 0                       /* acc1 = 进位 */

    /* ---- Third reduction step ---- */
    add     r11, rcx                    /* acc3 += acc2<<32 */
    adc     r12, rbp                    /* acc4 += acc2>>32 */
    mulx    rbp, rcx, r15               /* acc2 * poly3: hi=t1, lo=t0 */
    mov     rdx, QWORD PTR [rbx+24]     /* rdx = b[3] */
    adc     r13, rcx                    /* acc5 += t0 */
    adc     r8, rbp                     /* acc0 += t1 */
    adc     r9, 0                       /* acc1 += carry */
    xor     r10, r10                    /* acc2 = 0（清 CF=0, OF=0） */

    /* ---- Multiply by b[3] ---- */
    mulx    rbp, rcx, QWORD PTR [rsi]   /* b3*a0 */
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+8] /* b3*a1 */
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+16]/* b3*a2 */
    adcx    r13, rcx
    adox    r8, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+24]/* b3*a3 */
    mov     rdx, r11                    /* rdx = acc3 */
    adcx    r8, rcx
    shlx    rcx, r11, r14               /* t0 = acc3 << 32 */
    adox    r9, rbp                     /* acc1 += t1 */
    shrx    rbp, r11, r14               /* t1 = acc3 >> 32 */
    adcx    r9, r10                     /* acc1 += acc2 */
    adox    r10, r10
    adc     r10, 0                      /* acc2 = 进位 */

    /* ---- Fourth reduction step ---- */
    add     r12, rcx                    /* acc4 += acc3<<32 */
    adc     r13, rbp                    /* acc5 += acc3>>32 */
    mulx    rbp, rcx, r15               /* acc3 * poly3: hi=t1, lo=t0 */
    mov     rbx, r12                    /* t2 = acc4（保存） */
    mov     r14, 0xffffffff             /* poly1 = p 字 1 */
    adc     r8, rcx                     /* acc0 += t0 */
    mov     rdx, r13                    /* t3 = acc5（保存） */
    adc     r9, rbp                     /* acc1 += t1 */
    adc     r10, 0                      /* acc2 += carry */

    /* ---- 分支无关条件减 p ---- */
    xor     eax, eax                    /* CF=0 */
    mov     rcx, r8                     /* t0 = acc0（保存） */
    sbb     r12, -1                     /* acc4 -= poly[0] (=-1) */
    sbb     r13, r14                    /* acc5 -= poly1 */
    sbb     r8, 0
    mov     rbp, r9                     /* t1 = acc1（保存） */
    sbb     r9, r15                     /* acc1 -= poly3 */
    sbb     r10, 0                      /* acc2 -= 0 */

    cmovc   r12, rbx                    /* 有借位则恢复 acc4 */
    cmovc   r13, rdx                    /* 恢复 acc5 */
    mov     QWORD PTR [rdi], r12
    cmovc   r8, rcx                     /* 恢复 acc0 */
    mov     QWORD PTR [rdi+8], r13
    cmovc   r9, rbp                     /* 恢复 acc1 */
    mov     QWORD PTR [rdi+16], r8
    mov     QWORD PTR [rdi+24], r9

    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
.size jpssl_p256_mul_adx, .-jpssl_p256_mul_adx

/* ─────────────────────────────────────────────────────────────
 * jpssl_p256_sqr_adx(r[4], a[4])
 *   r = a*a*R^-1 mod p；a < p；结果 < p。
 * 对称平方（交叉积×2 + 平方项）+ 4 轮 nistz256 特殊归约。
 * ───────────────────────────────────────────────────────────── */
.p2align 5
.globl jpssl_p256_sqr_adx
.type   jpssl_p256_sqr_adx, @function
jpssl_p256_sqr_adx:
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi

    /* SysV: rdi = r, rsi = a */
    mov     rdx, QWORD PTR [rsi]        /* rdx = a[0] */
    mov     r14, QWORD PTR [rsi+8]      /* acc6 = a[1] */
    mov     r15, QWORD PTR [rsi+16]     /* acc7 = a[2] */
    mov     r8,  QWORD PTR [rsi+24]     /* acc0 = a[3] */

    /* ---- cross products ---- */
    mulx    r10, r9,  r14               /* a0*a1: hi=acc2, lo=acc1 */
    mulx    r11, rcx, r15               /* a0*a2: hi=acc3, lo=t0 */
    xor     eax, eax
    adc     r10, rcx                    /* acc2 += t0 */
    mulx    r12, rbp, r8                /* a0*a3: hi=acc4, lo=t1 */
    mov     rdx, r14                    /* rdx = a1 */
    adc     r11, rbp                    /* acc3 += t1 */
    adc     r12, 0                      /* acc4 += carry */
    xor     r13, r13                    /* acc5 = 0（cf=of=0） */

    mulx    rbp, rcx, r15               /* a1*a2: hi=t1, lo=t0 */
    adcx    r11, rcx                    /* acc3 += t0 */
    adox    r12, rbp                    /* acc4 += t1 */

    mulx    rbp, rcx, r8                /* a1*a3: hi=t1, lo=t0 */
    mov     rdx, r15                    /* rdx = a2 */
    adcx    r12, rcx                    /* acc4 += t0 */
    adox    r13, rbp                    /* acc5 += t1 */
    adc     r13, 0                      /* acc5 += carry */

    mulx    r14, rcx, r8                /* a2*a3: hi=acc6, lo=t0 */
    mov     rdx, QWORD PTR [rsi]        /* rdx = a0 */
    xor     r15, r15                    /* acc7 = 0（cf=of=0） */
    adcx    r9,  r9                     /* acc1 <<= 1 */
    adox    r13, rcx                    /* acc5 += t0 */
    adcx    r10, r10                    /* acc2 <<= 1 */
    adox    r14, r15                    /* acc6 += 0（of=0） */

    /* ---- squares ---- */
    mulx    rbp, r8,  QWORD PTR [rsi]   /* a0*a0: hi=t1, lo=acc0 */
    mov     rdx, QWORD PTR [rsi+8]      /* rdx = a1 */
    adcx    r11, r11                    /* acc3 <<= 1 */
    adox    r9,  rbp                    /* acc1 += a0^2.hi */
    adcx    r12, r12                    /* acc4 <<= 1 */
    mulx    rax, rcx, QWORD PTR [rsi+8] /* a1*a1: hi=t4, lo=t0 */
    mov     rdx, QWORD PTR [rsi+16]     /* rdx = a2 */
    adcx    r13, r13                    /* acc5 <<= 1 */
    adox    r10, rcx                    /* acc2 += a1^2.lo */
    adcx    r14, r14                    /* acc6 <<= 1 */
    mulx    rbp, rcx, QWORD PTR [rsi+16]/* a2*a2: hi=t1, lo=t0 */
    mov     rdx, QWORD PTR [rsi+24]     /* rdx = a3 */
    adox    r11, rax                    /* acc3 += a1^2.hi */
    adcx    r15, r15                    /* acc7 <<= 1 */
    adox    r12, rcx                    /* acc4 += a2^2.lo */
    mov     rbx, rdx                    /* t2 = a3（供平方使用） */
    mov     rsi, 32                     /* shift count（a_ptr 已用完） */
    adox    r13, rbp                    /* acc5 += a2^2.hi */
    mulx    rax, rcx, rbx               /* a3*a3: hi=t4, lo=t0 */
    mov     rdx, 0xffffffff00000001     /* rdx = poly3 */
    adox    r14, rcx                    /* acc6 += a3^2.lo */
    shlx    rcx, r8, rsi                /* t0 = acc0 << 32 */
    adox    r15, rax                    /* acc7 += a3^2.hi */
    shrx    rax, r8, rsi                /* t4 = acc0 >> 32 */
    mov     rbp, rdx                    /* t1 = poly3 */

    /* ---- Montgomery reduction (4 steps) ---- */
    add     r9,  rcx                    /* acc1 += acc0<<32 */
    adc     r10, rax                    /* acc2 += acc0>>32 */
    mulx    r8,  rcx, r8                /* poly3*acc0: hi=acc0, lo=t0 */
    adc     r11, rcx                    /* acc3 += t0 */
    shlx    rcx, r9, rsi                /* t0 = acc1 << 32 */
    adc     r8,  0                      /* acc0 += carry */
    shrx    rax, r9, rsi                /* t4 = acc1 >> 32 */

    add     r10, rcx                    /* acc2 += acc1<<32 */
    adc     r11, rax                    /* acc3 += acc1>>32 */
    mulx    r9,  rcx, r9                /* poly3*acc1: hi=acc1, lo=t0 */
    adc     r8,  rcx                    /* acc0 += t0 */
    shlx    rcx, r10, rsi               /* t0 = acc2 << 32 */
    adc     r9,  0                      /* acc1 += carry */
    shrx    rax, r10, rsi               /* t4 = acc2 >> 32 */

    add     r11, rcx                    /* acc3 += acc2<<32 */
    adc     r8,  rax                    /* acc0 += acc2>>32 */
    mulx    r10, rcx, r10               /* poly3*acc2: hi=acc2, lo=t0 */
    adc     r9,  rcx                    /* acc1 += t0 */
    shlx    rcx, r11, rsi               /* t0 = acc3 << 32 */
    adc     r10, 0                      /* acc2 += carry */
    shrx    rax, r11, rsi               /* t4 = acc3 >> 32 */

    add     r8,  rcx                    /* acc0 += acc3<<32 */
    adc     r9,  rax                    /* acc1 += acc3>>32 */
    mulx    r11, rcx, r11               /* poly3*acc3: hi=acc3, lo=t0 */
    adc     r10, rcx                    /* acc2 += t0 */
    adc     r11, 0                      /* acc3 += carry */

    /* ---- fold upper half + 分支无关条件减 p ---- */
    xor     rdx, rdx                    /* t3 = 0 */
    add     r12, r8                     /* acc4 += acc0 */
    mov     rsi, 0xffffffff             /* a_ptr = poly1 */
    adc     r13, r9                     /* acc5 += acc1 */
    mov     r8,  r12                    /* acc0 = acc4 */
    adc     r14, r10                    /* acc6 += acc2 */
    adc     r15, r11                    /* acc7 += acc3 */
    mov     r9,  r13                    /* acc1 = acc5 */
    adc     rdx, 0                      /* t3 += carry */

    sub     r12, -1                     /* acc4 -= poly[0] */
    mov     r10, r14                    /* acc2 = acc6 */
    sbb     r13, rsi                    /* acc5 -= poly1 */
    sbb     r14, 0                      /* acc6 -= 0 */
    mov     r11, r15                    /* acc3 = acc7 */
    sbb     r15, rbp                    /* acc7 -= poly3 */
    sbb     rdx, 0                      /* t3 -= 0 */

    cmovc   r12, r8                     /* 有借位则恢复 acc4 */
    cmovc   r13, r9                     /* 恢复 acc5 */
    mov     QWORD PTR [rdi], r12
    cmovc   r14, r10                    /* 恢复 acc6 */
    mov     QWORD PTR [rdi+8], r13
    cmovc   r15, r11                    /* 恢复 acc7 */
    mov     QWORD PTR [rdi+16], r14
    mov     QWORD PTR [rdi+24], r15

    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
.size jpssl_p256_sqr_adx, .-jpssl_p256_sqr_adx

/* ─────────────────────────────────────────────────────────────
 * jpssl_p256_ord_mul_adx(r[4], a[4], b[4])
 *   r = a*b*R^-1 mod n；a, b < n；结果 < n。
 * CIOS，u = acc_i * K0 (K0 = -n^{-1} mod 2^64 = 0xccd1c8aaee00bc4f)。
 * ───────────────────────────────────────────────────────────── */
.p2align 5
.globl jpssl_p256_ord_mul_adx
.type   jpssl_p256_ord_mul_adx, @function
jpssl_p256_ord_mul_adx:
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi

    /* SysV: rdi = r, rsi = a, rdx = b */
    mov     rbx, rdx                    /* b_ptr = b */
    lea     r14, [rip + .Lord]
    mov     r15, 0xccd1c8aaee00bc4f     /* r15 = LordK */

    mov     r9,  QWORD PTR [rsi]        /* acc1 = a[0] */
    mov     r10, QWORD PTR [rsi+8]      /* acc2 = a[1] */
    mov     r11, QWORD PTR [rsi+16]     /* acc3 = a[2] */
    mov     r12, QWORD PTR [rsi+24]     /* acc4 = a[3] */

    /* ---- Multiply by b[0] ---- */
    mov     rdx, QWORD PTR [rbx]        /* rdx = b[0] */
    mulx    r9, r8, r9                  /* b0*a0: hi=acc1, lo=acc0 */
    mulx    r10, rcx, r10               /* b0*a1: hi=acc2, lo=t0 */
    mulx    r11, rbp, r11               /* b0*a2: hi=acc3, lo=t1 */
    add     r9, rcx                     /* acc1 += t0 */
    mulx    r12, rcx, r12               /* b0*a3: hi=acc4, lo=t0 */
    mov     rdx, r8                     /* rdx = acc0 */
    mulx    rax, rdx, r15               /* u = acc0*K0（lo=rdx） */
    adc     r10, rbp                    /* acc2 += t1 */
    adc     r11, rcx                    /* acc3 += t0 */
    adc     r12, 0                      /* acc4 += carry */

    /* ---- reduction ---- */
    xor     r13, r13                    /* acc5 = 0（cf=0, of=0） */
    mulx    rbp, rcx, QWORD PTR [r14]   /* u*n0: hi=t1, lo=t0 */
    adcx    r8, rcx
    adox    r9, rbp                     /* acc1 += hi */
    mulx    rbp, rcx, QWORD PTR [r14+8] /* u*n1 */
    adcx    r9, rcx
    adox    r10, rbp
    mulx    rbp, rcx, QWORD PTR [r14+16]/* u*n2 */
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, QWORD PTR [r14+24]/* u*n3 */
    mov     rdx, QWORD PTR [rbx+8]      /* rdx = b[1] */
    adcx    r11, rcx
    adox    r12, rbp
    adcx    r12, r8                     /* acc4 += acc0 */
    adox    r13, r8                     /* acc5 += acc0 */
    adc     r13, 0                      /* acc5 += carry（cf=0, of=0） */

    /* ---- Multiply by b[1] ---- */
    mulx    rbp, rcx, QWORD PTR [rsi]   /* b1*a0 */
    adcx    r9, rcx
    adox    r10, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+8] /* b1*a1 */
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+16]/* b1*a2 */
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+24]/* b1*a3 */
    mov     rdx, r9                     /* rdx = acc1 */
    mulx    rax, rdx, r15               /* u = acc1*K0 */
    adcx    r12, rcx
    adox    r13, rbp
    adcx    r13, r8                     /* acc5 += acc0 */
    adox    r8, r8
    adc     r8, 0                       /* acc0 = 进位（cf=0, of=0） */

    /* ---- reduction ---- */
    mulx    rbp, rcx, QWORD PTR [r14]   /* u*n0 */
    adcx    r9, rcx
    adox    r10, rbp
    mulx    rbp, rcx, QWORD PTR [r14+8]
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, QWORD PTR [r14+16]
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, QWORD PTR [r14+24]
    mov     rdx, QWORD PTR [rbx+16]     /* rdx = b[2] */
    adcx    r12, rcx
    adox    r13, rbp
    adcx    r13, r9                     /* acc5 += acc1 */
    adox    r8, r9
    adc     r8, 0                       /* acc0 = 进位 */

    /* ---- Multiply by b[2] ---- */
    mulx    rbp, rcx, QWORD PTR [rsi]
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+8]
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+16]
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+24]
    mov     rdx, r10                    /* rdx = acc2 */
    mulx    rax, rdx, r15               /* u = acc2*K0 */
    adcx    r13, rcx
    adox    r8, rbp                     /* acc0 += hi */
    adcx    r8, r9                      /* acc0 += acc1 */
    adox    r9, r9
    adc     r9, 0                       /* acc1 = 进位 */

    /* ---- reduction ---- */
    mulx    rbp, rcx, QWORD PTR [r14]
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, QWORD PTR [r14+8]
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, QWORD PTR [r14+16]
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, QWORD PTR [r14+24]
    mov     rdx, QWORD PTR [rbx+24]     /* rdx = b[3] */
    adcx    r13, rcx
    adox    r8, rbp
    adcx    r8, r10                     /* acc0 += acc2 */
    adox    r9, r10
    adc     r9, 0                       /* acc1 = 进位 */

    /* ---- Multiply by b[3] ---- */
    mulx    rbp, rcx, QWORD PTR [rsi]
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+8]
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+16]
    adcx    r13, rcx
    adox    r8, rbp
    mulx    rbp, rcx, QWORD PTR [rsi+24]
    mov     rdx, r11                    /* rdx = acc3 */
    mulx    rax, rdx, r15               /* u = acc3*K0 */
    adcx    r8, rcx
    adox    r9, rbp
    adcx    r9, r10                     /* acc1 += acc2 */
    adox    r10, r10
    adc     r10, 0                      /* acc2 = 进位 */

    /* ---- reduction ---- */
    mulx    rbp, rcx, QWORD PTR [r14]
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, QWORD PTR [r14+8]
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, QWORD PTR [r14+16]
    adcx    r13, rcx
    adox    r8, rbp
    mulx    rbp, rcx, QWORD PTR [r14+24]
    mov     rbx, r12                    /* t2 = acc4（保存） */
    adcx    r8, rcx
    adox    r9, rbp
    mov     rdx, r13                    /* t3 = acc5（保存） */
    adcx    r9, r11                     /* acc1 += acc3 */
    adox    r10, r11
    adc     r10, 0                      /* acc2 = 进位 */

    /* ---- 分支无关条件减 n ---- */
    mov     rcx, r8                     /* t0 = acc0（保存） */
    sub     r12, QWORD PTR [r14]        /* acc4 -= n[0] */
    sbb     r13, QWORD PTR [r14+8]      /* acc5 -= n[1] */
    sbb     r8, QWORD PTR [r14+16]      /* acc0 -= n[2] */
    mov     rbp, r9                     /* t1 = acc1（保存） */
    sbb     r9, QWORD PTR [r14+24]      /* acc1 -= n[3] */
    sbb     r10, 0                      /* acc2 -= 0 */

    cmovc   r12, rbx
    cmovc   r13, rdx
    mov     QWORD PTR [rdi], r12
    cmovc   r8, rcx
    mov     QWORD PTR [rdi+8], r13
    cmovc   r9, rbp
    mov     QWORD PTR [rdi+16], r8
    mov     QWORD PTR [rdi+24], r9

    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
.size jpssl_p256_ord_mul_adx, .-jpssl_p256_ord_mul_adx

/* ─────────────────────────────────────────────────────────────
 * jpssl_p256_neg(r[4], a[4])
 *   r = p - a mod p（常数时间）；a < p。
 * ───────────────────────────────────────────────────────────── */
.p2align 5
.globl jpssl_p256_neg
.type   jpssl_p256_neg, @function
jpssl_p256_neg:
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi

    /* SysV: rdi = r, rsi = a */
    mov     r14, 0xffffffff             /* p1 = 0x00000000ffffffff */
    mov     r15, 0xffffffff00000001     /* p3 */

    xor     r8, r8
    xor     r9, r9
    xor     r10, r10
    xor     r11, r11
    xor     rax, rax
    sub     r8, QWORD PTR [rsi]         /* 0 - a0 */
    sbb     r9, QWORD PTR [rsi+8]
    sbb     r10, QWORD PTR [rsi+16]
    mov     r12, r8                     /* save t0 */
    sbb     r11, QWORD PTR [rsi+24]
    mov     r13, r9                     /* save t1 */
    sbb     rax, 0                      /* rax = -borrow（0 或 -1） */
    mov     rbx, r10                    /* save t2 */
    mov     rbp, r11                    /* save t3 */
    add     r8, -1                      /* + p0（0xffffffffffffffff） */
    adc     r9, r14                     /* + p1（0x00000000ffffffff） */
    adc     r10, 0
    adc     r11, r15                    /* + p3 */
    test    rax, rax
    cmovz   r8, r12
    cmovz   r9, r13
    mov     QWORD PTR [rdi], r8
    cmovz   r10, rbx
    mov     QWORD PTR [rdi+8], r9
    cmovz   r11, rbp
    mov     QWORD PTR [rdi+16], r10
    mov     QWORD PTR [rdi+24], r11

    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
.size jpssl_p256_neg, .-jpssl_p256_neg

/* ─────────────────────────────────────────────────────────────
 * jpssl_p256_inv_adx(r[4], a[4])
 *   r = a^(p-2) mod p（Fermat 求逆，a 为 Montgomery 表示）。
 * 固定平方-乘链（MODMUL 宏展开），常数时间。
 * ───────────────────────────────────────────────────────────── */
.p2align 5
.globl jpssl_p256_inv_adx
.type   jpssl_p256_inv_adx, @function
jpssl_p256_inv_adx:
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    sub     rsp, 448

    /* SysV: rdi = r, rsi = a；a 可能别名 r，先拷贝到栈帧。
     * rdi 随后被链的 lea 用作 dst 参数，故用 callee-saved r12 保存 r_ptr */
    mov     r12, rdi
    mov     rax, [rsi]
    mov     rcx, [rsi+8]
    mov     r9, [rsi+16]
    mov     r10, [rsi+24]
    mov     [rsp+0], rax
    mov     [rsp+8], rcx
    mov     [rsp+16], r9
    mov     [rsp+24], r10

    /* Fermat 链：x^2, x^3, x^6, x^7, ... x^(p-2) */
    lea     rdi, [rsp+32]
    lea     rsi, [rsp+0]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+64]
    lea     rsi, [rsp+32]
    lea     rdx, [rsp+0]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+96]
    lea     rsi, [rsp+64]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+128]
    lea     rsi, [rsp+96]
    lea     rdx, [rsp+0]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+160]
    lea     rsi, [rsp+128]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+160]
    lea     rsi, [rsp+160]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+160]
    lea     rsi, [rsp+160]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+192]
    lea     rsi, [rsp+128]
    lea     rdx, [rsp+160]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+224]
    lea     rsi, [rsp+192]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+224]
    lea     rsi, [rsp+224]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+224]
    lea     rsi, [rsp+224]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+224]
    lea     rsi, [rsp+224]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+224]
    lea     rsi, [rsp+224]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+224]
    lea     rsi, [rsp+224]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+224]
    lea     rsi, [rsp+224]
    lea     rdx, [rsp+192]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+256]
    lea     rsi, [rsp+224]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+256]
    lea     rsi, [rsp+256]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+256]
    lea     rsi, [rsp+256]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+256]
    lea     rsi, [rsp+256]
    lea     rdx, [rsp+128]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+288]
    lea     rsi, [rsp+256]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+288]
    lea     rsi, [rsp+288]
    lea     rdx, [rsp+0]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+288]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+320]
    lea     rsi, [rsp+320]
    lea     rdx, [rsp+288]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+320]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+352]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+384]
    lea     rsi, [rsp+256]
    lea     rdx, [rsp+352]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+352]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    lea     rdx, [rsp+0]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    lea     rdx, [rsp+384]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+384]
    lea     rdx, [rsp+416]
    call    jpssl_p256_mul_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    call    jpssl_p256_sqr_adx
    lea     rdi, [rsp+416]
    lea     rsi, [rsp+416]
    lea     rdx, [rsp+0]
    call    jpssl_p256_mul_adx

    /* 结果 T12 -> r（r12 保存了入口 rdi） */
    mov     rax, [rsp+416]
    mov     rcx, [rsp+424]
    mov     rdx, [rsp+432]
    mov     r8, [rsp+440]
    mov     [r12], rax
    mov     [r12+8], rcx
    mov     [r12+16], rdx
    mov     [r12+24], r8

    add     rsp, 448
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
.size jpssl_p256_inv_adx, .-jpssl_p256_inv_adx

/* ─────────────────────────────────────────────────────────────
 * ecp_nistz256_ord_sqr_mont(r[4], a[4], one)
 *   r = a*a*R^-1 mod n（Montgomery 平方，ADX 版）。
 *   移植自 OpenSSL ecp_nistz256-x86_64.pl 的 ord_sqr_montx：
 *   one 为循环次数（ord_inv 调用时传 1 = 一次平方）。
 * ───────────────────────────────────────────────────────────── */
.p2align 5
.globl ecp_nistz256_ord_sqr_mont
.type   ecp_nistz256_ord_sqr_mont, @function
ecp_nistz256_ord_sqr_mont:
push    rbp
push    rbx
push    r12
push    r13
push    r14
push    r15
mov    rbx,rdx
mov    rdx,QWORD PTR [rsi]
mov    r14,QWORD PTR [rsi+8]
mov    r15,QWORD PTR [rsi+16]
mov    r8,QWORD PTR [rsi+24]
lea     rsi, [rip + .Lord]
jmp .Loop_ord_sqrx
.p2align 5
.Loop_ord_sqrx:
mulx    r10,r9,r14
mulx    r11,rcx,r15
mov    rax,rdx
    .byte 102, 73, 15, 110, 206
mulx    r12,rbp,r8
mov    rdx,r14
add    r10,rcx
    .byte 102, 73, 15, 110, 215
adc    r11,rbp
adc    r12,0
xor    r13,r13
mulx    rbp,rcx,r15
adcx    r11,rcx
adox    r12,rbp
mulx    rbp,rcx,r8
mov    rdx,r15
adcx    r12,rcx
adox    r13,rbp
adc    r13,0
mulx    r14,rcx,r8
mov    rdx,rax
    .byte 102, 73, 15, 110, 216
xor    r15,r15
adcx    r9,r9
adox    r13,rcx
adcx    r10,r10
adox    r14,r15
mulx    rbp,r8,rdx
    .byte 102, 72, 15, 126, 202
adcx    r11,r11
adox    r9,rbp
adcx    r12,r12
mulx    rax,rcx,rdx
    .byte 102, 72, 15, 126, 210
adcx    r13,r13
adox    r10,rcx
adcx    r14,r14
mulx    rbp,rcx,rdx
    .byte 0x067
    .byte 102, 72, 15, 126, 218
adox    r11,rax
adcx    r15,r15
adox    r12,rcx
adox    r13,rbp
mulx    rax,rcx,rdx
adox    r14,rcx
adox    r15,rax
mov     rdx, r8                     /* rdx = acc0（归约第 1 轮） */
mulx    rcx,rdx,QWORD PTR [rsi+32]
xor    rax,rax
mulx    rbp,rcx,QWORD PTR [rsi]
adcx    r8,rcx
adox    r9,rbp
mulx    rbp,rcx,QWORD PTR [rsi+8]
adcx    r9,rcx
adox    r10,rbp
mulx    rbp,rcx,QWORD PTR [rsi+16]
adcx    r10,rcx
adox    r11,rbp
mulx    rbp,rcx,QWORD PTR [rsi+24]
adcx    r11,rcx
adox    r8,rbp
adcx    r8,rax
mov    rdx,r9
mulx    rcx,rdx,QWORD PTR [rsi+32]
mulx    rbp,rcx,QWORD PTR [rsi]
adox    r9,rcx
adcx    r10,rbp
mulx    rbp,rcx,QWORD PTR [rsi+8]
adox    r10,rcx
adcx    r11,rbp
mulx    rbp,rcx,QWORD PTR [rsi+16]
adox    r11,rcx
adcx    r8,rbp
mulx    rbp,rcx,QWORD PTR [rsi+24]
adox    r8,rcx
adcx    r9,rbp
adox    r9,rax
mov    rdx,r10
mulx    rcx,rdx,QWORD PTR [rsi+32]
mulx    rbp,rcx,QWORD PTR [rsi]
adcx    r10,rcx
adox    r11,rbp
mulx    rbp,rcx,QWORD PTR [rsi+8]
adcx    r11,rcx
adox    r8,rbp
mulx    rbp,rcx,QWORD PTR [rsi+16]
adcx    r8,rcx
adox    r9,rbp
mulx    rbp,rcx,QWORD PTR [rsi+24]
adcx    r9,rcx
adox    r10,rbp
adcx    r10,rax
mov    rdx,r11
mulx    rcx,rdx,QWORD PTR [rsi+32]
mulx    rbp,rcx,QWORD PTR [rsi]
adox    r11,rcx
adcx    r8,rbp
mulx    rbp,rcx,QWORD PTR [rsi+8]
adox    r8,rcx
adcx    r9,rbp
mulx    rbp,rcx,QWORD PTR [rsi+16]
adox    r9,rcx
adcx    r10,rbp
mulx    rbp,rcx,QWORD PTR [rsi+24]
adox    r10,rcx
adcx    r11,rbp
adox    r11,rax
add    r12,r8
adc    r9,r13
mov    rdx,r12
adc    r10,r14
adc    r11,r15
mov    r14,r9
adc    rax,0
sub    r12,QWORD PTR [rsi]
mov    r15,r10
sbb    r9,QWORD PTR [rsi+8]
sbb    r10,QWORD PTR [rsi+16]
mov    r8,r11
sbb    r11,QWORD PTR [rsi+24]
sbb    rax,0
cmovnc    rdx,r12
cmovnc    r14,r9
cmovnc    r15,r10
cmovnc    r8,r11
dec    rbx
jnz .Loop_ord_sqrx
mov    QWORD PTR [rdi],rdx
mov    QWORD PTR [rdi+8],r14
pxor    xmm1,xmm1
mov    QWORD PTR [rdi+16],r15
pxor    xmm2,xmm2
mov    QWORD PTR [rdi+24],r8
pxor    xmm3,xmm3
mov    r15,QWORD PTR [rsp]
mov    r14,QWORD PTR [rsp+8]
mov    r13,QWORD PTR [rsp+16]
mov    r12,QWORD PTR [rsp+24]
mov    rbx,QWORD PTR [rsp+32]
mov    rbp,QWORD PTR [rsp+40]
lea    rsp,QWORD PTR [rsp+48]
    ret

.size ecp_nistz256_ord_sqr_mont, .-ecp_nistz256_ord_sqr_mont



/* ─────────────────────────────────────────────────────────────
 * jpssl_p256_ord_inv_adx(r[4], a[4])
 *   r = a^(n-2) mod n（Fermat 求逆，a 为 Montgomery 表示）。
 * ORDMODMUL 宏展开：sqr 走 ecp_nistz256_ord_sqr_mont（one=1），
 * mul 走 jpssl_p256_ord_mul_adx。常数时间。
 * ───────────────────────────────────────────────────────────── */
.p2align 5
.globl jpssl_p256_ord_inv_adx
.type   jpssl_p256_ord_inv_adx, @function
jpssl_p256_ord_inv_adx:
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    sub     rsp, 480

    /* SysV: rdi = r, rsi = a；a 可能别名 r，先拷贝到栈帧。
     * rdi 随后被链的 lea 用作 dst 参数，故用 callee-saved r12 保存 r_ptr */
    mov     r12, rdi
    mov     rax, [rsi]
    mov     rcx, [rsi+8]
    mov     r9, [rsi+16]
    mov     r10, [rsi+24]
    mov     [rsp+32], rax
    mov     [rsp+40], rcx
    mov     [rsp+48], r9
    mov     [rsp+56], r10

    /* Fermat 链：x^2, x^3, ... x^(n-2) */
    lea     rdi, [rsp+64]
    lea     rsi, [rsp+32]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+96]
    lea     rsi, [rsp+32]
    lea     rdx, [rsp+64]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+128]
    lea     rsi, [rsp+96]
    lea     rdx, [rsp+64]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+160]
    lea     rsi, [rsp+128]
    lea     rdx, [rsp+64]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+192]
    lea     rsi, [rsp+160]
    lea     rdx, [rsp+64]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+224]
    lea     rsi, [rsp+192]
    lea     rdx, [rsp+64]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+256]
    lea     rsi, [rsp+224]
    lea     rdx, [rsp+64]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+288]
    lea     rsi, [rsp+256]
    lea     rdx, [rsp+64]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+288]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+160]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+96]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+96]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+96]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+160]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+160]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+160]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+160]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+96]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+96]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+96]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+96]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+32]
    call    jpssl_p256_ord_mul_adx
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    mov     edx, 1
    call    ecp_nistz256_ord_sqr_mont
    lea     rdi, [rsp+448]
    lea     rsi, [rsp+448]
    lea     rdx, [rsp+288]
    call    jpssl_p256_ord_mul_adx

    /* 结果 OT12 -> r（r12 保存了入口 rdi） */
    mov     rax, [rsp+448]
    mov     rcx, [rsp+456]
    mov     rdx, [rsp+464]
    mov     r8, [rsp+472]
    mov     [r12], rax
    mov     [r12+8], rcx
    mov     [r12+16], rdx
    mov     [r12+24], r8

    add     rsp, 480
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
.size jpssl_p256_ord_inv_adx, .-jpssl_p256_ord_inv_adx



/* ═════════════════════════════════════════════════════════════
 * NIST P-256 Jacobian 点运算（ADX，移植自 OpenSSL nistz256）
 *   ecp_nistz256_point_double(r[12], p[12])        Jacobian 倍点
 *   ecp_nistz256_point_add_affine(r[12], p[12], q[8]) Jacobian+仿射混合加
 * 私有辅助函数沿用 OpenSSL 内部寄存器约定（rsi=a, rbx=b, rdi=r，
 * 入口 rdx/r14/r15/r8 载入 a 的 limbs），与平台 ABI 无关。
 * 调用方（ecdsa.cpp）已保证 CPU 支持 ADX，故省略 ia32cap 分派。
 * ═════════════════════════════════════════════════════════════ */


.p2align 5
.type   __ecp_nistz256_mul_montx, @function
__ecp_nistz256_mul_montx:
mulx    r9,r8,r9
mulx    r10,rcx,r10
mov    r14,32
xor    r13,r13
mulx    r11,rbp,r11
mov    r15,QWORD PTR [rip + .Lpoly + 24]
adc    r9,rcx
mulx    r12,rcx,r12
mov    rdx,r8
adc    r10,rbp
shlx    rbp,r8,r14
adc    r11,rcx
shrx    rcx,r8,r14
adc    r12,0
add    r9,rbp
adc    r10,rcx
mulx    rbp,rcx,r15
mov    rdx,QWORD PTR [rbx+8]
adc    r11,rcx
adc    r12,rbp
adc    r13,0
xor    r8,r8
mulx    rbp,rcx,QWORD PTR [rsi+128]
adcx    r9,rcx
adox    r10,rbp
mulx    rbp,rcx,QWORD PTR [rsi+136]
adcx    r10,rcx
adox    r11,rbp
mulx    rbp,rcx,QWORD PTR [rsi+144]
adcx    r11,rcx
adox    r12,rbp
mulx    rbp,rcx,QWORD PTR [rsi+152]
mov    rdx,r9
adcx    r12,rcx
shlx    rcx,r9,r14
adox    r13,rbp
shrx    rbp,r9,r14
adcx    r13,r8
adox    r8,r8
adc    r8,0
add    r10,rcx
adc    r11,rbp
mulx    rbp,rcx,r15
mov    rdx,QWORD PTR [rbx+16]
adc    r12,rcx
adc    r13,rbp
adc    r8,0
xor    r9,r9
mulx    rbp,rcx,QWORD PTR [rsi+128]
adcx    r10,rcx
adox    r11,rbp
mulx    rbp,rcx,QWORD PTR [rsi+136]
adcx    r11,rcx
adox    r12,rbp
mulx    rbp,rcx,QWORD PTR [rsi+144]
adcx    r12,rcx
adox    r13,rbp
mulx    rbp,rcx,QWORD PTR [rsi+152]
mov    rdx,r10
adcx    r13,rcx
shlx    rcx,r10,r14
adox    r8,rbp
shrx    rbp,r10,r14
adcx    r8,r9
adox    r9,r9
adc    r9,0
add    r11,rcx
adc    r12,rbp
mulx    rbp,rcx,r15
mov    rdx,QWORD PTR [rbx+24]
adc    r13,rcx
adc    r8,rbp
adc    r9,0
xor    r10,r10
mulx    rbp,rcx,QWORD PTR [rsi+128]
adcx    r11,rcx
adox    r12,rbp
mulx    rbp,rcx,QWORD PTR [rsi+136]
adcx    r12,rcx
adox    r13,rbp
mulx    rbp,rcx,QWORD PTR [rsi+144]
adcx    r13,rcx
adox    r8,rbp
mulx    rbp,rcx,QWORD PTR [rsi+152]
mov    rdx,r11
adcx    r8,rcx
shlx    rcx,r11,r14
adox    r9,rbp
shrx    rbp,r11,r14
adcx    r9,r10
adox    r10,r10
adc    r10,0
add    r12,rcx
adc    r13,rbp
mulx    rbp,rcx,r15
mov    rbx,r12
mov    r14,QWORD PTR [rip + .Lpoly + 8]
adc    r8,rcx
mov    rdx,r13
adc    r9,rbp
adc    r10,0
xor    eax,eax
mov    rcx,r8
sbb    r12,-1
sbb    r13,r14
sbb    r8,0
mov    rbp,r9
sbb    r9,r15
sbb    r10,0
cmovc    r12,rbx
cmovc    r13,rdx
mov    QWORD PTR [rdi],r12
cmovc    r8,rcx
mov    QWORD PTR [rdi+8],r13
cmovc    r9,rbp
mov    QWORD PTR [rdi+16],r8
mov    QWORD PTR [rdi+24],r9
        ret
.size   __ecp_nistz256_mul_montx, .-__ecp_nistz256_mul_montx


.p2align 5
.type   __ecp_nistz256_sqr_montx, @function
__ecp_nistz256_sqr_montx:
mulx    r10,r9,r14
mulx    r11,rcx,r15
xor    eax,eax
adc    r10,rcx
mulx    r12,rbp,r8
mov    rdx,r14
adc    r11,rbp
adc    r12,0
xor    r13,r13
mulx    rbp,rcx,r15
adcx    r11,rcx
adox    r12,rbp
mulx    rbp,rcx,r8
mov    rdx,r15
adcx    r12,rcx
adox    r13,rbp
adc    r13,0
mulx    r14,rcx,r8
mov    rdx,QWORD PTR [rsi+128]
xor    r15,r15
adcx    r9,r9
adox    r13,rcx
adcx    r10,r10
adox    r14,r15
mulx    rbp,r8,rdx
mov    rdx,QWORD PTR [rsi+136]
adcx    r11,r11
adox    r9,rbp
adcx    r12,r12
mulx    rax,rcx,rdx
mov    rdx,QWORD PTR [rsi+144]
adcx    r13,r13
adox    r10,rcx
adcx    r14,r14
    .byte 0x067
mulx    rbp,rcx,rdx
mov    rdx,QWORD PTR [rsi+152]
adox    r11,rax
adcx    r15,r15
adox    r12,rcx
mov    rsi,32
adox    r13,rbp
    .byte 0x067, 0x067
mulx    rax,rcx,rdx
mov    rdx,QWORD PTR [rip + .Lpoly + 24]
adox    r14,rcx
shlx    rcx,r8,rsi
adox    r15,rax
shrx    rax,r8,rsi
mov    rbp,rdx
add    r9,rcx
adc    r10,rax
mulx    r8,rcx,r8
adc    r11,rcx
shlx    rcx,r9,rsi
adc    r8,0
shrx    rax,r9,rsi
add    r10,rcx
adc    r11,rax
mulx    r9,rcx,r9
adc    r8,rcx
shlx    rcx,r10,rsi
adc    r9,0
shrx    rax,r10,rsi
add    r11,rcx
adc    r8,rax
mulx    r10,rcx,r10
adc    r9,rcx
shlx    rcx,r11,rsi
adc    r10,0
shrx    rax,r11,rsi
add    r8,rcx
adc    r9,rax
mulx    r11,rcx,r11
adc    r10,rcx
adc    r11,0
xor    rdx,rdx
add    r12,r8
mov    rsi,QWORD PTR [rip + .Lpoly + 8]
adc    r13,r9
mov    r8,r12
adc    r14,r10
adc    r15,r11
mov    r9,r13
adc    rdx,0
sub    r12,-1
mov    r10,r14
sbb    r13,rsi
sbb    r14,0
mov    r11,r15
sbb    r15,rbp
sbb    rdx,0
cmovc    r12,r8
cmovc    r13,r9
mov    QWORD PTR [rdi],r12
cmovc    r14,r10
mov    QWORD PTR [rdi+8],r13
cmovc    r15,r11
mov    QWORD PTR [rdi+16],r14
mov    QWORD PTR [rdi+24],r15
        ret
.size   __ecp_nistz256_sqr_montx, .-__ecp_nistz256_sqr_montx


.p2align 5
.type   __ecp_nistz256_add_tox, @function
__ecp_nistz256_add_tox:
xor    r11,r11
adc    r12,QWORD PTR [rbx]
adc    r13,QWORD PTR [rbx+8]
mov    rax,r12
adc    r8,QWORD PTR [rbx+16]
adc    r9,QWORD PTR [rbx+24]
mov    rbp,r13
adc    r11,0
xor    r10,r10
sbb    r12,-1
mov    rcx,r8
sbb    r13,r14
sbb    r8,0
mov    r10,r9
sbb    r9,r15
sbb    r11,0
cmovc    r12,rax
cmovc    r13,rbp
mov    QWORD PTR [rdi],r12
cmovc    r8,rcx
mov    QWORD PTR [rdi+8],r13
cmovc    r9,r10
mov    QWORD PTR [rdi+16],r8
mov    QWORD PTR [rdi+24],r9
        ret
.size   __ecp_nistz256_add_tox, .-__ecp_nistz256_add_tox


.p2align 5
.type   __ecp_nistz256_sub_fromx, @function
__ecp_nistz256_sub_fromx:
xor    r11,r11
sbb    r12,QWORD PTR [rbx]
sbb    r13,QWORD PTR [rbx+8]
mov    rax,r12
sbb    r8,QWORD PTR [rbx+16]
sbb    r9,QWORD PTR [rbx+24]
mov    rbp,r13
sbb    r11,0
xor    r10,r10
adc    r12,-1
mov    rcx,r8
adc    r13,r14
adc    r8,0
mov    r10,r9
adc    r9,r15
bt    r11,0
cmovnc    r12,rax
cmovnc    r13,rbp
mov    QWORD PTR [rdi],r12
cmovnc    r8,rcx
mov    QWORD PTR [rdi+8],r13
cmovnc    r9,r10
mov    QWORD PTR [rdi+16],r8
mov    QWORD PTR [rdi+24],r9
        ret
.size   __ecp_nistz256_sub_fromx, .-__ecp_nistz256_sub_fromx


.p2align 5
.type   __ecp_nistz256_subx, @function
__ecp_nistz256_subx:
xor    r11,r11
sbb    rax,r12
sbb    rbp,r13
mov    r12,rax
sbb    rcx,r8
sbb    r10,r9
mov    r13,rbp
sbb    r11,0
xor    r9,r9
adc    rax,-1
mov    r8,rcx
adc    rbp,r14
adc    rcx,0
mov    r9,r10
adc    r10,r15
bt    r11,0
cmovc    r12,rax
cmovc    r13,rbp
cmovc    r8,rcx
cmovc    r9,r10
        ret
.size   __ecp_nistz256_subx, .-__ecp_nistz256_subx


.p2align 5
.type   __ecp_nistz256_mul_by_2x, @function
__ecp_nistz256_mul_by_2x:
xor    r11,r11
adc    r12,r12
adc    r13,r13
mov    rax,r12
adc    r8,r8
adc    r9,r9
mov    rbp,r13
adc    r11,0
xor    r10,r10
sbb    r12,-1
mov    rcx,r8
sbb    r13,r14
sbb    r8,0
mov    r10,r9
sbb    r9,r15
sbb    r11,0
cmovc    r12,rax
cmovc    r13,rbp
mov    QWORD PTR [rdi],r12
cmovc    r8,rcx
mov    QWORD PTR [rdi+8],r13
cmovc    r9,r10
mov    QWORD PTR [rdi+16],r8
mov    QWORD PTR [rdi+24],r9
        ret
.size   __ecp_nistz256_mul_by_2x, .-__ecp_nistz256_mul_by_2x


.p2align 5
.globl  ecp_nistz256_point_double
.type   ecp_nistz256_point_double, @function
ecp_nistz256_point_double:
push    rbp
push    rbx
push    r12
push    r13
push    r14
push    r15
sub    rsp,32*5+8
.Lpoint_double_shortcutx:
movdqu    xmm0,XMMWORD PTR [rsi]
mov    rbx,rsi
movdqu    xmm1,XMMWORD PTR [rsi+16]
mov    r12,QWORD PTR [rsi+32]
mov    r13,QWORD PTR [rsi+40]
mov    r8,QWORD PTR [rsi+48]
mov    r9,QWORD PTR [rsi+56]
mov    r14,QWORD PTR [rip + .Lpoly + 8]
mov    r15,QWORD PTR [rip + .Lpoly + 24]
movdqa    XMMWORD PTR [rsp+96],xmm0
movdqa    XMMWORD PTR [(96+16)+rsp],xmm1
lea    r10,QWORD PTR [rdi+32]
lea    r11,QWORD PTR [rdi+64]
    .byte 102, 72, 15, 110, 199
    .byte 102, 73, 15, 110, 202
    .byte 102, 73, 15, 110, 211
lea    rdi,QWORD PTR [rsp]
call    __ecp_nistz256_mul_by_2x
mov    rdx,QWORD PTR [rsi+64]
mov    r14,QWORD PTR [rsi+72]
mov    r15,QWORD PTR [rsi+80]
mov    r8,QWORD PTR [rsi+88]
lea    rsi,QWORD PTR [rsi-64]
lea    rdi,QWORD PTR [rsp+64]
call    __ecp_nistz256_sqr_montx
mov    rdx,QWORD PTR [rsp+0]
mov    r14,QWORD PTR [rsp+8]
lea    rsi,QWORD PTR [rsp-128]
mov    r15,QWORD PTR [rsp+16]
mov    r8,QWORD PTR [rsp+24]
lea    rdi,QWORD PTR [rsp]
call    __ecp_nistz256_sqr_montx
mov    rdx,QWORD PTR [rbx+32]
mov    r9,QWORD PTR [rbx+64]
mov    r10,QWORD PTR [rbx+72]
mov    r11,QWORD PTR [rbx+80]
mov    r12,QWORD PTR [rbx+88]
lea    rsi,QWORD PTR [rbx-64]
lea    rbx,QWORD PTR [rbx+32]
    .byte 102, 72, 15, 126, 215
call    __ecp_nistz256_mul_montx
call    __ecp_nistz256_mul_by_2x
mov    r12,QWORD PTR [rsp+96]
mov    r13,QWORD PTR [rsp+104]
lea    rbx,QWORD PTR [rsp+64]
mov    r8,QWORD PTR [rsp+112]
mov    r9,QWORD PTR [rsp+120]
lea    rdi,QWORD PTR [rsp+32]
call    __ecp_nistz256_add_tox
mov    r12,QWORD PTR [rsp+96]
mov    r13,QWORD PTR [rsp+104]
lea    rbx,QWORD PTR [rsp+64]
mov    r8,QWORD PTR [rsp+112]
mov    r9,QWORD PTR [rsp+120]
lea    rdi,QWORD PTR [rsp+64]
call    __ecp_nistz256_sub_fromx
mov    rdx,QWORD PTR [rsp+0]
mov    r14,QWORD PTR [rsp+8]
lea    rsi,QWORD PTR [rsp-128]
mov    r15,QWORD PTR [rsp+16]
mov    r8,QWORD PTR [rsp+24]
    .byte 102, 72, 15, 126, 207
call    __ecp_nistz256_sqr_montx
xor    r9,r9
mov    rax,r12
add    r12,-1
mov    r10,r13
adc    r13,rsi
mov    rcx,r14
adc    r14,0
mov    r8,r15
adc    r15,rbp
adc    r9,0
xor    rsi,rsi
test    rax,1
cmovz    r12,rax
cmovz    r13,r10
cmovz    r14,rcx
cmovz    r15,r8
cmovz    r9,rsi
mov    rax,r13
shr    r12,1
shl    rax,63
mov    r10,r14
shr    r13,1
or    r12,rax
shl    r10,63
mov    rcx,r15
shr    r14,1
or    r13,r10
shl    rcx,63
mov    QWORD PTR [rdi],r12
shr    r15,1
mov    QWORD PTR [rdi+8],r13
shl    r9,63
or    r14,rcx
or    r15,r9
mov    QWORD PTR [rdi+16],r14
mov    QWORD PTR [rdi+24],r15
mov    rdx,QWORD PTR [rsp+64]
lea    rbx,QWORD PTR [rsp+64]
mov    r9,QWORD PTR [rsp+32]
mov    r10,QWORD PTR [rsp+40]
lea    rsi,QWORD PTR [rsp-96]
mov    r11,QWORD PTR [rsp+48]
mov    r12,QWORD PTR [rsp+56]
lea    rdi,QWORD PTR [rsp+32]
call    __ecp_nistz256_mul_montx
lea    rdi,QWORD PTR [rsp+128]
call    __ecp_nistz256_mul_by_2x
lea    rbx,QWORD PTR [rsp+32]
lea    rdi,QWORD PTR [rsp+32]
call    __ecp_nistz256_add_tox
mov    rdx,QWORD PTR [rsp+96]
lea    rbx,QWORD PTR [rsp+96]
mov    r9,QWORD PTR [rsp+0]
mov    r10,QWORD PTR [rsp+8]
lea    rsi,QWORD PTR [rsp-128]
mov    r11,QWORD PTR [rsp+16]
mov    r12,QWORD PTR [rsp+24]
lea    rdi,QWORD PTR [rsp]
call    __ecp_nistz256_mul_montx
lea    rdi,QWORD PTR [rsp+128]
call    __ecp_nistz256_mul_by_2x
mov    rdx,QWORD PTR [rsp+32]
mov    r14,QWORD PTR [rsp+40]
lea    rsi,QWORD PTR [rsp-96]
mov    r15,QWORD PTR [rsp+48]
mov    r8,QWORD PTR [rsp+56]
    .byte 102, 72, 15, 126, 199
call    __ecp_nistz256_sqr_montx
lea    rbx,QWORD PTR [rsp+128]
mov    r8,r14
mov    r9,r15
mov    r14,rsi
mov    r15,rbp
call    __ecp_nistz256_sub_fromx
mov    rax,QWORD PTR [rsp+0]
mov    rbp,QWORD PTR [rsp+8]
mov    rcx,QWORD PTR [rsp+16]
mov    r10,QWORD PTR [rsp+24]
lea    rdi,QWORD PTR [rsp]
call    __ecp_nistz256_subx
mov    rdx,QWORD PTR [rsp+32]
lea    rbx,QWORD PTR [rsp+32]
mov    r14,r12
xor    ecx,ecx
mov    QWORD PTR [rsp+0],r12
mov    r10,r13
mov    QWORD PTR [rsp+8],r13
cmovz    r11,r8
mov    QWORD PTR [rsp+16],r8
lea    rsi,QWORD PTR [rsp-128]
cmovz    r12,r9
mov    QWORD PTR [rsp+24],r9
mov    r9,r14
lea    rdi,QWORD PTR [rsp]
call    __ecp_nistz256_mul_montx
    .byte 102, 72, 15, 126, 203
    .byte 102, 72, 15, 126, 207
call    __ecp_nistz256_sub_fromx
lea    rsi,QWORD PTR [rsp+216]
mov    r15,QWORD PTR [rsi-48]
mov    r14,QWORD PTR [rsi-40]
mov    r13,QWORD PTR [rsi-32]
mov    r12,QWORD PTR [rsi-24]
mov    rbx,QWORD PTR [rsi-16]
mov    rbp,QWORD PTR [rsi-8]
lea    rsp,QWORD PTR [rsi]
mov    rsi,QWORD PTR [rsp+16]
    ret
.size   ecp_nistz256_point_double, .-ecp_nistz256_point_double


.p2align 5
.globl  ecp_nistz256_point_add_affine
.type   ecp_nistz256_point_add_affine, @function
ecp_nistz256_point_add_affine:
push    rbp
push    rbx
push    r12
push    r13
push    r14
push    r15
sub    rsp,32*15+8
.Ladd_affinex_body:
movdqu    xmm0,XMMWORD PTR [rsi]
mov    rbx,rdx
movdqu    xmm1,XMMWORD PTR [rsi+16]
movdqu    xmm2,XMMWORD PTR [rsi+32]
movdqu    xmm3,XMMWORD PTR [rsi+48]
movdqu    xmm4,XMMWORD PTR [rsi+64]
movdqu    xmm5,XMMWORD PTR [rsi+80]
mov    rdx,QWORD PTR [rsi+64]
mov    r14,QWORD PTR [rsi+72]
mov    r15,QWORD PTR [rsi+80]
mov    r8,QWORD PTR [rsi+88]
movdqa    XMMWORD PTR [rsp+320],xmm0
movdqa    XMMWORD PTR [(320+16)+rsp],xmm1
movdqa    XMMWORD PTR [rsp+352],xmm2
movdqa    XMMWORD PTR [(352+16)+rsp],xmm3
movdqa    XMMWORD PTR [rsp+384],xmm4
movdqa    XMMWORD PTR [(384+16)+rsp],xmm5
por    xmm5,xmm4
movdqu    xmm0,XMMWORD PTR [rbx]
pshufd    xmm3,xmm5,0x0b1
movdqu    xmm1,XMMWORD PTR [rbx+16]
movdqu    xmm2,XMMWORD PTR [rbx+32]
por    xmm5,xmm3
movdqu    xmm3,XMMWORD PTR [rbx+48]
movdqa    XMMWORD PTR [rsp+416],xmm0
pshufd    xmm4,xmm5,0x01e
movdqa    XMMWORD PTR [(416+16)+rsp],xmm1
por    xmm1,xmm0
    .byte 102, 72, 15, 110, 199
movdqa    XMMWORD PTR [rsp+448],xmm2
movdqa    XMMWORD PTR [(448+16)+rsp],xmm3
por    xmm3,xmm2
por    xmm5,xmm4
pxor    xmm4,xmm4
por    xmm3,xmm1
lea    rsi,QWORD PTR [rsi-64]
lea    rdi,QWORD PTR [rsp+32]
call    __ecp_nistz256_sqr_montx
pcmpeqd    xmm5,xmm4
pshufd    xmm4,xmm3,0x0b1
mov    rdx,QWORD PTR [rbx]
mov    r9,r12
por    xmm4,xmm3
pshufd    xmm5,xmm5,0
pshufd    xmm3,xmm4,0x01e
mov    r10,r13
por    xmm4,xmm3
pxor    xmm3,xmm3
mov    r11,r14
pcmpeqd    xmm4,xmm3
pshufd    xmm4,xmm4,0
lea    rsi,QWORD PTR [rsp-96]
mov    r12,r15
lea    rdi,QWORD PTR [rsp]
call    __ecp_nistz256_mul_montx
lea    rbx,QWORD PTR [rsp+320]
lea    rdi,QWORD PTR [rsp+64]
call    __ecp_nistz256_sub_fromx
mov    rdx,QWORD PTR [rsp+384]
lea    rbx,QWORD PTR [rsp+384]
mov    r9,QWORD PTR [rsp+32]
mov    r10,QWORD PTR [rsp+40]
lea    rsi,QWORD PTR [rsp-96]
mov    r11,QWORD PTR [rsp+48]
mov    r12,QWORD PTR [rsp+56]
lea    rdi,QWORD PTR [rsp+32]
call    __ecp_nistz256_mul_montx
mov    rdx,QWORD PTR [rsp+384]
lea    rbx,QWORD PTR [rsp+384]
mov    r9,QWORD PTR [rsp+64]
mov    r10,QWORD PTR [rsp+72]
lea    rsi,QWORD PTR [rsp-64]
mov    r11,QWORD PTR [rsp+80]
mov    r12,QWORD PTR [rsp+88]
lea    rdi,QWORD PTR [rsp+288]
call    __ecp_nistz256_mul_montx
mov    rdx,QWORD PTR [rsp+448]
lea    rbx,QWORD PTR [rsp+448]
mov    r9,QWORD PTR [rsp+32]
mov    r10,QWORD PTR [rsp+40]
lea    rsi,QWORD PTR [rsp-96]
mov    r11,QWORD PTR [rsp+48]
mov    r12,QWORD PTR [rsp+56]
lea    rdi,QWORD PTR [rsp+32]
call    __ecp_nistz256_mul_montx
lea    rbx,QWORD PTR [rsp+352]
lea    rdi,QWORD PTR [rsp+96]
call    __ecp_nistz256_sub_fromx
mov    rdx,QWORD PTR [rsp+64]
mov    r14,QWORD PTR [rsp+72]
lea    rsi,QWORD PTR [rsp-64]
mov    r15,QWORD PTR [rsp+80]
mov    r8,QWORD PTR [rsp+88]
lea    rdi,QWORD PTR [rsp+128]
call    __ecp_nistz256_sqr_montx
mov    rdx,QWORD PTR [rsp+96]
mov    r14,QWORD PTR [rsp+104]
lea    rsi,QWORD PTR [rsp-32]
mov    r15,QWORD PTR [rsp+112]
mov    r8,QWORD PTR [rsp+120]
lea    rdi,QWORD PTR [rsp+192]
call    __ecp_nistz256_sqr_montx
mov    rdx,QWORD PTR [rsp+128]
lea    rbx,QWORD PTR [rsp+128]
mov    r9,QWORD PTR [rsp+64]
mov    r10,QWORD PTR [rsp+72]
lea    rsi,QWORD PTR [rsp-64]
mov    r11,QWORD PTR [rsp+80]
mov    r12,QWORD PTR [rsp+88]
lea    rdi,QWORD PTR [rsp+160]
call    __ecp_nistz256_mul_montx
mov    rdx,QWORD PTR [rsp+320]
lea    rbx,QWORD PTR [rsp+320]
mov    r9,QWORD PTR [rsp+128]
mov    r10,QWORD PTR [rsp+136]
lea    rsi,QWORD PTR [rsp+0]
mov    r11,QWORD PTR [rsp+144]
mov    r12,QWORD PTR [rsp+152]
lea    rdi,QWORD PTR [rsp]
call    __ecp_nistz256_mul_montx
xor    r11,r11
add    r12,r12
lea    rsi,QWORD PTR [rsp+192]
adc    r13,r13
mov    rax,r12
adc    r8,r8
adc    r9,r9
mov    rbp,r13
adc    r11,0
sub    r12,-1
mov    rcx,r8
sbb    r13,r14
sbb    r8,0
mov    r10,r9
sbb    r9,r15
sbb    r11,0
cmovc    r12,rax
mov    rax,QWORD PTR [rsi]
cmovc    r13,rbp
mov    rbp,QWORD PTR [rsi+8]
cmovc    r8,rcx
mov    rcx,QWORD PTR [rsi+16]
cmovc    r9,r10
mov    r10,QWORD PTR [rsi+24]
call    __ecp_nistz256_subx
lea    rbx,QWORD PTR [rsp+160]
lea    rdi,QWORD PTR [rsp+224]
call    __ecp_nistz256_sub_fromx
mov    rax,QWORD PTR [rsp+0]
mov    rbp,QWORD PTR [rsp+8]
mov    rcx,QWORD PTR [rsp+16]
mov    r10,QWORD PTR [rsp+24]
lea    rdi,QWORD PTR [rsp+64]
call    __ecp_nistz256_subx
mov    QWORD PTR [rdi],r12
mov    QWORD PTR [rdi+8],r13
mov    QWORD PTR [rdi+16],r8
mov    QWORD PTR [rdi+24],r9
mov    rdx,QWORD PTR [rsp+352]
lea    rbx,QWORD PTR [rsp+352]
mov    r9,QWORD PTR [rsp+160]
mov    r10,QWORD PTR [rsp+168]
lea    rsi,QWORD PTR [rsp+32]
mov    r11,QWORD PTR [rsp+176]
mov    r12,QWORD PTR [rsp+184]
lea    rdi,QWORD PTR [rsp+32]
call    __ecp_nistz256_mul_montx
mov    rdx,QWORD PTR [rsp+96]
lea    rbx,QWORD PTR [rsp+96]
mov    r9,QWORD PTR [rsp+64]
mov    r10,QWORD PTR [rsp+72]
lea    rsi,QWORD PTR [rsp-64]
mov    r11,QWORD PTR [rsp+80]
mov    r12,QWORD PTR [rsp+88]
lea    rdi,QWORD PTR [rsp+64]
call    __ecp_nistz256_mul_montx
lea    rbx,QWORD PTR [rsp+32]
lea    rdi,QWORD PTR [rsp+256]
call    __ecp_nistz256_sub_fromx
    .byte 102, 72, 15, 126, 199
movdqa    xmm0,xmm5
movdqa    xmm1,xmm5
pandn    xmm0,XMMWORD PTR [rsp+288]
movdqa    xmm2,xmm5
pandn    xmm1,XMMWORD PTR [rsp+304]
movdqa    xmm3,xmm5
pand    xmm2,XMMWORD PTR [rip + .LONE_mont]
pand    xmm3,XMMWORD PTR [rip + .LONE_mont + 16]
por    xmm2,xmm0
por    xmm3,xmm1
movdqa    xmm0,xmm4
movdqa    xmm1,xmm4
pandn    xmm0,xmm2
movdqa    xmm2,xmm4
pandn    xmm1,xmm3
movdqa    xmm3,xmm4
pand    xmm2,XMMWORD PTR [rsp+384]
pand    xmm3,XMMWORD PTR [rsp+400]
por    xmm2,xmm0
por    xmm3,xmm1
movdqu    XMMWORD PTR [rdi+64],xmm2
movdqu    XMMWORD PTR [rdi+80],xmm3
movdqa    xmm0,xmm5
movdqa    xmm1,xmm5
pandn    xmm0,XMMWORD PTR [rsp+224]
movdqa    xmm2,xmm5
pandn    xmm1,XMMWORD PTR [rsp+240]
movdqa    xmm3,xmm5
pand    xmm2,XMMWORD PTR [rsp+416]
pand    xmm3,XMMWORD PTR [rsp+432]
por    xmm2,xmm0
por    xmm3,xmm1
movdqa    xmm0,xmm4
movdqa    xmm1,xmm4
pandn    xmm0,xmm2
movdqa    xmm2,xmm4
pandn    xmm1,xmm3
movdqa    xmm3,xmm4
pand    xmm2,XMMWORD PTR [rsp+320]
pand    xmm3,XMMWORD PTR [rsp+336]
por    xmm2,xmm0
por    xmm3,xmm1
movdqu    XMMWORD PTR [rdi],xmm2
movdqu    XMMWORD PTR [rdi+16],xmm3
movdqa    xmm0,xmm5
movdqa    xmm1,xmm5
pandn    xmm0,XMMWORD PTR [rsp+256]
movdqa    xmm2,xmm5
pandn    xmm1,XMMWORD PTR [rsp+272]
movdqa    xmm3,xmm5
pand    xmm2,XMMWORD PTR [rsp+448]
pand    xmm3,XMMWORD PTR [rsp+464]
por    xmm2,xmm0
por    xmm3,xmm1
movdqa    xmm0,xmm4
movdqa    xmm1,xmm4
pandn    xmm0,xmm2
movdqa    xmm2,xmm4
pandn    xmm1,xmm3
movdqa    xmm3,xmm4
pand    xmm2,XMMWORD PTR [rsp+352]
pand    xmm3,XMMWORD PTR [rsp+368]
por    xmm2,xmm0
por    xmm3,xmm1
movdqu    XMMWORD PTR [rdi+32],xmm2
movdqu    XMMWORD PTR [rdi+48],xmm3
lea    rsi,QWORD PTR [rsp+536]
mov    r15,QWORD PTR [rsi-48]
mov    r14,QWORD PTR [rsi-40]
mov    r13,QWORD PTR [rsi-32]
mov    r12,QWORD PTR [rsi-24]
mov    rbx,QWORD PTR [rsi-16]
mov    rbp,QWORD PTR [rsi-8]
lea    rsp,QWORD PTR [rsi]
    ret
.size   ecp_nistz256_point_add_affine, .-ecp_nistz256_point_add_affine

/* ─────────────────────────────────────────────────────────────
 * jpssl_p256_madd(r[12], p[12], q[12]): Jacobian 混合加 R=P+Q（SysV ABI）
 * 移植自 Windows 版 ecdsa_p256_adx.asm；H==0 例外分支调用
 * ecp_nistz256_point_double 替代 jpssl_p256_dbl；栈帧 +8 保持
 * call 前 16B 对齐（被调 point_double 用 movdqa）。
 * ───────────────────────────────────────────────────────────── */
.p2align 5
.globl  jpssl_p256_madd
.type   jpssl_p256_madd, @function
jpssl_p256_madd:
.pushsection .rodata
.p2align 3
.LLjpssl_p256_field_one:
.quad 0x1
.quad 0xffffffff
.quad 0xffffffffffffffff
.quad 0xfffffffe
.popsection
push    rbp
push    rbx
push    r12
push    r13
push    r14
push    r15
push    rsi
push    rdi
sub     rsp, 584
mov     rbx, rdx
mov     r15, 0xffffffff00000001 /* p word 3 */
mov     r14, 0xffffffff /* p word 1 */
mov     rax, [rsi] /* X1 */
mov     rcx, [rsi+8]
mov     rdx, [rsi+16]
mov     r8, [rsi+24]
mov     [rsp+0], rax
mov     [rsp+8], rcx
mov     [rsp+16], rdx
mov     [rsp+24], r8
mov     rax, [rsi+32] /* Y1 */
mov     rcx, [rsi+40]
mov     rdx, [rsi+48]
mov     r8, [rsi+56]
mov     [rsp+32], rax
mov     [rsp+40], rcx
mov     [rsp+48], rdx
mov     [rsp+56], r8
mov     rax, [rsi+64] /* Z1 */
mov     rcx, [rsi+72]
mov     rdx, [rsi+80]
mov     r8, [rsi+88]
mov     [rsp+64], rax
mov     [rsp+72], rcx
mov     [rsp+80], rdx
mov     [rsp+88], r8
mov     rax, [rbx] /* Xq */
mov     rcx, [rbx+8]
mov     rdx, [rbx+16]
mov     r8, [rbx+24]
mov     [rsp+96], rax
mov     [rsp+104], rcx
mov     [rsp+112], rdx
mov     [rsp+120], r8
mov     rax, [rbx+32] /* Yq */
mov     rcx, [rbx+40]
mov     rdx, [rbx+48]
mov     r8, [rbx+56]
mov     [rsp+128], rax
mov     [rsp+136], rcx
mov     [rsp+144], rdx
mov     [rsp+152], r8
mov     rax, [rbx+64] /* Zq */
mov     rcx, [rbx+72]
mov     rdx, [rbx+80]
mov     r8, [rbx+88]
mov     [rsp+160], rax
mov     [rsp+168], rcx
mov     [rsp+176], rdx
mov     [rsp+184], r8
mov     rax, [rsp+64]
or      rax, [rsp+72]
or      rax, [rsp+80]
or      rax, [rsp+88]
jnz     .Lmadd_p_notinf
mov     rax, [rsp+96]
mov     rcx, [rsp+104]
mov     rdx, [rsp+112]
mov     r8, [rsp+120]
mov     [rbp], rax
mov     [rbp+8], rcx
mov     [rbp+16], rdx
mov     [rbp+24], r8
mov     rax, [rsp+128]
mov     rcx, [rsp+136]
mov     rdx, [rsp+144]
mov     r8, [rsp+152]
mov     [rbp+32], rax
mov     [rbp+40], rcx
mov     [rbp+48], rdx
mov     [rbp+56], r8
mov     rax, [rsp+160]
mov     rcx, [rsp+168]
mov     rdx, [rsp+176]
mov     r8, [rsp+184]
mov     [rbp+64], rax
mov     [rbp+72], rcx
mov     [rbp+80], rdx
mov     [rbp+88], r8
jmp     .Lmadd_done
.Lmadd_p_notinf:
lea     rdi, [rsp+192]
lea     rsi, [rsp+64]
call    jpssl_p256_sqr_adx
lea     rdi, [rsp+224]
lea     rsi, [rsp+96]
lea     rdx, [rsp+192]
call    jpssl_p256_mul_adx
lea     rdi, [rsp+256]
lea     rsi, [rsp+128]
lea     rdx, [rsp+64]
call    jpssl_p256_mul_adx
lea     rdi, [rsp+256]
lea     rsi, [rsp+256]
lea     rdx, [rsp+192]
call    jpssl_p256_mul_adx
mov     rax, [rsp+224]
mov     rcx, [rsp+232]
mov     rdx, [rsp+240]
mov     r8, [rsp+248]
sub     rax, [rsp+0]
sbb     rcx, [rsp+8]
sbb     rdx, [rsp+16]
sbb     r8, [rsp+24]
setc    r9b
movzx   r9d, r9b
mov     r10, rax
mov     r11, rcx
mov     r12, rdx
mov     r13, r8
add     r10, -1
adc     r11, r14
adc     r12, 0
adc     r13, r15
neg     r9
cmovc   rax, r10
cmovc   rcx, r11
cmovc   rdx, r12
cmovc   r8, r13
mov     [rsp+288], rax
mov     [rsp+296], rcx
mov     [rsp+304], rdx
mov     [rsp+312], r8
mov     rax, [rsp+256]
mov     rcx, [rsp+264]
mov     rdx, [rsp+272]
mov     r8, [rsp+280]
sub     rax, [rsp+32]
sbb     rcx, [rsp+40]
sbb     rdx, [rsp+48]
sbb     r8, [rsp+56]
setc    r9b
movzx   r9d, r9b
mov     r10, rax
mov     r11, rcx
mov     r12, rdx
mov     r13, r8
add     r10, -1
adc     r11, r14
adc     r12, 0
adc     r13, r15
neg     r9
cmovc   rax, r10
cmovc   rcx, r11
cmovc   rdx, r12
cmovc   r8, r13
mov     [rsp+320], rax
mov     [rsp+328], rcx
mov     [rsp+336], rdx
mov     [rsp+344], r8
mov     rax, [rsp+288]
or      rax, [rsp+296]
or      rax, [rsp+304]
or      rax, [rsp+312]
jnz     .Lmadd_h_nonzero
mov     rax, [rsp+320]
or      rax, [rsp+328]
or      rax, [rsp+336]
or      rax, [rsp+344]
jnz     .Lmadd_h_inf
call    ecp_nistz256_point_double
jmp     .Lmadd_done
.Lmadd_h_inf:
lea     rbx, [rip + .LLjpssl_p256_field_one]
mov     rax, [rbx]
mov     rcx, [rbx+8]
mov     rdx, [rbx+16]
mov     r8, [rbx+24]
mov     [rbp], rax
mov     [rbp+8], rcx
mov     [rbp+16], rdx
mov     [rbp+24], r8
mov     [rbp+32], rax
mov     [rbp+40], rcx
mov     [rbp+48], rdx
mov     [rbp+56], r8
mov QWORD PTR [rbp+64], 0
mov QWORD PTR [rbp+72], 0
mov QWORD PTR [rbp+80], 0
mov QWORD PTR [rbp+88], 0
jmp     .Lmadd_done
.Lmadd_h_nonzero:
mov     rax, [rsp+320]
mov     rcx, [rsp+328]
mov     rdx, [rsp+336]
mov     r8, [rsp+344]
add     rax, rax
adc     rcx, rcx
adc     rdx, rdx
adc     r8, r8
setc    r9b
movzx   r9d, r9b
sub     rax, -1
sbb     rcx, r14
sbb     rdx, 0
sbb     r8, r15
setc    r10b
movzx   r10d, r10b
xor     r9d, 1
and     r9d, r10d
neg     r9
mov     r10, r9
and     r10, r14
mov     r11, r9
and     r11, r15
add     rax, r9
adc     rcx, r10
adc     rdx, 0
adc     r8, r11
mov     [rsp+352], rax
mov     [rsp+360], rcx
mov     [rsp+368], rdx
mov     [rsp+376], r8
mov     rax, [rsp+288]
mov     rcx, [rsp+296]
mov     rdx, [rsp+304]
mov     r8, [rsp+312]
add     rax, rax
adc     rcx, rcx
adc     rdx, rdx
adc     r8, r8
setc    r9b
movzx   r9d, r9b
sub     rax, -1
sbb     rcx, r14
sbb     rdx, 0
sbb     r8, r15
setc    r10b
movzx   r10d, r10b
xor     r9d, 1
and     r9d, r10d
neg     r9
mov     r10, r9
and     r10, r14
mov     r11, r9
and     r11, r15
add     rax, r9
adc     rcx, r10
adc     rdx, 0
adc     r8, r11
mov     [rsp+384], rax
mov     [rsp+392], rcx
mov     [rsp+400], rdx
mov     [rsp+408], r8
lea     rdi, [rsp+384]
lea     rsi, [rsp+384]
call    jpssl_p256_sqr_adx
lea     rdi, [rsp+416]
lea     rsi, [rsp+288]
lea     rdx, [rsp+384]
call    jpssl_p256_mul_adx
lea     rdi, [rsp+448]
lea     rsi, [rsp+0]
lea     rdx, [rsp+384]
call    jpssl_p256_mul_adx
lea     rdi, [rsp+480]
lea     rsi, [rsp+352]
call    jpssl_p256_sqr_adx
mov     rax, [rsp+480]
mov     rcx, [rsp+488]
mov     rdx, [rsp+496]
mov     r8, [rsp+504]
sub     rax, [rsp+416]
sbb     rcx, [rsp+424]
sbb     rdx, [rsp+432]
sbb     r8, [rsp+440]
setc    r9b
movzx   r9d, r9b
mov     r10, rax
mov     r11, rcx
mov     r12, rdx
mov     r13, r8
add     r10, -1
adc     r11, r14
adc     r12, 0
adc     r13, r15
neg     r9
cmovc   rax, r10
cmovc   rcx, r11
cmovc   rdx, r12
cmovc   r8, r13
mov     [rsp+480], rax
mov     [rsp+488], rcx
mov     [rsp+496], rdx
mov     [rsp+504], r8
mov     rax, [rsp+448]
mov     rcx, [rsp+456]
mov     rdx, [rsp+464]
mov     r8, [rsp+472]
add     rax, rax
adc     rcx, rcx
adc     rdx, rdx
adc     r8, r8
setc    r9b
movzx   r9d, r9b
sub     rax, -1
sbb     rcx, r14
sbb     rdx, 0
sbb     r8, r15
setc    r10b
movzx   r10d, r10b
xor     r9d, 1
and     r9d, r10d
neg     r9
mov     r10, r9
and     r10, r14
mov     r11, r9
and     r11, r15
add     rax, r9
adc     rcx, r10
adc     rdx, 0
adc     r8, r11
mov     r9, [rsp+480]
mov     r10, [rsp+488]
mov     r11, [rsp+496]
mov     rbx, [rsp+504]
sub     r9, rax
sbb     r10, rcx
sbb     r11, rdx
sbb     rbx, r8
setc    r12b
movzx   r12d, r12b /* r12 = borrow */
mov     r13, r9
mov     rax, r10
mov     rcx, r11
mov     rdx, rbx
add     r13, -1
adc     rax, r14
adc     rcx, 0
adc     rdx, r15 /* r13,rax,rcx,rdx = a-b+p */
neg     r12 /* CF = borrow */
cmovc   r9, r13
cmovc   r10, rax
cmovc   r11, rcx
cmovc   rbx, rdx
mov     [rsp+480], r9
mov     [rsp+488], r10
mov     [rsp+496], r11
mov     [rsp+504], rbx
mov     rax, [rsp+448]
mov     rcx, [rsp+456]
mov     rdx, [rsp+464]
mov     r8, [rsp+472]
sub     rax, [rsp+480]
sbb     rcx, [rsp+488]
sbb     rdx, [rsp+496]
sbb     r8, [rsp+504]
setc    r9b
movzx   r9d, r9b
mov     r10, rax
mov     r11, rcx
mov     r12, rdx
mov     r13, r8
add     r10, -1
adc     r11, r14
adc     r12, 0
adc     r13, r15
neg     r9
cmovc   rax, r10
cmovc   rcx, r11
cmovc   rdx, r12
cmovc   r8, r13
mov     [rsp+320], rax
mov     [rsp+328], rcx
mov     [rsp+336], rdx
mov     [rsp+344], r8
lea     rdi, [rsp+512]
lea     rsi, [rsp+352]
lea     rdx, [rsp+320]
call    jpssl_p256_mul_adx
lea     rdi, [rsp+320]
lea     rsi, [rsp+32]
lea     rdx, [rsp+416]
call    jpssl_p256_mul_adx
mov     rax, [rsp+320]
mov     rcx, [rsp+328]
mov     rdx, [rsp+336]
mov     r8, [rsp+344]
add     rax, rax
adc     rcx, rcx
adc     rdx, rdx
adc     r8, r8
setc    r9b
movzx   r9d, r9b
sub     rax, -1
sbb     rcx, r14
sbb     rdx, 0
sbb     r8, r15
setc    r10b
movzx   r10d, r10b
xor     r9d, 1
and     r9d, r10d
neg     r9
mov     r10, r9
and     r10, r14
mov     r11, r9
and     r11, r15
add     rax, r9
adc     rcx, r10
adc     rdx, 0
adc     r8, r11
mov     r9, [rsp+512]
mov     r10, [rsp+520]
mov     r11, [rsp+528]
mov     rbx, [rsp+536]
sub     r9, rax
sbb     r10, rcx
sbb     r11, rdx
sbb     rbx, r8
setc    r12b
movzx   r12d, r12b /* r12 = borrow */
mov     r13, r9
mov     rax, r10
mov     rcx, r11
mov     rdx, rbx
add     r13, -1
adc     rax, r14
adc     rcx, 0
adc     rdx, r15 /* r13,rax,rcx,rdx = a-b+p */
neg     r12 /* CF = borrow */
cmovc   r9, r13
cmovc   r10, rax
cmovc   r11, rcx
cmovc   rbx, rdx
mov     [rsp+512], r9
mov     [rsp+520], r10
mov     [rsp+528], r11
mov     [rsp+536], rbx
lea     rdi, [rsp+544]
lea     rsi, [rsp+64]
lea     rdx, [rsp+288]
call    jpssl_p256_mul_adx
mov     rax, [rsp+544]
mov     rcx, [rsp+552]
mov     rdx, [rsp+560]
mov     r8, [rsp+568]
add     rax, rax
adc     rcx, rcx
adc     rdx, rdx
adc     r8, r8
setc    r9b
movzx   r9d, r9b
sub     rax, -1
sbb     rcx, r14
sbb     rdx, 0
sbb     r8, r15
setc    r10b
movzx   r10d, r10b
xor     r9d, 1
and     r9d, r10d
neg     r9
mov     r10, r9
and     r10, r14
mov     r11, r9
and     r11, r15
add     rax, r9
adc     rcx, r10
adc     rdx, 0
adc     r8, r11
mov     [rsp+544], rax
mov     [rsp+552], rcx
mov     [rsp+560], rdx
mov     [rsp+568], r8
mov     rax, [rsp+160]
or      rax, [rsp+168]
or      rax, [rsp+176]
or      rax, [rsp+184]
neg     rax /* CF = (Zq != 0) */
sbb     r9, r9 /* r9 = -(Zq != 0) */
mov     r10, r9
not     r10 /* r10 = mask_q (all-ones if Zq==0) */
mov     rax, [rsp+480]
and     rax, r9
mov     rcx, [rsp+0]
and     rcx, r10
or      rax, rcx
mov     [rbp], rax
mov     rax, [rsp+488]
and     rax, r9
mov     rcx, [rsp+8]
and     rcx, r10
or      rax, rcx
mov     [rbp+8], rax
mov     rax, [rsp+496]
and     rax, r9
mov     rcx, [rsp+16]
and     rcx, r10
or      rax, rcx
mov     [rbp+16], rax
mov     rax, [rsp+504]
and     rax, r9
mov     rcx, [rsp+24]
and     rcx, r10
or      rax, rcx
mov     [rbp+24], rax
mov     rax, [rsp+512]
and     rax, r9
mov     rcx, [rsp+32]
and     rcx, r10
or      rax, rcx
mov     [rbp+32], rax
mov     rax, [rsp+520]
and     rax, r9
mov     rcx, [rsp+40]
and     rcx, r10
or      rax, rcx
mov     [rbp+40], rax
mov     rax, [rsp+528]
and     rax, r9
mov     rcx, [rsp+48]
and     rcx, r10
or      rax, rcx
mov     [rbp+48], rax
mov     rax, [rsp+536]
and     rax, r9
mov     rcx, [rsp+56]
and     rcx, r10
or      rax, rcx
mov     [rbp+56], rax
mov     rax, [rsp+544]
and     rax, r9
mov     rcx, [rsp+64]
and     rcx, r10
or      rax, rcx
mov     [rbp+64], rax
mov     rax, [rsp+552]
and     rax, r9
mov     rcx, [rsp+72]
and     rcx, r10
or      rax, rcx
mov     [rbp+72], rax
mov     rax, [rsp+560]
and     rax, r9
mov     rcx, [rsp+80]
and     rcx, r10
or      rax, rcx
mov     [rbp+80], rax
mov     rax, [rsp+568]
and     rax, r9
mov     rcx, [rsp+88]
and     rcx, r10
or      rax, rcx
mov     [rbp+88], rax
.Lmadd_done:
add     rsp, 584
pop     rdi
pop     rsi
pop     r15
pop     r14
pop     r13
pop     r12
pop     rbx
pop     rbp
ret
.size   jpssl_p256_madd, .-jpssl_p256_madd

/* ─────────────────────────────────────────────────────────────
 * jpssl_p256_comb_mul_G(r[12], k[4], table, one[4]):
 *   64 窗口 4-bit comb 固定点标量乘（常数时间）
 *   table[i][d-1] = d*2^(4i)*G（Montgomery，行步长 960B）
 * ───────────────────────────────────────────────────────────── */
.p2align 5
.globl  jpssl_p256_comb_mul_G
.type   jpssl_p256_comb_mul_G, @function
jpssl_p256_comb_mul_G:
push    rbp
push    rbx
push    r12
push    r13
push    r14
push    r15
push    rsi
push    rdi
sub     rsp, 232
mov     rbx, rdx
mov     rbp, rcx
mov     rax, [rsi]
mov     [rsp+192], rax
mov     rax, [rsi+8]
mov     [rsp+200], rax
mov     rax, [rsi+16]
mov     [rsp+208], rax
mov     rax, [rsi+24]
mov     [rsp+216], rax
mov     rax, [rbp]
mov     [rsp+0], rax
mov     rax, [rbp+8]
mov     [rsp+8], rax
mov     rax, [rbp+16]
mov     [rsp+16], rax
mov     rax, [rbp+24]
mov     [rsp+24], rax
mov     rax, [rbp]
mov     [rsp+32], rax
mov     rax, [rbp+8]
mov     [rsp+40], rax
mov     rax, [rbp+16]
mov     [rsp+48], rax
mov     rax, [rbp+24]
mov     [rsp+56], rax
xor     eax, eax
mov     [rsp+64], rax
mov     [rsp+72], rax
mov     [rsp+80], rax
mov     [rsp+88], rax
xor     r12, r12 /* window index */
mov     r15, rbx /* window base pointer */
.Lcomb_loop:
mov     rax, [rsp+192]
and     rax, 15
mov     [rsp+224], rax
xor     r13, r13 /* any = 0 */
pxor    xmm0, xmm0
movdqu  [rsp+96], xmm0
movdqu  [rsp+112], xmm0
movdqu  [rsp+128], xmm0
movdqu  [rsp+144], xmm0
movdqu  [rsp+160], xmm0
movdqu  [rsp+176], xmm0
xor     r14, r14 /* entry byte offset */
.Lcomb_sel:
mov     rax, [rsp+224]
mov     rcx, r14
shr     rcx, 6
inc     rcx
xor     rdx, rdx
cmp     rax, rcx
sete    dl
neg     rdx
or      r13, rdx
mov     rax, [r15+r14]
and     rax, rdx
or      [rsp+96], rax
mov     rax, [r15+r14+8]
and     rax, rdx
or      [rsp+104], rax
mov     rax, [r15+r14+16]
and     rax, rdx
or      [rsp+112], rax
mov     rax, [r15+r14+24]
and     rax, rdx
or      [rsp+120], rax
mov     rax, [r15+r14+32]
and     rax, rdx
or      [rsp+128], rax
mov     rax, [r15+r14+40]
and     rax, rdx
or      [rsp+136], rax
mov     rax, [r15+r14+48]
and     rax, rdx
or      [rsp+144], rax
mov     rax, [r15+r14+56]
and     rax, rdx
or      [rsp+152], rax
add     r14, 64
cmp     r14, 960
jb      .Lcomb_sel
mov     rax, [rbp]
and     rax, r13
mov     [rsp+160], rax
mov     rax, [rbp+8]
and     rax, r13
mov     [rsp+168], rax
mov     rax, [rbp+16]
and     rax, r13
mov     [rsp+176], rax
mov     rax, [rbp+24]
and     rax, r13
mov     [rsp+184], rax
lea     rdi, [rsp+0]
lea     rsi, [rsp+0]
lea    rdx,QWORD PTR [rsp+96]
call    ecp_nistz256_point_add_affine
mov     rax, [rsp+192]
mov     rcx, [rsp+200]
mov     rdx, [rsp+208]
mov     r8, [rsp+216]
shrd    rax, rcx, 4
shrd    rcx, rdx, 4
shrd    rdx, r8, 4
shr     r8, 4
mov     [rsp+192], rax
mov     [rsp+200], rcx
mov     [rsp+208], rdx
mov     [rsp+216], r8
add     r15, 960
inc     r12
cmp     r12, 64
jb      .Lcomb_loop
mov     rax, [rsp+0]
mov     [rbx], rax
mov     rax, [rsp+8]
mov     [rbx+8], rax
mov     rax, [rsp+16]
mov     [rbx+16], rax
mov     rax, [rsp+24]
mov     [rbx+24], rax
mov     rax, [rsp+32]
mov     [rbx+32], rax
mov     rax, [rsp+40]
mov     [rbx+40], rax
mov     rax, [rsp+48]
mov     [rbx+48], rax
mov     rax, [rsp+56]
mov     [rbx+56], rax
mov     rax, [rsp+64]
mov     [rbx+64], rax
mov     rax, [rsp+72]
mov     [rbx+72], rax
mov     rax, [rsp+80]
mov     [rbx+80], rax
mov     rax, [rsp+88]
mov     [rbx+88], rax
add     rsp, 232
pop     rdi
pop     rsi
pop     r15
pop     r14
pop     r13
pop     r12
pop     rbx
pop     rbp
ret
.size   jpssl_p256_comb_mul_G, .-jpssl_p256_comb_mul_G


#endif /* __x86_64__ */
