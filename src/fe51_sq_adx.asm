; fe51_sq_adx.asm - Windows x64 (masm/ml64) radix-2^51 域平方
; r = a^2 mod p, p = 2^255 - 19
;
; 调用约定: Microsoft x64
;   fe51_sq_adx(rcx=r, rdx=a)    (extern "C")
;
; MULX (BMI2) + ADCX/ADOX 双进位链:
;   偶数列 t0,t2,t4,t6,t8 用 ADCX (CF 链)
;   奇数列 t1,t3,t5,t7 用 ADOX (OF 链)
;
; 利用平方对称性: 仅 15 次 MULX (vs 乘法 25 次), 非对角项乘以 2。
; 列结构:
;   t0 = a0^2
;   t1 = 2*a0*a1
;   t2 = 2*a0*a2 + a1^2
;   t3 = 2*a0*a3 + 2*a1*a2
;   t4 = 2*a0*a4 + 2*a1*a3 + a2^2
;   t5 = 2*a1*a4 + 2*a2*a3
;   t6 = 2*a2*a4 + a3^2
;   t7 = 2*a3*a4
;   t8 = a4^2
; 折叠/进位与 fe51_mul_adx 完全一致: 输出每个 limb < 2^51 + eps。

.code

fe51_sq_adx PROC
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 160                    ; t0..t8 每项 16 字节 = 144B + 对齐余量

    mov     r12, rdx                    ; r12 = a
    mov     r14, rcx                    ; r14 = r

    ; ---- t0 = a0^2 ; t1 = 2*a0*a1 ----
    mov     rdx, QWORD PTR [r12]
    mulx    r8, r9, QWORD PTR [r12]      ; t0 = a0*a0: hi=r8, lo=r9
    mulx    r10, r11, QWORD PTR [r12+8]  ; p01 = a0*a1: hi=r10, lo=r11
    add     r11, r11                     ; t1_lo = 2*p01_lo
    adc     r10, r10                     ; t1_hi = 2*p01_hi + carry
    mov     QWORD PTR [rsp+0], r9
    mov     QWORD PTR [rsp+8], r8
    mov     QWORD PTR [rsp+16], r11
    mov     QWORD PTR [rsp+24], r10

    ; ---- t2 = 2*a0*a2 + a1^2 ; t3 = 2*a0*a3 + 2*a1*a2 ----
    mov     rdx, QWORD PTR [r12]
    mulx    r8, r9, QWORD PTR [r12+16]   ; p02: hi=r8, lo=r9
    add     r9, r9                       ; 2*p02_lo
    adc     r8, r8                       ; 2*p02_hi
    mulx    r10, r11, QWORD PTR [r12+24] ; p03: hi=r10, lo=r11
    add     r11, r11                     ; 2*p03_lo
    adc     r10, r10                     ; 2*p03_hi
    mov     rdx, QWORD PTR [r12+8]
    mulx    rsi, rdi, QWORD PTR [r12+8]  ; a1^2: hi=rsi, lo=rdi
    mulx    rcx, rax, QWORD PTR [r12+16] ; p12 = a1*a2: hi=rcx, lo=rax
    add     rax, rax                     ; 2*p12_lo
    adc     rcx, rcx                     ; 2*p12_hi
    xor     r15, r15                     ; CF=OF=0
    adcx    r9, rdi                      ; t2_lo += a1^2_lo
    adcx    r8, rsi                      ; t2_hi += a1^2_hi
    adox    r11, rax                     ; t3_lo += 2*p12_lo
    adox    r10, rcx                     ; t3_hi += 2*p12_hi
    mov     QWORD PTR [rsp+32], r9
    mov     QWORD PTR [rsp+40], r8
    mov     QWORD PTR [rsp+48], r11
    mov     QWORD PTR [rsp+56], r10

    ; ---- t4 = 2*a0*a4 + 2*a1*a3 + a2^2 ; t5 = 2*a1*a4 + 2*a2*a3 ----
    mov     rdx, QWORD PTR [r12]
    mulx    r8, r9, QWORD PTR [r12+32]   ; p04: hi=r8, lo=r9
    add     r9, r9                       ; 2*p04_lo
    adc     r8, r8                       ; 2*p04_hi
    mov     rdx, QWORD PTR [r12+8]
    mulx    r10, r11, QWORD PTR [r12+32] ; p14 = a1*a4: hi=r10, lo=r11
    add     r11, r11                     ; 2*p14_lo
    adc     r10, r10                     ; 2*p14_hi
    mov     rdx, QWORD PTR [r12+8]
    mulx    rsi, rdi, QWORD PTR [r12+24] ; p13 = a1*a3: hi=rsi, lo=rdi
    add     rdi, rdi                     ; 2*p13_lo
    adc     rsi, rsi                     ; 2*p13_hi
    mov     rdx, QWORD PTR [r12+16]
    mulx    rbx, rbp, QWORD PTR [r12+16] ; a2^2: hi=rbx, lo=rbp
    mov     rdx, QWORD PTR [r12+16]
    mulx    rcx, rax, QWORD PTR [r12+24] ; p23 = a2*a3: hi=rcx, lo=rax
    add     rax, rax                     ; 2*p23_lo
    adc     rcx, rcx                     ; 2*p23_hi
    xor     r15, r15                     ; CF=OF=0
    adcx    r9, rdi                      ; t4_lo += 2*p13_lo
    adcx    r8, rsi                      ; t4_hi += 2*p13_hi
    adcx    r9, rbp                      ; t4_lo += a2^2_lo
    adcx    r8, rbx                      ; t4_hi += a2^2_hi
    adox    r11, rax                     ; t5_lo += 2*p23_lo
    adox    r10, rcx                     ; t5_hi += 2*p23_hi
    mov     QWORD PTR [rsp+64], r9
    mov     QWORD PTR [rsp+72], r8
    mov     QWORD PTR [rsp+80], r11
    mov     QWORD PTR [rsp+88], r10

    ; ---- t6 = 2*a2*a4 + a3^2 ; t7 = 2*a3*a4 ----
    mov     rdx, QWORD PTR [r12+16]
    mulx    r8, r9, QWORD PTR [r12+32]   ; p24: hi=r8, lo=r9
    add     r9, r9                       ; 2*p24_lo
    adc     r8, r8                       ; 2*p24_hi
    mov     rdx, QWORD PTR [r12+24]
    mulx    r10, r11, QWORD PTR [r12+32] ; p34 = a3*a4: hi=r10, lo=r11
    add     r11, r11                     ; 2*p34_lo
    adc     r10, r10                     ; 2*p34_hi
    mov     rdx, QWORD PTR [r12+24]
    mulx    rsi, rdi, QWORD PTR [r12+24] ; a3^2: hi=rsi, lo=rdi
    xor     r15, r15                     ; CF=OF=0
    adcx    r9, rdi                      ; t6_lo += a3^2_lo
    adcx    r8, rsi                      ; t6_hi += a3^2_hi
    mov     QWORD PTR [rsp+96], r9
    mov     QWORD PTR [rsp+104], r8
    mov     QWORD PTR [rsp+112], r11
    mov     QWORD PTR [rsp+120], r10

    ; ---- t8 = a4^2 ----
    mov     rdx, QWORD PTR [r12+32]
    mulx    r8, r9, QWORD PTR [r12+32]
    mov     QWORD PTR [rsp+128], r9
    mov     QWORD PTR [rsp+136], r8

    ; ---- 折叠: t0 += 19*t5 ; t1 += 19*t6 ; t2 += 19*t7 ; t3 += 19*t8 ----
    mov     rdx, 19
    mulx    rbp, rbx, QWORD PTR [rsp+80]
    mov     rax, QWORD PTR [rsp+88]
    imul    rax, rax, 19
    add     rbp, rax
    add     QWORD PTR [rsp+0], rbx
    adc     QWORD PTR [rsp+8], rbp

    mov     rdx, 19
    mulx    rbp, rbx, QWORD PTR [rsp+96]
    mov     rax, QWORD PTR [rsp+104]
    imul    rax, rax, 19
    add     rbp, rax
    add     QWORD PTR [rsp+16], rbx
    adc     QWORD PTR [rsp+24], rbp

    mov     rdx, 19
    mulx    rbp, rbx, QWORD PTR [rsp+112]
    mov     rax, QWORD PTR [rsp+120]
    imul    rax, rax, 19
    add     rbp, rax
    add     QWORD PTR [rsp+32], rbx
    adc     QWORD PTR [rsp+40], rbp

    mov     rdx, 19
    mulx    rbp, rbx, QWORD PTR [rsp+128]
    mov     rax, QWORD PTR [rsp+136]
    imul    rax, rax, 19
    add     rbp, rax
    add     QWORD PTR [rsp+48], rbx
    adc     QWORD PTR [rsp+56], rbp

    ; ---- 51-bit 进位链 ----
    mov     rax, QWORD PTR [rsp+0]
    mov     rcx, QWORD PTR [rsp+8]
    mov     r8, QWORD PTR [rsp+16]
    mov     r9, QWORD PTR [rsp+24]
    mov     r10, QWORD PTR [rsp+32]
    mov     r11, QWORD PTR [rsp+40]
    mov     rbx, QWORD PTR [rsp+48]
    mov     rbp, QWORD PTR [rsp+56]
    mov     rsi, QWORD PTR [rsp+64]
    mov     rdi, QWORD PTR [rsp+72]

    ; c = t0>>51; t0 &= MASK51; t1 += c
    mov     r15, rcx
    shl     r15, 13
    mov     rdx, rax
    shr     rdx, 51
    or      rdx, r15
    shl     rax, 13
    shr     rax, 13
    xor     rcx, rcx
    add     r8, rdx
    adc     r9, 0

    ; c = t1>>51; t1 &= MASK51; t2 += c
    mov     r15, r9
    shl     r15, 13
    mov     rdx, r8
    shr     rdx, 51
    or      rdx, r15
    shl     r8, 13
    shr     r8, 13
    xor     r9, r9
    add     r10, rdx
    adc     r11, 0

    ; c = t2>>51; t2 &= MASK51; t3 += c
    mov     r15, r11
    shl     r15, 13
    mov     rdx, r10
    shr     rdx, 51
    or      rdx, r15
    shl     r10, 13
    shr     r10, 13
    xor     r11, r11
    add     rbx, rdx
    adc     rbp, 0

    ; c = t3>>51; t3 &= MASK51; t4 += c
    mov     r15, rbp
    shl     r15, 13
    mov     rdx, rbx
    shr     rdx, 51
    or      rdx, r15
    shl     rbx, 13
    shr     rbx, 13
    xor     rbp, rbp
    add     rsi, rdx
    adc     rdi, 0

    ; c = t4>>51; t4 &= MASK51; t0 += c*19
    mov     r15, rdi
    shl     r15, 13
    mov     rdx, rsi
    shr     rdx, 51
    or      rdx, r15
    shl     rsi, 13
    shr     rsi, 13
    xor     rdi, rdi
    imul    rdx, rdx, 19
    add     rax, rdx
    adc     rcx, 0

    ; c = t0>>51; t0 &= MASK51; t1 += c
    mov     r15, rcx
    shl     r15, 13
    mov     rdx, rax
    shr     rdx, 51
    or      rdx, r15
    shl     rax, 13
    shr     rax, 13
    xor     rcx, rcx
    add     r8, rdx
    adc     r9, 0

    mov     QWORD PTR [r14], rax
    mov     QWORD PTR [r14+8], r8
    mov     QWORD PTR [r14+16], r10
    mov     QWORD PTR [r14+24], rbx
    mov     QWORD PTR [r14+32], rsi

    add     rsp, 160
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret

fe51_sq_adx ENDP

END
