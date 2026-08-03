; fe51_mul_adx.asm - Windows x64 (masm/ml64) radix-2^51 域乘法
; r = a*b mod p, p = 2^255 - 19
;
; 调用约定: Microsoft x64
;   fe51_mul_adx(rcx=r, rdx=a, r8=b)    (extern "C")
;
; MULX (BMI2) + ADCX/ADOX 双进位链:
;   偶数列 t0,t2,t4,t6,t8 用 ADCX (CF 链)
;   奇数列 t1,t3,t5,t7 用 ADOX (OF 链)
;   两条进位链互不干扰, 交错累加提升 ILP
;
; 输入 limb 允许 [0, 2^53), 输出每个 limb < 2^51 + eps (与 C 版本一致)

.code

fe51_mul_adx PROC
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 160                    ; t0..t8 各 16 字节 = 144B + 对齐余量

    mov     r12, rdx                    ; r12 = a
    mov     r13, r8                     ; r13 = b
    mov     r14, rcx                    ; r14 = r

    ; ---- 列对 (t0, t1): t0 = a0*b0 ; t1 = a0*b1 + a1*b0 ----
    mov     rdx, QWORD PTR [r12]
    mulx    r8, r9, QWORD PTR [r13]      ; t0 = a0*b0: hi=r8, lo=r9
    mulx    r10, r11, QWORD PTR [r13+8]  ; a0*b1: hi=r10, lo=r11
    mov     rdx, QWORD PTR [r12+8]
    mulx    rbx, rbp, QWORD PTR [r13]    ; a1*b0: hi=rbx, lo=rbp
    xor     rax, rax                    ; CF=OF=0
    adox    r11, rbp                    ; t1_lo += (OF 链)
    adox    r10, rbx                    ; t1_hi +=
    mov     QWORD PTR [rsp+0], r9
    mov     QWORD PTR [rsp+8], r8
    mov     QWORD PTR [rsp+16], r11
    mov     QWORD PTR [rsp+24], r10

    ; ---- 列对 (t2, t3): t2 = a0*b2 + a1*b1 + a2*b0 ; t3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 ----
    mov     rdx, QWORD PTR [r12]
    mulx    r8, r9, QWORD PTR [r13+16]   ; t2 = a0*b2: hi=r8, lo=r9
    mulx    r10, r11, QWORD PTR [r13+24] ; t3 = a0*b3: hi=r10, lo=r11
    xor     rax, rax
    mov     rdx, QWORD PTR [r12+8]
    mulx    rsi, rdi, QWORD PTR [r13+8]  ; a1*b1: hi=rsi, lo=rdi
    adcx    r9, rdi                     ; t2_lo += (CF 链)
    mulx    rcx, rax, QWORD PTR [r13+16] ; a1*b2: hi=rcx, lo=rax
    adox    r11, rax                    ; t3_lo += (OF 链)
    adcx    r8, rsi                     ; t2_hi +=
    adox    r10, rcx                    ; t3_hi +=
    mov     rdx, QWORD PTR [r12+16]
    mulx    rsi, rdi, QWORD PTR [r13]    ; a2*b0: hi=rsi, lo=rdi
    adcx    r9, rdi
    mulx    rcx, rax, QWORD PTR [r13+8]  ; a2*b1: hi=rcx, lo=rax
    adox    r11, rax
    adcx    r8, rsi
    adox    r10, rcx
    mov     rdx, QWORD PTR [r12+24]
    mulx    rcx, rax, QWORD PTR [r13]    ; a3*b0: hi=rcx, lo=rax
    adox    r11, rax
    adox    r10, rcx
    mov     QWORD PTR [rsp+32], r9
    mov     QWORD PTR [rsp+40], r8
    mov     QWORD PTR [rsp+48], r11
    mov     QWORD PTR [rsp+56], r10

    ; ---- 列对 (t4, t5): t4 = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0
    ;                        t5 = a1*b4 + a2*b3 + a3*b2 + a4*b1 ----
    mov     rdx, QWORD PTR [r12]
    mulx    r8, r9, QWORD PTR [r13+32]   ; t4 = a0*b4: hi=r8, lo=r9
    xor     rax, rax
    mov     rdx, QWORD PTR [r12+8]
    mulx    r10, r11, QWORD PTR [r13+32] ; t5 = a1*b4: hi=r10, lo=r11
    mulx    rsi, rdi, QWORD PTR [r13+24] ; a1*b3: hi=rsi, lo=rdi
    adcx    r9, rdi                     ; t4_lo +=
    adcx    r8, rsi                     ; t4_hi +=
    mov     rdx, QWORD PTR [r12+16]
    mulx    rsi, rdi, QWORD PTR [r13+24] ; a2*b3: hi=rsi, lo=rdi
    adox    r11, rdi                    ; t5_lo +=
    adox    r10, rsi                    ; t5_hi +=
    mulx    rsi, rdi, QWORD PTR [r13+16] ; a2*b2: hi=rsi, lo=rdi
    adcx    r9, rdi                     ; t4_lo +=
    adcx    r8, rsi                     ; t4_hi +=
    mov     rdx, QWORD PTR [r12+24]
    mulx    rsi, rdi, QWORD PTR [r13+16] ; a3*b2: hi=rsi, lo=rdi
    adox    r11, rdi                    ; t5_lo +=
    adox    r10, rsi                    ; t5_hi +=
    mulx    rsi, rdi, QWORD PTR [r13+8]  ; a3*b1: hi=rsi, lo=rdi
    adcx    r9, rdi                     ; t4_lo +=
    adcx    r8, rsi                     ; t4_hi +=
    mov     rdx, QWORD PTR [r12+32]
    mulx    rsi, rdi, QWORD PTR [r13+8]  ; a4*b1: hi=rsi, lo=rdi
    adox    r11, rdi                    ; t5_lo +=
    adox    r10, rsi                    ; t5_hi +=
    mulx    rsi, rdi, QWORD PTR [r13]    ; a4*b0: hi=rsi, lo=rdi
    adcx    r9, rdi                     ; t4_lo +=
    adcx    r8, rsi                     ; t4_hi +=
    mov     QWORD PTR [rsp+64], r9
    mov     QWORD PTR [rsp+72], r8
    mov     QWORD PTR [rsp+80], r11
    mov     QWORD PTR [rsp+88], r10

    ; ---- 列对 (t6, t7): t6 = a2*b4 + a3*b3 + a4*b2 ; t7 = a3*b4 + a4*b3 ----
    mov     rdx, QWORD PTR [r12+16]
    mulx    r8, r9, QWORD PTR [r13+32]   ; t6 = a2*b4: hi=r8, lo=r9
    xor     rax, rax
    mov     rdx, QWORD PTR [r12+24]
    mulx    r10, r11, QWORD PTR [r13+32] ; t7 = a3*b4: hi=r10, lo=r11
    mulx    rsi, rdi, QWORD PTR [r13+24] ; a3*b3: hi=rsi, lo=rdi
    adcx    r9, rdi                     ; t6_lo +=
    adcx    r8, rsi                     ; t6_hi +=
    mov     rdx, QWORD PTR [r12+32]
    mulx    rsi, rdi, QWORD PTR [r13+24] ; a4*b3: hi=rsi, lo=rdi
    adox    r11, rdi                    ; t7_lo +=
    adox    r10, rsi                    ; t7_hi +=
    mulx    rsi, rdi, QWORD PTR [r13+16] ; a4*b2: hi=rsi, lo=rdi
    adcx    r9, rdi                     ; t6_lo +=
    adcx    r8, rsi                     ; t6_hi +=
    mov     QWORD PTR [rsp+96], r9
    mov     QWORD PTR [rsp+104], r8
    mov     QWORD PTR [rsp+112], r11
    mov     QWORD PTR [rsp+120], r10

    ; ---- t8 = a4*b4 ----
    mov     rdx, QWORD PTR [r12+32]
    mulx    r8, r9, QWORD PTR [r13+32]
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

fe51_mul_adx ENDP

END
