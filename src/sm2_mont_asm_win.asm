; sm2_mont_asm_win.asm - Windows x64 (masm/ml64) SM2 256-bit Montgomery multiplication
;
;   sm2_mont_mul_adx(rcx=r, rdx=a, r8=b, r9=m, [rsp+40]=mp)   (extern "C")
;
; Computes r = a*b*R^{-1} mod m, R = 2^256, with a,b in [0,m) and the result
; in [0,m). Same CIOS semantics as the portable path in sm2.cpp
; (mul_512 + mont_reduce, modulus m > 2^255 and odd).
;
; Algorithm: fully unrolled 4-limb CIOS Montgomery multiplication using
; MULX (BMI2) plus ADCX/ADOX (ADX) dual carry chains. Consecutive columns
; alternate between the CF chain (ADCX) and the OF chain (ADOX): the lo word
; of each product goes to column k and the hi word to column k+1, and the
; carries of each column flow into the next column through the same chain,
; so the two chains never interfere.
;
; Register map:
;   rcx = r (reloaded from [rsp+88] at the end)
;   rbx = a, rbp = b, rdi = m, rsi = &t[0] (stack)
;   rdx = MULX multiplier (a[i] / u), rax = lo, r13 = hi (consumed by next ADOX)
;   r8..r12 = working columns t[i..i+4]
;   r14 = t[i+5], r15 = 0 (permanent zero)
;   rax/rdx/r13 double as the t[i+6..8] carry-chain columns
;   mp cached at [rsp+80], saved r at [rsp+88]
;
; Stack frame: sub rsp, 96 -> t[0..8] at [rsp+0..71], mp at [rsp+80], r at [rsp+88].
;
; Requires BMI2 (MULX) + ADX (ADCX/ADOX); caller checks sm2_mont_asm_available().

.code

sm2_mont_mul_adx PROC
    mov     r10, QWORD PTR [rsp+40]     ; mp (5th arg, read before pushes)
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 96

    mov     rsi, rsp                    ; rsi = &t[0]
    mov     QWORD PTR [rsp+88], rcx     ; save r (rcx is clobbered below)
    xor     eax, eax
    mov     ecx, 10
    mov     rdi, rsi
    rep stosq                           ; t[0..9] = 0
    mov     QWORD PTR [rsp+80], r10     ; save mp
    mov     rbx, rdx                    ; rbx = a
    mov     rbp, r8                     ; rbp = b
    mov     rdi, r9                     ; rdi = m
    xor     r15d, r15d                  ; r15 = 0 (also clears CF/OF)

    ; ========== i = 0: step 1, t[0..4] += a0 * b[0..3] ==========
    mov     rdx, QWORD PTR [rbx]
    mov     r8,  QWORD PTR [rsi]
    mov     r9,  QWORD PTR [rsi+8]
    mov     r10, QWORD PTR [rsi+16]
    mov     r11, QWORD PTR [rsi+24]
    mov     r12, QWORD PTR [rsi+32]
    xor     eax, eax
    mulx    r13, rax, QWORD PTR [rbp]
    adcx    r8, rax
    adox    r9, r13
    mulx    r13, rax, QWORD PTR [rbp+8]
    adcx    r9, rax
    adox    r10, r13
    mulx    r13, rax, QWORD PTR [rbp+16]
    adcx    r10, rax
    adox    r11, r13
    mulx    r13, rax, QWORD PTR [rbp+24]
    adcx    r11, rax
    adox    r12, r13
    ; propagate: CF -> t4, then CF/OF -> t5..t8
    adcx    r12, r15
    mov     r14, QWORD PTR [rsi+40]
    mov     r13, QWORD PTR [rsi+48]
    adox    r14, r15
    adcx    r14, r15
    mov     rax, QWORD PTR [rsi+56]
    adox    r13, r15
    adcx    r13, r15
    mov     rdx, QWORD PTR [rsi+64]
    adox    rax, r15
    adcx    rax, r15
    adox    rdx, r15
    adcx    rdx, r15
    mov     QWORD PTR [rsi+40], r14
    mov     QWORD PTR [rsi+48], r13
    mov     QWORD PTR [rsi+56], rax
    mov     QWORD PTR [rsi+64], rdx

    ; ========== i = 0: step 2, u = t0*mp, t[0..4] += u*m[0..3] ==========
    mov     rax, QWORD PTR [rsp+80]
    imul    rax, r8
    mov     rdx, rax
    xor     eax, eax
    mulx    r13, rax, QWORD PTR [rdi]
    adcx    r8, rax
    adox    r9, r13
    mulx    r13, rax, QWORD PTR [rdi+8]
    adcx    r9, rax
    adox    r10, r13
    mulx    r13, rax, QWORD PTR [rdi+16]
    adcx    r10, rax
    adox    r11, r13
    mulx    r13, rax, QWORD PTR [rdi+24]
    adcx    r11, rax
    adox    r12, r13
    adcx    r12, r15
    mov     r14, QWORD PTR [rsi+40]
    mov     r13, QWORD PTR [rsi+48]
    adox    r14, r15
    adcx    r14, r15
    mov     rax, QWORD PTR [rsi+56]
    adox    r13, r15
    adcx    r13, r15
    mov     rdx, QWORD PTR [rsi+64]
    adox    rax, r15
    adcx    rax, r15
    adox    rdx, r15
    adcx    rdx, r15
    mov     QWORD PTR [rsi], r8
    mov     QWORD PTR [rsi+8], r9
    mov     QWORD PTR [rsi+16], r10
    mov     QWORD PTR [rsi+24], r11
    mov     QWORD PTR [rsi+32], r12
    mov     QWORD PTR [rsi+40], r14
    mov     QWORD PTR [rsi+48], r13
    mov     QWORD PTR [rsi+56], rax
    mov     QWORD PTR [rsi+64], rdx

    ; ========== i = 1: step 1, t[1..5] += a1 * b[0..3] ==========
    mov     rdx, QWORD PTR [rbx+8]
    mov     r8,  QWORD PTR [rsi+8]
    mov     r9,  QWORD PTR [rsi+16]
    mov     r10, QWORD PTR [rsi+24]
    mov     r11, QWORD PTR [rsi+32]
    mov     r12, QWORD PTR [rsi+40]
    xor     eax, eax
    mulx    r13, rax, QWORD PTR [rbp]
    adcx    r8, rax
    adox    r9, r13
    mulx    r13, rax, QWORD PTR [rbp+8]
    adcx    r9, rax
    adox    r10, r13
    mulx    r13, rax, QWORD PTR [rbp+16]
    adcx    r10, rax
    adox    r11, r13
    mulx    r13, rax, QWORD PTR [rbp+24]
    adcx    r11, rax
    adox    r12, r13
    ; propagate: CF -> t5, then CF/OF -> t6..t8
    adcx    r12, r15
    mov     r14, QWORD PTR [rsi+48]
    mov     r13, QWORD PTR [rsi+56]
    adox    r14, r15
    adcx    r14, r15
    mov     rax, QWORD PTR [rsi+64]
    adox    r13, r15
    adcx    r13, r15
    adox    rax, r15
    adcx    rax, r15
    mov     QWORD PTR [rsi+48], r14
    mov     QWORD PTR [rsi+56], r13
    mov     QWORD PTR [rsi+64], rax

    ; ========== i = 1: step 2, u = t1*mp, t[1..5] += u*m[0..3] ==========
    mov     rax, QWORD PTR [rsp+80]
    imul    rax, r8
    mov     rdx, rax
    xor     eax, eax
    mulx    r13, rax, QWORD PTR [rdi]
    adcx    r8, rax
    adox    r9, r13
    mulx    r13, rax, QWORD PTR [rdi+8]
    adcx    r9, rax
    adox    r10, r13
    mulx    r13, rax, QWORD PTR [rdi+16]
    adcx    r10, rax
    adox    r11, r13
    mulx    r13, rax, QWORD PTR [rdi+24]
    adcx    r11, rax
    adox    r12, r13
    adcx    r12, r15
    mov     r14, QWORD PTR [rsi+48]
    mov     r13, QWORD PTR [rsi+56]
    adox    r14, r15
    adcx    r14, r15
    mov     rax, QWORD PTR [rsi+64]
    adox    r13, r15
    adcx    r13, r15
    adox    rax, r15
    adcx    rax, r15
    mov     QWORD PTR [rsi+8], r8
    mov     QWORD PTR [rsi+16], r9
    mov     QWORD PTR [rsi+24], r10
    mov     QWORD PTR [rsi+32], r11
    mov     QWORD PTR [rsi+40], r12
    mov     QWORD PTR [rsi+48], r14
    mov     QWORD PTR [rsi+56], r13
    mov     QWORD PTR [rsi+64], rax

    ; ========== i = 2: step 1, t[2..6] += a2 * b[0..3] ==========
    mov     rdx, QWORD PTR [rbx+16]
    mov     r8,  QWORD PTR [rsi+16]
    mov     r9,  QWORD PTR [rsi+24]
    mov     r10, QWORD PTR [rsi+32]
    mov     r11, QWORD PTR [rsi+40]
    mov     r12, QWORD PTR [rsi+48]
    xor     eax, eax
    mulx    r13, rax, QWORD PTR [rbp]
    adcx    r8, rax
    adox    r9, r13
    mulx    r13, rax, QWORD PTR [rbp+8]
    adcx    r9, rax
    adox    r10, r13
    mulx    r13, rax, QWORD PTR [rbp+16]
    adcx    r10, rax
    adox    r11, r13
    mulx    r13, rax, QWORD PTR [rbp+24]
    adcx    r11, rax
    adox    r12, r13
    ; propagate: CF -> t6, then CF/OF -> t7..t8
    adcx    r12, r15
    mov     r14, QWORD PTR [rsi+56]
    mov     r13, QWORD PTR [rsi+64]
    adox    r14, r15
    adcx    r14, r15
    adox    r13, r15
    adcx    r13, r15
    mov     QWORD PTR [rsi+56], r14
    mov     QWORD PTR [rsi+64], r13

    ; ========== i = 2: step 2, u = t2*mp, t[2..6] += u*m[0..3] ==========
    mov     rax, QWORD PTR [rsp+80]
    imul    rax, r8
    mov     rdx, rax
    xor     eax, eax
    mulx    r13, rax, QWORD PTR [rdi]
    adcx    r8, rax
    adox    r9, r13
    mulx    r13, rax, QWORD PTR [rdi+8]
    adcx    r9, rax
    adox    r10, r13
    mulx    r13, rax, QWORD PTR [rdi+16]
    adcx    r10, rax
    adox    r11, r13
    mulx    r13, rax, QWORD PTR [rdi+24]
    adcx    r11, rax
    adox    r12, r13
    adcx    r12, r15
    mov     r14, QWORD PTR [rsi+56]
    mov     r13, QWORD PTR [rsi+64]
    adox    r14, r15
    adcx    r14, r15
    adox    r13, r15
    adcx    r13, r15
    mov     QWORD PTR [rsi+16], r8
    mov     QWORD PTR [rsi+24], r9
    mov     QWORD PTR [rsi+32], r10
    mov     QWORD PTR [rsi+40], r11
    mov     QWORD PTR [rsi+48], r12
    mov     QWORD PTR [rsi+56], r14
    mov     QWORD PTR [rsi+64], r13

    ; ========== i = 3: step 1, t[3..7] += a3 * b[0..3] ==========
    mov     rdx, QWORD PTR [rbx+24]
    mov     r8,  QWORD PTR [rsi+24]
    mov     r9,  QWORD PTR [rsi+32]
    mov     r10, QWORD PTR [rsi+40]
    mov     r11, QWORD PTR [rsi+48]
    mov     r12, QWORD PTR [rsi+56]
    xor     eax, eax
    mulx    r13, rax, QWORD PTR [rbp]
    adcx    r8, rax
    adox    r9, r13
    mulx    r13, rax, QWORD PTR [rbp+8]
    adcx    r9, rax
    adox    r10, r13
    mulx    r13, rax, QWORD PTR [rbp+16]
    adcx    r10, rax
    adox    r11, r13
    mulx    r13, rax, QWORD PTR [rbp+24]
    adcx    r11, rax
    adox    r12, r13
    ; propagate: CF -> t7, then CF/OF -> t8
    adcx    r12, r15
    mov     r14, QWORD PTR [rsi+64]
    adox    r14, r15
    adcx    r14, r15
    mov     QWORD PTR [rsi+64], r14

    ; ========== i = 3: step 2, u = t3*mp, t[3..7] += u*m[0..3] ==========
    mov     rax, QWORD PTR [rsp+80]
    imul    rax, r8
    mov     rdx, rax
    xor     eax, eax
    mulx    r13, rax, QWORD PTR [rdi]
    adcx    r8, rax
    adox    r9, r13
    mulx    r13, rax, QWORD PTR [rdi+8]
    adcx    r9, rax
    adox    r10, r13
    mulx    r13, rax, QWORD PTR [rdi+16]
    adcx    r10, rax
    adox    r11, r13
    mulx    r13, rax, QWORD PTR [rdi+24]
    adcx    r11, rax
    adox    r12, r13
    adcx    r12, r15
    mov     r14, QWORD PTR [rsi+64]
    adox    r14, r15
    adcx    r14, r15
    mov     QWORD PTR [rsi+24], r8
    mov     QWORD PTR [rsi+32], r9
    mov     QWORD PTR [rsi+40], r10
    mov     QWORD PTR [rsi+48], r11
    mov     QWORD PTR [rsi+56], r12
    mov     QWORD PTR [rsi+64], r14

    ; ========== result = t[4..7]; conditional subtract if t[8] or r >= m ==========
    mov     r8,  QWORD PTR [rsi+32]
    mov     r9,  QWORD PTR [rsi+40]
    mov     r10, QWORD PTR [rsi+48]
    mov     r11, QWORD PTR [rsi+56]
    mov     rax, QWORD PTR [rsi+64]
    test    rax, rax
    jnz     sm2_sub
    cmp     r11, QWORD PTR [rdi+24]
    ja      sm2_sub
    jb      sm2_done
    cmp     r10, QWORD PTR [rdi+16]
    ja      sm2_sub
    jb      sm2_done
    cmp     r9, QWORD PTR [rdi+8]
    ja      sm2_sub
    jb      sm2_done
    cmp     r8, QWORD PTR [rdi]
    jb      sm2_done
sm2_sub:
    xor     eax, eax                    ; CF = 0
    sbb     r8, QWORD PTR [rdi]
    sbb     r9, QWORD PTR [rdi+8]
    sbb     r10, QWORD PTR [rdi+16]
    sbb     r11, QWORD PTR [rdi+24]
sm2_done:
    mov     rcx, QWORD PTR [rsp+88]
    mov     QWORD PTR [rcx], r8
    mov     QWORD PTR [rcx+8], r9
    mov     QWORD PTR [rcx+16], r10
    mov     QWORD PTR [rcx+24], r11
    add     rsp, 96
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret
sm2_mont_mul_adx ENDP

END
