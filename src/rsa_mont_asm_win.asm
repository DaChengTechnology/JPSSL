; rsa_mont_asm_win.asm — Windows x64 (masm/ml64) CIOS Montgomery 乘法
;
; 与 Linux 版 (rsa_mont_asm.cpp 内联汇编) 等价的手写汇编:
; MULX (BMI2) + 进位链加速 CIOS 循环, K=32 (2048-bit) / K=64 (4096-bit)。
;
; 调用约定: Microsoft x64
;   mont_mul_k32_asm(rcx=r, rdx=a, r8=b, r9=m, [rsp+40]=mp)
;   mont_mul_k64_asm(rcx=r, rdx=a, r8=b, r9=m, [rsp+40]=mp)
;
; 寄存器分配:
;   r12=r, r13=a, r14=b, r15=m, rbp=&t[0], rsi=mp(持久)
;   rbx=i (外循环), rcx=j (内循环), r8=&t[i] / 临时, r9=循环上限
;   rax/r10=乘积结果, r11=carry, rdi=stos/进位传播指针
; callee-saved (Windows): rbx, rbp, rdi, rsi, r12-r15 -> 全部 push/pop

.code

; ─────────────────────────────────────────────────────────────────────────
;  K=32 (2048-bit): t[66] = 2*32+2
;  t[0..31] 低半, t[32..63] 高半, t[64..65] 进位传播
; ─────────────────────────────────────────────────────────────────────────

mont_mul_k32_asm PROC
    mov     r10, QWORD PTR [rsp+40]   ; mp (在 push 之前取参数)
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 536                  ; t[66] = 528B + 8B 对齐

    mov     rsi, r10                  ; rsi = mp (r10 会被内循环 mulx 破坏)
    mov     r12, rcx                  ; r12 = r
    mov     r13, rdx                  ; r13 = a
    mov     r14, r8                   ; r14 = b
    mov     r15, r9                   ; r15 = m
    lea     rbp, [rsp+8]              ; rbp = &t[0]

    ; -- 清零 t[0..65] --
    xor     eax, eax
    mov     ecx, 66
    mov     rdi, rbp
    rep stosq

    ; -- 外循环 i = 0..31 --
    xor     ebx, ebx                  ; ebx = i
    mov     r9d, 32                   ; 循环上限

outer32:
    ; ========== Step 1: a[i] * b[0..31] (dual carry chain, 2x unrolled) ==========
    mov     rdx, QWORD PTR [r13+rbx*8]  ; rdx = a[i]
    xor     r11d, r11d                  ; carry into even limb
    xor     ecx, ecx                    ; j
    lea     r8, [rbp+rbx*8]             ; r8 = &t[i]

s1_loop32:
    mulx    r10, rax, QWORD PTR [r14+rcx*8]    ; even: a[i]*b[j]
    add     rax, QWORD PTR [r8+rcx*8]
    adc     r10, 0
    add     rax, r11
    adc     r10, 0
    mov     QWORD PTR [r8+rcx*8], rax
    mulx    rdi, r9, QWORD PTR [r14+rcx*8+8]   ; odd: a[i]*b[j+1]
    add     r9, QWORD PTR [r8+rcx*8+8]
    adc     rdi, 0
    add     r9, r10                     ; odd cell += even carry
    adc     rdi, 0
    mov     QWORD PTR [r8+rcx*8+8], r9
    mov     r11, rdi                    ; carry into next even limb
    add     ecx, 2
    cmp     ecx, 32
    jl      s1_loop32

    ; t[i+32] += carry (overflow propagation, same as original)
    lea     rdi, [rbp+rbx*8+256]
    add     QWORD PTR [rdi], r11
    jnc     carry_skip32
    mov     r11d, 1
s1_prop32:
    add     rdi, 8
    add     QWORD PTR [rdi], r11
    jc      s1_prop32
carry_skip32:

    ; ========== Step 2: u * m[0..31], u = t[i]*mp (low 64) ==========
    mov     rax, QWORD PTR [rbp+rbx*8]
    mul     rsi
    mov     rdx, rax
    xor     r11d, r11d                  ; carry into even limb
    xor     ecx, ecx                    ; j
    lea     r8, [rbp+rbx*8]             ; r8 = &t[i]

s2_loop32:
    mulx    r10, rax, QWORD PTR [r15+rcx*8]    ; even: a[i]*b[j]
    add     rax, QWORD PTR [r8+rcx*8]
    adc     r10, 0
    add     rax, r11
    adc     r10, 0
    mov     QWORD PTR [r8+rcx*8], rax
    mulx    rdi, r9, QWORD PTR [r15+rcx*8+8]   ; odd: a[i]*b[j+1]
    add     r9, QWORD PTR [r8+rcx*8+8]
    adc     rdi, 0
    add     r9, r10                     ; odd cell += even carry
    adc     rdi, 0
    mov     QWORD PTR [r8+rcx*8+8], r9
    mov     r11, rdi                    ; carry into next even limb
    add     ecx, 2
    cmp     ecx, 32
    jl      s2_loop32

    ; t[i+32] += carry (overflow propagation, same as original)
    lea     rdi, [rbp+rbx*8+256]
    add     QWORD PTR [rdi], r11
    jnc     carry_done32
    mov     r11d, 1
s2_prop32:
    add     rdi, 8
    add     QWORD PTR [rdi], r11
    jc      s2_prop32
carry_done32:

    inc     ebx
    cmp     ebx, 32
    jl      outer32

    ; ========== 写入结果 r = t[32..63] ==========
    xor     ecx, ecx
copy32:
    mov     rax, QWORD PTR [rbp+rcx*8+256]   ; rax = t[32+i]
    mov     QWORD PTR [r12+rcx*8], rax
    inc     ecx
    cmp     ecx, 32
    jl      copy32

    ; ========== 条件减法: if (r >= m) r -= m ==========
    mov     r8, QWORD PTR [rbp+512]          ; t[64]
    test    r8, r8
    jnz     do_sub1_32

    ; 比较 r 和 m (从高位到低位)
    mov     ecx, 31
cmp_loop32:
    mov     rax, QWORD PTR [r12+rcx*8]
    cmp     rax, QWORD PTR [r15+rcx*8]
    ja      do_sub1_32
    jb      done32
    dec     ecx
    jns     cmp_loop32
    jmp     done32

do_sub1_32:
    xor     r11d, r11d                      ; borrow = 0 (CF=0)
    mov     r9d, 32
    xor     ecx, ecx
sub_loop32:
    mov     rax, QWORD PTR [r12+rcx*8]
    sbb     rax, QWORD PTR [r15+rcx*8]
    mov     QWORD PTR [r12+rcx*8], rax
    inc     ecx
    dec     r9d                             ; 不修改 CF (cmp 会破坏借位!)
    jnz     sub_loop32

    ; 二次检查
    mov     r9, QWORD PTR [r12+31*8]
    cmp     r9, QWORD PTR [r15+31*8]
    jb      done32
    xor     r11d, r11d
    mov     r9d, 32
    xor     ecx, ecx
sub2_loop32:
    mov     rax, QWORD PTR [r12+rcx*8]
    sbb     rax, QWORD PTR [r15+rcx*8]
    mov     QWORD PTR [r12+rcx*8], rax
    inc     ecx
    dec     r9d                             ; 不修改 CF
    jnz     sub2_loop32

done32:
    add     rsp, 536
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret

mont_mul_k32_asm ENDP

; ─────────────────────────────────────────────────────────────────────────
;  K=64 (4096-bit): t[130] = 2*64+2
;  t[0..63] 低半, t[64..127] 高半, t[128..129] 进位传播
; ─────────────────────────────────────────────────────────────────────────

mont_mul_k64_asm PROC
    mov     r10, QWORD PTR [rsp+40]   ; mp
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 1048                 ; t[130] = 1040B + 8B 对齐

    mov     rsi, r10                  ; rsi = mp (r10 会被内循环 mulx 破坏)
    mov     r12, rcx                  ; r12 = r
    mov     r13, rdx                  ; r13 = a
    mov     r14, r8                   ; r14 = b
    mov     r15, r9                   ; r15 = m
    lea     rbp, [rsp+8]              ; rbp = &t[0]

    ; -- 清零 t[0..129] --
    xor     eax, eax
    mov     ecx, 130
    mov     rdi, rbp
    rep stosq

    ; -- 外循环 i = 0..63 --
    xor     ebx, ebx                  ; ebx = i
    mov     r9d, 64                   ; 循环上限

outer64:
    ; ========== Step 1: a[i] * b[0..63] (dual carry chain, 2x unrolled) ==========
    mov     rdx, QWORD PTR [r13+rbx*8]  ; rdx = a[i]
    xor     r11d, r11d                  ; carry into even limb
    xor     ecx, ecx                    ; j
    lea     r8, [rbp+rbx*8]             ; r8 = &t[i]

s1_loop64:
    mulx    r10, rax, QWORD PTR [r14+rcx*8]    ; even: a[i]*b[j]
    add     rax, QWORD PTR [r8+rcx*8]
    adc     r10, 0
    add     rax, r11
    adc     r10, 0
    mov     QWORD PTR [r8+rcx*8], rax
    mulx    rdi, r9, QWORD PTR [r14+rcx*8+8]   ; odd: a[i]*b[j+1]
    add     r9, QWORD PTR [r8+rcx*8+8]
    adc     rdi, 0
    add     r9, r10                     ; odd cell += even carry
    adc     rdi, 0
    mov     QWORD PTR [r8+rcx*8+8], r9
    mov     r11, rdi                    ; carry into next even limb
    add     ecx, 2
    cmp     ecx, 64
    jl      s1_loop64

    ; t[i+64] += carry (overflow propagation, same as original)
    lea     rdi, [rbp+rbx*8+512]
    add     QWORD PTR [rdi], r11
    jnc     carry_skip64
    mov     r11d, 1
s1_prop64:
    add     rdi, 8
    add     QWORD PTR [rdi], r11
    jc      s1_prop64
carry_skip64:

    ; ========== Step 2: u * m[0..63], u = t[i]*mp (low 64) ==========
    mov     rax, QWORD PTR [rbp+rbx*8]
    mul     rsi
    mov     rdx, rax
    xor     r11d, r11d                  ; carry into even limb
    xor     ecx, ecx                    ; j
    lea     r8, [rbp+rbx*8]             ; r8 = &t[i]

s2_loop64:
    mulx    r10, rax, QWORD PTR [r15+rcx*8]    ; even: a[i]*b[j]
    add     rax, QWORD PTR [r8+rcx*8]
    adc     r10, 0
    add     rax, r11
    adc     r10, 0
    mov     QWORD PTR [r8+rcx*8], rax
    mulx    rdi, r9, QWORD PTR [r15+rcx*8+8]   ; odd: a[i]*b[j+1]
    add     r9, QWORD PTR [r8+rcx*8+8]
    adc     rdi, 0
    add     r9, r10                     ; odd cell += even carry
    adc     rdi, 0
    mov     QWORD PTR [r8+rcx*8+8], r9
    mov     r11, rdi                    ; carry into next even limb
    add     ecx, 2
    cmp     ecx, 64
    jl      s2_loop64

    ; t[i+64] += carry (overflow propagation, same as original)
    lea     rdi, [rbp+rbx*8+512]
    add     QWORD PTR [rdi], r11
    jnc     carry_done64
    mov     r11d, 1
s2_prop64:
    add     rdi, 8
    add     QWORD PTR [rdi], r11
    jc      s2_prop64
carry_done64:

    inc     ebx
    cmp     ebx, 64
    jl      outer64

    ; ========== 写入结果 r = t[64..127] ==========
    xor     ecx, ecx
copy64:
    mov     rax, QWORD PTR [rbp+rcx*8+512]
    mov     QWORD PTR [r12+rcx*8], rax
    inc     ecx
    cmp     ecx, 64
    jl      copy64

    ; ========== 条件减法 ==========
    mov     r8, QWORD PTR [rbp+1024]         ; t[128]
    test    r8, r8
    jnz     do_sub1_64

    mov     ecx, 63
cmp_loop64:
    mov     rax, QWORD PTR [r12+rcx*8]
    cmp     rax, QWORD PTR [r15+rcx*8]
    ja      do_sub1_64
    jb      done64
    dec     ecx
    jns     cmp_loop64
    jmp     done64

do_sub1_64:
    xor     r11d, r11d                      ; borrow = 0 (CF=0)
    mov     r9d, 64
    xor     ecx, ecx
sub_loop64:
    mov     rax, QWORD PTR [r12+rcx*8]
    sbb     rax, QWORD PTR [r15+rcx*8]
    mov     QWORD PTR [r12+rcx*8], rax
    inc     ecx
    dec     r9d                             ; 不修改 CF
    jnz     sub_loop64

    mov     r9, QWORD PTR [r12+63*8]
    cmp     r9, QWORD PTR [r15+63*8]
    jb      done64
    xor     r11d, r11d
    mov     r9d, 64
    xor     ecx, ecx
sub2_loop64:
    mov     rax, QWORD PTR [r12+rcx*8]
    sbb     rax, QWORD PTR [r15+rcx*8]
    mov     QWORD PTR [r12+rcx*8], rax
    inc     ecx
    dec     r9d                             ; 不修改 CF
    jnz     sub2_loop64

done64:
    add     rsp, 1048
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret

mont_mul_k64_asm ENDP

; ─────────────────────────────────────────────────────────────────────────
;  半尺寸 Montgomery 乘法 (CRT 的 p/q 模幂专用)
;
;  与 mont_mul_k32/k64_asm 同构, 但只处理前 HK = K/2 个 limb:
;    - 外循环 HK 次, 内循环 (step1+step2) 各 HK 次 MULX
;    - t 数组 (2*HK+2) 个 limb, HK<=32 时分配 66 个
;    - 结果 r[0..HK-1] = t[HK..2HK-1], 高 HK 位清零 (半尺寸语义)
;    - 条件减法为半尺寸 (HK-limb) 减法, 借位丢弃
;
; 用宏生成两个静态实例 (HK 为立即数, 循环上限零开销):
;    mont_mul_half_k16_asm(rcx=r, rdx=a, r8=b, r9=m, [rsp+40]=mp)  ; 1024-bit
;    mont_mul_half_k32_asm(rcx=r, rdx=a, r8=b, r9=m, [rsp+40]=mp)  ; 2048-bit
; ─────────────────────────────────────────────────────────────────────────

MONT_MUL_HALF MACRO name, HK
    LOCAL outer, s1_loop, s1_prop, s2_start, s2_loop, cprop, cdone, copy, cmp1, do_sub, sub_loop, cmp2, do_sub2, sub2_loop, done

name PROC
    mov     r10, QWORD PTR [rsp+40]   ; mp (push 之前取参数)
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 536                  ; t[66] = 528B + 8B 对齐

    mov     rsi, r10                  ; rsi = mp (r10 会被内循环 mulx 破坏)
    mov     r12, rcx                  ; r12 = r
    mov     r13, rdx                  ; r13 = a
    mov     r14, r8                   ; r14 = b
    mov     r15, r9                   ; r15 = m
    lea     rbp, [rsp+8]              ; rbp = &t[0]

    ; -- 清零 t[0 .. 2*HK+1] --
    xor     eax, eax
    mov     ecx, 2*HK+2
    mov     rdi, rbp
    rep stosq

    ; -- 外循环 i = 0..HK-1 --
    xor     ebx, ebx                  ; ebx = i

outer:
    ; ========== Step 1: a[i] * b[0..HK-1] ==========
    mov     rdx, QWORD PTR [r13+rbx*8]  ; rdx = a[i]
    xor     r11d, r11d                  ; r11 = carry
    xor     ecx, ecx                    ; ecx = j
    lea     r8, [rbp+rbx*8]             ; r8 = &t[i]

s1_loop:
    mulx    r9, rax, QWORD PTR [r14+rcx*8]  ; r9:rax = a[i]*b[j]
    add     rax, QWORD PTR [r8+rcx*8]        ; rax += t[i+j]
    adc     r9, 0
    add     rax, r11                         ; rax += carry
    adc     r9, 0
    mov     QWORD PTR [r8+rcx*8], rax        ; t[i+j] = lo
    mov     r11, r9                          ; carry = hi
    inc     ecx
    cmp     ecx, HK
    jl      s1_loop

    ; t[i+HK] += carry (累加), 溢出向高位传播
    lea     rdi, [rbp+rbx*8]
    lea     rdi, [rdi+HK*8]
    add     QWORD PTR [rdi], r11
    jnc     s2_start
    mov     r11d, 1
s1_prop:
    add     rdi, 8
    add     QWORD PTR [rdi], r11
    jc      s1_prop
s2_start:

    ; ========== Step 2: u * m[0..HK-1], u = t[i]*mp (低 64) ==========
    mov     rax, QWORD PTR [rbp+rbx*8]       ; rax = t[i]
    mul     rsi                              ; rdx:rax = t[i] * mp
    mov     rdx, rax                         ; rdx = u
    xor     r11d, r11d                       ; r11 = carry
    xor     ecx, ecx                         ; ecx = j
    lea     r8, [rbp+rbx*8]                  ; r8 = &t[i]

s2_loop:
    mulx    r9, rax, QWORD PTR [r15+rcx*8]   ; r9:rax = u*m[j]
    add     rax, QWORD PTR [r8+rcx*8]        ; rax += t[i+j]
    adc     r9, 0
    add     rax, r11                         ; rax += carry
    adc     r9, 0
    mov     QWORD PTR [r8+rcx*8], rax        ; t[i+j] = lo
    mov     r11, r9                          ; carry = hi
    inc     ecx
    cmp     ecx, HK
    jl      s2_loop

    ; -- 进位传播 t[i+HK..] --
    lea     rdi, [rbp+rbx*8]
    lea     rdi, [rdi+HK*8]                  ; rdi = &t[i+HK]
cprop:
    add     QWORD PTR [rdi], r11
    jnc     cdone
    mov     r11d, 1
    add     rdi, 8
    jmp     cprop
cdone:

    inc     ebx
    cmp     ebx, HK
    jl      outer

    ; ========== 写入结果 r[0..HK-1] = t[HK..2HK-1] ==========
    lea     rdi, [rbp+HK*8]                  ; rdi = &t[HK]
    xor     ecx, ecx
copy:
    mov     rax, QWORD PTR [rdi+rcx*8]
    mov     QWORD PTR [r12+rcx*8], rax
    inc     ecx
    cmp     ecx, HK
    jl      copy

    ; 半尺寸输出要求: 高位 r[HK..2HK-1] 清零
    lea     rdi, [r12+HK*8]
    xor     eax, eax
    mov     ecx, HK
    rep stosq

    ; ========== 条件减法 (半尺寸, HK-limb) ==========
    ; t[2*HK] 非零 → 至少减一次; 否则完整比较 r 与 m (高位优先)
    lea     rdi, [rbp+HK*8]
    mov     r8, QWORD PTR [rdi+HK*8]         ; r8 = t[2*HK]
    test    r8, r8
    jnz     do_sub

    mov     ecx, HK-1
cmp1:
    mov     rax, QWORD PTR [r12+rcx*8]
    cmp     rax, QWORD PTR [r15+rcx*8]
    ja      do_sub
    jb      done
    dec     ecx
    jns     cmp1
    ; 全部相等 → r == m → 减一次 (结果为 0)

do_sub:
    xor     r11d, r11d                      ; CF = 0
    xor     ecx, ecx
    mov     r10d, HK
sub_loop:
    mov     rax, QWORD PTR [r12+rcx*8]
    sbb     rax, QWORD PTR [r15+rcx*8]
    mov     QWORD PTR [r12+rcx*8], rax
    inc     ecx
    dec     r10d                            ; 不修改 CF
    jnz     sub_loop

    ; 二次检查 (CIOS 保证输出 < 2m, 最多再减一次)
    mov     ecx, HK-1
cmp2:
    mov     rax, QWORD PTR [r12+rcx*8]
    cmp     rax, QWORD PTR [r15+rcx*8]
    ja      do_sub2
    jb      done
    dec     ecx
    jns     cmp2
    ; 全部相等 → r == m → 再减一次 (结果为 0)

do_sub2:
    xor     r11d, r11d
    xor     ecx, ecx
    mov     r10d, HK
sub2_loop:
    mov     rax, QWORD PTR [r12+rcx*8]
    sbb     rax, QWORD PTR [r15+rcx*8]
    mov     QWORD PTR [r12+rcx*8], rax
    inc     ecx
    dec     r10d
    jnz     sub2_loop

done:
    add     rsp, 536
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret
name ENDP
ENDM

MONT_MUL_HALF mont_mul_half_k16_asm, 16
MONT_MUL_HALF mont_mul_half_k32_asm, 32

; =====================================================================
;  FIOS Montgomery multiplication (4-way unrolled, ADCX/ADOX)
;  r = a*b*R^{-1} mod m,  R = 2^(K*64)
;  Ported from OpenSSL x86_64-mont.pl bn_mulx4x_mont (CryptoGams).
;  Register map: aptr=rsi bptr=rdi nptr=rcx tptr=rbx mi=r8 bi=r9 zero=rbp num=rax
;  args: rcx=r, rdx=a, r8=b, r9=m, [rsp+40]=mp, [rsp+48]=K
mont_mul_fios_asm PROC
	mov	r10, QWORD PTR [rsp+40]		; mp
	mov	eax, DWORD PTR [rsp+48]		; K (limbs) - 32-bit arg, zero-extend
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	push	rsi
	push	rdi
	mov	r11, rsp			; save original rsp (after pushes)
	sub	rsp, 640
	mov	QWORD PTR [rsp+40], r11		; frame slot = original rsp (r11 reused below)
	; frame: +0 num_bytes, +8 saved &b[i], +16 end of b,
	;        +24 mp, +32 rp, +40 saved rsp, +48 inner counter, +64 t[65]
	mov	QWORD PTR [rsp+32], rcx		; rp = r
	mov	rsi, rdx			; aptr = a
	mov	rdx, r8				; bp = b (core uses rdx as original b)
	mov	rcx, r9				; nptr = m
	mov	QWORD PTR [rsp+24], r10		; mp
	shl	rax, 3				; num_bytes = K*8
	mov	QWORD PTR [rsp+0], rax
	mov	r11, rdx
	add	r11, rax
	mov	QWORD PTR [rsp+16], r11		; end of b
	shr	rax, 5				; K/4
	sub	rax, 1
	mov	QWORD PTR [rsp+48], rax		; inner counter
	lea	rbx, [rsp+64]
	xor	eax, eax
	mov	ecx, 66
	mov	rdi, rbx
	rep stosq				; zero t[0..65]
	mov	rdi, rdx			; bptr = b
	mov	rcx, r9				; nptr = m (restore after stos)

fios_body:
lea rdi, [rdx+8]
mov rdx, QWORD PTR [rdx]
lea rbx, [rsp+96]
mov r9, rdx
mulx rax, r8, QWORD PTR [rsi]
mulx r14, r11, QWORD PTR [rsi+8]
add r11, rax
mov QWORD PTR [rsp+8], rdi
mulx r13, r12, QWORD PTR [rsi+16]
adc r12, r14
adc r13, 0
mov rdi, r8
imul r8, QWORD PTR [rsp+24]
xor rbp, rbp
mulx r14, rax, QWORD PTR [rsi+24]
mov rdx, r8
lea rsi, [rsi+32]
adcx r13, rax
adcx r14, rbp
mulx r10, rax, QWORD PTR [rcx]
adcx rdi, rax
adox r10, r11
mulx r11, rax, QWORD PTR [rcx+8]
adcx r10, rax
adox r11, r12
DB 196, 98, 251, 246, 161, 16, 0, 0, 0
mov rdi, QWORD PTR [rsp+48]
mov QWORD PTR [rbx-32], r10
adcx r11, rax
adox r12, r13
mulx r15, rax, QWORD PTR [rcx+24]
mov rdx, r9
mov QWORD PTR [rbx-24], r11
adcx r12, rax
adox r15, rbp
lea rcx, [rcx+32]
mov QWORD PTR [rbx-16], r12
jmp fios_1st
align 16
fios_1st:
adcx r15, rbp
mulx rax, r10, QWORD PTR [rsi]
adcx r10, r14
mulx r14, r11, QWORD PTR [rsi+8]
adcx r11, rax
mulx rax, r12, QWORD PTR [rsi+16]
adcx r12, r14
mulx r14, r13, QWORD PTR [rsi+24]
DB 103, 103
mov rdx, r8
adcx r13, rax
adcx r14, rbp
lea rsi, [rsi+32]
lea rbx, [rbx+32]
adox r10, r15
mulx r15, rax, QWORD PTR [rcx]
adcx r10, rax
adox r11, r15
mulx r15, rax, QWORD PTR [rcx+8]
adcx r11, rax
adox r12, r15
mulx r15, rax, QWORD PTR [rcx+16]
mov QWORD PTR [rbx-40], r10
adcx r12, rax
mov QWORD PTR [rbx-32], r11
adox r13, r15
mulx r15, rax, QWORD PTR [rcx+24]
mov rdx, r9
mov QWORD PTR [rbx-24], r12
adcx r13, rax
adox r15, rbp
lea rcx, [rcx+32]
mov QWORD PTR [rbx-16], r13
dec rdi
jnz fios_1st
mov rax, QWORD PTR [rsp]
mov rdi, QWORD PTR [rsp+8]
adc r15, rbp
add r14, r15
sbb r15, r15
mov QWORD PTR [rbx-8], r14
jmp fios_outer
align 16
fios_outer:
mov rdx, QWORD PTR [rdi]
lea rdi, [rdi+8]
sub rsi, rax
mov QWORD PTR [rbx], r15
lea rbx, [rsp+96]
sub rcx, rax
mulx r11, r8, QWORD PTR [rsi]
xor ebp, ebp
mov r9, rdx
mulx r12, r14, QWORD PTR [rsi+8]
adox r8, QWORD PTR [rbx-32]
adcx r11, r14
mulx r13, r15, QWORD PTR [rsi+16]
adox r11, QWORD PTR [rbx-24]
adcx r12, r15
adox r12, QWORD PTR [rbx-16]
adcx r13, rbp
adox r13, rbp
mov QWORD PTR [rsp+8], rdi
mov r15, r8
imul r8, QWORD PTR [rsp+24]
xor ebp, ebp
mulx r14, rax, QWORD PTR [rsi+24]
mov rdx, r8
adcx r13, rax
adox r13, QWORD PTR [rbx-8]
adcx r14, rbp
lea rsi, [rsi+32]
adox r14, rbp
mulx r10, rax, QWORD PTR [rcx]
adcx r15, rax
adox r10, r11
mulx r11, rax, QWORD PTR [rcx+8]
adcx r10, rax
adox r11, r12
mulx r12, rax, QWORD PTR [rcx+16]
mov QWORD PTR [rbx-32], r10
adcx r11, rax
adox r12, r13
mulx r15, rax, QWORD PTR [rcx+24]
mov rdx, r9
mov QWORD PTR [rbx-24], r11
lea rcx, [rcx+32]
adcx r12, rax
adox r15, rbp
mov rdi, QWORD PTR [rsp+48]
mov QWORD PTR [rbx-16], r12
jmp fios_inner
align 16
fios_inner:
mulx rax, r10, QWORD PTR [rsi]
adcx r15, rbp
adox r10, r14
mulx r14, r11, QWORD PTR [rsi+8]
adcx r10, QWORD PTR [rbx]
adox r11, rax
mulx rax, r12, QWORD PTR [rsi+16]
adcx r11, QWORD PTR [rbx+8]
adox r12, r14
mulx r14, r13, QWORD PTR [rsi+24]
mov rdx, r8
adcx r12, QWORD PTR [rbx+16]
adox r13, rax
adcx r13, QWORD PTR [rbx+24]
adox r14, rbp
lea rsi, [rsi+32]
lea rbx, [rbx+32]
adcx r14, rbp
adox r10, r15
mulx r15, rax, QWORD PTR [rcx]
adcx r10, rax
adox r11, r15
mulx r15, rax, QWORD PTR [rcx+8]
adcx r11, rax
adox r12, r15
mulx r15, rax, QWORD PTR [rcx+16]
mov QWORD PTR [rbx-40], r10
adcx r12, rax
adox r13, r15
mulx r15, rax, QWORD PTR [rcx+24]
mov rdx, r9
mov QWORD PTR [rbx-32], r11
mov QWORD PTR [rbx-24], r12
adcx r13, rax
adox r15, rbp
lea rcx, [rcx+32]
mov QWORD PTR [rbx-16], r13
dec rdi
jnz fios_inner
mov rax, QWORD PTR [rsp]
mov rdi, QWORD PTR [rsp+8]
adc r15, rbp
sub rbp, QWORD PTR [rbx]
adc r14, r15
sbb r15, r15
mov QWORD PTR [rbx-8], r14
cmp rdi, QWORD PTR [rsp+16]
jne fios_outer
lea rbx, [rsp+64]
sub rcx, rax
neg r15
mov rdx, rax
shr rax, 5
mov rdi, QWORD PTR [rsp+32]
jmp fios_sub
align 16
fios_sub:
mov r11, QWORD PTR [rbx]
mov r12, QWORD PTR [rbx+8]
mov r13, QWORD PTR [rbx+16]
mov r14, QWORD PTR [rbx+24]
lea rbx, [rbx+32]
sbb r11, QWORD PTR [rcx]
sbb r12, QWORD PTR [rcx+8]
sbb r13, QWORD PTR [rcx+16]
sbb r14, QWORD PTR [rcx+24]
lea rcx, [rcx+32]
mov QWORD PTR [rdi], r11
mov QWORD PTR [rdi+8], r12
mov QWORD PTR [rdi+16], r13
mov QWORD PTR [rdi+24], r14
lea rdi, [rdi+32]
dec rax
jnz fios_sub
sbb r15, 0

	; r15 = top-carry - borrow  =>  -1 if t < m (keep t), 0 otherwise (keep t-m)
	; (OpenSSL semantics: sbb $0,%r15 only; do NOT add a second sbb here)
	lea	rbx, [rsp+64]
	sub	rdi, rdx			; rewind rp to start of t-m result
	; ===== scalar conditional copy: r = mask ? t : (t-m) =====
	xor	r12, r12
fios_ccopy:
	mov	rax, QWORD PTR [rbx+r12]
	mov	r10, QWORD PTR [rdi+r12]
	mov	rcx, r15
	not	rcx
	and	rax, r15
	and	r10, rcx
	or	rax, r10
	mov	QWORD PTR [rdi+r12], rax
	add	r12, 8
	cmp	r12, rdx
	jb	fios_ccopy
	; ===== epilogue =====
	mov	rsp, QWORD PTR [rsp+40]
	pop	rdi
	pop	rsi
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	ret
mont_mul_fios_asm ENDP

END
